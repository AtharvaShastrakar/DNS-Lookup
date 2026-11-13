"""Core DNS querying built on dnspython."""

from __future__ import annotations

import ipaddress
import random
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename

DEFAULT_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
SUPPORTED_TYPES = DEFAULT_TYPES + (
    "CAA", "SRV", "PTR", "DS", "DNSKEY", "HTTPS", "SVCB", "NAPTR", "TLSA",
)
FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]

ROOT_SERVERS = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "170.247.170.2",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
    "e.root-servers.net": "192.203.230.10",
    "f.root-servers.net": "192.5.5.241",
    "g.root-servers.net": "192.112.36.4",
    "h.root-servers.net": "198.97.190.53",
    "i.root-servers.net": "192.36.148.17",
    "j.root-servers.net": "192.58.128.30",
    "k.root-servers.net": "193.0.14.129",
    "l.root-servers.net": "199.7.83.42",
    "m.root-servers.net": "202.12.27.33",
}


@dataclass
class Record:
    type: str
    value: str
    ttl: int
    priority: int | None = None


@dataclass
class QueryResult:
    name: str
    type: str
    status: str  # ok | nxdomain | noanswer | servfail | timeout | error
    records: list[Record] = field(default_factory=list)
    error: str | None = None
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def values(self) -> list[str]:
        return [r.value for r in self.records]


def _name(n: dns.name.Name) -> str:
    return "." if n == dns.name.root else n.to_text(omit_final_dot=True)


def format_rdata(rdata) -> tuple[str, int | None]:
    """Return (display value, priority) for an rdata object."""
    t = rdata.rdtype
    if t == dns.rdatatype.MX:
        return _name(rdata.exchange), rdata.preference
    if t == dns.rdatatype.SRV:
        return f"{rdata.weight} {rdata.port} {_name(rdata.target)}", rdata.priority
    if t == dns.rdatatype.TXT:
        return b"".join(rdata.strings).decode("utf-8", "replace"), None
    if t in (dns.rdatatype.NS, dns.rdatatype.CNAME, dns.rdatatype.PTR, dns.rdatatype.DNAME):
        return _name(rdata.target), None
    if t == dns.rdatatype.SOA:
        return (
            f"{_name(rdata.mname)} {_name(rdata.rname)} serial={rdata.serial} "
            f"refresh={rdata.refresh} retry={rdata.retry} expire={rdata.expire} "
            f"minimum={rdata.minimum}"
        ), None
    return rdata.to_text(), None


class DNSClient:
    """Thin wrapper around a dnspython resolver that never raises on lookup failures."""

    def __init__(self, nameserver: str | None = None, timeout: float = 5.0):
        try:
            resolver = dns.resolver.Resolver(configure=True)
        except dns.resolver.NoResolverConfiguration:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = list(FALLBACK_NAMESERVERS)
        if nameserver:
            resolver.nameservers = [nameserver]
        if not resolver.nameservers:
            resolver.nameservers = list(FALLBACK_NAMESERVERS)
        resolver.timeout = timeout
        resolver.lifetime = timeout * 2
        self.resolver = resolver
        self.timeout = timeout

    @property
    def nameservers(self) -> list[str]:
        return [str(ns) for ns in self.resolver.nameservers]

    def query(self, name: str, rtype: str) -> QueryResult:
        rtype = rtype.upper()
        start = time.perf_counter()
        result = QueryResult(name=name, type=rtype, status="ok")
        try:
            answer = self.resolver.resolve(name, rtype)
            ttl = answer.rrset.ttl if answer.rrset is not None else 0
            for rdata in answer:
                value, prio = format_rdata(rdata)
                result.records.append(Record(type=rtype, value=value, ttl=ttl, priority=prio))
            if any(r.priority is not None for r in result.records):
                result.records.sort(key=lambda r: (r.priority or 0, r.value))
        except dns.resolver.NXDOMAIN:
            result.status = "nxdomain"
            result.error = "domain does not exist"
        except dns.resolver.NoAnswer:
            result.status = "noanswer"
            result.error = f"no {rtype} records"
        except dns.resolver.NoNameservers as exc:
            result.status = "servfail"
            result.error = "all nameservers failed (SERVFAIL/REFUSED)"
            _ = exc
        except dns.exception.Timeout:
            result.status = "timeout"
            result.error = "query timed out"
        except dns.exception.DNSException as exc:
            result.status = "error"
            result.error = str(exc) or exc.__class__.__name__
        result.elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        return result

    def query_many(self, name: str, types: list[str] | tuple[str, ...], workers: int = 8) -> list[QueryResult]:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(types)))) as pool:
            return list(pool.map(lambda t: self.query(name, t), types))

    def txt(self, name: str) -> tuple[str, list[str]]:
        res = self.query(name, "TXT")
        return res.status, res.values

    def addresses(self, host: str) -> list[str]:
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            res = self.query(host, rtype)
            if res.ok:
                out.extend(res.values)
        return out

    def reverse(self, ip: str) -> QueryResult:
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return QueryResult(name=ip, type="PTR", status="error", error="not a valid IP address")
        rev = dns.reversename.from_address(ip).to_text()
        res = self.query(rev, "PTR")
        res.name = ip
        return res

    def batch(self, domains: list[str], types: list[str] | tuple[str, ...], workers: int = 16) -> dict[str, list[QueryResult]]:
        jobs = [(d, t) for d in domains for t in types]
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(pool.map(lambda job: self.query(*job), jobs))
        out: dict[str, list[QueryResult]] = {d: [] for d in domains}
        for (d, _), r in zip(jobs, results):
            out[d].append(r)
        return out


# --------------------------------------------------------------------------- trace

@dataclass
class TraceHop:
    zone: str
    server: str
    server_ip: str
    rtt_ms: float
    kind: str  # referral | answer | nxdomain | noanswer | error
    referral: str | None = None
    nameservers: list[str] = field(default_factory=list)
    records: list[Record] = field(default_factory=list)
    authoritative: bool = False
    error: str | None = None


def _send(qname: dns.name.Name, rdtype, ip: str, timeout: float):
    q = dns.message.make_query(qname, rdtype)
    q.flags &= ~dns.flags.RD
    resp = dns.query.udp(q, ip, timeout=timeout)
    if resp.flags & dns.flags.TC:
        resp = dns.query.tcp(q, ip, timeout=timeout)
    return resp


def trace(domain: str, rtype: str = "A", client: DNSClient | None = None,
          timeout: float = 3.0, max_hops: int = 16) -> list[TraceHop]:
    """Iteratively resolve `domain` from the root servers, like `dig +trace`."""
    client = client or DNSClient(timeout=timeout)
    qname = dns.name.from_text(domain)
    rdtype = dns.rdatatype.from_text(rtype)

    servers = list(ROOT_SERVERS.items())
    random.shuffle(servers)
    zone = "."
    hops: list[TraceHop] = []

    for _ in range(max_hops):
        resp = None
        used = ("", "")
        rtt = 0.0
        last_error = "no servers to ask"
        for ns_name, ip in servers[:4]:
            try:
                t0 = time.perf_counter()
                resp = _send(qname, rdtype, ip, timeout)
                rtt = round((time.perf_counter() - t0) * 1000, 1)
                used = (ns_name, ip)
                break
            except Exception as exc:  # network errors, timeouts, bad responses
                last_error = f"{ns_name} ({ip}): {exc or exc.__class__.__name__}"
        if resp is None:
            hops.append(TraceHop(zone=zone, server="-", server_ip="-", rtt_ms=0, kind="error", error=last_error))
            break

        aa = bool(resp.flags & dns.flags.AA)
        hop = TraceHop(zone=zone, server=used[0], server_ip=used[1], rtt_ms=rtt, kind="", authoritative=aa)

        if resp.rcode() == dns.rcode.NXDOMAIN:
            hop.kind = "nxdomain"
            hops.append(hop)
            break

        if resp.answer:
            hop.kind = "answer"
            for rrset in resp.answer:
                for rdata in rrset:
                    value, prio = format_rdata(rdata)
                    hop.records.append(Record(type=dns.rdatatype.to_text(rrset.rdtype), value=value,
                                              ttl=rrset.ttl, priority=prio))
            hops.append(hop)
            break

        if resp.rcode() != dns.rcode.NOERROR:
            hop.kind = "error"
            hop.error = dns.rcode.to_text(resp.rcode())
            hops.append(hop)
            break

        ns_rrsets = [rr for rr in resp.authority if rr.rdtype == dns.rdatatype.NS]
        if not ns_rrsets:
            hop.kind = "noanswer"
            hops.append(hop)
            break

        ns_rr = ns_rrsets[0]
        new_zone = ns_rr.name.to_text()
        ns_names = [r.target.to_text() for r in ns_rr]
        hop.kind = "referral"
        hop.referral = new_zone
        hop.nameservers = [n.rstrip(".") for n in ns_names]
        hops.append(hop)

        if new_zone == zone:
            hop.kind = "error"
            hop.error = "referral loop"
            break

        glue: dict[str, str] = {}
        for rr in resp.additional:
            if rr.rdtype == dns.rdatatype.A:
                for r in rr:
                    glue.setdefault(rr.name.to_text(), r.address)
        next_servers = [(n.rstrip("."), glue[n]) for n in ns_names if n in glue]
        if not next_servers:  # glueless delegation: resolve the NS names ourselves
            for n in ns_names[:4]:
                res = client.query(n, "A")
                if res.ok:
                    next_servers.append((n.rstrip("."), res.values[0]))
        if not next_servers:
            hops.append(TraceHop(zone=new_zone, server="-", server_ip="-", rtt_ms=0, kind="error",
                                 error="could not resolve any nameserver address"))
            break

        random.shuffle(next_servers)
        servers = next_servers
        zone = new_zone

    return hops
