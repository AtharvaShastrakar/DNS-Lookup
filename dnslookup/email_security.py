"""Email authentication audit: MX, SPF, DKIM and DMARC (plus MTA-STS / TLS-RPT)."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum

from .resolver import DNSClient


class Severity(str, Enum):
    PASS = "pass"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Finding:
    severity: Severity
    message: str
    weight: float = 1.0  # how heavily a WARN counts against the section score


def _ok(msg): return Finding(Severity.PASS, msg)
def _info(msg): return Finding(Severity.INFO, msg)
def _warn(msg, weight=1.0): return Finding(Severity.WARN, msg, weight)
def _fail(msg): return Finding(Severity.FAIL, msg)


# =========================================================================== MX

@dataclass
class MXHost:
    preference: int
    host: str
    addresses: list[str] = field(default_factory=list)
    ptr: dict[str, str | None] = field(default_factory=dict)
    is_cname: bool = False


@dataclass
class MXReport:
    domain: str
    hosts: list[MXHost] = field(default_factory=list)
    null_mx: bool = False
    findings: list[Finding] = field(default_factory=list)


def _inspect_mx_host(client: DNSClient, pref: int, host: str) -> MXHost:
    mx = MXHost(preference=pref, host=host)
    mx.is_cname = client.query(host, "CNAME").ok
    mx.addresses = client.addresses(host)
    for ip in mx.addresses[:3]:
        rev = client.reverse(ip)
        mx.ptr[ip] = rev.values[0] if rev.ok else None
    return mx


def check_mx(domain: str, client: DNSClient) -> MXReport:
    report = MXReport(domain=domain)
    res = client.query(domain, "MX")

    if res.status == "nxdomain":
        report.findings.append(_fail("Domain does not exist (NXDOMAIN)"))
        return report
    if res.status in ("timeout", "servfail", "error"):
        report.findings.append(_fail(f"MX lookup failed: {res.error}"))
        return report
    if not res.ok:
        if client.addresses(domain):
            report.findings.append(_warn("No MX records — mail falls back to the domain's A/AAAA record (implicit MX)"))
        else:
            report.findings.append(_fail("No MX records and no A/AAAA fallback — domain cannot receive mail"))
        return report

    if len(res.records) == 1 and res.records[0].value == "." and res.records[0].priority == 0:
        report.null_mx = True
        report.findings.append(_info("Null MX (RFC 7505): this domain explicitly does not accept email"))
        return report

    with ThreadPoolExecutor(max_workers=8) as pool:
        report.hosts = list(pool.map(lambda r: _inspect_mx_host(client, r.priority or 0, r.value), res.records))

    for h in report.hosts:
        try:
            ipaddress.ip_address(h.host)
            report.findings.append(_fail(f"{h.host}: MX points to an IP literal; it must be a hostname (RFC 5321)"))
            continue
        except ValueError:
            pass
        if h.host == ".":
            report.findings.append(_fail("Null MX '.' mixed with other MX records"))
            continue
        if h.is_cname:
            report.findings.append(_warn(f"{h.host}: MX target is a CNAME (not allowed by RFC 2181 §10.3)", 0.5))
        if not h.addresses:
            report.findings.append(_fail(f"{h.host}: MX host does not resolve to any address"))
        missing_ptr = [ip for ip, ptr in h.ptr.items() if not ptr]
        if missing_ptr:
            report.findings.append(_info(f"{h.host}: no reverse DNS (PTR) for {', '.join(missing_ptr)}"))

    resolvable = [h for h in report.hosts if h.addresses]
    if resolvable:
        report.findings.insert(0, _ok(f"{len(res.records)} MX record(s), {len(resolvable)} resolvable"))
    if len(report.hosts) == 1:
        report.findings.append(_info("Only one MX host — no failover if it is unreachable"))
    return report


# =========================================================================== SPF

SPF_LOOKUP_LIMIT = 10
SPF_VOID_LIMIT = 2
_KNOWN_MECHS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)


def find_spf(txts: list[str]) -> list[str]:
    return [t.strip() for t in txts if _SPF_RE.match(t.strip())]


@dataclass
class SPFTerm:
    raw: str
    qualifier: str
    name: str
    value: str | None
    modifier: bool = False


def parse_spf(record: str) -> list[SPFTerm]:
    terms: list[SPFTerm] = []
    for tok in record.split()[1:]:
        m = re.match(r"^([a-zA-Z][\w.-]*)=(.*)$", tok)
        if m:
            terms.append(SPFTerm(tok, "", m.group(1).lower(), m.group(2), modifier=True))
            continue
        qualifier, body = ("+", tok)
        if tok[0] in "+-~?":
            qualifier, body = tok[0], tok[1:]
        m = re.match(r"^([a-zA-Z0-9]+)(.*)$", body)
        name = m.group(1).lower() if m else body.lower()
        rest = m.group(2) if m else ""
        value = rest[1:] if rest.startswith(":") else (rest or None)
        terms.append(SPFTerm(tok, qualifier, name, value))
    return terms


@dataclass
class SPFNode:
    domain: str
    kind: str = "root"  # root | include | redirect
    record: str | None = None
    all_qualifier: str | None = None
    ip4: list[str] = field(default_factory=list)
    ip6: list[str] = field(default_factory=list)
    children: list["SPFNode"] = field(default_factory=list)
    error: str | None = None
    note: str | None = None


@dataclass
class SPFReport:
    domain: str
    record: str | None = None
    all_qualifier: str | None = None
    lookup_count: int = 0
    void_lookups: int = 0
    tree: SPFNode | None = None
    findings: list[Finding] = field(default_factory=list)


class _SPFWalker:
    def __init__(self, client: DNSClient):
        self.client = client
        self.lookups = 0
        self.void = 0
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def walk(self, domain: str, record: str, kind: str, depth: int, stack: frozenset[str]) -> SPFNode:
        node = SPFNode(domain=domain, kind=kind, record=record)
        terms = parse_spf(record)
        has_all = any(t.name == "all" and not t.modifier for t in terms)
        redirect: str | None = None

        for t in terms:
            if t.modifier:
                if t.name == "redirect":
                    redirect = t.value
                elif t.name != "exp":
                    self.warnings.append(f"{domain}: unknown modifier '{t.raw}' (ignored)")
                continue

            n = t.name
            if n == "all":
                node.all_qualifier = t.qualifier
            elif n == "include":
                if not t.value:
                    self.errors.append(f"{domain}: 'include' without a domain")
                    continue
                self.lookups += 1
                node.children.append(self._follow(t.value, "include", depth, stack))
            elif n in ("a", "mx"):
                self.lookups += 1
                target = (t.value or "").split("/")[0] or domain
                if "%" in target:
                    continue
                if n == "a":
                    if not self.client.addresses(target):
                        self.void += 1
                else:
                    mx = self.client.query(target, "MX")
                    if not mx.ok:
                        self.void += 1
                    elif len(mx.records) > 10:
                        self.errors.append(f"{domain}: 'mx' resolves to more than 10 hosts (PermError)")
            elif n == "ptr":
                self.lookups += 1
                self.warnings.append(f"{domain}: 'ptr' mechanism is deprecated (RFC 7208 §5.5) and slow")
            elif n == "exists":
                self.lookups += 1
            elif n in ("ip4", "ip6"):
                try:
                    net = ipaddress.ip_network(t.value or "", strict=False)
                    if (n == "ip4") != (net.version == 4):
                        raise ValueError
                    (node.ip4 if n == "ip4" else node.ip6).append(t.value)
                except ValueError:
                    self.errors.append(f"{domain}: invalid {n} value '{t.value}' (PermError)")
            else:
                self.errors.append(f"{domain}: unknown mechanism '{t.raw}' (PermError)")

        if redirect and not has_all:
            self.lookups += 1
            child = self._follow(redirect, "redirect", depth, stack)
            node.children.append(child)
            node.all_qualifier = child.all_qualifier
        return node

    def _follow(self, target: str, kind: str, depth: int, stack: frozenset[str]) -> SPFNode:
        if "%" in target:
            return SPFNode(domain=target, kind=kind, note="uses SPF macros — evaluated per message, not expanded")
        target = target.rstrip(".").lower()
        if target in stack:
            self.errors.append(f"SPF loop detected at {target}")
            return SPFNode(domain=target, kind=kind, error="loop")
        if depth >= 10:
            self.errors.append("SPF include depth exceeds 10")
            return SPFNode(domain=target, kind=kind, error="too deep")

        status, txts = self.client.txt(target)
        records = find_spf(txts)
        if not records:
            if status in ("nxdomain", "noanswer"):
                self.void += 1
            msg = f"{kind} target {target} has no SPF record (PermError)"
            if status in ("timeout", "servfail", "error"):
                msg = f"{kind} target {target} lookup failed: {status} (TempError)"
            self.errors.append(msg)
            return SPFNode(domain=target, kind=kind, error="no SPF record" if status != "timeout" else status)
        if len(records) > 1:
            self.errors.append(f"{target} publishes {len(records)} SPF records (PermError)")
        return self.walk(target, records[0], kind, depth + 1, stack | {target})


def check_spf(domain: str, client: DNSClient) -> SPFReport:
    report = SPFReport(domain=domain)
    status, txts = client.txt(domain)
    if status in ("timeout", "servfail", "error"):
        report.findings.append(_fail(f"TXT lookup failed: {status}"))
        return report

    records = find_spf(txts)
    if not records:
        report.findings.append(_fail("No SPF record — anyone can send mail claiming to be this domain"))
        return report
    if len(records) > 1:
        report.findings.append(_fail(f"{len(records)} SPF records published — receivers return PermError (RFC 7208 §3.2)"))

    record = records[0]
    report.record = record
    walker = _SPFWalker(client)
    report.tree = walker.walk(domain, record, "root", 0, frozenset({domain}))
    report.lookup_count = walker.lookups
    report.void_lookups = walker.void
    report.all_qualifier = report.tree.all_qualifier

    if len(records) == 1:
        report.findings.append(_ok("Single valid SPF record published"))

    if walker.lookups > SPF_LOOKUP_LIMIT:
        report.findings.append(_fail(f"{walker.lookups} DNS lookups — exceeds the limit of {SPF_LOOKUP_LIMIT} (PermError)"))
    elif walker.lookups >= 8:
        report.findings.append(_warn(f"{walker.lookups}/{SPF_LOOKUP_LIMIT} DNS lookups — close to the limit", 0.5))
    else:
        report.findings.append(_ok(f"{walker.lookups}/{SPF_LOOKUP_LIMIT} DNS lookups"))

    if walker.void > SPF_VOID_LIMIT:
        report.findings.append(_fail(f"{walker.void} void lookups — exceeds the limit of {SPF_VOID_LIMIT} (PermError)"))
    elif walker.void:
        report.findings.append(_warn(f"{walker.void} void lookup(s) (names returning no data)", 0.5))

    q = report.all_qualifier
    if q == "-":
        report.findings.append(_ok("Ends with -all (hard fail) — unauthorised senders are rejected"))
    elif q == "~":
        report.findings.append(_info("Ends with ~all (soft fail) — fine with an enforcing DMARC policy; -all is stricter"))
    elif q == "?":
        report.findings.append(_warn("Ends with ?all (neutral) — provides no protection"))
    elif q == "+":
        report.findings.append(_fail("Ends with +all — authorises the ENTIRE internet to send as this domain"))
    else:
        report.findings.append(_warn("No 'all' mechanism — unmatched senders default to neutral"))

    if len(record) > 450:
        report.findings.append(_info(f"Record is {len(record)} characters — long records risk UDP truncation"))

    for e in walker.errors:
        report.findings.append(_fail(e))
    for w in walker.warnings:
        report.findings.append(_warn(w, 0.5))
    return report


# =========================================================================== DKIM

COMMON_DKIM_SELECTORS = [
    "default", "dkim", "mail", "email", "smtp", "selector", "selector1", "selector2",
    "google", "google2048", "k1", "k2", "k3", "s1", "s2", "s1024", "s2048",
    "key1", "key2", "sig1", "dk", "mx", "mxvault", "everlytickey1", "everlytickey2",
    "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3", "zoho", "zmail",
    "mandrill", "mailjet", "sendgrid", "smtpapi", "amazonses", "ses", "pm", "pm-bounces",
    "mailchimp", "mc1", "hs1", "hs2", "cm", "krs", "turbo-smtp", "sendinblue", "brevo",
    "mailgun", "mg", "pic", "yahoo", "yandex", "titan1", "zendesk1", "zendesk2",
    "20161025", "20210112", "20221208", "20230601", "201909", "dkim1024", "dkim2048",
]


@dataclass
class DKIMSelector:
    selector: str
    fqdn: str
    record: str
    version: str | None = None
    key_type: str = "rsa"
    key_bits: int | None = None
    key_bits_estimated: bool = False
    testing: bool = False
    flags: list[str] = field(default_factory=list)
    revoked: bool = False
    hash_algorithms: str | None = None
    findings: list[Finding] = field(default_factory=list)


@dataclass
class DKIMReport:
    domain: str
    selectors_checked: list[str] = field(default_factory=list)
    selectors: list[DKIMSelector] = field(default_factory=list)
    wildcard: bool = False
    findings: list[Finding] = field(default_factory=list)


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    return tags


def rsa_key_bits(p: str) -> tuple[int | None, bool]:
    """Return (bits, estimated) for a base64 DKIM public key."""
    clean = re.sub(r"\s+", "", p)
    clean += "=" * (-len(clean) % 4)
    try:
        der = base64.b64decode(clean, validate=True)
    except (ValueError, binascii.Error):
        return None, False
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        key = load_der_public_key(der)
        return getattr(key, "key_size", None), False
    except Exception:
        pass
    # Fall back to an estimate (e.g. bare PKCS#1 keys) by snapping to a common size.
    raw_bits = max(0, len(der) - 38) * 8
    sizes = [512, 768, 1024, 1536, 2048, 3072, 4096]
    return min(sizes, key=lambda s: abs(s - raw_bits)), True


def analyse_dkim_record(selector: str, fqdn: str, record: str) -> DKIMSelector:
    tags = parse_tags(record)
    sel = DKIMSelector(selector=selector, fqdn=fqdn, record=record)
    sel.version = tags.get("v")
    sel.key_type = (tags.get("k") or "rsa").lower()
    sel.hash_algorithms = tags.get("h")
    sel.flags = [f.strip() for f in (tags.get("t") or "").split(":") if f.strip()]
    sel.testing = "y" in sel.flags
    p = re.sub(r"\s+", "", tags.get("p", ""))

    if sel.version and sel.version != "DKIM1":
        sel.findings.append(_warn(f"unexpected version v={sel.version}"))
    if not p:
        sel.revoked = True
        sel.findings.append(_info("empty p= — key revoked"))
        return sel

    if sel.key_type == "ed25519":
        sel.key_bits = 256
        sel.findings.append(_ok("Ed25519 key"))
    elif sel.key_type == "rsa":
        sel.key_bits, sel.key_bits_estimated = rsa_key_bits(p)
        if sel.key_bits is None:
            sel.findings.append(_fail("public key is not valid base64"))
        elif sel.key_bits < 1024:
            sel.findings.append(_fail(f"RSA {sel.key_bits}-bit key is breakable — use 2048 bits"))
        elif sel.key_bits < 2048:
            sel.findings.append(_warn(f"RSA {sel.key_bits}-bit key — 2048 bits recommended", 0.5))
        else:
            sel.findings.append(_ok(f"RSA {sel.key_bits}-bit key"))
    else:
        sel.findings.append(_warn(f"unknown key type k={sel.key_type}"))

    if sel.testing:
        sel.findings.append(_warn("t=y testing mode — receivers may ignore failures", 0.5))
    if sel.hash_algorithms and "sha256" not in sel.hash_algorithms.lower():
        sel.findings.append(_warn(f"h={sel.hash_algorithms} — SHA-1 only is deprecated"))
    return sel


def _probe_selector(client: DNSClient, domain: str, selector: str) -> DKIMSelector | None:
    fqdn = f"{selector}._domainkey.{domain}"
    status, txts = client.txt(fqdn)
    if status != "ok":
        return None
    for t in txts:
        if "p" in parse_tags(t):
            return analyse_dkim_record(selector, fqdn, t)
    return None


def check_dkim(domain: str, client: DNSClient, selectors: list[str] | None = None,
               include_common: bool = True) -> DKIMReport:
    chosen: list[str] = []
    for s in (selectors or []) + (COMMON_DKIM_SELECTORS if include_common or not selectors else []):
        s = s.strip().lower()
        if s and s not in chosen:
            chosen.append(s)
    report = DKIMReport(domain=domain, selectors_checked=chosen)

    canary = f"zz-{secrets.token_hex(4)}-nonexistent"
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda s: _probe_selector(client, domain, s), chosen + [canary]))
    canary_hit = results[-1]
    report.selectors = [r for r in results[:-1] if r is not None]
    if canary_hit is not None:
        # A wildcard answers for every selector; keep only records that differ from it.
        report.wildcard = True
        report.selectors = [s for s in report.selectors if s.record != canary_hit.record]
        report.findings.append(_info(f"Wildcard record at *._domainkey.{domain} ({canary_hit.record!r}) — "
                                     "selectors matching it were ignored"))

    active = [s for s in report.selectors if not s.revoked]
    if active:
        report.findings.append(_ok(f"{len(active)} active DKIM key(s): {', '.join(s.selector for s in active)}"))
    elif report.selectors:
        report.findings.append(_warn("Only revoked DKIM keys found"))
    else:
        report.findings.append(_warn(
            f"No DKIM key found among {len(chosen)} selectors checked — if DKIM uses a custom "
            "selector, pass it with --selector (find it in the 's=' tag of a DKIM-Signature header)", 2.0))

    for s in report.selectors:
        for f in s.findings:
            if f.severity in (Severity.WARN, Severity.FAIL):
                report.findings.append(Finding(f.severity, f"{s.selector}: {f.message}", f.weight))
    return report


# =========================================================================== DMARC

_MULTI_PART_SUFFIXES = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "gob", "nic"}


def organizational_domain(domain: str) -> str:
    """Rough organisational-domain guess (no Public Suffix List dependency)."""
    labels = domain.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass
class DMARCReport:
    domain: str
    source: str | None = None  # where the record was found
    record: str | None = None
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    adkim: str = "r"
    aspf: str = "r"
    findings: list[Finding] = field(default_factory=list)


def _dmarc_records(client: DNSClient, domain: str) -> tuple[str, list[str]]:
    status, txts = client.txt(f"_dmarc.{domain}")
    return status, [t.strip() for t in txts if re.match(r"^v\s*=\s*DMARC1\b", t.strip(), re.IGNORECASE)]


def check_dmarc(domain: str, client: DNSClient) -> DMARCReport:
    report = DMARCReport(domain=domain)
    status, records = _dmarc_records(client, domain)
    report.source = f"_dmarc.{domain}"

    if not records:
        org = organizational_domain(domain)
        if org != domain:
            status2, records = _dmarc_records(client, org)
            if records:
                report.source = f"_dmarc.{org}"
                report.findings.append(_info(f"Inherited from organisational domain {org}"))

    if not records:
        if status in ("timeout", "servfail", "error"):
            report.findings.append(_fail(f"DMARC lookup failed: {status}"))
        else:
            report.findings.append(_fail("No DMARC record — receivers get no policy and you get no reports"))
        return report
    if len(records) > 1:
        report.findings.append(_fail(f"{len(records)} DMARC records — receivers will ignore DMARC entirely"))

    report.record = records[0]
    tags = parse_tags(report.record)
    report.policy = (tags.get("p") or "").lower() or None
    sp = tags.get("sp")
    report.subdomain_policy = sp.lower() if sp else report.policy
    report.adkim = (tags.get("adkim") or "r").lower()
    report.aspf = (tags.get("aspf") or "r").lower()
    try:
        report.pct = int(tags.get("pct", "100"))
    except ValueError:
        report.findings.append(_warn(f"invalid pct={tags.get('pct')}"))
    report.rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    report.ruf = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]

    p = report.policy
    if p == "reject":
        report.findings.append(_ok("p=reject — spoofed mail is rejected"))
    elif p == "quarantine":
        report.findings.append(_ok("p=quarantine — spoofed mail goes to spam"))
        report.findings.append(_info("Consider moving to p=reject once reports look clean"))
    elif p == "none":
        report.findings.append(_warn("p=none — monitoring only, spoofed mail is still delivered", 1.5))
    else:
        report.findings.append(_fail(f"Missing or invalid policy (p={p or '∅'})"))

    if p in ("reject", "quarantine") and report.subdomain_policy == "none":
        report.findings.append(_warn("sp=none — subdomains can be spoofed freely"))
    if report.pct < 100:
        report.findings.append(_warn(f"pct={report.pct} — policy only applies to {report.pct}% of failing mail", 0.5))
    if report.rua:
        report.findings.append(_ok(f"Aggregate reports sent to {', '.join(report.rua)}"))
    else:
        report.findings.append(_warn("No rua= — you will not receive aggregate reports", 0.5))
    if report.adkim == "s" or report.aspf == "s":
        report.findings.append(_info(f"Strict alignment (adkim={report.adkim}, aspf={report.aspf})"))
    return report


# =========================================================================== extras

@dataclass
class ExtraReport:
    mta_sts: str | None = None
    tls_rpt: str | None = None
    bimi: str | None = None
    findings: list[Finding] = field(default_factory=list)


def check_extras(domain: str, client: DNSClient) -> ExtraReport:
    rep = ExtraReport()
    _, sts = client.txt(f"_mta-sts.{domain}")
    _, rpt = client.txt(f"_smtp._tls.{domain}")
    _, bimi = client.txt(f"default._bimi.{domain}")
    rep.mta_sts = next((t for t in sts if t.lower().startswith("v=stsv1")), None)
    rep.tls_rpt = next((t for t in rpt if t.lower().startswith("v=tlsrptv1")), None)
    rep.bimi = next((t for t in bimi if t.lower().startswith("v=bimi1")), None)
    rep.findings.append(_ok("MTA-STS published") if rep.mta_sts else _info("No MTA-STS (enforces TLS for inbound mail)"))
    rep.findings.append(_ok("TLS-RPT published") if rep.tls_rpt else _info("No TLS-RPT (reports on TLS delivery failures)"))
    if rep.bimi:
        rep.findings.append(_ok("BIMI record published"))
    return rep


# =========================================================================== overall

SECTION_WEIGHTS = {"mx": 15, "spf": 30, "dkim": 25, "dmarc": 30}


@dataclass
class EmailSecurityReport:
    domain: str
    mx: MXReport
    spf: SPFReport
    dkim: DKIMReport
    dmarc: DMARCReport
    extras: ExtraReport
    section_scores: dict[str, int] = field(default_factory=dict)
    score: int = 0
    grade: str = "F"


def section_score(findings: list[Finding], weight: int) -> int:
    if any(f.severity == Severity.FAIL for f in findings):
        return 0
    penalty = sum(0.25 * f.weight for f in findings if f.severity == Severity.WARN)
    return round(weight * max(0.0, 1.0 - penalty))


def grade_for(score: int) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= threshold:
            return letter
    return "F"


def audit_email(domain: str, client: DNSClient, selectors: list[str] | None = None,
                include_common: bool = True) -> EmailSecurityReport:
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_mx = pool.submit(check_mx, domain, client)
        f_spf = pool.submit(check_spf, domain, client)
        f_dkim = pool.submit(check_dkim, domain, client, selectors, include_common)
        f_dmarc = pool.submit(check_dmarc, domain, client)
        f_extra = pool.submit(check_extras, domain, client)
        report = EmailSecurityReport(domain=domain, mx=f_mx.result(), spf=f_spf.result(),
                                     dkim=f_dkim.result(), dmarc=f_dmarc.result(), extras=f_extra.result())

    if report.mx.null_mx:
        # A domain that never sends or receives mail only needs SPF -all + DMARC reject.
        weights = {"mx": 15, "spf": 40, "dkim": 0, "dmarc": 45}
    else:
        weights = SECTION_WEIGHTS
    scores = {
        "mx": section_score(report.mx.findings, weights["mx"]),
        "spf": section_score(report.spf.findings, weights["spf"]),
        "dkim": section_score(report.dkim.findings, weights["dkim"]) if weights["dkim"] else 0,
        "dmarc": section_score(report.dmarc.findings, weights["dmarc"]),
    }
    report.section_scores = scores
    report.score = sum(scores.values())
    report.grade = grade_for(report.score)
    return report
