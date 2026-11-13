"""Minimal WHOIS client (RFC 3912) that follows IANA and registrar referrals."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

IANA_WHOIS = "whois.iana.org"


@dataclass
class WhoisResult:
    domain: str
    server: str | None = None
    registrar: str | None = None
    created: str | None = None
    updated: str | None = None
    expires: str | None = None
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    dnssec: str | None = None
    raw: str = ""
    error: str | None = None


def _whois_query(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _field(raw: str, *keys: str) -> str | None:
    for key in keys:
        m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", raw, re.IGNORECASE | re.MULTILINE)
        if m and m.group(1):
            return m.group(1)
    return None


def _all(raw: str, key: str) -> list[str]:
    vals = re.findall(rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", raw, re.IGNORECASE | re.MULTILINE)
    seen: list[str] = []
    for v in vals:
        v = v.split()[0] if key.lower() == "domain status" else v
        v = v.lower() if key.lower() in ("name server", "nserver") else v
        if v and v not in seen:
            seen.append(v)
    return seen


def parse_whois(domain: str, raw: str) -> WhoisResult:
    res = WhoisResult(domain=domain, raw=raw)
    res.registrar = _field(raw, "Registrar", "Sponsoring Registrar", "registrar name")
    res.created = _field(raw, "Creation Date", "Created", "created", "Registered on", "Registration Time")
    res.updated = _field(raw, "Updated Date", "Last Modified", "last-update", "changed")
    res.expires = _field(raw, "Registry Expiry Date", "Registrar Registration Expiration Date",
                         "Expiry Date", "Expiration Date", "paid-till", "expires")
    res.dnssec = _field(raw, "DNSSEC")
    res.name_servers = _all(raw, "Name Server") or _all(raw, "nserver")
    res.status = _all(raw, "Domain Status") or _all(raw, "status")
    return res


def whois_lookup(domain: str, timeout: float = 10.0) -> WhoisResult:
    tld = domain.rsplit(".", 1)[-1]
    try:
        iana = _whois_query(IANA_WHOIS, tld, timeout)
    except OSError as exc:
        return WhoisResult(domain=domain, error=f"could not reach {IANA_WHOIS}: {exc}")

    server = _field(iana, "whois")
    if not server:
        return WhoisResult(domain=domain, server=IANA_WHOIS, raw=iana,
                           error=f"no WHOIS server published for .{tld}")
    try:
        raw = _whois_query(server, domain, timeout)
    except OSError as exc:
        return WhoisResult(domain=domain, server=server, error=f"could not reach {server}: {exc}")

    result = parse_whois(domain, raw)
    result.server = server

    # Thin registries (e.g. .com/.net) point at the registrar's own WHOIS server.
    referral = _field(raw, "Registrar WHOIS Server", "ReferralServer")
    if referral:
        referral = referral.replace("whois://", "").strip("/")
    if referral and referral.lower() != server.lower():
        try:
            raw2 = _whois_query(referral, domain, timeout)
            detail = parse_whois(domain, raw2)
            for attr in ("registrar", "created", "updated", "expires", "dnssec"):
                if not getattr(result, attr):
                    setattr(result, attr, getattr(detail, attr))
            result.name_servers = result.name_servers or detail.name_servers
            result.status = result.status or detail.status
            result.raw = raw + "\n\n# --- " + referral + " ---\n" + raw2
        except OSError:
            pass  # registry data is still useful on its own

    if not any([result.registrar, result.created, result.expires, result.name_servers]):
        if re.search(r"no match|not found|no data found|no entries", raw, re.IGNORECASE):
            result.error = "domain not found in WHOIS (may be unregistered)"
    return result
