import json

import pytest

from dnslookup.email_security import audit_email
from dnslookup.output import to_jsonable
from dnslookup.utils import InvalidDomainError, is_ip, normalize_domain
from dnslookup.whois import parse_whois

from .conftest import FakeClient


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  Example.COM.  ", "example.com"),
    ("https://www.example.com/path?q=1", "www.example.com"),
    ("example.com:8080", "example.com"),
    ("user@example.com", "example.com"),
    ("münchen.de", "xn--mnchen-3ya.de"),
    ("_dmarc.example.com", "_dmarc.example.com"),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "bad..domain", "-lead.com", "a" * 64 + ".com", "sp ace.com"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)


def test_is_ip():
    assert is_ip("8.8.8.8") and is_ip("2001:db8::1")
    assert not is_ip("example.com")


def test_report_is_json_serialisable():
    rep = audit_email("ex.com", FakeClient({("ex.com", "TXT"): ["v=spf1 -all"]}))
    data = json.loads(json.dumps(to_jsonable(rep)))
    assert data["spf"]["all_qualifier"] == "-"
    assert data["spf"]["findings"][0]["severity"] in {"pass", "info", "warn", "fail"}


def test_parse_whois():
    raw = """
   Domain Name: EXAMPLE.COM
   Registrar: Example Registrar, Inc.
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2030-08-13T04:00:00Z
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
"""
    res = parse_whois("example.com", raw)
    assert res.registrar == "Example Registrar, Inc."
    assert res.created.startswith("1995")
    assert res.expires.startswith("2030")
    assert res.status == ["clientDeleteProhibited"]
    assert res.name_servers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert res.dnssec == "signedDelegation"
