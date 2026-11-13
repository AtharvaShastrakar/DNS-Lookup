from dnslookup.email_security import (
    Severity, audit_email, check_dkim, check_dmarc, check_mx, check_spf,
    organizational_domain, parse_spf, rsa_key_bits,
)

from .conftest import FakeClient


def sev(findings):
    return {f.severity for f in findings}


def msgs(findings):
    return " | ".join(f.message for f in findings)


# ------------------------------------------------------------------ SPF

def test_parse_spf_terms():
    terms = parse_spf("v=spf1 ip4:1.2.3.0/24 -a/24 ~mx:mail.example.com include:x.com redirect=y.com -all")
    assert [(t.qualifier, t.name, t.value, t.modifier) for t in terms] == [
        ("+", "ip4", "1.2.3.0/24", False),
        ("-", "a", "/24", False),
        ("~", "mx", "mail.example.com", False),
        ("+", "include", "x.com", False),
        ("", "redirect", "y.com", True),
        ("-", "all", None, False),
    ]


def test_spf_missing():
    rep = check_spf("ex.com", FakeClient({("ex.com", "TXT"): ["hello"]}))
    assert rep.record is None
    assert Severity.FAIL in sev(rep.findings)


def test_spf_multiple_records_is_permerror():
    rep = check_spf("ex.com", FakeClient({("ex.com", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]}))
    assert "PermError" in msgs(rep.findings)


def test_spf_good_record_with_include_tree():
    client = FakeClient({
        ("ex.com", "TXT"): ["v=spf1 ip4:192.0.2.1 include:_spf.mail.com -all"],
        ("_spf.mail.com", "TXT"): ["v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 ~all"],
    })
    rep = check_spf("ex.com", client)
    assert rep.lookup_count == 1
    assert rep.all_qualifier == "-"
    assert rep.tree.children[0].domain == "_spf.mail.com"
    assert rep.tree.children[0].ip4 == ["198.51.100.0/24"]
    assert Severity.FAIL not in sev(rep.findings) and Severity.WARN not in sev(rep.findings)


def test_spf_too_many_lookups():
    zone = {("ex.com", "TXT"): ["v=spf1 " + " ".join(f"include:i{n}.com" for n in range(11)) + " -all"]}
    for n in range(11):
        zone[(f"i{n}.com", "TXT")] = ["v=spf1 ip4:192.0.2.1 -all"]
    rep = check_spf("ex.com", FakeClient(zone))
    assert rep.lookup_count == 11
    assert "exceeds the limit" in msgs(rep.findings)


def test_spf_nested_lookups_counted():
    client = FakeClient({
        ("ex.com", "TXT"): ["v=spf1 include:a.com mx -all"],
        ("a.com", "TXT"): ["v=spf1 include:b.com a ~all"],
        ("b.com", "TXT"): ["v=spf1 ip4:192.0.2.0/24 ~all"],
        ("a.com", "A"): ["192.0.2.5"],
        ("ex.com", "MX"): [(10, "mx.ex.com")],
    })
    rep = check_spf("ex.com", client)
    assert rep.lookup_count == 4  # include:a.com, mx, include:b.com, a
    assert rep.void_lookups == 0


def test_spf_plus_all_fails():
    rep = check_spf("ex.com", FakeClient({("ex.com", "TXT"): ["v=spf1 +all"]}))
    assert "ENTIRE internet" in msgs(rep.findings)
    assert Severity.FAIL in sev(rep.findings)


def test_spf_include_without_record_is_permerror_and_void():
    client = FakeClient({("ex.com", "TXT"): ["v=spf1 include:gone.example -all"]})
    rep = check_spf("ex.com", client)
    assert rep.void_lookups == 1
    assert "has no SPF record" in msgs(rep.findings)


def test_spf_loop_detected():
    client = FakeClient({
        ("ex.com", "TXT"): ["v=spf1 include:a.com -all"],
        ("a.com", "TXT"): ["v=spf1 include:ex.com -all"],
    })
    rep = check_spf("ex.com", client)
    assert "loop" in msgs(rep.findings)


def test_spf_redirect_inherits_all():
    client = FakeClient({
        ("ex.com", "TXT"): ["v=spf1 redirect=_spf.ex.com"],
        ("_spf.ex.com", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"],
    })
    rep = check_spf("ex.com", client)
    assert rep.all_qualifier == "-"
    assert rep.lookup_count == 1


def test_spf_invalid_ip_and_ptr_warning():
    rep = check_spf("ex.com", FakeClient({("ex.com", "TXT"): ["v=spf1 ip4:999.1.1.1 ptr -all"]}))
    text = msgs(rep.findings)
    assert "invalid ip4" in text
    assert "deprecated" in text


def test_spf_macros_not_expanded():
    rep = check_spf("ex.com", FakeClient({("ex.com", "TXT"): ["v=spf1 include:%{i}._ip.ex.com -all"]}))
    assert rep.tree.children[0].note
    assert Severity.FAIL not in sev(rep.findings)


# ------------------------------------------------------------------ DKIM

def test_rsa_key_bits(key1024, key2048):
    assert rsa_key_bits(key1024) == (1024, False)
    assert rsa_key_bits(key2048) == (2048, False)
    assert rsa_key_bits("!!notbase64!!")[0] is None


def test_dkim_finds_and_grades_keys(key1024, key2048):
    client = FakeClient({
        ("google._domainkey.ex.com", "TXT"): [f"v=DKIM1; k=rsa; p={key2048}"],
        ("s1._domainkey.ex.com", "TXT"): [f"v=DKIM1; k=rsa; t=y; p={key1024}"],
        ("old._domainkey.ex.com", "TXT"): ["v=DKIM1; p="],
    })
    rep = check_dkim("ex.com", client, selectors=["old"])
    by = {s.selector: s for s in rep.selectors}
    assert by["google"].key_bits == 2048
    assert by["s1"].key_bits == 1024 and by["s1"].testing
    assert by["old"].revoked
    text = msgs(rep.findings)
    assert "2 active DKIM key(s)" in text
    assert "s1: RSA 1024-bit" in text
    assert "testing" in text


def test_dkim_none_found():
    rep = check_dkim("ex.com", FakeClient({("ex.com", "A"): ["192.0.2.1"]}))
    assert not rep.selectors
    assert "No DKIM key found" in msgs(rep.findings)


def test_dkim_only_selectors():
    client = FakeClient({})
    rep = check_dkim("ex.com", client, selectors=["custom"], include_common=False)
    assert rep.selectors_checked == ["custom"]


def test_dkim_ed25519():
    client = FakeClient({("k1._domainkey.ex.com", "TXT"): ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="]})
    rep = check_dkim("ex.com", client)
    assert rep.selectors[0].key_type == "ed25519"
    assert Severity.WARN not in sev(rep.findings)


# ------------------------------------------------------------------ DMARC

def test_dmarc_missing():
    rep = check_dmarc("ex.com", FakeClient({}))
    assert Severity.FAIL in sev(rep.findings)


def test_dmarc_reject():
    rep = check_dmarc("ex.com", FakeClient({
        ("_dmarc.ex.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@ex.com; adkim=s"],
    }))
    assert rep.policy == "reject" and rep.subdomain_policy == "reject" and rep.adkim == "s"
    assert rep.rua == ["mailto:d@ex.com"]
    assert sev(rep.findings) <= {Severity.PASS, Severity.INFO}


def test_dmarc_none_policy_warns_and_pct():
    rep = check_dmarc("ex.com", FakeClient({("_dmarc.ex.com", "TXT"): ["v=DMARC1; p=none; pct=50"]}))
    text = msgs(rep.findings)
    assert "monitoring only" in text and "pct=50" in text and "No rua" in text


def test_dmarc_sp_none_warning():
    rep = check_dmarc("ex.com", FakeClient({("_dmarc.ex.com", "TXT"): ["v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c"]}))
    assert "subdomains can be spoofed" in msgs(rep.findings)


def test_dmarc_falls_back_to_org_domain():
    rep = check_dmarc("mail.ex.com", FakeClient({("_dmarc.ex.com", "TXT"): ["v=DMARC1; p=quarantine"]}))
    assert rep.source == "_dmarc.ex.com"
    assert rep.policy == "quarantine"


def test_organizational_domain():
    assert organizational_domain("a.b.example.com") == "example.com"
    assert organizational_domain("mail.example.co.uk") == "example.co.uk"
    assert organizational_domain("example.com") == "example.com"


# ------------------------------------------------------------------ MX

def test_mx_resolves_hosts():
    client = FakeClient({
        ("ex.com", "MX"): [(10, "mx1.ex.com"), (20, "mx2.ex.com")],
        ("mx1.ex.com", "A"): ["192.0.2.10"],
        ("mx2.ex.com", "A"): ["192.0.2.20"],
        ("192.0.2.10.rev", "PTR"): ["mx1.ex.com"],
    })
    rep = check_mx("ex.com", client)
    assert [h.host for h in rep.hosts] == ["mx1.ex.com", "mx2.ex.com"]
    assert rep.hosts[0].ptr == {"192.0.2.10": "mx1.ex.com"}
    assert Severity.FAIL not in sev(rep.findings)
    assert "no reverse DNS" in msgs(rep.findings)  # mx2 has no PTR


def test_mx_unresolvable_and_cname():
    client = FakeClient({
        ("ex.com", "MX"): [(10, "alias.ex.com")],
        ("alias.ex.com", "CNAME"): ["real.ex.com"],
    })
    rep = check_mx("ex.com", client)
    text = msgs(rep.findings)
    assert "CNAME" in text and "does not resolve" in text


def test_null_mx():
    rep = check_mx("ex.com", FakeClient({("ex.com", "MX"): [(0, ".")]}))
    assert rep.null_mx


def test_mx_nxdomain():
    rep = check_mx("nope.test", FakeClient({}))
    assert "NXDOMAIN" in msgs(rep.findings)


def test_implicit_mx():
    rep = check_mx("ex.com", FakeClient({("ex.com", "A"): ["192.0.2.1"]}))
    assert "implicit MX" in msgs(rep.findings)


# ------------------------------------------------------------------ overall

def test_audit_perfect_domain(key2048):
    client = FakeClient({
        ("ex.com", "MX"): [(10, "mx1.ex.com"), (20, "mx2.ex.com")],
        ("mx1.ex.com", "A"): ["192.0.2.10"],
        ("mx2.ex.com", "A"): ["192.0.2.20"],
        ("192.0.2.10.rev", "PTR"): ["mx1.ex.com"],
        ("192.0.2.20.rev", "PTR"): ["mx2.ex.com"],
        ("ex.com", "TXT"): ["v=spf1 mx -all"],
        ("selector1._domainkey.ex.com", "TXT"): [f"v=DKIM1; k=rsa; p={key2048}"],
        ("_dmarc.ex.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@ex.com"],
    })
    rep = audit_email("ex.com", client)
    assert rep.score == 100 and rep.grade == "A"


def test_audit_unprotected_domain():
    client = FakeClient({("ex.com", "MX"): [(10, "mx.ex.com")], ("mx.ex.com", "A"): ["192.0.2.1"]})
    rep = audit_email("ex.com", client)
    assert rep.grade == "F"
    assert rep.section_scores["spf"] == 0 and rep.section_scores["dmarc"] == 0
