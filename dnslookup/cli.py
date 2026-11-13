"""Command-line interface."""

import sys
from pathlib import Path
from typing import Annotated, List, Optional

import typer

from . import __version__
from . import output as out
from .email_security import audit_email, check_dkim, check_dmarc, check_mx, check_spf
from .resolver import DEFAULT_TYPES, SUPPORTED_TYPES, DNSClient, trace
from .utils import InvalidDomainError, is_ip, normalize_domain
from .whois import whois_lookup

app = typer.Typer(
    help="DNS lookups with email security auditing (MX, SPF, DKIM, DMARC).",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

ServerOpt = Annotated[Optional[str], typer.Option("--server", "-s", help="Nameserver IP to query (default: system resolver).")]
TimeoutOpt = Annotated[float, typer.Option("--timeout", help="Per-query timeout in seconds.")]
JsonOpt = Annotated[bool, typer.Option("--json", "-j", help="Output JSON instead of tables.")]
TypesOpt = Annotated[Optional[List[str]], typer.Option("--type", "-t", help="Record type(s); repeat or comma-separate. Default: A,AAAA,MX,NS,TXT,CNAME,SOA.")]
SelectorOpt = Annotated[Optional[List[str]], typer.Option("--selector", "-S", help="DKIM selector(s) to check; repeat or comma-separate.")]


def _domain(raw: str) -> str:
    try:
        return normalize_domain(raw)
    except InvalidDomainError as exc:
        out.console.print(f"[red]✖ {exc}[/]")
        raise typer.Exit(2)


def _split(values: Optional[List[str]]) -> List[str]:
    items: List[str] = []
    for v in values or []:
        items += [x.strip() for x in v.split(",") if x.strip()]
    return items


def _types(values: Optional[List[str]]) -> List[str]:
    types = [t.upper() for t in _split(values)] or list(DEFAULT_TYPES)
    if types == ["ALL"]:
        return list(SUPPORTED_TYPES)
    bad = [t for t in types if t not in SUPPORTED_TYPES]
    if bad:
        out.console.print(f"[red]✖ unsupported record type(s): {', '.join(bad)}[/]  "
                          f"[dim]supported: {', '.join(SUPPORTED_TYPES)}, ALL[/]")
        raise typer.Exit(2)
    return types


def _version(value: bool):
    if value:
        print(f"dnslookup {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[Optional[bool], typer.Option("--version", "-V", callback=_version, is_eager=True, help="Show version.")] = None,
):
    """DNS lookups with email security auditing."""


@app.command()
def query(domain: str, type: TypesOpt = None, server: ServerOpt = None, timeout: TimeoutOpt = 5.0, json: JsonOpt = False):
    """Query DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, …). Use [bold]-t ALL[/] for every type."""
    d = _domain(domain)
    client = DNSClient(server, timeout)
    with out.console.status(f"Querying {d}…") if not json else _null():
        results = client.query_many(d, _types(type))
    if json:
        out.print_json({"domain": d, "nameservers": client.nameservers, "results": results})
    else:
        out.render_query(d, results, client.nameservers)
    if all(r.status == "nxdomain" for r in results):
        raise typer.Exit(1)


@app.command()
def reverse(ips: List[str], server: ServerOpt = None, timeout: TimeoutOpt = 5.0, json: JsonOpt = False):
    """Reverse DNS (PTR) lookup for one or more IP addresses."""
    client = DNSClient(server, timeout)
    results = [client.reverse(ip) for ip in ips]
    out.print_json(results) if json else out.render_reverse(results)


@app.command("trace")
def trace_cmd(domain: str, type: Annotated[str, typer.Option("--type", "-t")] = "A",
              timeout: TimeoutOpt = 3.0, json: JsonOpt = False):
    """Trace resolution from the root servers down to the authoritative nameserver."""
    d = _domain(domain)
    rtype = _types([type])[0]
    with out.console.status(f"Tracing {d} from the root…") if not json else _null():
        hops = trace(d, rtype, DNSClient(timeout=timeout), timeout=timeout)
    out.print_json(hops) if json else out.render_trace(d, rtype, hops)


@app.command()
def batch(
    file: Annotated[Path, typer.Argument(help="File with one domain per line ('-' for stdin). '#' starts a comment.")],
    type: TypesOpt = None, server: ServerOpt = None, timeout: TimeoutOpt = 5.0,
    workers: Annotated[int, typer.Option("--workers", "-w", help="Concurrent queries.")] = 16,
    json: JsonOpt = False,
):
    """Look up many domains concurrently."""
    text = sys.stdin.read() if str(file) == "-" else file.read_text()
    domains: List[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            d = normalize_domain(line)
        except InvalidDomainError as exc:
            out.console.print(f"[yellow]⚠ skipping {exc}[/]")
            continue
        if d not in domains:
            domains.append(d)
    if not domains:
        out.console.print("[red]✖ no domains found in input[/]")
        raise typer.Exit(2)
    types = _types(type) if _split(type) else ["A", "MX"]
    client = DNSClient(server, timeout)
    with out.console.status(f"Looking up {len(domains)} domains…") if not json else _null():
        results = client.batch(domains, types, workers)
    out.print_json(results) if json else out.render_batch(results)


@app.command()
def whois(domain: str, raw: Annotated[bool, typer.Option("--raw", help="Print the raw WHOIS response.")] = False,
          json: JsonOpt = False):
    """WHOIS registration data (registrar, dates, nameservers)."""
    d = _domain(domain)
    with out.console.status(f"WHOIS {d}…") if not json else _null():
        res = whois_lookup(d)
    if json:
        out.print_json(res)
    elif raw:
        print(res.raw or res.error)
    else:
        out.render_whois(res)


@app.command()
def email(domain: str, selector: SelectorOpt = None,
          only_selectors: Annotated[bool, typer.Option("--only-selectors", help="Probe only the given selectors, not the built-in list.")] = False,
          server: ServerOpt = None, timeout: TimeoutOpt = 5.0, json: JsonOpt = False):
    """Full email security audit: MX, SPF, DKIM, DMARC, MTA-STS — with a score and grade."""
    d = _domain(domain)
    client = DNSClient(server, timeout)
    with out.console.status(f"Auditing email security for {d}…") if not json else _null():
        rep = audit_email(d, client, _split(selector), include_common=not only_selectors)
    out.print_json(rep) if json else out.render_email_report(rep)
    if rep.grade == "F":
        raise typer.Exit(1)


@app.command()
def mx(domain: str, server: ServerOpt = None, timeout: TimeoutOpt = 5.0, json: JsonOpt = False):
    """Check MX records: resolution, reverse DNS, CNAME misuse, Null MX."""
    d = _domain(domain)
    rep = check_mx(d, DNSClient(server, timeout))
    out.print_json(rep) if json else out.console.print(out.mx_panel(rep))


@app.command()
def spf(domain: str, server: ServerOpt = None, timeout: TimeoutOpt = 5.0, json: JsonOpt = False):
    """Validate SPF: syntax, include tree, 10-lookup limit, void lookups, 'all' policy."""
    d = _domain(domain)
    rep = check_spf(d, DNSClient(server, timeout))
    out.print_json(rep) if json else out.console.print(out.spf_panel(rep))


@app.command()
def dkim(domain: str, selector: SelectorOpt = None,
         only_selectors: Annotated[bool, typer.Option("--only-selectors", help="Probe only the given selectors.")] = False,
         server: ServerOpt = None, timeout: TimeoutOpt = 5.0, json: JsonOpt = False):
    """Discover DKIM keys by probing selectors and check key type/size."""
    d = _domain(domain)
    with out.console.status("Probing DKIM selectors…") if not json else _null():
        rep = check_dkim(d, DNSClient(server, timeout), _split(selector), include_common=not only_selectors)
    out.print_json(rep) if json else out.console.print(out.dkim_panel(rep))


@app.command()
def dmarc(domain: str, server: ServerOpt = None, timeout: TimeoutOpt = 5.0, json: JsonOpt = False):
    """Check the DMARC policy, alignment and reporting."""
    d = _domain(domain)
    rep = check_dmarc(d, DNSClient(server, timeout))
    out.print_json(rep) if json else out.console.print(out.dmarc_panel(rep))


class _null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


if __name__ == "__main__":
    app()
