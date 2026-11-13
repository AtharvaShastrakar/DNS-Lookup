"""Rich terminal rendering and JSON export."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .email_security import (
    DKIMReport, DMARCReport, EmailSecurityReport, ExtraReport, Finding, MXReport,
    SPFNode, SPFReport, Severity,
)
from .resolver import QueryResult, TraceHop
from .whois import WhoisResult

console = Console()

TYPE_COLORS = {
    "A": "green", "AAAA": "bright_green", "MX": "magenta", "NS": "cyan", "TXT": "yellow",
    "CNAME": "blue", "SOA": "bright_blue", "CAA": "bright_magenta", "PTR": "bright_cyan",
}
STATUS_STYLE = {"ok": "green", "nxdomain": "red", "noanswer": "dim", "timeout": "yellow",
                "servfail": "red", "error": "red"}
SEV_ICON = {
    Severity.PASS: ("✔", "green"), Severity.INFO: ("ℹ", "cyan"),
    Severity.WARN: ("⚠", "yellow"), Severity.FAIL: ("✖", "red"),
}
GRADE_STYLE = {"A": "bold green", "B": "bold bright_green", "C": "bold yellow", "D": "bold dark_orange", "F": "bold red"}


# --------------------------------------------------------------------------- json

def to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, Severity):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def print_json(obj: Any) -> None:
    print(json.dumps(to_jsonable(obj), indent=2, ensure_ascii=False))


# --------------------------------------------------------------------------- records

def render_query(domain: str, results: list[QueryResult], nameservers: list[str]) -> None:
    table = Table(title=f"DNS records for [bold]{domain}[/]", title_justify="left",
                  header_style="bold", expand=True, show_lines=False)
    table.add_column("Type", width=7, no_wrap=True)
    table.add_column("Pri", justify="right", width=4)
    table.add_column("Value", overflow="fold", ratio=1)
    table.add_column("TTL", justify="right", width=7)

    empty: list[QueryResult] = []
    for res in results:
        color = TYPE_COLORS.get(res.type, "white")
        if not res.ok:
            empty.append(res)
            continue
        for i, rec in enumerate(res.records):
            table.add_row(
                Text(res.type if i == 0 else "", style=f"bold {color}"),
                str(rec.priority) if rec.priority is not None else "",
                rec.value,
                _ttl(rec.ttl),
            )
        table.add_section()

    console.print(table)
    if empty:
        line = Text("  ")
        for res in empty:
            line.append(f"{res.type}: ", style="bold")
            line.append(res.status, style=STATUS_STYLE.get(res.status, "white"))
            line.append("   ")
        console.print(line)
    total = sum(r.elapsed_ms for r in results)
    console.print(f"[dim]  resolver {', '.join(nameservers)} · {len(results)} queries · {total:.0f} ms total[/]")


def _ttl(seconds: int) -> str:
    if seconds >= 86400 and seconds % 3600 == 0:
        return f"{seconds // 86400}d" if seconds % 86400 == 0 else f"{seconds // 3600}h"
    if seconds >= 3600 and seconds % 60 == 0:
        return f"{seconds // 3600}h{(seconds % 3600) // 60 or ''}{'m' if seconds % 3600 else ''}"
    if seconds >= 60:
        return f"{seconds // 60}m{seconds % 60 or ''}{'s' if seconds % 60 else ''}"
    return f"{seconds}s"


def render_reverse(results: list[QueryResult]) -> None:
    table = Table(title="Reverse DNS", title_justify="left", header_style="bold")
    table.add_column("IP address", style="cyan")
    table.add_column("Hostname (PTR)")
    table.add_column("TTL", justify="right")
    for r in results:
        if r.ok:
            for rec in r.records:
                table.add_row(r.name, f"[green]{rec.value}[/]", _ttl(rec.ttl))
        else:
            table.add_row(r.name, f"[{STATUS_STYLE.get(r.status, 'red')}]{r.error}[/]", "")
    console.print(table)


def render_batch(results: dict[str, list[QueryResult]]) -> None:
    types = [r.type for r in next(iter(results.values()), [])]
    table = Table(title="Batch lookup", title_justify="left", header_style="bold", expand=True)
    table.add_column("Domain", style="bold", no_wrap=True)
    for t in types:
        table.add_column(t, overflow="fold", style=TYPE_COLORS.get(t, "white"))
    for domain, rows in results.items():
        cells = []
        for r in rows:
            if r.ok:
                vals = [f"{rec.priority} {rec.value}" if rec.priority is not None else rec.value for rec in r.records]
                cells.append("\n".join(vals))
            else:
                cells.append(Text(r.status, style=STATUS_STYLE.get(r.status, "red") + " italic"))
        table.add_row(domain, *cells)
    console.print(table)


def render_trace(domain: str, rtype: str, hops: list[TraceHop]) -> None:
    root = Tree(f"[bold]Trace[/] {domain} [dim]{rtype}[/]")
    for hop in hops:
        label = Text()
        label.append(f"{hop.zone:<16}", style="bold cyan")
        label.append(f" {hop.server}", style="white")
        if hop.server_ip != "-":
            label.append(f" ({hop.server_ip})", style="dim")
        if hop.rtt_ms:
            label.append(f"  {hop.rtt_ms:.0f} ms", style="yellow")
        node = root.add(label)
        if hop.kind == "referral":
            node.add(Text(f"→ referral to {hop.referral}  [{', '.join(hop.nameservers[:4])}"
                          f"{', …' if len(hop.nameservers) > 4 else ''}]", style="dim"))
        elif hop.kind == "answer":
            tag = " (authoritative)" if hop.authoritative else ""
            sub = node.add(Text(f"✔ answer{tag}", style="bold green"))
            for rec in hop.records:
                pr = f"{rec.priority} " if rec.priority is not None else ""
                sub.add(f"[{TYPE_COLORS.get(rec.type, 'white')}]{rec.type:<6}[/] {pr}{rec.value}  [dim]{_ttl(rec.ttl)}[/]")
        elif hop.kind == "nxdomain":
            node.add(Text("✖ NXDOMAIN — name does not exist", style="bold red"))
        elif hop.kind == "noanswer":
            node.add(Text(f"∅ no {rtype} records (NOERROR/NODATA)", style="yellow"))
        else:
            node.add(Text(f"✖ {hop.error}", style="bold red"))
    console.print(root)


def render_whois(res: WhoisResult) -> None:
    if res.error and not res.registrar:
        console.print(f"[red]✖ WHOIS: {res.error}[/]")
        return
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(overflow="fold")
    for label, value in (
        ("Domain", res.domain), ("Registrar", res.registrar), ("Created", res.created),
        ("Updated", res.updated), ("Expires", res.expires), ("DNSSEC", res.dnssec),
        ("Name servers", "\n".join(res.name_servers)), ("Status", "\n".join(res.status)),
        ("WHOIS server", res.server),
    ):
        table.add_row(label, value or "[dim]—[/]")
    console.print(Panel(table, title="WHOIS", title_align="left", border_style="blue"))


# --------------------------------------------------------------------------- email security

def _findings(findings: list[Finding]) -> Group:
    lines = []
    for f in findings:
        icon, color = SEV_ICON[f.severity]
        t = Text()
        t.append(f" {icon} ", style=f"bold {color}")
        t.append(f.message, style=color if f.severity in (Severity.FAIL, Severity.WARN) else "")
        lines.append(t)
    return Group(*lines)


def _status_border(findings: list[Finding]) -> str:
    sevs = {f.severity for f in findings}
    if Severity.FAIL in sevs:
        return "red"
    if Severity.WARN in sevs:
        return "yellow"
    return "green"


def mx_panel(rep: MXReport) -> Panel:
    parts: list = []
    if rep.hosts:
        t = Table(header_style="bold", box=None, padding=(0, 1))
        t.add_column("Pri", justify="right")
        t.add_column("Mail server", style="magenta")
        t.add_column("Addresses", overflow="fold")
        t.add_column("Reverse DNS", overflow="fold", style="dim")
        for h in rep.hosts:
            ptrs = [p or "—" for p in h.ptr.values()]
            t.add_row(str(h.preference), h.host + (" [yellow](CNAME)[/]" if h.is_cname else ""),
                      "\n".join(h.addresses) or "[red]unresolved[/]", "\n".join(ptrs))
        parts += [t, Text()]
    parts.append(_findings(rep.findings))
    return Panel(Group(*parts), title="[bold]MX[/] · mail servers", title_align="left",
                 border_style=_status_border(rep.findings))


def _spf_tree(node: SPFNode, tree: Tree) -> None:
    for child in node.children:
        label = Text()
        label.append(f"{child.kind}: ", style="dim")
        label.append(child.domain, style="bold red" if child.error else "bold")
        if child.error:
            label.append(f"  ✖ {child.error}", style="red")
        if child.note:
            label.append(f"  ({child.note})", style="dim italic")
        if child.ip4 or child.ip6:
            label.append(f"  {len(child.ip4)} ip4 · {len(child.ip6)} ip6", style="cyan")
        sub = tree.add(label)
        _spf_tree(child, sub)


def spf_panel(rep: SPFReport) -> Panel:
    parts: list = []
    if rep.record:
        parts.append(Text(rep.record, style="yellow", overflow="fold"))
        if rep.tree and rep.tree.children:
            tree = Tree(Text(f"{rep.domain}", style="bold"), guide_style="dim")
            _spf_tree(rep.tree, tree)
            parts += [Text(), tree]
        parts.append(Text())
    parts.append(_findings(rep.findings))
    q = {"-": "-all", "~": "~all", "?": "?all", "+": "+all"}.get(rep.all_qualifier or "", "no all")
    sub = f"{rep.lookup_count}/10 lookups · {q}" if rep.record else ""
    return Panel(Group(*parts), title="[bold]SPF[/] · sender policy", subtitle=sub, subtitle_align="right",
                 title_align="left", border_style=_status_border(rep.findings))


def dkim_panel(rep: DKIMReport) -> Panel:
    parts: list = []
    if rep.selectors:
        t = Table(header_style="bold", box=None, padding=(0, 1))
        t.add_column("Selector", style="bold cyan")
        t.add_column("Key")
        t.add_column("Flags")
        t.add_column("Record", overflow="ellipsis", no_wrap=True, max_width=48, style="dim")
        for s in rep.selectors:
            if s.revoked:
                key = "[dim]revoked[/]"
            else:
                bits = f"{'~' if s.key_bits_estimated else ''}{s.key_bits or '?'}"
                color = "green" if (s.key_bits or 0) >= 2048 or s.key_type == "ed25519" else "yellow"
                key = f"[{color}]{s.key_type.upper()} {bits}[/]"
            flags = ", ".join(x for x in (
                "[yellow]t=y testing[/]" if s.testing else "",
                *(f"t={f}" for f in s.flags if f != "y"),
                f"h={s.hash_algorithms}" if s.hash_algorithms else "",
            ) if x)
            t.add_row(s.selector, key, flags or "—", s.record)
        parts += [t, Text()]
    parts.append(_findings(rep.findings))
    return Panel(Group(*parts), title="[bold]DKIM[/] · signing keys",
                 subtitle=f"{len(rep.selectors_checked)} selectors probed", subtitle_align="right",
                 title_align="left", border_style=_status_border(rep.findings))


def dmarc_panel(rep: DMARCReport) -> Panel:
    parts: list = []
    if rep.record:
        parts.append(Text(rep.record, style="yellow", overflow="fold"))
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style="bold cyan")
        t.add_column(overflow="fold")
        pol_color = {"reject": "green", "quarantine": "bright_green", "none": "yellow"}.get(rep.policy or "", "red")
        t.add_row("Policy", f"[{pol_color}]{rep.policy}[/]")
        t.add_row("Subdomains", rep.subdomain_policy or "—")
        t.add_row("Percentage", f"{rep.pct}%")
        t.add_row("Alignment", f"DKIM {'strict' if rep.adkim == 's' else 'relaxed'} · SPF {'strict' if rep.aspf == 's' else 'relaxed'}")
        t.add_row("Reports (rua)", ", ".join(rep.rua) or "—")
        if rep.ruf:
            t.add_row("Forensic (ruf)", ", ".join(rep.ruf))
        parts += [Text(), t, Text()]
    parts.append(_findings(rep.findings))
    return Panel(Group(*parts), title="[bold]DMARC[/] · domain policy", title_align="left",
                 subtitle=rep.source or "", subtitle_align="right", border_style=_status_border(rep.findings))


def extras_panel(rep: ExtraReport) -> Panel:
    return Panel(_findings(rep.findings), title="[bold]Transport & branding[/]", title_align="left", border_style="blue")


def render_email_report(rep: EmailSecurityReport) -> None:
    style = GRADE_STYLE.get(rep.grade, "bold")
    header = Table.grid(padding=(0, 3))
    header.add_column(justify="center")
    header.add_column()
    grade = Text(f"\n {rep.grade} \n", style=f"{style} reverse")
    breakdown = Table(show_header=False, box=None, padding=(0, 1))
    breakdown.add_column(style="bold")
    breakdown.add_column(justify="right")
    labels = {"mx": "MX", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC"}
    for key, val in rep.section_scores.items():
        breakdown.add_row(labels[key], f"{val}")
    breakdown.add_row("[bold]Total[/]", f"[{style}]{rep.score}/100[/]")
    header.add_row(grade, Group(Text(f"Email security for {rep.domain}", style="bold"), breakdown))
    console.print(Panel(header, border_style=style.split()[-1], title="[bold]Email security audit[/]", title_align="left"))
    console.print(mx_panel(rep.mx))
    console.print(spf_panel(rep.spf))
    console.print(dkim_panel(rep.dkim))
    console.print(dmarc_panel(rep.dmarc))
    console.print(extras_panel(rep.extras))
