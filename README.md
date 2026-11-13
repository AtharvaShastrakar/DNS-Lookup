# dnslookup

A DNS query CLI with Rich terminal output and a built-in **email security audit** (MX, SPF, DKIM, DMARC).

## What it does

- **Record lookups**: A, AAAA, MX, NS, TXT, CNAME, SOA, plus CAA, SRV, PTR, DS, DNSKEY, HTTPS, SVCB, NAPTR and TLSA (`-t ALL`)
- **Reverse DNS**: resolves IP addresses back to hostnames
- **Trace**: walks resolution from the root servers to the authoritative nameserver, like `dig +trace`
- **Batch**: looks up many domains concurrently from a file or stdin
- **WHOIS**: registrar, dates, nameservers and status, following IANA and registrar referrals
- **Email security audit**, scored 0–100 and graded A–F:
  - **MX**: checks that hosts resolve, reverse DNS (PTR), CNAME targets (RFC 2181), IP-literal MX, Null MX (RFC 7505) and implicit MX fallback
  - **SPF**: checks syntax, expands the full `include`/`redirect` tree, counts DNS lookups against the 10-lookup limit, counts void lookups against the limit of 2, detects loops, checks `ip4`/`ip6` values, flags `ptr` as deprecated and grades the `all` policy (`+all`, `?all`, `~all`, `-all`)
  - **DKIM**: probes about 65 common selectors (plus any you pass), parses the key and reports its RSA size or Ed25519 type. It also flags revoked keys, `t=y` testing mode and SHA-1-only keys, and filters out wildcard records.
  - **DMARC**: reports the policy, subdomain policy, `pct`, alignment and `rua`/`ruf` reporting, and falls back to the organisational domain when the record is missing
  - **Extras**: MTA-STS, TLS-RPT and BIMI
- **JSON output** (`--json`) on every command, for scripts and pipelines

## Quick start

Requires [uv](https://docs.astral.sh/uv/) (Python ≥ 3.10 is fetched automatically if needed).

```bash
uv tool install .            # installs a global `dnslookup` command
dnslookup query example.com
dnslookup email example.com
```

To run from the source tree without installing:

```bash
uv sync
uv run python -m dnslookup email example.com
```

## Commands

| Command | Description |
|---|---|
| `dnslookup query DOMAIN [-t TYPE…]` | Query records (default A, AAAA, MX, NS, TXT, CNAME, SOA; `-t ALL` for every type) |
| `dnslookup reverse IP [IP…]` | Reverse (PTR) lookup |
| `dnslookup trace DOMAIN [-t A]` | Iterative trace from the root servers |
| `dnslookup batch FILE [-t A,MX] [-w 16]` | Concurrent lookups for a list of domains (`-` reads from stdin) |
| `dnslookup whois DOMAIN [--raw]` | WHOIS registration data |
| `dnslookup email DOMAIN [-S selector…]` | Full email security audit with score and grade |
| `dnslookup mx DOMAIN` | MX checks only |
| `dnslookup spf DOMAIN` | SPF validation and include tree |
| `dnslookup dkim DOMAIN [-S selector…] [--only-selectors]` | DKIM key discovery and analysis |
| `dnslookup dmarc DOMAIN` | DMARC policy check |

Common options: `--server/-s 1.1.1.1` (use a specific resolver), `--timeout 5`, `--json/-j`.

### Examples

```bash
dnslookup query github.com -t MX -t TXT
dnslookup query cloudflare.com -t ALL --server 1.1.1.1
dnslookup trace www.github.com
dnslookup spf salesforce.com
dnslookup dkim yourcompany.com -S s1 -S mycustomselector
dnslookup email yourcompany.com --json | jq '.grade, .score'
printf "github.com\ncloudflare.com\n" | dnslookup batch - -t A,MX
```

### Finding your DKIM selector

DKIM keys live at `<selector>._domainkey.<domain>`. DNS has no way to list them, so the tool probes common selectors. If yours is custom, open any email you sent, find the `DKIM-Signature:` header, and pass its `s=` value with `-S`.

## Scoring

| Section | Weight |
|---|---|
| MX | 15 |
| SPF | 30 |
| DKIM | 25 |
| DMARC | 30 |

A ✖ finding zeroes its section, and each ⚠ removes about 25% of it. For a Null MX domain, which accepts no mail, DKIM isn't scored and the points go to SPF and DMARC. Grades: **A** ≥ 90, **B** ≥ 80, **C** ≥ 65, **D** ≥ 50, otherwise **F**. The `email` command exits with code 1 on an F, so it can gate CI.

## Development

```bash
uv sync
uv run python -m pytest        # offline unit tests using an in-memory fake DNS zone
```

Project layout:

```
dnslookup/
  resolver.py        DNS client (dnspython), reverse, batch, iterative trace
  email_security.py  MX / SPF / DKIM / DMARC / MTA-STS checks and scoring
  whois.py           WHOIS client with referral following
  output.py          Rich rendering + JSON export
  cli.py             Typer commands
tests/               46 unit tests
```

> **macOS note:** if `uv run dnslookup` fails with `No module named 'dnslookup'`, macOS has set the "hidden" flag on uv's editable-install `.pth` file, and Python skips hidden `.pth` files. Use `uv run python -m dnslookup …` or `uv tool install .`, or run `uv sync --no-editable`.
