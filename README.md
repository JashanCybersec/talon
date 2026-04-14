# Talon

**Fast CVE triage from service fingerprints.**

Talon identifies known vulnerabilities in your exposed services by analyzing HTTP headers, service banners, Nmap scan output, or raw version strings — and cross-references them against NVD, OSV, CISA KEV, ExploitDB, and public PoC databases to produce a prioritized, actionable report.

---

## Features

- **Multiple input modes** — URL, HTTP header, service banner, version string, Nmap XML, or batch file
- **Multi-source CVE lookup** — NVD + OSV with automatic deduplication
- **Exploit signal enrichment** — flags CISA KEV, public PoC, and ExploitDB hits
- **Actionable triage** — findings grouped as *Actionable*, *Needs Validation*, or *Context*
- **Batch scanning** — scan hundreds of targets from a newline-delimited file
- **Reports** — rich terminal table, JSON, and Markdown output formats
- **Offline-capable** — cached KEV and ExploitDB datasets ship with the tool

---

## Installation

**From PyPI** *(recommended)*:
```bash
pip install talon
```

**From source** (editable install):
```bash
git clone https://github.com/JashanCybersec/talon.git
cd Talon
pip install -e .
```

**Requirements:** Python ≥ 3.9

---

## Quick Start

```bash
# Scan a live URL
talon --url https://example.com

# Parse an HTTP header string
talon --header "Server: nginx/1.18.0"

# Check a known service version
talon --version "apache 2.4.49"

# Parse a service banner
talon --banner "OpenSSH_8.2p1 Ubuntu"

# Analyze Nmap XML output
talon --nmap scan.xml

# Batch scan from a targets file
talon targets.txt

# Save reports to disk
talon --url https://example.com --output json
talon --url https://example.com --output md
talon --url https://example.com --output all

# Refresh KEV and ExploitDB caches
talon --update
```

---

## Input Modes

| Flag | Description | Example |
|---|---|---|
| `-u / --url` | Fetch live HTTP headers from a URL | `talon -u https://example.com` |
| `-H / --header` | Parse a raw HTTP header string | `talon -H "Server: nginx/1.18.0"` |
| `-b / --banner` | Parse a service banner | `talon -b "OpenSSH_8.2p1"` |
| `-v / --version` | Check a version string directly | `talon -v "apache 2.4.49"` |
| `-s / --service` | Hint the service name | `talon -v "2.4.49" -s apache` |
| `-n / --nmap` | Analyze an Nmap XML file | `talon -n scan.xml` |
| `targets_file` | Batch mode — newline-delimited file | `talon targets.txt` |

Flags `-H`, `-b`, and `-v` can be repeated for multi-component scans.

---

## Filtering

| Flag | Description | Default |
|---|---|---|
| `-m / --mode` | `strict` (high/medium) or `broad` (include low/context) | `strict` |
| `-c / --confidence` | Minimum confidence: `high`, `medium`, `low` | `medium` |
| `-t / --top` | Max findings to display | `10` |

---

## Output Flags

| Flag | Description |
|---|---|
| `-o / --output json` | Write `talon-report.json` to the current directory |
| `-o / --output md` | Write `talon-report.md` to the current directory |
| `-o / --output all` | Write both |
| `--no-color` | Disable terminal colors |
| `-q / --quiet` | Suppress warnings |
| `--verbose` | Show debug output for API calls |

---

## Batch Mode

Create a newline-delimited file where each line is a URL, IP, header, banner, or version string:

```text
https://example.com
nginx/1.18.0
OpenSSH_8.2p1 Ubuntu
Server: Apache/2.4.49 (Unix)
192.168.1.1
```

```bash
talon targets.txt
talon targets.txt --output json
```

Lines starting with `#` are treated as comments and skipped.

---

## Cache Updates

Talon ships with bundled KEV and ExploitDB snapshots. Refresh them with:

```bash
talon --update
```

NVD and OSV are queried live; no API key is required for basic usage (NVD rate-limits apply).

---

## Report Formats

### Terminal (default)
Rich, color-coded table with component stack, evidence tree, and findings grouped by disposition.

### JSON (`--output json`)
Machine-readable report at `talon-report.json` — includes full CVE metadata, evidence records, reasoning chains, and validation hints.

### Markdown (`--output md`)
Shareable `talon-report.md` ready for inclusion in audit documents or GitHub issues.

---

## Finding Dispositions

| Disposition | Meaning |
|---|---|
| **Actionable** | High/medium confidence version match — patch or mitigate now |
| **Needs Validation** | Service matched but version unconfirmed — verify before acting |
| **Context** | Protocol-level context — informs the attack surface |

---

## Scoring Signals

Each finding is scored based on:

- **Match strength** — exact version, CPE range, service-level, or description match
- **KEV** — CISA Known Exploited Vulnerabilities catalog
- **PoC** — public proof-of-concept available
- **EDB** — ExploitDB exploit entry

---

## License

MIT — see [LICENSE](LICENSE).
