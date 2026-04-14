# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-04-13

### Added

- **Multi-source CVE lookup** — NVD + OSV with automatic deduplication and cross-source confirmation
- **Five input modes** — URL (live HTTP header fetch), HTTP header string, service banner, version string, Nmap XML file
- **Batch scanning** — newline-delimited targets file with automatic input-type detection
- **Exploit signal enrichment** — CISA KEV, public PoC, and ExploitDB cross-referencing per finding
- **Three-tier disposition system** — Actionable, Needs Validation, Context
- **Scoring engine** — composite score from match strength + exploit signals
- **Stack analysis** — multi-component fingerprinting, evidence tree, and stack summary
- **Report formats** — rich terminal table (via `rich`), JSON, and Markdown
- **Cache management** — bundled KEV and ExploitDB snapshots; `--update` flag for refresh
- **Filtering** — `--mode` (strict/broad), `--confidence`, and `--top` flags
- **Protocol-level context findings** — protocol abuse surface identified separately from product matches
- **Validation hints** — per-finding ATT&CK-style surface, auth requirement, and next-check guidance

[1.0.0]: https://github.com/JashanCybersec/talon/releases/tag/v1.0.0
