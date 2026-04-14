import argparse
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

try:
    from .extractors import (
        extract_from_banner,
        extract_from_headers,
        extract_from_nmap,
        extract_from_nmap_xml,
        extract_from_url,
        looks_like_nmap_xml,
    )
    from .extractors.normalize import extract_version_value, looks_like_version, normalize_service, parse_product_version
    from .engine import build_finding, determine_match_strength, filter_findings, label_for_score, score_result
    from .engine.stack import build_stack_components, summarize_target
    from .output import (
        print_batch_results,
        print_results_table,
        write_json_batch_report,
        write_json_report,
        write_markdown_batch_report,
        write_markdown_report,
    )
    from .sources import ExploitDBSource, KEVSource, NVDSource, OSVSource, PoCSource
except ImportError:
    from extractors import (
        extract_from_banner,
        extract_from_headers,
        extract_from_nmap,
        extract_from_nmap_xml,
        extract_from_url,
        looks_like_nmap_xml,
    )
    from extractors.normalize import extract_version_value, looks_like_version, normalize_service, parse_product_version
    from engine import build_finding, determine_match_strength, filter_findings, label_for_score, score_result
    from engine.stack import build_stack_components, summarize_target
    from output import (
        print_batch_results,
        print_results_table,
        write_json_batch_report,
        write_json_report,
        write_markdown_batch_report,
        write_markdown_report,
    )
    from sources import ExploitDBSource, KEVSource, NVDSource, OSVSource, PoCSource


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"


def _get_version() -> str:
    try:
        from . import __version__
    except ImportError:
        try:
            from __init__ import __version__
        except ImportError:
            __version__ = "1.0.0"
    return __version__


VERSION = _get_version()

EXAMPLES = """\
examples:
  talon --url https://example.com              Scan a live URL
  talon --header "Server: nginx/1.18.0"        Parse a header string
  talon --version "apache 2.4.49"              Check a known version
  talon --banner "OpenSSH_8.2p1 Ubuntu"        Parse a service banner
  talon --nmap scan.xml                        Analyze Nmap XML output
  talon targets.txt                            Batch scan from file
  talon --url https://example.com -o json      Save JSON report
  talon --update                               Refresh CVE caches
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="talon",
        description="Talon — fast CVE triage from service fingerprints.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--app-version", action="version", version=f"talon {VERSION}")

    input_group = parser.add_argument_group("input modes")
    input_group.add_argument("-H", "--header", action="append", help='HTTP header string  (e.g. "Server: nginx/1.18.0"); may be repeated')
    input_group.add_argument("-u", "--url", help="URL to fetch and inspect headers from")
    input_group.add_argument("-n", "--nmap", help="Nmap XML output file")
    input_group.add_argument("-v", "--version", action="append", help='Service version string  (e.g. "apache 2.4.49"); may be repeated')
    input_group.add_argument("-b", "--banner", action="append", help='Service banner  (e.g. "OpenSSH_8.2p1 Ubuntu"); may be repeated')
    input_group.add_argument("-s", "--service", help='Explicit service name  (e.g. "apache")')
    input_group.add_argument(
        "targets_file",
        nargs="?",
        help="Newline-delimited targets file or Nmap XML file",
    )

    filter_group = parser.add_argument_group("filtering")
    filter_group.add_argument("-t", "--top", type=int, default=10, help="Max results to display (default: 10)")
    filter_group.add_argument(
        "-m", "--mode",
        choices=["strict", "broad"],
        default="strict",
        help="strict = high/medium confidence; broad = include low/context (default: strict)",
    )
    filter_group.add_argument(
        "-c", "--confidence",
        choices=["high", "medium", "low"],
        help="Minimum confidence threshold (default: medium)",
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument("-o", "--output", choices=["json", "md", "all"], help="Save report to disk")
    output_group.add_argument("--no-color", action="store_true", help="Disable terminal colors")
    verbosity = output_group.add_mutually_exclusive_group(required=False)
    verbosity.add_argument("-q", "--quiet", action="store_true", help="Suppress warnings")
    verbosity.add_argument("--verbose", action="store_true", help="Show debug output for API calls")

    parser.add_argument("--update", action="store_true", help="Refresh KEV, ExploitDB and PoC caches")
    return parser


def parse_version_string(version_string: str, service_hint: str = "") -> Dict[str, str]:
    if not version_string.strip():
        return {
            "service": "unknown",
            "version": "",
            "raw": version_string,
            "source": "version",
            "warning": "Empty version string; continuing with service name only.",
        }

    normalized_service_hint = normalize_service(service_hint) if service_hint else ""
    if normalized_service_hint:
        version = extract_version_value(version_string)
        finding = {"service": normalized_service_hint, "version": version, "raw": version_string, "source": "version"}
        if not version:
            finding["warning"] = "Version not found in plain version string; continuing with service name only."
        return finding

    if looks_like_version(version_string.strip()):
        return {
            "service": "unknown",
            "version": version_string.strip(),
            "raw": version_string,
            "source": "version",
            "warning": "Version-only input requires --service for accurate matching.",
        }

    service, version = parse_product_version(version_string)
    finding = {"service": service, "version": version, "raw": version_string, "source": "version"}
    if not version:
        finding["warning"] = "Version not found in plain version string; continuing with service name only."
    return finding


def collect_findings(args: argparse.Namespace) -> Tuple[List[Dict[str, str]], List[Tuple[str, str]]]:
    findings: List[Dict[str, str]] = []
    raw_inputs: List[Tuple[str, str]] = []

    for header_raw in (args.header or []):
        header_blob = header_raw.replace("\\n", "\n")
        raw_inputs.append(("header", header_blob))
        findings.extend(_tag_input_mode(_apply_service_hint(extract_from_headers(header_blob), args.service or ""), "header"))

    if args.url:
        raw_inputs.append(("url", args.url))
        url_findings = _tag_input_mode(_apply_service_hint(extract_from_url(args.url), args.service or ""), "url")
        findings.extend(url_findings)
        _append_finding_evidence(raw_inputs, "url", url_findings, exclude_values={args.url})

    if args.nmap:
        raw_inputs.append(("nmap", args.nmap))
        findings.extend(_tag_input_mode(_apply_service_hint(extract_from_nmap(args.nmap), args.service or ""), "nmap"))

    nmap_xml = getattr(args, "nmap_xml", "")
    nmap_source = getattr(args, "nmap_source", "")
    if nmap_xml:
        raw_inputs.append(("nmap", nmap_source or "stdin:nmap"))
        findings.extend(
            _tag_input_mode(
                _apply_service_hint(extract_from_nmap_xml(nmap_xml, source_label=nmap_source or "stdin:nmap"), args.service or ""),
                "nmap",
            )
        )

    for version_str in (args.version or []):
        raw_inputs.append(("version", version_str))
        findings.extend(_tag_input_mode([parse_version_string(version_str, args.service or "")], "version"))

    for banner_str in (args.banner or []):
        raw_inputs.append(("banner", banner_str))
        findings.extend(_tag_input_mode(_apply_service_hint(extract_from_banner(banner_str), args.service or ""), "banner"))

    if not raw_inputs:
        raise ValueError("No input mode selected")
    return findings, raw_inputs


def refresh_caches(kev: KEVSource, exploitdb: ExploitDBSource, poc: PoCSource) -> List[str]:
    messages = []
    messages.append("KEV cache updated." if kev.update() else "KEV update failed; using local cache if available.")
    messages.append(
        "ExploitDB cache updated." if exploitdb.update() else "ExploitDB update failed; using local cache if available."
    )
    messages.append("PoC cache cleared (stale negatives removed)." if poc.update() else "PoC cache clear failed.")
    return messages


def load_targets_file(targets_file: str) -> List[str]:
    path = Path(targets_file)
    if not path.is_file():
        raise FileNotFoundError(f"Targets file not found: {targets_file}")

    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        targets.append(candidate)

    if not targets:
        raise ValueError(f"Targets file contained no scan targets: {targets_file}")
    return targets


def load_nmap_file(path: str) -> argparse.Namespace:
    return argparse.Namespace(
        header=None,
        url=None,
        nmap=path,
        nmap_xml=None,
        nmap_source=None,
        version=None,
        banner=None,
        service=None,
    )


def load_nmap_stdin(stdin_text: str, source_label: str = "stdin:nmap") -> argparse.Namespace:
    return argparse.Namespace(
        header=None,
        url=None,
        nmap=None,
        nmap_xml=stdin_text,
        nmap_source=source_label,
        version=None,
        banner=None,
        service=None,
    )


def is_nmap_xml_file(path: str) -> bool:
    file_path = Path(path)
    if not file_path.is_file():
        return False
    if file_path.suffix.lower() == ".xml":
        return True
    try:
        head = file_path.read_text(encoding="utf-8", errors="ignore")[:4096]
    except OSError:
        return False
    return looks_like_nmap_xml(head)


def analyze_target(
    component: Dict[str, str],
    nvd: NVDSource,
    osv: OSVSource,
    kev: KEVSource,
    poc: PoCSource,
    exploitdb: ExploitDBSource,
) -> List[Dict]:
    service = component["service"]
    version = component.get("version", "")
    if not service or service == "unknown":
        return []

    nvd_cves = nvd.search(service, version)
    osv_cves = osv.query(service, version)

    seen_ids: Dict[str, Dict] = {}
    for cve in nvd_cves:
        seen_ids[cve["cve_id"]] = {**cve, "osv_hit": False}
    for cve in osv_cves:
        existing = seen_ids.get(cve["cve_id"])
        if existing:
            existing["osv_hit"] = True
            existing["source"] = "nvd+osv"
        else:
            seen_ids[cve["cve_id"]] = {**cve, "osv_hit": True}

    matched_candidates = []
    for cve in seen_ids.values():
        match_label, match_points, include = determine_match_strength(service, version, cve)
        if include:
            matched_candidates.append((cve, match_label, match_points))

    if not matched_candidates:
        return []

    cve_ids = [cve["cve_id"] for cve, _, _ in matched_candidates]
    poc_hits = poc.batch_has_poc(cve_ids)

    scored_results: List[Dict] = []
    for cve, match_label, match_points in matched_candidates:
        cve_id_upper = cve["cve_id"].upper()
        has_kev = kev.has_cve(cve["cve_id"])
        has_poc = poc_hits.get(cve_id_upper, False)
        has_edb = exploitdb.has_cve(cve["cve_id"])
        score = score_result(match_points, has_kev, has_poc, has_edb)
        scored_results.append(
            build_finding(
                component,
                cve,
                match_label,
                score,
                has_kev,
                has_poc,
                has_edb,
                label_for_score(score),
            )
        )

    scored_results.sort(key=lambda item: (item["score"], item["cvss"]), reverse=True)
    return scored_results


def execute_scan(
    findings: List[Dict[str, str]],
    raw_inputs: List[Tuple[str, str]],
    mode: str,
    confidence: str,
    top: int,
    nvd: NVDSource,
    osv: OSVSource,
    kev: KEVSource,
    poc: PoCSource,
    exploitdb: ExploitDBSource,
) -> Dict:
    warnings = [finding.get("warning") for finding in findings if finding.get("warning")]
    components = build_stack_components(findings, raw_inputs)
    target = summarize_target(components, raw_inputs)

    all_results: List[Dict] = []
    for component in components:
        if not component.get("query", component.get("analyze", True)):
            continue
        all_results.extend(analyze_target(component, nvd, osv, kev, poc, exploitdb))

    ranked_results = _dedupe_and_rank_results(all_results)
    filtered_results, effective_min_confidence = filter_findings(
        ranked_results,
        mode=mode,
        min_confidence=confidence,
    )
    final_results = filtered_results[:top]

    status_message = ""
    if not final_results:
        if ranked_results:
            status_message = "No findings matched the selected mode/confidence filters."
        else:
            status_message = "No findings matched or network sources were unavailable."

    return {
        "target": target,
        "components": components,
        "warnings": [warning for warning in warnings if warning],
        "ranked_findings": ranked_results,
        "findings": final_results,
        "effective_min_confidence": effective_min_confidence,
        "status_message": status_message,
    }


def save_reports(
    target: str,
    components: List[Dict],
    results: List[Dict],
    output_mode: str,
    scan_mode: str,
    min_confidence: str,
) -> List[Path]:
    paths: List[Path] = []
    cwd = Path.cwd()
    if output_mode in {"json", "all"}:
        paths.append(
            write_json_report(
                target,
                components,
                results,
                cwd / "talon-report.json",
                mode=scan_mode,
                min_confidence=min_confidence,
            )
        )
    if output_mode in {"md", "all"}:
        paths.append(
            write_markdown_report(
                target,
                components,
                results,
                cwd / "talon-report.md",
                mode=scan_mode,
                min_confidence=min_confidence,
            )
        )
    return paths


def save_batch_reports(
    scans: List[Dict],
    summary: Dict,
    output_mode: str,
    scan_mode: str,
    min_confidence: str,
) -> List[Path]:
    paths: List[Path] = []
    cwd = Path.cwd()
    if output_mode in {"json", "all"}:
        paths.append(
            write_json_batch_report(
                scans,
                summary,
                cwd / "talon-report.json",
                mode=scan_mode,
                min_confidence=min_confidence,
            )
        )
    if output_mode in {"md", "all"}:
        paths.append(
            write_markdown_batch_report(
                scans,
                summary,
                cwd / "talon-report.md",
                mode=scan_mode,
                min_confidence=min_confidence,
            )
        )
    return paths


def _apply_service_hint(findings: List[Dict[str, str]], service_hint: str) -> List[Dict[str, str]]:
    normalized_hint = normalize_service(service_hint) if service_hint else ""
    if not normalized_hint:
        return findings

    updated: List[Dict[str, str]] = []
    for finding in findings:
        service = normalize_service(finding.get("service", ""))
        if service in {"", "unknown"}:
            updated.append({**finding, "service": normalized_hint})
        else:
            updated.append(finding)
    return updated


def _tag_input_mode(findings: List[Dict[str, str]], input_mode: str) -> List[Dict[str, str]]:
    tagged = []
    for finding in findings:
        evidence_record = finding.get("evidence_record") or {
            "source": input_mode,
            "field": finding.get("header_name", ""),
            "raw": finding.get("evidence") if input_mode == "inference" else finding.get("raw", ""),
            "direct": input_mode != "inference",
        }
        tagged.append({**finding, "input_mode": input_mode, "evidence_record": evidence_record})
    return tagged


def _append_finding_evidence(
    raw_inputs: List[Tuple[str, str]],
    input_mode: str,
    findings: Sequence[Dict[str, str]],
    exclude_values: Sequence[str] = (),
) -> None:
    seen_values = {value for _, value in raw_inputs}
    excluded = {value for value in exclude_values if value}
    for finding in findings:
        evidence_value = ""
        for key in ("raw_headers", "raw"):
            candidate = str(finding.get(key, "")).strip()
            if candidate:
                evidence_value = candidate
                break
        if not evidence_value or evidence_value in seen_values or evidence_value in excluded:
            continue
        raw_inputs.append((f"{input_mode}-evidence", evidence_value))
        seen_values.add(evidence_value)


def _merge_component_references(existing: Sequence[Dict[str, str]], incoming: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    merged: Dict[Tuple[str, str], Dict[str, str]] = {}
    for reference in list(existing) + list(incoming):
        key = (reference.get("service", ""), reference.get("version", ""))
        if key not in merged:
            merged[key] = reference
    return sorted(merged.values(), key=lambda item: (item.get("service", ""), item.get("version", "")))


def _component_display(references: Sequence[Dict[str, str]]) -> str:
    labels: List[str] = []
    for reference in references:
        label = " ".join(part for part in [reference.get("service", ""), reference.get("version", "")] if part).strip()
        if label and label not in labels:
            labels.append(label)
    if len(labels) <= 2:
        return ", ".join(labels)
    return ", ".join(labels[:2]) + f" +{len(labels) - 2}"


def _merge_records(
    existing: Sequence[Dict[str, object]],
    incoming: Sequence[Dict[str, object]],
    keys: Sequence[str],
) -> List[Dict[str, object]]:
    merged: Dict[Tuple[object, ...], Dict[str, object]] = {}
    for record in list(existing) + list(incoming):
        key = tuple(record.get(name) for name in keys)
        if key not in merged:
            merged[key] = record
    return list(merged.values())


def _merge_reasoning(existing: Sequence[str], incoming: Sequence[str]) -> List[str]:
    merged: List[str] = []
    for value in list(existing) + list(incoming):
        if value and value not in merged:
            merged.append(value)
    return merged


def _apply_protocol_finding_shape(finding: Dict, merged_components: Sequence[Dict[str, object]]) -> None:
    protocol_targets = _component_display(merged_components)
    finding["matched_by"] = "protocol"
    finding["match"] = "Protocol"
    finding["confidence"] = "low"
    finding["confidence_rank"] = 1
    finding["disposition"] = "context"
    finding["component"] = "protocol"
    finding["service"] = "protocol"
    finding["target_component"] = "protocol"
    finding["component_display"] = f"protocol: {protocol_targets}" if protocol_targets else "protocol"

    validation = finding.get("validation", {})
    validation.update(
        {
            "category": "protocol abuse",
            "surface": validation.get("surface", "edge protocol interface"),
            "auth": "none",
            "hint": "Verify the exposed protocol path on the front-end edge and confirm which observed components negotiate it.",
        }
    )
    finding["validation"] = validation
    finding["reasoning"] = _merge_reasoning(
        finding.get("reasoning", []),
        [f"Protocol-level context affects: {protocol_targets}." if protocol_targets else "Protocol-level context affects multiple observed components."],
    )
    finding["why"] = f"protocol via {protocol_targets}" if protocol_targets else "protocol via multiple observed components"


def _make_debug_logger(enabled: bool):
    def log(message: str) -> None:
        if enabled:
            print(f"[debug] {message}", file=sys.stderr)
    return log


def _dedupe_and_rank_results(all_results: Sequence[Dict]) -> List[Dict]:
    deduped: Dict[str, Dict] = {}
    for result in all_results:
        existing = deduped.get(result["cve_id"])
        if not existing:
            deduped[result["cve_id"]] = result
            continue

        merged_components = _merge_component_references(
            existing.get("affected_components", []),
            result.get("affected_components", []),
        )
        merged_evidence = _merge_records(existing.get("evidence", []), result.get("evidence", []), ("source", "field", "raw"))
        merged_reasoning = _merge_reasoning(existing.get("reasoning", []), result.get("reasoning", []))
        has_protocol = existing.get("matched_by") == "protocol" or result.get("matched_by") == "protocol"
        if (result["score"], result["cvss"]) > (existing["score"], existing["cvss"]):
            winner = {**result}
            winner["affected_components"] = merged_components
            winner["component_display"] = _component_display(merged_components)
            winner["evidence"] = merged_evidence
            winner["reasoning"] = merged_reasoning
            if has_protocol:
                _apply_protocol_finding_shape(winner, merged_components)
            deduped[result["cve_id"]] = winner
        else:
            existing["affected_components"] = merged_components
            existing["component_display"] = _component_display(merged_components)
            existing["evidence"] = merged_evidence
            existing["reasoning"] = merged_reasoning
            if has_protocol:
                _apply_protocol_finding_shape(existing, merged_components)

    for finding in deduped.values():
        if finding.get("matched_by") == "protocol":
            _apply_protocol_finding_shape(finding, finding.get("affected_components", []))

    return sorted(deduped.values(), key=lambda item: (item["score"], item["cvss"]), reverse=True)


_BATCH_HEADER_NAMES = {
    "server", "x-powered-by", "x-powered-by-plesk", "x-generator",
    "x-aspnet-version", "x-aspnetmvc-version",
}


def _classify_batch_target(target: str) -> str:
    """Detect whether a batch target line is a url, banner, header, or version string."""
    # Explicit URL scheme
    if "://" in target:
        return "url"
    # SSH banner (SSH-2.0-OpenSSH_8.2p1 ...)
    if re.match(r"^SSH-\d", target, re.IGNORECASE):
        return "banner"
    # FTP/SMTP/generic numeric response code (220, 230, 502, ...)
    if re.match(r"^\d{3}[\s-]", target):
        return "banner"
    # HTTP header string: "Header-Name: value" or known header names
    m = re.match(r"^([A-Za-z][A-Za-z0-9\-]*)\s*:\s*\S", target)
    if m:
        header_name = m.group(1).lower()
        if header_name in _BATCH_HEADER_NAMES or "-" in header_name:
            return "header"
    # IP address (with optional port/path)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", target):
        return "url"
    # Hostname / domain: strip path+port, check for alphabetic TLD
    hostname = target.split("/")[0].split(":")[0]
    if hostname.lower() == "localhost":
        return "url"
    if "." in hostname:
        parts = hostname.split(".")
        if parts[-1].isalpha() and len(parts[-1]) >= 2:
            return "url"
    # Anything else: treat as a version/service string
    return "version"


def _build_batch_args(target: str) -> argparse.Namespace:
    target_type = _classify_batch_target(target)
    if target_type == "banner":
        return argparse.Namespace(
            header=None, url=None, nmap=None, nmap_xml=None, nmap_source=None,
            version=None, banner=[target], service=None,
        )
    if target_type == "header":
        return argparse.Namespace(
            header=[target], url=None, nmap=None, nmap_xml=None, nmap_source=None,
            version=None, banner=None, service=None,
        )
    if target_type == "version":
        return argparse.Namespace(
            header=None, url=None, nmap=None, nmap_xml=None, nmap_source=None,
            version=[target], banner=None, service=None,
        )
    # url
    return argparse.Namespace(
        header=None, url=target, nmap=None, nmap_xml=None, nmap_source=None,
        version=None, banner=None, service=None,
    )


def _print_warnings(warnings: Sequence[str], quiet: bool, target_label: str = "") -> None:
    if quiet:
        return
    prefix = f"Warning [{target_label}]" if target_label else "Warning"
    for warning in warnings:
        print(f"{prefix}: {warning}", file=sys.stderr)


def summarize_batch_scans(scans: Sequence[Dict]) -> Dict:
    by_disposition = {"actionable": 0, "needs_validation": 0, "context": 0}
    for scan in scans:
        for finding in scan.get("findings", []):
            disposition = finding.get("disposition", "needs_validation")
            by_disposition[disposition] = by_disposition.get(disposition, 0) + 1

    return {
        "targets_scanned": len(scans),
        "targets_with_findings": sum(1 for scan in scans if scan.get("findings")),
        "targets_with_actionable": sum(
            1 for scan in scans if any(finding.get("disposition") == "actionable" for finding in scan.get("findings", []))
        ),
        "findings_total": sum(len(scan.get("findings", [])) for scan in scans),
        "by_disposition": by_disposition,
    }


def _format_elapsed(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.1f}s"


def main() -> int:
    t_start = time.monotonic()
    parser = build_parser()
    args = parser.parse_args()

    if args.top < 1:
        parser.error("--top must be at least 1")

    explicit_inputs = [args.header, args.url, args.nmap, args.version, args.banner]
    if args.targets_file and (any(explicit_inputs) or args.service):
        parser.error("targets_file cannot be combined with --header, --url, --nmap, --version, --banner, or --service")

    debug = _make_debug_logger(args.verbose)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    kev = KEVSource(DATA_DIR, logger=debug)
    poc = PoCSource(DATA_DIR, logger=debug)
    exploitdb = ExploitDBSource(DATA_DIR, logger=debug)
    nvd = NVDSource(DATA_DIR, logger=debug)
    osv = OSVSource(DATA_DIR, logger=debug)

    if args.update:
        for message in refresh_caches(kev, exploitdb, poc):
            if not args.quiet:
                print(message)
        if not any(explicit_inputs) and not args.targets_file:
            return 0

    stdin_text = ""
    if not any(explicit_inputs) and not args.targets_file and not sys.stdin.isatty():
        stdin_text = sys.stdin.read()
        if not stdin_text.strip():
            stdin_text = ""

    if args.targets_file and is_nmap_xml_file(args.targets_file):
        findings, raw_inputs = collect_findings(load_nmap_file(args.targets_file))
        scan = execute_scan(
            findings,
            raw_inputs,
            args.mode,
            args.confidence,
            args.top,
            nvd,
            osv,
            kev,
            poc,
            exploitdb,
        )
        _print_warnings(scan.get("warnings", []), args.quiet)

        print_results_table(
            scan["target"],
            scan["findings"],
            components=scan["components"],
            no_color=args.no_color,
            mode=args.mode,
            min_confidence=scan["effective_min_confidence"],
            status_message=scan["status_message"],
            elapsed=_format_elapsed(time.monotonic() - t_start),
        )

        if args.output:
            paths = save_reports(
                scan["target"],
                scan["components"],
                scan["findings"],
                args.output,
                args.mode,
                scan["effective_min_confidence"],
            )
            for path in paths:
                print(f"Saved report: {path}")
        return 0

    if stdin_text:
        if not looks_like_nmap_xml(stdin_text):
            parser.error("stdin input was provided, but it did not look like Nmap XML")

        findings, raw_inputs = collect_findings(load_nmap_stdin(stdin_text))
        scan = execute_scan(
            findings,
            raw_inputs,
            args.mode,
            args.confidence,
            args.top,
            nvd,
            osv,
            kev,
            poc,
            exploitdb,
        )
        _print_warnings(scan.get("warnings", []), args.quiet)

        print_results_table(
            scan["target"],
            scan["findings"],
            components=scan["components"],
            no_color=args.no_color,
            mode=args.mode,
            min_confidence=scan["effective_min_confidence"],
            status_message=scan["status_message"],
            elapsed=_format_elapsed(time.monotonic() - t_start),
        )

        if args.output:
            paths = save_reports(
                scan["target"],
                scan["components"],
                scan["findings"],
                args.output,
                args.mode,
                scan["effective_min_confidence"],
            )
            for path in paths:
                print(f"Saved report: {path}")
        return 0

    if args.targets_file:
        try:
            targets = load_targets_file(args.targets_file)
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))

        scans: List[Dict] = []
        for target_input in targets:
            findings, raw_inputs = collect_findings(_build_batch_args(target_input))
            scan = execute_scan(
                findings,
                raw_inputs,
                args.mode,
                args.confidence,
                args.top,
                nvd,
                osv,
                kev,
                poc,
                exploitdb,
            )
            scan["input_target"] = target_input
            scans.append(scan)
            _print_warnings(scan.get("warnings", []), args.quiet, target_input)

        effective_min_confidence = scans[0]["effective_min_confidence"] if scans else (args.confidence or "medium")
        summary = summarize_batch_scans(scans)
        print_batch_results(
            scans,
            summary,
            no_color=args.no_color,
            mode=args.mode,
            min_confidence=effective_min_confidence,
            elapsed=_format_elapsed(time.monotonic() - t_start),
        )

        if args.output:
            paths = save_batch_reports(scans, summary, args.output, args.mode, effective_min_confidence)
            for path in paths:
                print(f"Saved report: {path}")
        return 0

    if not any(explicit_inputs):
        parser.error("at least one of --header, --url, --nmap, --version, or --banner is required unless using --update")

    findings, raw_inputs = collect_findings(args)
    scan = execute_scan(
        findings,
        raw_inputs,
        args.mode,
        args.confidence,
        args.top,
        nvd,
        osv,
        kev,
        poc,
        exploitdb,
    )
    _print_warnings(scan.get("warnings", []), args.quiet)

    print_results_table(
        scan["target"],
        scan["findings"],
        components=scan["components"],
        no_color=args.no_color,
        mode=args.mode,
        min_confidence=scan["effective_min_confidence"],
        status_message=scan["status_message"],
        elapsed=_format_elapsed(time.monotonic() - t_start),
    )

    if args.output:
        paths = save_reports(
            scan["target"],
            scan["components"],
            scan["findings"],
            args.output,
            args.mode,
            scan["effective_min_confidence"],
        )
        for path in paths:
            print(f"Saved report: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
