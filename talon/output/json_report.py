import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

try:
    from .. import __version__
    from ..engine.findings import split_findings_by_disposition
    from ..engine.stack import evidence_tree_lines, summarize_stack
except ImportError:
    try:
        from __init__ import __version__
    except ImportError:
        __version__ = "1.0.0"
    from engine.findings import split_findings_by_disposition
    from engine.stack import evidence_tree_lines, summarize_stack


def write_json_report(
    target: str,
    components: List[Dict],
    results: List[Dict],
    output_path: Path,
    mode: str = "strict",
    min_confidence: str = "medium",
) -> Path:
    payload = {
        "version": f"talon {__version__}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "filters": {
            "mode": mode,
            "min_confidence": min_confidence,
        },
        "stack": {
            "summary": summarize_stack(components),
            "ordered_components": [component.get("service", "") for component in components],
            "evidence_tree": evidence_tree_lines(components),
        },
        "components": components,
        "findings": results,
        "results": results,
        "sections": split_findings_by_disposition(results),
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def write_json_batch_report(
    scans: List[Dict],
    summary: Dict,
    output_path: Path,
    mode: str = "strict",
    min_confidence: str = "medium",
) -> Path:
    payload = {
        "version": f"talon {__version__}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "type": "batch",
        "filters": {
            "mode": mode,
            "min_confidence": min_confidence,
        },
        "summary": summary,
        "targets": [_scan_payload(scan) for scan in scans],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def _scan_payload(scan: Dict) -> Dict:
    components = scan.get("components", [])
    findings = scan.get("findings", [])
    return {
        "input_target": scan.get("input_target", scan.get("target", "")),
        "target": scan.get("target", ""),
        "status_message": scan.get("status_message", ""),
        "warnings": scan.get("warnings", []),
        "stack": {
            "summary": summarize_stack(components),
            "ordered_components": [component.get("service", "") for component in components],
            "evidence_tree": evidence_tree_lines(components),
        },
        "components": components,
        "findings": findings,
        "sections": split_findings_by_disposition(findings),
    }
