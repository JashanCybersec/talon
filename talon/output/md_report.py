from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

try:
    from .. import __version__
    from ..engine.findings import DISPOSITION_TITLES, split_findings_by_disposition
    from ..engine.stack import evidence_tree_lines, summarize_stack
except ImportError:
    try:
        from __init__ import __version__
    except ImportError:
        __version__ = "1.0.0"
    from engine.findings import DISPOSITION_TITLES, split_findings_by_disposition
    from engine.stack import evidence_tree_lines, summarize_stack


def write_markdown_report(
    target: str,
    components: List[Dict],
    results: List[Dict],
    output_path: Path,
    mode: str = "strict",
    min_confidence: str = "medium",
) -> Path:
    stack_summary = summarize_stack(components)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Talon v{__version__}",
        "",
        f"**Date:** {timestamp}",
        f"**Target:** `{target}`",
        f"**Mode:** `{mode}`",
        f"**Minimum confidence:** `{min_confidence}`",
        "",
    ]
    if stack_summary:
        lines.extend([
            f"Stack: `{stack_summary}`",
            "",
        ])
    evidence_tree = evidence_tree_lines(components)
    if evidence_tree:
        lines.extend([
            "## Evidence Tree",
            "",
        ])
        for line in evidence_tree:
            lines.append(f"- {line}")
        lines.append("")
    lines.extend([
        "## Components",
        "",
        "| Component | Confidence | Query | Evidence |",
        "| --- | --- | --- | --- |",
    ])
    for component in components:
        lines.append(
            f"| {_component_label(component)} | {component.get('confidence', 'Unknown')} | "
            f"{'Y' if component.get('query', component.get('analyze', True)) else 'N'} | "
            f"{_summarize_evidence(component.get('evidence', []))} |"
        )
    grouped = split_findings_by_disposition(results)
    lines.extend(["", "## Findings", ""])
    for disposition, title in DISPOSITION_TITLES.items():
        section_results = grouped.get(disposition, [])
        if not section_results:
            continue
        lines.extend([
            f"### {title}",
            "",
            "| Score | CVE | Component | CVSS | Priority | Confidence | Type | Evidence | Matched By | Signals |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ])
        for result in section_results:
            lines.append(
                f"| {result['score']} | {result['cve_id']} | {result.get('component_display', '')} | "
                f"{result['cvss']:.1f} | {result['label']} | {result.get('confidence', '').upper()} | "
                f"{_validation_category(result)} | "
                f"{_evidence_label(result)} | {result.get('matched_by', '')} | {_signal_summary(result)} |"
            )

        lines.extend(["", "#### Why This CVE", ""])
        for result in section_results:
            lines.extend([
                f"##### {result['cve_id']} (`{result.get('component_display', '')}`)",
                "",
                f"- `matched_by`: `{result.get('matched_by', '')}`",
                f"- `confidence`: `{result.get('confidence', '')}`",
                f"- `disposition`: `{result.get('disposition', '')}`",
                f"- `evidence`: `{_evidence_label(result)}`",
                f"- `type`: `{_validation_category(result)}`",
                f"- `surface`: `{result.get('validation', {}).get('surface', '')}`",
                f"- `auth`: `{result.get('validation', {}).get('auth', '')}`",
                f"- `next_check`: `{result.get('validation', {}).get('hint', '')}`",
            ])
            for reason in result.get("reasoning", []):
                lines.append(f"- {reason}")
            lines.append("")
    exploit_count = sum(1 for result in results if result["poc"] or result["edb"])
    kev_count = sum(1 for result in results if result["kev"])
    lines.extend([
        "",
        f"Displayed {len(results)} findings. {exploit_count} have public exploits. {kev_count} are in KEV.",
    ])
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def write_markdown_batch_report(
    scans: List[Dict],
    summary: Dict,
    output_path: Path,
    mode: str = "strict",
    min_confidence: str = "medium",
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Talon v{__version__}",
        "",
        "## Batch Scan",
        "",
        f"**Date:** {timestamp}",
        f"**Mode:** `{mode}`",
        f"**Minimum confidence:** `{min_confidence}`",
        "",
        "## Summary",
        "",
        f"- Targets scanned: `{summary.get('targets_scanned', 0)}`",
        f"- Targets with findings: `{summary.get('targets_with_findings', 0)}`",
        f"- Targets with actionable findings: `{summary.get('targets_with_actionable', 0)}`",
        f"- Total findings: `{summary.get('findings_total', 0)}`",
        (
            f"- Disposition counts: actionable=`{summary.get('by_disposition', {}).get('actionable', 0)}`, "
            f"needs_validation=`{summary.get('by_disposition', {}).get('needs_validation', 0)}`, "
            f"context=`{summary.get('by_disposition', {}).get('context', 0)}`"
        ),
        "",
    ]

    for index, scan in enumerate(scans, start=1):
        components = scan.get("components", [])
        findings = scan.get("findings", [])
        target = scan.get("target", "")
        input_target = scan.get("input_target", target)
        lines.extend([
            f"## Target {index}: `{input_target}`",
            "",
        ])
        if target and target != input_target:
            lines.extend([f"Resolved: `{target}`", ""])

        stack_summary = summarize_stack(components)
        if stack_summary:
            lines.extend([f"Stack: `{stack_summary}`", ""])

        evidence_tree = evidence_tree_lines(components)
        if evidence_tree:
            lines.extend(["### Evidence Tree", ""])
            for line in evidence_tree:
                lines.append(f"- {line}")
            lines.append("")

        lines.extend([
            "### Components",
            "",
            "| Component | Confidence | Query | Evidence |",
            "| --- | --- | --- | --- |",
        ])
        for component in components:
            lines.append(
                f"| {_component_label(component)} | {component.get('confidence', 'Unknown')} | "
                f"{'Y' if component.get('query', component.get('analyze', True)) else 'N'} | "
                f"{_summarize_evidence(component.get('evidence', []))} |"
            )

        grouped = split_findings_by_disposition(findings)
        lines.extend(["", "### Findings", ""])
        for disposition, title in DISPOSITION_TITLES.items():
            section_results = grouped.get(disposition, [])
            if not section_results:
                continue
            lines.extend([
                f"#### {title}",
                "",
                "| Score | CVE | Component | CVSS | Priority | Confidence | Type | Evidence | Matched By | Signals |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ])
            for result in section_results:
                lines.append(
                    f"| {result['score']} | {result['cve_id']} | {result.get('component_display', '')} | "
                    f"{result['cvss']:.1f} | {result['label']} | {result.get('confidence', '').upper()} | "
                    f"{_validation_category(result)} | "
                    f"{_evidence_label(result)} | {result.get('matched_by', '')} | {_signal_summary(result)} |"
                )
            lines.append("")

        if scan.get("status_message"):
            lines.extend([scan["status_message"], ""])

    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def _component_label(component: Dict) -> str:
    return " ".join(part for part in [component.get("service", ""), component.get("version", "")] if part).strip()


def _summarize_evidence(evidence: List[str], limit: int = 2) -> str:
    if not evidence:
        return ""
    shown = evidence[:limit]
    if len(evidence) > limit:
        shown.append(f"+{len(evidence) - limit} more")
    return "; ".join(shown)


def _evidence_label(result: Dict) -> str:
    evidence = result.get("evidence", [])
    if not evidence:
        return ""
    first = evidence[0]
    label = first.get("label", "")
    field = first.get("field", "")
    if field:
        return f"{label} [{field}]"
    return label


def _signal_summary(result: Dict) -> str:
    labels = []
    if result.get("kev"):
        labels.append("KEV")
    if result.get("poc"):
        labels.append("PoC")
    if result.get("edb"):
        labels.append("EDB")
    return ", ".join(labels) if labels else "-"


def _validation_category(result: Dict) -> str:
    return result.get("validation", {}).get("category", "")
