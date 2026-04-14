import io
import sys
from typing import Dict, List, Optional

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

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


def _safe_console(no_color: bool = False) -> Console:
    encoding = getattr(sys.stdout, "encoding", None) or ""
    if encoding.lower().replace("-", "") not in {"utf8", "utf16", "utf32"}:
        try:
            safe_out = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True,
            )
            safe_out.close = lambda: safe_out.flush()  # prevent closing underlying stdout
            return Console(file=safe_out, no_color=no_color)
        except AttributeError:
            pass
    return Console(no_color=no_color)


def print_results_table(
    target: str,
    results: List[Dict],
    components: Optional[List[Dict]] = None,
    no_color: bool = False,
    mode: str = "strict",
    min_confidence: str = "medium",
    status_message: str = "",
    elapsed: str = "",
) -> None:
    console = _safe_console(no_color=no_color)
    rich_symbols = _supports_text(console, "\u2714\u2717\u2502\u2500") and not no_color
    header = f"Talon v{__version__} | Target: {target}"
    if elapsed:
        header += f" | {elapsed}"
    console.print(Text(header))
    console.print(f"Mode: {mode} | Minimum confidence: {min_confidence}")
    _print_scan(console, rich_symbols, target, results, components, status_message)


def print_batch_results(
    scans: List[Dict],
    summary: Dict,
    no_color: bool = False,
    mode: str = "strict",
    min_confidence: str = "medium",
    elapsed: str = "",
) -> None:
    console = _safe_console(no_color=no_color)
    rich_symbols = _supports_text(console, "\u2714\u2717\u2502\u2500") and not no_color
    header = f"Talon v{__version__} | Batch Scan"
    if elapsed:
        header += f" | {elapsed}"
    console.print(Text(header))
    console.print(f"Mode: {mode} | Minimum confidence: {min_confidence}")
    _print_batch_summary(console, summary)

    for index, scan in enumerate(scans, start=1):
        console.print("")
        console.print(Text(f"Target {index}/{len(scans)} | Input: {scan.get('input_target', scan.get('target', ''))}"))
        if scan.get("target") and scan.get("input_target") != scan.get("target"):
            console.print(f"Resolved: {scan['target']}")
        _print_scan(
            console,
            rich_symbols,
            scan.get("target", scan.get("input_target", "")),
            scan.get("findings", []),
            scan.get("components"),
            scan.get("status_message", ""),
        )

    console.print("")
    console.print("Batch Summary:")
    _print_batch_summary(console, summary)


def _print_scan(
    console: Console,
    rich_symbols: bool,
    target: str,
    results: List[Dict],
    components: Optional[List[Dict]],
    status_message: str,
) -> None:
    if components:
        stack = summarize_stack(components)
        if stack:
            console.print(f"Stack: {stack}")
        _print_components(console, components, rich_symbols)
        _print_evidence_tree(console, components)

    grouped = split_findings_by_disposition(results)
    for disposition, title in DISPOSITION_TITLES.items():
        section_results = grouped.get(disposition, [])
        if not section_results:
            continue
        console.print(f"{title}:")
        _print_finding_section(console, section_results, rich_symbols)

    if status_message:
        console.print(status_message)

    exploit_count = sum(1 for result in results if result["poc"] or result["edb"])
    kev_count = sum(1 for result in results if result["kev"])
    counts = ", ".join(
        f"{len(grouped.get(disposition, []))} {title.lower()}" for disposition, title in DISPOSITION_TITLES.items()
    )
    finding_word = "finding" if len(results) == 1 else "findings"
    exploit_word = "has" if exploit_count == 1 else "have"
    kev_word = "is" if kev_count == 1 else "are"
    console.print(
        f"Displayed {len(results)} {finding_word}. {counts}. {exploit_count} {exploit_word} public exploits. {kev_count} {kev_word} in KEV."
    )


def _print_components(console: Console, components: List[Dict], rich_symbols: bool) -> None:
    table = Table(
        show_header=True,
        header_style="bold",
        box=box.SIMPLE if rich_symbols else box.ASCII,
        expand=True,
    )
    table.add_column("Component", min_width=18)
    table.add_column("Confidence", no_wrap=True, min_width=16)
    table.add_column("Query", justify="center", no_wrap=True, min_width=5)
    table.add_column("Evidence")

    for component in components:
        confidence = component.get("confidence", "Unknown")
        analyze = "Y" if component.get("query", component.get("analyze", True)) else "N"
        evidence = _summarize_evidence(component.get("evidence", []))
        table.add_row(_component_label(component), confidence, analyze, evidence)

    console.print("Components:")
    console.print(table)


def _print_evidence_tree(console: Console, components: List[Dict]) -> None:
    lines = evidence_tree_lines(components)
    if not lines:
        return

    console.print("Evidence Tree:")
    for line in lines:
        console.print(f"- {line}")


def _print_finding_section(console: Console, results: List[Dict], rich_symbols: bool) -> None:
    table = Table(
        show_header=True,
        header_style="bold",
        box=box.SIMPLE if rich_symbols else box.ASCII,
        show_lines=True,
        expand=True,
        pad_edge=False,
    )
    table.add_column("Score", justify="right", no_wrap=True, width=5)
    table.add_column("CVE", no_wrap=True, min_width=16)
    table.add_column("CVSS", justify="right", no_wrap=True, width=4)
    table.add_column("Priority", no_wrap=True, min_width=10)
    table.add_column("Signals", no_wrap=True, width=12)
    table.add_column("Description", ratio=1)

    label_styles = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW CONFIDENCE": "dim"}
    for result in results:
        label_text = Text(result["label"])
        label_style = label_styles.get(result["label"], "")
        if label_style:
            label_text.stylize(label_style)
        description = _truncate(result.get("description", ""), 80)
        cve_line = result["cve_id"]
        component = result.get("component_display", "")
        if component:
            cve_line += f"\n[dim]{component}[/dim]"
        table.add_row(
            str(result["score"]),
            cve_line,
            f"{result['cvss']:.1f}",
            label_text,
            _signal_summary(result),
            description,
        )

    console.print(table)


def _truncate(text: str, length: int) -> str:
    text = text.replace("\n", " ").strip()
    if len(text) <= length:
        return text
    return text[:length - 1] + "\u2026"


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
    validation = result.get("validation", {})
    return validation.get("category", "")


def _print_batch_summary(console: Console, summary: Dict) -> None:
    by_disposition = summary.get("by_disposition", {})
    console.print(
        "Targets scanned: "
        f"{summary.get('targets_scanned', 0)} | "
        f"Targets with findings: {summary.get('targets_with_findings', 0)} | "
        f"Targets with actionable findings: {summary.get('targets_with_actionable', 0)} | "
        f"Total findings: {summary.get('findings_total', 0)}"
    )
    console.print(
        "Disposition counts: "
        f"actionable={by_disposition.get('actionable', 0)}, "
        f"needs_validation={by_disposition.get('needs_validation', 0)}, "
        f"context={by_disposition.get('context', 0)}"
    )


def _supports_text(console: Console, sample: str) -> bool:
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        sample.encode(encoding)
        return True
    except UnicodeEncodeError:
        return False
