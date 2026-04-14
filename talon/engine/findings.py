from typing import Dict, List, Optional, Sequence, Tuple
import re


MATCH_METADATA = {
    "Exact": {
        "matched_by": "exact_version",
        "confidence": "high",
        "disposition": "actionable",
    },
    "Partial": {
        "matched_by": "cpe_range",
        "confidence": "medium",
        "disposition": "actionable",
    },
    "Service": {
        "matched_by": "service_cpe",
        "confidence": "low",
        "disposition": "needs_validation",
    },
    "Description": {
        "matched_by": "description",
        "confidence": "low",
        "disposition": "needs_validation",
    },
    "Protocol": {
        "matched_by": "protocol",
        "confidence": "low",
        "disposition": "context",
    },
}

CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}
DISPOSITION_ORDER = {"actionable": 0, "needs_validation": 1, "context": 2}
DISPOSITION_TITLES = {
    "actionable": "Actionable Findings",
    "needs_validation": "Needs Validation",
    "context": "Context",
}

EVIDENCE_SOURCE_LABELS = {
    "version": "Plain version string",
    "banner": "Banner",
    "header": "Header evidence",
    "url": "URL response header",
    "nmap": "Nmap service record",
    "inference": "Inference",
}

VALIDATION_HINTS = [
    (
        re.compile(r"\bpath traversal\b|\bdirectory traversal\b", re.IGNORECASE),
        {
            "category": "path traversal",
            "surface": "HTTP request path or file parameter",
            "auth": "none",
            "hint": "Check normalized path handling on the exposed request path and confirm traversal is blocked.",
        },
    ),
    (
        re.compile(r"\bserver-side request forgery\b|\bssrf\b", re.IGNORECASE),
        {
            "category": "ssrf",
            "surface": "URL fetch, webhook, or proxy input",
            "auth": "none or low-privilege feature access",
            "hint": "Identify features that fetch remote URLs and verify whether arbitrary destinations can be requested.",
        },
    ),
    (
        re.compile(r"\brequest smuggling\b", re.IGNORECASE),
        {
            "category": "request smuggling",
            "surface": "public HTTP edge interface",
            "auth": "none",
            "hint": "Probe front-end and back-end parsing differences on the public HTTP interface.",
        },
    ),
    (
        re.compile(r"\bsql injection\b", re.IGNORECASE),
        {
            "category": "sql injection",
            "surface": "query parameter or form input",
            "auth": "none or low privilege",
            "hint": "Confirm whether untrusted input reaches SQL queries without parameterization.",
        },
    ),
    (
        re.compile(r"\bcross-site scripting\b|\bxss\b", re.IGNORECASE),
        {
            "category": "cross-site scripting",
            "surface": "rendered HTML or templated output",
            "auth": "user interaction or stored content path",
            "hint": "Locate reflected or stored input sinks and verify whether the rendered output is sanitized.",
        },
    ),
    (
        re.compile(r"\bauthentication bypass\b|\bauthorization bypass\b|\baccess control\b", re.IGNORECASE),
        {
            "category": "access control bypass",
            "surface": "protected endpoint or workflow",
            "auth": "none or low privilege",
            "hint": "Verify whether unauthenticated or low-privilege requests can reach the protected function.",
        },
    ),
    (
        re.compile(r"\bremote code execution\b|\bcommand injection\b|\barbitrary code execution\b|\brce\b", re.IGNORECASE),
        {
            "category": "remote code execution",
            "surface": "network-facing request or service input",
            "auth": "none or low privilege",
            "hint": "Confirm whether untrusted input reaches an execution primitive on the exposed service interface.",
        },
    ),
    (
        re.compile(r"\bdeserialization\b", re.IGNORECASE),
        {
            "category": "deserialization",
            "surface": "serialized object or session input",
            "auth": "none or low privilege",
            "hint": "Identify deserialized inputs and verify whether attacker-controlled data reaches the vulnerable sink.",
        },
    ),
    (
        re.compile(r"\bfile upload\b", re.IGNORECASE),
        {
            "category": "file upload",
            "surface": "upload endpoint",
            "auth": "none or authenticated upload flow",
            "hint": "Verify whether uploaded content is validated and isolated before server-side processing.",
        },
    ),
    (
        re.compile(r"\binformation disclosure\b|\binformation leak\b|\bsensitive information\b", re.IGNORECASE),
        {
            "category": "information disclosure",
            "surface": "response body, error path, or debug interface",
            "auth": "none or low privilege",
            "hint": "Check whether sensitive content is returned through normal requests, errors, or debug paths.",
        },
    ),
    (
        re.compile(r"\bdenial of service\b|\bresource exhaustion\b|\bmemory corruption\b|\bcrash\b", re.IGNORECASE),
        {
            "category": "denial of service",
            "surface": "network-facing request pattern",
            "auth": "none",
            "hint": "Identify the request pattern that triggers abnormal resource consumption or process instability.",
        },
    ),
]


def build_finding(
    component: Dict,
    cve: Dict,
    match_label: str,
    score: int,
    has_kev: bool,
    has_poc: bool,
    has_edb: bool,
    label: str,
) -> Dict:
    match_metadata = MATCH_METADATA.get(
        match_label,
        {
            "matched_by": "unknown",
            "confidence": "low",
            "disposition": "needs_validation",
        },
    )
    evidence = _finding_evidence(component)
    finding = {
        "target_component": component.get("service", ""),
        "component": component.get("service", ""),
        "service": component.get("service", ""),
        "version": component.get("version", ""),
        "score": score,
        "cve_id": cve["cve_id"],
        "cvss": cve["cvss"],
        "kev": has_kev,
        "poc": has_poc,
        "edb": has_edb,
        "match": match_label,
        "matched_by": match_metadata["matched_by"],
        "confidence": match_metadata["confidence"],
        "confidence_rank": confidence_rank(match_metadata["confidence"]),
        "disposition": match_metadata["disposition"],
        "label": label,
        "description": cve["description"],
        "cpes": cve["cpes"],
        "source": cve.get("source", "nvd"),
        "component_display": _component_display([component]),
        "affected_components": [_component_reference(component)],
        "evidence": evidence,
        "reasoning": _build_reasoning(component, cve, match_label, evidence, has_kev, has_poc, has_edb),
        "validation": _build_validation_hint(component, cve, match_label),
    }
    finding["why"] = summarize_finding_why(finding)
    return finding


def confidence_rank(confidence: str) -> int:
    return CONFIDENCE_ORDER.get((confidence or "").lower(), 0)


def filter_findings(
    findings: Sequence[Dict],
    mode: str = "strict",
    min_confidence: Optional[str] = None,
) -> Tuple[List[Dict], str]:
    effective_min_confidence = (min_confidence or ("medium" if mode == "strict" else "low")).lower()
    threshold = confidence_rank(effective_min_confidence)
    filtered = [finding for finding in findings if confidence_rank(finding.get("confidence", "")) >= threshold]

    if mode == "strict":
        filtered = [finding for finding in filtered if finding.get("disposition") != "context"]

    return filtered, effective_min_confidence


def split_findings_by_disposition(findings: Sequence[Dict]) -> Dict[str, List[Dict]]:
    grouped = {name: [] for name in DISPOSITION_TITLES}
    for finding in findings:
        grouped.setdefault(finding.get("disposition", "needs_validation"), []).append(finding)
    for disposition, items in grouped.items():
        items.sort(
            key=lambda item: (
                DISPOSITION_ORDER.get(disposition, 99),
                -item.get("score", 0),
                -item.get("cvss", 0.0),
                item.get("cve_id", ""),
            )
        )
    return grouped


def summarize_finding_why(finding: Dict) -> str:
    evidence = finding.get("evidence", [])
    if not evidence:
        return finding.get("matched_by", "unknown")

    first = evidence[0]
    evidence_label = EVIDENCE_SOURCE_LABELS.get(first.get("source", ""), "Observed evidence")
    field = first.get("field", "")
    if field:
        evidence_label = f"{evidence_label} [{field}]"
    return f"{finding.get('matched_by', 'unknown')} via {evidence_label}"


def _build_reasoning(
    component: Dict,
    cve: Dict,
    match_label: str,
    evidence: Sequence[Dict],
    has_kev: bool,
    has_poc: bool,
    has_edb: bool,
) -> List[str]:
    reasoning: List[str] = []

    direct_evidence = [entry for entry in evidence if entry.get("direct")]
    if direct_evidence:
        reasoning.append(f"Component observed directly via {_evidence_reference(direct_evidence[0])}.")
    else:
        reasoning.append("Component inferred from contextual evidence; manual validation is recommended.")

    version = component.get("version", "")
    if version:
        reasoning.append(f"Selected component version candidate: {version}.")
    else:
        reasoning.append("No component version was observed directly.")

    reasoning.append(_match_reasoning(match_label))

    if cve.get("source") == "nvd+osv":
        reasoning.append("OSV independently confirmed the package and version match.")
    elif cve.get("source") == "osv":
        reasoning.append("OSV matched the package version directly.")

    if has_kev:
        reasoning.append("CISA KEV marks this CVE as actively exploited.")
    if has_poc:
        reasoning.append("A public proof-of-concept is available.")
    if has_edb:
        reasoning.append("ExploitDB has an exploit reference for this CVE.")

    return reasoning


def _evidence_reference(entry: Dict) -> str:
    source_label = EVIDENCE_SOURCE_LABELS.get(entry.get("source", ""), "Observed evidence")
    field = entry.get("field", "")
    if field:
        return f"{source_label} [{field}]"
    return source_label


def _match_reasoning(match_label: str) -> str:
    if match_label == "Exact":
        return "Structured vulnerability data matched the exact observed version."
    if match_label == "Partial":
        return "Structured vulnerability data indicates the observed version falls within an affected range."
    if match_label == "Service":
        return "The product matched structured vulnerability data, but no direct version match was available."
    if match_label == "Description":
        return "The product matched vulnerability descriptions only; manual validation is required."
    if match_label == "Protocol":
        return "This is protocol-level context rather than a product-specific version match."
    return "The match reason could not be classified."


def _finding_evidence(component: Dict) -> List[Dict]:
    evidence: List[Dict] = []
    for record in component.get("evidence_records", []):
        evidence.append(
            {
                "source": record.get("source", ""),
                "field": record.get("field", ""),
                "raw": record.get("raw", ""),
                "label": EVIDENCE_SOURCE_LABELS.get(record.get("source", ""), "Observed evidence"),
                "normalized_component": component.get("service", ""),
                "normalized_version": component.get("version", ""),
                "direct": bool(record.get("direct", component.get("direct", False))),
            }
        )
    return evidence


def _build_validation_hint(component: Dict, cve: Dict, match_label: str) -> Dict[str, str]:
    description = cve.get("description", "")
    lowered = description.lower()

    if match_label == "Protocol":
        protocol = "HTTP/2" if "http/2" in lowered else "protocol"
        return {
            "category": "protocol abuse",
            "surface": f"{protocol} edge interface",
            "auth": "none",
            "hint": f"Verify that the public edge negotiates {protocol} and confirm whether the front-end component handles malformed protocol traffic safely.",
        }

    for pattern, template in VALIDATION_HINTS:
        if pattern.search(description):
            return dict(template)

    stack_role = component.get("stack_role", "unknown")
    if stack_role in {"edge", "web"}:
        surface = "public HTTP or edge interface"
    elif stack_role == "runtime":
        surface = "application runtime input"
    elif stack_role == "application":
        surface = "application endpoint or worker input"
    else:
        surface = "observed service interface"

    return {
        "category": "manual validation",
        "surface": surface,
        "auth": "unknown",
        "hint": "Confirm that the component and version are truly present before validating the cited vulnerability behavior.",
    }


def _component_reference(component: Dict) -> Dict[str, object]:
    return {
        "service": component.get("service", ""),
        "version": component.get("version", ""),
        "confidence": component.get("confidence", "Confirmed"),
        "evidence_records": component.get("evidence_records", []),
    }


def _component_display(components: Sequence[Dict]) -> str:
    labels = []
    for component in components:
        label = " ".join(
            part for part in [component.get("service", ""), component.get("version", "")] if part
        ).strip()
        if label and label not in labels:
            labels.append(label)
    return ", ".join(labels)
