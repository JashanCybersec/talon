import re
from typing import Dict, Iterable, List, Sequence, Tuple

try:
    from ..extractors.normalize import normalize_service
except ImportError:
    from extractors.normalize import normalize_service


CONFIDENCE_RANK = {
    "Weak inference": 1,
    "Strong inference": 2,
    "Confirmed": 3,
}

DIRECT_EVIDENCE = {
    "version": "Plain version string",
    "banner": "Banner",
    "header": "Header evidence",
    "url": "URL response header",
    "nmap": "Nmap service record",
}

STACK_ROLE_ORDER = {
    "edge": 0,
    "web": 1,
    "runtime": 2,
    "framework": 3,
    "application": 4,
    "database": 5,
    "cache": 6,
    "queue": 7,
    "unknown": 99,
}

# Services that have no meaningful CVE records in NVD/OSV.
# Querying them wastes API calls and adds noise without findings.
NO_CVE_SERVICES = {
    # Hosting / CDN / infrastructure — no product CVEs
    "vercel", "netlify", "squarespace", "akamai", "cloudflare",
    # Analytics / marketing
    "google-analytics", "google-hosted-libraries", "datadog", "hotjar",
    "hubspot",
    # CMS plugins / page builders (no NVD entries under these names)
    "wp-rocket", "wp rocket", "woocommerce", "wpml", "payload",
    # Static site generators
    "gatsby", "hugo", "vitepress", "jekyll", "hexo",
    # Headless / jamstack platforms
    "ghost",
    # CSS / UI toolkits with no CVE records
    "tailwindcss", "font-awesome", "bootstrap",
    # JS utility libraries with no meaningful CVE records
    "framer-motion", "gsap", "three.js", "d3.js", "socket.io",
    "ember.js", "backbone.js", "handlebars", "underscore.js",
    "axios", "popper.js", "owl-carousel", "swiper", "moment.js", "lodash",
    # Shopify (hosted SaaS)
    "shopify",
}

STACK_ROLE_MAP = {
    "cloudflare": "edge",
    "ats": "edge",
    "varnish": "edge",
    "envoy": "edge",
    "haproxy": "edge",
    "traefik": "edge",
    "nginx": "web",
    "apache": "web",
    "iis": "web",
    "lighttpd": "web",
    "caddy": "web",
    "openssh": "edge",
    "php": "runtime",
    "node": "runtime",
    "openssl": "runtime",
    "spring": "framework",
    "django": "framework",
    "flask": "framework",
    "laravel": "framework",
    "express": "framework",
    "log4j": "framework",
    "spring-boot": "application",
    "tomcat": "application",
    "wordpress": "application",
    "gunicorn": "application",
    "uwsgi": "application",
    "plack": "application",
    "mysql": "database",
    "postgresql": "database",
    "redis": "cache",
}

SERVICE_INFERENCES = {
    "express": [
        {"service": "node", "confidence": "Strong inference", "reason": "Express implies a Node.js application."},
    ],
    "laravel": [
        {"service": "php", "confidence": "Strong inference", "reason": "Laravel implies a PHP runtime."},
    ],
    "spring-boot": [
        {"service": "spring", "confidence": "Strong inference", "reason": "Spring Boot implies the Spring Framework."},
    ],
}

RAW_INFERENCE_RULES = [
    (
        re.compile(r"\blaravel_session\b", re.IGNORECASE),
        [
            {"service": "laravel", "confidence": "Strong inference", "reason": "Cookie or header contains laravel_session."},
            {"service": "php", "confidence": "Strong inference", "reason": "Laravel implies a PHP runtime."},
        ],
    ),
]


def build_stack_components(findings: List[Dict[str, str]], raw_inputs: Sequence[Tuple[str, str]]) -> List[Dict]:
    components: Dict[str, Dict] = {}
    normalized_findings = [_normalize_finding(finding) for finding in findings]

    for finding in normalized_findings:
        if finding["service"] == "unknown":
            continue
        _upsert_component(components, finding, direct=True)

    direct_services = {finding["service"] for finding in normalized_findings if finding["service"] != "unknown"}
    inferred_findings = [_normalize_finding(finding) for finding in _infer_components(direct_services, raw_inputs)]
    for finding in inferred_findings:
        _upsert_component(components, finding, direct=False)

    finalized = [_finalize_component(component) for component in components.values()]
    finalized.sort(key=_stack_sort_key)
    for index, component in enumerate(finalized):
        component["stack_index"] = index
    return finalized


def summarize_target(components: List[Dict], raw_inputs: Sequence[Tuple[str, str]]) -> str:
    stack_summary = summarize_stack(components)
    if stack_summary:
        return stack_summary
    primary_inputs = [_summarize_raw_input(name, value) for name, value in raw_inputs if value and not name.endswith("-evidence")]
    fallback = [value for value in primary_inputs if value]
    if not fallback:
        fallback = [_summarize_raw_input(name, value) for name, value in raw_inputs if value]
        fallback = [value for value in fallback if value]
    return " + ".join(fallback) if fallback else "manual input"


def summarize_stack(components: Sequence[Dict], limit: int = 6) -> str:
    labels = [component_label(component) for component in components if component_label(component)]
    if not labels:
        return ""
    if len(labels) > limit:
        labels = labels[:limit] + [f"+{len(labels) - limit} more"]
    return " -> ".join(labels)


def component_label(component: Dict) -> str:
    return " ".join(part for part in [component["service"], component.get("version", "")] if part).strip()


def summarize_component_evidence(component: Dict, limit: int = 2) -> str:
    evidence = component.get("evidence", [])
    if not evidence:
        return ""
    shown = evidence[:limit]
    if len(evidence) > limit:
        shown.append(f"+{len(evidence) - limit} more")
    return "; ".join(shown)


def evidence_tree_lines(components: Sequence[Dict]) -> List[str]:
    lines: List[str] = []
    seen = set()

    for component in components:
        label = component_label(component)
        for record in component.get("evidence_records", []):
            line = _evidence_tree_line(label, record)
            if line and line not in seen:
                seen.add(line)
                lines.append(line)

    return lines


def _normalize_finding(finding: Dict[str, str]) -> Dict[str, str]:
    normalized = {**finding}
    normalized["service"] = normalize_service(finding.get("service", ""))
    normalized["confidence"] = finding.get("confidence", "Confirmed")
    normalized["evidence_records"] = _normalize_evidence_records(finding)
    normalized["evidence"] = _normalize_evidence_strings(finding, normalized["evidence_records"])
    normalized["analyze"] = bool(finding.get("analyze", True))
    return normalized


def _default_evidence(finding: Dict[str, str]) -> str:
    input_mode = finding.get("input_mode") or finding.get("source", "")
    return DIRECT_EVIDENCE.get(input_mode, "Observed evidence")


def _normalize_evidence_records(finding: Dict[str, str]) -> List[Dict[str, object]]:
    records = finding.get("evidence_records")
    if isinstance(records, list) and records:
        return [_sanitize_evidence_record(record, finding) for record in records]

    record = finding.get("evidence_record")
    if isinstance(record, dict):
        return [_sanitize_evidence_record(record, finding)]

    return [_default_evidence_record(finding)]


def _normalize_evidence_strings(finding: Dict[str, str], evidence_records: Sequence[Dict[str, object]]) -> List[str]:
    raw_evidence = finding.get("evidence")
    values: List[str] = []
    if isinstance(raw_evidence, str):
        _add_unique(values, raw_evidence)
    elif isinstance(raw_evidence, list):
        for value in raw_evidence:
            _add_unique(values, str(value))

    if not values:
        for record in evidence_records:
            _add_unique(values, _evidence_summary(record))

    return values


def _sanitize_evidence_record(record: Dict[str, object], finding: Dict[str, str]) -> Dict[str, object]:
    input_mode = finding.get("input_mode") or finding.get("source", "")
    return {
        "source": str(record.get("source") or input_mode or "unknown"),
        "field": str(record.get("field") or finding.get("header_name") or "").strip().lower(),
        "raw": str(record.get("raw") or finding.get("raw") or "").strip(),
        "direct": bool(record.get("direct", input_mode != "inference")),
    }


def _default_evidence_record(finding: Dict[str, str]) -> Dict[str, object]:
    input_mode = finding.get("input_mode") or finding.get("source", "") or "unknown"
    raw_value = finding.get("raw", "")
    if input_mode == "inference":
        raw_value = finding.get("evidence", "") or raw_value

    return {
        "source": input_mode,
        "field": str(finding.get("header_name", "")).strip().lower(),
        "raw": str(raw_value).strip(),
        "direct": input_mode != "inference",
    }


def _infer_components(direct_services: Iterable[str], raw_inputs: Sequence[Tuple[str, str]]) -> List[Dict[str, str]]:
    inferred: List[Dict[str, str]] = []

    for service in sorted(set(direct_services)):
        for rule in SERVICE_INFERENCES.get(service, []):
            inferred.append({
                "service": rule["service"],
                "version": "",
                "raw": service,
                "source": "inference",
                "input_mode": "inference",
                "confidence": rule["confidence"],
                "evidence": rule["reason"],
                "evidence_record": {
                    "source": "inference",
                    "raw": rule["reason"],
                    "direct": False,
                },
                "analyze": False,
            })

    raw_blob = "\n".join(value for _, value in raw_inputs if value)
    for pattern, rules in RAW_INFERENCE_RULES:
        if not pattern.search(raw_blob):
            continue
        for rule in rules:
            inferred.append({
                "service": rule["service"],
                "version": "",
                "raw": raw_blob,
                "source": "inference",
                "input_mode": "inference",
                "confidence": rule["confidence"],
                "evidence": rule["reason"],
                "evidence_record": {
                    "source": "inference",
                    "raw": rule["reason"],
                    "direct": False,
                },
                "analyze": False,
            })

    return inferred


def _upsert_component(components: Dict[str, Dict], finding: Dict[str, str], direct: bool) -> None:
    service = finding["service"]
    component = components.setdefault(
        service,
        {
            "service": service,
            "version_candidates": [],
            "confidence_rank": 0,
            "confidence": "Weak inference",
            "evidence": [],
            "evidence_records": [],
            "sources": [],
            "direct": False,
            "analyze": False,
        },
    )

    for record in finding.get("evidence_records", []):
        _add_unique_record(component["evidence_records"], record)
        _add_unique(component["evidence"], _evidence_summary(record))

    for value in finding.get("evidence", []):
        _add_unique(component["evidence"], value)
    _add_unique(component["sources"], finding.get("source", "unknown"))
    component["direct"] = component["direct"] or direct
    component["analyze"] = component["analyze"] or bool(finding.get("analyze", direct))

    confidence = finding.get("confidence", "Confirmed")
    confidence_rank = CONFIDENCE_RANK.get(confidence, 0)
    if confidence_rank > component["confidence_rank"]:
        component["confidence_rank"] = confidence_rank
        component["confidence"] = confidence

    version = (finding.get("version") or "").strip()
    if version:
        component["version_candidates"].append((confidence_rank, 1 if direct else 0, version))


def _finalize_component(component: Dict) -> Dict:
    version = ""
    versions = sorted({candidate[2] for candidate in component["version_candidates"]})
    if component["version_candidates"]:
        component["version_candidates"].sort(reverse=True)
        version = component["version_candidates"][0][2]

    service = component["service"]
    stack_role = _stack_role_for_service(service)
    query = (
        bool(component["direct"])
        and component["confidence"] == "Confirmed"
        and service not in NO_CVE_SERVICES
    )
    analyze = component["analyze"] or query

    return {
        "service": component["service"],
        "version": version,
        "versions": versions,
        "confidence": component["confidence"],
        "confidence_rank": component["confidence_rank"],
        "evidence": component["evidence"],
        "evidence_records": component["evidence_records"],
        "sources": component["sources"],
        "direct": component["direct"],
        "stack_role": stack_role,
        "stack_rank": STACK_ROLE_ORDER.get(stack_role, STACK_ROLE_ORDER["unknown"]),
        "query": query,
        "analyze": analyze,
        "context_only": not analyze,
    }


def _add_unique(values: List[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _add_unique_record(values: List[Dict[str, object]], record: Dict[str, object]) -> None:
    key = (
        str(record.get("source", "")),
        str(record.get("field", "")),
        str(record.get("raw", "")),
        bool(record.get("direct", False)),
    )
    existing = {
        (
            str(item.get("source", "")),
            str(item.get("field", "")),
            str(item.get("raw", "")),
            bool(item.get("direct", False)),
        )
        for item in values
    }
    if key not in existing:
        values.append(record)


def _summarize_raw_input(input_mode: str, value: str, limit: int = 80) -> str:
    collapsed = " ".join(value.strip().split())
    if not collapsed:
        return ""
    if len(collapsed) > limit:
        return collapsed[: limit - 3] + "..."
    return collapsed


def _stack_role_for_service(service: str) -> str:
    return STACK_ROLE_MAP.get(normalize_service(service), "unknown")


def _stack_sort_key(component: Dict) -> Tuple[int, int, int, int, str]:
    return (
        component.get("stack_rank", STACK_ROLE_ORDER["unknown"]),
        -int(component.get("query", False)),
        -component.get("confidence_rank", 0),
        -int(bool(component.get("version", ""))),
        component.get("service", ""),
    )


def _evidence_summary(record: Dict[str, object]) -> str:
    source = str(record.get("source", ""))
    if source == "inference":
        return str(record.get("raw", "")).strip() or "Inference"

    label = DIRECT_EVIDENCE.get(source, "Observed evidence")
    field = str(record.get("field", "")).strip().lower()
    if field:
        return f"{label} [{field}]"
    return label


def _evidence_tree_line(component_name: str, record: Dict[str, object]) -> str:
    source = str(record.get("source", ""))
    raw = " ".join(str(record.get("raw", "")).split())
    if source == "inference":
        detail = raw or "Inference"
        return f"Inference: {detail} -> {component_name}"

    label = DIRECT_EVIDENCE.get(source, "Observed evidence")
    field = str(record.get("field", "")).strip().lower()
    if field:
        label = f"{label} [{field}]"
    if raw:
        return f"{label}: {raw} -> {component_name}"
    return f"{label} -> {component_name}"
