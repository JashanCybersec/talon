import re
from typing import Dict, List

from .normalize import detect_known_service, extract_version_value, looks_like_version, normalize_service, parse_product_version

# Matches bare domain names like "github.com", "example.co.uk" that are
# used as Server header values but are not meaningful product identifiers.
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z]{2,})+$", re.IGNORECASE)

# Server header values that are internal infrastructure labels rather than
# real product names with CVE records.
_INFRA_SERVER_RE = re.compile(
    r"\b(?:proxy|gateway|cdn|edge|gtm|loadbalancer|lb|balancer|waf|cache|"
    r"frontend|backend|origin|relay|router|dispatcher|broker|mesh)\b",
    re.IGNORECASE,
)

# Also catches compound infra labels where the infra keyword is a suffix
# of the service name (e.g. "atlassianedge" ends with "edge",
# "snooserv" ends with "serv").
_INFRA_SUFFIX_RE = re.compile(
    r"(?:proxy|gateway|cdn|edge|gtm|lb|balancer|waf|cache|"
    r"frontend|backend|origin|relay|router|dispatcher|broker|mesh|serv)$",
    re.IGNORECASE,
)


HEADER_PATTERNS = {
    "server": re.compile(r"^(?:server)\s*:\s*(.+)$", re.IGNORECASE),
    "x-powered-by": re.compile(r"^(?:x-powered-by)\s*:\s*(.+)$", re.IGNORECASE),
    "x-powered-by-plesk": re.compile(r"^(?:x-powered-by-plesk)\s*:\s*(.+)$", re.IGNORECASE),
    "x-generator": re.compile(r"^(?:x-generator)\s*:\s*(.+)$", re.IGNORECASE),
    "x-aspnet-version": re.compile(r"^(?:x-aspnet-version)\s*:\s*(.+)$", re.IGNORECASE),
    "x-aspnetmvc-version": re.compile(r"^(?:x-aspnetmvc-version)\s*:\s*(.+)$", re.IGNORECASE),
}

HEADER_NAMES = {"server", "x-powered-by", "x-powered-by-plesk", "x-generator", "x-aspnet-version", "x-aspnetmvc-version"}

# Headers where the value is just a version number — map to a known service.
HEADER_SERVICE_HINTS = {
    "x-aspnet-version": "asp.net",
    "x-aspnetmvc-version": "asp.net-mvc",
    "x-powered-by-plesk": "plesk",
}


def _parse_value(raw_value: str, header_name: str = "") -> Dict[str, str]:
    stripped = raw_value.strip()

    # Headers whose value is just a bare version number (no product name in value).
    # Use the header name itself as the service hint.
    if header_name in HEADER_SERVICE_HINTS:
        service_hint = HEADER_SERVICE_HINTS[header_name]
        ver = extract_version_value(stripped) if looks_like_version(stripped) else ""
        return {
            "service": service_hint,
            "version": ver,
            "raw": stripped,
            "source": "header",
            "header_name": header_name,
        }

    service, version = parse_product_version(stripped)
    if service != "unknown" and version:
        result = {
            "service": service,
            "version": version,
            "raw": stripped,
            "source": "header",
        }
        if header_name:
            result["header_name"] = header_name
        return result

    if not stripped or stripped.endswith(":"):
        result = {
            "service": "unknown",
            "version": "",
            "raw": stripped,
            "source": "header",
            "warning": "Header value empty; continuing with service name only.",
        }
        if header_name:
            result["header_name"] = header_name
        return result

    if ":" in stripped:
        header_name = stripped.split(":", 1)[0].strip().lower()
        if header_name and header_name not in HEADER_NAMES:
            return {
                "service": "unknown",
                "version": "",
                "raw": stripped,
                "source": "header",
                "header_name": header_name,
                "warning": "Known version header not found; using raw header for inference only.",
            }

    head = stripped.split("/")[0].split()
    candidate = head[0].rstrip(":") if head else ""
    # Skip bare domain names used as server identifiers (e.g. "github.com").
    if candidate and _DOMAIN_RE.match(candidate):
        return {
            "service": "unknown",
            "version": "",
            "raw": stripped,
            "source": "header",
            "warning": "Server header contains a domain name, not a product version.",
        }
    # Skip generic/meaningless server values that reveal nothing useful.
    if candidate.lower() in {"server", "web server", "web", "unknown", "none", "-", "origin"}:
        return {
            "service": "unknown",
            "version": "",
            "raw": stripped,
            "source": "header",
            "warning": "Server header contains a generic placeholder value.",
        }
    normalized_candidate = normalize_service(candidate) if candidate else "unknown"
    if not candidate or candidate.lower() in HEADER_NAMES:
        normalized_candidate = "unknown"
    detected_service = detect_known_service(stripped)
    if detected_service != "unknown":
        normalized_candidate = detected_service
    # Suppress internal infrastructure server labels (proxy, cdn, edge, gtm, etc.)
    # Apply AFTER detect_known_service so known products (nginx, envoy) are not suppressed.
    _KNOWN_PRODUCTS = {"cloudflare", "traefik", "varnish", "envoy", "haproxy", "nginx",
                       "apache", "iis", "tomcat", "lighttpd", "caddy", "gunicorn",
                       "uwsgi", "plack", "ats", "openresty"}
    if normalized_candidate not in _KNOWN_PRODUCTS and (
        _INFRA_SERVER_RE.search(stripped) or _INFRA_SUFFIX_RE.search(normalized_candidate)
    ):
        normalized_candidate = "unknown"

    result = {
        "service": normalized_candidate,
        "version": "",
        "raw": stripped,
        "source": "header",
        "warning": "Version not found in header; continuing with service name only.",
    }
    if header_name:
        result["header_name"] = header_name
    return result


def extract_from_headers(header_blob: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    for line in header_blob.splitlines():
        line = line.strip()
        if not line:
            continue
        for header_name, pattern in HEADER_PATTERNS.items():
            match = pattern.match(line)
            if match:
                raw_val = match.group(1)
                # X-Powered-By can carry multiple comma-separated technologies
                # (e.g. "Next.js, Payload"). Split and process each part.
                if header_name in {"x-powered-by", "x-generator"} and "," in raw_val:
                    for part in raw_val.split(","):
                        part = part.strip()
                        if part:
                            findings.append(_parse_value(part, header_name=header_name))
                else:
                    findings.append(_parse_value(raw_val, header_name=header_name))
                break

    if findings:
        return findings

    raw_value = header_blob.strip()
    if "\n" in raw_value:
        return [{
            "service": "unknown",
            "version": "",
            "raw": raw_value[:200],
            "source": "header",
            "warning": "No recognized version headers found in response.",
        }]

    parsed = _parse_value(raw_value)
    parsed.setdefault("warning", "Known version header not found; continuing with service name only.")
    return [parsed]
