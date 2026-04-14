import re
from typing import Dict, List

from .normalize import detect_known_service, normalize_service, parse_product_version

# Explicit patterns — each yields one (service, version) pair.
# Order matters: more specific patterns first.
BANNER_PATTERNS = [
    (re.compile(r"\b(?:Apache\s+Traffic\s+Server|ATS)\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "ats"),
    (re.compile(r"\bVarnish(?:[-\s]?Cache)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "varnish"),
    (re.compile(r"\bApache(?:[-\s]+Tomcat)(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "tomcat"),
    (re.compile(r"\bMicrosoft[-\s]?IIS(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "iis"),
    (re.compile(r"\blighttpd(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "lighttpd"),
    (re.compile(r"\bEnvoy(?:/|\s+)(?:proxy(?:/|\s+))?v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "envoy"),
    (re.compile(r"\bHAProxy(?:/|\s+version\s+|\s+)v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "haproxy"),
    (re.compile(r"\bPostfix(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "postfix"),
    (re.compile(r"\bvsftpd(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"\bProFTPD(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "proftpd"),
    (re.compile(r"\bnginx(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "nginx"),
    (re.compile(r"\bApache(?:\s+HTTPD?)?(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "apache"),
    (re.compile(r"\bOpenSSH[_/]v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "openssh"),
    (re.compile(r"\bNode\.?js(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "node"),
    (re.compile(r"\bOpenSSL(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "openssl"),
    (re.compile(r"\bPHP(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "php"),
    (re.compile(r"\bGunicorn(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "gunicorn"),
    (re.compile(r"\buWSGI(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "uwsgi"),
    (re.compile(r"\bPlack(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "plack"),
    (re.compile(r"\bCaddy(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "caddy"),
    (re.compile(r"\bTraefik(?:\s+proxy)?(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "traefik"),
    (re.compile(r"\bTomcat(?:\s+version)?\s*/?\s*v?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE), "tomcat"),
]

def extract_from_banner(banner: str) -> List[Dict[str, str]]:
    """
    Parse a raw banner string and return one finding per service found.
    Banners often contain multiple services (e.g. "nginx/1.18.0 PHP/7.4.3"),
    so we scan for ALL known patterns and return all matches, deduped by service.
    """
    findings: List[Dict[str, str]] = []
    seen_services: set = set()

    for pattern, service_name in BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            normalized = normalize_service(service_name)
            if normalized not in seen_services:
                seen_services.add(normalized)
                findings.append({
                    "service": normalized,
                    "version": match.group(1),
                    "raw": banner,
                    "source": "banner",
                })

    if findings:
        return findings

    # Generic fallback — parse the full banner rather than a trailing fragment
    service, version = parse_product_version(banner)
    if service != "unknown" or version:
        finding = {"service": service, "version": version, "raw": banner, "source": "banner"}
        if service == "unknown":
            finding["warning"] = "Unknown banner pattern; continuing with service hint or version only."
        return [finding]

    # Last resort — return the first token as service name only
    tokens = banner.strip().split()
    service = normalize_service(tokens[0]) if tokens else "unknown"
    if service == "unknown":
        service = detect_known_service(banner)
    return [{
        "service": service,
        "version": "",
        "raw": banner,
        "source": "banner",
        "warning": "Unknown banner pattern; continuing with service name only.",
    }]
