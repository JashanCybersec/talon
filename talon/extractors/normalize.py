"""Shared normalization and product/version parsing helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple


SERVICE_ALIASES = {
    "apache tomcat": "tomcat",
    "apache-tomcat": "tomcat",
    "apache_tomcat": "tomcat",
    "apache httpd": "apache",
    "apache http server": "apache",
    # Nmap product names for common services
    "redis key-value store": "redis",
    "redis key value store": "redis",
    "mariadb": "mysql",
    "percona server": "mysql",
    "mysql community server": "mysql",
    "postgresql database": "postgresql",
    "microsoft sql server": "mssql",
    "ms sql server": "mssql",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "apache-log4j": "log4j",
    "apache log4j": "log4j",
    "log4j-core": "log4j",
    "log4j core": "log4j",
    "log4j2": "log4j",
    "logging-log4j2": "log4j",
    "logging log4j2": "log4j",
    "microsoft-iis": "iis",
    "microsoft iis": "iis",
    "node.js": "node",
    "node js": "node",
    "node_js": "node",
    "nodejs": "node",
    "open-ssh": "openssh",
    "open ssh": "openssh",
    "open_ssh": "openssh",
    # Spring variants
    "spring-core": "spring",
    "spring_core": "spring",
    "spring-framework": "spring",
    "spring_framework": "spring",
    "springframework": "spring",
    "spring-boot": "spring-boot",
    "springboot": "spring-boot",
    # Real-world server/runtime names
    "apache traffic server": "ats",
    "apache-traffic-server": "ats",
    "apache_traffic_server": "ats",
    "traffic server": "ats",
    "trafficserver": "ats",
    "varnish cache": "varnish",
    "varnish-cache": "varnish",
    "varnish_cache": "varnish",
    "gunicorn": "gunicorn",
    "uwsgi": "uwsgi",
    "u wsgi": "uwsgi",
    "u_wsgi": "uwsgi",
    "u-wsgi": "uwsgi",
    "plack": "plack",
    "combust plack": "plack",
    "combust/plack": "plack",
    "caddy server": "caddy",
    "traefik proxy": "traefik",
    "cloudflare": "cloudflare",
    "apache trafficserver": "ats",
    # JavaScript libraries
    "jquery": "jquery",
    "jquery ui": "jquery_ui",
    "jquery-ui": "jquery_ui",
    "bootstrap": "bootstrap",
    "twitter bootstrap": "bootstrap",
    "lodash": "lodash",
    "lodash.js": "lodash",
    "moment.js": "moment.js",
    "momentjs": "moment.js",
    "moment": "moment.js",
    "angular": "angular",
    "angularjs": "angular",
    "angular.js": "angular",
    "react": "react",
    "reactjs": "react",
    "react.js": "react",
    "vue.js": "vue.js",
    "vuejs": "vue.js",
    "vue": "vue.js",
    # CMS / application platforms
    "wordpress": "wordpress",
    "wp": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "joomla!": "joomla",
    "shopify": "shopify",
    "magento": "magento",
    "wix": "wix",
    "squarespace": "squarespace",
    # Frameworks
    "next.js": "next.js",
    "nextjs": "next.js",
    "nuxt.js": "nuxt.js",
    "nuxtjs": "nuxt.js",
    "laravel": "laravel",
    "django": "django",
    "rails": "rails",
    "ruby on rails": "rails",
    "asp.net": "asp.net",
    "aspnet": "asp.net",
    "asp net": "asp.net",
    "express": "express",
    "expressjs": "express",
    "express.js": "express",
    "flask": "flask",
    # Frontend tooling
    "font-awesome": "font-awesome",
    "fontawesome": "font-awesome",
    "font awesome": "font-awesome",
    "tailwindcss": "tailwindcss",
    "tailwind css": "tailwindcss",
    "tailwind": "tailwindcss",
    # Web servers
    "openresty": "openresty",
    # Analytics
    "google-analytics": "google-analytics",
    "google analytics": "google-analytics",
    # Languages
    "php": "php",
    # Variant names that should collapse to canonical service
    "wordpress.com": "wordpress",
    "wordpress com": "wordpress",
    "wordpress vip": "wordpress",
    # Additional JS libraries
    "swiper": "swiper",
    "swiperjs": "swiper",
    "swiper.js": "swiper",
    "framer-motion": "framer-motion",
    "framer motion": "framer-motion",
    "gsap": "gsap",
    "greensock": "gsap",
    "three.js": "three.js",
    "threejs": "three.js",
    "d3.js": "d3.js",
    "d3js": "d3.js",
    "socket.io": "socket.io",
    "socketio": "socket.io",
    "ember.js": "ember.js",
    "emberjs": "ember.js",
    "backbone.js": "backbone.js",
    "backbonejs": "backbone.js",
    "handlebars": "handlebars",
    "handlebars.js": "handlebars",
    "underscore.js": "underscore.js",
    "underscorejs": "underscore.js",
    "axios": "axios",
    # Hosting panels
    "plesk": "plesk",
    "pleskwin": "plesk",
    "plesklinux": "plesk",
    "plesklin": "plesk",
    "pleskl": "plesk",
    # Additional JS libraries
    "popper.js": "popper.js",
    "popper": "popper.js",
    "@popperjs/core": "popper.js",
    "owl-carousel": "owl-carousel",
    "owl carousel": "owl-carousel",
    "owlcarousel": "owl-carousel",
    "google-hosted-libraries": "google-hosted-libraries",
    "google hosted libraries": "google-hosted-libraries",
    # Frameworks
    "asp.net-mvc": "asp.net-mvc",
    "asp.net mvc": "asp.net-mvc",
    "aspnetmvc": "asp.net-mvc",
    # Analytics / third-party
    "datadog": "datadog",
    "hotjar": "hotjar",
    # CDN
    "akamai": "akamai",
    # CMS
    "ghost": "ghost",
    "hubspot": "hubspot",
    "gatsby": "gatsby",
    "gatsbyjs": "gatsby",
}

KNOWN_SERVICE_PATTERNS = [
    (re.compile(r"\b(?:apache\s+traffic\s+server|traffic\s+server|ats)\b", re.IGNORECASE), "ats"),
    (re.compile(r"\bvarnish(?:[-\s]?cache)?\b", re.IGNORECASE), "varnish"),
    (re.compile(r"\bcloudflare\b", re.IGNORECASE), "cloudflare"),
    (re.compile(r"\bgunicorn\b", re.IGNORECASE), "gunicorn"),
    (re.compile(r"\bu[\s_-]?wsgi\b", re.IGNORECASE), "uwsgi"),
    (re.compile(r"\bplack\b", re.IGNORECASE), "plack"),
    (re.compile(r"\bcaddy\b", re.IGNORECASE), "caddy"),
    (re.compile(r"\btraefik\b", re.IGNORECASE), "traefik"),
]

VERSION_RE = re.compile(r"^v?(?P<version>\d[A-Za-z0-9._+-]*)$", re.IGNORECASE)

# Matches a product name followed by a version number, with an optional
# literal "version" keyword in between (e.g. "Apache Tomcat version 9.0.54")
PRODUCT_VERSION_RE = re.compile(
    r"^\s*(?P<service>[A-Za-z][A-Za-z0-9.+ _-]*?)"
    r"(?:\s+version)?"           # optional literal "version" keyword
    r"(?:[/\s_-]+)(?P<version>v?\d[A-Za-z0-9._+-]*)\b",
    re.IGNORECASE,
)

# Strips a trailing " version" word that bleeds into the service name when
# the regex above doesn't match (e.g. "Microsoft IIS version 10.0" where
# the whole "Microsoft IIS version" gets captured as the service).
_TRAILING_VERSION_WORD_RE = re.compile(r"\s+version\s*$", re.IGNORECASE)


def normalize_service(service: str) -> str:
    raw = service.strip().lower()
    if not raw:
        return "unknown"

    normalized = re.sub(r"[_./-]+", " ", raw)
    normalized = _TRAILING_VERSION_WORD_RE.sub("", normalized).strip()
    normalized = re.sub(r"\s+", " ", normalized)
    if not normalized or not re.search(r"[a-z0-9]", normalized):
        return "unknown"
    if not re.search(r"[a-z]", normalized):
        return "unknown"

    candidates = [
        normalized,
        raw.replace("_", "-"),
        normalized.replace(" ", "-"),
        normalized.replace(" ", "_"),
        normalized.replace(" ", ""),
    ]
    for candidate in candidates:
        alias = SERVICE_ALIASES.get(candidate)
        if alias:
            return alias
    return normalized


def detect_known_service(text: str) -> str:
    raw = text.strip()
    if not raw:
        return "unknown"

    for pattern, service_name in KNOWN_SERVICE_PATTERNS:
        if pattern.search(raw):
            return service_name

    normalized = normalize_service(raw)
    if normalized != "unknown":
        return normalized
    return "unknown"


def looks_like_version(value: str) -> bool:
    return bool(VERSION_RE.match(value.strip()))


def extract_version_value(text: str) -> str:
    if not text.strip():
        return ""

    match = PRODUCT_VERSION_RE.match(text.strip())
    if match:
        return _normalize_version_value(match.group("version"))

    for part in text.strip().split():
        if looks_like_version(part):
            return _normalize_version_value(part)
    return ""


def parse_product_version(text: str, service_hint: str = "") -> Tuple[str, str]:
    stripped = text.strip()
    if not stripped:
        return "unknown", ""

    normalized_hint = normalize_service(service_hint) if service_hint else ""
    if normalized_hint:
        return normalized_hint, extract_version_value(stripped)

    if looks_like_version(stripped):
        return "unknown", _normalize_version_value(stripped)

    match = PRODUCT_VERSION_RE.match(stripped)
    if match:
        return normalize_service(match.group("service")), _normalize_version_value(match.group("version"))

    parts = stripped.split()
    version_index: Optional[int] = next(
        (index for index, part in enumerate(parts) if looks_like_version(part)), None
    )
    if version_index is not None and version_index > 0:
        return normalize_service(" ".join(parts[:version_index])), _normalize_version_value(parts[version_index])

    return normalize_service(stripped), ""


def _normalize_version_value(value: str) -> str:
    match = VERSION_RE.match(value.strip())
    if match:
        return match.group("version")
    return value.strip()
