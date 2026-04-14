import re
from typing import Dict, Iterable, List, Tuple


DESCRIPTION_ALIASES = {
    "apache": {"apache http server", "apache httpd"},
    "ats": {"apache traffic server", "traffic server", "ats"},
    "nginx": {"nginx"},
    "openssh": {"openssh", "open ssh"},
    "iis": {"iis", "internet information services"},
    "log4j": {"log4j", "log4j-core", "log4j2"},
    "node": {"node.js", "nodejs"},
    "tomcat": {"tomcat", "apache tomcat"},
    "lighttpd": {"lighttpd"},
    "varnish": {"varnish", "varnish cache"},
    "cloudflare": {"cloudflare"},
    "gunicorn": {"gunicorn"},
    "uwsgi": {"uwsgi", "uWSGI"},
    "plack": {"plack"},
    "caddy": {"caddy"},
    "traefik": {"traefik"},
    "envoy": {"envoy", "envoy proxy"},
    "haproxy": {"haproxy", "ha-proxy"},
    "postfix": {"postfix"},
    "vsftpd": {"vsftpd"},
    "proftpd": {"proftpd"},
    # JavaScript libraries
    "jquery": {"jquery"},
    "jquery_ui": {"jquery ui", "jquery_ui"},
    "bootstrap": {"bootstrap", "twitter bootstrap"},
    "lodash": {"lodash"},
    "moment.js": {"moment.js", "moment"},
    "angular": {"angular", "angularjs"},
    "react": {"react", "reactjs"},
    "vue.js": {"vue.js", "vuejs", "vue"},
    # CMS / application platforms
    "wordpress": {"wordpress"},
    "drupal": {"drupal"},
    "joomla": {"joomla", "joomla!"},
    "magento": {"magento"},
    # Frameworks
    "next.js": {"next.js", "nextjs"},
    "nuxt.js": {"nuxt.js", "nuxtjs"},
    "laravel": {"laravel"},
    "django": {"django"},
    "rails": {"rails", "ruby on rails"},
    "asp.net": {"asp.net"},
    "express": {"express", "expressjs"},
    "flask": {"flask", "werkzeug"},
    # Web servers
    "openresty": {"openresty"},
    # Hosting panels
    "plesk": {"plesk"},
    # Web frameworks
    "asp.net-mvc": {"asp.net mvc", "asp.net-mvc"},
    # Additional JS libraries
    "popper.js": {"popper.js", "popper"},
    "owl-carousel": {"owl carousel", "owl-carousel"},
    # Languages
    "php": {"php"},
    # Additional JS libraries
    "swiper": {"swiper"},
    "framer-motion": {"framer-motion", "framer motion"},
    "gsap": {"gsap", "greensock"},
    "three.js": {"three.js"},
    "d3.js": {"d3.js", "d3"},
    "socket.io": {"socket.io"},
    "ember.js": {"ember.js", "ember"},
    "backbone.js": {"backbone.js", "backbone"},
    "handlebars": {"handlebars"},
    "underscore.js": {"underscore.js", "underscore"},
    "axios": {"axios"},
    # CMS
    "ghost": {"ghost"},
    "gatsby": {"gatsby"},
}

CPE_ALIASES = {
    "apache": {"http_server", "apache:http_server"},
    "ats": {"traffic_server", "apache:traffic_server"},
    "nginx": {"nginx", "f5:nginx"},
    "openssh": {"openssh", "openbsd:openssh"},
    "iis": {
        "iis",
        "internet_information_server",
        "internet_information_services",
        "microsoft:internet_information_server",
        "microsoft:internet_information_services",
    },
    "log4j": {"log4j", "apache:log4j", "logging_log4j2", "apache:logging_log4j2"},
    "node": {"node_js", "nodejs:node_js"},
    "tomcat": {"tomcat", "apache:tomcat"},
    "lighttpd": {"lighttpd", "lighttpd:lighttpd"},
    "varnish": {"varnish_cache", "varnish_cache:varnish_cache"},
    "cloudflare": {"cloudflare", "cloudflare:cloudflare"},
    "gunicorn": {"gunicorn", "gunicorn:gunicorn"},
    "uwsgi": {"uwsgi", "unbit:uwsgi"},
    "plack": {"plack", "plack:plack"},
    "caddy": {"caddy", "caddyserver:caddy"},
    "traefik": {"traefik", "traefik:traefik"},
    "envoy": {"envoy", "envoyproxy:envoy"},
    "haproxy": {"haproxy", "haproxy:haproxy"},
    "postfix": {"postfix", "postfix:postfix"},
    "vsftpd": {"vsftpd", "vsftpd:vsftpd"},
    "proftpd": {"proftpd", "proftpd:proftpd"},
    # JavaScript libraries
    "jquery": {"jquery", "jquery:jquery"},
    "jquery_ui": {"jquery_ui", "jquery:jquery_ui"},
    "bootstrap": {"bootstrap", "twbs:bootstrap", "getbootstrap:bootstrap"},
    "lodash": {"lodash", "lodash:lodash"},
    "moment.js": {"moment", "moment:moment", "momentjs:moment"},
    "angular": {"angular", "angularjs", "google:angular"},
    "react": {"react", "facebook:react"},
    "vue.js": {"vue", "vue.js", "vuejs:vue.js", "vuejs:vue"},
    # CMS / application platforms
    "wordpress": {"wordpress", "wordpress:wordpress"},
    "drupal": {"drupal", "drupal:drupal"},
    "joomla": {"joomla", "joomla!:joomla", "joomla:joomla"},
    "magento": {"magento", "magento:magento", "adobe:magento"},
    # Frameworks
    "next.js": {"nextjs", "vercel:next.js", "next.js"},
    "nuxt.js": {"nuxt", "nuxt.js", "nuxtjs:nuxt.js"},
    "laravel": {"laravel", "laravel:laravel"},
    "django": {"django", "djangoproject:django"},
    "rails": {"rails", "rubyonrails:rails"},
    "asp.net": {"asp.net", "microsoft:asp.net", ".net", "microsoft:.net"},
    "express": {"express", "expressjs:express"},
    "flask": {"flask", "palletsprojects:flask", "werkzeug", "palletsprojects:werkzeug"},
    # Web servers
    "openresty": {"openresty", "openresty:openresty"},
    # Languages
    "php": {"php", "php:php"},
    # Hosting panels
    "plesk": {"plesk", "parallels:plesk"},
    # Web frameworks
    "asp.net-mvc": {"asp.net_mvc", "microsoft:asp.net_mvc"},
    # Additional JS libraries
    "popper.js": {"popper.js", "floating-ui:popper.js"},
    "owl-carousel": {"owl-carousel", "owlcarousel2:owlcarousel"},
    # Additional JS libraries
    "swiper": {"swiper", "nolimits4web:swiper"},
    "framer-motion": {"framer-motion", "framer:motion"},
    "gsap": {"gsap", "greensock:gsap"},
    "three.js": {"three.js", "mrdoob:three.js"},
    "d3.js": {"d3", "d3:d3", "d3.js"},
    "socket.io": {"socket.io", "socket:socket.io"},
    "ember.js": {"ember.js", "emberjs:ember.js"},
    "backbone.js": {"backbone.js", "jashkenas:backbone"},
    "handlebars": {"handlebars", "handlebars.js", "handlebarsjs:handlebars"},
    "underscore.js": {"underscore.js", "jashkenas:underscore"},
    "axios": {"axios", "axios:axios"},
    # CMS
    "ghost": {"ghost", "ghost:ghost", "tryghost:ghost"},
    "gatsby": {"gatsby", "gatsbyjs:gatsby"},
}

WILDCARD_VERSIONS = {"", "*", "-"}
VERSION_TOKEN_RE = re.compile(r"\d+|[a-z]+", re.IGNORECASE)
VERSION_CORE_RE = re.compile(r"^\d+(?:\.\d+)*")
PRE_RELEASE_QUALIFIERS = {"dev", "snapshot", "alpha", "a", "beta", "b", "pre", "preview", "rc", "c"}
POST_RELEASE_QUALIFIERS = {"p", "pl", "patch", "post", "hotfix", "sp"}
DESCRIPTION_FALLBACK_DISABLED = {"iis", "cloudflare"}


def determine_match_strength(service: str, version: str, cve: Dict) -> Tuple[str, int, bool]:
    description = (cve.get("description") or "").lower()
    normalized_service = _normalize_token(service)
    service_keys = _service_description_keys(service)
    cpe_keys = _service_cpe_keys(service)
    matching_cpes = [
        entry for entry in cve.get("cpe_matches", [])
        if entry.get("vulnerable", True) and _service_matches_cpe(entry.get("criteria", ""), cpe_keys)
    ]

    # OSV results are already pre-filtered by package+version at query time.
    # They have no CPE data, so we trust the source directly instead of
    # requiring CPE evidence — otherwise all OSV hits get dropped as Unknown.
    if cve.get("source") == "osv":
        if version:
            return "Exact", 20, True
        return "Service", 0, True

    # If the exact package@version was independently confirmed by OSV, keep the
    # structured NVD metadata for enrichment but treat the match strength as
    # exact. This is especially important for ecosystems where NVD models
    # affected versions as wide ranges instead of literal per-version CPEs.
    if cve.get("osv_hit") and version:
        return "Exact", 20, True

    # CVEs with generic protocol criteria (for example HTTP/2 Rapid Reset)
    # should not be presented as product-exact findings even if NVD also lists
    # product-specific affected ranges.
    if matching_cpes and _has_protocol_level_evidence(cve):
        return "Protocol", 0, True

    if version:
        if any(_is_exact_cpe_version_match(version, entry) for entry in matching_cpes):
            return "Exact", 20, True

        if any(_is_partial_cpe_version_match(version, entry) for entry in matching_cpes):
            return "Partial", 5, True

        if (
            normalized_service not in DESCRIPTION_FALLBACK_DISABLED
            and _description_mentions_service(description, service_keys)
            and _description_mentions_version(description, version)
        ):
            return "Description", -10, True

        return "Unknown", 0, False

    if matching_cpes:
        return "Service", 0, True

    if normalized_service not in DESCRIPTION_FALLBACK_DISABLED and _description_mentions_service(description, service_keys):
        return "Description", -10, True

    return "Unknown", 0, False


def _service_description_keys(service: str) -> List[str]:
    normalized = _normalize_token(service)
    keys = DESCRIPTION_ALIASES.get(normalized, {normalized})
    return sorted({key.lower() for key in keys if key}, key=len, reverse=True)


def _service_cpe_keys(service: str) -> List[str]:
    normalized = _normalize_token(service)
    keys = CPE_ALIASES.get(normalized, {normalized})
    return sorted({key.lower() for key in keys if key}, key=len, reverse=True)


def _service_matches_cpe(criteria: str, service_keys: Iterable[str]) -> bool:
    vendor, product, _ = _parse_cpe(criteria)
    combined = f"{vendor}:{product}" if vendor and product else ""
    return any(key in {product, combined} for key in service_keys)


def _description_mentions_service(description: str, service_keys: Iterable[str]) -> bool:
    return any(_phrase_in_text(key, description) for key in service_keys)


def _description_mentions_version(description: str, version: str) -> bool:
    versions = {version.lower()}
    core_version = _core_version(version)
    if core_version:
        versions.add(core_version)
    return any(
        candidate and re.search(rf"(?<![a-z0-9]){re.escape(candidate)}(?![a-z0-9])", description)
        for candidate in versions
    )


def _is_exact_cpe_version_match(version: str, cpe_match: Dict) -> bool:
    _, _, criteria_version = _parse_cpe(cpe_match.get("criteria", ""))
    return criteria_version not in WILDCARD_VERSIONS and _versions_equivalent(version, criteria_version)


def _is_partial_cpe_version_match(version: str, cpe_match: Dict) -> bool:
    if _version_in_range(version, cpe_match):
        return True
    _, _, criteria_version = _parse_cpe(cpe_match.get("criteria", ""))
    if criteria_version in WILDCARD_VERSIONS:
        return False
    return _version_prefix_match(version, criteria_version)


def _version_in_range(version: str, cpe_match: Dict) -> bool:
    target_version = _comparable_version(version)
    if not target_version:
        return False

    start_including = _comparable_version(cpe_match.get("version_start_including", ""))
    start_excluding = _comparable_version(cpe_match.get("version_start_excluding", ""))
    end_including = _comparable_version(cpe_match.get("version_end_including", ""))
    end_excluding = _comparable_version(cpe_match.get("version_end_excluding", ""))

    if start_including and _compare_versions(target_version, start_including) < 0:
        return False
    if start_excluding and _compare_versions(target_version, start_excluding) <= 0:
        return False
    if end_including and _compare_versions(target_version, end_including) > 0:
        return False
    if end_excluding and _compare_versions(target_version, end_excluding) >= 0:
        return False

    return any([start_including, start_excluding, end_including, end_excluding])


def _versions_equivalent(left: str, right: str) -> bool:
    return _compare_versions(_comparable_version(left), _comparable_version(right)) == 0


def _version_prefix_match(left: str, right: str) -> bool:
    left_version = _comparable_version(left)
    right_version = _comparable_version(right)
    if not left_version or not right_version or _versions_equivalent(left_version, right_version):
        return False

    return _has_safe_version_prefix(left_version, right_version) or _has_safe_version_prefix(right_version, left_version)


def _comparable_version(version: str) -> str:
    return version.strip().lower()


def _core_version(version: str) -> str:
    match = VERSION_CORE_RE.match(version.strip().lower())
    return match.group(0) if match else ""


def _family_version(version: str) -> str:
    core_version = _core_version(version)
    if not core_version:
        return ""
    parts = core_version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else core_version


def _has_safe_version_prefix(prefix: str, full: str) -> bool:
    if not full.startswith(prefix) or len(full) <= len(prefix):
        return False
    return not full[len(prefix)].isdigit()


def _compare_versions(left: str, right: str) -> int:
    left_tokens = _version_tokens(left)
    right_tokens = _version_tokens(right)
    index = 0

    while index < len(left_tokens) and index < len(right_tokens):
        left_token = left_tokens[index]
        right_token = right_tokens[index]
        if left_token == right_token:
            index += 1
            continue
        if isinstance(left_token, int) and isinstance(right_token, int):
            return -1 if left_token < right_token else 1
        return -1 if str(left_token) < str(right_token) else 1

    left_tail = left_tokens[index:]
    right_tail = right_tokens[index:]
    left_tail_rank = _tail_rank(left_tail)
    right_tail_rank = _tail_rank(right_tail)
    if left_tail_rank != right_tail_rank:
        return -1 if left_tail_rank < right_tail_rank else 1
    if _tokens_are_zeroish(left_tail) and _tokens_are_zeroish(right_tail):
        return 0
    if _tokens_are_zeroish(left_tail):
        return -1
    if _tokens_are_zeroish(right_tail):
        return 1
    if not left_tail and right_tail:
        return -1
    if left_tail and not right_tail:
        return 1
    return 0


def _version_tokens(version: str) -> List[object]:
    tokens: List[object] = []
    for token in VERSION_TOKEN_RE.findall(version.lower()):
        tokens.append(int(token) if token.isdigit() else token)
    return tokens


def _tail_rank(tokens: Iterable[object]) -> int:
    normalized = list(tokens)
    if not normalized:
        return 0
    if _tokens_are_zeroish(normalized):
        return 0
    first_text = next((token for token in normalized if isinstance(token, str)), "")
    if first_text in PRE_RELEASE_QUALIFIERS:
        return -1
    if first_text in POST_RELEASE_QUALIFIERS:
        return 1
    return 1


def _phrase_in_text(phrase: str, text: str) -> bool:
    words = [re.escape(word) for word in phrase.split() if word]
    if not words:
        return False
    pattern = r"(?<![a-z0-9])" + r"(?:[\s_-]+)".join(words) + r"(?![a-z0-9])"
    return re.search(pattern, text) is not None


def _tokens_are_zeroish(tokens: Iterable[object]) -> bool:
    normalized = list(tokens)
    if not normalized:
        return True
    return all(token == 0 for token in normalized if isinstance(token, int)) and not any(
        isinstance(token, str) for token in normalized
    )


def _parse_cpe(criteria: str) -> Tuple[str, str, str]:
    parts = criteria.split(":")
    vendor = _normalize_token(parts[3]) if len(parts) > 3 else ""
    product = _normalize_token(parts[4]) if len(parts) > 4 else ""
    version = parts[5].strip().lower() if len(parts) > 5 else ""
    return vendor, product, version


def _normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _has_protocol_level_evidence(cve: Dict) -> bool:
    description = (cve.get("description") or "").lower()
    if "http/2" in description and "protocol" in description:
        return True

    for entry in cve.get("cpe_matches", []):
        vendor, product, version = _parse_cpe(entry.get("criteria", ""))
        if vendor == "ietf" and product == "http" and (version.startswith("2") or version in WILDCARD_VERSIONS):
            return True
    return False
