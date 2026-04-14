"""HTML body fingerprinting for technology detection.

Inspects page source (scripts, stylesheets, meta tags, inline patterns,
cookies) to identify technologies and extract versions — similar to what
Wappalyzer does but focused on CVE-relevant software.
"""

import re
from typing import Dict, List, Tuple

from .normalize import normalize_service


# ── Fingerprint rules ──────────────────────────────────────────────────
# Each rule: (service_name, version_regex_or_None, *match_patterns)
# match_patterns are compiled against the HTML body.
# If version_regex is not None it is applied to the first capturing group
# of the match pattern, or to the full match if no group.

_VERSIONED_SCRIPT_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_VERSIONED_LINK_RE = re.compile(
    r"""<link[^>]+href\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_META_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_META_GENERATOR_REV_RE = re.compile(
    r"""<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+name\s*=\s*["']generator["']""",
    re.IGNORECASE,
)


# ── Technology patterns ────────────────────────────────────────────────
# (canonical_name, [(regex_pattern, version_group_index_or_None), ...])
#
# version_group_index: which regex group holds the version.
# None means no version extraction.

TECH_PATTERNS: List[Tuple[str, List[Tuple[re.Pattern, int | None]]]] = [
    # ── JavaScript libraries ──
    ("jquery", [
        (re.compile(r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)[.\-/]", re.I), 1),
        (re.compile(r"jquery/(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"jquery\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"jQuery\s+v?(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"jquery-migrate[.-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("bootstrap", [
        (re.compile(r"bootstrap[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"bootstrap\.min\.(?:js|css)\?ver=(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"Bootstrap\s+v?(\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("lodash", [
        (re.compile(r"lodash[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("moment.js", [
        (re.compile(r"moment[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("angular", [
        (re.compile(r"angular[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r'ng-version="(\d+\.\d+(?:\.\d+)?)"', re.I), 1),
    ]),
    ("react", [
        (re.compile(r"react(?:\.production\.min)?[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"data-reactroot", re.I), None),
    ]),
    ("vue.js", [
        (re.compile(r"vue[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"data-v-[0-9a-f]{8}", re.I), None),
    ]),

    # ── CMS / Application platforms ──
    ("wordpress", [
        (re.compile(r"/wp-(?:content|includes|admin)/", re.I), None),
        (re.compile(r"wp-emoji-release\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r'<meta[^>]+WordPress\s+(\d+\.\d+(?:\.\d+)?)', re.I), 1),
    ]),
    ("drupal", [
        (re.compile(r"Drupal\.settings", re.I), None),
        (re.compile(r"/sites/(?:default|all)/", re.I), None),
        (re.compile(r'Drupal\s+(\d+\.\d+(?:\.\d+)?)', re.I), 1),
    ]),
    ("joomla", [
        (re.compile(r"/media/jui/", re.I), None),
        (re.compile(r"/media/system/js/", re.I), None),
        (re.compile(r'Joomla!\s*-?\s*', re.I), None),
        (re.compile(r'content="Joomla![^"]*(\d+\.\d+(?:\.\d+)?)', re.I), 1),
    ]),
    ("shopify", [
        (re.compile(r"cdn\.shopify\.com", re.I), None),
        (re.compile(r"Shopify\.theme", re.I), None),
    ]),
    ("magento", [
        (re.compile(r"/static/version\d+/frontend/", re.I), None),
        (re.compile(r"Mage\.Cookies", re.I), None),
        (re.compile(r"Mage\.Modules", re.I), None),
        (re.compile(r"requirejs-config\.js\?ver=", re.I), None),
        (re.compile(r'src="[^"]*magento[^"]*\.js"', re.I), None),
        (re.compile(r"X-Magento-", re.I), None),
    ]),
    ("wix", [
        (re.compile(r"static\.parastorage\.com", re.I), None),
        (re.compile(r"wix-code-sdk", re.I), None),
    ]),
    ("squarespace", [
        (re.compile(r"squarespace\.com", re.I), None),
        (re.compile(r"static\d*\.squarespace\.com", re.I), None),
    ]),

    # ── Frameworks ──
    ("next.js", [
        (re.compile(r"/_next/", re.I), None),
        (re.compile(r"__NEXT_DATA__", re.I), None),
        (re.compile(r"next/(\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("nuxt.js", [
        (re.compile(r"/_nuxt/", re.I), None),
        (re.compile(r"__NUXT__", re.I), None),
    ]),
    ("laravel", [
        (re.compile(r"laravel_session", re.I), None),
        (re.compile(r"XSRF-TOKEN", re.I), None),   # Laravel sets this cookie automatically
        # Note: <meta name="csrf-token"> is also used by Rails; removed to avoid
        # false positives. Use laravel_session / XSRF-TOKEN as primary signals.
    ]),
    ("django", [
        (re.compile(r"csrfmiddlewaretoken", re.I), None),
        (re.compile(r"__admin_media_prefix__", re.I), None),
    ]),
    ("rails", [
        (re.compile(r"csrf-param.*authenticity_token", re.I), None),
        (re.compile(r"data-turbo(?:links)?-track", re.I), None),
    ]),
    ("asp.net", [
        (re.compile(r"__VIEWSTATE", re.I), None),
        (re.compile(r"__EVENTVALIDATION", re.I), None),
        (re.compile(r'asp\.net\s+(\d+\.\d+(?:\.\d+)?)', re.I), 1),
    ]),
    ("express", [
        (re.compile(r"X-Powered-By:\s*Express", re.I), None),
    ]),
    ("flask", [
        (re.compile(r"Werkzeug[/\s](\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),

    # ── Web servers (from body clues) ──
    ("apache", [
        (re.compile(r"<address>Apache/(\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("nginx", [
        (re.compile(r"<center>nginx/(\d+\.\d+(?:\.\d+)?)</center>", re.I), 1),
    ]),
    ("openresty", [
        (re.compile(r"openresty/(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"openresty", re.I), None),
    ]),

    # ── Frontend tooling / UI ──
    ("font-awesome", [
        (re.compile(r"font-?awesome[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("tailwindcss", [
        (re.compile(r"tailwindcss[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r'(?:href|src)="[^"]*tailwind[^"]*\.(?:css|js)"', re.I), None),
        (re.compile(r"@import\s+['\"]tailwindcss", re.I), None),
        (re.compile(r"cdn\.tailwindcss\.com", re.I), None),
        (re.compile(r"unpkg\.com/tailwindcss", re.I), None),
        # Tailwind's responsive/variant prefixes followed by bare Tailwind utilities.
        # Require known utility names directly after the colon — this filters out
        # namespaced variants like sm:nv-block or lg:d-flex used by other frameworks.
        (re.compile(
            r'class="[^"]*\b(?:dark|sm|md|lg|xl):'
            r'(?:bg-|text-|flex\b|grid\b|hidden\b|block\b|inline\b|'
            r'p-|m-|w-|h-|rounded|border|font-|items-|justify-|gap-|space-)',
            re.I,
        ), None),
    ]),

    # ── JavaScript libraries (additional) ──
    ("popper.js", [
        (re.compile(r"popper[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"popper\.min\.js", re.I), None),
        (re.compile(r"@popperjs", re.I), None),
    ]),
    ("owl-carousel", [
        (re.compile(r"owl\.carousel[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"owl\.carousel\.js", re.I), None),
        (re.compile(r'class="[^"]*owl-carousel', re.I), None),
    ]),
    ("google-hosted-libraries", [
        (re.compile(r"ajax\.googleapis\.com/ajax/libs/", re.I), None),
    ]),
    ("swiper", [
        (re.compile(r"swiper[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r'class="[^"]*swiper-(?:wrapper|slide|container)', re.I), None),
        (re.compile(r"swiper\.min\.js", re.I), None),
    ]),
    ("framer-motion", [
        (re.compile(r"framer-motion[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"framer-motion", re.I), None),
        (re.compile(r"data-framer-", re.I), None),
    ]),

    # ── Analytics / third-party ──
    ("google-analytics", [
        (re.compile(r"google-analytics\.com/analytics\.js", re.I), None),
        (re.compile(r"googletagmanager\.com", re.I), None),
        (re.compile(r"gtag\(\s*['\"]config['\"]", re.I), None),
    ]),
    ("datadog", [
        (re.compile(r"datadog-rum[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"dd-rum[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"datadoghq\.com", re.I), None),
        (re.compile(r"DatadogRUM", re.I), None),
    ]),
    ("hotjar", [
        (re.compile(r"hotjar\.com", re.I), None),
        (re.compile(r"_hjSettings", re.I), None),
    ]),

    # ── CDN / Security ──
    ("akamai", [
        (re.compile(r"akamai(?:hd|edge)?\.net", re.I), None),
        (re.compile(r"akamaized\.net", re.I), None),
        (re.compile(r"akam/\d+", re.I), None),
    ]),
    ("cloudflare", [
        (re.compile(r"cdnjs\.cloudflare\.com", re.I), None),
        (re.compile(r"__cfduid", re.I), None),
        (re.compile(r"cf-ray", re.I), None),
    ]),

    # ── PHP (from body clues like error pages) ──
    ("php", [
        (re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"X-Powered-By:.*PHP/(\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),

    # ── Additional CMS / Platforms ──
    ("ghost", [
        (re.compile(r"ghost/(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r'class="[^"]*ghost-', re.I), None),
        (re.compile(r"ghost\.org", re.I), None),
    ]),
    ("hubspot", [
        (re.compile(r"js\.hs-scripts\.com", re.I), None),
        (re.compile(r"hubspot\.com", re.I), None),
    ]),
    ("gatsby", [
        (re.compile(r"gatsby[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"___gatsby", re.I), None),
        (re.compile(r"gatsby-image", re.I), None),
    ]),

    # ── Additional JS libraries ──
    ("axios", [
        (re.compile(r"axios[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
    ]),
    ("gsap", [
        (re.compile(r"gsap[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"greensock", re.I), None),
    ]),
    ("three.js", [
        (re.compile(r"three[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"three\.min\.js", re.I), None),
    ]),
    ("d3.js", [
        (re.compile(r"d3[./\-]v?(\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"d3\.min\.js", re.I), None),
    ]),
    ("socket.io", [
        (re.compile(r"socket\.io[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"socket\.io\.js", re.I), None),
    ]),
    ("ember.js", [
        (re.compile(r"ember[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"ember-application", re.I), None),
    ]),
    ("backbone.js", [
        (re.compile(r"backbone[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"backbone\.min\.js", re.I), None),
    ]),
    ("handlebars", [
        (re.compile(r"handlebars[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"Handlebars\.compile", re.I), None),
    ]),
    ("underscore.js", [
        (re.compile(r"underscore[./\-](\d+\.\d+(?:\.\d+)?)", re.I), 1),
        (re.compile(r"underscore\.min\.js", re.I), None),
    ]),
]


def fingerprint_html(
    html: str,
    headers: str = "",
    cookies: str = "",
) -> List[Dict[str, str]]:
    """Scan HTML body, headers, and cookies for technology fingerprints.

    Returns a list of finding dicts compatible with the extractor pipeline.
    """
    combined = f"{headers}\n{html}\n{cookies}"
    findings: List[Dict[str, str]] = []
    seen: set = set()

    # Meta generator tags
    for pattern in (_META_GENERATOR_RE, _META_GENERATOR_REV_RE):
        for match in pattern.finditer(html):
            _process_generator(match.group(1).strip(), findings, seen)

    # Technology patterns
    for service, patterns in TECH_PATTERNS:
        if service in seen:
            continue
        for regex, ver_group in patterns:
            match = regex.search(combined)
            if match:
                version = ""
                if ver_group is not None:
                    try:
                        version = match.group(ver_group)
                    except (IndexError, AttributeError):
                        version = ""
                _add_finding(findings, seen, service, version, match.group(0))
                break

    return findings


def _process_generator(content: str, findings: List[Dict[str, str]], seen: set) -> None:
    """Parse a <meta generator> content value like 'WordPress 6.2' or 'Joomla! 3.9'."""
    if not content:
        return
    # Strip trailing parenthetical URLs like "(https://www.drupal.org)" so they
    # don't get absorbed into the service name.
    cleaned = re.sub(r"\s*\(https?://[^)]+\)", "", content).strip()
    # Drop long strings that look like marketing copy (e.g. "Joomla! - Open Source…").
    # A real generator is short: product name + optional version, typically ≤ 40 chars.
    if len(cleaned) > 60:
        return
    # Also drop strings that contain sentence-like patterns (multiple words after a dash).
    if re.search(r"\s+-\s+\w+\s+\w+", cleaned):
        return
    # Try to split into name + version
    m = re.match(r"^([A-Za-z][A-Za-z0-9.!+ _-]*?)\s+v?(\d+(?:\.\d+)*)", cleaned)
    if m:
        service = normalize_service(m.group(1))
        version = m.group(2)
    else:
        # Only treat the whole string as a bare service name if it looks like
        # a plain product name — skip metadata strings like
        # "WPML ver:4.7.2 stt:1,4,3,27,28,2;" that contain colons or semicolons.
        if re.search(r"[:;]", cleaned):
            return
        service = normalize_service(cleaned)
        version = ""
    if service != "unknown" and service not in seen:
        _add_finding(findings, seen, service, version, content)


def _add_finding(
    findings: List[Dict[str, str]],
    seen: set,
    service: str,
    version: str,
    raw: str,
) -> None:
    normalized = normalize_service(service)
    if normalized == "unknown" or normalized in seen:
        return
    seen.add(normalized)
    evidence_label = "HTML fingerprint"
    if version:
        evidence_label = "HTML fingerprint (versioned)"
    findings.append({
        "service": normalized,
        "version": version,
        "raw": raw[:200],
        "source": "fingerprint",
        "confidence": "Confirmed" if version else "Strong inference",
        "analyze": bool(version),
        "evidence_record": {
            "source": "fingerprint",
            "field": "body",
            "raw": raw[:200],
            "label": evidence_label,
            "direct": True,
        },
    })
