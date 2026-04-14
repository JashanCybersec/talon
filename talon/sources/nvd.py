import json
import re
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class NVDSource:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _last_request_time = 0.0
    _VERSION_CORE_RE = re.compile(r"^\d+(?:\.\d+)*")

    # Maps service names to CPE vendor:product pairs for virtualMatchString queries.
    # This lets NVD do server-side version range matching instead of keyword search.
    CPE_MAP = {
        "apache":    ("apache", "http_server"),
        "ats":       ("apache", "traffic_server"),
        "nginx":     ("f5", "nginx"),
        "openssh":   ("openbsd", "openssh"),
        "iis":       ("microsoft", "internet_information_services"),
        "tomcat":    ("apache", "tomcat"),
        "lighttpd":  ("lighttpd", "lighttpd"),
        "varnish":   ("varnish-cache", "varnish-cache"),
        "gunicorn":  ("gunicorn", "gunicorn"),
        "uwsgi":     ("unbit", "uwsgi"),
        "caddy":     ("caddyserver", "caddy"),
        "traefik":   ("traefik", "traefik"),
        "envoy":     ("envoyproxy", "envoy"),
        "haproxy":   ("haproxy", "haproxy"),
        "postfix":   ("postfix", "postfix"),
        "vsftpd":    ("beasts", "vsftpd"),
        "proftpd":   ("proftpd_project", "proftpd"),
        "openssl":   ("openssl", "openssl"),
        "php":       ("php", "php"),
        "mysql":     ("oracle", "mysql"),
        "postgresql": ("postgresql", "postgresql"),
        "redis":     ("redis", "redis"),
        "curl":      ("haxx", "curl"),
        "wordpress": ("wordpress", "wordpress"),
        "jquery":    ("jquery", "jquery"),
        "node":      ("nodejs", "node.js"),
        "nodejs":    ("nodejs", "node.js"),
        "express":   ("expressjs", "express"),
        "django":    ("djangoproject", "django"),
        "flask":     ("palletsprojects", "flask"),
        "spring":       ("vmware", "spring_framework"),
        "spring-boot":  ("vmware", "spring_boot"),
        "drupal":       ("drupal", "drupal"),
        "joomla":       ("joomla", "joomla\\!"),
        "laravel":      ("laravel", "laravel"),
        "rails":        ("rubyonrails", "ruby_on_rails"),
        "asp.net":      ("microsoft", "asp.net"),
        "asp.net-mvc":  ("microsoft", "asp.net_mvc"),
        "mssql":        ("microsoft", "sql_server"),
        "log4j":        ("apache", "log4j"),
        "openresty":    ("openresty", "openresty"),
        "plesk":        ("parallels", "plesk"),
    }

    def __init__(self, data_dir: Path, logger: Optional[Callable[[str], None]] = None):
        self.data_dir = data_dir
        self._logger = logger or (lambda message: None)

    def search(self, service: str, version: str, results_per_page: int = 50) -> List[Dict]:
        results: List[Dict] = []
        seen_ids = set()

        # Strategy 1: CPE-based search (precise, server-side version matching)
        # This is the most accurate — NVD checks version ranges for us.
        if version:
            cpe_string = self._build_cpe_string(service, version)
            if cpe_string:
                self._collect_cpe_results(cpe_string, results_per_page, 3, results, seen_ids)

        # Strategy 2: Keyword search (catches CVEs without proper CPE data)
        keywords = self._build_keywords(service, version)
        if version:
            for keyword in keywords[:-1]:
                self._collect_results(keyword, results_per_page, 1, results, seen_ids)

        # Strategy 3: Service-only keyword (broad sweep, 2 pages)
        service_keyword = keywords[-1]
        self._collect_results(service_keyword, results_per_page, 2, results, seen_ids)
        return results

    def _collect_results(
        self,
        keyword: str,
        results_per_page: int,
        max_pages: int,
        results: List[Dict],
        seen_ids: set,
    ) -> None:
        for page in range(max_pages):
            self._logger(f"NVD keyword search: '{keyword}' page {page + 1}")
            payload = self._search_keyword(keyword, results_per_page, start_index=page * results_per_page)
            if not payload:
                break

            vulnerabilities = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)

                descriptions = cve.get("descriptions", [])
                description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
                cpe_matches = self._collect_cpe_matches(cve.get("configurations", []))
                results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss": self._extract_cvss(cve.get("metrics", {})),
                    "cpes": [entry["criteria"] for entry in cpe_matches],
                    "cpe_matches": cpe_matches,
                })

            total_results = int(payload.get("totalResults", 0) or 0)
            if (page + 1) * results_per_page >= total_results:
                break

    def _build_cpe_string(self, service: str, version: str) -> str:
        """Build a CPE 2.3 string for virtualMatchString queries."""
        normalized = service.strip().lower().replace("-", "").replace("_", "")
        cpe_pair = self.CPE_MAP.get(normalized)
        if not cpe_pair:
            # Try with original service name
            cpe_pair = self.CPE_MAP.get(service.strip().lower())
        if not cpe_pair:
            return ""
        vendor, product = cpe_pair
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    def _collect_cpe_results(
        self,
        cpe_string: str,
        results_per_page: int,
        max_pages: int,
        results: List[Dict],
        seen_ids: set,
    ) -> None:
        """Search NVD using virtualMatchString — server-side CPE version range matching."""
        for page in range(max_pages):
            self._logger(f"NVD CPE search: '{cpe_string}' page {page + 1}")
            params = urlencode({
                "virtualMatchString": cpe_string,
                "resultsPerPage": results_per_page,
                "startIndex": page * results_per_page,
            })
            url = f"{self.BASE_URL}?{params}"
            payload = self._fetch_json(url)
            if not payload:
                break

            vulnerabilities = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)

                descriptions = cve.get("descriptions", [])
                description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
                cpe_matches = self._collect_cpe_matches(cve.get("configurations", []))
                results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss": self._extract_cvss(cve.get("metrics", {})),
                    "cpes": [entry["criteria"] for entry in cpe_matches],
                    "cpe_matches": cpe_matches,
                })

            total_results = int(payload.get("totalResults", 0) or 0)
            if (page + 1) * results_per_page >= total_results:
                break

    def _search_keyword(self, keyword: str, results_per_page: int, start_index: int = 0) -> Dict:
        params = urlencode({"keywordSearch": keyword, "resultsPerPage": results_per_page, "startIndex": start_index})
        url = f"{self.BASE_URL}?{params}"
        return self._fetch_json(url)

    def _fetch_json(self, url: str, retries: int = 3) -> Dict:
        for attempt in range(retries):
            self._throttle()
            request = Request(url, headers={"User-Agent": "Talon/1.0"})
            try:
                with urlopen(request, timeout=20) as response:
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as exc:
                if exc.code in {403, 429, 500, 502, 503, 504} and attempt < retries - 1:
                    self._logger(f"NVD request failed with HTTP {exc.code}, retrying attempt {attempt + 2}.")
                    time.sleep(1 + attempt)
                    continue
                self._logger(f"NVD request failed with HTTP {exc.code}: {url}")
                return {}
            except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                if attempt < retries - 1:
                    self._logger(f"NVD request error '{exc}', retrying attempt {attempt + 2}.")
                    time.sleep(1 + attempt)
                    continue
                self._logger(f"NVD request error '{exc}': {url}")
                return {}
        return {}

    @classmethod
    def _throttle(cls) -> None:
        elapsed = time.time() - cls._last_request_time
        if elapsed < 1:
            time.sleep(1 - elapsed)
        cls._last_request_time = time.time()

    def _build_keywords(self, service: str, version: str) -> List[str]:
        keywords: List[str] = []
        seen = set()

        def add_keyword(candidate: str) -> None:
            value = candidate.strip()
            if value and value not in seen:
                seen.add(value)
                keywords.append(value)

        if version:
            add_keyword(f"{service} {version}")

            core_version = self._extract_core_version(version)
            if core_version and core_version != version:
                add_keyword(f"{service} {core_version}")

            family_version = self._extract_family_version(version)
            if family_version and family_version not in {version, core_version}:
                add_keyword(f"{service} {family_version}")

        add_keyword(service)
        return keywords

    def _collect_cpe_matches(self, configurations: List[Dict]) -> List[Dict]:
        cpe_matches: List[Dict] = []

        def walk_nodes(nodes: List[Dict], depth: int = 0) -> None:
            if depth > 10:
                return
            for node in nodes:
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria")
                    if criteria:
                        cpe_matches.append({
                            "criteria": criteria.lower(),
                            "version_start_including": match.get("versionStartIncluding") or "",
                            "version_start_excluding": match.get("versionStartExcluding") or "",
                            "version_end_including": match.get("versionEndIncluding") or "",
                            "version_end_excluding": match.get("versionEndExcluding") or "",
                            "vulnerable": bool(match.get("vulnerable", True)),
                        })
                walk_nodes(node.get("nodes", []), depth + 1)

        for config in configurations:
            walk_nodes(config.get("nodes", []))
        return cpe_matches

    @staticmethod
    def _extract_cvss(metrics: Dict) -> float:
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score)
        return 0.0

    @classmethod
    def _extract_core_version(cls, version: str) -> str:
        match = cls._VERSION_CORE_RE.match(version.strip().lower())
        return match.group(0) if match else ""

    @classmethod
    def _extract_family_version(cls, version: str) -> str:
        core_version = cls._extract_core_version(version)
        if not core_version:
            return ""
        parts = core_version.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else core_version
