import json
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# Maps Talon service names to OSV ecosystem identifiers.
# OSV uses ecosystem to scope queries — without it results are too broad.
ECOSYSTEM_MAP = {
    "express":    ("npm", "express"),
    "jquery":     ("npm", "jquery"),
    "django":     ("PyPI", "django"),
    "flask":      ("PyPI", "flask"),
    "requests":   ("PyPI", "requests"),
    "spring":     ("Maven", "org.springframework:spring-core"),
    "log4j":      ("Maven", "org.apache.logging.log4j:log4j-core"),
    "struts":     ("Maven", "org.apache.struts:struts2-core"),
    "lodash":     ("npm", "lodash"),
    "axios":      ("npm", "axios"),
    "moment":     ("npm", "moment"),
    "react":      ("npm", "react"),
    "vue":        ("npm", "vue"),
    "angular":    ("npm", "@angular/core"),
}


class OSVSource:
    API_URL = "https://api.osv.dev/v1/query"

    def __init__(self, data_dir: Path, logger: Optional[Callable[[str], None]] = None):
        self.data_dir = data_dir
        self._logger = logger or (lambda message: None)

    def query(self, service: str, version: str) -> List[Dict]:
        """
        Query OSV for CVEs affecting this service+version.
        Returns a list of dicts with cve_id, description, cvss, severity, aliases.
        Only runs if the service is in ECOSYSTEM_MAP — avoids useless queries.
        """
        service_key = service.strip().lower()
        if service_key not in ECOSYSTEM_MAP:
            self._logger(f"OSV: no ecosystem mapping for '{service}', skipping.")
            return []

        ecosystem, package_name = ECOSYSTEM_MAP[service_key]
        payload: Dict = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version

        self._logger(f"OSV query: ecosystem={ecosystem} package={package_name} version={version or 'any'}")
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            self.API_URL,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "Talon/1.0"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            self._logger(f"OSV request failed: HTTP {exc.code}")
            return []
        except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._logger(f"OSV request failed: {exc}")
            return []

        results = []
        for vuln in data.get("vulns", []):
            cve_id = self._extract_cve_id(vuln)
            if not cve_id:
                continue
            description = (vuln.get("summary") or vuln.get("details") or "")[:300]
            severity = self._extract_severity(vuln)
            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss": severity,
                "cpes": [],
                "cpe_matches": [],
                "source": "osv",
            })

        self._logger(f"OSV: found {len(results)} CVEs for {package_name}@{version or 'any'}.")
        return results

    @staticmethod
    def _extract_cve_id(vuln: Dict) -> str:
        """Pull the CVE-YYYY-NNNNN alias out of the vuln's aliases list."""
        osv_id = vuln.get("id", "")
        if osv_id.startswith("CVE-"):
            return osv_id
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return ""

    @staticmethod
    def _extract_severity(vuln: Dict) -> float:
        """
        Extract CVSS base score from OSV severity array.

        OSV severity[].score is a CVSS vector string like:
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        or sometimes a plain numeric string like "9.8".

        We compute the base score from the vector's metric weights,
        or fall back to database_specific fields.
        """
        # CVSS v3 metric weights for base score calculation
        _AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        _AC  = {"L": 0.77, "H": 0.44}
        _PR_U= {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
        _PR_C= {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
        _UI  = {"N": 0.85, "R": 0.62}
        _CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

        for entry in vuln.get("severity", []):
            score_str = (entry.get("score") or "").strip()
            if not score_str:
                continue

            # Plain numeric score
            try:
                val = float(score_str)
                if 0.0 <= val <= 10.0:
                    return val
            except ValueError:
                pass

            # CVSS vector string
            if score_str.upper().startswith("CVSS:"):
                try:
                    metrics: dict = {}
                    for part in score_str.split("/")[1:]:
                        if ":" in part:
                            k, v = part.split(":", 1)
                            metrics[k.upper()] = v.upper()

                    scope = metrics.get("S", "U")
                    av  = _AV.get(metrics.get("AV", ""), 0.0)
                    ac  = _AC.get(metrics.get("AC", ""), 0.0)
                    pr  = (_PR_C if scope == "C" else _PR_U).get(metrics.get("PR", ""), 0.0)
                    ui  = _UI.get(metrics.get("UI", ""), 0.0)
                    c   = _CIA.get(metrics.get("C", ""), 0.0)
                    i   = _CIA.get(metrics.get("I", ""), 0.0)
                    a   = _CIA.get(metrics.get("A", ""), 0.0)

                    iss = 1 - (1 - c) * (1 - i) * (1 - a)
                    if scope == "C":
                        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
                    else:
                        impact = 6.42 * iss

                    exploitability = 8.22 * av * ac * pr * ui

                    if impact <= 0:
                        base = 0.0
                    elif scope == "C":
                        base = min(1.08 * (impact + exploitability), 10.0)
                    else:
                        base = min(impact + exploitability, 10.0)

                    # Round up to 1 decimal per CVSS spec
                    import math
                    base = math.ceil(base * 10) / 10
                    return round(base, 1)
                except (KeyError, ZeroDivisionError, ValueError, TypeError):
                    pass

        # Last resort: database_specific fields
        db = vuln.get("database_specific") or {}
        for field in ("cvss_score", "severity_score", "base_score", "score"):
            val = db.get(field)
            if val is not None:
                try:
                    result = float(val)
                    if 0.0 <= result <= 10.0:
                        return result
                except (ValueError, TypeError):
                    pass

        return 0.0
