import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class PoCSource:
    BASE_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"

    def __init__(self, data_dir: Path, logger: Optional[Callable[[str], None]] = None):
        self.data_dir = data_dir
        self.cache_dir = self.data_dir / "poc"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._logger = logger or (lambda message: None)

    def update(self) -> bool:
        """Clear stale negative PoC cache entries (empty pocs) so they get re-fetched."""
        cleared = 0
        if not self.cache_dir.exists():
            return True
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                normalized = self._normalize_payload(data)
                if not normalized.get("pocs"):
                    cache_file.unlink()
                    cleared += 1
            except (OSError, json.JSONDecodeError):
                cache_file.unlink(missing_ok=True)
                cleared += 1
        self._logger(f"Cleared {cleared} stale PoC cache entries.")
        return True

    def has_poc(self, cve_id: str) -> bool:
        data = self._get_data(cve_id)
        return bool(data.get("pocs", []))

    def batch_has_poc(self, cve_ids: List[str], max_workers: int = 8) -> Dict[str, bool]:
        unique_ids = sorted({cve_id.upper() for cve_id in cve_ids if cve_id})
        if not unique_ids:
            return {}

        workers = min(max_workers, len(unique_ids))
        self._logger(f"Checking PoC availability for {len(unique_ids)} CVEs with {workers} worker(s).")
        if workers <= 1:
            return {cve_id: self.has_poc(cve_id) for cve_id in unique_ids}

        results: Dict[str, bool] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(self.has_poc, cve_id): cve_id for cve_id in unique_ids}
            for future in as_completed(future_map):
                cve_id = future_map[future]
                try:
                    results[cve_id] = bool(future.result())
                except Exception as exc:  # pragma: no cover - defensive fallback for thread worker failures
                    self._logger(f"PoC lookup failed for {cve_id}: {exc}")
                    results[cve_id] = False
        return results

    def _get_data(self, cve_id: str) -> Dict[str, List[Dict]]:
        normalized_cve = cve_id.upper()
        parts = normalized_cve.split("-")
        if len(parts) < 3 or parts[0] != "CVE" or not parts[1].isdigit():
            self._logger(f"Skipping invalid CVE identifier for PoC lookup: {cve_id}")
            return {"pocs": []}

        cache_path = self.cache_dir / f"{normalized_cve}.json"
        if cache_path.exists():
            try:
                self._logger(f"PoC cache hit for {normalized_cve}.")
                return self._normalize_payload(json.loads(cache_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                self._logger(f"PoC cache read failed for {normalized_cve}, refetching.")

        year = parts[1]
        url = f"{self.BASE_URL}/{year}/{normalized_cve}.json"
        request = Request(url, headers={"User-Agent": "Talon/1.0"})
        try:
            self._logger(f"Fetching PoC data for {normalized_cve} from {url}")
            with urlopen(request, timeout=15) as response:
                payload = response.read().decode("utf-8")
                cache_path.write_text(payload, encoding="utf-8")
                return self._normalize_payload(json.loads(payload))
        except HTTPError as exc:
            if exc.code == 404:
                cache_path.write_text('{"pocs": []}', encoding="utf-8")
                self._logger(f"No PoC found for {normalized_cve} (404).")
            else:
                self._logger(f"PoC lookup failed for {normalized_cve} with HTTP {exc.code}.")
            return {"pocs": []}
        except (URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._logger(f"PoC lookup failed for {normalized_cve}: {exc}")
            return {"pocs": []}

    @staticmethod
    def _normalize_payload(payload) -> Dict[str, List[Dict]]:
        if isinstance(payload, dict):
            pocs = payload.get("pocs", [])
            return {"pocs": pocs if isinstance(pocs, list) else []}
        if isinstance(payload, list):
            return {"pocs": payload}
        return {"pocs": []}
