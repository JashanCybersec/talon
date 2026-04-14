import json
from pathlib import Path
from typing import Callable, Dict, Optional, Set
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class KEVSource:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, data_dir: Path, logger: Optional[Callable[[str], None]] = None):
        self.data_dir = data_dir
        self.cache_path = self.data_dir / "kev.json"
        self._cve_set: Set[str] = set()
        self._logger = logger or (lambda message: None)
        self._load_cache()

    def update(self) -> bool:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        request = Request(self.URL, headers={"User-Agent": "Talon/1.0"})
        try:
            self._logger(f"Updating KEV cache from {self.URL}")
            with urlopen(request, timeout=20) as response:
                payload = response.read().decode("utf-8")
                self.cache_path.write_text(payload, encoding="utf-8")
                self._load_cache()
                return True
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError) as exc:
            self._logger(f"KEV update failed: {exc}")
            return False

    def has_cve(self, cve_id: str) -> bool:
        return cve_id.upper() in self._cve_set

    def _load_cache(self) -> None:
        self._cve_set = set()
        if not self.cache_path.exists():
            return

        try:
            payload: Dict = json.loads(self.cache_path.read_text(encoding="utf-8"))
            for item in payload.get("vulnerabilities", []):
                cve_id = item.get("cveID")
                if cve_id:
                    self._cve_set.add(cve_id.upper())
        except (OSError, json.JSONDecodeError):
            self._cve_set = set()
