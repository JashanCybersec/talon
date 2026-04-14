import re
import socket
import ssl
from typing import Dict, List
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .fingerprint import fingerprint_html
from .header import extract_from_headers


def extract_from_url(url: str, timeout: int = 10) -> List[Dict[str, str]]:
    raw_url = url.strip()
    if not raw_url:
        return [_invalid_url_result(raw_url, "Invalid URL: empty input.")]

    if "://" not in raw_url:
        url = f"http://{raw_url}"
        parsed = urlparse(url)
    else:
        url = raw_url
        parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return [{
            "service": "unknown",
            "version": "",
            "raw": url,
            "source": "url",
            "warning": f"Unsupported URL scheme: {parsed.scheme}",
        }]

    if not parsed.hostname:
        return [_invalid_url_result(url, "Invalid URL: missing host.")]

    try:
        request = Request(url, headers={"User-Agent": "Talon/1.0"})
    except ValueError:
        return [_invalid_url_result(url, f"Invalid URL: {url}")]

    try:
        with urlopen(request, timeout=timeout) as response:
            header_blob = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
            try:
                body = response.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            cookie_header = response.headers.get("Set-Cookie", "")
            findings = extract_from_headers(header_blob)
            fp_findings = fingerprint_html(body, headers=header_blob, cookies=cookie_header)
            _merge_fingerprint_findings(findings, fp_findings)
            for finding in findings:
                finding["target"] = url
                finding["raw_headers"] = header_blob
            return findings
    except HTTPError as exc:
        if exc.headers:
            header_blob = "\n".join(f"{key}: {value}" for key, value in exc.headers.items())
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            cookie_header = exc.headers.get("Set-Cookie", "")
            findings = extract_from_headers(header_blob)
            fp_findings = fingerprint_html(body, headers=header_blob, cookies=cookie_header)
            _merge_fingerprint_findings(findings, fp_findings)
            for finding in findings:
                finding["target"] = url
                finding["raw_headers"] = header_blob
                finding.setdefault("warning", f"HTTP {exc.code} - headers still parsed.")
            if header_blob.strip():
                return findings
        return [{
            "service": "unknown",
            "version": "",
            "raw": url,
            "source": "url",
            "warning": f"HTTP error while fetching URL: {exc.code}",
        }]
    except (URLError, TimeoutError, socket.timeout) as exc:
        return [{
            "service": "unknown",
            "version": "",
            "raw": url,
            "source": "url",
            "warning": f"Network error while fetching URL: {getattr(exc, 'reason', str(exc))}",
        }]
    except ssl.SSLError as exc:
        return [{
            "service": "unknown",
            "version": "",
            "raw": url,
            "source": "url",
            "warning": f"SSL error while fetching URL: {exc}",
        }]
    except OSError as exc:
        return [{
            "service": "unknown",
            "version": "",
            "raw": url,
            "source": "url",
            "warning": f"Connection error while fetching URL: {exc}",
        }]


def _merge_fingerprint_findings(
    findings: List[Dict[str, str]],
    fp_findings: List[Dict[str, str]],
) -> None:
    """Merge fingerprint findings into the main list, avoiding duplicates."""
    from .normalize import normalize_service  # noqa: PLC0415
    existing_services = {
        _base_service(normalize_service(f.get("service", "")))
        for f in findings if f.get("service", "") not in ("unknown", "")
    }
    for fp in fp_findings:
        service = fp.get("service", "")
        normalized = normalize_service(service)
        base = _base_service(normalized)
        if normalized and normalized != "unknown" and base not in existing_services:
            existing_services.add(base)
            fp["service"] = normalized  # canonicalize before appending
            findings.append(fp)


def _base_service(service: str) -> str:
    """Return the core service name, stripping any trailing version tokens."""
    return re.sub(r"\s+\d[\d.]*$", "", service.strip().lower())


def _invalid_url_result(raw_url: str, warning: str) -> Dict[str, str]:
    return {
        "service": "unknown",
        "version": "",
        "raw": raw_url,
        "source": "url",
        "warning": warning,
    }
