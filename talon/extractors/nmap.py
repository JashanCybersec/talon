import re
import xml.etree.ElementTree as ET
from typing import Dict, List
from xml.etree.ElementTree import XMLParser

from .normalize import normalize_service

# Nmap sometimes puts OS/distro info into the version field, e.g.:
#   version="6.6.1p1 Ubuntu 2ubuntu2.13"
#   version="2.4.7 (Ubuntu)"
# Strip everything from the first whitespace or parenthesis that follows
# an initial version token so only the real version number remains.
_VERSION_NOISE_RE = re.compile(r"^(v?\d[A-Za-z0-9._+-]*)[\s(].*$")


def extract_from_nmap(xml_path: str) -> List[Dict[str, str]]:
    from pathlib import Path
    if not Path(xml_path).is_file():
        return [{
            "service": "unknown", "version": "", "raw": xml_path,
            "source": "nmap", "warning": f"Nmap XML file not found: {xml_path}",
        }]
    try:
        parser = ET.XMLParser()
        tree = ET.parse(xml_path, parser=parser)
    except ET.ParseError as exc:
        return [{
            "service": "unknown", "version": "", "raw": xml_path,
            "source": "nmap", "warning": f"Invalid Nmap XML: {exc}",
        }]
    except OSError as exc:
        return [{
            "service": "unknown", "version": "", "raw": xml_path,
            "source": "nmap", "warning": f"Unable to read Nmap XML: {exc}",
        }]
    return _extract_findings(tree.getroot())


def extract_from_nmap_xml(xml_blob: str, source_label: str = "stdin:nmap") -> List[Dict[str, str]]:
    try:
        parser = ET.XMLParser()
        root = ET.fromstring(xml_blob, parser=parser)
    except ET.ParseError as exc:
        return [{
            "service": "unknown",
            "version": "",
            "raw": source_label,
            "source": "nmap",
            "warning": f"Invalid Nmap XML: {exc}",
        }]
    return _extract_findings(root)


def looks_like_nmap_xml(xml_blob: str) -> bool:
    stripped = xml_blob.lstrip()
    return stripped.startswith("<?xml") or stripped.startswith("<nmaprun")


# Generic protocol-only names that carry no product info and should be skipped
# when no real product name is available (e.g. a closed port's service name).
_PROTOCOL_ONLY_NAMES = {
    "http", "https", "ssh", "ftp", "smtp", "imap", "pop3", "telnet",
    "ssl", "tls", "tcpwrapped", "unknown",
}


def _extract_findings(root: ET.Element) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    for port in root.findall(".//port"):
        # Only process open ports
        state_el = port.find("state")
        if state_el is not None and state_el.attrib.get("state") != "open":
            continue

        service = port.find("service")
        if service is None:
            continue

        product = (service.attrib.get("product") or "").strip()
        name = (service.attrib.get("name") or "").strip()
        version = (service.attrib.get("version") or "").strip()
        extrainfo = (service.attrib.get("extrainfo") or "").strip()

        # Use product name when available; fall back to protocol name only if
        # it carries meaningful identity (i.e. not a bare protocol keyword).
        if product:
            service_name = product
        elif name and name.lower() not in _PROTOCOL_ONLY_NAMES:
            service_name = name
        else:
            # No useful product name — skip this port
            continue

        # Strip OS/distro noise that Nmap includes in the version field
        # (e.g. "6.6.1p1 Ubuntu 2ubuntu2.13" → "6.6.1p1").
        clean_version = version
        if version:
            m = _VERSION_NOISE_RE.match(version)
            if m:
                clean_version = m.group(1)

        # Build raw display string using the clean version to avoid noise like
        # "6.6.1p1 Ubuntu 2ubuntu2.13" — keep extrainfo only if not redundant.
        raw_parts = [service_name]
        if clean_version:
            raw_parts.append(clean_version)
        if extrainfo and extrainfo not in version and extrainfo not in clean_version:
            raw_parts.append(extrainfo)
        raw = " ".join(raw_parts).strip()

        finding = {
            "service": normalize_service(service_name),
            "version": clean_version,
            "raw": raw or service_name,
            "source": "nmap",
        }
        if not version:
            finding["warning"] = "Nmap service version missing; continuing with service name only."
        findings.append(finding)

    return findings
