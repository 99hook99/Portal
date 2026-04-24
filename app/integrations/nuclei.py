import json
import re
from typing import List, Optional
from urllib.parse import urlparse

from app.integrations.base import VulnFinding

SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ip(s: Optional[str]) -> bool:
    return bool(s and _IP_RE.match(s))


def _parse_host(host_str: str, ip_hint: Optional[str] = None):
    """Return (asset_ip, asset_hostname, port) from a nuclei host/matched field."""
    hostname: Optional[str] = None
    port: Optional[int] = None

    if "://" in host_str:
        p = urlparse(host_str)
        hostname = p.hostname
        port = p.port
        if port is None:
            port = 443 if p.scheme == "https" else (80 if p.scheme == "http" else None)
    elif ":" in host_str:
        parts = host_str.rsplit(":", 1)
        hostname = parts[0].lstrip("[").rstrip("]")
        try:
            port = int(parts[1])
        except ValueError:
            hostname = host_str
    else:
        hostname = host_str

    if ip_hint:
        return ip_hint, (hostname if not _is_ip(hostname) else None), port

    if _is_ip(hostname):
        return hostname, None, port
    return None, hostname, port


def parse_nuclei_jsonl(content: str) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info") or {}
        classification = info.get("classification") or {}

        # Severity
        severity = SEV_MAP.get((info.get("severity") or "info").lower(), "info")

        # Title: template name + optional matcher
        name = info.get("name") or item.get("template-id") or item.get("templateID") or "Unknown"
        matcher = item.get("matcher-name") or item.get("matcher_name") or ""
        title = f"{name} [{matcher}]" if matcher else name

        # Plugin ID = template ID
        plugin_id = item.get("template-id") or item.get("templateID") or ""

        # CVEs
        cve_raw = classification.get("cve-id") or []
        if isinstance(cve_raw, str):
            cve_raw = [cve_raw]
        cve_ids = ",".join(cve_raw) if cve_raw else None

        # CVSS
        cvss_score: Optional[float] = None
        raw = classification.get("cvss-score")
        if raw is not None:
            try:
                cvss_score = float(raw)
            except (ValueError, TypeError):
                pass

        # Description – prepend matched-at URL as evidence
        description = info.get("description") or None
        matched_at = item.get("matched-at") or item.get("matched") or ""
        if matched_at:
            description = f"Matched: {matched_at}\n\n{description}" if description else f"Matched: {matched_at}"

        solution = info.get("remediation") or None

        # Tags → plugin_family
        tags = info.get("tags") or []
        if isinstance(tags, list):
            plugin_family = ",".join(tags[:4]) if tags else None
        else:
            plugin_family = str(tags) or None

        # Host / IP / port
        host_str = item.get("host") or item.get("matched-at") or item.get("matched") or ""
        ip_hint = item.get("ip") or None
        asset_ip, asset_hostname, port = _parse_host(host_str, ip_hint)

        if not asset_ip and not asset_hostname:
            continue

        # Protocol
        scan_type = (item.get("type") or "").lower()
        protocol = "udp" if scan_type == "dns" else "tcp"

        findings.append(VulnFinding(
            title=title,
            severity=severity,
            source="nuclei",
            asset_ip=asset_ip,
            asset_hostname=asset_hostname,
            description=description,
            solution=solution,
            cvss_score=cvss_score,
            cve_ids=cve_ids,
            plugin_id=plugin_id,
            plugin_family=plugin_family,
            port=port,
            protocol=protocol,
        ))

    return findings
