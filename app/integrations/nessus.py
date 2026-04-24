"""
Nessus / Tenable integration – full enterprise collector.

Credentials loaded from NessusConfig DB table (configured via UI)
or fallback to environment variables.
"""
from typing import Optional
import httpx

from app.integrations.base import BaseIntegration, VulnFinding


SEVERITY_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


# ── Field helpers (ported from collector script) ──────────────────────────────

def _safe(d, key, default=""):
    if not isinstance(d, dict):
        return default
    v = d.get(key)
    if v is None or v == "" or v == {}:
        return default
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, (int, float)):
        return str(v)
    return default


def _first(*values):
    for v in values:
        if v and str(v).strip():
            return str(v).strip()
    return ""


def _extract_field(field_name, *containers, default=""):
    for c in containers:
        if not isinstance(c, dict):
            continue
        v = c.get(field_name)
        if v is None or v == "" or v == {}:
            continue
        if isinstance(v, bool):
            return str(v).lower()
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, str):
            return v
    return default


def _extract_refs(attrs):
    raw = attrs.get("ref_information", {})
    if not raw:
        return [], [], [], [], []

    refs = raw.get("ref", [])
    if isinstance(refs, dict):
        refs = [refs]
    if not isinstance(refs, list):
        return [], [], [], [], []

    cve, iava, bid, xref, kev = [], [], [], [], []

    for ref in refs:
        if not isinstance(ref, dict):
            continue
        name = ref.get("name", "").upper().strip()
        values = ref.get("values", {})

        vals = []
        if isinstance(values, dict):
            rv = values.get("value") or values.get("ref_value") or ""
            if isinstance(rv, list):
                vals = [str(x) for x in rv if x]
            elif rv:
                vals = [str(rv)]
        elif isinstance(values, list):
            for item in values:
                if isinstance(item, dict):
                    rv = item.get("value") or item.get("ref_value") or ""
                    if isinstance(rv, list):
                        vals.extend([str(x) for x in rv if x])
                    elif rv:
                        vals.append(str(rv))
                elif item:
                    vals.append(str(item))
        elif isinstance(values, str) and values:
            vals = [values]

        vals = [v.strip() for v in vals if v.strip()]

        if name == "CVE":
            cve.extend(vals)
        elif name == "IAVA":
            iava.extend(vals)
        elif name == "CISA-KNOWN-EXPLOITED":
            kev.extend(vals)
        elif name == "BID":
            bid.extend(vals)
        elif name:
            xref.extend([f"{name}:{v}" for v in vals])

    return cve, iava, bid, xref, kev


def _parse_plugin_detail(data):
    """Parse /scans/{sid}/hosts/{hid}/plugins/{pid} response into (meta, output_records)."""
    pd = data.get("info", {}).get("plugindescription", {})
    attrs = pd.get("pluginattributes", {})

    risk = attrs.get("risk_information", {}) or {}
    pi = attrs.get("plugin_information", {}) or {}
    vi = attrs.get("vuln_information", {}) or {}
    ei = attrs.get("exploit_information", {}) or {}
    ti = attrs.get("threat_intelligence", {}) or {}

    cve_list, iava_list, bid_list, xref_list, kev_dates = _extract_refs(attrs)

    cpe_raw = vi.get("cpe") or attrs.get("cpe") or risk.get("cpe") or ""
    cpe_str = ", ".join(str(c) for c in cpe_raw) if isinstance(cpe_raw, list) else str(cpe_raw).strip()

    vpr_raw = attrs.get("vpr") or {}
    vpr_score = _first(
        _safe(attrs, "vpr_score"),
        _safe(vpr_raw, "score"),
        _safe(risk, "vpr_score"),
    )

    epss_score = _first(
        _safe(attrs, "epss_score"),
        _safe(ti, "epss_score"),
        _safe(risk, "epss_score"),
    )

    exploit_available = _extract_field("exploit_available", ei, attrs, vi)
    exploitability_ease = _extract_field("exploitability_ease", ei, attrs, vi)
    exploit_code_mat = _first(
        _safe(attrs, "exploit_code_maturity"),
        _extract_field("exploit_code_maturity", ei, vi),
    )
    in_the_news = _extract_field("in_the_news", ei, attrs, vi)

    sev_raw = pd.get("severity", {})
    sev_id = int(sev_raw.get("id", 0)) if isinstance(sev_raw, dict) else 0

    meta = {
        "plugin_id": str(pd.get("pluginid", "")),
        "plugin_name": pd.get("pluginname", ""),
        "plugin_family": _safe(pi, "plugin_family"),
        "plugin_type": _safe(pi, "plugin_type"),
        "severity_id": sev_id,
        "severity_label": SEVERITY_MAP.get(sev_id, "info"),
        "risk_factor": _safe(risk, "risk_factor"),
        "cvss3_base_score": _safe(risk, "cvss3_base_score"),
        "cvss3_temporal_score": _safe(risk, "cvss3_temporal_score"),
        "cvss3_vector": _safe(risk, "cvss3_vector"),
        "cvss2_base_score": _safe(risk, "cvss_base_score"),
        "cvss2_vector": _safe(risk, "cvss_vector"),
        "vpr_score": vpr_score,
        "epss_score": epss_score,
        "exploit_available": exploit_available,
        "exploitability_ease": exploitability_ease,
        "exploit_code_maturity": exploit_code_mat,
        "in_the_news": in_the_news,
        "patch_pub_date": _safe(vi, "patch_publication_date"),
        "vuln_pub_date": _safe(vi, "vuln_publication_date"),
        "cpe_plugin": cpe_str,
        "cve": ", ".join(cve_list),
        "iava": ", ".join(iava_list),
        "cisa_kev_date": ", ".join(kev_dates),
        "bid": ", ".join(bid_list),
        "xrefs": ", ".join(xref_list),
        "synopsis": (attrs.get("synopsis") or "").replace("\n", " ")[:500],
        "solution": (attrs.get("solution") or "").replace("\n", " ")[:1000],
        "description": (attrs.get("description") or "").replace("\n", " ")[:2000],
    }

    output_records = []
    for out in data.get("outputs", []):
        raw_text = (out.get("plugin_output") or "").strip()
        ports = out.get("ports") or {}
        if not ports:
            output_records.append({"port": "", "protocol": "", "service": "", "plugin_output": raw_text})
        else:
            for port_str in ports:
                parts = [p.strip() for p in port_str.replace(" ", "").split("/")]
                output_records.append({
                    "port": parts[0] if len(parts) > 0 else "",
                    "protocol": parts[1] if len(parts) > 1 else "",
                    "service": parts[2] if len(parts) > 2 else "",
                    "plugin_output": raw_text,
                })

    if not output_records:
        output_records.append({"port": "", "protocol": "", "service": "", "plugin_output": ""})

    return meta, output_records


def _to_float(val):
    try:
        return float(val) if val else None
    except (ValueError, TypeError):
        return None


def _to_int(val):
    try:
        return int(val) if val else None
    except (ValueError, TypeError):
        return None


# ── Integration class ─────────────────────────────────────────────────────────

class NessusIntegration(BaseIntegration):
    def __init__(
        self,
        url: Optional[str],
        access_key: Optional[str],
        secret_key: Optional[str],
        verify_ssl: bool = False,
        excluded_folders: Optional[str] = None,
    ):
        self.url = (url or "").rstrip("/")
        self.headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Accept": "application/json",
        }
        self.verify_ssl = verify_ssl
        self.excluded_folder_ids: set[int] = set()
        if excluded_folders:
            for tok in excluded_folders.split(","):
                tok = tok.strip()
                if tok.isdigit():
                    self.excluded_folder_ids.add(int(tok))

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers=self.headers, verify=self.verify_ssl, timeout=120.0)

    async def test_connection(self) -> bool:
        try:
            async with self._client() as client:
                r = await client.get(f"{self.url}/server/status")
                return r.status_code == 200
        except Exception:
            return False

    async def _api_get(self, client: httpx.AsyncClient, path: str):
        try:
            r = await client.get(f"{self.url}{path}")
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    async def fetch_vulnerabilities(self) -> list[VulnFinding]:
        findings: list[VulnFinding] = []

        async with self._client() as client:
            folders_data = await self._api_get(client, "/folders")
            folders = (folders_data or {}).get("folders", [])

            for folder in folders:
                folder_id = folder["id"]
                if folder_id in self.excluded_folder_ids:
                    continue

                scans_data = await self._api_get(client, f"/scans?folder_id={folder_id}")
                scans = (scans_data or {}).get("scans") or []

                for scan in scans:
                    status = scan.get("status", "")
                    if status in ("empty", "scheduled", "pending", "running"):
                        continue

                    scan_id = scan["id"]
                    scan_name = scan.get("name", "")

                    detail = await self._api_get(client, f"/scans/{scan_id}")
                    if not detail:
                        continue
                    hosts = detail.get("hosts") or []

                    for host_summary in hosts:
                        host_id = host_summary["host_id"]
                        ip_hint = host_summary.get("hostname", "")

                        host_data = await self._api_get(
                            client, f"/scans/{scan_id}/hosts/{host_id}"
                        )
                        if not host_data:
                            continue

                        info = host_data.get("info", {})
                        ip = info.get("host-ip", ip_hint) or ip_hint
                        hostname = host_summary.get("hostname", "")
                        fqdn = info.get("host-fqdn", "")
                        os_str = info.get("operating-system", "")
                        mac = info.get("mac-address", "")

                        for vuln_entry in host_data.get("vulnerabilities", []):
                            plugin_id = str(vuln_entry["plugin_id"])
                            sev_int = vuln_entry.get("severity", 0)
                            plugin_name_hint = vuln_entry.get("plugin_name", "")

                            plugin_data = await self._api_get(
                                client,
                                f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}",
                            )

                            if not plugin_data:
                                findings.append(VulnFinding(
                                    title=plugin_name_hint or f"Plugin {plugin_id}",
                                    severity=SEVERITY_MAP.get(sev_int, "info"),
                                    source="nessus",
                                    asset_ip=ip,
                                    asset_hostname=hostname or None,
                                    plugin_id=plugin_id,
                                    plugin_name=plugin_name_hint,
                                    scan_name=scan_name,
                                    os=os_str or None,
                                    mac_address=mac or None,
                                    fqdn=fqdn or None,
                                ))
                                continue

                            meta, output_records = _parse_plugin_detail(plugin_data)
                            meta["severity_id"] = sev_int
                            meta["severity_label"] = SEVERITY_MAP.get(sev_int, "info")

                            cvss3 = _to_float(meta.get("cvss3_base_score"))
                            cvss2 = _to_float(meta.get("cvss2_base_score"))
                            cvss = cvss3 or cvss2

                            vpr = _to_float(meta.get("vpr_score"))
                            epss = _to_float(meta.get("epss_score"))

                            ea_raw = meta.get("exploit_available", "")
                            exploit_avail = (ea_raw.lower() == "true") if ea_raw else None

                            for out_rec in output_records:
                                port = _to_int(out_rec.get("port"))
                                protocol = out_rec.get("protocol") or None

                                findings.append(VulnFinding(
                                    title=meta.get("plugin_name") or plugin_name_hint or f"Plugin {plugin_id}",
                                    severity=SEVERITY_MAP.get(sev_int, "info"),
                                    source="nessus",
                                    asset_ip=ip,
                                    asset_hostname=hostname or None,
                                    description=meta.get("description") or None,
                                    solution=meta.get("solution") or None,
                                    cvss_score=cvss,
                                    cvss_vector=meta.get("cvss3_vector") or meta.get("cvss2_vector") or None,
                                    cve_ids=meta.get("cve") or None,
                                    plugin_id=plugin_id,
                                    plugin_name=meta.get("plugin_name") or plugin_name_hint,
                                    plugin_family=meta.get("plugin_family") or None,
                                    port=port,
                                    protocol=protocol,
                                    vpr_score=vpr,
                                    epss_score=epss,
                                    exploit_available=exploit_avail,
                                    cisa_kev_date=meta.get("cisa_kev_date") or None,
                                    synopsis=meta.get("synopsis") or None,
                                    scan_name=scan_name,
                                    os=os_str or None,
                                    mac_address=mac or None,
                                    fqdn=fqdn or None,
                                ))

        return findings
