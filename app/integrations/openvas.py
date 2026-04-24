"""
OpenVAS / Greenbone Vulnerability Manager integration.

Credentials (from .env):
  OPENVAS_HOST      – GVM host
  OPENVAS_PORT      – default 9390
  OPENVAS_USERNAME
  OPENVAS_PASSWORD

Uses the GMP (Greenbone Management Protocol) XML API.
Install python-gvm for production use: pip install python-gvm
"""
from typing import Optional
from app.integrations.base import BaseIntegration, VulnFinding

SEVERITY_MAP = {
    (9.0, 10.0): "critical",
    (7.0, 8.9):  "high",
    (4.0, 6.9):  "medium",
    (0.1, 3.9):  "low",
    (0.0, 0.0):  "info",
}


def _map_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


class OpenVASIntegration(BaseIntegration):
    def __init__(
        self,
        host: Optional[str],
        port: int = 9390,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    async def test_connection(self) -> bool:
        try:
            from gvm.connections import TLSConnection
            from gvm.protocols.gmp import Gmp
            conn = TLSConnection(hostname=self.host, port=self.port)
            with Gmp(connection=conn) as gmp:
                gmp.authenticate(self.username, self.password)
            return True
        except Exception:
            return False

    async def fetch_vulnerabilities(self) -> list[VulnFinding]:
        """
        Fetch results from all completed OpenVAS tasks.
        Requires: pip install python-gvm
        """
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp
        import xml.etree.ElementTree as ET

        findings: list[VulnFinding] = []

        conn = TLSConnection(hostname=self.host, port=self.port)
        with Gmp(connection=conn) as gmp:
            gmp.authenticate(self.username, self.password)
            results_xml = gmp.get_results(filter_string="rows=-1 apply_overrides=1 levels=hmlg")
            root = ET.fromstring(results_xml)

            for result in root.findall(".//result"):
                name = result.findtext("name") or "Unknown"
                host_el = result.find("host")
                host_ip = host_el.text if host_el is not None else None
                hostname = result.findtext("host/hostname") or None
                port_str = result.findtext("port") or ""
                port = None
                if "/" in port_str:
                    try:
                        port = int(port_str.split("/")[0])
                    except ValueError:
                        pass

                cvss_raw = result.findtext("severity") or "0"
                try:
                    cvss = float(cvss_raw)
                except ValueError:
                    cvss = 0.0

                nvt = result.find("nvt")
                cve_ids = None
                description = result.findtext("description")
                solution = None
                if nvt is not None:
                    refs = [ref.get("id", "") for ref in nvt.findall("refs/ref[@type='cve']")]
                    cve_ids = ",".join(refs) if refs else None
                    solution = nvt.findtext("solution")

                findings.append(VulnFinding(
                    title=name,
                    severity=_map_severity(cvss),
                    source="openvas",
                    asset_ip=host_ip,
                    asset_hostname=hostname,
                    description=description,
                    solution=solution,
                    cvss_score=cvss if cvss > 0 else None,
                    cve_ids=cve_ids,
                    port=port,
                ))

        return findings
