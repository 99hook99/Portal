"""
Microsoft Defender for Endpoint integration.

Credentials (from .env):
  MDE_TENANT_ID     – Azure AD tenant ID
  MDE_CLIENT_ID     – App registration client ID
  MDE_CLIENT_SECRET – App registration client secret

Required API permissions on the App Registration:
  Vulnerability.Read.All   (Microsoft Threat and Vulnerability Management)
  Machine.Read.All
"""
from typing import Optional
import httpx

from app.integrations.base import BaseIntegration, VulnFinding

TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
API_BASE  = "https://api.securitycenter.microsoft.com/api"


SEVERITY_MAP = {
    "Critical": "critical",
    "High":     "high",
    "Medium":   "medium",
    "Low":      "low",
    "None":     "info",
}


class MDEIntegration(BaseIntegration):
    def __init__(
        self,
        tenant_id: Optional[str],
        client_id: Optional[str],
        client_secret: Optional[str],
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None

    async def _get_token(self) -> str:
        url = TOKEN_URL.format(tenant_id=self.tenant_id)
        async with httpx.AsyncClient() as client:
            r = await client.post(url, data={
                "grant_type":    "client_credentials",
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
                "scope":         "https://api.securitycenter.microsoft.com/.default",
            })
            r.raise_for_status()
            self._token = r.json()["access_token"]
        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    async def test_connection(self) -> bool:
        try:
            await self._get_token()
            async with httpx.AsyncClient() as client:
                r = await client.get(f"{API_BASE}/vulnerabilities?$top=1", headers=self._headers())
                return r.status_code == 200
        except Exception:
            return False

    async def fetch_vulnerabilities(self) -> list[VulnFinding]:
        await self._get_token()
        findings: list[VulnFinding] = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            # Fetch machine vulnerabilities via the MachineVulnerabilities endpoint
            url = f"{API_BASE}/vulnerabilities/machinesVulnerabilities?$top=1000"
            while url:
                r = await client.get(url, headers=self._headers())
                r.raise_for_status()
                data = r.json()
                for item in data.get("value", []):
                    findings.append(VulnFinding(
                        title=item.get("vulnerabilityId", "Unknown"),
                        severity=SEVERITY_MAP.get(item.get("severity", ""), "info"),
                        source="mde",
                        asset_hostname=item.get("machineName"),
                        cve_ids=item.get("cveId"),
                        cvss_score=item.get("cvssV3"),
                        plugin_id=item.get("vulnerabilityId"),
                        description=item.get("description"),
                    ))
                url = data.get("@odata.nextLink")

        return findings
