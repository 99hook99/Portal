from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VulnFinding:
    title: str
    severity: str                  # critical, high, medium, low, info
    source: str
    asset_ip: Optional[str] = None
    asset_hostname: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_ids: Optional[str] = None   # comma-separated
    plugin_id: Optional[str] = None
    plugin_name: Optional[str] = None
    plugin_family: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    # Nessus enrichment
    vpr_score: Optional[float] = None
    epss_score: Optional[float] = None
    exploit_available: Optional[bool] = None
    cisa_kev_date: Optional[str] = None
    synopsis: Optional[str] = None
    scan_name: Optional[str] = None
    os: Optional[str] = None
    mac_address: Optional[str] = None
    fqdn: Optional[str] = None
    cloud_resource_id: Optional[str] = None


class BaseIntegration(ABC):
    @abstractmethod
    async def test_connection(self) -> bool: ...

    @abstractmethod
    async def fetch_vulnerabilities(self) -> list[VulnFinding]: ...
