from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


# ── Asset ─────────────────────────────────────────────────────────────────────

class AssetBase(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    fqdn: Optional[str] = None
    cloud_resource_id: Optional[str] = None
    identity_type: str = "host"
    os: Optional[str] = None
    os_version: Optional[str] = None
    eol_status: Optional[str] = None
    asset_type: str = "server"
    criticality: str = "medium"
    business_criticality: Optional[str] = None
    business_service: Optional[str] = None
    data_classification: Optional[str] = None
    asset_labels: Optional[str] = None
    environment: Optional[str] = None
    owner: Optional[str] = None
    secondary_owner: Optional[str] = None
    internet_exposure: Optional[str] = "unknown"
    location_type: Optional[str] = None
    compensating_controls: Optional[str] = None
    reachability: Optional[str] = None      # Primary REACH field: internet-facing/partner/internal/isolated
    asset_tier: Optional[str] = None        # Primary CRIT field: tier0/prod-critical/important/standard/low-value
    business_unit: Optional[str] = None
    owner_team: Optional[str] = None
    source: str = "manual"
    tags: Optional[str] = None
    status: str = "active"
    risk_score: float = 0.0


class AssetCreate(AssetBase):
    pass


class AssetMetaUpdate(BaseModel):
    """Partial update for enrichment fields — all optional."""
    owner: Optional[str] = None
    secondary_owner: Optional[str] = None
    business_service: Optional[str] = None
    business_criticality: Optional[str] = None
    criticality: Optional[str] = None
    data_classification: Optional[str] = None
    asset_labels: Optional[str] = None
    environment: Optional[str] = None
    internet_exposure: Optional[str] = None
    location_type: Optional[str] = None
    compensating_controls: Optional[str] = None
    eol_status: Optional[str] = None
    reachability: Optional[str] = None
    asset_tier: Optional[str] = None
    identity_type: Optional[str] = None
    fqdn: Optional[str] = None
    cloud_resource_id: Optional[str] = None
    tags: Optional[str] = None
    status: Optional[str] = None


class AssetOut(AssetBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    vuln_count: Optional[int] = 0
    critical_count: Optional[int] = 0
    # Cloud-specific fields
    region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    cloud_account_name: Optional[str] = None
    instance_type: Optional[str] = None
    run_state: Optional[str] = None
    public_ips: Optional[str] = None    # JSON list
    private_ips: Optional[str] = None   # JSON list
    aws_image_id: Optional[str] = None
    aws_image_name: Optional[str] = None

    class Config:
        from_attributes = True


# ── Vulnerability ──────────────────────────────────────────────────────────────

class VulnBase(BaseModel):
    title: str
    description: Optional[str] = None
    solution: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_ids: Optional[str] = None
    plugin_id: Optional[str] = None
    plugin_name: Optional[str] = None
    source: str = "manual"
    status: str = "open"
    asset_id: Optional[int] = None
    port: Optional[int] = None
    protocol: Optional[str] = None


class VulnCreate(VulnBase):
    pass


class VulnOut(VulnBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    asset_hostname: Optional[str] = None
    asset_ip: Optional[str] = None
    # Nessus enrichment
    vpr_score: Optional[float] = None
    epss_score: Optional[float] = None
    exploit_available: Optional[bool] = None
    cisa_kev_date: Optional[str] = None
    synopsis: Optional[str] = None
    scan_name: Optional[str] = None
    plugin_family: Optional[str] = None
    patch_available: Optional[bool] = None
    # v2 scoring fields
    public_poc: Optional[bool] = None
    exploited_in_org: Optional[bool] = None
    priority_score: Optional[float] = None
    priority_class: Optional[str] = None
    sla_deadline: Optional[datetime] = None
    decision_bucket: Optional[str] = None
    priority_reason: Optional[str] = None
    matched_rule_tags: Optional[str] = None
    sla_status: Optional[str] = None

    class Config:
        from_attributes = True


class VulnStatusUpdate(BaseModel):
    status: str


# ── CVE ───────────────────────────────────────────────────────────────────────

class CVEOut(BaseModel):
    id: int
    cve_id: str
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    severity: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    references: Optional[str] = None
    affected_products: Optional[str] = None

    class Config:
        from_attributes = True


# ── Scanner ───────────────────────────────────────────────────────────────────

class AWSConfigIn(BaseModel):
    access_key_id: str
    secret_access_key: str
    region: str = "eu-central-1"


class AWSConfigOut(BaseModel):
    configured: bool
    access_key_hint: Optional[str] = None
    region: Optional[str] = None
    updated_at: Optional[datetime] = None


class NessusConfigIn(BaseModel):
    url: str
    access_key: str
    secret_key: str
    excluded_folders: Optional[str] = None


class NessusConfigOut(BaseModel):
    configured: bool
    url: Optional[str] = None
    access_key_hint: Optional[str] = None
    excluded_folders: Optional[str] = None
    updated_at: Optional[datetime] = None


class ScannerCreateIn(BaseModel):
    name: str
    scanner_type: str


class ScannerOut(BaseModel):
    id: int
    name: str
    scanner_type: str
    enabled: bool
    status: str
    last_sync: Optional[datetime] = None
    total_findings: int
    configured: bool = False

    class Config:
        from_attributes = True


class ScanJobOut(BaseModel):
    id: int
    scanner_id: int
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_vulnerabilities: int
    open_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    total_assets: int
    assets_at_risk: int
    remediated_30d: int
    new_30d: int


class SeverityDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class TrendPoint(BaseModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int


class TopAsset(BaseModel):
    id: int
    hostname: Optional[str]
    ip_address: Optional[str]
    criticality: str
    vuln_count: int
    risk_score: float
