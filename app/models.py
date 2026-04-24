from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Text, Boolean, DateTime, ForeignKey
)
from sqlalchemy.orm import relationship
from app.database import Base


class AWSConfig(Base):
    __tablename__ = "aws_config"

    id = Column(Integer, primary_key=True)
    scanner_id = Column(Integer, ForeignKey("scanners.id"), nullable=True, unique=True)
    access_key_id = Column(String)
    secret_access_key = Column(String)
    region = Column(String, default="eu-central-1")
    updated_at = Column(DateTime, default=datetime.utcnow)


class NessusConfig(Base):
    __tablename__ = "nessus_config"

    id = Column(Integer, primary_key=True)
    scanner_id = Column(Integer, ForeignKey("scanners.id"), nullable=True, unique=True)
    url = Column(String)
    access_key = Column(String)
    secret_key = Column(String)
    excluded_folders = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    # ── Identity ──────────────────────────────────────────────
    hostname        = Column(String, nullable=True, index=True)
    ip_address      = Column(String, nullable=True, index=True)
    mac_address     = Column(String, nullable=True)
    fqdn            = Column(String, nullable=True)
    cloud_resource_id = Column(String, nullable=True)   # ARN / Azure ID / GCP resource ID
    identity_type   = Column(String, default="host")    # host / cloud_resource / container / image / app / repo / web

    # ── OS & Software ─────────────────────────────────────────
    os              = Column(String, nullable=True)
    os_version      = Column(String, nullable=True)
    eol_status      = Column(String, nullable=True)     # active / eol / eos / unknown

    # ── Classification ────────────────────────────────────────
    asset_type          = Column(String, default="server")   # kept for legacy/compat
    criticality         = Column(String, default="medium")   # technical: critical/high/medium/low
    business_criticality= Column(String, nullable=True)      # business: critical/high/medium/low
    business_service    = Column(String, nullable=True)      # e.g. "Payment Platform"
    data_classification = Column(String, nullable=True)      # public/internal/confidential/restricted/pii
    asset_labels        = Column(String, nullable=True)      # comma-sep: crown_jewel,regulated,customer_facing,privileged_zone
    environment         = Column(String, nullable=True)      # prod/staging/uat/dev/test

    # ── Ownership ─────────────────────────────────────────────
    owner           = Column(String, nullable=True)
    secondary_owner = Column(String, nullable=True)

    # ── Network & Location ────────────────────────────────────
    internet_exposure = Column(String, nullable=True)  # exposed/partial/internal/unknown
    location_type     = Column(String, nullable=True)  # on-prem/cloud/saas/ot/hybrid

    # ── Cloud-specific ────────────────────────────────────────
    region            = Column(String, nullable=True)   # AWS region / Azure location
    cloud_account_id  = Column(String, nullable=True)   # AWS account ID / Azure subscription
    cloud_account_name= Column(String, nullable=True)   # AWS account alias / Azure sub name
    instance_type     = Column(String, nullable=True)   # t3.medium / db.r5.large / 512MB-10s
    run_state         = Column(String, nullable=True)   # running/stopped/available/active
    public_ips        = Column(String, nullable=True)   # JSON list of public IPs
    private_ips       = Column(String, nullable=True)   # JSON list of private IPs
    aws_image_id      = Column(String, nullable=True)   # AMI ID
    aws_image_name    = Column(String, nullable=True)   # AMI name

    # ── Compensating controls (used in priority scoring) ──────
    compensating_controls = Column(String, nullable=True)  # none/one/two_plus/multilayer

    # ── Lifecycle ─────────────────────────────────────────────
    source      = Column(String, default="manual")
    status      = Column(String, default="active")
    risk_score  = Column(Float, default=0.0)
    tags        = Column(String, nullable=True)   # JSON dict of all resource tags
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)

    # ── New v2 fields ─────────────────────────────────────────
    asset_tier    = Column(String, nullable=True)  # tier0/prod-critical/important/standard/low-value
    reachability  = Column(String, nullable=True)  # internet-facing/partner/vpn/user-reachable/internal/isolated
    business_unit = Column(String, nullable=True)
    owner_team    = Column(String, nullable=True)

    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text, nullable=True)
    solution = Column(Text, nullable=True)
    severity = Column(String, index=True)   # critical, high, medium, low, info
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    cve_ids = Column(String, nullable=True)  # comma-separated CVE IDs
    plugin_id = Column(String, nullable=True)
    plugin_name = Column(String, nullable=True)
    plugin_family = Column(String, nullable=True)
    source = Column(String, default="manual")
    status = Column(String, default="open")  # open, in_progress, accepted, remediated
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    # Nessus / scanner enrichment
    vpr_score       = Column(Float,   nullable=True)
    epss_score      = Column(Float,   nullable=True)
    exploit_available = Column(Boolean, nullable=True)
    cisa_kev_date   = Column(String,  nullable=True)
    synopsis        = Column(String,  nullable=True)
    scan_name       = Column(String,  nullable=True)
    patch_available = Column(Boolean, nullable=True, default=True)

    # Priority scoring (computed)
    priority_score  = Column(Float,   nullable=True)
    priority_class  = Column(String,  nullable=True)   # critical/high/medium/low
    sla_deadline    = Column(DateTime, nullable=True)

    # ── New v2 fields ─────────────────────────────────────────
    decision_bucket   = Column(String, nullable=True)  # P0/P1/P2/P3/P4
    priority_reason   = Column(Text, nullable=True)    # human text
    matched_rule_tags = Column(Text, nullable=True)    # JSON array string
    public_poc        = Column(Boolean, nullable=True)
    exploited_in_org  = Column(Boolean, nullable=True)
    sla_status        = Column(String, nullable=True)  # On Track/At Risk/Breached
    base_source       = Column(String, nullable=True)  # CVSS / VPR / FALLBACK

    asset = relationship("Asset", back_populates="vulnerabilities")


class CVERecord(Base):
    __tablename__ = "cve_records"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    description = Column(Text, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String, nullable=True)
    cvss_v2_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    references = Column(Text, nullable=True)         # newline-separated URLs
    affected_products = Column(Text, nullable=True)  # newline-separated


class NVDEntry(Base):
    __tablename__ = "nvd_entries"

    id               = Column(Integer, primary_key=True, index=True)
    cve_id           = Column(String, unique=True, index=True)
    description      = Column(Text, nullable=True)
    published        = Column(DateTime, nullable=True, index=True)
    last_modified    = Column(DateTime, nullable=True, index=True)
    cvss_v3_score    = Column(Float,  nullable=True)
    cvss_v3_vector   = Column(String, nullable=True)
    cvss_v3_severity = Column(String, nullable=True)
    cvss_v2_score    = Column(Float,  nullable=True)
    cvss_v2_severity = Column(String, nullable=True)
    cwe              = Column(String, nullable=True)
    references       = Column(Text,   nullable=True)   # JSON array of URLs
    affected_products = Column(Text,  nullable=True)   # JSON array of CPE strings
    last_fetched     = Column(DateTime, default=datetime.utcnow)


class KEVEntry(Base):
    __tablename__ = "kev_entries"

    id                 = Column(Integer, primary_key=True, index=True)
    cve_id             = Column(String, unique=True, index=True)
    vendor_project     = Column(String, nullable=True)
    product            = Column(String, nullable=True)
    vulnerability_name = Column(String, nullable=True)
    date_added         = Column(DateTime, nullable=True, index=True)
    short_description  = Column(Text,   nullable=True)
    required_action    = Column(Text,   nullable=True)
    due_date           = Column(DateTime, nullable=True)
    known_ransomware   = Column(String, nullable=True)  # "Known" or "Unknown"
    notes              = Column(Text,   nullable=True)
    last_fetched       = Column(DateTime, default=datetime.utcnow)


class Scanner(Base):
    __tablename__ = "scanners"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    scanner_type = Column(String)   # nessus, mde, openvas, nmap, pac
    enabled = Column(Boolean, default=True)
    status = Column(String, default="idle")  # idle, scanning, error, disabled, unconfigured
    last_sync = Column(DateTime, nullable=True)
    total_findings = Column(Integer, default=0)

    scan_jobs = relationship("ScanJob", back_populates="scanner", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    scanner_id = Column(Integer, ForeignKey("scanners.id"))
    status = Column(String, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    findings_count = Column(Integer, default=0)
    error_message = Column(String, nullable=True)
    log = Column(Text, nullable=True)

    scanner = relationship("Scanner", back_populates="scan_jobs")


class AppSystem(Base):
    __tablename__ = "app_systems"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    asset_links = relationship("AppSystemAsset", back_populates="system", cascade="all, delete-orphan")


class AppSystemAsset(Base):
    __tablename__ = "app_system_assets"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("app_systems.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    environment = Column(String(20), default="prod")  # prod, uat, dev, test

    system = relationship("AppSystem", back_populates="asset_links")
    asset = relationship("Asset")


class ScoringConfig(Base):
    """Singleton (id=1). All scoring weights editable via Settings."""
    __tablename__ = "scoring_config"

    id = Column(Integer, primary_key=True, default=1)

    # ── Intelligence layer ─────────────────────────────────────
    intelligence_cap    = Column(Float, default=2.0)
    epss_multiplier     = Column(Float, default=2.0)
    kev_bonus           = Column(Float, default=1.5)
    kev_floor           = Column(Float, default=7.0)
    exploit_wild_bonus  = Column(Float, default=1.0)
    exploit_poc_bonus   = Column(Float, default=0.5)
    no_patch_bonus      = Column(Float, default=0.3)
    eol_bonus           = Column(Float, default=0.5)

    # ── Environment factors (K) ────────────────────────────────
    env_prod    = Column(Float, default=1.2)
    env_uat     = Column(Float, default=1.0)
    env_dev     = Column(Float, default=0.8)
    env_test    = Column(Float, default=0.6)
    env_unknown = Column(Float, default=1.0)

    # ── Exposure / Accessibility (D) ──────────────────────────
    exp_internet = Column(Float, default=1.5)
    exp_partial  = Column(Float, default=1.2)
    exp_internal = Column(Float, default=1.0)
    exp_local    = Column(Float, default=0.5)
    exp_unknown  = Column(Float, default=1.0)

    # ── Exploitability / Attack vector (E) ────────────────────
    av_network_noauth = Column(Float, default=1.1)
    av_network_auth   = Column(Float, default=1.0)
    av_local          = Column(Float, default=0.9)
    av_physical       = Column(Float, default=0.8)

    # ── Sensitive data (S) ────────────────────────────────────
    data_pii          = Column(Float, default=1.15)
    data_internal     = Column(Float, default=1.05)
    data_public       = Column(Float, default=1.00)
    data_none         = Column(Float, default=0.90)

    # ── Compensating controls (C) ─────────────────────────────
    comp_none       = Column(Float, default=0.00)
    comp_one        = Column(Float, default=0.15)
    comp_two_plus   = Column(Float, default=0.30)
    comp_multilayer = Column(Float, default=0.45)

    # ── SLA thresholds ────────────────────────────────────────
    sla_critical_hours  = Column(Integer, default=24)
    sla_high_days       = Column(Integer, default=7)
    sla_medium_days     = Column(Integer, default=30)
    sla_low_days        = Column(Integer, default=90)

    # ── Score classification thresholds ───────────────────────
    threshold_critical  = Column(Float, default=9.0)
    threshold_high      = Column(Float, default=7.0)
    threshold_medium    = Column(Float, default=4.0)

    # ── Decision Override thresholds ──────────────────────────
    p0_epss_kev_reach_enabled = Column(Boolean, default=True)
    p0_exploited_wild_enabled = Column(Boolean, default=True)
    p1_epss_threshold_prod    = Column(Float, default=0.70)
    p1_epss_threshold_tier0   = Column(Float, default=0.85)
    p1_cvss_poc_threshold     = Column(Float, default=7.0)

    # ── New ENV multipliers ────────────────────────────────────
    env2_prod    = Column(Float, default=1.10)
    env2_uat     = Column(Float, default=1.00)
    env2_dev     = Column(Float, default=0.90)
    env2_test    = Column(Float, default=0.80)
    env2_unknown = Column(Float, default=1.00)

    # ── New REACH multipliers ──────────────────────────────────
    reach_internet  = Column(Float, default=1.30)
    reach_partner   = Column(Float, default=1.15)
    reach_internal  = Column(Float, default=1.00)
    reach_isolated  = Column(Float, default=0.85)
    reach_unknown   = Column(Float, default=1.00)

    # ── CRIT multipliers (asset criticality tier) ──────────────
    crit_tier0     = Column(Float, default=1.20)
    crit_prodc     = Column(Float, default=1.15)
    crit_important = Column(Float, default=1.05)
    crit_standard  = Column(Float, default=1.00)
    crit_low       = Column(Float, default=0.90)
    crit_unknown   = Column(Float, default=1.00)

    # ── CTRL multipliers ──────────────────────────────────────
    ctrl_none           = Column(Float, default=1.00)
    ctrl_one_verified   = Column(Float, default=0.95)
    ctrl_two_verified   = Column(Float, default=0.90)
    ctrl_multilayer     = Column(Float, default=0.80)
    ctrl_unknown        = Column(Float, default=1.00)

    # ── New SLA by decision bucket ─────────────────────────────
    sla_p0_hours  = Column(Integer, default=24)
    sla_p1_hours  = Column(Integer, default=72)
    sla_p2_days   = Column(Integer, default=7)
    sla_p3_days   = Column(Integer, default=30)
    sla_p4_days   = Column(Integer, default=90)

    # ── Score → Decision bucket thresholds ────────────────────
    bucket_p2_min = Column(Float, default=7.0)
    bucket_p3_min = Column(Float, default=4.0)

    # ── Smart Floors & Contextual Bonuses (v3) ─────────────────
    kev_internet_floor     = Column(Float, default=9.5)
    exploit_internet_bonus = Column(Float, default=1.5)
    epss_prod_bonus        = Column(Float, default=1.0)
    epss_prod_threshold    = Column(Float, default=0.70)

    updated_at = Column(DateTime, default=datetime.utcnow)
