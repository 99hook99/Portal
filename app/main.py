from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from sqlalchemy import text

from app.database import engine, SessionLocal
from app.models import Base
from app.config import settings
from app.routers import dashboard, vulnerabilities, assets, cve, scanners, app_systems, scoring


def _run_migrations():
    """Add new columns to existing tables without breaking old data."""
    vuln_cols = [
        ("vpr_score", "FLOAT"),
        ("epss_score", "FLOAT"),
        ("exploit_available", "BOOLEAN"),
        ("cisa_kev_date", "VARCHAR"),
        ("synopsis", "VARCHAR"),
        ("scan_name", "VARCHAR"),
        ("plugin_family", "VARCHAR"),
    ]
    asset_cols = [
        ("fqdn",                "VARCHAR"),
        ("cloud_resource_id",   "VARCHAR"),
        ("identity_type",       "VARCHAR DEFAULT 'host'"),
        ("eol_status",          "VARCHAR"),
        ("business_criticality","VARCHAR"),
        ("business_service",    "VARCHAR"),
        ("data_classification", "VARCHAR"),
        ("asset_labels",        "VARCHAR"),
        ("environment",         "VARCHAR"),
        ("owner",               "VARCHAR"),
        ("secondary_owner",     "VARCHAR"),
        ("internet_exposure",    "VARCHAR DEFAULT 'unknown'"),
        ("location_type",        "VARCHAR"),
        ("compensating_controls","VARCHAR"),
    ]
    with engine.connect() as conn:
        vuln_existing = {row[1] for row in conn.execute(text("PRAGMA table_info(vulnerabilities)"))}
        for col, typ in vuln_cols:
            if col not in vuln_existing:
                conn.execute(text(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {typ}"))

        asset_existing = {row[1] for row in conn.execute(text("PRAGMA table_info(assets)"))}
        for col, typ in asset_cols:
            if col not in asset_existing:
                conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col} {typ}"))

        vuln_new_cols = [
            ("patch_available",    "BOOLEAN DEFAULT 1"),
            ("priority_score",     "FLOAT"),
            ("priority_class",     "VARCHAR"),
            ("sla_deadline",       "DATETIME"),
            ("decision_bucket",    "VARCHAR"),
            ("priority_reason",    "TEXT"),
            ("matched_rule_tags",  "TEXT"),
            ("public_poc",         "BOOLEAN"),
            ("exploited_in_org",   "BOOLEAN"),
            ("sla_status",         "VARCHAR"),
            ("base_source",        "VARCHAR"),
        ]
        vuln_existing2 = {row[1] for row in conn.execute(text("PRAGMA table_info(vulnerabilities)"))}
        for col, typ in vuln_new_cols:
            if col not in vuln_existing2:
                conn.execute(text(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {typ}"))

        asset_new_cols = [
            ("asset_tier",    "VARCHAR"),
            ("reachability",  "VARCHAR"),
            ("business_unit", "VARCHAR"),
            ("owner_team",    "VARCHAR"),
        ]
        asset_existing2 = {row[1] for row in conn.execute(text("PRAGMA table_info(assets)"))}
        for col, typ in asset_new_cols:
            if col not in asset_existing2:
                conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col} {typ}"))

        # ScoringConfig new columns
        scoring_new_cols = [
            ("p0_epss_kev_reach_enabled", "BOOLEAN DEFAULT 1"),
            ("p0_exploited_wild_enabled", "BOOLEAN DEFAULT 1"),
            ("p1_epss_threshold_prod",    "FLOAT DEFAULT 0.70"),
            ("p1_epss_threshold_tier0",   "FLOAT DEFAULT 0.85"),
            ("p1_cvss_poc_threshold",     "FLOAT DEFAULT 7.0"),
            ("env2_prod",                 "FLOAT DEFAULT 1.10"),
            ("env2_uat",                  "FLOAT DEFAULT 1.00"),
            ("env2_dev",                  "FLOAT DEFAULT 0.90"),
            ("env2_test",                 "FLOAT DEFAULT 0.80"),
            ("env2_unknown",              "FLOAT DEFAULT 1.00"),
            ("reach_internet",            "FLOAT DEFAULT 1.30"),
            ("reach_partner",             "FLOAT DEFAULT 1.15"),
            ("reach_internal",            "FLOAT DEFAULT 1.00"),
            ("reach_isolated",            "FLOAT DEFAULT 0.85"),
            ("reach_unknown",             "FLOAT DEFAULT 1.00"),
            ("crit_tier0",                "FLOAT DEFAULT 1.20"),
            ("crit_prodc",                "FLOAT DEFAULT 1.15"),
            ("crit_important",            "FLOAT DEFAULT 1.05"),
            ("crit_standard",             "FLOAT DEFAULT 1.00"),
            ("crit_low",                  "FLOAT DEFAULT 0.90"),
            ("crit_unknown",              "FLOAT DEFAULT 1.00"),
            ("ctrl_none",                 "FLOAT DEFAULT 1.00"),
            ("ctrl_one_verified",         "FLOAT DEFAULT 0.95"),
            ("ctrl_two_verified",         "FLOAT DEFAULT 0.90"),
            ("ctrl_multilayer",           "FLOAT DEFAULT 0.80"),
            ("ctrl_unknown",              "FLOAT DEFAULT 1.00"),
            ("sla_p0_hours",              "INTEGER DEFAULT 24"),
            ("sla_p1_hours",              "INTEGER DEFAULT 72"),
            ("sla_p2_days",               "INTEGER DEFAULT 7"),
            ("sla_p3_days",               "INTEGER DEFAULT 30"),
            ("sla_p4_days",               "INTEGER DEFAULT 90"),
            ("bucket_p2_min",             "FLOAT DEFAULT 7.0"),
            ("bucket_p3_min",             "FLOAT DEFAULT 4.0"),
            ("kev_internet_floor",         "FLOAT DEFAULT 9.5"),
            ("exploit_internet_bonus",     "FLOAT DEFAULT 1.5"),
            ("epss_prod_bonus",            "FLOAT DEFAULT 1.0"),
            ("epss_prod_threshold",        "FLOAT DEFAULT 0.70"),
        ]
        scoring_existing = {row[1] for row in conn.execute(text("PRAGMA table_info(scoring_config)"))}
        for col, typ in scoring_new_cols:
            if col not in scoring_existing:
                conn.execute(text(f"ALTER TABLE scoring_config ADD COLUMN {col} {typ}"))

        # aws_config table (new or migrate)
        existing_tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        if "aws_config" not in existing_tables:
            conn.execute(text(
                "CREATE TABLE aws_config (id INTEGER PRIMARY KEY, scanner_id INTEGER UNIQUE, "
                "access_key_id VARCHAR, secret_access_key VARCHAR, "
                "region VARCHAR DEFAULT 'eu-central-1', updated_at DATETIME)"
            ))
        else:
            aws_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(aws_config)"))}
            if "scanner_id" not in aws_cols:
                conn.execute(text("ALTER TABLE aws_config ADD COLUMN scanner_id INTEGER"))

        # nessus_config: add scanner_id if missing
        if "nessus_config" in existing_tables:
            nc_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(nessus_config)"))}
            if "scanner_id" not in nc_cols:
                conn.execute(text("ALTER TABLE nessus_config ADD COLUMN scanner_id INTEGER"))

        conn.commit()
    _backfill_identity_type()


def _backfill_identity_type():
    """Set identity_type on existing assets that have none."""
    from app.models import Asset
    db = SessionLocal()
    try:
        rows = db.query(Asset).filter(
            (Asset.identity_type == None) | (Asset.identity_type == "host")
        ).all()
        for a in rows:
            a.identity_type = _detect_identity_type(
                a.source or "", a.os or "", a.asset_type or "", a.tags or "",
                hostname=a.hostname or "", fqdn=a.fqdn or ""
            )
        db.commit()
    finally:
        db.close()


def _detect_identity_type(source: str, os: str, asset_type: str, tags: str,
                          hostname: str = "", fqdn: str = "") -> str:
    from app.utils import detect_identity_type
    return detect_identity_type(source, os, asset_type, tags, hostname=hostname, fqdn=fqdn)


def _backfill_scanner_configs():
    """Link existing singleton configs to their scanner rows if not yet linked."""
    from app.models import Scanner, NessusConfig, AWSConfig
    db = SessionLocal()
    try:
        for stype, Model in [("nessus", NessusConfig), ("aws", AWSConfig)]:
            cfg = db.query(Model).filter(Model.scanner_id == None).first()
            if cfg:
                scanner = db.query(Scanner).filter(Scanner.scanner_type == stype).first()
                if scanner:
                    cfg.scanner_id = scanner.id
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def _ensure_scanners():
    """Add any missing scanner rows (for existing DBs that predate new integrations)."""
    from app.models import Scanner
    REQUIRED = [
        ("Nuclei (ProjectDiscovery)", "nuclei"),
        ("AWS Security (Inspector + Config + SecHub)", "aws"),
    ]
    db = SessionLocal()
    try:
        for name, stype in REQUIRED:
            if not db.query(Scanner).filter(Scanner.scanner_type == stype).first():
                db.add(Scanner(name=name, scanner_type=stype, enabled=True, status="unconfigured", total_findings=0))
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _run_migrations()
    _ensure_scanners()
    _backfill_scanner_configs()
    if settings.SEED_DEMO_DATA:
        from app.seed import seed
        db = SessionLocal()
        try:
            seed(db)
        finally:
            db.close()
    # Ensure ScoringConfig singleton + initial recalc
    from app.routers.scoring import _get_or_create_config, recalculate_all
    db = SessionLocal()
    try:
        _get_or_create_config(db)
        recalculate_all(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(dashboard.router,       prefix="/api/dashboard",       tags=["dashboard"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities",  tags=["vulnerabilities"])
app.include_router(assets.router,          prefix="/api/assets",           tags=["assets"])
app.include_router(cve.router,             prefix="/api/cve",              tags=["cve"])
app.include_router(scanners.router,        prefix="/api/scanners",         tags=["scanners"])
app.include_router(app_systems.router,     prefix="/api/app-systems",      tags=["app-systems"])
app.include_router(scoring.router,         prefix="/api/scoring",          tags=["scoring"])

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    return FileResponse("static/index.html")
