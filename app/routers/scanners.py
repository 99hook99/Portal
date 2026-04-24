from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scanner, ScanJob
from app.schemas import ScannerOut, ScanJobOut, NessusConfigIn, NessusConfigOut, AWSConfigIn, AWSConfigOut, ScannerCreateIn
from app.config import settings

router = APIRouter()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _merge_source(existing: str | None, new_source: str) -> str:
    parts = {s.strip() for s in (existing or "").split(",") if s.strip()}
    parts.add(new_source.strip())
    return ",".join(sorted(parts))


def _is_configured(stype: str, db=None, scanner_id: int = None) -> bool:
    if stype == "nessus":
        if db:
            try:
                from app.models import NessusConfig
                q = db.query(NessusConfig)
                if scanner_id:
                    cfg = q.filter(NessusConfig.scanner_id == scanner_id).first()
                else:
                    cfg = q.first()
                if cfg and cfg.url and cfg.access_key:
                    return True
            except Exception:
                pass
        return bool(settings.NESSUS_URL and settings.NESSUS_ACCESS_KEY)
    if stype == "mde":
        return bool(settings.MDE_TENANT_ID and settings.MDE_CLIENT_ID)
    if stype == "openvas":
        return bool(settings.OPENVAS_HOST and settings.OPENVAS_USERNAME)
    if stype == "nmap":
        return bool(settings.NMAP_TARGETS)
    if stype == "pac":
        return bool(settings.PAC_URL and settings.PAC_API_KEY)
    if stype == "nuclei":
        return True
    if stype == "aws":
        if db:
            try:
                from app.models import AWSConfig
                q = db.query(AWSConfig)
                if scanner_id:
                    cfg = q.filter(AWSConfig.scanner_id == scanner_id).first()
                else:
                    cfg = q.first()
                if cfg and cfg.access_key_id and cfg.secret_access_key:
                    return True
            except Exception:
                pass
        return bool(settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY)
    return False


def _persist_findings(db, findings, source: str):
    from app.models import Asset, Vulnerability
    from sqlalchemy import case, func

    now = datetime.utcnow()

    # ── Phase 1: resolve / create assets ─────────────────────────────────────
    asset_cache: dict = {}

    for f in findings:
        cloud_rid = getattr(f, "cloud_resource_id", None)
        ip = f.asset_ip or ""
        if not cloud_rid and not ip:
            continue

        cache_key = cloud_rid or ip
        if cache_key in asset_cache:
            continue

        asset = None
        if cloud_rid:
            asset = db.query(Asset).filter(Asset.cloud_resource_id == cloud_rid).first()
        if not asset and ip:
            asset = db.query(Asset).filter(Asset.ip_address == ip).first()

        if asset:
            asset.last_seen = now
            asset.source = _merge_source(asset.source, source)
            if f.asset_hostname:
                asset.hostname = f.asset_hostname
            if ip and not asset.ip_address:
                asset.ip_address = ip
            if cloud_rid and not asset.cloud_resource_id:
                asset.cloud_resource_id = cloud_rid
            if getattr(f, "os", None):
                asset.os = f.os
            if getattr(f, "mac_address", None):
                asset.mac_address = f.mac_address
        else:
            asset = Asset(
                ip_address=ip or None,
                hostname=f.asset_hostname,
                cloud_resource_id=cloud_rid,
                identity_type="cloud_resource" if cloud_rid else "host",
                location_type="cloud" if cloud_rid else None,
                os=getattr(f, "os", None),
                mac_address=getattr(f, "mac_address", None),
                source=source,
                first_seen=now,
                last_seen=now,
            )
            db.add(asset)
            db.flush()

        asset_cache[cache_key] = asset

    # ── Phase 2: bulk load existing vulnerabilities (1 query instead of N) ───
    asset_ids = [a.id for a in asset_cache.values()]
    existing_vulns: dict[tuple, Vulnerability] = {}
    if asset_ids:
        for v in db.query(Vulnerability).filter(Vulnerability.asset_id.in_(asset_ids)).all():
            existing_vulns[(v.asset_id, v.plugin_id or "", v.port, v.protocol)] = v

    # ── Phase 3: upsert vulnerabilities using in-memory dict lookup ───────────
    seen_vuln_keys: set = set()

    for f in findings:
        cloud_rid = getattr(f, "cloud_resource_id", None)
        ip = f.asset_ip or ""
        if not cloud_rid and not ip:
            continue

        asset = asset_cache.get(cloud_rid or ip)
        if not asset:
            continue

        plugin_id = f.plugin_id or ""
        vuln_key = (asset.id, plugin_id, f.port, f.protocol)

        if vuln_key in existing_vulns:
            vuln = existing_vulns[vuln_key]
            vuln.last_seen = now
            vuln.severity = f.severity
            if f.cvss_score is not None:
                vuln.cvss_score = f.cvss_score
            if f.cvss_vector:
                vuln.cvss_vector = f.cvss_vector
            if f.cve_ids:
                vuln.cve_ids = f.cve_ids
            if f.description:
                vuln.description = f.description
            if f.solution:
                vuln.solution = f.solution
        else:
            vuln = Vulnerability(
                title=f.title,
                description=f.description,
                solution=f.solution,
                severity=f.severity,
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                cve_ids=f.cve_ids,
                plugin_id=plugin_id,
                plugin_name=f.plugin_name,
                source=source,
                status="open",
                asset_id=asset.id,
                port=f.port,
                protocol=f.protocol,
                first_seen=now,
                last_seen=now,
            )
            db.add(vuln)
            existing_vulns[vuln_key] = vuln  # prevent duplicate inserts in same sync

        vuln.vpr_score = getattr(f, "vpr_score", None)
        vuln.epss_score = getattr(f, "epss_score", None)
        vuln.exploit_available = getattr(f, "exploit_available", None)
        vuln.cisa_kev_date = getattr(f, "cisa_kev_date", None)
        vuln.synopsis = getattr(f, "synopsis", None)
        vuln.scan_name = getattr(f, "scan_name", None)
        vuln.plugin_family = getattr(f, "plugin_family", None)

        seen_vuln_keys.add(vuln_key)

    db.commit()

    # ── Phase 4: auto-resolve stale vulns ─────────────────────────────────────
    scanned_asset_ids = {a.id for a in asset_cache.values()}
    if scanned_asset_ids:
        stale = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id.in_(scanned_asset_ids),
                Vulnerability.source == source,
                Vulnerability.status.in_(["open", "in_progress"]),
                Vulnerability.last_seen < now,
            )
            .all()
        )
        for v in stale:
            key = (v.asset_id, v.plugin_id or "", v.port, v.protocol)
            if key not in seen_vuln_keys:
                v.status = "remediated"
                v.last_seen = now
        if stale:
            db.commit()

    # ── Phase 5: risk scores via single SQL aggregation (1 query, not N) ─────
    if asset_ids:
        score_rows = (
            db.query(
                Vulnerability.asset_id,
                func.sum(
                    case(
                        (Vulnerability.severity == "critical", 10),
                        (Vulnerability.severity == "high", 7),
                        (Vulnerability.severity == "medium", 4),
                        (Vulnerability.severity == "low", 1),
                        else_=0,
                    )
                ).label("score"),
            )
            .filter(
                Vulnerability.asset_id.in_(asset_ids),
                Vulnerability.status == "open",
            )
            .group_by(Vulnerability.asset_id)
            .all()
        )
        score_map = {row.asset_id: min(100.0, float(row.score or 0)) for row in score_rows}
        for asset in asset_cache.values():
            asset.risk_score = score_map.get(asset.id, 0.0)
        db.commit()


# ── Nessus configure endpoints ─────────────────────────────────────────────────

@router.get("/nessus/configure", response_model=NessusConfigOut)
def get_nessus_config(db: Session = Depends(get_db)):
    from app.models import NessusConfig
    cfg = db.query(NessusConfig).first()
    if not cfg:
        return NessusConfigOut(configured=False)
    hint = (cfg.access_key[:6] + "***") if cfg.access_key else ""
    return NessusConfigOut(
        configured=True,
        url=cfg.url,
        access_key_hint=hint,
        excluded_folders=cfg.excluded_folders or "",
        updated_at=cfg.updated_at,
    )


@router.post("/nessus/configure")
def save_nessus_config(cfg_in: NessusConfigIn, db: Session = Depends(get_db)):
    from app.models import NessusConfig
    cfg = db.query(NessusConfig).first()
    if cfg:
        cfg.url = cfg_in.url
        if cfg_in.access_key:
            cfg.access_key = cfg_in.access_key
        if cfg_in.secret_key:
            cfg.secret_key = cfg_in.secret_key
        cfg.excluded_folders = cfg_in.excluded_folders
        cfg.updated_at = datetime.utcnow()
    else:
        cfg = NessusConfig(
            url=cfg_in.url,
            access_key=cfg_in.access_key,
            secret_key=cfg_in.secret_key,
            excluded_folders=cfg_in.excluded_folders,
            updated_at=datetime.utcnow(),
        )
        db.add(cfg)
    db.commit()

    nessus_scanner = db.query(Scanner).filter(Scanner.scanner_type == "nessus").first()
    if nessus_scanner and nessus_scanner.status == "unconfigured":
        nessus_scanner.status = "idle"
        db.commit()

    return {"status": "ok", "message": "Nessus configured successfully"}


@router.post("/nessus/test")
async def test_nessus_connection(cfg_in: NessusConfigIn):
    from app.integrations.nessus import NessusIntegration
    integration = NessusIntegration(
        url=cfg_in.url,
        access_key=cfg_in.access_key,
        secret_key=cfg_in.secret_key,
        verify_ssl=False,
        excluded_folders=cfg_in.excluded_folders,
    )
    ok = await integration.test_connection()
    return {"success": ok, "message": "Connection successful" if ok else "Connection failed – check URL and API keys"}


# ── AWS configure / test / sync ───────────────────────────────────────────────

@router.get("/aws/configure", response_model=AWSConfigOut)
def get_aws_config(db: Session = Depends(get_db)):
    from app.models import AWSConfig
    cfg = db.query(AWSConfig).first()
    if not cfg:
        return AWSConfigOut(configured=False)
    hint = (cfg.access_key_id[:4] + "***") if cfg.access_key_id else ""
    return AWSConfigOut(
        configured=True,
        access_key_hint=hint,
        region=cfg.region,
        updated_at=cfg.updated_at,
    )


@router.post("/aws/configure")
def save_aws_config(cfg_in: AWSConfigIn, db: Session = Depends(get_db)):
    from app.models import AWSConfig
    cfg = db.query(AWSConfig).first()
    if cfg:
        cfg.access_key_id = cfg_in.access_key_id
        cfg.secret_access_key = cfg_in.secret_access_key
        cfg.region = cfg_in.region
        cfg.updated_at = datetime.utcnow()
    else:
        cfg = AWSConfig(
            access_key_id=cfg_in.access_key_id,
            secret_access_key=cfg_in.secret_access_key,
            region=cfg_in.region,
            updated_at=datetime.utcnow(),
        )
        db.add(cfg)
    db.commit()

    aws_scanner = db.query(Scanner).filter(Scanner.scanner_type == "aws").first()
    if aws_scanner and aws_scanner.status == "unconfigured":
        aws_scanner.status = "idle"
        db.commit()

    return {"status": "ok", "message": "AWS configured successfully"}


@router.post("/aws/test")
async def test_aws_connection(cfg_in: AWSConfigIn):
    from app.integrations.aws import AWSIntegration
    integration = AWSIntegration(
        access_key_id=cfg_in.access_key_id,
        secret_access_key=cfg_in.secret_access_key,
        region=cfg_in.region,
    )
    ok = await integration.test_connection()
    return {"success": ok, "message": "Connection successful" if ok else "Connection failed – check credentials and region"}


def _upsert_aws_assets(db, assets_data: list) -> int:
    from app.models import Asset
    now = datetime.utcnow()
    created = 0

    _CLOUD_FIELDS = [
        "hostname", "ip_address", "os", "environment", "owner", "business_service",
        "internet_exposure", "asset_type",
        "region", "cloud_account_id", "cloud_account_name",
        "instance_type", "run_state", "public_ips", "private_ips",
        "aws_image_id", "aws_image_name", "tags",
    ]

    for a in assets_data:
        arn = a.get("cloud_resource_id")
        if not arn:
            continue
        asset = db.query(Asset).filter(Asset.cloud_resource_id == arn).first()
        if asset:
            asset.last_seen = now
            asset.source = _merge_source(asset.source, "aws")
            for field in _CLOUD_FIELDS:
                val = a.get(field)
                if val is not None:
                    setattr(asset, field, val)
        else:
            asset = Asset(
                cloud_resource_id=arn,
                identity_type="cloud_resource",
                location_type="cloud",
                source="aws",
                first_seen=now,
                last_seen=now,
                status="active",
                **{f: a.get(f) for f in _CLOUD_FIELDS if a.get(f) is not None},
            )
            db.add(asset)
            created += 1
    db.commit()
    return created


async def _run_aws_sync(scanner_id: int, job_id: int):
    from app.database import SessionLocal
    from app.models import AWSConfig, Vulnerability
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        scanner = db.query(Scanner).filter(Scanner.id == scanner_id).first()
        if not job or not scanner:
            return

        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        cfg = db.query(AWSConfig).filter(AWSConfig.scanner_id == scanner_id).first()
        if not cfg:
            cfg = db.query(AWSConfig).first()
        if not cfg:
            job.status = "failed"
            job.error_message = "AWS not configured"
            scanner.status = "error"
            db.commit()
            return

        try:
            from app.integrations.aws import AWSIntegration
            integration = AWSIntegration(
                access_key_id=cfg.access_key_id,
                secret_access_key=cfg.secret_access_key,
                region=cfg.region,
            )

            # 1. Discover assets across all regions
            account_name = integration._get_account_name()
            assets_data = await integration.collect_assets()
            for a in assets_data:
                a["cloud_account_name"] = account_name
            assets_created = _upsert_aws_assets(db, assets_data)

            # 2. Sync vulnerability + CSPM findings
            findings = await integration.fetch_vulnerabilities()
            _persist_findings(db, findings, "aws")

            regions_scanned = integration._get_all_regions()
            job.findings_count = len(findings)
            job.error_message = (
                f"Assets discovered: {len(assets_data)} across {len(regions_scanned)} region(s). "
                f"New: {assets_created}. Findings: {len(findings)}."
            )
            scanner.total_findings = db.query(Vulnerability).filter(Vulnerability.source == "aws").count()
            scanner.last_sync = datetime.utcnow()
            scanner.status = "idle"
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            db.commit()
        except Exception as exc:
            job.status = "failed"
            job.error_message = str(exc)[:500]
            scanner.status = "error"
            db.commit()
    finally:
        db.close()


@router.get("/aws/diagnose")
async def aws_diagnose(db: Session = Depends(get_db)):
    """Test each AWS service API and report what works / what fails."""
    from app.models import AWSConfig
    cfg = db.query(AWSConfig).first()
    if not cfg:
        raise HTTPException(status_code=400, detail="AWS not configured")

    from app.integrations.aws import AWSIntegration
    integration = AWSIntegration(
        access_key_id=cfg.access_key_id,
        secret_access_key=cfg.secret_access_key,
        region=cfg.region,
    )

    results = {}

    def _try(label: str, fn):
        try:
            result = fn()
            results[label] = {"ok": True, "count": len(result) if hasattr(result, "__len__") else result}
        except Exception as e:
            results[label] = {"ok": False, "error": str(e)[:200]}

    region = cfg.region

    _try("sts:GetCallerIdentity", lambda: [integration._client("sts").get_caller_identity()])
    _try("ec2:DescribeRegions",   lambda: integration._get_all_regions())
    _try("lambda:ListFunctions",  lambda: integration._collect_lambda(region))
    _try("ec2:DescribeInstances", lambda: integration._collect_ec2(region))
    _try("rds:DescribeDBInstances", lambda: integration._collect_rds(region))
    _try("s3:ListBuckets",        lambda: integration._collect_s3())
    _try("ecs:ListClusters",      lambda: integration._collect_ecs(region))
    _try("eks:ListClusters",      lambda: integration._collect_eks(region))
    _try("elbv2:DescribeLBs",     lambda: integration._collect_load_balancers(region))
    _try("dynamodb:ListTables",   lambda: integration._collect_dynamodb(region))
    _try("apigateway:GetAPIs",    lambda: integration._collect_api_gateways(region))
    _try("elasticache:Clusters",  lambda: integration._collect_elasticache(region))
    _try("sns:ListTopics",        lambda: integration._collect_sns(region))
    _try("sqs:ListQueues",        lambda: integration._collect_sqs(region))
    _try("secretsmanager:List",   lambda: integration._collect_secrets(region))
    _try("cloudfront:ListDist",   lambda: integration._collect_cloudfront())

    ok_count = sum(1 for v in results.values() if v["ok"])
    fail_count = len(results) - ok_count
    return {
        "region_configured": region,
        "services_ok": ok_count,
        "services_failed": fail_count,
        "details": results,
    }


@router.post("/aws/sync")
async def aws_sync(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scanner = db.query(Scanner).filter(Scanner.scanner_type == "aws").first()
    if not scanner:
        raise HTTPException(status_code=404, detail="AWS scanner not found")
    if not _is_configured("aws", db):
        raise HTTPException(status_code=400, detail="AWS is not configured. Click Connect to enter credentials.")

    job = ScanJob(scanner_id=scanner.id, status="pending")
    db.add(job)
    scanner.status = "scanning"
    db.commit()
    db.refresh(job)

    background_tasks.add_task(_run_aws_sync, scanner.id, job.id)
    return {"job_id": job.id, "status": "pending", "message": "AWS sync started"}


# ── Nuclei ingest ─────────────────────────────────────────────────────────────

@router.post("/nuclei/ingest")
async def nuclei_ingest(request: Request, db: Session = Depends(get_db)):
    """Accept Nuclei JSONL via file upload (multipart) or raw body (pipe)."""
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        file = form.get("file")
        if not file:
            raise HTTPException(status_code=400, detail="No file field in form data")
        raw = await file.read()
        content = raw.decode("utf-8", errors="replace")
    else:
        body = await request.body()
        content = body.decode("utf-8", errors="replace")

    if not content.strip():
        raise HTTPException(status_code=400, detail="Empty body")

    from app.integrations.nuclei import parse_nuclei_jsonl
    findings = parse_nuclei_jsonl(content)

    if not findings:
        raise HTTPException(status_code=400, detail="No valid Nuclei findings could be parsed")

    scanner = db.query(Scanner).filter(Scanner.scanner_type == "nuclei").first()
    if not scanner:
        raise HTTPException(status_code=404, detail="Nuclei scanner not found – add it in the DB")

    job = ScanJob(
        scanner_id=scanner.id,
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(job)
    scanner.status = "scanning"
    db.commit()
    db.refresh(job)

    try:
        _persist_findings(db, findings, "nuclei")
        from app.models import Vulnerability
        job.findings_count = len(findings)
        scanner.total_findings = (
            db.query(Vulnerability).filter(Vulnerability.source == "nuclei").count()
        )
        scanner.last_sync = datetime.utcnow()
        scanner.status = "idle"
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        job.status = "failed"
        job.error_message = str(exc)[:500]
        scanner.status = "error"
        db.commit()
        raise HTTPException(status_code=500, detail=f"Persist failed: {exc}")

    return {
        "status": "ok",
        "findings_imported": len(findings),
        "job_id": job.id,
        "message": f"Imported {len(findings)} findings from Nuclei scan",
    }


# ── Generic multi-instance CRUD ───────────────────────────────────────────────

@router.post("/", response_model=ScannerOut)
def create_scanner(payload: ScannerCreateIn, db: Session = Depends(get_db)):
    existing = db.query(Scanner).filter(Scanner.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="A scanner with that name already exists")
    s = Scanner(
        name=payload.name,
        scanner_type=payload.scanner_type,
        enabled=True,
        status="unconfigured",
        total_findings=0,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return ScannerOut(
        id=s.id, name=s.name, scanner_type=s.scanner_type,
        enabled=s.enabled, status=s.status, last_sync=s.last_sync,
        total_findings=s.total_findings, configured=False,
    )


@router.delete("/{scanner_id}")
def delete_scanner(scanner_id: int, db: Session = Depends(get_db)):
    s = db.query(Scanner).filter(Scanner.id == scanner_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scanner not found")
    if s.scanner_type == "nessus":
        from app.models import NessusConfig
        cfg = db.query(NessusConfig).filter(NessusConfig.scanner_id == scanner_id).first()
        if cfg:
            db.delete(cfg)
    elif s.scanner_type == "aws":
        from app.models import AWSConfig
        cfg = db.query(AWSConfig).filter(AWSConfig.scanner_id == scanner_id).first()
        if cfg:
            db.delete(cfg)
    db.delete(s)
    db.commit()
    return {"status": "ok"}


@router.get("/{scanner_id}/configure")
def get_scanner_config(scanner_id: int, db: Session = Depends(get_db)):
    s = db.query(Scanner).filter(Scanner.id == scanner_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scanner not found")
    if s.scanner_type == "nessus":
        from app.models import NessusConfig
        cfg = db.query(NessusConfig).filter(NessusConfig.scanner_id == scanner_id).first()
        if not cfg:
            return {"configured": False, "scanner_type": "nessus"}
        return {
            "configured": True, "scanner_type": "nessus",
            "url": cfg.url,
            "access_key_hint": (cfg.access_key[:6] + "***") if cfg.access_key else "",
            "excluded_folders": cfg.excluded_folders or "",
            "updated_at": cfg.updated_at,
        }
    if s.scanner_type == "aws":
        from app.models import AWSConfig
        cfg = db.query(AWSConfig).filter(AWSConfig.scanner_id == scanner_id).first()
        if not cfg:
            return {"configured": False, "scanner_type": "aws"}
        return {
            "configured": True, "scanner_type": "aws",
            "access_key_hint": (cfg.access_key_id[:4] + "***") if cfg.access_key_id else "",
            "region": cfg.region,
            "updated_at": cfg.updated_at,
        }
    return {"configured": False, "scanner_type": s.scanner_type}


@router.post("/{scanner_id}/configure")
async def save_scanner_config(scanner_id: int, request: Request, db: Session = Depends(get_db)):
    s = db.query(Scanner).filter(Scanner.id == scanner_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scanner not found")
    body = await request.json()
    if s.scanner_type == "nessus":
        from app.models import NessusConfig
        cfg = db.query(NessusConfig).filter(NessusConfig.scanner_id == scanner_id).first()
        if cfg:
            cfg.url = body.get("url", cfg.url)
            if body.get("access_key"):
                cfg.access_key = body["access_key"]
            if body.get("secret_key"):
                cfg.secret_key = body["secret_key"]
            cfg.excluded_folders = body.get("excluded_folders", cfg.excluded_folders)
            cfg.updated_at = datetime.utcnow()
        else:
            cfg = NessusConfig(
                scanner_id=scanner_id,
                url=body.get("url"),
                access_key=body.get("access_key"),
                secret_key=body.get("secret_key"),
                excluded_folders=body.get("excluded_folders"),
                updated_at=datetime.utcnow(),
            )
            db.add(cfg)
        if s.status == "unconfigured":
            s.status = "idle"
    elif s.scanner_type == "aws":
        from app.models import AWSConfig
        cfg = db.query(AWSConfig).filter(AWSConfig.scanner_id == scanner_id).first()
        if cfg:
            cfg.access_key_id = body.get("access_key_id", cfg.access_key_id)
            cfg.secret_access_key = body.get("secret_access_key", cfg.secret_access_key)
            cfg.region = body.get("region", cfg.region)
            cfg.updated_at = datetime.utcnow()
        else:
            cfg = AWSConfig(
                scanner_id=scanner_id,
                access_key_id=body.get("access_key_id"),
                secret_access_key=body.get("secret_access_key"),
                region=body.get("region", "eu-central-1"),
                updated_at=datetime.utcnow(),
            )
            db.add(cfg)
        if s.status == "unconfigured":
            s.status = "idle"
    else:
        raise HTTPException(status_code=400, detail=f"Scanner type '{s.scanner_type}' does not support this endpoint")
    db.commit()
    return {"status": "ok", "message": f"{s.name} configured successfully"}


@router.post("/{scanner_id}/test")
async def test_scanner_connection(scanner_id: int, request: Request, db: Session = Depends(get_db)):
    s = db.query(Scanner).filter(Scanner.id == scanner_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scanner not found")
    body = await request.json()
    if s.scanner_type == "nessus":
        from app.integrations.nessus import NessusIntegration
        integration = NessusIntegration(
            url=body.get("url"),
            access_key=body.get("access_key"),
            secret_key=body.get("secret_key"),
            verify_ssl=False,
            excluded_folders=body.get("excluded_folders"),
        )
        ok = await integration.test_connection()
        return {"success": ok, "message": "Connection successful" if ok else "Connection failed – check URL and API keys"}
    if s.scanner_type == "aws":
        from app.integrations.aws import AWSIntegration
        integration = AWSIntegration(
            access_key_id=body.get("access_key_id"),
            secret_access_key=body.get("secret_access_key"),
            region=body.get("region", "eu-central-1"),
        )
        ok = await integration.test_connection()
        return {"success": ok, "message": "Connection successful" if ok else "Connection failed – check credentials"}
    raise HTTPException(status_code=400, detail=f"Test not supported for '{s.scanner_type}'")


@router.post("/{scanner_id}/sync")
async def sync_scanner(scanner_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    s = db.query(Scanner).filter(Scanner.id == scanner_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scanner not found")
    if not _is_configured(s.scanner_type, db, scanner_id=scanner_id):
        raise HTTPException(status_code=400, detail=f"{s.name} is not configured")
    job = ScanJob(scanner_id=scanner_id, status="pending")
    db.add(job)
    s.status = "scanning"
    db.commit()
    db.refresh(job)
    if s.scanner_type == "aws":
        background_tasks.add_task(_run_aws_sync, scanner_id, job.id)
    else:
        background_tasks.add_task(_run_scan, scanner_id, job.id)
    return {"job_id": job.id, "status": "pending", "message": f"{s.name} sync started"}


# ── Scanner list & jobs ────────────────────────────────────────────────────────

@router.get("/", response_model=list[ScannerOut])
def list_scanners(db: Session = Depends(get_db)):
    scanners = db.query(Scanner).all()
    result = []
    for s in scanners:
        configured = _is_configured(s.scanner_type, db, scanner_id=s.id)
        status = s.status if configured else "unconfigured"
        result.append(ScannerOut(
            id=s.id, name=s.name, scanner_type=s.scanner_type,
            enabled=s.enabled, status=status, last_sync=s.last_sync,
            total_findings=s.total_findings, configured=configured,
        ))
    return result


@router.get("/{scanner_id}/jobs", response_model=list[ScanJobOut])
def scanner_jobs(scanner_id: int, limit: int = 20, db: Session = Depends(get_db)):
    s = db.query(Scanner).filter(Scanner.id == scanner_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scanner not found")
    return (
        db.query(ScanJob)
        .filter(ScanJob.scanner_id == scanner_id)
        .order_by(ScanJob.started_at.desc())
        .limit(limit)
        .all()
    )


# ── Background scan task ───────────────────────────────────────────────────────

async def _run_scan(scanner_id: int, job_id: int):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        scanner = db.query(Scanner).filter(Scanner.id == scanner_id).first()
        if not job or not scanner:
            return

        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        try:
            from app.integrations import get_integration
            integration = get_integration(scanner.scanner_type, db)
            if integration:
                findings = await integration.fetch_vulnerabilities()
                _persist_findings(db, findings, scanner.scanner_type)
                job.findings_count = len(findings)
                from app.models import Vulnerability
                scanner.total_findings = (
                    db.query(Vulnerability)
                    .filter(Vulnerability.source == scanner.scanner_type)
                    .count()
                )
                scanner.last_sync = datetime.utcnow()
                scanner.status = "idle"
            else:
                job.status = "failed"
                job.error_message = "Scanner not configured or integration unavailable"
                scanner.status = "error"
                db.commit()
                return
        except Exception as exc:
            job.status = "failed"
            job.error_message = str(exc)[:500]
            scanner.status = "error"
            db.commit()
            return

        job.status = "completed"
        job.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


@router.post("/{scanner_id}/scan")
def trigger_scan(
    scanner_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    s = db.query(Scanner).filter(Scanner.id == scanner_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scanner not found")
    if not _is_configured(s.scanner_type, db):
        raise HTTPException(
            status_code=400,
            detail="Scanner is not configured. Use the Configure button to set credentials.",
        )

    job = ScanJob(scanner_id=scanner_id, status="pending")
    db.add(job)
    s.status = "scanning"
    db.commit()
    db.refresh(job)

    background_tasks.add_task(_run_scan, scanner_id, job.id)
    return {"job_id": job.id, "status": "pending", "message": "Scan job queued"}


@router.get("/config/status")
def config_status(db: Session = Depends(get_db)):
    return {
        "nessus":  _is_configured("nessus", db),
        "mde":     _is_configured("mde"),
        "openvas": _is_configured("openvas"),
        "nmap":    _is_configured("nmap"),
        "pac":     _is_configured("pac"),
        "aws":     _is_configured("aws", db),
    }
