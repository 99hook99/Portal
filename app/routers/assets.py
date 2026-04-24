from typing import Optional
from datetime import datetime
import csv, io, json, ipaddress
from fastapi import APIRouter, Depends, Query, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Vulnerability, AppSystemAsset
from app.schemas import AssetOut, AssetCreate, AssetMetaUpdate
from app.utils import detect_identity_type

router = APIRouter()


@router.get("/")
def list_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=1000),
    criticality: Optional[str] = None,
    asset_type: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    unassigned: bool = Query(False),
    system_id: Optional[int] = None,
    identity_type: Optional[str] = None,
    location_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Asset)
    if criticality:
        q = q.filter(Asset.criticality == criticality)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type)
    if source:
        q = q.filter(Asset.source.contains(source))
    if search:
        term = f"%{search}%"
        q = q.filter(
            Asset.hostname.ilike(term) | Asset.ip_address.ilike(term)
        )
    if unassigned:
        assigned = db.query(AppSystemAsset.asset_id).distinct()
        q = q.filter(~Asset.id.in_(assigned))
    if system_id:
        sys_assets = db.query(AppSystemAsset.asset_id).filter(
            AppSystemAsset.system_id == system_id
        ).distinct()
        q = q.filter(Asset.id.in_(sys_assets))
    if identity_type:
        if identity_type == "cloud_resource":
            q = q.filter(Asset.identity_type == "cloud_resource")
        elif identity_type == "host":
            q = q.filter(~Asset.identity_type.in_(["cloud_resource", "web"]))
        else:
            q = q.filter(Asset.identity_type == identity_type)
    if location_type:
        if location_type == "cloud":
            q = q.filter(or_(Asset.location_type == "cloud", Asset.identity_type == "cloud_resource"))
        elif location_type == "host":
            q = q.filter(Asset.location_type != "cloud", Asset.identity_type != "cloud_resource")
        else:
            q = q.filter(Asset.location_type == location_type)

    _CSPM_FAMILIES = ["%CSPM%", "%Cloud Security%", "%Benchmark%", "%Compliance%", "%Patch Management%"]

    total = q.count()
    items = q.order_by(Asset.risk_score.desc()).offset((page - 1) * per_page).limit(per_page).all()

    result = []
    for a in items:
        base_q = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.asset_id == a.id,
            Vulnerability.status != "remediated",
        )
        vc = base_q.scalar() or 0
        cc = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.asset_id == a.id,
            Vulnerability.severity == "critical",
            Vulnerability.status != "remediated",
        ).scalar() or 0
        hc = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.asset_id == a.id,
            Vulnerability.severity == "high",
            Vulnerability.status != "remediated",
        ).scalar() or 0
        rec_filter = or_(*[Vulnerability.plugin_family.ilike(f) for f in _CSPM_FAMILIES])
        rc = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.asset_id == a.id,
            Vulnerability.status != "remediated",
            rec_filter,
        ).scalar() or 0
        result.append({
            **AssetOut.model_validate(a).model_dump(),
            "vuln_count": vc, "critical_count": cc,
            "high_count": hc, "rec_count": rc,
        })

    return {"total": total, "page": page, "per_page": per_page, "items": result}


def _merge_source(existing: str | None, new_source: str) -> str:
    parts = {s.strip() for s in (existing or "").split(",") if s.strip()}
    parts.add(new_source.strip())
    return ",".join(sorted(parts))


def _normalize_hostname(h: str) -> str:
    return h.strip().lower() if h else ""

def _normalize_ip(ip: str) -> str:
    if not ip:
        return ""
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip.strip()

def _parse_bool(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes")

VALID_CRITICALITY    = {"critical", "high", "medium", "low"}
VALID_ASSET_TYPES    = {"server", "workstation", "network", "cloud", "iot", "container", "image", "app", "repo", "web", "other"}
VALID_IDENTITY_TYPES = {"host", "server", "workstation", "cloud_resource", "container", "image", "app", "repo", "web"}
VALID_EXPOSURE       = {"exposed", "partial", "internal", "unknown"}
VALID_LOCATION       = {"on-prem", "cloud", "saas", "ot", "hybrid"}
VALID_DATA_CLASS     = {"public", "internal", "confidential", "restricted", "pii"}
VALID_ENVIRON        = {"prod", "staging", "uat", "dev", "test"}
VALID_EOL            = {"active", "eol", "eos", "unknown"}
VALID_LABELS         = {"crown_jewel", "regulated", "customer_facing", "privileged_zone"}


def _str(row: dict, key: str) -> str:
    return (row.get(key) or "").strip()


def _upsert_asset(row: dict, db: Session, default_source: str = "import") -> tuple[Asset, str]:
    hostname = _normalize_hostname(_str(row, "hostname"))
    ip       = _normalize_ip(_str(row, "ip_address") or _str(row, "ip"))

    if not hostname and not ip:
        raise ValueError("Each row must have at least hostname or ip_address")

    asset = None
    if hostname:
        asset = db.query(Asset).filter(func.lower(Asset.hostname) == hostname).first()
    if not asset and ip:
        asset = db.query(Asset).filter(Asset.ip_address == ip).first()

    # Validated + defaulted values
    criticality = _str(row, "criticality").lower() or "medium"
    if criticality not in VALID_CRITICALITY:
        criticality = "medium"
    asset_type = _str(row, "asset_type").lower() or "server"
    if asset_type not in VALID_ASSET_TYPES:
        asset_type = "server"

    os_val      = _str(row, "os")
    os_ver      = _str(row, "os_version")
    source_val  = _str(row, "source") or default_source

    identity = _str(row, "identity_type").lower()
    if identity not in VALID_IDENTITY_TYPES:
        identity = detect_identity_type(source_val, os_val, asset_type, _str(row, "tags"),
                                        hostname=_str(row, "hostname"), fqdn=_str(row, "fqdn"))

    exposure = _str(row, "internet_exposure").lower() or "unknown"
    if exposure not in VALID_EXPOSURE:
        exposure = "unknown"

    location = _str(row, "location_type").lower()
    if location not in VALID_LOCATION:
        location = None

    data_cls = _str(row, "data_classification").lower()
    if data_cls not in VALID_DATA_CLASS:
        data_cls = None

    environ = _str(row, "environment").lower()
    if environ not in VALID_ENVIRON:
        environ = None

    eol = _str(row, "eol_status").lower()
    if eol not in VALID_EOL:
        eol = None

    # Normalise asset_labels — keep only known values
    raw_labels = _str(row, "asset_labels")
    if raw_labels:
        labels = ",".join(l.strip() for l in raw_labels.split(",") if l.strip() in VALID_LABELS)
    else:
        labels = None

    if asset:
        if hostname and asset.hostname != hostname:   asset.hostname = hostname
        if ip and asset.ip_address != ip:             asset.ip_address = ip
        if os_val:    asset.os = os_val
        if os_ver:    asset.os_version = os_ver
        if _str(row, "mac_address"):  asset.mac_address = _str(row, "mac_address")
        if _str(row, "fqdn"):         asset.fqdn = _str(row, "fqdn")
        if _str(row, "cloud_resource_id"): asset.cloud_resource_id = _str(row, "cloud_resource_id")
        if _str(row, "tags"):         asset.tags = _str(row, "tags")
        if _str(row, "owner"):        asset.owner = _str(row, "owner")
        if _str(row, "secondary_owner"): asset.secondary_owner = _str(row, "secondary_owner")
        if _str(row, "business_service"): asset.business_service = _str(row, "business_service")
        if _str(row, "business_criticality"): asset.business_criticality = _str(row, "business_criticality")
        if labels:    asset.asset_labels = labels
        if data_cls:  asset.data_classification = data_cls
        if environ:   asset.environment = environ
        if eol:       asset.eol_status = eol
        if location:  asset.location_type = location
        asset.source          = _merge_source(asset.source, source_val)
        asset.criticality     = criticality
        asset.asset_type      = asset_type
        asset.identity_type   = identity
        asset.internet_exposure = exposure
        asset.last_seen       = datetime.utcnow()
        action = "updated"
    else:
        asset = Asset(
            hostname=hostname or None,
            ip_address=ip or None,
            fqdn=_str(row, "fqdn") or None,
            cloud_resource_id=_str(row, "cloud_resource_id") or None,
            identity_type=identity,
            os=os_val or None,
            os_version=os_ver or None,
            eol_status=eol,
            mac_address=_str(row, "mac_address") or None,
            tags=_str(row, "tags") or None,
            owner=_str(row, "owner") or None,
            secondary_owner=_str(row, "secondary_owner") or None,
            business_service=_str(row, "business_service") or None,
            business_criticality=_str(row, "business_criticality") or None,
            data_classification=data_cls,
            asset_labels=labels,
            environment=environ,
            internet_exposure=exposure,
            location_type=location,
            criticality=criticality,
            asset_type=asset_type,
            source=source_val,
            status="active",
            risk_score=0.0,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.add(asset)
        action = "created"

    return asset, action


@router.post("/import")
async def import_assets(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    filename = (file.filename or "").lower()

    rows = []
    errors = []

    file_source = "json" if filename.endswith(".json") else "csv"

    if filename.endswith(".json"):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                rows = data
            elif isinstance(data, dict) and "assets" in data:
                rows = data["assets"]
            else:
                raise ValueError("JSON must be an array or {assets: [...]}")
        except (json.JSONDecodeError, ValueError) as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    else:
        # Treat as CSV (default)
        try:
            text = content.decode("utf-8-sig")  # handle BOM
            reader = csv.DictReader(io.StringIO(text))
            rows = list(reader)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid CSV: {e}")

    created = updated = skipped = 0

    for i, row in enumerate(rows):
        # Strip whitespace from all keys/values
        row = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
        try:
            _, action = _upsert_asset(row, db, default_source=file_source)
            if action == "created":
                created += 1
            else:
                updated += 1
        except ValueError as e:
            errors.append({"row": i + 1, "error": str(e)})
            skipped += 1
            continue

    db.commit()
    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "errors": errors[:20],  # cap error list
    }


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    vc = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.asset_id == a.id,
        Vulnerability.status != "remediated",
    ).scalar() or 0
    cc = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.asset_id == a.id,
        Vulnerability.severity == "critical",
        Vulnerability.status != "remediated",
    ).scalar() or 0
    return {**AssetOut.model_validate(a).model_dump(), "vuln_count": vc, "critical_count": cc}


@router.patch("/{asset_id}")
def update_asset_meta(asset_id: int, payload: AssetMetaUpdate, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(a, field, value)
    a.last_seen = datetime.utcnow()
    db.commit()
    db.refresh(a)
    return AssetOut.model_validate(a).model_dump()


@router.get("/{asset_id}/report", response_class=HTMLResponse)
def asset_report(asset_id: int, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")

    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.cvss_score.desc().nulls_last())
        .all()
    )

    SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e", "info": "#64748b"}
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        if v.severity in sev_counts:
            sev_counts[v.severity] += 1

    kev_vulns = [v for v in vulns if v.cisa_kev_date]
    exploit_vulns = [v for v in vulns if v.exploit_available]

    def sev_badge(s):
        c = SEV_COLOR.get(s, "#64748b")
        return f'<span style="background:{c}20;color:{c};border:1px solid {c}40;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">{s}</span>'

    def safe(v):
        return (v or "–").replace("<", "&lt;").replace(">", "&gt;")

    vuln_rows = ""
    for v in vulns:
        status_style = "color:#22c55e" if v.status == "remediated" else "color:#8a9abf"
        vpr = f"{v.vpr_score:.1f}" if v.vpr_score else "–"
        epss = f"{v.epss_score:.3f}" if v.epss_score else "–"
        kev = "⚠ KEV" if v.cisa_kev_date else ""
        exploit = "✓" if v.exploit_available else ""
        cvss = f"{v.cvss_score:.1f}" if v.cvss_score else "–"
        port = f"{v.port}/{v.protocol or 'tcp'}" if v.port else "–"
        vuln_rows += f"""
        <tr>
          <td>{sev_badge(v.severity)}</td>
          <td style="font-weight:500">{safe(v.title)}</td>
          <td style="font-family:monospace;font-size:11px">{safe(v.cve_ids)}</td>
          <td style="text-align:center">{cvss}</td>
          <td style="text-align:center;font-weight:600;color:#f97316">{vpr}</td>
          <td style="text-align:center;font-size:11px;color:#8a9abf">{epss}</td>
          <td style="text-align:center;color:#ef4444;font-weight:600">{kev}</td>
          <td style="text-align:center;color:#22c55e">{exploit}</td>
          <td style="font-family:monospace;font-size:11px">{port}</td>
          <td style="{status_style};font-size:11px">{safe(v.status).replace("_", " ")}</td>
        </tr>"""

    host_label = a.hostname or a.ip_address or f"Asset #{asset_id}"
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Report – {safe(host_label)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 13px; color: #1e293b; background: #fff; padding: 32px; }}
  h1 {{ font-size: 22px; font-weight: 700; color: #0f172a; }}
  h2 {{ font-size: 14px; font-weight: 600; color: #334155; margin: 24px 0 10px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 28px; padding-bottom: 16px; border-bottom: 3px solid #0f172a; }}
  .header-left {{ }}
  .header-right {{ text-align: right; font-size: 11px; color: #64748b; }}
  .kv-grid {{ display: grid; grid-template-columns: 140px 1fr; gap: 4px 12px; margin-bottom: 4px; }}
  .kv-grid .k {{ color: #64748b; font-weight: 500; }}
  .kv-grid .v {{ color: #1e293b; font-family: monospace; font-size: 12px; }}
  .sev-summary {{ display: flex; gap: 16px; margin: 12px 0 20px; }}
  .sev-box {{ text-align: center; padding: 10px 18px; border-radius: 8px; border: 1px solid #e2e8f0; }}
  .sev-box .n {{ font-size: 24px; font-weight: 700; }}
  .sev-box .l {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-top: 2px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ background: #f1f5f9; text-align: left; padding: 7px 8px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; color: #64748b; border-bottom: 1px solid #e2e8f0; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  tr:hover td {{ background: #f8fafc; }}
  .alert-box {{ background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 10px 14px; margin: 10px 0; font-size: 12px; color: #991b1b; }}
  .print-btn {{ position: fixed; top: 16px; right: 16px; background: #0f172a; color: #fff; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; }}
  @media print {{
    .print-btn {{ display: none; }}
    body {{ padding: 16px; }}
    @page {{ margin: 1.5cm; }}
  }}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">⬇ Save as PDF</button>
<div class="header">
  <div class="header-left">
    <div style="font-size:11px;color:#64748b;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.5px">Vulnerability Report</div>
    <h1>{safe(host_label)}</h1>
    <div style="margin-top:6px;font-size:12px;color:#64748b">Source: {safe(a.source)} &nbsp;·&nbsp; Type: {safe(a.asset_type)}</div>
  </div>
  <div class="header-right">
    <div>Generated: {generated}</div>
    <div style="margin-top:4px">Total findings: <strong>{len(vulns)}</strong></div>
  </div>
</div>

<h2>Asset Information</h2>
<div class="kv-grid">
  <span class="k">IP Address</span><span class="v">{safe(a.ip_address)}</span>
  <span class="k">Hostname</span><span class="v">{safe(a.hostname)}</span>
  <span class="k">FQDN</span><span class="v">{safe(getattr(a, 'fqdn', None))}</span>
  <span class="k">Operating System</span><span class="v">{safe(a.os)} {safe(a.os_version)}</span>
  <span class="k">MAC Address</span><span class="v">{safe(a.mac_address)}</span>
  <span class="k">First Seen</span><span class="v">{a.first_seen.strftime("%Y-%m-%d %H:%M") if a.first_seen else "–"}</span>
  <span class="k">Last Seen</span><span class="v">{a.last_seen.strftime("%Y-%m-%d %H:%M") if a.last_seen else "–"}</span>
  <span class="k">Risk Score</span><span class="v">{a.risk_score:.1f} / 100</span>
</div>

<h2>Severity Summary</h2>
<div class="sev-summary">
  <div class="sev-box"><div class="n" style="color:#ef4444">{sev_counts['critical']}</div><div class="l">Critical</div></div>
  <div class="sev-box"><div class="n" style="color:#f97316">{sev_counts['high']}</div><div class="l">High</div></div>
  <div class="sev-box"><div class="n" style="color:#eab308">{sev_counts['medium']}</div><div class="l">Medium</div></div>
  <div class="sev-box"><div class="n" style="color:#22c55e">{sev_counts['low']}</div><div class="l">Low</div></div>
  <div class="sev-box"><div class="n" style="color:#64748b">{sev_counts['info']}</div><div class="l">Info</div></div>
  <div class="sev-box"><div class="n" style="color:#ef4444">{len(exploit_vulns)}</div><div class="l">Exploit Avail.</div></div>
  <div class="sev-box"><div class="n" style="color:#ef4444">{len(kev_vulns)}</div><div class="l">CISA KEV</div></div>
</div>

{'<div class="alert-box">⚠ <strong>CISA Known Exploited Vulnerabilities:</strong> ' + ', '.join(v.title[:40] for v in kev_vulns[:5]) + ('…' if len(kev_vulns) > 5 else '') + '</div>' if kev_vulns else ''}

<h2>Vulnerabilities ({len(vulns)})</h2>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Title</th><th>CVE</th>
      <th style="text-align:center">CVSS</th><th style="text-align:center">VPR</th>
      <th style="text-align:center">EPSS</th><th style="text-align:center">KEV</th>
      <th style="text-align:center">Exploit</th><th>Port</th><th>Status</th>
    </tr>
  </thead>
  <tbody>{vuln_rows}</tbody>
</table>

<div style="margin-top:24px;font-size:11px;color:#94a3b8;text-align:center;border-top:1px solid #e2e8f0;padding-top:12px">
  VM Portal · Vulnerability Report · {generated}
</div>
</body>
</html>"""

    return HTMLResponse(content=html)


@router.get("/{asset_id}/vulnerabilities")
def asset_vulns(
    asset_id: int,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    q = db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id)
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    if status:
        q = q.filter(Vulnerability.status == status)
    return q.order_by(Vulnerability.cvss_score.desc().nulls_last()).all()
