from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Vulnerability, ScanJob, Scanner
from app.schemas import DashboardStats, SeverityDistribution, TrendPoint, TopAsset

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
def get_stats(db: Session = Depends(get_db)):
    def count_sev(sev):
        return db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.severity == sev,
            Vulnerability.status != "remediated",
        ).scalar() or 0

    total = db.query(func.count(Vulnerability.id)).scalar() or 0
    open_v = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.status == "open"
    ).scalar() or 0

    total_assets = db.query(func.count(Asset.id)).scalar() or 0
    assets_at_risk = db.query(func.count(Asset.id)).filter(Asset.risk_score > 0).scalar() or 0

    cutoff = datetime.utcnow() - timedelta(days=30)
    remediated_30d = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.status == "remediated",
        Vulnerability.last_seen >= cutoff,
    ).scalar() or 0
    new_30d = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.first_seen >= cutoff
    ).scalar() or 0

    return DashboardStats(
        total_vulnerabilities=total,
        open_vulnerabilities=open_v,
        critical=count_sev("critical"),
        high=count_sev("high"),
        medium=count_sev("medium"),
        low=count_sev("low"),
        info=count_sev("info"),
        total_assets=total_assets,
        assets_at_risk=assets_at_risk,
        remediated_30d=remediated_30d,
        new_30d=new_30d,
    )


@router.get("/severity-distribution", response_model=SeverityDistribution)
def severity_distribution(db: Session = Depends(get_db)):
    def c(sev):
        return db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.severity == sev
        ).scalar() or 0

    return SeverityDistribution(
        critical=c("critical"), high=c("high"),
        medium=c("medium"), low=c("low"), info=c("info"),
    )


@router.get("/trend")
def trend(db: Session = Depends(get_db)):
    points = []
    for days_back in range(29, -1, -1):
        day = datetime.utcnow() - timedelta(days=days_back)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)

        def c(sev):
            return db.query(func.count(Vulnerability.id)).filter(
                Vulnerability.severity == sev,
                Vulnerability.first_seen <= day_end,
                Vulnerability.status != "remediated",
            ).scalar() or 0

        points.append(TrendPoint(
            date=day_start.strftime("%Y-%m-%d"),
            critical=c("critical"),
            high=c("high"),
            medium=c("medium"),
            low=c("low"),
        ))
    return points


@router.get("/top-assets")
def top_assets(limit: int = 10, db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.risk_score.desc()).limit(limit).all()
    result = []
    for a in assets:
        vuln_count = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.asset_id == a.id,
            Vulnerability.status != "remediated",
        ).scalar() or 0
        result.append(TopAsset(
            id=a.id,
            hostname=a.hostname,
            ip_address=a.ip_address,
            criticality=a.criticality,
            vuln_count=vuln_count,
            risk_score=a.risk_score,
        ))
    return result


@router.get("/recent-activity")
def recent_activity(limit: int = 8, db: Session = Depends(get_db)):
    jobs = (
        db.query(ScanJob, Scanner.name, Scanner.scanner_type)
        .join(Scanner)
        .order_by(ScanJob.started_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": j.id,
            "scanner": name,
            "scanner_type": stype,
            "status": j.status,
            "started_at": j.started_at,
            "completed_at": j.completed_at,
            "findings_count": j.findings_count,
        }
        for j, name, stype in jobs
    ]


@router.get("/scanner-status")
def scanner_status(db: Session = Depends(get_db)):
    scanners = db.query(Scanner).all()
    return [
        {"id": s.id, "name": s.name, "type": s.scanner_type, "status": s.status}
        for s in scanners
    ]


@router.get("/os-distribution")
def os_distribution(db: Session = Depends(get_db)):
    rows = (
        db.query(Asset.os, func.count(Asset.id))
        .filter(Asset.os.isnot(None), Asset.os != "")
        .group_by(Asset.os)
        .order_by(func.count(Asset.id).desc())
        .limit(10)
        .all()
    )
    return [{"os": r[0] or "Unknown", "count": r[1]} for r in rows]


@router.get("/status-distribution")
def status_distribution(db: Session = Depends(get_db)):
    rows = (
        db.query(Vulnerability.status, func.count(Vulnerability.id))
        .group_by(Vulnerability.status)
        .all()
    )
    counts = {r[0]: r[1] for r in rows}
    return {
        "open":        counts.get("open", 0),
        "in_progress": counts.get("in_progress", 0),
        "accepted":    counts.get("accepted", 0),
        "remediated":  counts.get("remediated", 0),
    }


@router.get("/accepted-risks")
def accepted_risks(limit: int = 15, db: Session = Depends(get_db)):
    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.status == "accepted")
        .order_by(Vulnerability.cvss_score.desc().nulls_last())
        .limit(limit)
        .all()
    )
    result = []
    for v in vulns:
        asset = db.query(Asset).filter(Asset.id == v.asset_id).first() if v.asset_id else None
        result.append({
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "vpr_score": v.vpr_score,
            "cisa_kev_date": v.cisa_kev_date,
            "exploit_available": v.exploit_available,
            "asset_hostname": asset.hostname if asset else None,
            "asset_ip": asset.ip_address if asset else None,
            "asset_id": v.asset_id,
        })
    return result


@router.get("/risk-age")
def risk_age(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    buckets = [
        ("< 7 days",   now - timedelta(days=7),  now),
        ("7–30 days",  now - timedelta(days=30), now - timedelta(days=7)),
        ("30–90 days", now - timedelta(days=90), now - timedelta(days=30)),
        ("> 90 days",  datetime.min,             now - timedelta(days=90)),
    ]
    result = []
    for label, start, end in buckets:
        count = (
            db.query(func.count(Vulnerability.id))
            .filter(
                Vulnerability.status.in_(["open", "in_progress"]),
                Vulnerability.first_seen >= start,
                Vulnerability.first_seen < end,
            )
            .scalar() or 0
        )
        result.append({"label": label, "count": count})
    return result


@router.get("/enrichment-stats")
def enrichment_stats(db: Session = Depends(get_db)):
    exploit_count = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.exploit_available == True, Vulnerability.status != "remediated")
        .scalar() or 0
    )
    kev_count = (
        db.query(func.count(Vulnerability.id))
        .filter(
            Vulnerability.cisa_kev_date.isnot(None),
            Vulnerability.cisa_kev_date != "",
            Vulnerability.status != "remediated",
        )
        .scalar() or 0
    )
    from sqlalchemy import cast, Float
    avg_vpr = (
        db.query(func.avg(Vulnerability.vpr_score))
        .filter(Vulnerability.vpr_score.isnot(None), Vulnerability.status != "remediated")
        .scalar()
    )
    return {
        "exploit_available": exploit_count,
        "cisa_kev": kev_count,
        "avg_vpr": round(float(avg_vpr), 1) if avg_vpr else None,
    }
