from datetime import datetime, timedelta
from collections import defaultdict
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Vulnerability, ScanJob, Scanner
from app.schemas import DashboardStats, SeverityDistribution, TrendPoint, TopAsset

router = APIRouter()


@router.get("/kpi")
def kpi_metrics(period: str = Query("7d", pattern="^(24h|7d|30d|1y)$"), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    period_days = {"24h": 1, "7d": 7, "30d": 30, "1y": 365}[period]
    curr_start = now - timedelta(days=period_days)
    prev_start = curr_start - timedelta(days=period_days)

    V = Vulnerability

    def snap(sev=None):
        q = db.query(func.count(V.id)).filter(V.status != "remediated")
        if sev:
            q = q.filter(V.severity == sev)
        return q.scalar() or 0

    def cnt_new(since, until=None, sev=None):
        q = db.query(func.count(V.id)).filter(V.first_seen >= since)
        if until:
            q = q.filter(V.first_seen < until)
        if sev:
            q = q.filter(V.severity == sev)
        return q.scalar() or 0

    def cnt_rem(since, until=None):
        q = db.query(func.count(V.id)).filter(V.status == "remediated", V.last_seen >= since)
        if until:
            q = q.filter(V.last_seen < until)
        return q.scalar() or 0

    def avg_mttr(since, until=None):
        q = db.query(func.avg(
            func.julianday(V.last_seen) - func.julianday(V.first_seen)
        )).filter(V.status == "remediated", V.last_seen >= since)
        if until:
            q = q.filter(V.last_seen < until)
        return q.scalar()

    def pct(c, p):
        if not p:
            return None
        return round((c - p) / p * 100, 1)

    new_c  = cnt_new(curr_start)
    new_p  = cnt_new(prev_start, curr_start)
    crit_c = cnt_new(curr_start, sev="critical")
    crit_p = cnt_new(prev_start, curr_start, "critical")
    high_c = cnt_new(curr_start, sev="high")
    high_p = cnt_new(prev_start, curr_start, "high")
    rem_c  = cnt_rem(curr_start)
    rem_p  = cnt_rem(prev_start, curr_start)
    mttr_c = avg_mttr(curr_start)
    mttr_p = avg_mttr(prev_start, curr_start)
    acc    = db.query(func.count(V.id)).filter(V.status == "accepted").scalar() or 0
    acc_c  = db.query(func.count(V.id)).filter(V.status == "accepted", V.last_seen >= curr_start).scalar() or 0
    acc_p  = db.query(func.count(V.id)).filter(V.status == "accepted", V.last_seen >= prev_start, V.last_seen < curr_start).scalar() or 0

    assets_covered = db.query(func.count(func.distinct(V.asset_id))).filter(V.status != "remediated").scalar() or 0
    total_assets   = db.query(func.count(Asset.id)).scalar() or 0

    # ── Sparklines via GROUP BY (2 queries instead of N×4) ──────
    if period == "24h":
        fmt, n, td = '%Y-%m-%d %H', 24, timedelta(hours=1)
    elif period == "1y":
        fmt, n, td = '%Y-%W', 52, timedelta(weeks=1)
    else:
        fmt, n, td = '%Y-%m-%d', period_days, timedelta(days=1)

    new_rows = db.query(
        func.strftime(fmt, V.first_seen).label("b"),
        V.severity,
        func.count(V.id).label("c"),
    ).filter(V.first_seen >= curr_start).group_by("b", V.severity).all()

    rem_rows = db.query(
        func.strftime(fmt, V.last_seen).label("b"),
        func.count(V.id).label("c"),
    ).filter(V.status == "remediated", V.last_seen >= curr_start).group_by("b").all()

    bkt = defaultdict(lambda: defaultdict(int))
    for b, sev, c in new_rows:
        bkt[b]["total"] += c
        bkt[b][sev] += c
    rem_bkt = {b: c for b, c in rem_rows}

    sl: dict = {"total": [], "critical": [], "high": [], "remediated": []}
    for i in range(n):
        key = (curr_start + i * td).strftime(fmt)
        d = bkt.get(key, {})
        sl["total"].append(d.get("total", 0))
        sl["critical"].append(d.get("critical", 0))
        sl["high"].append(d.get("high", 0))
        sl["remediated"].append(rem_bkt.get(key, 0))

    return {
        "period": period,
        "snap": {
            "total": snap(), "critical": snap("critical"), "high": snap("high"),
            "medium": snap("medium"), "low": snap("low"),
            "accepted": acc, "assets_covered": assets_covered, "total_assets": total_assets,
        },
        "metrics": {
            "new":        {"v": new_c,  "pct": pct(new_c,  new_p)},
            "critical":   {"v": crit_c, "pct": pct(crit_c, crit_p)},
            "high":       {"v": high_c, "pct": pct(high_c, high_p)},
            "remediated": {"v": rem_c,  "pct": pct(rem_c,  rem_p)},
            "accepted":   {"v": acc_c,  "pct": pct(acc_c,  acc_p)},
            "mttr": {
                "v":   round(float(mttr_c), 1) if mttr_c else None,
                "pct": pct(float(mttr_c), float(mttr_p)) if mttr_c and mttr_p else None,
            },
        },
        "sparklines": sl,
    }


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
def trend(period: str = Query("30d", pattern="^(24h|7d|30d|1y)$"), db: Session = Depends(get_db)):
    period_days = {"24h": 1, "7d": 7, "30d": 30, "1y": 365}[period]
    now = datetime.utcnow()
    start = now - timedelta(days=period_days)

    if period == "24h":
        fmt, n, td, date_fmt = '%Y-%m-%d %H', 24, timedelta(hours=1), "%H:00"
    elif period == "1y":
        fmt, n, td, date_fmt = '%Y-%W', 52, timedelta(weeks=1), "%b %d"
    else:
        fmt, n, td, date_fmt = '%Y-%m-%d', period_days, timedelta(days=1), "%m-%d"

    rows = db.query(
        func.strftime(fmt, Vulnerability.first_seen).label("b"),
        Vulnerability.severity,
        func.count(Vulnerability.id).label("c"),
    ).filter(Vulnerability.first_seen >= start).group_by("b", Vulnerability.severity).all()

    bkt: dict = defaultdict(lambda: defaultdict(int))
    for b, sev, c in rows:
        bkt[b][sev] += c

    points = []
    for i in range(n):
        bs = start + i * td
        key = bs.strftime(fmt)
        d = bkt.get(key, {})
        points.append({
            "date": bs.strftime(date_fmt),
            "critical": d.get("critical", 0),
            "high":     d.get("high", 0),
            "medium":   d.get("medium", 0),
            "low":      d.get("low", 0),
        })
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
