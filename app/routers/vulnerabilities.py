from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Vulnerability, Asset
from app.schemas import VulnOut, VulnCreate, VulnStatusUpdate

router = APIRouter()


_SORT_COLS = {
    "title":      Vulnerability.title,
    "severity":   Vulnerability.severity,
    "cvss":       Vulnerability.cvss_score,
    "vpr":        Vulnerability.vpr_score,
    "status":     Vulnerability.status,
    "first_seen": Vulnerability.first_seen,
    "last_seen":  Vulnerability.last_seen,
    "source":     Vulnerability.source,
}


@router.get("/")
def list_vulns(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    asset_id: Optional[int] = None,
    host: Optional[str] = None,
    category: Optional[str] = None,  # 'vulnerability' | 'recommendation'
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
):
    q = db.query(Vulnerability)
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    if status:
        if status == "open":
            q = q.filter(Vulnerability.status.in_(["open", "in_progress"]))
        else:
            q = q.filter(Vulnerability.status == status)
    if source:
        q = q.filter(Vulnerability.source == source)
    if asset_id:
        q = q.filter(Vulnerability.asset_id == asset_id)
    if host:
        term = f"%{host}%"
        matching_ids = [
            a.id for a in
            db.query(Asset).filter(
                Asset.hostname.ilike(term) | Asset.ip_address.ilike(term)
            ).all()
        ]
        q = q.filter(Vulnerability.asset_id.in_(matching_ids))
    if search:
        term = f"%{search}%"
        q = q.filter(
            Vulnerability.title.ilike(term) |
            Vulnerability.cve_ids.ilike(term) |
            Vulnerability.description.ilike(term)
        )
    if category == "recommendation":
        q = q.filter(or_(
            Vulnerability.plugin_family.ilike("%CSPM%"),
            Vulnerability.plugin_family.ilike("%Cloud Security%"),
            Vulnerability.plugin_family.ilike("%Benchmark%"),
            Vulnerability.plugin_family.ilike("%Compliance%"),
            Vulnerability.plugin_family.ilike("%Patch Management%"),
        ))
    elif category == "vulnerability":
        q = q.filter(
            ~or_(
                Vulnerability.plugin_family.ilike("%CSPM%"),
                Vulnerability.plugin_family.ilike("%Cloud Security%"),
                Vulnerability.plugin_family.ilike("%Benchmark%"),
                Vulnerability.plugin_family.ilike("%Compliance%"),
                Vulnerability.plugin_family.ilike("%Patch Management%"),
            )
        )

    total = q.count()
    sort_col = _SORT_COLS.get(sort_by, Vulnerability.cvss_score)
    order = sort_col.asc().nulls_last() if sort_dir == "asc" else sort_col.desc().nulls_last()
    items = (
        q.order_by(order)
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    result = []
    for v in items:
        asset = db.query(Asset).filter(Asset.id == v.asset_id).first() if v.asset_id else None
        result.append({
            **VulnOut.model_validate(v).model_dump(),
            "asset_hostname": asset.hostname if asset else None,
            "asset_ip": asset.ip_address if asset else None,
        })

    return {"total": total, "page": page, "per_page": per_page, "items": result}


@router.get("/summary")
def vuln_summary(db: Session = Depends(get_db)):
    rows = (
        db.query(Vulnerability.severity, Vulnerability.status, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity, Vulnerability.status)
        .all()
    )
    return [{"severity": r[0], "status": r[1], "count": r[2]} for r in rows]


@router.get("/{vuln_id}")
def get_vuln(vuln_id: int, db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    asset = db.query(Asset).filter(Asset.id == v.asset_id).first() if v.asset_id else None
    return {
        **VulnOut.model_validate(v).model_dump(),
        "asset_hostname": asset.hostname if asset else None,
        "asset_ip": asset.ip_address if asset else None,
        "asset_criticality": asset.criticality if asset else None,
    }


@router.patch("/{vuln_id}/status")
def update_status(vuln_id: int, body: VulnStatusUpdate, db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    valid = {"open", "in_progress", "accepted", "remediated"}
    if body.status not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid}")
    v.status = body.status
    db.commit()
    return {"id": vuln_id, "status": v.status}
