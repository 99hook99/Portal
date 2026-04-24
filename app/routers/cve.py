from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CVERecord
from app.schemas import CVEOut

router = APIRouter()


@router.get("/")
def list_cves(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=200),
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(CVERecord)
    if severity:
        q = q.filter(CVERecord.severity == severity)
    if search:
        term = f"%{search}%"
        q = q.filter(
            CVERecord.cve_id.ilike(term) | CVERecord.description.ilike(term)
        )
    total = q.count()
    items = q.order_by(CVERecord.cvss_v3_score.desc().nulls_last()).offset((page - 1) * per_page).limit(per_page).all()
    return {"total": total, "page": page, "per_page": per_page, "items": items}


@router.get("/{cve_id}", response_model=CVEOut)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    c = db.query(CVERecord).filter(CVERecord.cve_id == cve_id.upper()).first()
    if not c:
        raise HTTPException(status_code=404, detail="CVE not found")
    return c
