import json
import asyncio
import httpx
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query, HTTPException
from sqlalchemy import asc, desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CVERecord, NVDEntry, KEVEntry
from app.schemas import CVEOut

router = APIRouter()

NVD_API_KEY = "379AE5A9-9401-F111-8367-0EBF96DE670D"
NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_nvd_sync_status: dict = {"running": False, "last_synced": None, "last_count": 0, "error": None}
_kev_sync_status: dict = {"running": False, "last_synced": None, "last_count": 0, "error": None}


# ── Local CVE records ──────────────────────────────────────────────────────────

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
        q = q.filter(CVERecord.cve_id.ilike(term) | CVERecord.description.ilike(term))
    total = q.count()
    items = q.order_by(CVERecord.cvss_v3_score.desc().nulls_last()).offset((page - 1) * per_page).limit(per_page).all()
    return {"total": total, "page": page, "per_page": per_page, "items": items}


# ── NVD ────────────────────────────────────────────────────────────────────────

@router.get("/nvd/status")
def nvd_status():
    return _nvd_sync_status


@router.post("/nvd/sync")
async def sync_nvd(
    background_tasks: BackgroundTasks,
    days: int = Query(30, ge=1, le=365),
):
    if _nvd_sync_status["running"]:
        raise HTTPException(status_code=409, detail="Sync already running")
    background_tasks.add_task(_do_nvd_sync, days)
    return {"status": "started"}


@router.get("/nvd")
def list_nvd(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=200),
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = Query("published"),
    sort_dir: str = Query("desc"),
    db: Session = Depends(get_db),
):
    q = db.query(NVDEntry)
    if severity:
        q = q.filter(NVDEntry.cvss_v3_severity == severity.lower())
    if search:
        term = f"%{search}%"
        q = q.filter(NVDEntry.cve_id.ilike(term) | NVDEntry.description.ilike(term))
    total = q.count()

    _COLS = {
        "published":     NVDEntry.published,
        "last_modified": NVDEntry.last_modified,
        "cve_id":        NVDEntry.cve_id,
        "cvss_v3_score": NVDEntry.cvss_v3_score,
    }
    col = _COLS.get(sort_by, NVDEntry.published)
    order = desc(col).nulls_last() if sort_dir == "desc" else asc(col).nulls_last()
    items = q.order_by(order).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "sync_status": _nvd_sync_status,
        "items": [_nvd_row(n) for n in items],
    }


@router.get("/nvd/{cve_id}")
def get_nvd_entry(cve_id: str, db: Session = Depends(get_db)):
    n = db.query(NVDEntry).filter(NVDEntry.cve_id == cve_id.upper()).first()
    if not n:
        raise HTTPException(status_code=404, detail="Not found in NVD cache")
    return _nvd_row(n, full=True)


# ── KEV ────────────────────────────────────────────────────────────────────────

@router.get("/kev/status")
def kev_status():
    return _kev_sync_status


@router.post("/kev/sync")
async def sync_kev(background_tasks: BackgroundTasks):
    if _kev_sync_status["running"]:
        raise HTTPException(status_code=409, detail="Sync already running")
    background_tasks.add_task(_do_kev_sync)
    return {"status": "started"}


@router.get("/kev")
def list_kev(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=200),
    search: Optional[str] = None,
    sort_by: str = Query("date_added"),
    sort_dir: str = Query("desc"),
    db: Session = Depends(get_db),
):
    q = db.query(KEVEntry)
    if search:
        term = f"%{search}%"
        q = q.filter(
            KEVEntry.cve_id.ilike(term)
            | KEVEntry.vendor_project.ilike(term)
            | KEVEntry.product.ilike(term)
            | KEVEntry.vulnerability_name.ilike(term)
        )
    total = q.count()

    _COLS = {
        "date_added":    KEVEntry.date_added,
        "due_date":      KEVEntry.due_date,
        "cve_id":        KEVEntry.cve_id,
        "vendor_project":KEVEntry.vendor_project,
    }
    col = _COLS.get(sort_by, KEVEntry.date_added)
    order = desc(col).nulls_last() if sort_dir == "desc" else asc(col).nulls_last()
    items = q.order_by(order).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "sync_status": _kev_sync_status,
        "items": [_kev_row(k) for k in items],
    }


@router.get("/kev/{cve_id}")
def get_kev_entry(cve_id: str, db: Session = Depends(get_db)):
    k = db.query(KEVEntry).filter(KEVEntry.cve_id == cve_id.upper()).first()
    if not k:
        raise HTTPException(status_code=404, detail="Not found in KEV")
    return _kev_row(k, full=True)


# ── Local CVE detail (must be last — catches /{cve_id}) ───────────────────────

@router.get("/{cve_id}", response_model=CVEOut)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    c = db.query(CVERecord).filter(CVERecord.cve_id == cve_id.upper()).first()
    if not c:
        raise HTTPException(status_code=404, detail="CVE not found")
    return c


# ── Serialisers ────────────────────────────────────────────────────────────────

def _nvd_row(n: NVDEntry, full: bool = False) -> dict:
    d = {
        "id":              n.id,
        "cve_id":          n.cve_id,
        "description":     n.description,
        "published":       n.published.isoformat() if n.published else None,
        "last_modified":   n.last_modified.isoformat() if n.last_modified else None,
        "cvss_v3_score":   n.cvss_v3_score,
        "cvss_v3_vector":  n.cvss_v3_vector,
        "cvss_v3_severity":n.cvss_v3_severity,
        "cvss_v2_score":   n.cvss_v2_score,
        "cvss_v2_severity":n.cvss_v2_severity,
        "cwe":             n.cwe,
        "last_fetched":    n.last_fetched.isoformat() if n.last_fetched else None,
    }
    if full:
        d["references"]        = json.loads(n.references or "[]")
        d["affected_products"] = json.loads(n.affected_products or "[]")
    return d


def _kev_row(k: KEVEntry, full: bool = False) -> dict:
    return {
        "id":                k.id,
        "cve_id":            k.cve_id,
        "vendor_project":    k.vendor_project,
        "product":           k.product,
        "vulnerability_name":k.vulnerability_name,
        "date_added":        k.date_added.isoformat() if k.date_added else None,
        "short_description": k.short_description,
        "required_action":   k.required_action if full else None,
        "due_date":          k.due_date.isoformat() if k.due_date else None,
        "known_ransomware":  k.known_ransomware,
        "notes":             k.notes if full else None,
        "last_fetched":      k.last_fetched.isoformat() if k.last_fetched else None,
    }


# ── Background sync tasks ─────────────────────────────────────────────────────

async def _do_nvd_sync(days: int) -> None:
    from app.database import SessionLocal
    _nvd_sync_status.update(running=True, error=None)
    db = SessionLocal()
    try:
        now   = datetime.utcnow()
        start = now - timedelta(days=days)
        start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str   = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        headers   = {"apiKey": NVD_API_KEY}
        total_synced = 0
        start_idx    = 0
        per_page     = 2000

        async with httpx.AsyncClient(timeout=120) as client:
            while True:
                params = {
                    "lastModStartDate": start_str,
                    "lastModEndDate":   end_str,
                    "startIndex":       start_idx,
                    "resultsPerPage":   per_page,
                }
                resp = await client.get(NVD_BASE, headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json()

                vulns = data.get("vulnerabilities", [])
                for item in vulns:
                    _upsert_nvd(db, item.get("cve", {}))
                    total_synced += 1
                db.commit()

                total_results = data.get("totalResults", 0)
                start_idx += per_page
                if not vulns or start_idx >= total_results:
                    break
                await asyncio.sleep(0.7)   # NVD rate-limit with API key: ~50 req/30 s

        _nvd_sync_status.update(last_synced=datetime.utcnow().isoformat(), last_count=total_synced)
    except Exception as exc:
        _nvd_sync_status["error"] = str(exc)
    finally:
        _nvd_sync_status["running"] = False
        db.close()


async def _do_kev_sync() -> None:
    from app.database import SessionLocal
    _kev_sync_status.update(running=True, error=None)
    db = SessionLocal()
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        count = 0
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cveID", "")
            if not cve_id:
                continue
            fields = dict(
                vendor_project    = item.get("vendorProject", ""),
                product           = item.get("product", ""),
                vulnerability_name= item.get("vulnerabilityName", ""),
                date_added        = _parse_date(item.get("dateAdded", "")),
                short_description = item.get("shortDescription", ""),
                required_action   = item.get("requiredAction", ""),
                due_date          = _parse_date(item.get("dueDate", "")),
                known_ransomware  = item.get("knownRansomwareCampaignUse", "Unknown"),
                notes             = item.get("notes", ""),
                last_fetched      = datetime.utcnow(),
            )
            existing = db.query(KEVEntry).filter(KEVEntry.cve_id == cve_id).first()
            if existing:
                for k, v in fields.items():
                    setattr(existing, k, v)
            else:
                db.add(KEVEntry(cve_id=cve_id, **fields))
            count += 1

        db.commit()
        _kev_sync_status.update(last_synced=datetime.utcnow().isoformat(), last_count=count)
    except Exception as exc:
        _kev_sync_status["error"] = str(exc)
    finally:
        _kev_sync_status["running"] = False
        db.close()


# ── NVD upsert helper ─────────────────────────────────────────────────────────

def _upsert_nvd(db, cve: dict) -> None:
    cve_id = cve.get("id", "")
    if not cve_id:
        return

    # English description
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )

    # CVSS v3 (prefer v3.1, fall back to v3.0)
    cvss_v3_score = cvss_v3_vector = cvss_v3_severity = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in cve.get("metrics", {}).get(key, []):
            d = m.get("cvssData", {})
            cvss_v3_score    = d.get("baseScore")
            cvss_v3_vector   = d.get("vectorString")
            cvss_v3_severity = d.get("baseSeverity", "").lower() or None
            break
        if cvss_v3_score is not None:
            break

    # CVSS v2
    cvss_v2_score = cvss_v2_severity = None
    for m in cve.get("metrics", {}).get("cvssMetricV2", []):
        d = m.get("cvssData", {})
        cvss_v2_score    = d.get("baseScore")
        cvss_v2_severity = m.get("baseSeverity", "").lower() or None
        break

    # CWE
    cwes: list[str] = []
    for w in cve.get("weaknesses", []):
        for wd in w.get("description", []):
            if wd.get("lang") == "en" and wd["value"] not in cwes:
                cwes.append(wd["value"])
    cwe = ", ".join(cwes[:3]) or None

    refs     = [r["url"] for r in cve.get("references", []) if r.get("url")]
    products: list[str] = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("criteria"):
                    products.append(cpe["criteria"])

    published     = _parse_nvd_date(cve.get("published", ""))
    last_modified = _parse_nvd_date(cve.get("lastModified", ""))

    fields = dict(
        description      = desc,
        published        = published,
        last_modified    = last_modified,
        cvss_v3_score    = cvss_v3_score,
        cvss_v3_vector   = cvss_v3_vector,
        cvss_v3_severity = cvss_v3_severity,
        cvss_v2_score    = cvss_v2_score,
        cvss_v2_severity = cvss_v2_severity,
        cwe              = cwe,
        references       = json.dumps(refs[:20]),
        affected_products= json.dumps(products[:30]),
        last_fetched     = datetime.utcnow(),
    )
    existing = db.query(NVDEntry).filter(NVDEntry.cve_id == cve_id).first()
    if existing:
        for k, v in fields.items():
            setattr(existing, k, v)
    else:
        db.add(NVDEntry(cve_id=cve_id, **fields))


def _parse_nvd_date(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s[:19])
    except Exception:
        return None


def _parse_date(s: str) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s[:len(fmt)], fmt)
        except Exception:
            pass
    return None
