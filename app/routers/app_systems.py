from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import SessionLocal
from app import models

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _asset_row(link, db):
    a = link.asset
    if not a:
        return None
    vuln_count = db.query(func.count(models.Vulnerability.id)).filter(
        models.Vulnerability.asset_id == a.id,
        models.Vulnerability.status != "remediated",
    ).scalar() or 0
    return {
        "link_id": link.id,
        "id": a.id,
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "asset_type": a.asset_type,
        "criticality": a.criticality,
        "risk_score": a.risk_score,
        "os": a.os,
        "status": a.status,
        "vuln_count": vuln_count,
        "environment": link.environment,
    }


@router.get("/environments")
def get_environments(db: Session = Depends(get_db)):
    envs = ["prod", "uat", "dev", "test"]
    result = {}
    for env in envs:
        links = db.query(models.AppSystemAsset).filter(
            models.AppSystemAsset.environment == env
        ).all()
        system_ids = {lnk.system_id for lnk in links}
        asset_ids  = {lnk.asset_id  for lnk in links}

        counts = {sev: 0 for sev in ("critical", "high", "medium", "low")}
        if asset_ids:
            for sev in counts:
                counts[sev] = db.query(func.count(models.Vulnerability.id)).filter(
                    models.Vulnerability.asset_id.in_(asset_ids),
                    models.Vulnerability.severity == sev,
                    models.Vulnerability.status != "remediated",
                ).scalar() or 0

        systems = []
        for sid in system_ids:
            sys = db.query(models.AppSystem).filter(models.AppSystem.id == sid).first()
            if sys:
                env_asset_count = sum(1 for lnk in links if lnk.system_id == sid)
                systems.append({"id": sys.id, "name": sys.name, "asset_count": env_asset_count})
        systems.sort(key=lambda s: s["name"])

        result[env] = {
            "system_count": len(system_ids),
            "asset_count": len(asset_ids),
            **counts,
            "systems": systems,
        }
    return result


@router.get("/asset-index")
def asset_index(db: Session = Depends(get_db)):
    """Returns {asset_id: [{id, name, environment}]} for all assigned assets."""
    sys_names = {s.id: s.name for s in db.query(models.AppSystem).all()}
    links = db.query(models.AppSystemAsset).all()
    result = {}
    for lnk in links:
        if lnk.system_id not in sys_names:
            continue
        key = str(lnk.asset_id)
        if key not in result:
            result[key] = []
        result[key].append({
            "link_id": lnk.id,
            "id": lnk.system_id,
            "name": sys_names[lnk.system_id],
            "environment": lnk.environment,
        })
    return result


@router.get("/")
def list_systems(db: Session = Depends(get_db)):
    systems = db.query(models.AppSystem).order_by(models.AppSystem.name).all()
    result = []
    for sys in systems:
        env_counts = {"prod": 0, "uat": 0, "dev": 0, "test": 0}
        unique_assets: dict[int, float] = {}

        for lnk in sys.asset_links:
            if lnk.environment in env_counts:
                env_counts[lnk.environment] += 1
            if lnk.asset_id not in unique_assets and lnk.asset:
                unique_assets[lnk.asset_id] = lnk.asset.risk_score or 0.0

        risk_score = round(sum(unique_assets.values()) / len(unique_assets), 1) if unique_assets else 0.0

        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        if unique_assets:
            for sev in vuln_counts:
                vuln_counts[sev] = db.query(func.count(models.Vulnerability.id)).filter(
                    models.Vulnerability.asset_id.in_(list(unique_assets.keys())),
                    models.Vulnerability.severity == sev,
                    models.Vulnerability.status != "remediated",
                ).scalar() or 0

        result.append({
            "id": sys.id,
            "name": sys.name,
            "description": sys.description,
            "created_at": sys.created_at,
            "asset_count": len(sys.asset_links),
            "unique_asset_count": len(unique_assets),
            "env_counts": env_counts,
            "risk_score": risk_score,
            "vuln_counts": vuln_counts,
        })
    return result


@router.post("/", status_code=201)
def create_system(body: dict, db: Session = Depends(get_db)):
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    sys = models.AppSystem(name=name, description=body.get("description"))
    db.add(sys)
    db.commit()
    db.refresh(sys)
    return {
        "id": sys.id, "name": sys.name, "description": sys.description,
        "created_at": sys.created_at, "asset_count": 0, "unique_asset_count": 0,
        "env_counts": {"prod": 0, "uat": 0, "dev": 0, "test": 0},
        "risk_score": 0.0, "vuln_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }


@router.get("/{system_id}")
def get_system(system_id: int, db: Session = Depends(get_db)):
    sys = db.query(models.AppSystem).filter(models.AppSystem.id == system_id).first()
    if not sys:
        raise HTTPException(404, "System not found")

    assets_by_env = {"prod": [], "uat": [], "dev": [], "test": []}
    for lnk in sys.asset_links:
        row = _asset_row(lnk, db)
        if row:
            env = lnk.environment if lnk.environment in assets_by_env else "prod"
            assets_by_env[env].append(row)

    env_counts = {env: len(assets) for env, assets in assets_by_env.items()}
    return {
        "id": sys.id,
        "name": sys.name,
        "description": sys.description,
        "created_at": sys.created_at,
        "asset_count": len(sys.asset_links),
        "env_counts": env_counts,
        "assets_by_env": assets_by_env,
    }


@router.delete("/{system_id}", status_code=204)
def delete_system(system_id: int, db: Session = Depends(get_db)):
    sys = db.query(models.AppSystem).filter(models.AppSystem.id == system_id).first()
    if not sys:
        raise HTTPException(404)
    db.delete(sys)
    db.commit()


@router.post("/{system_id}/assets", status_code=201)
def add_asset(system_id: int, body: dict, db: Session = Depends(get_db)):
    if not db.query(models.AppSystem).filter(models.AppSystem.id == system_id).first():
        raise HTTPException(404, "System not found")
    if not db.query(models.Asset).filter(models.Asset.id == body.get("asset_id")).first():
        raise HTTPException(404, "Asset not found")
    lnk = models.AppSystemAsset(
        system_id=system_id,
        asset_id=body["asset_id"],
        environment=body.get("environment", "prod"),
    )
    db.add(lnk)
    db.commit()
    db.refresh(lnk)
    return {"id": lnk.id, "system_id": lnk.system_id, "asset_id": lnk.asset_id, "environment": lnk.environment}


@router.delete("/{system_id}/assets/{link_id}", status_code=204)
def remove_asset(system_id: int, link_id: int, db: Session = Depends(get_db)):
    lnk = db.query(models.AppSystemAsset).filter(
        models.AppSystemAsset.id == link_id,
        models.AppSystemAsset.system_id == system_id,
    ).first()
    if not lnk:
        raise HTTPException(404)
    db.delete(lnk)
    db.commit()


@router.patch("/{system_id}/assets/{link_id}")
def update_asset_env(system_id: int, link_id: int, body: dict, db: Session = Depends(get_db)):
    lnk = db.query(models.AppSystemAsset).filter(
        models.AppSystemAsset.id == link_id,
        models.AppSystemAsset.system_id == system_id,
    ).first()
    if not lnk:
        raise HTTPException(404)
    lnk.environment = body.get("environment", lnk.environment)
    db.commit()
    return {"id": lnk.id, "environment": lnk.environment}
