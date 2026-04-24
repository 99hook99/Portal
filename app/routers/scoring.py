from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ScoringConfig, Vulnerability, Asset

router = APIRouter()


def _get_or_create_config(db: Session) -> ScoringConfig:
    cfg = db.query(ScoringConfig).filter(ScoringConfig.id == 1).first()
    if not cfg:
        cfg = ScoringConfig(id=1)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _compute_sla_status(deadline) -> str | None:
    if not deadline:
        return None
    diff = (deadline - datetime.utcnow()).total_seconds()
    if diff < 0:         return 'Breached'
    if diff < 86400 * 2: return 'At Risk'
    return 'On Track'


def recalculate_all(db: Session) -> int:
    from app.scoring import calculate, score_factors
    cfg = _get_or_create_config(db)
    assets = {a.id: a for a in db.query(Asset).all()}
    vulns = db.query(Vulnerability).filter(Vulnerability.status != 'remediated').all()
    count = 0
    for v in vulns:
        asset = assets.get(v.asset_id)
        score, cls, deadline = calculate(v, asset, cfg)
        factors = score_factors(v, asset, cfg)
        v.priority_score  = score
        v.priority_class  = cls
        v.sla_deadline    = deadline
        v.sla_status      = _compute_sla_status(deadline)
        v.base_source     = factors.get('base_source')
        count += 1
    db.commit()
    return count


@router.get("/config")
def get_config(db: Session = Depends(get_db)):
    cfg = _get_or_create_config(db)
    return _cfg_to_dict(cfg)


@router.patch("/config")
def update_config(payload: dict, background: BackgroundTasks, db: Session = Depends(get_db)):
    cfg = _get_or_create_config(db)
    allowed = {c.name for c in ScoringConfig.__table__.columns} - {"id", "updated_at"}
    for k, v in payload.items():
        if k in allowed and v is not None:
            col_type = ScoringConfig.__table__.columns[k].type.__class__.__name__
            if col_type == 'Boolean':
                setattr(cfg, k, bool(v))
            elif isinstance(v, bool):
                setattr(cfg, k, v)
            elif isinstance(v, (int, float)):
                setattr(cfg, k, float(v) if col_type == 'Float' else int(v))
            else:
                setattr(cfg, k, v)
    cfg.updated_at = datetime.utcnow()
    db.commit()
    background.add_task(recalculate_all, db)
    return _cfg_to_dict(cfg)


@router.post("/recalculate")
def trigger_recalculate(db: Session = Depends(get_db)):
    count = recalculate_all(db)
    return {"recalculated": count}


@router.get("/prioritized")
def get_prioritized(
    page: int = 1,
    per_page: int = 25,
    severity: str = "",
    status: str = "open",
    kev: str = "",
    env: str = "",
    reach: str = "",
    search: str = "",
    db: Session = Depends(get_db),
):
    from app.scoring import calculate, score_factors
    from app.schemas import VulnOut

    cfg = _get_or_create_config(db)
    assets = {a.id: a for a in db.query(Asset).all()}

    q = db.query(Vulnerability)

    if status:
        if status == "open":
            q = q.filter(Vulnerability.status.in_(["open", "in_progress"]))
        else:
            q = q.filter(Vulnerability.status == status)

    if severity:
        q = q.filter(Vulnerability.priority_class == severity)
    else:
        q = q.filter(Vulnerability.priority_score != None)

    if kev == "1":
        q = q.filter(Vulnerability.cisa_kev_date != None)

    if search:
        like = f"%{search}%"
        q = q.filter(
            Vulnerability.title.ilike(like) |
            Vulnerability.cve_ids.ilike(like)
        )

    q = q.order_by(Vulnerability.priority_score.desc().nulls_last())
    total = q.count()
    vulns = q.offset((page - 1) * per_page).limit(per_page).all()

    # Optional in-memory filters that need asset data (env, reach)
    items = []
    for v in vulns:
        asset = assets.get(v.asset_id)

        # Lazy env/reach filters
        if env or reach:
            from app.scoring import _get_reachability, _get_env
            a_env   = _get_env(asset)   if asset else 'unknown'
            a_reach = _get_reachability(asset) if asset else 'unknown'
            if env   and a_env   != env:   continue
            if reach and a_reach != reach: continue

        if v.priority_score is None:
            score, cls, deadline = calculate(v, asset, cfg)
            v.priority_score = score
            v.priority_class = cls
            v.sla_deadline   = deadline
            v.sla_status     = _compute_sla_status(deadline)

        factors = score_factors(v, asset, cfg)
        item = VulnOut.model_validate(v).model_dump()
        item["priority_score"] = v.priority_score
        item["priority_class"] = v.priority_class
        item["sla_deadline"]   = v.sla_deadline.isoformat() if v.sla_deadline else None
        item["sla_status"]     = v.sla_status
        item["asset_hostname"] = asset.hostname    if asset else None
        item["asset_ip"]       = asset.ip_address  if asset else None
        item["asset_env"]      = asset.environment if asset else None
        item["factors"]        = factors
        items.append(item)

    db.commit()
    return {"total": total, "page": page, "per_page": per_page, "items": items}


@router.get("/priority-dashboard")
def get_priority_dashboard(db: Session = Depends(get_db)):
    from app.scoring import _get_reachability, _get_env

    assets_map = {a.id: a for a in db.query(Asset).all()}
    open_vulns = db.query(Vulnerability).filter(
        Vulnerability.status.in_(["open", "in_progress"])
    ).all()

    kev_open        = sum(1 for v in open_vulns if v.cisa_kev_date)
    high_epss_open  = sum(1 for v in open_vulns if (v.epss_score or 0) >= 0.5)
    sla_breached    = sum(1 for v in open_vulns if v.sla_status == 'Breached')
    critical_open   = sum(1 for v in open_vulns if v.priority_class == 'critical')
    high_open       = sum(1 for v in open_vulns if v.priority_class == 'high')
    total_open      = len(open_vulns)

    internet_prod_open = 0
    for v in open_vulns:
        a = assets_map.get(v.asset_id)
        if a and _get_reachability(a) == 'internet-facing' and _get_env(a) in ('prod', 'production'):
            internet_prod_open += 1

    kpis = {
        "critical_open":     critical_open,
        "high_open":         high_open,
        "kev_open":          kev_open,
        "high_epss_open":    high_epss_open,
        "internet_prod_open":internet_prod_open,
        "sla_breached":      sla_breached,
        "total_open":        total_open,
    }

    # Top 10 critical findings
    crit_vulns = sorted(
        [v for v in open_vulns if v.priority_class == 'critical'],
        key=lambda v: -(v.priority_score or 0)
    )[:10]
    section_a = [_vuln_summary(v, assets_map) for v in crit_vulns]

    # Top 8 high findings
    high_vulns = sorted(
        [v for v in open_vulns if v.priority_class == 'high'],
        key=lambda v: -(v.priority_score or 0)
    )[:8]
    section_b = [_vuln_summary(v, assets_map) for v in high_vulns]

    # Top assets by cumulative risk
    asset_risk: dict = {}
    for v in open_vulns:
        if v.asset_id is None:
            continue
        if v.asset_id not in asset_risk:
            asset_risk[v.asset_id] = {'scores': [], 'crit': 0, 'high': 0}
        ar = asset_risk[v.asset_id]
        ar['scores'].append(v.priority_score or 0)
        if v.priority_class == 'critical': ar['crit'] += 1
        elif v.priority_class == 'high':   ar['high'] += 1

    top_assets = []
    for aid, ar in sorted(asset_risk.items(),
                          key=lambda x: -sum(sorted(x[1]['scores'], reverse=True)[:10]))[:5]:
        a = assets_map.get(aid)
        top_scores = sorted(ar['scores'], reverse=True)[:10]
        top_assets.append({
            'asset_id':        aid,
            'hostname':        a.hostname    if a else None,
            'ip_address':      a.ip_address  if a else None,
            'environment':     a.environment if a else None,
            'cumulative_score':round(sum(top_scores), 2),
            'critical_count':  ar['crit'],
            'high_count':      ar['high'],
            'vuln_count':      len(ar['scores']),
        })

    # Top campaigns
    campaigns = _build_campaigns(open_vulns)
    top_campaigns = sorted(campaigns.values(), key=lambda c: -c['campaign_score'])[:5]

    return {
        "kpis":          kpis,
        "section_a":     section_a,
        "section_b":     section_b,
        "top_assets":    top_assets,
        "top_campaigns": list(top_campaigns),
    }


@router.get("/breakdown/{vuln_id}")
def get_breakdown(vuln_id: int, db: Session = Depends(get_db)):
    """Per-finding explainability breakdown. Each finding on each asset is distinct."""
    from app.scoring import build_breakdown
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Finding not found")
    asset = db.query(Asset).filter(Asset.id == v.asset_id).first() if v.asset_id else None
    cfg = _get_or_create_config(db)
    return build_breakdown(v, asset, cfg)


@router.get("/campaigns")
def get_campaigns(db: Session = Depends(get_db)):
    open_vulns = db.query(Vulnerability).filter(
        Vulnerability.status.in_(["open", "in_progress"])
    ).all()
    campaigns = _build_campaigns(open_vulns)
    return sorted(campaigns.values(), key=lambda c: -c['campaign_score'])


# ── Helpers ────────────────────────────────────────────────────────────────────

def _vuln_summary(v: "Vulnerability", assets_map: dict) -> dict:
    a = assets_map.get(v.asset_id)
    return {
        'id':            v.id,
        'title':         v.title,
        'severity':      v.severity,
        'priority_class':v.priority_class,
        'priority_score':v.priority_score,
        'cvss_score':    v.cvss_score,
        'epss_score':    v.epss_score,
        'cve_ids':       v.cve_ids,
        'cisa_kev_date': v.cisa_kev_date,
        'exploit_available': v.exploit_available,
        'patch_available':   v.patch_available,
        'sla_deadline':  v.sla_deadline.isoformat() if v.sla_deadline else None,
        'sla_status':    v.sla_status,
        'status':        v.status,
        'asset_id':      v.asset_id,
        'asset_hostname':a.hostname    if a else None,
        'asset_ip':      a.ip_address  if a else None,
        'asset_env':     a.environment if a else None,
    }


def _build_campaigns(vulns: list) -> dict:
    campaigns: dict = {}
    for v in vulns:
        if v.plugin_id:
            key   = f"plugin:{v.plugin_id}"
            label = f"{v.plugin_id}" + (f" – {v.plugin_name}" if v.plugin_name else "")
        elif v.cve_ids:
            first = v.cve_ids.split(',')[0].strip()
            key   = f"cve:{first}"
            label = first
        else:
            prefix = (v.title or '')[:40]
            key    = f"title:{prefix}"
            label  = prefix

        if key not in campaigns:
            campaigns[key] = {'key': key, 'label': label, 'scores': [],
                              'asset_ids': set(), 'crit': 0, 'high': 0}
        c = campaigns[key]
        c['scores'].append(v.priority_score or 0)
        if v.asset_id: c['asset_ids'].add(v.asset_id)
        if v.priority_class == 'critical': c['crit'] += 1
        elif v.priority_class == 'high':   c['high'] += 1

    result = {}
    for key, c in campaigns.items():
        scores = c['scores']
        if not scores: continue
        max_s  = max(scores)
        avg_s  = sum(scores) / len(scores)
        acount = len(c['asset_ids'])
        result[key] = {
            'campaign_key':   c['key'],
            'campaign_label': c['label'],
            'campaign_score': round(max_s * 0.5 + min(3.0, acount / 10.0), 3),
            'affected_assets':acount,
            'total_findings': len(scores),
            'critical_count': c['crit'],
            'high_count':     c['high'],
            'max_score':      round(max_s, 2),
            'avg_score':      round(avg_s, 2),
        }
    return result


def _cfg_to_dict(cfg: ScoringConfig) -> dict:
    return {c.name: getattr(cfg, c.name) for c in ScoringConfig.__table__.columns}
