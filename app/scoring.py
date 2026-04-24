"""
Risk Scoring Engine v4
======================
Base score selection:
  CVSS (primary) → VPR (fallback) → severity mapping (FALLBACK)

Threat bonuses ONLY when base_source == "CVSS":
  bonus_raw = EPSS×mul + KEV + ExploitWild + PublicPoC + NoPatch + EOL
  bonus_capped = min(intelligence_cap, bonus_raw)
  base_ext = min(10, base + bonus_capped)

When base_source == "VPR":
  base_ext = base  (no threat bonuses, no intel cap applied)

Hard floors (always active, regardless of base_source):
  Rule A: KEV → base_ext = max(kev_floor, base_ext)
  Rule B: KEV + internet-facing → base_ext = max(kev_internet_floor, base_ext)

Contextual bonuses (CVSS only — avoid double-counting with VPR):
  Rule C: exploit_wild + internet-facing → +exploit_internet_bonus
  Rule D: EPSS >= threshold + prod + reachable → +epss_prod_bonus

Contextual multipliers (always active):
  final = base_ext × ENV × REACH × CRIT × CTRL  (capped 10.0)
"""
from __future__ import annotations
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import Vulnerability, Asset, ScoringConfig

_SEVERITY_FALLBACK = {
    'critical': 9.0,
    'high':     7.5,
    'medium':   5.0,
    'low':      2.5,
    'info':     1.0,
}


# ── Field mapping helpers ──────────────────────────────────────────────────────

def _get_reachability(asset) -> str:
    if getattr(asset, 'reachability', None):
        return asset.reachability.lower()
    exp = (getattr(asset, 'internet_exposure', None) or '').lower()
    return {
        'exposed':  'internet-facing',
        'partial':  'partner',
        'internal': 'internal',
        'local':    'isolated',
    }.get(exp, 'unknown')


def _get_asset_tier(asset) -> str:
    if getattr(asset, 'asset_tier', None):
        return asset.asset_tier.lower()
    labels = (getattr(asset, 'asset_labels', None) or '').lower()
    crit   = (getattr(asset, 'criticality', None) or '').lower()
    biz    = (getattr(asset, 'business_criticality', None) or '').lower()
    if 'crown_jewel' in labels or 'tier0' in labels: return 'tier0'
    if crit == 'critical' or biz == 'critical':       return 'prod-critical'
    if crit == 'high'     or biz == 'high':           return 'important'
    if crit == 'low'      or biz == 'low':            return 'low-value'
    return 'standard'


def _get_env(asset) -> str:
    return (getattr(asset, 'environment', None) or '').lower()


def _is_eol(asset) -> bool:
    return (getattr(asset, 'eol_status', None) or '').lower() in ('eol', 'eos')


# ── Core scoring ───────────────────────────────────────────────────────────────

def _compute_score(vuln, asset, cfg) -> tuple[float, dict]:
    """Returns (final_score_0_10, breakdown_dict)."""

    # ── 1. Base score selection ────────────────────────────────────────────────
    if vuln.cvss_score is not None:
        base        = float(vuln.cvss_score)
        base_source = "CVSS"
    elif vuln.vpr_score is not None:
        base        = float(vuln.vpr_score)
        base_source = "VPR"
    else:
        sev = (getattr(vuln, 'severity', None) or '').lower()
        base        = _SEVERITY_FALLBACK.get(sev, 5.0)
        base_source = "FALLBACK"

    # ── 2. Threat bonus layer ──────────────────────────────────────────────────
    # Only applied when base comes from CVSS. VPR already encodes threat context.
    epss = vuln.epss_score or 0.0

    if base_source == "CVSS":
        bonus = 0.0
        bonus += epss * cfg.epss_multiplier
        if vuln.cisa_kev_date:                        bonus += cfg.kev_bonus
        if vuln.exploit_available:                    bonus += cfg.exploit_wild_bonus
        if getattr(vuln, 'public_poc', None):         bonus += cfg.exploit_poc_bonus
        if vuln.patch_available is False:             bonus += cfg.no_patch_bonus
        if asset is not None and _is_eol(asset):      bonus += cfg.eol_bonus

        bonus_capped = min(cfg.intelligence_cap, bonus)
        base_ext     = min(10.0, base + bonus_capped)
    else:
        # VPR or FALLBACK: carry base as-is, no bonus stacking
        bonus        = 0.0
        bonus_capped = 0.0
        base_ext     = base

    # ── 3. Hard floors (always active) ────────────────────────────────────────
    floor_applied = None

    # Rule A: KEV hard floor
    if vuln.cisa_kev_date:
        if base_ext < cfg.kev_floor:
            base_ext      = cfg.kev_floor
            floor_applied = 'kev'

    reach = env = tier = 'unknown'

    if asset is not None:
        reach = _get_reachability(asset)
        env   = _get_env(asset)
        tier  = _get_asset_tier(asset)

        # Rule B: KEV + internet-facing — always active
        kev_internet_floor = getattr(cfg, 'kev_internet_floor', 9.5)
        if vuln.cisa_kev_date and reach == 'internet-facing':
            if base_ext < kev_internet_floor:
                base_ext      = kev_internet_floor
                floor_applied = 'kev_internet'

        # ── 4. Contextual bonuses (CVSS only — no double-counting with VPR) ──

        reach_reachable = reach in ('internet-facing', 'partner', 'vpn', 'user-reachable')

        # Rule C: exploit in wild + internet-facing (CVSS only)
        if base_source == "CVSS":
            exploit_internet_bonus = getattr(cfg, 'exploit_internet_bonus', 1.5)
            if vuln.exploit_available and reach == 'internet-facing':
                base_ext = min(10.0, base_ext + exploit_internet_bonus)

        # Rule D: high EPSS + prod + reachable (CVSS only)
        if base_source == "CVSS":
            epss_prod_threshold = getattr(cfg, 'epss_prod_threshold', 0.70)
            epss_prod_bonus     = getattr(cfg, 'epss_prod_bonus', 1.0)
            if epss >= epss_prod_threshold and env in ('prod', 'production') and reach_reachable:
                base_ext = min(10.0, base_ext + epss_prod_bonus)

        base_ext = min(10.0, base_ext)

        # ── 5. Context multipliers (always active) ────────────────────────────

        env_map = {
            'prod': cfg.env2_prod, 'production': cfg.env2_prod,
            'uat':  cfg.env2_uat,  'staging':    cfg.env2_uat,
            'dev':  cfg.env2_dev,  'development':cfg.env2_dev,
            'test': cfg.env2_test, 'lab':        cfg.env2_test,
        }
        ENV = env_map.get(env, cfg.env2_unknown)

        reach_map = {
            'internet-facing': cfg.reach_internet,
            'external':        cfg.reach_internet,
            'partner':         cfg.reach_partner,
            'vpn':             cfg.reach_partner,
            'user-reachable':  cfg.reach_partner,
            'internal':        cfg.reach_internal,
            'isolated':        cfg.reach_isolated,
            'local':           cfg.reach_isolated,
        }
        REACH = reach_map.get(reach, cfg.reach_unknown)

        crit_map = {
            'tier0':        cfg.crit_tier0,
            'prod-critical':cfg.crit_prodc,
            'important':    cfg.crit_important,
            'standard':     cfg.crit_standard,
            'low-value':    cfg.crit_low,
        }
        CRIT = crit_map.get(tier, cfg.crit_unknown)

        ctrl_raw = (getattr(asset, 'compensating_controls', None) or 'none').lower()
        ctrl_map = {
            'none':       cfg.ctrl_none,
            'one':        cfg.ctrl_one_verified,
            'two_plus':   cfg.ctrl_two_verified,
            'multilayer': cfg.ctrl_multilayer,
        }
        CTRL = ctrl_map.get(ctrl_raw, cfg.ctrl_unknown)

        final = min(10.0, base_ext * ENV * REACH * CRIT * CTRL)
    else:
        ENV = REACH = CRIT = CTRL = 1.0
        final = base_ext

    final = round(max(0.0, final), 2)

    breakdown = {
        'base':          round(base, 2),
        'base_source':   base_source,
        'bonus_raw':     round(bonus, 3),
        'bonus_capped':  round(bonus_capped, 3),
        'base_ext':      round(base_ext, 2),
        'floor_applied': floor_applied,
        'ENV':           round(ENV, 3),
        'REACH':         round(REACH, 3),
        'CRIT':          round(CRIT, 3),
        'CTRL':          round(CTRL, 3),
        'final':         final,
        'reach':         reach,
        'env':           env,
        'tier':          tier,
        'eol':           asset is not None and _is_eol(asset),
        'kev':           bool(vuln.cisa_kev_date),
        'epss':          epss,
        'exploit_wild':  bool(vuln.exploit_available),
        'public_poc':    bool(getattr(vuln, 'public_poc', None)),
        'no_patch':      vuln.patch_available is False,
    }
    return final, breakdown


def _classify(score: float, cfg) -> tuple[str, timedelta]:
    if score >= cfg.threshold_critical:
        return 'critical', timedelta(hours=cfg.sla_critical_hours)
    if score >= cfg.threshold_high:
        return 'high',     timedelta(days=cfg.sla_high_days)
    if score >= cfg.threshold_medium:
        return 'medium',   timedelta(days=cfg.sla_medium_days)
    return 'low', timedelta(days=cfg.sla_low_days)


# ── Public API ─────────────────────────────────────────────────────────────────

def calculate(vuln, asset, cfg) -> tuple[float, str, datetime]:
    """Returns (priority_score, priority_class, sla_deadline)."""
    score, _ = _compute_score(vuln, asset, cfg)
    cls, delta = _classify(score, cfg)
    deadline = datetime.utcnow() + delta
    return score, cls, deadline


def score_factors(vuln, asset, cfg) -> dict:
    """Full breakdown dict for the detail drawer."""
    score, bd = _compute_score(vuln, asset, cfg)
    cls, _ = _classify(score, cfg)
    bd['score'] = score
    bd['priority_class'] = cls
    return bd


# ── Explainability breakdown ────────────────────────────────────────────────────

def build_breakdown(vuln, asset, cfg) -> dict:
    """
    Returns a structured explainability object for the UI.
    All values are derived from _compute_score — no independent scoring logic here.
    """
    score, bd = _compute_score(vuln, asset, cfg)
    cls, sla_delta = _classify(score, cfg)

    base_source = bd['base_source']
    base        = bd['base']
    bonus_capped = bd['bonus_capped']
    base_ext    = bd['base_ext']
    reach       = bd['reach']
    env         = bd['env']
    epss        = bd['epss']

    # ── Trace running total to build display steps ─────────────────────────────
    # This mirrors the scoring algorithm purely for building display bar positions.
    # The actual final values all come from _compute_score above.

    rt = base

    # After bonus
    if base_source == "CVSS":
        rt = min(10.0, rt + bonus_capped)
    rt_after_bonus = round(rt, 3)

    # After KEV floor (Rule A)
    rt_before_a = rt
    if vuln.cisa_kev_date:
        rt = max(cfg.kev_floor, rt)
    rt_after_kev_floor = round(rt, 3)
    kev_floor_applied = rt > rt_before_a

    # After KEV+internet floor (Rule B)
    rt_before_b = rt
    kev_internet_floor_val = getattr(cfg, 'kev_internet_floor', 9.5)
    if asset is not None and vuln.cisa_kev_date and reach == 'internet-facing':
        rt = max(kev_internet_floor_val, rt)
    rt_after_kev_internet = round(rt, 3)
    kev_internet_applied = rt > rt_before_b

    # After exploit+internet bonus (Rule C, CVSS only)
    rt_before_c = rt
    exploit_internet_bonus_val = getattr(cfg, 'exploit_internet_bonus', 1.5)
    exploit_internet_applied = (
        asset is not None and base_source == "CVSS"
        and bool(vuln.exploit_available) and reach == 'internet-facing'
    )
    if exploit_internet_applied:
        rt = min(10.0, rt + exploit_internet_bonus_val)
    rt_after_exploit_internet = round(rt, 3)

    # After EPSS+prod+reachable bonus (Rule D, CVSS only)
    rt_before_d = rt
    epss_prod_bonus_val     = getattr(cfg, 'epss_prod_bonus', 1.0)
    epss_prod_threshold_val = getattr(cfg, 'epss_prod_threshold', 0.70)
    reach_reachable = reach in ('internet-facing', 'partner', 'vpn', 'user-reachable')
    epss_prod_applied = (
        asset is not None and base_source == "CVSS"
        and epss >= epss_prod_threshold_val
        and env in ('prod', 'production')
        and reach_reachable
    )
    if epss_prod_applied:
        rt = min(10.0, rt + epss_prod_bonus_val)
    rt_after_epss_prod = round(rt, 3)

    # ── Build bonus sub-signal list ────────────────────────────────────────────
    bonus_signals = []
    if base_source == "CVSS":
        if epss > 0:
            bonus_signals.append(f"EPSS {epss:.2f} × {cfg.epss_multiplier} = +{epss * cfg.epss_multiplier:.2f}")
        if vuln.cisa_kev_date:
            bonus_signals.append(f"KEV +{cfg.kev_bonus}")
        if vuln.exploit_available:
            bonus_signals.append(f"Exploit-in-wild +{cfg.exploit_wild_bonus}")
        if getattr(vuln, 'public_poc', None):
            bonus_signals.append(f"Public PoC +{cfg.exploit_poc_bonus}")
        if vuln.patch_available is False:
            bonus_signals.append(f"No patch +{cfg.no_patch_bonus}")
        if asset is not None and _is_eol(asset):
            bonus_signals.append(f"EOL asset +{cfg.eol_bonus}")

    bonus_desc = "; ".join(bonus_signals) if bonus_signals else "No active threat signals"
    if base_source == "CVSS" and bd['bonus_raw'] > bonus_capped:
        bonus_desc += f" (raw {bd['bonus_raw']:.2f} → capped at {cfg.intelligence_cap})"

    # ── Breakdown steps ────────────────────────────────────────────────────────
    steps = [
        {
            "key":           "base_score",
            "label":         f"Base Score ({base_source})",
            "type":          "base",
            "value":         round(base, 2),
            "delta":         round(base, 2),
            "running_total": round(base, 2),
            "applied":       True,
            "description":   {
                "CVSS":     "CVSS score from the scanner or NVD. Full threat bonus layer is active.",
                "VPR":      "Scanner-provided VPR. Threat bonuses are automatically disabled — VPR already encodes exploit context.",
                "FALLBACK": f"No CVSS or VPR available. Score derived from severity label '{vuln.severity}'.",
            }.get(base_source, "Base score"),
        },
        {
            "key":           "threat_bonus",
            "label":         "Threat Intelligence Bonus",
            "type":          "bonus" if (base_source == "CVSS" and bonus_capped > 0) else "bonus_disabled",
            "value":         round(bonus_capped, 2),
            "delta":         round(bonus_capped, 2),
            "running_total": rt_after_bonus,
            "applied":       base_source == "CVSS" and bonus_capped > 0,
            "description":   bonus_desc if base_source == "CVSS"
                             else f"Disabled — base source is {base_source}. Threat context is already encoded.",
            "signals":       bonus_signals if base_source == "CVSS" else [],
        },
        {
            "key":           "kev_floor",
            "label":         f"KEV Hard Floor (≥ {cfg.kev_floor})",
            "type":          "floor",
            "value":         cfg.kev_floor,
            "delta":         round(rt_after_kev_floor - rt_before_a, 3),
            "running_total": rt_after_kev_floor,
            # applied = condition was met; delta tells whether score actually changed
            "applied":       bool(vuln.cisa_kev_date),
            "description":   (f"Floor raised score to {cfg.kev_floor}" if kev_floor_applied
                              else f"KEV present — score already ≥ {cfg.kev_floor}, no change needed") if vuln.cisa_kev_date
                             else "Not in CISA Known Exploited Vulnerabilities catalog",
        },
        {
            "key":           "kev_internet_floor",
            "label":         f"KEV + Internet-Facing Floor (≥ {kev_internet_floor_val})",
            "type":          "floor",
            "value":         kev_internet_floor_val,
            "delta":         round(rt_after_kev_internet - rt_before_b, 3),
            "running_total": rt_after_kev_internet,
            "applied":       bool(vuln.cisa_kev_date and asset is not None and reach == 'internet-facing'),
            "description":   (f"Floor raised score to {kev_internet_floor_val} (Critical territory)" if kev_internet_applied
                              else f"KEV + internet-facing — score already ≥ {kev_internet_floor_val}, no change needed")
                             if (vuln.cisa_kev_date and asset is not None and reach == 'internet-facing')
                             else "Not triggered — requires KEV + internet-facing asset",
        },
        {
            "key":           "exploit_internet_bonus",
            "label":         f"Exploit-in-Wild + Internet Bonus (+{exploit_internet_bonus_val})",
            "type":          "contextual",
            "value":         exploit_internet_bonus_val if exploit_internet_applied else 0.0,
            "delta":         round(rt_after_exploit_internet - rt_before_c, 3),
            "running_total": rt_after_exploit_internet,
            "applied":       exploit_internet_applied,
            "description":   f"Active exploit + internet-facing asset → +{exploit_internet_bonus_val}" if exploit_internet_applied
                             else _not_triggered_reason_exploit(vuln, reach, base_source),
        },
        {
            "key":           "epss_prod_bonus",
            "label":         f"High EPSS + Prod + Reachable Bonus (+{epss_prod_bonus_val})",
            "type":          "contextual",
            "value":         epss_prod_bonus_val if epss_prod_applied else 0.0,
            "delta":         round(rt_after_epss_prod - rt_before_d, 3),
            "running_total": rt_after_epss_prod,
            "applied":       epss_prod_applied,
            "description":   f"EPSS {epss:.2f} ≥ {epss_prod_threshold_val} + production environment + reachable → +{epss_prod_bonus_val}" if epss_prod_applied
                             else _not_triggered_reason_epss(epss, epss_prod_threshold_val, env, reach_reachable, base_source),
        },
        {
            "key":           "intermediate_score",
            "label":         "Pre-Multiplier Score",
            "type":          "result",
            "value":         base_ext,
            "delta":         None,
            "running_total": base_ext,
            "applied":       True,
            "description":   "Score after all additive adjustments and floors. Context multipliers are applied next.",
        },
    ]

    # ── Context multipliers ────────────────────────────────────────────────────
    ctrl_raw = (getattr(asset, 'compensating_controls', None) or 'none').lower() if asset else 'none'
    context = {
        "env_label":      env or 'unknown',
        "env_multiplier": bd['ENV'],
        "reach_label":    reach,
        "reach_multiplier": bd['REACH'],
        "crit_label":     bd['tier'],
        "crit_multiplier": bd['CRIT'],
        "ctrl_label":     ctrl_raw,
        "ctrl_multiplier": bd['CTRL'],
    }

    formula_view = {
        "intermediate_score": base_ext,
        "env_multiplier":     bd['ENV'],
        "reach_multiplier":   bd['REACH'],
        "crit_multiplier":    bd['CRIT'],
        "ctrl_multiplier":    bd['CTRL'],
        "final_score":        score,
    }

    # ── SLA text ───────────────────────────────────────────────────────────────
    sla_map = {
        'critical': f"{cfg.sla_critical_hours}h",
        'high':     f"{cfg.sla_high_days}d",
        'medium':   f"{cfg.sla_medium_days}d",
        'low':      f"{cfg.sla_low_days}d",
    }

    # ── Asset info ─────────────────────────────────────────────────────────────
    asset_info = {
        "hostname":    getattr(asset, 'hostname', None)    if asset else None,
        "ip":          getattr(asset, 'ip_address', None)  if asset else None,
        "fqdn":        getattr(asset, 'fqdn', None)        if asset else None,
        "environment": getattr(asset, 'environment', None) if asset else None,
        "tier":        bd['tier'],
        "reachability":reach,
    }

    return {
        "finding_id":      vuln.id,
        "asset_id":        vuln.asset_id,
        "plugin_id":       vuln.plugin_id,
        "cves":            [c.strip() for c in (vuln.cve_ids or '').split(',') if c.strip()],
        "title":           vuln.title,
        "severity":        vuln.severity,
        "asset":           asset_info,
        "base_source":     base_source,
        "base_score":      round(base, 2),
        "breakdown_steps": steps,
        "context":         context,
        "formula_view":    formula_view,
        "final_score":     score,
        "severity_class":  cls,
        "sla":             sla_map.get(cls, '–'),
        "summary_reason":  _build_summary_reason(bd, vuln, asset, score, cls),
    }


def _not_triggered_reason_exploit(vuln, reach, base_source) -> str:
    if base_source != "CVSS":
        return "Not applied — only active when base score source is CVSS"
    reasons = []
    if not vuln.exploit_available:
        reasons.append("no exploit in the wild")
    if reach != 'internet-facing':
        reasons.append(f"asset is {reach}, not internet-facing")
    return "Not triggered — " + "; ".join(reasons) if reasons else "Not triggered"


def _not_triggered_reason_epss(epss, threshold, env, reachable, base_source) -> str:
    if base_source != "CVSS":
        return "Not applied — only active when base score source is CVSS"
    reasons = []
    if epss < threshold:
        reasons.append(f"EPSS {epss:.2f} is below threshold {threshold}")
    if env not in ('prod', 'production'):
        reasons.append(f"environment is '{env}', not production")
    if not reachable:
        reasons.append("asset is not reachable")
    return "Not triggered — " + "; ".join(reasons) if reasons else "Not triggered"


def _build_summary_reason(bd, vuln, asset, score, cls) -> str:
    parts = []

    if bd['base_source'] == 'VPR':
        parts.append("scored using scanner-provided VPR")

    if vuln.cisa_kev_date:
        parts.append("listed in CISA KEV")
    if vuln.exploit_available:
        parts.append("active exploit in the wild")
    if getattr(vuln, 'public_poc', None):
        parts.append("public PoC available")

    reach = bd['reach']
    if reach == 'internet-facing':
        parts.append("internet-facing asset")
    elif reach == 'partner':
        parts.append("partner-accessible asset")

    env = bd['env']
    if env in ('prod', 'production'):
        parts.append("production environment")

    tier = bd['tier']
    if tier == 'tier0':
        parts.append("Tier 0 (crown jewel) criticality")
    elif tier == 'prod-critical':
        parts.append("production-critical asset")
    elif tier == 'important':
        parts.append("important asset")

    if bd['CTRL'] < 1.0:
        ctrl = (getattr(asset, 'compensating_controls', None) or 'none').lower() if asset else 'unknown'
        parts.append(f"score reduced by compensating controls ({ctrl})")

    if bd['floor_applied'] == 'kev_internet':
        parts.append(f"KEV+internet floor raised score to {getattr(bd, 'kev_internet_floor', 9.5) if hasattr(bd, 'kev_internet_floor') else 9.5}")

    if not parts:
        return f"Scored {score:.1f}/10 based on the base metric with neutral asset context."

    return f"This finding is {cls.title()} ({score:.1f}/10) because: {', '.join(parts)}."
