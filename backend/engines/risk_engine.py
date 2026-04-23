"""
Risk Scoring Engine — the core L × I → R calculation loop.

Implements the three-tier scoring architecture:

  Likelihood  L = (Vulnerability × Accessibility × Threat) − Compensating Controls
  Impact      I = Criticality × Network_Position
  Final       R = Normalize(L × I, 0–100)

Runs every 60 seconds (configurable) against every asset in the Asset Master.
"""

from __future__ import annotations

import datetime
import logging
import math

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.config import settings
from backend.models import (
    Asset, Zone, Vulnerability, AssetVulnerability,
    RiskScore, Anomaly, CompensatingControl, TrafficLog,
)

logger = logging.getLogger("claroty.risk")


# ── Sub-score calculators ──────────────────────────────────────────────────────

async def _calc_vulnerability_score(session: AsyncSession, asset: Asset) -> float:
    """
    Vulnerability / Hygiene score (0.0–1.0).
    Composite of max CVSS × max EPSS, boosted for KEV presence.
    """
    stmt = (
        select(Vulnerability)
        .join(AssetVulnerability)
        .where(AssetVulnerability.asset_id == asset.id)
    )
    result = await session.execute(stmt)
    vulns = result.scalars().all()

    # Hygiene Penalty: Open Ports -> nmap-services -> Hygiene Penalty
    port_stmt = select(TrafficLog.port).where(TrafficLog.dst_ip == asset.ip).distinct()
    open_ports = (await session.execute(port_stmt)).scalars().all()
    hygiene_penalty = sum(0.15 for p in open_ports if p in {21, 23, 80, 161})

    if not vulns:
        # No known vulns — still penalise insecure protocols or EOL
        base = 0.0
        if asset.eol_status:
            base += 0.3
        if asset.protocol_security == "insecure":
            base += 0.2
        return min(base + hygiene_penalty, 1.0)

    max_cvss = max(v.cvss_score for v in vulns) / 10.0        # normalise to 0-1
    max_epss = max(v.epss_score for v in vulns)
    has_kev  = any(v.is_kev for v in vulns)

    # Predictive Formula: CVSS * (1 + EPSS_Score) normalized
    base_cvss = max_cvss / 10.0
    vuln_score = min(base_cvss * (1.0 + max_epss), 1.0)

    # KEV boost
    if has_kev:
        vuln_score = max(vuln_score, 0.9)

    # EOL penalty
    if asset.eol_status:
        vuln_score = min(vuln_score + 0.15, 1.0)

    # Insecure protocol penalty
    if asset.protocol_security == "insecure":
        vuln_score = min(vuln_score + 0.1, 1.0)

    # Apply Hygiene Penalty from Open Ports
    vuln_score = min(vuln_score + hygiene_penalty, 1.0)

    return round(min(vuln_score, 1.0), 4)


async def _calc_accessibility_score(session: AsyncSession, asset: Asset) -> float:
    """
    Accessibility score (0.0–1.0) based on interface conduits and routes.
    """
    if asset.has_internet_route:
        return 1.0

    # Query Conduits crossing zones where asset is involved
    if asset.zone_id:
        from backend.models import Conduit
        stmt = select(func.count()).select_from(Conduit).where(
            (Conduit.source_zone_id == asset.zone_id) | (Conduit.dest_zone_id == asset.zone_id)
        )
        conduit_count = (await session.execute(stmt)).scalar() or 0
        if conduit_count > 3:
            return 0.8
        elif conduit_count > 0:
            return 0.5
    
    return 0.2


async def _calc_infection_score(session: AsyncSession, asset: Asset) -> float:
    """
    Infection score (0.0–1.0) based on lateral movement capabilities (ports 445, 22).
    """
    stmt = select(func.count()).select_from(TrafficLog).where(
        (TrafficLog.src_ip == asset.ip) | (TrafficLog.dst_ip == asset.ip),
        TrafficLog.port.in_([22, 445])
    )
    result = await session.execute(stmt)
    lateral_port_hits = result.scalar() or 0
    if lateral_port_hits > 5:
        return 1.0
    elif lateral_port_hits > 0:
        return 0.7
    return 0.1


async def _calc_threat_score(session: AsyncSession, asset: Asset) -> float:
    """
    Threat score (0.0–1.0) from active rule-engine anomalies.
    """
    stmt = (
        select(Anomaly)
        .where(Anomaly.asset_id == asset.id, Anomaly.is_active == True)
        .order_by(Anomaly.threat_score.desc())
    )
    result = await session.execute(stmt)
    anomalies = result.scalars().all()

    if not anomalies:
        return 0.05  # Ambient baseline

    max_threat = max(a.threat_score for a in anomalies)
    count_boost = min(len(anomalies) * 0.1, 0.3)
    return round(min(max_threat + count_boost, 1.0), 4)


async def _calc_compensating_reduction(session: AsyncSession, asset: Asset) -> float:
    """Compensating Controls reduction factor (0.0–1.0)."""
    stmt = select(CompensatingControl).where(CompensatingControl.asset_id == asset.id)
    controls = (await session.execute(stmt)).scalars().all()
    if not controls:
        return 0.0
    return min(sum(c.reduction_pct for c in controls), 0.50)


def _calc_criticality_weight(asset: Asset) -> float:
    """Map Vendor/Device Type to Purdue Level, then scale to criticality weight [0.1-1.0]"""
    from backend.engines.data_manager import data_manager
    
    purdue_level = data_manager.get_purdue_level(asset.vendor, asset.device_type)
    asset.purdue_level = purdue_level
    
    # Automatically assign Criticality = 10 for Level 1 and Criticality = 3 for Level 4
    if purdue_level == 1:
        w = 10.0
    elif purdue_level == 4:
        w = 3.0
    else:
        # Purdue Level -> Base Weight
        level_weights = {0: 10.0, 2: 7.5, 3: 5.0}
        w = level_weights.get(purdue_level, 5.0)

    # Device Type Overrides (Fine-tuning within Purdue)
    type_boosts = {
        "plc": 1.0,
        "safety_plc": 2.0,
        "switch": -0.5,
        "iot_gateway": -1.0,
    }
    w += type_boosts.get(asset.device_type.lower(), 0.0)
    w = max(1.0, min(10.0, w))

    return w / 10.0


def _calc_impact(asset: Asset, zone: Zone | None) -> float:
    """Impact: Criticality × Network Position"""
    crit = _calc_criticality_weight(asset)
    net_weight = zone.network_position_weight if zone else 0.4
    return round(crit * net_weight, 4)


def _normalize_score(raw: float) -> float:
    """Normalize Likelihood * Impact to 0-100 score."""
    scaled = raw * 100
    return round(max(0.0, min(100.0, scaled)), 1)


# ── Main risk calculation loop ────────────────────────────────────────────────

async def calculate_all_risk_scores(session: AsyncSession) -> list[dict]:
    """
    Recalculate risk scores for every asset.
    Returns list of score summaries for the API / dashboard.
    """
    # Load all assets with their zones
    stmt = select(Asset).options(selectinload(Asset.zone))
    result = await session.execute(stmt)
    assets = result.scalars().all()

    scores = []
    now = datetime.datetime.utcnow()

    for asset in assets:
        vuln  = await _calc_vulnerability_score(session, asset)
        acc   = await _calc_accessibility_score(session, asset)
        infec = await _calc_infection_score(session, asset)
        threat = await _calc_threat_score(session, asset)
        comp  = await _calc_compensating_reduction(session, asset)

        # ── Likelihood ── (5-parameter alg: V * A * I * T)
        L_raw = vuln * acc * infec * threat
        L = max(0.0, L_raw * (1.0 - comp))

        # ── Impact ── (Criticality * NetPos)
        I_score = _calc_impact(asset, asset.zone)

        # ── Final Score ──
        R = _normalize_score(L * I_score)

        # Floors
        if vuln > 0.8:
            R = max(R, 25.0)
        if asset.eol_status:
            R = max(R, 15.0)

        # Store the score
        score_record = RiskScore(
            asset_id=asset.id,
            likelihood=round(L, 4),
            impact=round(I_score, 4),
            vulnerability_component=vuln,
            accessibility_component=acc,
            threat_component=threat,
            final_score=R,
            timestamp=now,
        )
        session.add(score_record)

        scores.append({
            "asset_id": asset.id,
            "ip": asset.ip,
            "likelihood": round(L, 4),
            "impact": round(I_score, 4),
            "vulnerability": vuln,
            "accessibility": acc,
            "infection": infec,
            "threat": threat,
            "compensating": comp,
            "final_score": R,
        })

    await session.commit()
    logger.info("Risk scores recalculated for %d assets", len(assets))
    return scores
