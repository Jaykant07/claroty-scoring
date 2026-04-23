"""Dashboard API routes — summary, heatmap, activity feed."""

from __future__ import annotations

import datetime
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_session
from backend.models import (
    Asset, Zone, RiskScore, Anomaly, Vulnerability,
    TrafficLog, SyslogEvent,
)

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_summary(session: AsyncSession = Depends(get_session)):
    """Global KPI summary for the dashboard."""
    # Total assets
    total = (await session.execute(select(func.count()).select_from(Asset))).scalar() or 0

    # Get latest risk scores per asset (subquery)
    # Simple approach: get all latest scores
    assets_stmt = select(Asset)
    assets_result = await session.execute(assets_stmt)
    assets = assets_result.scalars().all()

    risk_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    scores = []
    for asset in assets:
        rs_stmt = (
            select(RiskScore)
            .where(RiskScore.asset_id == asset.id)
            .order_by(RiskScore.timestamp.desc())
            .limit(1)
        )
        rs_result = await session.execute(rs_stmt)
        latest = rs_result.scalar_one_or_none()
        score = latest.final_score if latest else 0.0
        scores.append(score)

        if score >= 75:
            risk_buckets["critical"] += 1
        elif score >= 50:
            risk_buckets["high"] += 1
        elif score >= 25:
            risk_buckets["medium"] += 1
        else:
            risk_buckets["low"] += 1

    avg_risk = sum(scores) / len(scores) if scores else 0.0

    # Active anomalies
    anomaly_count = (
        await session.execute(
            select(func.count()).select_from(Anomaly).where(Anomaly.is_active == True)
        )
    ).scalar() or 0

    # Total vulns
    vuln_count = (
        await session.execute(select(func.count()).select_from(Vulnerability))
    ).scalar() or 0

    # Cross-zone events (last 24h)
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    cross_zone = (
        await session.execute(
            select(func.count()).select_from(TrafficLog)
            .where(TrafficLog.is_cross_zone == True, TrafficLog.timestamp >= cutoff)
        )
    ).scalar() or 0

    # EOL assets
    eol_count = (
        await session.execute(
            select(func.count()).select_from(Asset).where(Asset.eol_status == True)
        )
    ).scalar() or 0

    return {
        "total_assets": total,
        "critical_risk_count": risk_buckets["critical"],
        "high_risk_count": risk_buckets["high"],
        "medium_risk_count": risk_buckets["medium"],
        "low_risk_count": risk_buckets["low"],
        "average_risk_score": round(avg_risk, 1),
        "active_anomalies": anomaly_count,
        "total_vulnerabilities": vuln_count,
        "cross_zone_events": cross_zone,
        "eol_assets": eol_count,
    }


@router.get("/heatmap")
async def get_heatmap(session: AsyncSession = Depends(get_session)):
    """Risk heatmap data — zone × severity matrix."""
    zones_stmt = select(Zone).order_by(Zone.iec_level)
    zones_result = await session.execute(zones_stmt)
    zones = zones_result.scalars().all()

    # Build zone lookup: zone_id -> zone
    zone_map = {z.id: z for z in zones}

    # Fetch ALL assets with their latest risk score
    all_assets_stmt = select(Asset)
    all_assets = (await session.execute(all_assets_stmt)).scalars().all()

    # Group asset scores by zone
    zone_buckets: dict[str, dict] = {}  # key: zone_name, value: {iec_level, buckets}

    for asset in all_assets:
        # Get latest risk score
        rs_stmt = (
            select(RiskScore)
            .where(RiskScore.asset_id == asset.id)
            .order_by(RiskScore.timestamp.desc())
            .limit(1)
        )
        latest = (await session.execute(rs_stmt)).scalar_one_or_none()
        score = latest.final_score if latest else 0.0

        # Determine zone name
        if asset.zone_id and asset.zone_id in zone_map:
            z = zone_map[asset.zone_id]
            zone_name = z.name
            iec_level = z.iec_level
        else:
            zone_name = "Unassigned"
            iec_level = 99  # Sort to end

        if zone_name not in zone_buckets:
            zone_buckets[zone_name] = {
                "iec_level": iec_level,
                "zone_id": asset.zone_id or 0,
                "buckets": {"critical": [], "high": [], "medium": [], "low": []}
            }

        if score >= 75:
            zone_buckets[zone_name]["buckets"]["critical"].append(score)
        elif score >= 50:
            zone_buckets[zone_name]["buckets"]["high"].append(score)
        elif score >= 25:
            zone_buckets[zone_name]["buckets"]["medium"].append(score)
        else:
            zone_buckets[zone_name]["buckets"]["low"].append(score)

    # Also include zones that have no assets (so the grid stays complete)
    for z in zones:
        if z.name not in zone_buckets:
            zone_buckets[z.name] = {
                "iec_level": z.iec_level,
                "zone_id": z.id,
                "buckets": {"critical": [], "high": [], "medium": [], "low": []}
            }

    cells = []
    for zone_name, zone_data in zone_buckets.items():
        for severity, scores in zone_data["buckets"].items():
            cells.append({
                "zone_id": zone_data["zone_id"],
                "zone_name": zone_name,
                "iec_level": zone_data["iec_level"],
                "severity": severity,
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
            })

    # Sort by iec_level then zone_name
    cells.sort(key=lambda c: (c["iec_level"], c["zone_name"]))
    return cells


@router.get("/activity")
async def get_activity_feed(
    limit: int = 30,
    session: AsyncSession = Depends(get_session),
):
    """Recent activity events for the live feed."""
    events = []

    # Recent anomalies
    a_stmt = select(Anomaly).order_by(Anomaly.timestamp.desc()).limit(10)
    a_result = await session.execute(a_stmt)
    for a in a_result.scalars().all():
        # Look up asset IP
        asset_stmt = select(Asset).where(Asset.id == a.asset_id)
        asset_result = await session.execute(asset_stmt)
        asset = asset_result.scalar_one_or_none()
        events.append({
            "event_type": "anomaly",
            "message": f"[{a.attack_id}] {a.anomaly_type} detected on {asset.ip if asset else 'unknown'} — {a.attack_name}",
            "severity": "critical" if a.threat_score >= 0.7 else "warning",
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        })

    # Recent syslog events
    s_stmt = select(SyslogEvent).order_by(SyslogEvent.timestamp.desc()).limit(10)
    s_result = await session.execute(s_stmt)
    for s in s_result.scalars().all():
        sev = "critical" if s.event_type in ("auth_failure", "firewall_deny") else "info"
        events.append({
            "event_type": "syslog",
            "message": f"[{s.event_type}] {s.message[:120]}",
            "severity": sev,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None,
        })

    # Recent cross-zone traffic
    t_stmt = (
        select(TrafficLog)
        .where(TrafficLog.is_cross_zone == True)
        .order_by(TrafficLog.timestamp.desc())
        .limit(10)
    )
    t_result = await session.execute(t_stmt)
    for t in t_result.scalars().all():
        events.append({
            "event_type": "cross_zone",
            "message": f"Cross-zone {t.protocol}: {t.src_ip} → {t.dst_ip}:{t.port}",
            "severity": "warning",
            "timestamp": t.timestamp.isoformat() if t.timestamp else None,
        })

    # Sort by timestamp
    events.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return events[:limit]
