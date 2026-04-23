"""Asset API routes — list, detail, and risk history."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database import get_session
from backend.models import (
    Asset, Zone, RiskScore, Vulnerability, AssetVulnerability,
    Anomaly, CompensatingControl, TrafficLog
)
from backend.engines.data_manager import data_manager

router = APIRouter(prefix="/api/assets", tags=["Assets"])


@router.get("")
async def list_assets(
    zone_id: int | None = None,
    sort_by: str = "risk",
    session: AsyncSession = Depends(get_session),
):
    """List all assets with their current risk scores."""
    stmt = select(Asset).options(selectinload(Asset.zone))
    if zone_id:
        stmt = stmt.where(Asset.zone_id == zone_id)

    result = await session.execute(stmt)
    assets = result.scalars().all()

    items = []
    for asset in assets:
        # Get latest risk score
        rs_stmt = (
            select(RiskScore)
            .where(RiskScore.asset_id == asset.id)
            .order_by(RiskScore.timestamp.desc())
            .limit(1)
        )
        rs_result = await session.execute(rs_stmt)
        latest_risk = rs_result.scalar_one_or_none()

        # Count vulnerabilities
        vc_stmt = select(func.count()).select_from(AssetVulnerability).where(
            AssetVulnerability.asset_id == asset.id
        )
        vc_result = await session.execute(vc_stmt)
        vuln_count = vc_result.scalar() or 0

        items.append({
            "id": asset.id,
            "ip": asset.ip,
            "mac": asset.mac,
            "hostname": asset.hostname,
            "cpe": asset.cpe,
            "vendor": asset.vendor,
            "firmware": asset.firmware,
            "serial": asset.serial,
            "device_type": asset.device_type,
            "os_type": asset.os_type,
            "os_confidence": asset.os_confidence,
            "zone_id": asset.zone_id,
            "zone_name": asset.zone.name if asset.zone else "",
            "iec_level": asset.zone.iec_level if asset.zone else None,
            "criticality_score": asset.criticality_score,
            "security_level": asset.security_level,
            "has_internet_route": asset.has_internet_route,
            "protocol_security": asset.protocol_security,
            "protocols": asset.protocols,
            "eol_status": asset.eol_status,
            "cpu_load": asset.cpu_load,
            "memory_pct": asset.memory_pct,
            "discovered_at": asset.discovered_at.isoformat() if asset.discovered_at else None,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
            "current_risk_score": latest_risk.final_score if latest_risk else 0.0,
            "vulnerability_count": vuln_count,
        })

    # Sort
    if sort_by == "risk":
        items.sort(key=lambda x: x["current_risk_score"], reverse=True)
    elif sort_by == "name":
        items.sort(key=lambda x: x["hostname"])
    elif sort_by == "ip":
        items.sort(key=lambda x: x["ip"])

    return items


@router.get("/{asset_id}")
async def get_asset_detail(
    asset_id: int,
    session: AsyncSession = Depends(get_session),
):
    """Full asset detail with risk breakdown, CVEs, anomalies."""
    stmt = select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.zone))
    result = await session.execute(stmt)
    asset = result.scalar_one_or_none()
    if not asset:
        return {"error": "Asset not found"}

    # Vulnerabilities
    v_stmt = (
        select(Vulnerability)
        .join(AssetVulnerability)
        .where(AssetVulnerability.asset_id == asset.id)
        .order_by(Vulnerability.epss_score.desc())
    )
    v_result = await session.execute(v_stmt)
    vulns = v_result.scalars().all()

    # Anomalies (active)
    a_stmt = (
        select(Anomaly)
        .where(Anomaly.asset_id == asset.id)
        .order_by(Anomaly.timestamp.desc())
        .limit(20)
    )
    a_result = await session.execute(a_stmt)
    anomalies = a_result.scalars().all()

    # Risk history (last 50)
    rs_stmt = (
        select(RiskScore)
        .where(RiskScore.asset_id == asset.id)
        .order_by(RiskScore.timestamp.desc())
        .limit(50)
    )
    rs_result = await session.execute(rs_stmt)
    risk_history = rs_result.scalars().all()

    # Compensating controls
    cc_stmt = select(CompensatingControl).where(CompensatingControl.asset_id == asset.id)
    cc_result = await session.execute(cc_stmt)
    controls = cc_result.scalars().all()

    # Re-calculate Infection cleanly for visual component mapping
    tl_stmt = select(TrafficLog.port).where(TrafficLog.dst_ip == asset.ip).distinct()
    tl_result = await session.execute(tl_stmt)
    open_ports = tl_result.scalars().all()
    
    infection_penalty = 0
    for p in open_ports:
        if p is None: continue
        service = data_manager.get_nmap_service(p)
        if p in [21, 23] or service in ["ftp", "telnet"]:
            infection_penalty += 15
        elif p == 80 or service == "http":
            infection_penalty += 10

    # Build risk breakdown from latest score
    latest = risk_history[0] if risk_history else None
    breakdown = None
    if latest:
        breakdown = {
            "vulnerability": latest.vulnerability_component,
            "accessibility": latest.accessibility_component,
            "threat": latest.threat_component,
            "infection": infection_penalty,
            "compensating": sum(c.reduction_pct for c in controls),
            "criticality": latest.impact,
            "final_score": latest.final_score,
        }

    return {
        "id": asset.id,
        "ip": asset.ip,
        "mac": asset.mac,
        "hostname": asset.hostname,
        "cpe": asset.cpe,
        "vendor": asset.vendor,
        "firmware": asset.firmware,
        "serial": asset.serial,
        "device_type": asset.device_type,
        "os_type": asset.os_type,
        "os_confidence": asset.os_confidence,
        "zone_id": asset.zone_id,
        "zone_name": asset.zone.name if asset.zone else "",
        "iec_level": asset.zone.iec_level if asset.zone else None,
        "criticality_score": asset.criticality_score,
        "security_level": asset.security_level,
        "has_internet_route": asset.has_internet_route,
        "protocol_security": asset.protocol_security,
        "protocols": asset.protocols,
        "eol_status": asset.eol_status,
        "cpu_load": asset.cpu_load,
        "memory_pct": asset.memory_pct,
        "current_risk_score": latest.final_score if latest else 0.0,
        "vulnerability_count": len(vulns),
        "risk_breakdown": breakdown,
        "vulnerabilities": [
            {
                "id": v.id, "cve_id": v.cve_id, "cvss_score": v.cvss_score,
                "epss_score": v.epss_score, "severity": v.severity,
                "description": v.description, "cwe_id": v.cwe_id, "is_kev": v.is_kev,
            }
            for v in vulns
        ],
        "anomalies": [
            {
                "id": a.id, "anomaly_type": a.anomaly_type, "threat_score": a.threat_score,
                "attack_id": a.attack_id, "attack_name": a.attack_name,
                "description": a.description, "is_active": a.is_active,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            }
            for a in anomalies
        ],
        "risk_history": [
            {
                "final_score": r.final_score, "likelihood": r.likelihood,
                "impact": r.impact, "vulnerability_component": r.vulnerability_component,
                "accessibility_component": r.accessibility_component,
                "threat_component": r.threat_component,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            }
            for r in risk_history
        ],
        "compensating_controls": [
            {"id": c.id, "control_type": c.control_type, "reduction_pct": c.reduction_pct, "description": c.description}
            for c in controls
        ],
    }


@router.get("/{asset_id}/risk-history")
async def get_risk_history(
    asset_id: int,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
):
    """Fetch historical risk scores for trending/charting."""
    stmt = (
        select(RiskScore)
        .where(RiskScore.asset_id == asset_id)
        .order_by(RiskScore.timestamp.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    scores = result.scalars().all()

    return [
        {
            "final_score": s.final_score,
            "likelihood": s.likelihood,
            "impact": s.impact,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None,
        }
        for s in reversed(scores)  # chronological order
    ]
