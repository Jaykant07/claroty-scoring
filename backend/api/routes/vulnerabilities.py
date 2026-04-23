"""Vulnerability and Anomaly API routes."""

from __future__ import annotations

import os
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database import get_session
from backend.models import Vulnerability, Anomaly, Asset

router = APIRouter(tags=["Vulnerabilities & Anomalies"])

@router.get("/api/intelligence-status")
async def get_intelligence_status():
    """Return modification timestamps of threat intelligence files."""
    base_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "data")
    epss_path = os.path.join(base_path, "epss_cache.json")
    cisa_path = os.path.join(base_path, "cisa_kev.json")
    
    import datetime
    
    def get_time(path):
        if os.path.exists(path):
            return datetime.datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
        return None

    return {
        "epss_last_updated": get_time(epss_path),
        "cisa_last_updated": get_time(cisa_path)
    }


@router.get("/api/vulnerabilities")
async def list_vulnerabilities(
    severity: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    """List all tracked CVEs with CVSS + EPSS scores."""
    stmt = select(Vulnerability).order_by(Vulnerability.cvss_score.desc())
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity.upper())
    result = await session.execute(stmt)
    vulns = result.scalars().all()

    return [
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "epss_score": v.epss_score,
            "severity": v.severity,
            "description": v.description,
            "cwe_id": v.cwe_id,
            "is_kev": v.is_kev,
            "published_at": v.published_at.isoformat() if v.published_at else None,
        }
        for v in vulns
    ]


@router.get("/api/anomalies")
async def list_anomalies(
    active_only: bool = True,
    anomaly_type: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    """List anomalies with MITRE ATT&CK mappings."""
    # Action 4: The API 'Ping'
    print("[API] Anomaly data requested by UI")
    
    # Objective 3 requirement: Read exactly from Threat_Events
    from sqlalchemy import text
    threat_items = []
    try:
        t_result = await session.execute(text("SELECT id, timestamp, source_ip, mitre_id, tactic, severity FROM Threat_Events ORDER BY timestamp DESC"))
        for t in t_result.fetchall():
            threat_items.append({
                "id": f"te_{t.id}",
                "asset_id": 0,
                "asset_ip": t.source_ip,
                "asset_vendor": "Threat Event Match",
                "device_type": "Network",
                "anomaly_type": "active_threat",
                "threat_score": float(t.severity) / 100.0,
                "attack_id": t.mitre_id,
                "attack_name": "Active Threat Profile",
                "mitre_tactic": t.tactic,
                "description": f"Persisted Threat from {t.source_ip} via {t.mitre_id}",
                "is_active": True,
                "timestamp": str(t.timestamp)
            })
    except Exception:
        pass

    stmt = select(Anomaly).order_by(Anomaly.timestamp.desc())
    if active_only:
        stmt = stmt.where(Anomaly.is_active == True)
    if anomaly_type:
        stmt = stmt.where(Anomaly.anomaly_type == anomaly_type)
    stmt = stmt.limit(100)

    result = await session.execute(stmt)
    anomalies = result.scalars().all()

    items = []
    for a in anomalies:
        # Look up asset info
        asset_stmt = select(Asset).where(Asset.id == a.asset_id)
        asset_result = await session.execute(asset_stmt)
        asset = asset_result.scalar_one_or_none()

        items.append({
            "id": a.id,
            "asset_id": a.asset_id,
            "asset_ip": asset.ip if asset else "",
            "asset_vendor": asset.vendor if asset else "",
            "device_type": asset.device_type if asset else "",
            "anomaly_type": a.anomaly_type,
            "threat_score": a.threat_score,
            "attack_id": a.attack_id,
            "attack_name": a.attack_name,
            "mitre_tactic": a.mitre_tactic,
            "mitigation": getattr(a, 'mitigation', ""),
            "description": a.description,
            "is_active": a.is_active,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        })

    return threat_items + items


@router.get("/api/traffic/cross-zone")
async def list_cross_zone_traffic(
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
):
    """List recent cross-zone traffic events."""
    from backend.models import TrafficLog

    stmt = (
        select(TrafficLog)
        .where(TrafficLog.is_cross_zone == True)
        .order_by(TrafficLog.timestamp.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    logs = result.scalars().all()

    return [
        {
            "id": t.id,
            "src_ip": t.src_ip,
            "dst_ip": t.dst_ip,
            "protocol": t.protocol,
            "port": t.port,
            "is_encrypted": t.is_encrypted,
            "timestamp": t.timestamp.isoformat() if t.timestamp else None,
        }
        for t in logs
    ]


@router.get("/api/syslog/events")
async def list_syslog_events(
    event_type: str | None = None,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
):
    """List recent syslog events."""
    from backend.models import SyslogEvent

    stmt = select(SyslogEvent).order_by(SyslogEvent.timestamp.desc())
    if event_type:
        stmt = stmt.where(SyslogEvent.event_type == event_type)
    stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    events = result.scalars().all()

    return [
        {
            "id": s.id,
            "source_ip": s.source_ip,
            "event_type": s.event_type,
            "severity": s.severity,
            "message": s.message,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None,
        }
        for s in events
    ]
