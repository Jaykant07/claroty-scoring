"""Zone API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_session
from backend.models import Zone, Asset, RiskScore

router = APIRouter(prefix="/api/zones", tags=["Zones"])


@router.get("")
async def list_zones(session: AsyncSession = Depends(get_session)):
    """List all IEC 62443 zones with asset counts and avg risk."""
    stmt = select(Zone)
    result = await session.execute(stmt)
    zones = result.scalars().all()

    items = []
    for zone in zones:
        # Count assets
        ac_stmt = select(func.count()).select_from(Asset).where(Asset.zone_id == zone.id)
        ac_result = await session.execute(ac_stmt)
        count = ac_result.scalar() or 0

        # Avg risk
        avg_stmt = (
            select(func.avg(RiskScore.final_score))
            .join(Asset)
            .where(Asset.zone_id == zone.id)
        )
        avg_result = await session.execute(avg_stmt)
        avg_risk = avg_result.scalar() or 0.0

        items.append({
            "id": zone.id,
            "name": zone.name,
            "vlan_id": zone.vlan_id,
            "ip_range": zone.ip_range,
            "iec_level": zone.iec_level,
            "description": zone.description,
            "asset_count": count,
            "avg_risk": round(avg_risk, 1),
        })

    items.sort(key=lambda x: x["iec_level"])
    return items


@router.get("/{zone_id}/assets")
async def get_zone_assets(zone_id: int, session: AsyncSession = Depends(get_session)):
    """List assets in a specific zone."""
    stmt = select(Asset).where(Asset.zone_id == zone_id)
    result = await session.execute(stmt)
    assets = result.scalars().all()

    items = []
    for asset in assets:
        rs_stmt = (
            select(RiskScore)
            .where(RiskScore.asset_id == asset.id)
            .order_by(RiskScore.timestamp.desc())
            .limit(1)
        )
        rs_result = await session.execute(rs_stmt)
        latest = rs_result.scalar_one_or_none()

        items.append({
            "id": asset.id,
            "ip": asset.ip,
            "vendor": asset.vendor,
            "device_type": asset.device_type,
            "hostname": asset.hostname,
            "criticality_score": asset.criticality_score,
            "current_risk_score": latest.final_score if latest else 0.0,
        })

    items.sort(key=lambda x: x["current_risk_score"], reverse=True)
    return items
