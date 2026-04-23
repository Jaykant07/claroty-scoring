"""Discovery control endpoints."""

from __future__ import annotations

import asyncio
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_session
import backend.state as state
from backend.acquisition.snmp_poller import poll_all_assets

router = APIRouter(prefix="/api/discovery", tags=["Discovery"])

@router.post("/start")
async def start_discovery():
    """Start passive discovery and trigger background SNMP polling."""
    state.DISCOVERY_ACTIVE = True
    
    from backend.database import async_session
    from sqlalchemy import select
    from backend.models import Asset
    
    async with async_session() as session:
        stmt = select(Asset).where(Asset.ip.isnot(None))
        assets = (await session.execute(stmt)).scalars().all()
        count = len(assets)
        
    if count == 0:
        state.DISCOVERY_ACTIVE = False
        return {"status": "ok", "message": "No devices found", "count": 0}
        
    # Trigger SNMP poller in background
    asyncio.create_task(poll_all_assets())
    
    return {"status": "ok", "message": "Discovery started", "count": count}

@router.post("/stop")
async def stop_discovery():
    """Stop passive discovery."""
    state.DISCOVERY_ACTIVE = False
    return {"status": "ok", "message": "Discovery stopped"}

@router.delete("/clear")
async def clear_discovery(session: AsyncSession = Depends(get_session)):
    """Delete all assets, protocol logs (traffic_logs), and threat events."""
    await session.execute(text("DELETE FROM assets"))
    await session.execute(text("DELETE FROM traffic_logs"))
    
    # Delete from Threat_Events which is managed natively
    try:
        await session.execute(text("DELETE FROM Threat_Events"))
    except Exception:
        pass
        
    await session.commit()
    return {"status": "ok", "message": "Database reset"}
