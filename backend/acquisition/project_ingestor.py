"""
Project File Ingestor — Offline OT asset discovery.

Parses offline project exports (e.g. .json or .csv from PLC engineering software)
to discover "dormant" or air-gapped assets that aren't actively speaking on the wire.
Captures high-fidelity data like firmware, hardware_model, and rack_slot.
"""

from __future__ import annotations

import json
import logging
import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.models import Asset

logger = logging.getLogger("claroty.ingestor")


async def ingest_project_json(session: AsyncSession, filepath: str) -> dict:
    """Read a JSON export of an OT project and merge into the Asset Master."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load project file {filepath}: {e}")
        return {"status": "error", "message": str(e)}

    devices = data.get("devices", [])
    added = 0
    updated = 0

    for dev in devices:
        ip = dev.get("ip")
        if not ip:
            continue

        stmt = select(Asset).where(Asset.ip == ip)
        result = await session.execute(stmt)
        asset = result.scalar_one_or_none()

        if asset:
            # Update existing with high-fidelity project data
            asset.firmware = dev.get("firmware", asset.firmware)
            asset.hardware_model = dev.get("hardware_model", asset.hardware_model)
            asset.rack_slot = dev.get("rack_slot", asset.rack_slot)
            asset.vendor = dev.get("vendor", asset.vendor)
            updated += 1
        else:
            # Insert dormant asset
            new_asset = Asset(
                ip=ip,
                mac=dev.get("mac", ""),
                hostname=dev.get("hostname", ""),
                vendor=dev.get("vendor", ""),
                hardware_model=dev.get("hardware_model", ""),
                firmware=dev.get("firmware", ""),
                rack_slot=dev.get("rack_slot", ""),
                device_type=dev.get("device_type", "unknown"),
                discovered_at=datetime.datetime.utcnow(),
                last_seen=None, # Dormant
            )
            session.add(new_asset)
            added += 1

    await session.commit()
    logger.info(f"Project Ingestor: {added} new assets added, {updated} updated from {filepath}")
    return {"status": "success", "added": added, "updated": updated}
