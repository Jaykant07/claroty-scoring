"""
Semi-Active SNMPv3 Poller — OT-Safe hardware / firmware metadata collection.

Polls known assets using SNMPv3 (authPriv) for:
  - sysDescr, sysName  → firmware / OS version
  - hrProcessorLoad    → CPU utilisation
  - hrStorageUsed/Size → Memory utilisation
  - ifOperStatus       → Port status
  - entPhysicalSerialNum → Hardware serial

Rate-limited to 1 req/second per device to avoid PLC disruption.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import random

from backend.config import settings

logger = logging.getLogger("claroty.snmp")

# ── OID constants ──────────────────────────────────────────────────────────────

OID_SYS_DESCR  = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME   = "1.3.6.1.2.1.1.5.0"
OID_CPU_LOAD   = "1.3.6.1.2.1.25.3.3.1.2"      # hrProcessorLoad (table)
OID_IF_STATUS  = "1.3.6.1.2.1.2.2.1.8"          # ifOperStatus (table)
OID_SERIAL     = "1.3.6.1.2.1.47.1.1.1.1.11.1"  # entPhysicalSerialNum
OID_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"     # hrStorageUsed


async def poll_device_snmpv3(ip: str) -> dict | None:
    """
    Poll a single device via SNMPv3.
    Returns dict with firmware, hostname, cpu_load, serial or None on failure.
    """
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            get_cmd, SnmpEngine, UsmUserData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except ImportError:
        logger.debug("pysnmp not available – skipping SNMP poll for %s", ip)
        return None

    user_data = UsmUserData(
        settings.SNMP_USER,
        authKey=settings.SNMP_AUTH_KEY,
        privKey=settings.SNMP_PRIV_KEY,
    )

    result = {}
    oids_to_fetch = [
        ("firmware", OID_SYS_DESCR),
        ("hostname", OID_SYS_NAME),
        ("serial",   OID_SERIAL),
        ("memory_pct", OID_STORAGE_USED),
    ]

    for label, oid in oids_to_fetch:
        try:
            err_indication, err_status, _, var_binds = await get_cmd(
                SnmpEngine(),
                user_data,
                await UdpTransportTarget.create((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            if not err_indication and not err_status and var_binds:
                result[label] = str(var_binds[0][1])
        except Exception as exc:
            logger.debug("SNMP %s fetch %s failed: %s", ip, label, exc)

        # OT-Safe: 1 second between requests
        await asyncio.sleep(1.0)

    return result if result else None


# ── Simulation fallback ───────────────────────────────────────────────────────

_SIM_FIRMWARE = {
    "Siemens":    "SIMATIC S7-1500 CPU 1518 V3.0",
    "Rockwell":   "ControlLogix L8 v32.011",
    "Schneider":  "Modicon M340 BMX P34 v3.40",
    "Honeywell":  "Safety Manager SC v10.3",
    "ABB":        "AC500 PM573 v2.8.0",
    "Cisco":      "Cisco IOS 15.2(7)E4",
    "Dell":       "Windows 10 Enterprise LTSC 21H2",
    "HP":         "Windows Server 2019 Datacenter",
    "Lenovo":     "Windows 11 Pro 23H2",
    "Wonderware": "InTouch HMI 2020 R2 SP1",
    "Unisoc":     "Unisoc T610 IoT Gateway FW 1.4.2",
}


def simulate_snmp_poll(device: dict) -> dict:
    """Return synthetic SNMP data for a simulated device."""
    vendor = device.get("vendor", "Unknown")
    return {
        "firmware":  _SIM_FIRMWARE.get(vendor, f"{vendor} Generic FW 1.0"),
        "hostname":  f"{device.get('device_type', 'unknown')}-{device.get('ip', '0.0.0.0').split('.')[-1]}",
        "serial":    f"SN-{vendor[:3].upper()}-{random.randint(100000, 999999)}",
        "cpu_load":  round(random.uniform(5, 85), 1),
        "memory_pct": round(random.uniform(20, 90), 1),
    }

async def poll_all_assets():
    from sqlalchemy import select
    from backend.models import Asset
    from backend.database import async_session
    
    logger.info("📡 [DISCOVERY] Initiating semi-active SNMPv3 asset discovery cycle...")
    
    async with async_session() as session:
        stmt = select(Asset).where(Asset.ip.isnot(None))
        assets = (await session.execute(stmt)).scalars().all()
        
        total = len(assets)
        logger.info(f"📡 [DISCOVERY] Found {total} assets to poll in database.")
        
        for i, asset in enumerate(assets, 1):
            if not asset.ip: continue
            
            logger.info(f"📡 [DISCOVERY] ({i}/{total}) Probing asset {asset.ip} ({asset.device_type})...")
            
            res = await poll_device_snmpv3(asset.ip)
            if not res and settings.SIMULATION_MODE:
                res = simulate_snmp_poll({"ip": asset.ip, "vendor": asset.vendor, "device_type": asset.device_type})
            
            if res:
                logger.info(f"✅ [DISCOVERY] Successfully gathered metadata for {asset.ip}: {res.get('hostname', 'unknown')} | {res.get('firmware', 'unknown')}")
                if "firmware" in res: asset.firmware = res["firmware"]
                if "hostname" in res: asset.hostname = res["hostname"]
                if "serial" in res: asset.serial = res["serial"]
                if "memory_pct" in res: 
                    try:
                        asset.memory_pct = float(res["memory_pct"])
                    except:
                        pass
                session.add(asset)
            else:
                logger.warning(f"❌ [DISCOVERY] Failed to reach {asset.ip} via SNMPv3")
                
        await session.commit()
        logger.info("📡 [DISCOVERY] SNMPv3 asset discovery cycle complete.")

