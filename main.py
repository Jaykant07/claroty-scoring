"""
Main entry point for Claroty OT Security Risk Scoring Platform.
Launches the Sniffer, Scheduler, Risk Engine, Anomaly Engine, and API concurrently.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncio
import logging
import datetime
from sqlalchemy import select
import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from backend.config import settings
from backend.database import async_session, engine
from backend.models import Base, Asset, TrafficLog, Anomaly, Zone
from backend.acquisition.passive_dpi import start_live_sniffer
from backend.engines.vulnerability_sync import sync_vulnerabilities
from backend.engines.risk_engine import calculate_all_risk_scores
from backend.engines.rule_engine import evaluate_packet_rules
import backend.state as state

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("claroty.main")
logging.getLogger("httpx").setLevel(logging.WARNING)

packet_queue = asyncio.Queue()

def check_dpi_signature(record: dict, asset: Asset | None):
    """If a packet contains S7Comm or Modbus, override the Heuristic Guess (TTL) and force PLC with Criticality 10."""
    if not asset:
        return
    proto = record.get("protocol", "unknown").lower()
    port = record.get("dst_port") or record.get("src_port")
    
    if proto in ["s7comm", "modbus"] or port in [102, 502]:
        if asset.device_type != "PLC" or asset.purdue_level != 1:
            asset.device_type = "PLC"
            asset.criticality_score = 10.0
            asset.purdue_level = 1
            logger.info(f"[DPI OVERRIDE] Protocol identified; overriding TTL heuristics for IP {asset.ip}")

async def db_writer_worker():
    """Reads packets from queue and saves them to DB.
    
    Two-phase commit to prevent SQLite write lock from blocking API reads:
    Phase 1: Write the TrafficLog + fast asset UPSERT, then immediately commit.
    Phase 2: Do heavier enrichment (CPE, risk scoring) in a separate session.
    """
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    from backend.engines.data_manager import data_manager
    from backend.models import RiskScore
    from backend.engines.scoring_engine import calculate_asset_risk

    while True:
        record = await packet_queue.get()
        try:
            # Pop enrichment fields before saving to TrafficLog
            fw = record.pop("firmware_extracted", "")
            hw = record.pop("model_extracted", "")
            vendor_val = record.pop("vendor", "")
            os_val = record.pop("os_type", "unknown")
            os_conf = record.pop("os_confidence", 0.0)
            crit_override = record.pop("criticality_override", None)
            dev_override = record.pop("device_category_override", None)
            active_threat = record.pop("active_threat", None)
            threat_desc = record.pop("threat_desc", "")

            proto = record.get("protocol", "unknown")
            port = record.get("port") or record.get("dst_port") or record.get("src_port")
            service_name = data_manager.add_nmap_service(port) if port else None

            src_ip = record.get("src_ip", "")
            dst_ip = record.get("dst_ip", "")

            # ── Phase 1: Fast write — TrafficLog + minimal Asset UPSERT ──────────
            async with async_session() as session:
                # Save traffic log
                t = TrafficLog(**record)
                session.add(t)

                # UPSERT src asset (minimal fields only)
                if src_ip and not src_ip.startswith("239.") and src_ip != "0.0.0.0":
                    is_plc = proto in ["modbus", "dnp3", "s7comm", "ethernet_ip", "profinet", "bacnet"]
                    dev_type = dev_override if dev_override else ("plc" if is_plc else "industrial_asset")
                    src_values = {
                        "ip": src_ip,
                        "mac": record.get("src_mac", ""),
                        "device_type": dev_type,
                        "vendor": vendor_val or "unknown",
                        "os_type": os_val,
                        "os_confidence": os_conf,
                        "criticality_score": 1.0 if (crit_override or is_plc) else 0.5,
                        "last_seen": datetime.datetime.utcnow()
                    }
                    stmt_src = sqlite_insert(Asset).values(src_values)
                    await session.execute(stmt_src.on_conflict_do_update(
                        index_elements=['ip'],
                        set_={"last_seen": stmt_src.excluded.last_seen}
                    ))

                # UPSERT dst asset (minimal fields only)
                if dst_ip and not dst_ip.startswith("239.") and dst_ip != "0.0.0.0":
                    dst_values = {
                        "ip": dst_ip,
                        "mac": record.get("dst_mac", ""),
                        "device_type": "industrial_asset",
                        "last_seen": datetime.datetime.utcnow()
                    }
                    stmt_dst = sqlite_insert(Asset).values(dst_values)
                    await session.execute(stmt_dst.on_conflict_do_update(
                        index_elements=['ip'],
                        set_={"last_seen": stmt_dst.excluded.last_seen}
                    ))

                await session.commit()  # Fast commit — releases write lock immediately

            # ── Phase 2: Enrichment — runs after write lock is released ──────────
            async with async_session() as session:
                src_asset = None
                dst_asset = None

                if src_ip:
                    src_asset = (await session.execute(
                        select(Asset).where(Asset.ip == src_ip)
                    )).scalar_one_or_none()

                if dst_ip and not dst_ip.startswith("239.") and dst_ip != "0.0.0.0":
                    dst_asset = (await session.execute(
                        select(Asset).where(Asset.ip == dst_ip)
                    )).scalar_one_or_none()

                if src_asset:
                    updated = False

                    if fw and src_asset.firmware != fw:
                        src_asset.firmware = fw; updated = True
                    if hw and src_asset.hardware_model != hw:
                        src_asset.hardware_model = hw; updated = True
                    if vendor_val and vendor_val != "unknown" and not src_asset.vendor or src_asset.vendor in ("", "unknown"):
                        src_asset.vendor = vendor_val; updated = True
                    if os_val and os_val != "unknown" and src_asset.os_type != os_val:
                        src_asset.os_type = os_val; updated = True
                    if os_conf > (src_asset.os_confidence or 0.0):
                        src_asset.os_confidence = os_conf; updated = True

                    # Protocols
                    current_protocols = [p.strip() for p in src_asset.protocols.split(",")] if src_asset.protocols else []
                    new_protocol_added = False
                    if proto and proto != "unknown" and proto not in current_protocols:
                        current_protocols.append(proto); new_protocol_added = True
                    if service_name and service_name.lower() != "unknown" and service_name not in current_protocols:
                        current_protocols.append(service_name); new_protocol_added = True
                    if new_protocol_added:
                        src_asset.protocols = ", ".join(current_protocols); updated = True
                        if "telnet" in [p.lower() for p in current_protocols] or "ftp" in [p.lower() for p in current_protocols]:
                            if not active_threat:
                                active_threat = "Critical Hygiene"
                                threat_desc = "Insecure management protocol (Telnet/FTP) detected."

                    # Purdue Level
                    new_purdue = data_manager.get_purdue_level(src_asset.vendor, src_asset.device_type, [port] if port else [])
                    if new_purdue and src_asset.purdue_level != new_purdue:
                        src_asset.purdue_level = new_purdue; updated = True

                    # DPI Override (only when classification actually changes)
                    check_dpi_signature(record, src_asset)

                    if updated:
                        session.add(src_asset)

                if dst_asset:
                    check_dpi_signature(record, dst_asset)

                # Risk scoring
                if src_asset:
                    old_rs = (await session.execute(
                        select(RiskScore).where(RiskScore.asset_id == src_asset.id)
                        .order_by(RiskScore.timestamp.desc()).limit(1)
                    )).scalar_one_or_none()
                    old_score = old_rs.final_score if old_rs else 0.0
                    new_rs = await calculate_asset_risk(session, src_asset)
                    if abs(new_rs.final_score - old_score) > 5.0 and old_score > 0.0:
                        logger.warning(f"[RISK SHIFT] {src_ip} risk: {old_score:.1f} -> {new_rs.final_score:.1f}")

                # Threat Engine
                if active_threat and src_asset:
                    from backend.engines.threat_engine import threat_engine
                    await threat_engine.process_threat(session, src_ip, src_asset, active_threat, threat_desc)

                # Rule Engine
                await evaluate_packet_rules(session, record.copy() if hasattr(record, "copy") else record)

                # Snapshot for Phase 3 (BEFORE commit so data is still accessible)
                _need_cpe = bool(src_asset and not src_asset.cpe)
                _asset_id = src_asset.id if src_asset else None
                _s_vendor  = src_asset.vendor if src_asset else None
                _s_devtype = src_asset.device_type if src_asset else None
                _s_ostype  = src_asset.os_type if src_asset else None

                await session.commit()  # Release write lock

            # ── Phase 3: CPE resolution via HTTP — zero DB lock held ─────────────
            if _need_cpe and _asset_id:
                try:
                    from backend.engines.cpe_resolver import cpe_resolver
                    new_cpe = await cpe_resolver.resolve_cpe(_s_vendor, _s_devtype, _s_ostype)
                    if new_cpe:
                        async with async_session() as cpe_session:
                            a = (await cpe_session.execute(
                                select(Asset).where(Asset.id == _asset_id)
                            )).scalar_one_or_none()
                            if a and not a.cpe:
                                a.cpe = new_cpe
                                await cpe_session.commit()
                except Exception as cpe_err:
                    logger.debug(f"CPE resolution skipped for {src_ip}: {cpe_err}")

        except Exception as e:
            logger.error(f"Error writing packet to DB: {e}")
        finally:
            packet_queue.task_done()

async def risk_engine_job():
    logger.info("Running Risk Engine (Likelihood x Impact)...")
    try:
        async with async_session() as session:
            await calculate_all_risk_scores(session)
    except Exception as e:
        logger.error(f"Error in risk engine: {e}")

async def vuln_sync_job():
    logger.info("Running NVD/EPSS Vulnerability Sync...")
    try:
        async with async_session() as session:
            stmt = select(Asset)
            assets = (await session.execute(stmt)).scalars().all()
            if assets:
                await sync_vulnerabilities(session, assets)
            else:
                logger.info("No assets to sync vulnerabilities for. Wait for network discovery.")
    except Exception as e:
        logger.error(f"Error in vuln sync: {e}")

async def run_services():
    # Database init
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    if settings.SIMULATION_MODE:
        from backend.seed import seed_demo_data
        await seed_demo_data()

    # Start persistent background workers
    asyncio.create_task(db_writer_worker())

    # Set up APScheduler for recurring tasks
    scheduler = AsyncIOScheduler()
    scheduler.add_job(vuln_sync_job, 'cron', hour=settings.NVD_SYNC_HOUR)
    scheduler.start()

    # Launch Sniffer
    loop = asyncio.get_running_loop()
    def on_packet(record):
        if not state.DISCOVERY_ACTIVE:
            return
        # Bridge the blocking thread-based Sniffer logic back to async queue
        loop.call_soon_threadsafe(packet_queue.put_nowait, record)
        
    asyncio.create_task(start_live_sniffer(on_packet))
    
    # Simulation mode: only generate traffic when user explicitly starts discovery
    # We store the generator task so it can be started/stopped with discovery
    if settings.SIMULATION_MODE:
        from backend.acquisition.passive_dpi import generate_simulated_traffic
        async def start_sim_when_active():
            """Wait for DISCOVERY_ACTIVE before starting simulated traffic."""
            while True:
                if state.DISCOVERY_ACTIVE:
                    await generate_simulated_traffic(on_packet)
                await asyncio.sleep(1.0)
        asyncio.create_task(start_sim_when_active())

    # Run FastAPI API layer
    config = uvicorn.Config("backend.api.main:app", host=settings.API_HOST, port=settings.API_PORT, reload=False, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            # required for python 3.8+ on windows to work with asyncio nicely
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(run_services())
    except KeyboardInterrupt:
        logger.info("Shutting down Claroty OT Platform...")
