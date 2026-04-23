"""
Real-time Rule Engine (Zero-Trust & Hardening Controls)
Processes anomalies instantly from live traffic.
"""

from __future__ import annotations

import logging
import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.models import Asset, Conduit, Anomaly

logger = logging.getLogger("claroty.rule_engine")

async def evaluate_packet_rules(session: AsyncSession, record: dict):
    """Evaluate deep packet rules like Zero-Trust crossings, PLC Mode, CVE-2024-6242, and Firmware Integrity."""
    src_ip = record.get("src_ip")
    dst_ip = record.get("dst_ip")
    if not src_ip or not dst_ip:
        return

    # 1. Fetch Assets
    src_asset = (await session.execute(select(Asset).where(Asset.ip == src_ip))).scalar_one_or_none()
    dst_asset = (await session.execute(select(Asset).where(Asset.ip == dst_ip))).scalar_one_or_none()

    # If src is attacker simulating Kali scans
    if src_asset and src_asset.zone and ("External" in src_asset.zone.name or "Unauthorized" in src_asset.zone.name):
        # MITRE T0846 mapping
        await _trigger_anomaly(session, dst_asset or src_asset, "T0846", "Remote System Discovery", "Scan detected from External/Unauthorized Zone (Kali)", 0.8)
        
        # Zero-Trust / Conduit Check
        if dst_asset and dst_asset.zone:
            # Check conduit
            stmt = select(Conduit).where(
                Conduit.source_zone_id == src_asset.zone_id,
                Conduit.dest_zone_id == dst_asset.zone_id
            )
            conduit = (await session.execute(stmt)).scalar_one_or_none()
            if not conduit:
                await _trigger_anomaly(session, dst_asset, "T0866", "Exploitation of Remote Services", "Zero-Trust Violation: Traffic crossed into zone without a valid Conduit.", 0.9)

    # 2. Firmware Integrity (Phase 4)
    fw = record.pop("firmware_extracted", "")
    hw = record.pop("model_extracted", "")
    if src_asset:
        if fw and src_asset.firmware and src_asset.firmware != fw:
            await _trigger_anomaly(session, src_asset, "T0839", "Module Firmware", f"Firmware Integrity Violation: Changed from {src_asset.firmware} to {fw}", 1.0)
            src_asset.firmware = fw
        elif fw:
            src_asset.firmware = fw
            
        if hw and src_asset.hardware_model != hw:
            src_asset.hardware_model = hw

    # 3. CVE-2024-6242 Backplane Bypass (Phase 5)
    cip_depth = record.pop("cip_path_depth", 0)
    if cip_depth > 2:
        await _trigger_anomaly(session, dst_asset or src_asset, "T0890", "Exploitation for Evasion", f"CVE-2024-6242 Attempt: CIP Forward Open path depth of {cip_depth} exceeds safe limits.", 1.0)

    # 4. Controller Mode Monitoring (Phase 5)
    mode = record.pop("plc_mode_change", "")
    if mode == "Remote Program":
        await _trigger_anomaly(session, dst_asset or src_asset, "T0858", "Change Operating Mode", "Controller mode shifted to Remote Program.", 0.85)

def generate_mitigation(desc: str) -> str:
    d = desc.lower()
    if "zero-trust" in d or "conduit" in d:
        return "Review Conduit rules and block unauthorized zone crossing at firewall."
    if "firmware" in d:
        return "Quarantine asset immediately and verify firmware digital hashes."
    if "cve-" in d:
        return "Apply vendor patch or deploy IPS virtual blocking for exploit string."
    if "scan" in d:
        return "Block source IP dynamically at perimeter and investigate source origin."
    if "mode" in d:
        return "Turn physical key-switch to RUN mode restricting remote programming."
    return "Isolate device and investigate network traffic."

async def _trigger_anomaly(session: AsyncSession, asset: Asset | None, attack_id: str, name: str, desc: str, score: float):
    from backend.engines.data_manager import data_manager
    if not asset:
        return

    # Map to MITRE ICS taxonomy and enforce Predictive Risk / Impact
    tactic = ""
    mitre_data = data_manager.get_mitre_mapping(attack_id)
    if mitre_data:
        tactic = mitre_data.get("tactic", "")
        if mitre_data.get("impact") == "High":
            score = 1.0  # Set Asset Risk to Critical

    # Avoid duplicate active anomalies
    stmt = select(Anomaly).where(Anomaly.asset_id == asset.id, Anomaly.attack_id == attack_id, Anomaly.is_active == True)
    existing = (await session.execute(stmt)).scalar_one_or_none()
    if not existing:
        anom = Anomaly(
            asset_id=asset.id,
            anomaly_type="rule_violation",
            threat_score=score,
            attack_id=attack_id,
            attack_name=name,
            mitre_tactic=tactic,
            mitigation=generate_mitigation(desc),
            description=desc,
            is_active=True,
            timestamp=datetime.datetime.utcnow()
        )
        session.add(anom)
        logger.warning(f"Rule Engine Alert: [{attack_id}] {name} on {asset.ip}")
        
        # Phase 6: Automatic PCAP Trigger for critical alerts
        if score >= 0.9:
            from backend.acquisition.pcap_trigger import capture_pcap_task
            import asyncio
            asyncio.create_task(capture_pcap_task(asset.ip))
