"""
Demo Data Seeder — populates the database with realistic OT assets,
zones, vulnerabilities, anomalies, and risk scores for demo / development.
"""

from __future__ import annotations

import datetime
import logging
import random

from sqlalchemy import select

from backend.database import async_session
from backend.models import (
    Asset, Zone, Conduit, CompensatingControl, TrafficLog, SyslogEvent, NetFlowRecord,
)
from backend.acquisition.passive_dpi import SIMULATED_DEVICES, SIMULATED_TRAFFIC_PATTERNS
from backend.acquisition.snmp_poller import simulate_snmp_poll
from backend.engines.vulnerability_sync import seed_simulated_vulnerabilities

from backend.engines.risk_engine import calculate_all_risk_scores

logger = logging.getLogger("claroty.seed")

# ── Zone definitions ───────────────────────────────────────────────────────────

ZONE_DEFS = [
    {"name": "Safety Instrumented", "vlan_id": 10, "ip_range": "10.10.0.0/24",   "iec_level": 0, "description": "IEC 62443 Level 0 — Safety Instrumented Systems (SIS). Highest criticality."},
    {"name": "Process Control",     "vlan_id": 11, "ip_range": "10.10.1.0/24",   "iec_level": 1, "description": "IEC 62443 Level 1 — PLCs, RTUs, and field devices controlling physical processes."},
    {"name": "Supervisory",         "vlan_id": 12, "ip_range": "10.10.2.0/24",   "iec_level": 2, "description": "IEC 62443 Level 2 — HMIs, SCADA servers, and supervisory systems."},
    {"name": "DMZ",                 "vlan_id": 13, "ip_range": "10.10.3.0/24",   "iec_level": 3, "description": "IEC 62443 Level 3 — Demilitarised zone: historians, engineering workstations, network infrastructure."},
    {"name": "Enterprise",          "vlan_id": 14, "ip_range": "10.10.4.0/24",   "iec_level": 4, "description": "IEC 62443 Level 4 — Corporate IT: office workstations, email, ERP systems."},
    {"name": "Control Zone (VM)",   "vlan_id": 56, "ip_range": "192.168.56.0/25","iec_level": 1, "description": "Parrot OS PLC Simulator"},
    {"name": "Attacker Zone",       "vlan_id": 99, "ip_range": "192.168.56.128/25","iec_level": 3, "description": "Kali Linux Sandbox"},
]


async def seed_demo_data() -> None:
    """Populate the database with comprehensive demo data."""
    async with async_session() as session:
        # Check if already seeded
        existing = await session.execute(select(Zone))
        if existing.scalars().first():
            logger.info("Database already seeded — skipping")
            return

        logger.info("Seeding demo data...")

        # ── 1. Create Zones ───────────────────────────────────────────────
        zone_map = {}  # name → Zone object
        for zdef in ZONE_DEFS:
            zone = Zone(**zdef)
            session.add(zone)
            zone_map[zdef["name"]] = zone

        await session.flush()
        logger.info("Created %d IEC 62443 zones", len(ZONE_DEFS))
        
        # Build strict zero-trust conduits
        # Examples: Supervisory can talk to Process Control. DMZ can talk to Supervisory.
        # But Attacker Zone intentionally has NO valid conduits to Control Zone.
        valid_conduits = [
            ("Supervisory", "Process Control"),
            ("Process Control", "Safety Instrumented"),
            ("DMZ", "Supervisory"),
            ("Enterprise", "DMZ")
        ]
        for src, dst in valid_conduits:
            session.add(Conduit(source_zone_id=zone_map[src].id, dest_zone_id=zone_map[dst].id))
        
        await session.flush()

        # ── 2. Create Assets ──────────────────────────────────────────────
        assets = []
        for dev in SIMULATED_DEVICES:
            zone = zone_map.get(dev["zone"])
            snmp_data = simulate_snmp_poll(dev)

            # Determine protocol security
            proto_sec = "insecure"  # OT devices typically use cleartext
            if dev["device_type"] in ("workstation", "ews", "historian"):
                proto_sec = "mixed"
            if dev["device_type"] == "switch":
                proto_sec = "secure"

            # Internet route — Enterprise and some DMZ devices
            has_internet = dev["zone"] in ("Enterprise",) or (
                dev["zone"] == "DMZ" and random.random() > 0.5
            )

            asset = Asset(
                ip=dev["ip"],
                mac=dev["mac"],
                hostname=snmp_data["hostname"],
                cpe=dev["cpe"],
                vendor=dev["vendor"],
                firmware=snmp_data["firmware"],
                serial=snmp_data["serial"],
                device_type=dev["device_type"],
                zone_id=zone.id if zone else None,
                criticality_score=dev["criticality"],
                security_level=dev["iec"],
                has_internet_route=has_internet,
                protocol_security=proto_sec,
                eol_status=dev["eol"],
                cpu_load=snmp_data["cpu_load"],
                memory_pct=snmp_data["memory_pct"],
                discovered_at=datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(7, 90)),
                last_seen=datetime.datetime.utcnow(),
            )
            session.add(asset)
            assets.append(asset)

        await session.flush()
        logger.info("Created %d assets", len(assets))

        # ── 3. Compensating Controls ──────────────────────────────────────
        # Assets behind the DMZ firewall get compensating controls
        for asset in assets:
            if asset.zone_id and asset.zone_id == zone_map["Process Control"].id:
                session.add(CompensatingControl(
                    asset_id=asset.id,
                    control_type="firewall",
                    reduction_pct=0.30,
                    description="IEC 62443 Conduit — Palo Alto PA-3250 firewall between Supervisory and Process Control zones",
                ))
            if asset.zone_id and asset.zone_id == zone_map["Safety Instrumented"].id:
                session.add(CompensatingControl(
                    asset_id=asset.id,
                    control_type="segmentation",
                    reduction_pct=0.40,
                    description="Air-gapped safety network with unidirectional data diode",
                ))
                session.add(CompensatingControl(
                    asset_id=asset.id,
                    control_type="ids",
                    reduction_pct=0.10,
                    description="Dedicated IDS monitoring all traffic to/from SIS zone",
                ))

        await session.flush()

        # ── 4. Traffic Logs ───────────────────────────────────────────────
        for _ in range(60):
            pattern = random.choice(SIMULATED_TRAFFIC_PATTERNS)
            session.add(TrafficLog(
                src_ip=pattern[0],
                dst_ip=pattern[1],
                protocol=pattern[2],
                port=pattern[3],
                payload_sig=f"{pattern[2]}_{pattern[3]}",
                is_cross_zone=pattern[4],
                is_encrypted=pattern[3] in (4840, 443, 22),
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=random.randint(0, 1440)),
            ))
        await session.flush()

        # ── 5. Syslog Events ─────────────────────────────────────────────
        from backend.acquisition.syslog_listener import _SIM_MESSAGES, classify_event
        for _ in range(30):
            msg, src = random.choice(_SIM_MESSAGES)
            severity = 6
            facility = 1
            if msg.startswith("<"):
                end = msg.index(">")
                pri = int(msg[1:end])
                facility = pri >> 3
                severity = pri & 0x07
            session.add(SyslogEvent(
                source_ip=src,
                event_type=classify_event(msg),
                facility=facility,
                severity=severity,
                message=msg,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=random.randint(0, 720)),
            ))
        await session.flush()

        # ── 6. Netflow Records ────────────────────────────────────────────
        from backend.acquisition.netflow_parser import _SIM_FLOWS
        for _ in range(40):
            flow = random.choice(_SIM_FLOWS)
            session.add(NetFlowRecord(
                src_ip=flow[0],
                dst_ip=flow[1],
                src_port=random.randint(1024, 65535),
                dst_port=flow[2],
                protocol_num=flow[3],
                bytes_sent=random.randint(64, 150000),
                packets=random.randint(1, 500),
                duration_ms=random.randint(10, 60000),
                is_cross_zone=flow[4],
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=random.randint(0, 1440)),
            ))
        await session.flush()

        # ── 7. Vulnerabilities ────────────────────────────────────────────
        await seed_simulated_vulnerabilities(session, assets)



        # ── 9. Initial Risk Calculation ───────────────────────────────────
        await calculate_all_risk_scores(session)

        await session.commit()
        logger.info("Demo data seeding complete!")
