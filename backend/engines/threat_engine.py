import logging
import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import json
import os

from backend.models import Asset, Anomaly

logger = logging.getLogger("claroty.threat_engine")

class ThreatEngine:
    def __init__(self):
        self.mapping = {}
        base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
        mapping_path = os.path.join(base_path, "mitre_ics_mapping.json")
        if os.path.exists(mapping_path):
            with open(mapping_path, "r") as f:
                self.mapping = json.load(f)

    async def process_threat(self, session: AsyncSession, src_ip: str, asset: Asset, mitre_id: str, desc: str):
        if not asset:
            return

        threat_data = self.mapping.get(mitre_id, {})
        if not threat_data:
            # Fallback deduction
            threat_data = {
                "attack_id": mitre_id,
                "attack_name": "Unknown Threat Profile",
                "impact": "Medium",
                "tactic": "Unknown",
                "threat_weight": 40
            }

        tactic = threat_data.get("tactic", "Unknown")
        attack_name = threat_data.get("attack_name", "Unknown Threat")
        threat_weight = threat_data.get("threat_weight", 40)
        score = threat_weight / 100.0 if threat_weight <= 100.0 else 1.0

        # High-visibility Log Trigger
        print(f"\n[!!! THREAT DETECTED !!!] {src_ip} -> {mitre_id} ({tactic})")
        logger.warning(f"Threat Event Intercepted: {src_ip} via {mitre_id}")

        # Execute Immediate Raw SQL Persistence required by objective
        from sqlalchemy import text
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS Threat_Events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                mitre_id TEXT,
                tactic TEXT,
                severity FLOAT
            )
        """))
        
        # Scale severity strictly to 100 (Critical) or 70 (High)
        sev = 100.0 if threat_weight >= 70 or attack_name == "Remote System Discovery" else 70.0
        
        await session.execute(
            text("INSERT INTO Threat_Events (timestamp, source_ip, mitre_id, tactic, severity) VALUES (:ts, :ip, :mitre, :tactic, :sev)"),
            {"ts": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), "ip": src_ip, "mitre": mitre_id, "tactic": tactic, "sev": sev}
        )

        # Update Asset
        asset.current_risk_score = (asset.current_risk_score or 0.0) + threat_weight
        session.add(asset)

        # Ensure UI maps to Threat_Events structurally (Anomaly is our equivalent table)
        stmt = select(Anomaly).where(
            Anomaly.asset_id == asset.id, 
            Anomaly.attack_id == mitre_id, 
            Anomaly.is_active == True
        )
        existing = (await session.execute(stmt)).scalar_one_or_none()
        
        if not existing:
            anom = Anomaly(
                asset_id=asset.id,
                anomaly_type="active_threat",
                threat_score=score,
                attack_id=mitre_id,
                attack_name=attack_name,
                mitre_tactic=tactic,
                description=desc,
                is_active=True,
                timestamp=datetime.datetime.utcnow()
            )
            session.add(anom)
            
        await session.commit()

threat_engine = ThreatEngine()
