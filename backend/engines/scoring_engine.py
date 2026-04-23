"""
Multi-Dimensional Risk Engine
Implements the active per-packet Risk calculation.
Formula: Risk = min(100, [((V * A) + (I + T)) * C] / 10)
"""
from __future__ import annotations
import datetime
import logging
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models import Asset, TrafficLog, Anomaly, RiskScore
from backend.engines.data_manager import data_manager

logger = logging.getLogger("claroty.scoring_engine")

MITRE_EVENT_MAPPING = {
    "Port Scanning": "T0846",
    "Default Community String": "T0812",
    "Unauthorized Write Command": "T0855"
}

Industrial_Vendors = [
    "siemens", "rockwell", "allen-bradley", "schneider", "honeywell", "abb", 
    "yokogawa", "emerson", "mitsubishi", "general electric", "ge", "omron", 
    "beckhoff", "wago", "phoenix contact", "moxa", "hirschmann", "belden", 
    "ruggedcom", "advantech", "westermo", "endress", "keyence", "pro-face", 
    "red lion", "eaton"
]

async def calculate_asset_risk(session: AsyncSession, asset: Asset) -> RiskScore:
    """Calculates risk score for an asset and returns the resulting RiskScore record."""
    vendor = asset.vendor if asset.vendor else "unknown"
    os_type = asset.os_type if asset.os_type else "unknown"

    # Step 1: V (Vulnerability)
    import json
    import os
    vulnerabilities = data_manager.get_vulnerabilities(vendor, os_type)
    v = 0.0
    
    epss_cache = {}
    epss_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "epss_cache.json")
    try:
        if os.path.exists(epss_path):
            with open(epss_path, "r", encoding="utf-8") as f:
                epss_cache = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load EPSS cache in Risk Engine: {e}")

    if vulnerabilities:
        # Find max CVSS
        max_cvss = max(float(vuln.get("cvss", 0.0)) for vuln in vulnerabilities)
        
        # Check if in KEV and find max EPSS
        max_epss = 0.0
        has_kev = False
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "")
            if data_manager.is_kev(cve_id):
                has_kev = True
            
            # Use cached EPSS data if available
            epss_val = epss_cache.get(cve_id, 0.0)
            if epss_val > max_epss:
                max_epss = epss_val
                
        # Risk component V
        v = max_cvss * max_epss
    
    # Step 2: A (Accessibility)
    # Count of unique active ports seen in traffic log for this asset * 0.1
    stmt = select(func.count(func.distinct(TrafficLog.port))).where(
        (TrafficLog.src_ip == asset.ip) | (TrafficLog.dst_ip == asset.ip)
    )
    unique_ports = (await session.execute(stmt)).scalar() or 0
    a = float(unique_ports)

    # Step 3: I (Infection/Hygiene)
    # Penalty of 15 for Telnet(23)/FTP(21), 10 for HTTP(80)
    stmt = select(TrafficLog.port).where(TrafficLog.dst_ip == asset.ip).distinct()
    open_ports = (await session.execute(stmt)).scalars().all()
    
    i_penalty = 0
    for p in open_ports:
        if p is None:
            continue
        service = data_manager.get_nmap_service(p)
        if p in [21, 23] or service in ["ftp", "telnet"]:
            i_penalty += 15
        elif p == 80 or service == "http":
            i_penalty += 10
            
    # Step 4: T (Threat)
    stmt = select(Anomaly.attack_id).where(
        (Anomaly.asset_id == asset.id) & 
        (Anomaly.is_active == True)
    )
    active_anomalies_ids = (await session.execute(stmt)).scalars().all()
    
    t_val = 0.0
    detected_techniques = [aid for aid in active_anomalies_ids if aid]
    if detected_techniques:
        impact_map = {"High": 100.0, "Medium": 50.0, "Low": 25.0}
        for tech in detected_techniques:
            mapping = data_manager.get_mitre_mapping(tech)
            val = impact_map.get(mapping.get("impact", "Low"), 0.0)
            if val > t_val:
                t_val = val
    t = t_val
    
    # Step 5: C (Criticality) via Purdue Level
    c_purdue = asset.purdue_level if asset.purdue_level is not None else 3
    c = {0: 10.0, 1: 10.0, 2: 7.0, 3: 4.0, 4: 1.0}.get(c_purdue, 4.0)

    # Calculate Risk
    raw_risk = ((v + (a * i_penalty) + t) * c) / 10.0
    final_score = min(100.0, max(0.0, raw_risk))
    
    # Floor to 2 decimals
    final_score = round(final_score, 2)
    
    score_record = RiskScore(
        asset_id=asset.id,
        likelihood=round((v * a) / 10.0, 4),
        impact=c,
        vulnerability_component=v,
        accessibility_component=a,
        threat_component=t,
        final_score=final_score,
        timestamp=datetime.datetime.utcnow(),
    )
    session.add(score_record)
    
    return score_record
