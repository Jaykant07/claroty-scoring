"""SQLAlchemy ORM models — the Asset Master and all supporting tables."""

from __future__ import annotations

import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, Enum as SAEnum,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ── Zones (IEC 62443) ─────────────────────────────────────────────────────────

class Zone(Base):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False, unique=True)
    vlan_id = Column(Integer, nullable=True)
    ip_range = Column(String(64), nullable=True)               # e.g. "10.10.1.0/24"
    iec_level = Column(Integer, nullable=False, default=2)      # 0-4
    description = Column(Text, default="")

    assets = relationship("Asset", back_populates="zone")

    @property
    def network_position_weight(self) -> float:
        """IEC 62443 Security Level → Impact weight."""
        return {0: 1.0, 1: 1.0, 2: 0.6, 3: 0.4, 4: 0.2}.get(self.iec_level, 0.4)


# ── Assets ─────────────────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False, unique=True)
    mac = Column(String(17), default="")
    hostname = Column(String(256), default="")
    cpe = Column(String(256), default="")                       # CPE 2.3 string
    vendor = Column(String(128), default="")
    firmware = Column(String(256), default="")
    hardware_model = Column(String(128), default="")
    rack_slot = Column(String(64), default="")
    serial = Column(String(128), default="")
    device_type = Column(String(64), default="unknown")         # plc, hmi, scada, ews, switch, workstation
    os_type = Column(String(64), default="unknown")
    os_confidence = Column(Float, default=0.0)
    zone_id = Column(Integer, ForeignKey("zones.id"), nullable=True)

    criticality_score = Column(Float, default=0.5)              # 0.0-1.0
    security_level = Column(Integer, default=2)                 # IEC SL 0-4
    purdue_level = Column(Integer, nullable=True)                   # Purdue Model Level 0-4
    has_internet_route = Column(Boolean, default=False)
    protocol_security = Column(String(16), default="unknown")   # secure | insecure | mixed | unknown
    protocols = Column(String(512), default="")                 # comma separated list of protocols
    eol_status = Column(Boolean, default=False)                 # True = End-of-Life

    # Populated by SNMP
    cpu_load = Column(Float, nullable=True)
    memory_pct = Column(Float, nullable=True)

    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)

    zone = relationship("Zone", back_populates="assets")
    vulnerabilities = relationship("AssetVulnerability", back_populates="asset")
    risk_scores = relationship("RiskScore", back_populates="asset", order_by="RiskScore.timestamp.desc()")
    anomalies = relationship("Anomaly", back_populates="asset", order_by="Anomaly.timestamp.desc()")
    compensating_controls = relationship("CompensatingControl", back_populates="asset")


# ── Vulnerabilities ────────────────────────────────────────────────────────────

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), nullable=False, unique=True)    # CVE-2024-XXXXX
    cvss_score = Column(Float, default=0.0)                     # 0.0-10.0
    epss_score = Column(Float, default=0.0)                     # 0.0-1.0
    predictive_risk = Column(Boolean, default=False)            # True if EPSP > 0.5
    epss_percentile = Column(Float, default=0.0)
    severity = Column(String(16), default="MEDIUM")             # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, default="")
    cwe_id = Column(String(20), default="")
    is_kev = Column(Boolean, default=False)                     # CISA Known Exploited
    published_at = Column(DateTime, nullable=True)
    last_synced = Column(DateTime, default=datetime.datetime.utcnow)

    assets = relationship("AssetVulnerability", back_populates="vulnerability")


class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)

    asset = relationship("Asset", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability", back_populates="assets")


# ── Risk Scores ────────────────────────────────────────────────────────────────

class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    likelihood = Column(Float, default=0.0)
    impact = Column(Float, default=0.0)
    vulnerability_component = Column(Float, default=0.0)
    accessibility_component = Column(Float, default=0.0)
    threat_component = Column(Float, default=0.0)
    final_score = Column(Float, default=0.0)                    # 0-100
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    asset = relationship("Asset", back_populates="risk_scores")


# ── Traffic Logs ───────────────────────────────────────────────────────────────

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_mac = Column(String(17), default="")
    dst_mac = Column(String(17), default="")
    protocol = Column(String(32), default="unknown")            # modbus, dnp3, profinet, s7comm...
    port = Column(Integer, nullable=True)
    payload_sig = Column(String(128), default="")
    is_cross_zone = Column(Boolean, default=False)
    is_encrypted = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


# ── Syslog Events ─────────────────────────────────────────────────────────────

class SyslogEvent(Base):
    __tablename__ = "syslog_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(45), nullable=False)
    event_type = Column(String(32), default="info")             # admin_login, firewall_deny, config_change, auth_failure
    facility = Column(Integer, default=1)
    severity = Column(Integer, default=6)                       # 0-7 (RFC 5424)
    message = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


# ── NetFlow Records ───────────────────────────────────────────────────────────

class NetFlowRecord(Base):
    __tablename__ = "netflow_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol_num = Column(Integer, default=6)                   # 6=TCP, 17=UDP
    bytes_sent = Column(Integer, default=0)
    packets = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)
    is_cross_zone = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


# ── Anomalies (Transformer output) ────────────────────────────────────────────

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    anomaly_type = Column(String(32), default="unknown")        # beaconing, ghost_ip, protocol_anomaly, volume_spike
    threat_score = Column(Float, default=0.0)                   # 0.0-1.0
    attack_id = Column(String(16), default="")                  # MITRE ATT&CK ICS ID (e.g. T0806)
    attack_name = Column(String(128), default="")
    mitre_tactic = Column(String(64), default="")               # e.g., Execution, Lateral Movement
    mitigation = Column(Text, default="")
    description = Column(Text, default="")
    is_active = Column(Boolean, default=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    asset = relationship("Asset", back_populates="anomalies")


# ── Compensating Controls ─────────────────────────────────────────────────────

class CompensatingControl(Base):
    __tablename__ = "compensating_controls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    control_type = Column(String(32), default="firewall")       # firewall, ids, segmentation, vpn
    reduction_pct = Column(Float, default=0.30)                 # % reduction on Likelihood
    description = Column(Text, default="")

    asset = relationship("Asset", back_populates="compensating_controls")


# ── Conduits (Zero-Trust) ─────────────────────────────────────────────────────

class Conduit(Base):
    __tablename__ = "conduits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_zone_id = Column(Integer, ForeignKey("zones.id", ondelete="CASCADE"), nullable=False)
    dest_zone_id = Column(Integer, ForeignKey("zones.id", ondelete="CASCADE"), nullable=False)
    allowed_protocols = Column(String(128), default="*") # comma separated, or *
    description = Column(Text, default="")

