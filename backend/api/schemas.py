"""Pydantic response schemas for all API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


# ── Zone ───────────────────────────────────────────────────────────────────────

class ZoneSchema(BaseModel):
    id: int
    name: str
    vlan_id: Optional[int] = None
    ip_range: Optional[str] = None
    iec_level: int
    description: str
    asset_count: int = 0
    avg_risk: float = 0.0

    class Config:
        from_attributes = True


# ── Vulnerability ──────────────────────────────────────────────────────────────

class VulnerabilitySchema(BaseModel):
    id: int
    cve_id: str
    cvss_score: float
    epss_score: float
    predictive_risk: bool = False
    epss_percentile: float = 0.0
    severity: str
    description: str
    cwe_id: str
    is_kev: bool
    published_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Risk Score ─────────────────────────────────────────────────────────────────

class RiskScoreSchema(BaseModel):
    likelihood: float
    impact: float
    vulnerability_component: float
    accessibility_component: float
    threat_component: float
    final_score: float
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


class RiskBreakdownSchema(BaseModel):
    vulnerability: float
    accessibility: float
    threat: float
    compensating: float
    likelihood: float
    criticality: float
    network_position: float
    impact: float
    final_score: float


# ── Anomaly ────────────────────────────────────────────────────────────────────

class AnomalySchema(BaseModel):
    id: int
    asset_id: int
    asset_ip: str = ""
    asset_vendor: str = ""
    anomaly_type: str
    threat_score: float
    attack_id: str
    attack_name: str
    mitre_tactic: str = ""
    mitigation: str = ""
    description: str
    is_active: bool
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Compensating Control ──────────────────────────────────────────────────────

class CompensatingControlSchema(BaseModel):
    id: int
    control_type: str
    reduction_pct: float
    description: str

    class Config:
        from_attributes = True


# ── Asset ──────────────────────────────────────────────────────────────────────

class AssetSchema(BaseModel):
    id: int
    ip: str
    mac: str
    hostname: str
    cpe: str
    vendor: str
    firmware: str
    serial: str
    device_type: str
    zone_id: Optional[int] = None
    zone_name: str = ""
    criticality_score: float
    security_level: int
    purdue_level: Optional[int] = None
    has_internet_route: bool
    protocol_security: str
    eol_status: bool
    cpu_load: Optional[float] = None
    memory_pct: Optional[float] = None
    discovered_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    current_risk_score: float = 0.0
    vulnerability_count: int = 0

    class Config:
        from_attributes = True


class AssetDetailSchema(AssetSchema):
    vulnerabilities: list[VulnerabilitySchema] = []
    anomalies: list[AnomalySchema] = []
    risk_history: list[RiskScoreSchema] = []
    compensating_controls: list[CompensatingControlSchema] = []
    risk_breakdown: Optional[RiskBreakdownSchema] = None


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardSummarySchema(BaseModel):
    total_assets: int
    critical_risk_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    average_risk_score: float
    active_anomalies: int
    total_vulnerabilities: int
    cross_zone_events: int
    eol_assets: int


class HeatmapCellSchema(BaseModel):
    zone_id: int
    zone_name: str
    iec_level: int
    severity: str
    count: int
    avg_score: float


class ActivityEventSchema(BaseModel):
    event_type: str
    message: str
    severity: str
    timestamp: Optional[datetime] = None


# ── Syslog ─────────────────────────────────────────────────────────────────────

class SyslogEventSchema(BaseModel):
    id: int
    source_ip: str
    event_type: str
    severity: int
    message: str
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Traffic ────────────────────────────────────────────────────────────────────

class TrafficLogSchema(BaseModel):
    id: int
    src_ip: str
    dst_ip: str
    protocol: str
    port: Optional[int] = None
    is_cross_zone: bool
    is_encrypted: bool
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True
