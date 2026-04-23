"""Centralized configuration loaded from .env with sensible defaults."""

from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)


class Settings:
    # ── Database ──────────────────────────────────────
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./claroty.db")

    # ── NVD ───────────────────────────────────────────
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_SYNC_HOUR: int = int(os.getenv("NVD_SYNC_HOUR", "2"))

    # ── EPSS ──────────────────────────────────────────
    EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"

    # ── Sniffing / Simulation ─────────────────────────
    SNIFF_INTERFACE: str = os.getenv("SNIFF_INTERFACE", "")
    SIMULATION_MODE: bool = os.getenv("SIMULATION_MODE", "true").lower() == "true"

    # ── SNMP ──────────────────────────────────────────
    SNMP_USER: str = os.getenv("SNMP_USER", "claroty_reader")
    SNMP_AUTH_KEY: str = os.getenv("SNMP_AUTH_KEY", "Auth12345678")
    SNMP_PRIV_KEY: str = os.getenv("SNMP_PRIV_KEY", "Priv12345678")

    # ── Syslog ────────────────────────────────────────
    SYSLOG_PORT: int = int(os.getenv("SYSLOG_PORT", "1514"))

    # ── NetFlow ───────────────────────────────────────
    NETFLOW_PORT: int = int(os.getenv("NETFLOW_PORT", "2055"))

    # ── Risk Engine ───────────────────────────────────
    RISK_CALC_INTERVAL_SEC: int = int(os.getenv("RISK_CALC_INTERVAL_SEC", "60"))
    COMPENSATING_CONTROL_REDUCTION: float = float(
        os.getenv("COMPENSATING_CONTROL_REDUCTION", "0.30")
    )

    # ── Server ────────────────────────────────────────
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")


settings = Settings()
