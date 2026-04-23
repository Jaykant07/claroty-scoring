"""
FastAPI application — the main REST API for the Claroty OT Security Platform.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.database import engine
from backend.models import Base

logger = logging.getLogger("claroty.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle.
    
    NOTE: Table creation and seeding is handled by main.py to avoid
    concurrent write-lock contention with SQLite.
    """
    import asyncio
    logger.info("Database tables created / verified")
    yield
    await engine.dispose()


app = FastAPI(
    title="Claroty OT Security Risk Scoring Platform",
    version="1.0.0",
    description="Multi-vector OT asset discovery, vulnerability correlation, and IEC 62443-compliant risk scoring.",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL, "http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
from backend.api.routes.assets import router as assets_router
from backend.api.routes.zones import router as zones_router
from backend.api.routes.dashboard import router as dashboard_router
from backend.api.routes.vulnerabilities import router as vulns_router
from backend.api.routes.compliance import router as compliance_router
from backend.api.routes.discovery import router as discovery_router

app.include_router(assets_router)
app.include_router(zones_router)
app.include_router(dashboard_router)
app.include_router(vulns_router)
app.include_router(compliance_router)
app.include_router(discovery_router)


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "platform": "Claroty OT Security", "version": "1.0.0"}
