"""
Compliance API Routes (Phase 7)
Serves SL-T vs SL-A metrics and generates Executive Summary PDFs.
"""

from __future__ import annotations

import os
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_session
from backend.models import Asset, Zone, RiskScore

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

router = APIRouter(prefix="/api/compliance", tags=["Compliance"])

@router.get("/metrics")
async def get_compliance_metrics(session: AsyncSession = Depends(get_session)):
    """Calculate Security Level Target (SL-T) vs Achieved (SL-A) per Zone."""
    stmt = select(Zone).order_by(Zone.iec_level)
    zones = (await session.execute(stmt)).scalars().all()

    results = []
    
    for zone in zones:
        # SL-T is the configured IEC 62443 level for the zone
        sl_t = zone.iec_level
        
        # Calculate SL-A based on asset risk. 
        # If avg risk is low (<25), SL-A is 4. If critical (>75), SL-A is 0.
        ass_stmt = select(Asset).where(Asset.zone_id == zone.id)
        assets = (await session.execute(ass_stmt)).scalars().all()
        
        scores = []
        for asset in assets:
            rs_stmt = select(RiskScore).where(RiskScore.asset_id == asset.id).order_by(RiskScore.timestamp.desc()).limit(1)
            rs = (await session.execute(rs_stmt)).scalar_one_or_none()
            if rs:
                scores.append(rs.final_score)
        
        if not scores:
            sl_a = sl_t # Assume compliant if empty
        else:
            avg_rc = sum(scores) / len(scores)
            if avg_rc >= 75: sl_a = 0
            elif avg_rc >= 50: sl_a = 1
            elif avg_rc >= 25: sl_a = 2
            elif avg_rc >= 10: sl_a = 3
            else: sl_a = 4
            
        results.append({
            "zone": zone.name,
            "sl_t": sl_t,
            "sl_a": sl_a,
            "gap": max(0, sl_t - sl_a)
        })
        
    return {"metrics": results}


@router.get("/pdf")
async def get_compliance_pdf(session: AsyncSession = Depends(get_session)):
    """Generate and return an Executive Summary PDF using reportlab."""
    data = await get_compliance_metrics(session)
    metrics = data["metrics"]
    
    os.makedirs("reports", exist_ok=True)
    pdf_path = "reports/Executive_Compliance_Summary.pdf"

    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    # Header
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, "Claroty OT Security Platform")
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 70, "Executive Compliance & Risk Summary (IEC 62443)")
    
    # Overview
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 120, "1. Zone Compliance Gap Analysis")
    
    # Table Header
    c.setFont("Helvetica-Bold", 10)
    y = height - 150
    c.drawString(50, y, "Zone Name")
    c.drawString(250, y, "Target (SL-T)")
    c.drawString(350, y, "Achieved (SL-A)")
    c.drawString(450, y, "Gap")
    
    c.line(50, y - 5, 550, y - 5)
    
    # Rows
    c.setFont("Helvetica", 10)
    y -= 25
    for m in metrics:
        c.drawString(50, y, m["zone"])
        c.drawString(250, y, str(m["sl_t"]))
        c.drawString(350, y, str(m["sl_a"]))
        
        gap = m["gap"]
        if gap > 0:
            c.setFillColor(colors.red)
        else:
            c.setFillColor(colors.black)
        c.drawString(450, y, str(gap))
        
        c.setFillColor(colors.black)
        y -= 20
        
    # Recommendations
    y -= 30
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "2. Top Remediation Recommendations")
    
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, "- Address CVE-2024-6242 vulnerability if present in PLCs by segmenting CIP routes.")
    y -= 15
    c.drawString(50, y, "- Review Zero-Trust conduits, particularly cross-VLAN access into Process Control.")
    y -= 15
    c.drawString(50, y, "- Implement compensate controls (firewalls) on EOL devices.")

    c.line(50, 50, 550, 50)
    c.drawString(50, 35, "Confidential - Internal Use Only")

    c.save()
    
    return FileResponse(pdf_path, media_type="application/pdf", filename="Executive_Summary.pdf")
