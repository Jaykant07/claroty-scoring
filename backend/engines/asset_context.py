"""AssetContextManager: Joint lookup orchestrator across multiple ICS datasets."""

import logging
from backend.engines.data_manager import data_manager
from backend.engines.epss_manager import epss_manager
from backend.models import Asset

logger = logging.getLogger("claroty.asset_context")

class AssetContextManager:
    def __init__(self):
        self.dm = data_manager

    def enrich_asset(self, asset: Asset) -> dict:
        """
        Perform a joint lookup across the taxonomy, NVD, EPSS, and MITRE mapping dictionaries.
        Prioritizes EPSS ranking dynamically.
        """
        # 1. Generate CPE
        vendor_str = asset.vendor or ""
        os_str = asset.os_type or ""
        cpe = self.dm.generate_cpe(vendor_str, os_str)

        # 2. Assign Taxonomy / Purdue Level
        req_type = asset.device_type or "unknown"
        purdue_level = self.dm.get_purdue_level(vendor_str, req_type)

        # 3. Precision Vulnerability Array - Prioritize EPSS Ranking
        vulns = []
        if cpe:
            matched = self.dm.get_vulnerabilities_by_cpe(cpe)
            # Rehydrate with EPSS dynamically
            for v in matched:
                cve_id = v.get("cve_id", "")
                epss_metrics = epss_manager.get_cve_metrics(cve_id)
                v["epss_score"] = epss_metrics["epss"]
                v["epss_percentile"] = epss_metrics["percentile"]
                v["predictive_risk"] = epss_metrics["percentile"] > 0.95
                vulns.append(v)
            
            # Sort explicitly by EPSS
            vulns.sort(key=lambda x: x["epss_score"], reverse=True)

        return {
            "cpe": cpe,
            "purdue_level": purdue_level,
            "vulnerabilities": vulns
        }

asset_context_manager = AssetContextManager()
