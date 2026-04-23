"""EPSSManager: Optimized memory store for loading and retrieving EPSS bulk calculations."""

import os
import csv
import logging

logger = logging.getLogger("claroty.epss_manager")

class EPSSManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EPSSManager, cls).__new__(cls)
            cls._instance.data = {}
            cls._instance.load_epss_csv()
        return cls._instance

    def load_epss_csv(self):
        base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
        csv_path = os.path.join(base_path, "epss_scores-2026-04-18.csv")

        if not os.path.exists(csv_path):
            logger.warning(f"EPSS CSV not found at {csv_path}. EPSS enrichment will fallback to 0.0.")
            return

        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    # Skip comments or header rows
                    if not row or row[0].startswith("#") or row[0] == "cve":
                        continue
                    if len(row) >= 3:
                        cve = row[0]
                        try:
                            epss = float(row[1])
                            percentile = float(row[2])
                            self.data[cve] = {"epss": epss, "percentile": percentile}
                        except ValueError:
                            pass
            logger.info(f"EPSSManager loaded {len(self.data)} records successfully.")
        except Exception as e:
            logger.error(f"Failed to parse EPSS CSV: {e}")

    def get_cve_metrics(self, cve_id: str) -> dict:
        """Returns the EPSS score and percentile dict for a given CVE."""
        return self.data.get(cve_id, {"epss": 0.0, "percentile": 0.0})

epss_manager = EPSSManager()
