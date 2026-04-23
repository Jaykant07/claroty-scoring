import os
import time
import json
import csv
import logging
import asyncio
import httpx

logger = logging.getLogger("claroty.data_sync")

class DataSync:
    """Hybrid Data Intelligence Manager."""
    
    def __init__(self):
        self.base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
        self.cisa_kev_path = os.path.join(self.base_path, "cisa_kev.json")
        self.epss_cache_path = os.path.join(self.base_path, "epss_cache.json")
        self.epss_csv_path = os.path.join(self.base_path, "epss_scores-2026-04-18.csv")

    def _is_stale(self, filepath: str, days=7) -> bool:
        if not os.path.exists(filepath):
            return True
        age_seconds = time.time() - os.path.getmtime(filepath)
        return age_seconds > (days * 86400)

    async def _download_cisa_kev(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            logger.info("Downloading CISA KEV data from official repository...")
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    cve_list = [v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")]
                    with open(self.cisa_kev_path, "w", encoding="utf-8") as f:
                        json.dump(cve_list, f)
                    logger.info("Successfully updated cisa_kev.json.")
                else:
                    logger.warning(f"Download CISA KEV returned HTTP {resp.status_code}")
        except Exception as e:
            logger.warning(f"Failed to download CISA KEV (safe-fail to cache): {e}")

    def transform_epss_csv(self):
        """Converts the uploaded CSV rows into a high-speed JSON lookup table."""
        if not os.path.exists(self.epss_csv_path):
            logger.warning("No EPSS CSV file found to transform.")
            return

        cache_data = {}
        try:
            with open(self.epss_csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    # cve,epss,percentile
                    if not row or row[0].startswith("#") or row[0] == "cve":
                        continue
                    if len(row) >= 2:
                        try:
                            cve = row[0]
                            epss_score = float(row[1])
                            cache_data[cve] = epss_score
                        except ValueError:
                            pass
            
            with open(self.epss_cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_data, f)
            logger.info(f"Successfully transformed EPSS CSV into epss_cache.json with {len(cache_data)} records.")
        except Exception as e:
            logger.error(f"Error transforming EPSS CSV: {e}")

    async def _update_epss_data(self):
        # We perform CSV transform locally if the json is missing or stale. 
        # (Could also be adapted to download the .gz file directly from cyber.gov if requested)
        if self._is_stale(self.epss_cache_path, days=7):
            logger.info("EPSS cache is stale or missing. Re-transforming from local CSV...")
            # Running synchronous logic safely inside the async flow (CSV is small enough / fast enough)
            self.transform_epss_csv()

    def _update_cpe_index(self):
        cpe_db_path = os.path.join(self.base_path, "cpe_index.db")
        if self._is_stale(cpe_db_path, days=7):
            logger.info("CPE Index is strictly older than 7 days. Launching asynchronous FTS5 generation.")
            from backend.engines.cpe_indexer import build_cpe_index_db
            build_cpe_index_db(cpe_db_path)

    async def async_update(self):
        """Non-blocking intelligence background sync."""
        try:
            if self._is_stale(self.cisa_kev_path, days=7):
                await self._download_cisa_kev()
            
            await self._update_epss_data()
            
            # Spin off expensive Index generation silently
            asyncio.create_task(asyncio.to_thread(self._update_cpe_index))
        except Exception as e:
            logger.error(f"DataSync background task encountered safe-fail error: {e}")

data_sync_engine = DataSync()
