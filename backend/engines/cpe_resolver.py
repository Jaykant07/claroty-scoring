import re
import os
import sqlite3
import httpx
import logging
from urllib.parse import quote

logger = logging.getLogger("claroty.cpe_resolver")

class CPEResolver:
    def __init__(self):
        self.base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
        self.cpe_db_path = os.path.join(self.base_path, "cpe_index.db")
        self.cpe_dictionary = {}
        dic_path = os.path.join(self.base_path, "cpe_dictionary.json")
        if os.path.exists(dic_path):
            import json
            with open(dic_path, "r") as f:
                self.cpe_dictionary = json.load(f)
                
    def clean_cpe_keyword(self, keyword: str) -> str:
        k = keyword.lower()
        k = re.sub(r'\b(inc\.?|corp\.?|ltd\.?|llc|gmbh|ag|\(r\)|\(tm\)|®|™)\b', '', k)
        return ' '.join(k.split())

    async def resolve_cpe(self, vendor: str, device_type: str, os_type: str) -> str:
        if not vendor or vendor == "unknown":
            return ""

        v_lower = vendor.lower()
        o_lower = os_type.lower() if os_type else ""
        d_lower = device_type.lower() if device_type and device_type != "unknown" else ""

        # Tier 1: Static Dictionary Bypass
        v_dict = self.cpe_dictionary.get(v_lower, {})
        if o_lower and o_lower in v_dict:
            return v_dict[o_lower]
        if d_lower and d_lower in v_dict:
            return v_dict[d_lower]

        parts = [vendor]
        if device_type and device_type != "unknown" and device_type != "industrial_asset":
            parts.append(device_type)
        if os_type and os_type != "unknown":
            parts.append(os_type)

        search_term = self.clean_cpe_keyword(" ".join(parts))
        if not search_term:
            return ""

        # Tier 2: FTS5 Local DB Vectorization
        if os.path.exists(self.cpe_db_path):
            try:
                conn = sqlite3.connect(self.cpe_db_path)
                cursor = conn.cursor()
                match_query = " AND ".join([f'"{w}"*' for w in search_term.split()])
                cursor.execute(f"SELECT cpe_name FROM cpe_index WHERE title MATCH ? LIMIT 1", (match_query,))
                row = cursor.fetchone()
                conn.close()
                if row:
                    return row[0]
            except Exception as e:
                logger.debug(f"FTS5 Query failed for '{search_term}': {e}")

        # Tier 3: Remote NVD Call (Offline safe fallback)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={quote(search_term)}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    products = data.get("products", [])
                    if products:
                        return products[0].get("cpe", {}).get("cpeName", "")
        except Exception:
            pass

        return ""

cpe_resolver = CPEResolver()
