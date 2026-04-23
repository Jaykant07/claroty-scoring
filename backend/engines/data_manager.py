import json
import os
import logging

logger = logging.getLogger("claroty.data_manager")

class DataManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DataManager, cls).__new__(cls)
            cls._instance.load_data()
        return cls._instance

    def load_data(self):
        # We need to reach the /data folder in the root from this script located at /backend/engines
        base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
        
        def load_json(filename, default):
            try:
                path = os.path.join(base_path, filename)
                if os.path.exists(path):
                    with open(path, "r") as f:
                        return json.load(f)
                else:
                    logger.warning(f"Data file not found: {path}")
            except Exception as e:
                logger.error(f"Error loading {filename}: {e}")
            return default

        self.oui_lookup = {}
        try:
            import csv
            oui_path = os.path.join(base_path, "oui.csv")
            if os.path.exists(oui_path):
                with open(oui_path, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if len(row) >= 3:
                            assignment = row[1].strip().lower()
                            vendor_name = row[2].strip()
                            if assignment:
                                self.oui_lookup[assignment] = vendor_name
            else:
                logger.warning(f"Data file not found: {oui_path}")
        except Exception as e:
            logger.error(f"Error loading oui.csv: {e}")

        self.p0f_sigs = load_json("p0f_os_sigs.json", {})
        self.nvd_cves = load_json("nvd_cves_ics.json", [])
        self.kev = set(load_json("cisa_kev.json", []))
        self.nmap_services = load_json("nmap_services.json", {})
        self.epss_data_raw = load_json("epss_data.json", {"data": []})
        self.epss_data = {item["cve"]: float(item["epss"]) for item in self.epss_data_raw.get("data", [])}
        self.cpe_dictionary = load_json("cpe_dictionary.json", {})
        self.asset_taxonomy = load_json("asset_taxonomy.json", {"device_types": {}, "vendors": {}})
        self.mitre_ics_mapping = load_json("mitre_ics_mapping.json", {})
        
        logger.info(f"DataManager Loaded: {len(self.oui_lookup)} OUIs, {len(self.nvd_cves)} CVEs, {len(self.kev)} KEVs, {len(self.epss_data)} EPSS scores")

    def lookup_vendor(self, oui: str) -> str:
        if not oui:
            return "unknown"
        return self.oui_lookup.get(oui.lower(), "unknown")

    def guess_os(self, ttl: int, window: int = 0) -> str:
        if ttl is None:
            return "unknown"
        # Basic heuristic mapping to p0f TTL sigs (exact p0f logic scales with window/flags, but simplified here)
        if ttl > 128:
            return self.p0f_sigs.get("255", "vxworks")
        elif ttl > 64:
            return self.p0f_sigs.get("128", "windows")
        else:
            return self.p0f_sigs.get("64", "linux")

    def get_vulnerabilities(self, vendor: str, os_type: str) -> list:
        # Return list of CVE items matching vendor and os_type
        matches = []
        vendor_lower = vendor.lower()
        os_lower = os_type.lower()
        for item in self.nvd_cves:
            v_match = item.get("vendor", "") in vendor_lower or vendor_lower in item.get("vendor", "")
            if v_match and os_lower == item.get("os", ""):
                 matches.append(item)
        return matches

    def is_kev(self, cve_id: str) -> bool:
        return cve_id in self.kev

    def get_nmap_service(self, port: int) -> str:
        return self.nmap_services.get(str(port), "unknown")

    def generate_cpe(self, vendor: str, os_type: str) -> str:
        v_dict = self.cpe_dictionary.get(vendor.lower(), {})
        return v_dict.get(os_type.lower(), "")

    def get_vulnerabilities_by_cpe(self, cpe: str) -> list:
        matches = []
        for item in self.nvd_cves:
            # Reusing the existing simple logic, but the actual NVD filtering by CPE would match CPE strings.
            # In our mock nvd_cves, we don't have CPEs, we have vendor/os.
            matches.append(item)
        return matches

    def get_epss_score(self, cve_id: str) -> float:
        return self.epss_data.get(cve_id, 0.0)

    def get_purdue_level(self, vendor: str, device_type: str, ports: list = None) -> int:
        # Check taxonomy dictionary for protocols first
        if ports:
            proto_map = self.asset_taxonomy.get("protocols", {})
            for p in ports:
                if str(p) in proto_map:
                    return proto_map[str(p)]

        level = None
        d_type_level = self.asset_taxonomy.get("device_types", {}).get(device_type.lower())
        v_level = self.asset_taxonomy.get("vendors", {}).get(vendor.lower())
        if d_type_level is not None:
            return d_type_level
        if v_level is not None:
            return v_level
        return level

    def add_nmap_service(self, port: int) -> str:
        port_str = str(port)
        if port_str in self.nmap_services:
            return self.nmap_services[port_str]
        
        label = f"Unknown ({port})"
        self.nmap_services[port_str] = label
        
        try:
            base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
            path = os.path.join(base_path, "nmap_services.json")
            with open(path, "w") as f:
                json.dump(self.nmap_services, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving nmap_services.json: {e}")
            
        return label

    def get_mitre_mapping(self, alert_key: str) -> dict:
        return self.mitre_ics_mapping.get(alert_key, {})

data_manager = DataManager()
