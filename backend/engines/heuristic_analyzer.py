"""
DeepDiscovery Heuristic Analyzer
Executes Multi-Factor Signature Matrix logic for deep OS & Device fingerprinting.
"""
import logging

logger = logging.getLogger("claroty.heuristics")

class DeepDiscovery:
    def __init__(self):
        pass

    def calculate_initial_ttl(self, ttl: int) -> int:
        ceiling_bounds = [32, 64, 128, 255]
        for bound in ceiling_bounds:
            if ttl <= bound:
                return bound
        return 255
        
    def analyze(self, pkt) -> dict:
        result = {
            "os_type": "unknown",
            "confidence": 0.0,
            "device_category": None,
            "criticality_override": None
        }
        
        try:
            from scapy.all import IP, TCP, UDP, Raw, SNMP
        except ImportError:
            return result

        if not pkt.haslayer(IP):
            return result
            
        ttl = pkt[IP].ttl
        initial_ttl = self.calculate_initial_ttl(ttl)
        
        # Scoring metrics
        scores = {"linux": 0, "windows": 0, "macOS": 0, "android": 0}
        
        ttl_match = 0.0
        win_match = 0.0
        opt_match = 0.0
        candidate_os = "unknown"

        if pkt.haslayer(TCP):
            w = pkt[TCP].window
            opts = pkt[TCP].options # list of tuples
            opt_keys = [str(o[0]) for o in opts]
            
            mss = 1460
            for o in opts:
                if o[0] == "MSS":
                    mss = o[1]
            
            # --- FACTOR 1: TCP Option Sequence (Weight 50) ---
            if opt_keys == ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'WScale']:
                scores["linux"] += 50
                scores["android"] += 50
            elif opt_keys == ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']:
                scores["windows"] += 50
            elif opt_keys == ['MSS', 'WScale', 'SAckOK', 'Timestamp']:
                scores["macOS"] += 50
                
            if max(scores.values()) > 0:
                opt_match = max(scores.values()) / 50.0

            # --- FACTOR 2: MSS Ratio (Weight 30) ---
            win_score_linux = 0
            win_score_win = 0
            if mss > 0 and w % mss == 0:
                win_score_linux = 30
            if w in [8192, 65535]:
                win_score_win = 30
                
            if win_score_linux > win_score_win:
                scores["linux"] += win_score_linux
            elif win_score_win > 0:
                scores["windows"] += win_score_win
                
            if max(win_score_linux, win_score_win) > 0:
                win_match = max(win_score_linux, win_score_win) / 30.0
            
            # --- INITIAL TTL BASELINE (Weight 20) ---
            if initial_ttl == 64:
                scores["linux"] += 20
                scores["macOS"] += 20
                scores["android"] += 20
                ttl_match = 1.0
            elif initial_ttl == 128:
                scores["windows"] += 20
                ttl_match = 1.0
            
            # Identify Best Candidate
            best_score = 0
            for os_n, s in scores.items():
                if s > best_score:
                    best_score = s
                    candidate_os = os_n
                    
            if best_score > 0:
                # S_conf formula
                s_conf = ((20.0 * ttl_match) + (30.0 * win_match) + (50.0 * opt_match)) / 100.0
                if s_conf < 0.50:
                    result["os_type"] = "Generic Device"
                    result["confidence"] = s_conf
                else:
                    result["os_type"] = candidate_os
                    result["confidence"] = s_conf
        else:
            # Fallback for UDP/ICMP
            if initial_ttl == 128:
                result["os_type"] = "windows"
                result["confidence"] = 0.20
            elif initial_ttl == 64:
                result["os_type"] = "linux"
                result["confidence"] = 0.20

        # --- FACTOR 3: Protocol Association (Overrides) ---
        dport = 0
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            
        if dport == 502:
            result["device_category"] = "plc"
            result["criticality_override"] = 10.0
        elif dport == 102:
            result["device_category"] = "plc"
            result["criticality_override"] = 10.0
        elif dport == 44818:
            result["device_category"] = "plc"
            result["criticality_override"] = 10.0
            
        # Payload Deep Dive (Banner Grabbing Ground Truth)
        if pkt.haslayer(SNMP):
            try:
                for varbind in pkt[SNMP].PDUvarbinds:
                    if varbind.oid.val.startswith("1.3.6.1.2.1.1.1"):
                        val_str = varbind.value.val.decode(errors='ignore')
                        result["device_category"] = "plc" 
                        result["criticality_override"] = 10.0
                        if "windows" in val_str.lower(): result["os_type"] = "windows"
                        elif "linux" in val_str.lower(): result["os_type"] = "linux"
                        elif "vxworks" in val_str.lower(): result["os_type"] = "vxworks"
                        result["confidence"] = 1.0 
            except Exception:
                pass
                
        if pkt.haslayer(Raw) and dport in [80, 443]:
            payload = bytes(pkt[Raw].load)[:512].lower()
            for kw in [b"siemens", b"rockwell", b"ecostruxure", b"honeywell"]:
                if kw in payload:
                    result["device_category"] = "hmi"
                    result["criticality_override"] = 7.0
                    result["confidence"] = 1.0
                    
        return result
