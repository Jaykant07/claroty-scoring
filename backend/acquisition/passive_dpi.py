"""
Passive Deep Packet Inspection — OT Protocol Detection.

Listens on a SPAN / mirror port to identify OT protocols (Modbus, DNP3, Profinet,
EtherNet/IP, OPC-UA, BACnet, S7comm).  In simulation mode it generates realistic
synthetic traffic for demo / development purposes.

**OT-Safe**: Only reads traffic already on the wire.  Never injects packets.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import random
import queue
import threading
import sqlite3
import os
import json
from typing import Callable

from backend.config import settings
from backend.engines.data_manager import data_manager
from backend.engines.heuristic_analyzer import DeepDiscovery

logger = logging.getLogger("claroty.dpi")
deep_discovery = DeepDiscovery()

threat_queue = queue.Queue()

def threat_writer_worker():
    # Execute sqlite natively dropping check_same_thread
    conn = sqlite3.connect("claroty.db", check_same_thread=False, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    while True:
        try:
            threat_data = threat_queue.get()
            if threat_data is None:
                continue
            
            src_ip, mitre_id, tactic, severity = threat_data
            ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            
            # Action 2: Immediate Persistence using Raw SQL
            conn.execute("CREATE TABLE IF NOT EXISTS Threat_Events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME, source_ip TEXT, mitre_id TEXT, tactic TEXT, severity FLOAT)")
            conn.execute("INSERT INTO Threat_Events (timestamp, source_ip, mitre_id, tactic, severity) VALUES (?, ?, ?, ?, ?)", (ts, src_ip, mitre_id, tactic, severity))
            
            # Action 3: Formula Update exactly simulating the user logic on the correct history table
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM assets WHERE ip = ?", (src_ip,))
            row = cursor.fetchone()
            if row:
                asset_id = row[0]
                cursor.execute("SELECT final_score FROM risk_scores WHERE asset_id = ? ORDER BY id DESC LIMIT 1", (asset_id,))
                risk_row = cursor.fetchone()
                base_risk = risk_row[0] if risk_row is not None else 0.0
                new_risk = base_risk + severity
                conn.execute("INSERT INTO risk_scores (asset_id, final_score, timestamp) VALUES (?, ?, ?)", (asset_id, new_risk, ts))
            conn.commit()

            # Action 5: PCAP Trigger
            if severity > 50:
                import asyncio
                from backend.acquisition.pcap_trigger import capture_pcap_task
                def _run_pcap():
                    pcap_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(pcap_loop)
                    pcap_loop.run_until_complete(capture_pcap_task(src_ip, 5))
                    pcap_loop.close()
                threading.Thread(target=_run_pcap, daemon=True).start()
                
        except Exception as e:
            logger.error(f"[DEBUG] DB threat write error: {e}")

threading.Thread(target=threat_writer_worker, daemon=True).start()

def process_threats(packet):
    try:
        from scapy.all import TCP, IP
        # Explicit test rule check
        if packet.haslayer(TCP) and packet.haslayer(IP) and getattr(packet[TCP], 'flags', None) == 'S':
            print("[ALERT] SYN SCAN")
            weight = 50
            try:
                base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
                mapping_path = os.path.join(base_path, "mitre_ics_mapping.json")
                if os.path.exists(mapping_path):
                    with open(mapping_path, "r") as f:
                        mapping = json.load(f)
                        weight = mapping.get("T0846", {}).get("threat_weight", 50)
            except Exception:
                pass
            threat_queue.put((packet[IP].src, "T0846", "Discovery", weight))
    except Exception:
        pass

# ── OT Protocol Fingerprints ──────────────────────────────────────────────────

OT_PROTOCOLS = {
    502:   "modbus",
    20000: "dnp3",
    44818: "ethernet_ip",
    4840:  "opc_ua",
    47808: "bacnet",
    102:   "s7comm",
}

ETHER_TYPE_PROFINET = 0x8892

# Well-known insecure ports
INSECURE_PORTS = {23, 80, 161, 502, 20000, 47808}   # telnet, http, snmpv1/2, modbus, dnp3, bacnet
SECURE_PORTS   = {22, 443, 4840, 8443}               # ssh, https, opc-ua (TLS), alt-https


def _classify_protocol_security(port: int) -> str:
    if port in INSECURE_PORTS:
        return "insecure"
    if port in SECURE_PORTS:
        return "secure"
    return "unknown"

# Rate Limiter Maps
global_port_scans = {}
asset_packet_counts = {}

def check_port_scan(src_ip: str, dst_port: int, ts) -> bool:
    if src_ip not in global_port_scans:
        global_port_scans[src_ip] = {"ports": {dst_port}, "ts": ts}
        return False
    state = global_port_scans[src_ip]
    if (ts - state["ts"]).total_seconds() < 5.0:
        state["ports"].add(dst_port)
        if len(state["ports"]) > 10:
            return True
    else:
        global_port_scans[src_ip] = {"ports": {dst_port}, "ts": ts}
    return False

# ── Live Sniffer (Scapy) ──────────────────────────────────────────────────────

async def start_live_sniffer(on_packet: Callable) -> None:
    """Start Scapy sniffer on the configured interface (blocking in thread)."""
    try:
        from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, Ether, SNMP
    except ImportError:
        logger.warning("Scapy not installed – falling back to simulation mode")
        return

    iface = settings.SNIFF_INTERFACE
    if not iface:
        logger.info("No SNIFF_INTERFACE configured – skipping live capture")
        return

    def _callback(pkt):
        process_threats(pkt)
        record = None
        ts = datetime.datetime.utcnow()

        # Identify Vendor via MAC OUI
        vendor = "unknown"
        src_mac = pkt.src if pkt.haslayer("Ether") else ""
        out_mac = pkt.dst if pkt.haslayer("Ether") else ""
        if src_mac:
            oui = src_mac.replace(":", "").replace("-", "")[:6].lower()
            vendor = data_manager.lookup_vendor(oui)

        src_ip_str = pkt[IP].src if pkt.haslayer(IP) else "unknown"

        # OS Fingerprinting - limited to first 5 packets
        asset_packet_counts[src_ip_str] = asset_packet_counts.get(src_ip_str, 0) + 1
        if asset_packet_counts[src_ip_str] <= 5:
            dd_res = deep_discovery.analyze(pkt)
            os_type = dd_res["os_type"]
            os_confidence = dd_res["confidence"]
            device_category_override = dd_res["device_category"]
            criticality_override = dd_res["criticality_override"]
        else:
            os_type, os_confidence, device_category_override, criticality_override = "unknown", 0.0, None, None

        # Layer-2 Profinet
        if pkt.haslayer(Ether) and pkt[Ether].type == ETHER_TYPE_PROFINET:
            record = {
                "src_ip": "",
                "dst_ip": "",
                "src_mac": src_mac,
                "dst_mac": out_mac,
                "vendor": vendor,
                "os_type": "vxworks", # Profinet relies on RTOS
                "protocol": "profinet",
                "port": None,
                "payload_sig": "ether_type_0x8892",
                "is_encrypted": False,
                "timestamp": ts,
            }

        # IP-based OT protocols
        elif pkt.haslayer(IP):
            sport = dport = None
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            # Debug Sniffer Print
            print(f"[DEBUG] Packet received from {pkt[IP].src} on port {dport or sport}")

            proto_name = OT_PROTOCOLS.get(dport, OT_PROTOCOLS.get(sport))
            
            # Deep Packet Inspection - Extracting Telemetry
            firmware_ver = ""
            hardware_mod = ""
            payload_sig_ext = ""

            # Check for SNMP sysDescr (1.3.6.1.2.1.1.1.0)
            if pkt.haslayer(SNMP):
                try:
                    for varbind in pkt[SNMP].PDUvarbinds:
                        oid = varbind.oid.val
                        if getattr(varbind, "value", None) and hasattr(varbind.value, "val"):
                            if oid.startswith("1.3.6.1.2.1.1.1"):
                                val = varbind.value.val
                                if isinstance(val, bytes):
                                    val_str = val.decode(errors='ignore')
                                    payload_sig_ext = f"SNMP_sysDescr:{val_str[:20]}"
                                    if "v" in val_str.lower():
                                        firmware_ver = val_str
                except Exception:
                    pass

                # Rule (T0812) - Credential Bruteforce check
                try:
                    if hasattr(pkt[SNMP], "community") and pkt[SNMP].community and hasattr(pkt[SNMP].community, "val"):
                        community = pkt[SNMP].community.val.decode('utf-8', errors='ignore')
                        src_ip_str = pkt[IP].src if pkt.haslayer(IP) else ""
                        if community in ["public", "private"] and src_ip_str.split('.')[0] not in ["10", "192", "172"]:
                            record["active_threat"] = "T0812"
                            record["threat_desc"] = f"SNMP community bruteforce attempt with string '{community}'."
                except Exception:
                    pass

            # Check for ENIP / CIP
            if proto_name == "ethernet_ip" and pkt.haslayer(TCP) and pkt.haslayer("Raw"):
                raw_data = bytes(pkt["Raw"].load)
                # Extremely primitive CIP signature match looking for ListIdentity responses
                if len(raw_data) > 24 and raw_data[0] == 0x63: # ListIdentity Command
                    payload_sig_ext = "CIP_ListIdentity"
                    # In a real scenario, we'd parse the CIP Item Data for product name / revision
                    # For this demo, if it's a CIP Identity response, we flag it.
                    hardware_mod = "Extracted via CIP"
                
                # Check for CVE-2024-6242 (Forward Open with deep path)
                if len(raw_data) > 40 and raw_data[0] == 0x54:  # Forward Open
                    # simplistic check for path size > 2 words (just simulation logic)
                    path_size_offset = 34
                    if len(raw_data) > path_size_offset and raw_data[path_size_offset] > 2:
                        record["cip_path_depth"] = raw_data[path_size_offset]

            # Modbus / S7comm Mode monitoring (Phase 5)
            if proto_name == "modbus" and pkt.haslayer(TCP):
                if pkt.haslayer("Raw"):
                    raw_data = bytes(pkt["Raw"].load)
                    if len(raw_data) > 7 and raw_data[7] == 0x2B: # Example MEI type for mode change
                        record["plc_mode_change"] = "Remote Program"

            sig = f"{proto_name}_{dport}"
            if payload_sig_ext:
                sig += f" | {payload_sig_ext}"

            if proto_name:
                record = {
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "src_mac": src_mac,
                    "dst_mac": out_mac,
                    "vendor": vendor,
                    "os_type": os_type,
                    "os_confidence": os_confidence,
                    "device_category_override": device_category_override,
                    "criticality_override": criticality_override,
                    "protocol": proto_name,
                    "port": dport or sport,
                    "payload_sig": sig,
                    "firmware_extracted": firmware_ver,
                    "model_extracted": hardware_mod,
                    "is_encrypted": dport in SECURE_PORTS or sport in SECURE_PORTS,
                    "timestamp": ts,
                    "active_threat": record.get("active_threat") if "active_threat" in locals() else None,
                    "threat_desc": record.get("threat_desc") if "threat_desc" in locals() else ""
                }
                
                # Rule (T0846) - Discovery Array Limits
                if sport or dport:
                    if check_port_scan(pkt[IP].src, dport or sport, ts):
                        record["active_threat"] = "T0846"
                        record["threat_desc"] = "Port Scan activity detected. Target crossed threshold limit."

        if record and on_packet:
            on_packet(record)

    bpf = "tcp port 502 or tcp port 20000 or tcp port 44818 or tcp port 4840 or udp port 47808 or tcp port 102"
    logger.info("Starting live DPI on interface %s", iface)

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        lambda: scapy_sniff(iface=iface, filter=bpf, prn=_callback, store=0),
    )


# ── Simulation Mode ───────────────────────────────────────────────────────────

SIMULATED_DEVICES = [
    {"ip": "10.10.1.10", "mac": "00:1C:06:01:AA:01", "vendor": "Siemens",    "device_type": "plc",          "zone": "Process Control",   "iec": 1, "cpe": "cpe:2.3:h:siemens:s7-1500:-:*:*:*:*:*:*:*",       "criticality": 0.95, "eol": False},
    {"ip": "10.10.1.11", "mac": "00:1C:06:01:AA:02", "vendor": "Siemens",    "device_type": "plc",          "zone": "Process Control",   "iec": 1, "cpe": "cpe:2.3:h:siemens:s7-300:-:*:*:*:*:*:*:*",        "criticality": 0.90, "eol": True},
    {"ip": "10.10.1.20", "mac": "00:80:F4:02:BB:01", "vendor": "Rockwell",   "device_type": "plc",          "zone": "Process Control",   "iec": 1, "cpe": "cpe:2.3:h:rockwellautomation:controllogix:-:*:*:*:*:*:*:*", "criticality": 0.92, "eol": False},
    {"ip": "10.10.1.30", "mac": "00:0C:29:03:CC:01", "vendor": "Schneider",  "device_type": "plc",          "zone": "Process Control",   "iec": 1, "cpe": "cpe:2.3:h:schneider-electric:m340:-:*:*:*:*:*:*:*", "criticality": 0.88, "eol": False},
    {"ip": "10.10.2.10", "mac": "00:1C:06:04:DD:01", "vendor": "Siemens",    "device_type": "hmi",          "zone": "Supervisory",       "iec": 2, "cpe": "cpe:2.3:a:siemens:wincc:-:*:*:*:*:*:*:*",          "criticality": 0.65, "eol": False},
    {"ip": "10.10.2.11", "mac": "00:80:F4:05:EE:01", "vendor": "Rockwell",   "device_type": "hmi",          "zone": "Supervisory",       "iec": 2, "cpe": "cpe:2.3:a:rockwellautomation:factorytalk_view:-:*:*:*:*:*:*:*", "criticality": 0.60, "eol": False},
    {"ip": "10.10.2.20", "mac": "00:0C:29:06:FF:01", "vendor": "Wonderware", "device_type": "scada",        "zone": "Supervisory",       "iec": 2, "cpe": "cpe:2.3:a:aveva:wonderware:-:*:*:*:*:*:*:*",       "criticality": 0.75, "eol": True},
    {"ip": "10.10.3.10", "mac": "00:50:56:07:11:01", "vendor": "Dell",       "device_type": "ews",          "zone": "DMZ",               "iec": 3, "cpe": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",   "criticality": 0.40, "eol": False},
    {"ip": "10.10.3.11", "mac": "00:50:56:07:22:01", "vendor": "HP",         "device_type": "historian",    "zone": "DMZ",               "iec": 3, "cpe": "cpe:2.3:a:osisoft:pi_server:-:*:*:*:*:*:*:*",     "criticality": 0.55, "eol": False},
    {"ip": "10.10.3.20", "mac": "00:50:56:08:33:01", "vendor": "Cisco",      "device_type": "switch",       "zone": "DMZ",               "iec": 3, "cpe": "cpe:2.3:h:cisco:catalyst_2960:-:*:*:*:*:*:*:*",   "criticality": 0.50, "eol": False},
    {"ip": "10.10.4.10", "mac": "D4:BE:D9:09:44:01", "vendor": "Dell",       "device_type": "workstation",  "zone": "Enterprise",        "iec": 4, "cpe": "cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*",  "criticality": 0.20, "eol": False},
    {"ip": "10.10.4.11", "mac": "D4:BE:D9:09:55:01", "vendor": "Lenovo",     "device_type": "workstation",  "zone": "Enterprise",        "iec": 4, "cpe": "cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*",  "criticality": 0.15, "eol": False},
    {"ip": "10.10.0.5",  "mac": "00:1C:06:00:00:05", "vendor": "Honeywell",  "device_type": "safety_plc",   "zone": "Safety Instrumented","iec": 0, "cpe": "cpe:2.3:h:honeywell:safety_manager:-:*:*:*:*:*:*:*","criticality": 1.0,  "eol": False},
    {"ip": "10.10.1.40", "mac": "00:0C:29:0A:66:01", "vendor": "ABB",        "device_type": "plc",          "zone": "Process Control",   "iec": 1, "cpe": "cpe:2.3:h:abb:ac500:-:*:*:*:*:*:*:*",             "criticality": 0.85, "eol": False},
    {"ip": "10.10.2.30", "mac": "B4:A9:FC:0B:77:01", "vendor": "Unisoc",     "device_type": "iot_gateway",  "zone": "Supervisory",       "iec": 2, "cpe": "cpe:2.3:h:unisoc:t610:-:*:*:*:*:*:*:*",           "criticality": 0.70, "eol": False},
]

SIMULATED_TRAFFIC_PATTERNS = [
    ("10.10.1.10", "10.10.2.10", "s7comm",      102,   False),
    ("10.10.1.20", "10.10.2.11", "ethernet_ip", 44818, False),
    ("10.10.1.30", "10.10.2.20", "modbus",      502,   False),
    ("10.10.1.11", "10.10.2.10", "s7comm",      102,   False),
    ("10.10.1.40", "10.10.2.20", "modbus",      502,   False),
    ("10.10.2.30", "10.10.3.10", "opc_ua",      4840,  True),    # cross-zone
    ("10.10.2.20", "10.10.4.10", "http",        80,    True),    # cross-zone, insecure
    ("10.10.0.5",  "10.10.1.10", "modbus",      502,   False),
    ("10.10.3.11", "10.10.2.20", "opc_ua",      4840,  True),    # cross-zone
    ("10.10.1.10", "10.10.1.20", "s7comm",      102,   False),
]


async def generate_simulated_traffic(on_packet: Callable, interval: float = 2.0) -> None:
    """Continuously emit synthetic OT traffic records for demo mode."""
    logger.info("Starting simulated DPI traffic generator (interval=%.1fs)", interval)
    while True:
        pattern = random.choice(SIMULATED_TRAFFIC_PATTERNS)
        record = {
            "src_ip":       pattern[0],
            "dst_ip":       pattern[1],
            "src_mac":      "",
            "dst_mac":      "",
            "vendor":       random.choice(["Siemens", "Rockwell", "Dell", "Unknown"]),
            "os_type":      random.choice(["windows", "linux", "vxworks"]),
            "protocol":     pattern[2],
            "port":         pattern[3],
            "payload_sig":  f"{pattern[2]}_{pattern[3]}",
            "is_encrypted": pattern[3] in SECURE_PORTS,
            "is_cross_zone": pattern[4],
            "timestamp":    datetime.datetime.utcnow(),
        }
        if on_packet:
            on_packet(record)
        await asyncio.sleep(interval + random.uniform(-0.5, 0.5))
