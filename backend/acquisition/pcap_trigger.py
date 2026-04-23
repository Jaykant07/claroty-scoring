"""
Targeted PCAP Capture (Phase 6)
Fired by the Rule Engine when a critical threshold > 0.9 is breached.
Captures an offending IP's traffic briefly for forensic review.
"""

import asyncio
import os
import logging
from backend.config import settings

logger = logging.getLogger("claroty.pcap")

# Semaphore to prevent capturing too many pcaps at once
_pcap_lock = asyncio.Lock()

async def capture_pcap_task(target_ip: str, duration_sec: int = 10):
    if _pcap_lock.locked():
        logger.warning(f"PCAP capture already running. Skipping targeted capture for {target_ip}.")
        return

    async with _pcap_lock:
        try:
            from scapy.all import sniff, wrpcap
        except ImportError:
            logger.error("Scapy missing. Cannot capture PCAP.")
            return

        iface = settings.SNIFF_INTERFACE
        if not iface:
            return

        os.makedirs("pcaps", exist_ok=True)
        filename = f"pcaps/forensics_{target_ip.replace('.', '_')}_{int(asyncio.get_event_loop().time())}.pcap"
        
        # BPF filter to only grab traffic relating to the offending IP to stay lightweight
        bpf_filter = f"host {target_ip}"
        
        logger.warning(f"[FORENSICS] Critical Alert on {target_ip}. Triggering {duration_sec}s targeted PCAP capture on {iface}...")

        def _sniff_sync():
            # Returns a PacketList
            return sniff(iface=iface, filter=bpf_filter, timeout=duration_sec)

        loop = asyncio.get_event_loop()
        packets = await loop.run_in_executor(None, _sniff_sync)

        if packets:
            wrpcap(filename, packets)
            logger.warning(f"[FORENSICS] Captured {len(packets)} packets. Saved to {filename}")
        else:
            logger.info(f"[FORENSICS] PCAP triggered but no packets caught for {target_ip} in {duration_sec}s window.")
