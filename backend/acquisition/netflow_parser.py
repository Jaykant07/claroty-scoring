"""
NetFlow / IPFIX Parser — flow record ingestion and cross-zone detection.

Listens for NetFlow v5 or IPFIX data on a configurable UDP port.
In simulation mode generates synthetic flow records that demonstrate
cross-zone communication and traffic volume patterns.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import random
import struct

from backend.config import settings

logger = logging.getLogger("claroty.netflow")


# ── NetFlow v5 header / record structs ─────────────────────────────────────────

NETFLOW_V5_HEADER = struct.Struct("!HHIIIIBBH")   # 24 bytes
NETFLOW_V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")  # 48 bytes


def parse_netflow_v5(data: bytes) -> list[dict]:
    """Parse a NetFlow v5 datagram into a list of flow dicts."""
    if len(data) < 24:
        return []
    version, count = struct.unpack_from("!HH", data, 0)
    if version != 5:
        return []
    records = []
    offset = 24
    for _ in range(min(count, 30)):  # cap at 30 per datagram
        if offset + 48 > len(data):
            break
        fields = NETFLOW_V5_RECORD.unpack_from(data, offset)
        # fields[0]=srcaddr, [1]=dstaddr, ...
        import socket
        src_ip = socket.inet_ntoa(struct.pack("!I", fields[0]))
        dst_ip = socket.inet_ntoa(struct.pack("!I", fields[1]))
        records.append({
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "src_port":     fields[10],
            "dst_port":     fields[11],
            "protocol_num": fields[13],
            "bytes_sent":   fields[5],
            "packets":      fields[4],
            "duration_ms":  fields[7] - fields[6] if fields[7] > fields[6] else 0,
            "timestamp":    datetime.datetime.utcnow(),
        })
        offset += 48
    return records


class NetFlowProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol for receiving NetFlow datagrams."""

    def __init__(self, callback):
        self._callback = callback

    def datagram_received(self, data: bytes, addr: tuple):
        records = parse_netflow_v5(data)
        for rec in records:
            if self._callback:
                self._callback(rec)


async def start_netflow_listener(callback) -> None:
    """Start a UDP NetFlow listener."""
    port = settings.NETFLOW_PORT
    logger.info("Starting NetFlow listener on UDP port %d", port)
    loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(
        lambda: NetFlowProtocol(callback),
        local_addr=("0.0.0.0", port),
    )


# ── Simulation mode ───────────────────────────────────────────────────────────

_SIM_FLOWS = [
    ("10.10.1.10", "10.10.2.10", 102,  6,  False),   # S7comm intra-zone
    ("10.10.1.20", "10.10.2.11", 44818, 6, False),   # EtherNet/IP
    ("10.10.1.30", "10.10.2.20", 502,   6, False),   # Modbus
    ("10.10.2.30", "10.10.3.10", 4840,  6, True),    # OPC-UA cross-zone
    ("10.10.2.20", "10.10.4.10", 80,    6, True),    # HTTP cross-zone
    ("10.10.0.5",  "10.10.1.10", 502,   6, False),   # Safety → Process
    ("10.10.3.11", "10.10.2.20", 4840,  6, True),    # Historian cross-zone
    ("10.10.4.10", "10.10.1.10", 502,   6, True),    # Enterprise→Process (bad!)
    ("10.10.1.10", "10.10.1.20", 102,   6, False),   # PLC-to-PLC
]


async def generate_simulated_netflow(callback, interval: float = 3.0) -> None:
    """Emit synthetic NetFlow records for demo mode."""
    logger.info("Starting simulated NetFlow generator")
    while True:
        flow_template = random.choice(_SIM_FLOWS)
        record = {
            "src_ip":       flow_template[0],
            "dst_ip":       flow_template[1],
            "src_port":     random.randint(1024, 65535),
            "dst_port":     flow_template[2],
            "protocol_num": flow_template[3],
            "bytes_sent":   random.randint(64, 150000),
            "packets":      random.randint(1, 500),
            "duration_ms":  random.randint(10, 60000),
            "is_cross_zone": flow_template[4],
            "timestamp":    datetime.datetime.utcnow(),
        }
        if callback:
            callback(record)
        await asyncio.sleep(interval + random.uniform(-1, 1.5))
