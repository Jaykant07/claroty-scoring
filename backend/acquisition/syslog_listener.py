"""
Syslog Listener — UDP socket receiver for RFC 5424 syslog messages.

Classifies events into: admin_login, firewall_deny, config_change, auth_failure.
In simulation mode generates synthetic security-relevant events.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import random
import re

from backend.config import settings

logger = logging.getLogger("claroty.syslog")

# ── Event classification patterns ──────────────────────────────────────────────

EVENT_PATTERNS = [
    (re.compile(r"login|session opened|accepted\s+password", re.I), "admin_login"),
    (re.compile(r"denied|blocked|drop|reject|firewall", re.I),      "firewall_deny"),
    (re.compile(r"config|changed|modified|updated|write mem", re.I), "config_change"),
    (re.compile(r"failed|invalid|unauthorized|bad password", re.I),  "auth_failure"),
]


def classify_event(message: str) -> str:
    """Classify a syslog message into an event type."""
    for pattern, event_type in EVENT_PATTERNS:
        if pattern.search(message):
            return event_type
    return "info"


# ── Live listener ──────────────────────────────────────────────────────────────

class SyslogProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol for receiving syslog datagrams."""

    def __init__(self, callback):
        self._callback = callback

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            message = data.decode("utf-8", errors="replace").strip()
            # Parse RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME ...
            # Simplified extraction
            severity = 6  # default INFO
            facility = 1
            if message.startswith("<"):
                end = message.index(">")
                pri = int(message[1:end])
                facility = pri >> 3
                severity = pri & 0x07
                message = message[end + 1:].strip()

            event = {
                "source_ip":  addr[0],
                "facility":   facility,
                "severity":   severity,
                "event_type": classify_event(message),
                "message":    message[:1024],
                "timestamp":  datetime.datetime.utcnow(),
            }
            if self._callback:
                self._callback(event)
        except Exception as exc:
            logger.debug("Failed to parse syslog from %s: %s", addr, exc)


async def start_syslog_listener(callback) -> None:
    """Start a UDP syslog listener."""
    port = settings.SYSLOG_PORT
    logger.info("Starting syslog listener on UDP port %d", port)
    loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(callback),
        local_addr=("0.0.0.0", port),
    )


# ── Simulation mode ───────────────────────────────────────────────────────────

_SIM_MESSAGES = [
    ("<134>1 admin login accepted on console port",             "10.10.3.20"),
    ("<131>1 Firewall DENY TCP 10.10.2.30 -> 8.8.8.8:443",     "10.10.3.20"),
    ("<133>1 Configuration changed by admin@10.10.3.10",        "10.10.2.20"),
    ("<131>1 Failed password for root from 10.10.4.10",         "10.10.2.10"),
    ("<134>1 Session opened for user operator on HMI",          "10.10.2.10"),
    ("<131>1 Blocked Modbus write from 10.10.4.10 to 10.10.1.10", "10.10.3.20"),
    ("<133>1 PLC program download detected on S7-1500",         "10.10.1.10"),
    ("<131>1 Unauthorized access attempt to Safety Manager",    "10.10.0.5"),
    ("<134>1 Firmware update initiated on Catalyst switch",     "10.10.3.20"),
    ("<131>1 Deny cross-zone traffic 10.10.2.30 -> 10.10.1.10", "10.10.3.20"),
]


async def generate_simulated_syslog(callback, interval: float = 5.0) -> None:
    """Emit synthetic syslog events for demo mode."""
    logger.info("Starting simulated syslog generator")
    while True:
        msg, src = random.choice(_SIM_MESSAGES)
        severity = 6
        facility = 1
        event_type = classify_event(msg)
        if msg.startswith("<"):
            end = msg.index(">")
            pri = int(msg[1:end])
            facility = pri >> 3
            severity = pri & 0x07

        event = {
            "source_ip":  src,
            "facility":   facility,
            "severity":   severity,
            "event_type": event_type,
            "message":    msg,
            "timestamp":  datetime.datetime.utcnow(),
        }
        if callback:
            callback(event)
        await asyncio.sleep(interval + random.uniform(-1, 2))
