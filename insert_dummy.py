import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import select
from backend.database import async_session
from backend.models import Asset

async def insert_dummy():
    async with async_session() as session:
        # Create 5 dummy assets with no firmware/hostname
        dummy_assets = [
            Asset(ip="10.10.10.101", vendor="Siemens", device_type="PLC", protocol_security="insecure"),
            Asset(ip="10.10.10.102", vendor="Rockwell", device_type="PLC", protocol_security="insecure"),
            Asset(ip="10.10.10.103", vendor="Cisco", device_type="switch", protocol_security="secure"),
            Asset(ip="10.10.10.104", vendor="Dell", device_type="workstation", protocol_security="mixed"),
            Asset(ip="10.10.10.105", vendor="Schneider", device_type="RTU", protocol_security="insecure"),
        ]
        for a in dummy_assets:
            session.add(a)
        await session.commit()
        print("Inserted 5 undiscovered dummy assets for testing.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(insert_dummy())
