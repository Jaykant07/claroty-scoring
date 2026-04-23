import os
import gzip
import sqlite3
import logging
import httpx
import xml.etree.ElementTree as ET

logger = logging.getLogger("claroty.cpe_indexer")

def build_cpe_index_db(db_path: str):
    logger.info("Initializing CPE Dictionary FTS5 Index build...")
    url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
    gz_path = db_path + ".gz"
    
    try:
        # Download the XML stream using basic httpx.Client avoiding full memory buffering
        with httpx.Client(timeout=120.0) as client:
            with client.stream("GET", url, follow_redirects=True) as response:
                if response.status_code == 200:
                    with open(gz_path, "wb") as f:
                        for chunk in response.iter_bytes():
                            f.write(chunk)
                else:
                    logger.warning(f"Download failed with status: {response.status_code}. Using built-in mock.")
                    _mock_cpe_db(db_path)
                    return
    except Exception as e:
        logger.error(f"Failed to fetch CPE dict: {e}")
        _mock_cpe_db(db_path)
        return

    # Parse and insert into SQLite FTS5 organically
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TABLE IF EXISTS cpe_index")
    conn.execute("CREATE VIRTUAL TABLE cpe_index USING fts5(cpe_name, title)")
    
    try:
        count = 0
        batch_data = []
        with gzip.open(gz_path, 'rt', encoding='utf-8') as f:
            context = ET.iterparse(f, events=('end',))
            for event, elem in context:
                if elem.tag.endswith('cpe-item'):
                    cpe_name = elem.attrib.get('name', '')
                    title = ""
                    for child in elem:
                        if child.tag.endswith('title'):
                            title = child.text
                            break
                    if cpe_name and title:
                        batch_data.append((cpe_name, title))
                        count += 1
                        
                    if len(batch_data) >= 10000:
                        conn.executemany("INSERT INTO cpe_index (cpe_name, title) VALUES (?, ?)", batch_data)
                        batch_data = []
                        
                    elem.clear() # Dump memory 
                    
        if batch_data:
            conn.executemany("INSERT INTO cpe_index (cpe_name, title) VALUES (?, ?)", batch_data)
            
        conn.commit()
        logger.info(f"CPE FTS5 Indexing complete. Indexed {count} records mapping into {db_path}")
    except Exception as e:
        logger.error(f"Error parsing CPE XML matrix: {e}")
        conn.rollback()
    finally:
        conn.close()
        if os.path.exists(gz_path):
            os.remove(gz_path)

def _mock_cpe_db(db_path: str):
    logger.info("Initializing fallback CPE Database (Offline Simulation Mode).")
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("DROP TABLE IF EXISTS cpe_index")
        conn.execute("CREATE VIRTUAL TABLE cpe_index USING fts5(cpe_name, title)")
        conn.executemany("INSERT INTO cpe_index (cpe_name, title) VALUES (?, ?)", [
            ("cpe:2.3:o:siemens:s7-1200_firmware:-:*:*:*:*:*:*:*", "Siemens S7-1200 Firmware"),
            ("cpe:2.3:o:schneider-electric:modicon_m340_firmware:-:*:*:*:*:*:*:*", "Schneider Electric Modicon M340 Firmware"),
            ("cpe:2.3:o:rockwellautomation:controllogix_5580_firmware:-:*:*:*:*:*:*:*", "Rockwell Automation ControlLogix 5580 Firmware"),
            ("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", "Palo Alto Networks PAN-OS"),
            ("cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", "Cisco IOS"),
        ])
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"CPE Mock DB collision error: {e}")
