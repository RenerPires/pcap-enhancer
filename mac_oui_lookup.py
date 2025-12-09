#!/usr/bin/env python3
"""
MAC OUI Vendor Lookup
Downloads and caches IEEE OUI database for vendor name resolution
"""
import os
import re
import urllib.request
import json

OUI_DB_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_DB_URL_ALT = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
OUI_CACHE_FILE = "/tmp/oui_db.json"

def download_oui_database():
    """Download IEEE OUI database and parse into dictionary"""
    print("Downloading IEEE OUI database...")
    oui_db = {}
    
    # Try primary URL first
    try:
        with urllib.request.urlopen(OUI_DB_URL, timeout=30) as response:
            for line in response:
                line = line.decode('utf-8', errors='ignore').strip()
                # OUI format: XX-XX-XX   (hex)     Vendor Name
                match = re.match(r'^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$', line)
                if match:
                    oui = f"{match.group(1)}{match.group(2)}{match.group(3)}".upper()
                    vendor = match.group(4).strip()
                    oui_db[oui] = vendor
        
        # Cache the database
        with open(OUI_CACHE_FILE, 'w') as f:
            json.dump(oui_db, f)
        print(f"Downloaded {len(oui_db)} OUI entries")
        return oui_db
    except Exception as e:
        print(f"Warning: Could not download from primary URL: {e}")
        # Try alternative Wireshark manuf file
        try:
            print("Trying alternative OUI source (Wireshark manuf)...")
            with urllib.request.urlopen(OUI_DB_URL_ALT, timeout=30) as response:
                for line in response:
                    line = line.decode('utf-8', errors='ignore').strip()
                    if line.startswith('#') or not line:
                        continue
                    # Wireshark manuf format: OUI TAB Vendor
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        oui_part = parts[0].strip().replace(':', '').replace('-', '').upper()
                        if len(oui_part) == 6:
                            vendor = parts[1].strip()
                            oui_db[oui_part] = vendor
            
            if oui_db:
                with open(OUI_CACHE_FILE, 'w') as f:
                    json.dump(oui_db, f)
                print(f"Downloaded {len(oui_db)} OUI entries from alternative source")
                return oui_db
        except Exception as e2:
            print(f"Warning: Could not download OUI database from alternative source: {e2}")
            return {}

def load_oui_database():
    """Load OUI database from cache or download"""
    # Try to load from cache first
    if os.path.exists(OUI_CACHE_FILE):
        try:
            with open(OUI_CACHE_FILE, 'r') as f:
                oui_db = json.load(f)
                print(f"Loaded {len(oui_db)} OUI entries from cache")
                return oui_db
        except:
            pass
    
    # Download if cache doesn't exist
    return download_oui_database()

def lookup_mac_vendor(mac_address, oui_db):
    """Lookup vendor name from MAC address"""
    try:
        import pandas as pd
    except ImportError:
        pd = None
    
    if not mac_address:
        return None
    if pd and pd.isna(mac_address):
        return None
    
    mac_str = str(mac_address).upper().replace(':', '').replace('-', '').replace('.', '')
    
    # Extract OUI (first 6 hex characters)
    if len(mac_str) >= 6:
        oui = mac_str[:6]
        return oui_db.get(oui, None)
    return None

def lookup_oui_vendor(oui_value, oui_db):
    """Lookup vendor name from OUI value (hex string)"""
    try:
        import pandas as pd
    except ImportError:
        pd = None
    
    if not oui_value:
        return None
    if pd and pd.isna(oui_value):
        return None
    
    oui_str = str(oui_value).upper().replace(':', '').replace('-', '').replace('.', '')
    
    # OUI might be in format like "00:11:22" or "001122" or just "001122"
    if len(oui_str) >= 6:
        oui = oui_str[:6]
        return oui_db.get(oui, None)
    return None

if __name__ == "__main__":
    # Test the lookup
    import sys
    if len(sys.argv) > 1:
        oui_db = load_oui_database()
        mac = sys.argv[1]
        vendor = lookup_mac_vendor(mac, oui_db)
        print(f"MAC: {mac} -> Vendor: {vendor}")

