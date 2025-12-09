#!/usr/bin/env python3
"""
Device Fingerprinting and Vulnerability Lookup (OpenVAS-style)
Matches devices against known signatures and generates CPE (Common Platform Enumeration) identifiers
"""
import re
import json
import os
import urllib.request
import urllib.parse

# Device signature database (can be extended)
DEVICE_SIGNATURES = {
    # OT/ICS Devices
    "schneider_modicon": {
        "vendor": "Schneider Electric",
        "models": ["Modicon M340", "Modicon M580", "Modicon Quantum"],
        "patterns": [
            r"Schneider\s+Electric",
            r"Modicon\s+M\d+",
            r"Unity\s+Pro",
        ],
        "cpe_prefix": "cpe:2.3:h:schneider-electric:modicon"
    },
    "siemens_s7": {
        "vendor": "Siemens",
        "models": ["SIMATIC S7-1200", "SIMATIC S7-1500", "SIMATIC S7-300", "SIMATIC S7-400"],
        "patterns": [
            r"Siemens",
            r"SIMATIC\s+S7",
            r"S7-\d+",
        ],
        "cpe_prefix": "cpe:2.3:h:siemens:simatic_s7"
    },
    "rockwell_ab": {
        "vendor": "Rockwell Automation",
        "models": ["Allen-Bradley", "ControlLogix", "CompactLogix"],
        "patterns": [
            r"Allen.?Bradley",
            r"Rockwell",
            r"ControlLogix",
            r"CompactLogix",
        ],
        "cpe_prefix": "cpe:2.3:h:rockwell:"
    },
    "abb_plc": {
        "vendor": "ABB",
        "models": ["AC500", "AC800M"],
        "patterns": [
            r"ABB\s+AC\d+",
            r"AC500",
            r"AC800M",
        ],
        "cpe_prefix": "cpe:2.3:h:abb:"
    },
    # Network Equipment
    "cisco": {
        "vendor": "Cisco",
        "models": ["IOS", "Catalyst", "ASA"],
        "patterns": [
            r"Cisco\s+IOS",
            r"Cisco\s+ASA",
            r"cisco",
        ],
        "cpe_prefix": "cpe:2.3:h:cisco:"
    },
    # Web Servers
    "apache": {
        "vendor": "Apache Software Foundation",
        "models": ["Apache HTTP Server"],
        "patterns": [
            r"Apache/(\d+\.\d+(?:\.\d+)?)",
        ],
        "cpe_prefix": "cpe:2.3:a:apache:http_server"
    },
    "nginx": {
        "vendor": "Nginx",
        "models": ["nginx"],
        "patterns": [
            r"nginx/(\d+\.\d+(?:\.\d+)?)",
        ],
        "cpe_prefix": "cpe:2.3:a:nginx:nginx"
    },
    "iis": {
        "vendor": "Microsoft",
        "models": ["Internet Information Services"],
        "patterns": [
            r"Microsoft-IIS/(\d+\.\d+)",
        ],
        "cpe_prefix": "cpe:2.3:a:microsoft:iis"
    },
}

def extract_version_from_string(text, pattern=None):
    """Extract version number from text"""
    if not text:
        return None
    
    text_str = str(text)
    
    # Common version patterns
    version_patterns = [
        r'[vV](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
        r'Version[:\s]+(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
        r'/(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
        r'(\d+\.\d+\.\d+\.\d+)',  # IP-like versions
        r'(\d+\.\d+\.\d+)',
        r'(\d+\.\d+)',
    ]
    
    if pattern:
        version_patterns.insert(0, pattern)
    
    for pattern in version_patterns:
        match = re.search(pattern, text_str)
        if match:
            return match.group(1)
    
    return None

def match_device_signature(text, source_type="http_server"):
    """Match text against device signatures"""
    if not text:
        return None
    
    text_str = str(text).lower()
    matches = []
    
    for device_id, signature in DEVICE_SIGNATURES.items():
        for pattern in signature["patterns"]:
            if re.search(pattern, text_str, re.IGNORECASE):
                matches.append({
                    "device_id": device_id,
                    "vendor": signature["vendor"],
                    "models": signature["models"],
                    "cpe_prefix": signature["cpe_prefix"],
                    "matched_pattern": pattern,
                    "source": source_type
                })
                break
    
    return matches[0] if matches else None

def generate_cpe(vendor, product, version=None):
    """Generate CPE 2.3 string"""
    # Normalize vendor and product names for CPE
    vendor_norm = re.sub(r'[^a-zA-Z0-9]', '_', vendor.lower())
    product_norm = re.sub(r'[^a-zA-Z0-9]', '_', product.lower())
    
    cpe = f"cpe:2.3:h:{vendor_norm}:{product_norm}"
    if version:
        version_norm = re.sub(r'[^a-zA-Z0-9._-]', '', str(version))
        cpe += f":{version_norm}"
    
    return cpe

def fingerprint_device(http_server=None, snmp_sysdescr=None, ssh_version=None, 
                       user_agent=None, modbus_func=None, s7comm_func=None):
    """Fingerprint device from multiple sources (OpenVAS-style)"""
    fingerprints = []
    vendor = None
    product = None
    version = None
    cpe = None
    
    # Try HTTP Server header first (most common for web-accessible devices)
    if http_server:
        match = match_device_signature(http_server, "http_server")
        if match:
            fingerprints.append(match)
            vendor = match["vendor"]
            product = match["models"][0] if match["models"] else "Unknown"
            version = extract_version_from_string(http_server)
            if match["cpe_prefix"]:
                cpe = f"{match['cpe_prefix']}:{version}" if version else match["cpe_prefix"]
    
    # Try SNMP sysDescr (very reliable for OT devices)
    if snmp_sysdescr and not vendor:
        match = match_device_signature(snmp_sysdescr, "snmp")
        if match:
            fingerprints.append(match)
            vendor = match["vendor"]
            product = match["models"][0] if match["models"] else "Unknown"
            version = extract_version_from_string(snmp_sysdescr)
            if match["cpe_prefix"]:
                cpe = f"{match['cpe_prefix']}:{version}" if version else match["cpe_prefix"]
    
    # Try SSH version
    if ssh_version and not vendor:
        # SSH versions often indicate OS, but can also indicate device type
        ssh_str = str(ssh_version).lower()
        if "openssh" in ssh_str:
            vendor = "OpenSSH"
            product = "OpenSSH"
            version = extract_version_from_string(ssh_version)
            cpe = generate_cpe("openssh", "openssh", version)
    
    # Protocol-based inference (OT devices)
    if modbus_func and not vendor:
        vendor = "Modbus Device"
        product = "Modbus/TCP Device"
        cpe = "cpe:2.3:a:modbus:modbus"
    
    if s7comm_func and not vendor:
        vendor = "Siemens"
        product = "SIMATIC S7"
        cpe = "cpe:2.3:h:siemens:simatic_s7"
    
    # Try user agent
    if user_agent and not vendor:
        match = match_device_signature(user_agent, "user_agent")
        if match:
            fingerprints.append(match)
            if not vendor:
                vendor = match["vendor"]
                product = match["models"][0] if match["models"] else "Unknown"
                version = extract_version_from_string(user_agent)
                if match["cpe_prefix"]:
                    cpe = f"{match['cpe_prefix']}:{version}" if version else match["cpe_prefix"]
    
    return {
        "vendor": vendor,
        "product": product,
        "version": version,
        "cpe": cpe,
        "fingerprints": fingerprints,
        "confidence": "high" if len(fingerprints) > 1 else "medium" if vendor else "low"
    }

def lookup_cve(cpe=None, vendor=None, product=None, version=None):
    """Lookup CVE information (simplified - would need NVD API key for full functionality)"""
    if not cpe and not (vendor and product):
        return None
    
    # This is a placeholder - in production, you'd query NVD API or local CVE database
    # For now, return a note that CVE lookup would be performed
    return {
        "cpe": cpe,
        "note": "CVE lookup requires NVD API access or local CVE database",
        "cve_count": None
    }

if __name__ == "__main__":
    # Test the fingerprinting
    test_cases = [
        {"http_server": "Apache/2.4.41 (Ubuntu)"},
        {"http_server": "nginx/1.18.0"},
        {"snmp_sysdescr": "Schneider Electric Modicon M340 Firmware v2.4.1"},
        {"ssh_version": "SSH-2.0-OpenSSH_8.2"},
    ]
    
    for test in test_cases:
        result = fingerprint_device(**test)
        print(f"Input: {test}")
        print(f"Result: {result}")
        print()


