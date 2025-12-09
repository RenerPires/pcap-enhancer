#!/usr/bin/env python3
import sys
import os
import pandas as pd
import re
import urllib.request
import json

# Import MAC OUI lookup functions
try:
    from mac_oui_lookup import load_oui_database, lookup_mac_vendor, lookup_oui_vendor
except ImportError:
    # Fallback if mac_oui_lookup.py is not in path
    OUI_CACHE_FILE = "/tmp/oui_db.json"
    
    def load_oui_database():
        """Load OUI database from cache"""
        if os.path.exists(OUI_CACHE_FILE):
            try:
                with open(OUI_CACHE_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def lookup_mac_vendor(mac_address, oui_db):
        """Lookup vendor name from MAC address"""
        if not mac_address or pd.isna(mac_address):
            return None
        mac_str = str(mac_address).upper().replace(':', '').replace('-', '').replace('.', '')
        if len(mac_str) >= 6:
            oui = mac_str[:6]
            return oui_db.get(oui, None)
        return None
    
    def lookup_oui_vendor(oui_value, oui_db):
        """Lookup vendor name from OUI value"""
        if not oui_value or pd.isna(oui_value):
            return None
        oui_str = str(oui_value).upper().replace(':', '').replace('-', '').replace('.', '')
        if len(oui_str) >= 6:
            oui = oui_str[:6]
            return oui_db.get(oui, None)
        return None

def load_csv(path):
    if os.path.isfile(path):
        try:
            df = pd.read_csv(path)
            # Check if the CSV is empty (only headers or completely empty)
            if df.empty or (len(df.columns) == 0):
                return pd.DataFrame()
            return df
        except (pd.errors.EmptyDataError, pd.errors.ParserError):
            # File exists but is empty or malformed
            return pd.DataFrame()
    return pd.DataFrame()

def load_zeek_log(path, sep="\t"):
    if os.path.isfile(path):
        df = pd.read_csv(path, sep=sep, comment="#", low_memory=False)
        return df
    return pd.DataFrame()

def load_p0f(path):
    if not os.path.isfile(path):
        return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "mod=cli" in line:
                continue
            if "status: up" in line:
                continue
            if "->" in line and "os=" in line:
                parts = line.split()
                src_ip = None
                os_guess = None
                for i, p in enumerate(parts):
                    if p == "src":
                        if i + 1 < len(parts):
                            src_ip = parts[i + 1].split("/")[0]
                    if p.startswith("os="):
                        os_guess = p.split("=", 1)[1]
                if src_ip is not None and os_guess is not None:
                    rows.append({"ip": src_ip, "os_guess": os_guess})
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df = df.groupby("ip")["os_guess"].apply(lambda x: "; ".join(sorted(set(x)))).reset_index()
    return df

def main():
    if len(sys.argv) < 2:
        print("Usage: enrich_pcap.py <output-dir-from-analyze_pcap>")
        sys.exit(1)

    out_dir = sys.argv[1]
    if not os.path.isdir(out_dir):
        print(f"Directory not found: {out_dir}")
        sys.exit(1)

    flows = load_csv(os.path.join(out_dir, "flows.csv"))
    dhcp_vendors = load_csv(os.path.join(out_dir, "dhcp_vendors.csv"))
    http_req = load_csv(os.path.join(out_dir, "http_requests.csv"))
    dns = load_csv(os.path.join(out_dir, "dns_queries.csv"))

    # OT protocol CSVs
    modbus = load_csv(os.path.join(out_dir, "modbus.csv"))
    opcua = load_csv(os.path.join(out_dir, "opcua.csv"))
    dnp3 = load_csv(os.path.join(out_dir, "dnp3.csv"))
    iec104 = load_csv(os.path.join(out_dir, "iec104.csv"))
    s7comm = load_csv(os.path.join(out_dir, "s7comm.csv"))

    zeek_dir = os.path.join(out_dir, "zeek")
    zeek_conn = load_zeek_log(os.path.join(zeek_dir, "conn.log"))
    zeek_http = load_zeek_log(os.path.join(zeek_dir, "http.log"))
    zeek_ssl = load_zeek_log(os.path.join(zeek_dir, "ssl.log"))
    zeek_dhcp = load_zeek_log(os.path.join(zeek_dir, "dhcp.log"))
    zeek_ssh = load_zeek_log(os.path.join(zeek_dir, "ssh.log"))
    zeek_snmp = load_zeek_log(os.path.join(zeek_dir, "snmp.log"))
    
    # Zeek OT logs (if ICS analyzers are enabled)
    zeek_modbus = load_zeek_log(os.path.join(zeek_dir, "modbus.log"))
    zeek_dnp3 = load_zeek_log(os.path.join(zeek_dir, "dnp3.log"))

    p0f_df = load_p0f(os.path.join(out_dir, "p0f.log"))
    
    # Device identification sources
    ssh_banners = load_csv(os.path.join(out_dir, "ssh_banners.csv"))
    snmp_details = load_csv(os.path.join(out_dir, "snmp_details.csv"))
    http_response_headers = load_csv(os.path.join(out_dir, "http_response_headers.csv"))
    
    # Note: SSH and SNMP field names vary by Wireshark version
    # We'll rely more on Zeek logs for these
    
    # nDPI flows (deep packet inspection results)
    ndpi_flows = load_csv(os.path.join(out_dir, "ndpi_flows.csv"))
    
    # Import device fingerprinting (OpenVAS-style)
    try:
        from device_fingerprint import fingerprint_device, generate_cpe, extract_version_from_string
        DEVICE_FINGERPRINTING_AVAILABLE = True
    except ImportError:
        DEVICE_FINGERPRINTING_AVAILABLE = False
        print("Warning: device_fingerprint.py not available. Advanced device identification disabled.")
    
    # Try to load nDPI JSON if available (more detailed)
    ndpi_json_data = None
    ndpi_json_path = os.path.join(out_dir, "ndpi_flows.json")
    if os.path.isfile(ndpi_json_path):
        try:
            import json
            with open(ndpi_json_path, 'r') as f:
                ndpi_json_data = json.load(f)
        except:
            pass

    if flows.empty:
        print("flows.csv is empty or missing. Nothing to enrich.")
        sys.exit(0)

    # Load OUI database for MAC vendor lookup
    print("Loading MAC OUI vendor database...")
    oui_db = load_oui_database()
    if not oui_db:
        print("Warning: OUI database not available. Vendor names will not be resolved.")
        print("Run mac_oui_lookup.py to download the database.")

    src_cols = [
        "eth.src", "eth.src.oui", "ip.src",
        "tcp.srcport", "udp.srcport"
    ]
    dst_cols = [
        "eth.dst", "eth.dst.oui", "ip.dst",
        "tcp.dstport", "udp.dstport"
    ]
    for col in src_cols + dst_cols:
        if col not in flows.columns:
            flows[col] = None

    # Aggregate source hosts with MAC vendor lookup
    src_hosts_data = []
    for ip, group in flows.groupby("ip.src"):
        macs = "; ".join(sorted(set([str(v) for v in group["eth.src"] if pd.notna(v)])))
        oui_values = "; ".join(sorted(set([str(v) for v in group["eth.src.oui"] if pd.notna(v)])))
        
        # Lookup vendor names from MAC addresses and OUIs
        vendor_names = set()
        for mac in group["eth.src"].dropna():
            vendor = lookup_mac_vendor(mac, oui_db)
            if vendor:
                vendor_names.add(vendor)
        for oui in group["eth.src.oui"].dropna():
            vendor = lookup_oui_vendor(oui, oui_db)
            if vendor:
                vendor_names.add(vendor)
        vendor_names_str = "; ".join(sorted(vendor_names)) if vendor_names else None
        
        tcp_ports = "; ".join(sorted(set([str(int(v)) for v in group["tcp.srcport"] if pd.notna(v)]))) if group["tcp.srcport"].notna().any() else ""
        udp_ports = "; ".join(sorted(set([str(int(v)) for v in group["udp.srcport"] if pd.notna(v)]))) if group["udp.srcport"].notna().any() else ""
        
        # Determine device role (client vs server)
        # Client: uses ephemeral ports (>32768) or common client ports
        # Server: uses well-known ports (<1024) or common service ports
        tcp_port_list = [int(p) for p in group["tcp.srcport"].dropna() if pd.notna(p)]
        udp_port_list = [int(p) for p in group["udp.srcport"].dropna() if pd.notna(p)]
        all_ports = tcp_port_list + udp_port_list
        
        device_role = "Unknown"
        if all_ports:
            well_known_ports = [p for p in all_ports if p < 1024]
            ephemeral_ports = [p for p in all_ports if p > 32768]
            if len(well_known_ports) > len(ephemeral_ports):
                device_role = "Server"
            elif len(ephemeral_ports) > len(well_known_ports):
                device_role = "Client"
            else:
                device_role = "Mixed"
        
        src_hosts_data.append({
            "ip": ip,
            "macs": macs if macs else None,
            "mac_oui_prefixes": oui_values if oui_values else None,
            "mac_vendor_names": vendor_names_str,
            "tcp_ports": tcp_ports if tcp_ports else None,
            "udp_ports": udp_ports if udp_ports else None,
            "device_role": device_role
        })
    
    src_hosts = pd.DataFrame(src_hosts_data)

    dhcp_hosts = pd.DataFrame()
    if not dhcp_vendors.empty and "ip.src" in dhcp_vendors.columns:
        dhcp_hosts = dhcp_vendors.groupby("ip.src")["bootp.option.vendor_class_id"] \
            .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
            .reset_index().rename(columns={
                "ip.src": "ip",
                "bootp.option.vendor_class_id": "dhcp_vendor_class"
            })

    # Enhanced HTTP aggregation with application identification
    http_hosts = pd.DataFrame()
    if not http_req.empty and "ip.src" in http_req.columns:
        http_data = []
        for ip, group in http_req.groupby("ip.src"):
            user_agents = "; ".join(sorted(set([str(v) for v in group["http.user_agent"] if pd.notna(v)])))
            methods = "; ".join(sorted(set([str(v) for v in group["http.request.method"] if pd.notna(v)])))
            hosts = "; ".join(sorted(set([str(v) for v in group["http.host"] if pd.notna(v)])))
            uris = "; ".join(sorted(set([str(v) for v in group["http.request.uri"] if pd.notna(v)])))
            response_codes = "; ".join(sorted(set([str(int(v)) for v in group["http.response.code"] if pd.notna(v)])))
            content_types = "; ".join(sorted(set([str(v) for v in group["http.content_type"] if pd.notna(v)])))
            
            # Extract HTTP Server headers (device/firmware identification)
            server_headers = "; ".join(sorted(set([str(v) for v in group["http.server"] if pd.notna(v)])))
            
            # Extract X-Powered-By and other identifying headers
            x_powered_by = None
            if "http.x_powered_by" in group.columns:
                x_powered_by = "; ".join(sorted(set([str(v) for v in group["http.x_powered_by"] if pd.notna(v)])))
            
            # Application identification from user agents and hosts
            applications = set()
            firmware_versions = set()
            device_models = set()
            device_vendors = set()
            
            for ua in group["http.user_agent"].dropna():
                ua_str = str(ua)
                ua_lower = ua_str.lower()
                if "chrome" in ua_lower:
                    applications.add("Chrome Browser")
                elif "firefox" in ua_lower:
                    applications.add("Firefox Browser")
                elif "safari" in ua_lower and "chrome" not in ua_lower:
                    applications.add("Safari Browser")
                elif "edge" in ua_lower:
                    applications.add("Edge Browser")
                elif "curl" in ua_lower:
                    applications.add("curl")
                elif "wget" in ua_lower:
                    applications.add("wget")
                elif "python" in ua_lower:
                    applications.add("Python HTTP Client")
                elif "java" in ua_lower:
                    applications.add("Java HTTP Client")
                
                # Try to extract firmware/version from user agent
                # Common patterns: "Product/Version", "v1.2.3", "Version X.Y"
                import re
                version_patterns = [
                    r'[vV](\d+\.\d+(?:\.\d+)?)',
                    r'Version[:\s]+(\d+\.\d+(?:\.\d+)?)',
                    r'/(\d+\.\d+(?:\.\d+)?)',
                    r'(\d+\.\d+\.\d+)',
                ]
                for pattern in version_patterns:
                    match = re.search(pattern, ua_str)
                    if match:
                        firmware_versions.add(match.group(1))
                        break
            
            # Extract firmware from HTTP Server headers (common in OT devices)
            # Use device fingerprinting if available (OpenVAS-style)
            for server in group["http.server"].dropna():
                server_str = str(server)
                # Patterns like "Apache/2.4.41", "nginx/1.18.0", "DeviceName v1.2.3"
                import re
                version_match = re.search(r'[/\s]([vV]?)(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', server_str)
                if version_match:
                    firmware_versions.add(version_match.group(2))
                
                # Try device fingerprinting (OpenVAS-style)
                if DEVICE_FINGERPRINTING_AVAILABLE:
                    fingerprint = fingerprint_device(http_server=server_str)
                    if fingerprint and fingerprint.get("vendor"):
                        device_vendors.add(fingerprint["vendor"])
                        if fingerprint.get("product"):
                            device_models.add(fingerprint["product"])
                        if fingerprint.get("version"):
                            firmware_versions.add(fingerprint["version"])
                
                # Try to identify device model from server string
                server_lower = server_str.lower()
                if any(x in server_lower for x in ["schneider", "siemens", "rockwell", "allen-bradley", "abb", "omron"]):
                    # Extract model info
                    model_match = re.search(r'([A-Z]{2,}\d+[A-Z]?\d*)', server_str)
                    if model_match:
                        device_models.add(model_match.group(1))
            
            for host in group["http.host"].dropna():
                host_lower = str(host).lower()
                if "api" in host_lower:
                    applications.add("API Client")
                if "cloud" in host_lower or "aws" in host_lower or "azure" in host_lower:
                    applications.add("Cloud Service")
            
            applications_str = "; ".join(sorted(applications)) if applications else None
            firmware_str = "; ".join(sorted(firmware_versions)) if firmware_versions else None
            device_model_str = "; ".join(sorted(device_models)) if device_models else None
            device_vendor_str = "; ".join(sorted(device_vendors)) if device_vendors else None
            
            http_data.append({
                "ip": ip,
                "http_user_agents": user_agents if user_agents else None,
                "http_server_headers": server_headers if server_headers else None,
                "http_x_powered_by": x_powered_by if x_powered_by else None,
                "http_methods": methods if methods else None,
                "http_hosts": hosts if hosts else None,
                "http_uris": uris if uris else None,
                "http_response_codes": response_codes if response_codes else None,
                "http_content_types": content_types if content_types else None,
                "applications": applications_str,
                "firmware_versions": firmware_str,
                "device_models": device_model_str,
                "device_vendors_http": device_vendor_str
            })
        
        http_hosts = pd.DataFrame(http_data)

    dns_hosts = pd.DataFrame()
    if not dns.empty and "ip.src" in dns.columns:
        dns_hosts = dns.groupby("ip.src")["dns.qry.name"] \
            .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
            .reset_index().rename(columns={
                "ip.src": "ip",
                "dns.qry.name": "dns_queries"
            })

    # OT protocol host aggregations
    modbus_hosts = pd.DataFrame()
    if not modbus.empty and "ip.src" in modbus.columns and "modbus.func_code" in modbus.columns:
        modbus_hosts = modbus.groupby("ip.src")["modbus.func_code"] \
            .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
            .reset_index().rename(columns={
                "ip.src": "ip",
                "modbus.func_code": "modbus_func_codes"
            })

    opcua_hosts = pd.DataFrame()
    if not opcua.empty and "ip.src" in opcua.columns and "opcua.service_type" in opcua.columns:
        opcua_hosts = opcua.groupby("ip.src")["opcua.service_type"] \
            .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
            .reset_index().rename(columns={
                "ip.src": "ip",
                "opcua.service_type": "opcua_service_types"
            })

    dnp3_hosts = pd.DataFrame()
    if not dnp3.empty and "ip.src" in dnp3.columns and "dnp3.func_code" in dnp3.columns:
        dnp3_hosts = dnp3.groupby("ip.src")["dnp3.func_code"] \
            .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
            .reset_index().rename(columns={
                "ip.src": "ip",
                "dnp3.func_code": "dnp3_func_codes"
            })

    iec104_hosts = pd.DataFrame()
    if not iec104.empty and "ip.src" in iec104.columns and "iec104.typeid" in iec104.columns:
        iec104_hosts = iec104.groupby("ip.src")["iec104.typeid"] \
            .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
            .reset_index().rename(columns={
                "ip.src": "ip",
                "iec104.typeid": "iec104_type_ids"
            })

    s7comm_hosts = pd.DataFrame()
    if not s7comm.empty and "ip.src" in s7comm.columns and "s7comm.param.func" in s7comm.columns:
        s7comm_hosts = s7comm.groupby("ip.src")["s7comm.param.func"] \
            .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
            .reset_index().rename(columns={
                "ip.src": "ip",
                "s7comm.param.func": "s7comm_functions"
            })

    ssl_hosts = pd.DataFrame()
    if not zeek_ssl.empty and "id.orig_h" in zeek_ssl.columns:
        cols = []
        if "server_name" in zeek_ssl.columns:
            cols.append("server_name")
        if "ja3" in zeek_ssl.columns:
            cols.append("ja3")
        if "ja3s" in zeek_ssl.columns:
            cols.append("ja3s")
        if cols:
            ssl_hosts = zeek_ssl.groupby("id.orig_h")[cols] \
                .agg(lambda col: "; ".join(sorted(set([str(v) for v in col if pd.notna(v)])))) \
                .reset_index().rename(columns={"id.orig_h": "ip"})

    dhcp_zeek_hosts = pd.DataFrame()
    if not zeek_dhcp.empty and "client_addr" in zeek_dhcp.columns:
        cols = []
        if "host_name" in zeek_dhcp.columns:
            cols.append("host_name")
        if "client_fqdn" in zeek_dhcp.columns:
            cols.append("client_fqdn")
        if "vendor_class" in zeek_dhcp.columns:
            cols.append("vendor_class")
        if cols:
            dhcp_zeek_hosts = zeek_dhcp.groupby("client_addr")[cols] \
                .agg(lambda col: "; ".join(sorted(set([str(v) for v in col if pd.notna(v)])))) \
                .reset_index().rename(columns={"client_addr": "ip"})

    conn_hosts = pd.DataFrame()
    if not zeek_conn.empty and "id.orig_h" in zeek_conn.columns:
        conn_hosts = zeek_conn.groupby("id.orig_h").agg({
            "proto": lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)]))),
            "service": lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)]))),
        }).reset_index().rename(columns={
            "id.orig_h": "ip",
            "proto": "zeek_protocols",
            "service": "zeek_services"
        })

    # Zeek OT protocol aggregations
    zeek_modbus_hosts = pd.DataFrame()
    if not zeek_modbus.empty and "id.orig_h" in zeek_modbus.columns:
        func_col = "func" if "func" in zeek_modbus.columns else None
        if func_col is not None:
            zeek_modbus_hosts = zeek_modbus.groupby("id.orig_h")[func_col] \
                .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
                .reset_index().rename(columns={
                    "id.orig_h": "ip",
                    func_col: "zeek_modbus_functions"
                })

    zeek_dnp3_hosts = pd.DataFrame()
    if not zeek_dnp3.empty and "id.orig_h" in zeek_dnp3.columns:
        func_col = "func" if "func" in zeek_dnp3.columns else None
        if func_col is not None:
            zeek_dnp3_hosts = zeek_dnp3.groupby("id.orig_h")[func_col] \
                .apply(lambda x: "; ".join(sorted(set([str(v) for v in x if pd.notna(v)])))) \
                .reset_index().rename(columns={
                    "id.orig_h": "ip",
                    func_col: "zeek_dnp3_functions"
                })

    # SSH banner extraction (device identification)
    # Note: SSH field names vary by Wireshark version, so we'll extract from Zeek logs primarily
    ssh_hosts = pd.DataFrame()
    if not ssh_banners.empty and "ip.src" in ssh_banners.columns:
        ssh_data = []
        for ip, group in ssh_banners.groupby("ip.src"):
            # Try to extract any SSH-related information
            ssh_info = []
            for col in group.columns:
                if col not in ["ip.src", "ip.dst"]:
                    values = "; ".join(sorted(set([str(v) for v in group[col] if pd.notna(v)])))
                    if values:
                        ssh_info.append(values)
            if ssh_info:
                ssh_data.append({
                    "ip": ip,
                    "ssh_info": "; ".join(ssh_info)
                })
        if ssh_data:
            ssh_hosts = pd.DataFrame(ssh_data)
    
    # Zeek SSH log extraction (primary source for SSH device identification)
    zeek_ssh_hosts = pd.DataFrame()
    if not zeek_ssh.empty and "id.orig_h" in zeek_ssh.columns:
        ssh_data = []
        for ip, group in zeek_ssh.groupby("id.orig_h"):
            ssh_info = {}
            if "version" in group.columns:
                ssh_info["zeek_ssh_version"] = "; ".join(sorted(set([str(v) for v in group["version"] if pd.notna(v)])))
            if "client" in group.columns:
                ssh_info["zeek_ssh_client"] = "; ".join(sorted(set([str(v) for v in group["client"] if pd.notna(v)])))
            if "server" in group.columns:
                ssh_info["zeek_ssh_server"] = "; ".join(sorted(set([str(v) for v in group["server"] if pd.notna(v)])))
            if "server_host_key" in group.columns:
                ssh_info["zeek_ssh_server_host_key"] = "; ".join(sorted(set([str(v) for v in group["server_host_key"] if pd.notna(v)])))
            if "host_key_alg" in group.columns:
                ssh_info["zeek_ssh_host_key_alg"] = "; ".join(sorted(set([str(v) for v in group["host_key_alg"] if pd.notna(v)])))
            
            if ssh_info:
                ssh_info["ip"] = ip
                ssh_data.append(ssh_info)
        
        if ssh_data:
            zeek_ssh_hosts = pd.DataFrame(ssh_data)
    
    # SNMP device identification (sysDescr, sysObjectID)
    # Note: SNMP field extraction from tshark is unreliable, so we'll use Zeek logs primarily
    snmp_hosts = pd.DataFrame()
    if not snmp_details.empty and "ip.src" in snmp_details.columns:
        # Try to extract any SNMP information available
        snmp_data = {}
        for _, row in snmp_details.iterrows():
            ip = row.get("ip.src")
            if pd.notna(ip):
                if ip not in snmp_data:
                    snmp_data[ip] = {"raw_snmp": []}
                
                # Collect any SNMP-related values
                for col in row.index:
                    if col not in ["ip.src", "ip.dst"] and pd.notna(row[col]):
                        snmp_data[ip]["raw_snmp"].append(f"{col}:{row[col]}")
        
        if snmp_data:
            snmp_list = []
            for ip, data in snmp_data.items():
                snmp_list.append({
                    "ip": ip,
                    "snmp_raw": "; ".join(sorted(set(data["raw_snmp"]))) if data["raw_snmp"] else None
                })
            snmp_hosts = pd.DataFrame(snmp_list)
    
    # Zeek SNMP log extraction (primary source for SNMP device identification)
    zeek_snmp_hosts = pd.DataFrame()
    if not zeek_snmp.empty and "id.orig_h" in zeek_snmp.columns:
        snmp_data = []
        for ip, group in zeek_snmp.groupby("id.orig_h"):
            snmp_info = {"ip": ip}
            
            # Zeek SNMP log typically has display_string which is sysDescr
            if "display_string" in group.columns:
                snmp_info["snmp_sysdescr"] = "; ".join(sorted(set([str(v) for v in group["display_string"] if pd.notna(v)])))
            
            # Extract other SNMP fields if available
            if "version" in group.columns:
                snmp_info["snmp_version"] = "; ".join(sorted(set([str(v) for v in group["version"] if pd.notna(v)])))
            
            snmp_data.append(snmp_info)
        
        if snmp_data:
            zeek_snmp_hosts = pd.DataFrame(snmp_data)

    # nDPI application identification aggregation
    ndpi_hosts = pd.DataFrame()
    if not ndpi_flows.empty:
        # nDPI CSV format varies, try common column names
        src_ip_col = None
        protocol_col = None
        app_col = None
        category_col = None
        breed_col = None
        
        # Try to find the right columns
        for col in ndpi_flows.columns:
            col_lower = col.lower()
            if "src" in col_lower and "ip" in col_lower:
                src_ip_col = col
            elif "protocol" in col_lower or "proto" in col_lower:
                protocol_col = col
            elif "app" in col_lower or "application" in col_lower:
                app_col = col
            elif "category" in col_lower:
                category_col = col
            elif "breed" in col_lower:
                breed_col = col
        
        if src_ip_col:
            ndpi_data = []
            for ip, group in ndpi_flows.groupby(src_ip_col):
                protocols = set()
                apps = set()
                categories = set()
                breeds = set()
                
                if protocol_col:
                    protocols.update([str(v) for v in group[protocol_col].dropna()])
                if app_col:
                    apps.update([str(v) for v in group[app_col].dropna()])
                if category_col:
                    categories.update([str(v) for v in group[category_col].dropna()])
                if breed_col:
                    breeds.update([str(v) for v in group[breed_col].dropna()])
                
                ndpi_data.append({
                    "ip": ip,
                    "ndpi_protocols": "; ".join(sorted(protocols)) if protocols else None,
                    "ndpi_applications": "; ".join(sorted(apps)) if apps else None,
                    "ndpi_categories": "; ".join(sorted(categories)) if categories else None,
                    "ndpi_breeds": "; ".join(sorted(breeds)) if breeds else None
                })
            
            if ndpi_data:
                ndpi_hosts = pd.DataFrame(ndpi_data)
    
    # Parse nDPI JSON if available (more detailed)
    if ndpi_json_data and isinstance(ndpi_json_data, dict):
        if "flows" in ndpi_json_data:
            ndpi_json_hosts = {}
            for flow in ndpi_json_data["flows"]:
                src_ip = flow.get("src_ip") or flow.get("ip_src")
                if src_ip:
                    if src_ip not in ndpi_json_hosts:
                        ndpi_json_hosts[src_ip] = {
                            "ndpi_protocols": set(),
                            "ndpi_applications": set(),
                            "ndpi_categories": set(),
                            "ndpi_breeds": set(),
                            "ndpi_risks": set()
                        }
                    
                    if "proto" in flow or "protocol" in flow:
                        proto = flow.get("proto") or flow.get("protocol")
                        if proto:
                            ndpi_json_hosts[src_ip]["ndpi_protocols"].add(str(proto))
                    
                    if "app_protocol" in flow or "application" in flow:
                        app = flow.get("app_protocol") or flow.get("application")
                        if app:
                            ndpi_json_hosts[src_ip]["ndpi_applications"].add(str(app))
                    
                    if "category" in flow:
                        ndpi_json_hosts[src_ip]["ndpi_categories"].add(str(flow["category"]))
                    
                    if "breed" in flow:
                        ndpi_json_hosts[src_ip]["ndpi_breeds"].add(str(flow["breed"]))
                    
                    if "risk" in flow or "risks" in flow:
                        risks = flow.get("risk") or flow.get("risks", [])
                        if isinstance(risks, list):
                            for risk in risks:
                                if risk:
                                    ndpi_json_hosts[src_ip]["ndpi_risks"].add(str(risk))
                        elif risks:
                            ndpi_json_hosts[src_ip]["ndpi_risks"].add(str(risks))
            
            # Convert to DataFrame and merge with existing ndpi_hosts
            if ndpi_json_hosts:
                json_data = []
                for ip, data in ndpi_json_hosts.items():
                    json_data.append({
                        "ip": ip,
                        "ndpi_protocols": "; ".join(sorted(data["ndpi_protocols"])) if data["ndpi_protocols"] else None,
                        "ndpi_applications": "; ".join(sorted(data["ndpi_applications"])) if data["ndpi_applications"] else None,
                        "ndpi_categories": "; ".join(sorted(data["ndpi_categories"])) if data["ndpi_categories"] else None,
                        "ndpi_breeds": "; ".join(sorted(data["ndpi_breeds"])) if data["ndpi_breeds"] else None,
                        "ndpi_risks": "; ".join(sorted(data["ndpi_risks"])) if data["ndpi_risks"] else None
                    })
                
                ndpi_json_df = pd.DataFrame(json_data)
                if ndpi_hosts.empty:
                    ndpi_hosts = ndpi_json_df
                else:
                    # Merge JSON data with CSV data
                    for col in ["ndpi_protocols", "ndpi_applications", "ndpi_categories", "ndpi_breeds", "ndpi_risks"]:
                        if col in ndpi_json_df.columns:
                            if col in ndpi_hosts.columns:
                                # Merge values
                                merged = ndpi_hosts.merge(ndpi_json_df[["ip", col]], on="ip", how="outer", suffixes=("", "_json"))
                                if f"{col}_json" in merged.columns:
                                    merged[col] = merged.apply(
                                        lambda row: "; ".join(sorted(set(
                                            (str(row[col]) if pd.notna(row[col]) else "").split("; ") +
                                            (str(row[f"{col}_json"]) if pd.notna(row.get(f"{col}_json")) else "").split("; ")
                                        ))) if any(pd.notna(row.get(c)) for c in [col, f"{col}_json"]) else None,
                                        axis=1
                                    )
                                    merged = merged.drop(columns=[f"{col}_json"])
                                ndpi_hosts = merged
                            else:
                                ndpi_hosts = ndpi_hosts.merge(ndpi_json_df[["ip", col]], on="ip", how="left")

    # Merge all data
    hosts = src_hosts
    for df in [
        dhcp_hosts,
        http_hosts,
        dns_hosts,
        ssl_hosts,
        dhcp_zeek_hosts,
        conn_hosts,
        p0f_df,
        ssh_hosts,
        zeek_ssh_hosts,
        snmp_hosts,
        zeek_snmp_hosts,
        modbus_hosts,
        opcua_hosts,
        dnp3_hosts,
        iec104_hosts,
        s7comm_hosts,
        zeek_modbus_hosts,
        zeek_dnp3_hosts,
        ndpi_hosts,
    ]:
        if not df.empty:
            hosts = hosts.merge(df, on="ip", how="left")
    
    # Add risk indicators and device classification
    print("Calculating risk indicators and device classification...")
    
    def calculate_risk_score(row):
        """Calculate risk score based on various indicators"""
        risk = 0
        risk_factors = []
        
        # OT protocols with write operations
        if pd.notna(row.get("modbus_func_codes")):
            modbus_codes = str(row["modbus_func_codes"])
            if any(code in modbus_codes for code in ["5", "6", "15", "16"]):
                risk += 3
                risk_factors.append("Modbus Write Operations")
        
        if pd.notna(row.get("dnp3_func_codes")):
            dnp3_codes = str(row["dnp3_func_codes"])
            if "DIRECT_OPERATE" in dnp3_codes or "WRITE" in dnp3_codes:
                risk += 3
                risk_factors.append("DNP3 Control Operations")
        
        if pd.notna(row.get("s7comm_functions")):
            risk += 2
            risk_factors.append("S7comm PLC Communication")
        
        # nDPI risk indicators
        if pd.notna(row.get("ndpi_risks")):
            ndpi_risks = str(row["ndpi_risks"])
            if ndpi_risks:
                risk += 2
                risk_factors.append(f"nDPI Risks: {ndpi_risks}")
        
        # nDPI suspicious categories
        if pd.notna(row.get("ndpi_categories")):
            categories = str(row["ndpi_categories"]).lower()
            suspicious_cats = ["malware", "attack", "exploit", "cryptocurrency", "p2p", "tor", "proxy"]
            if any(cat in categories for cat in suspicious_cats):
                risk += 2
                risk_factors.append("Suspicious nDPI Category")
        
        # Unusual ports
        if pd.notna(row.get("tcp_ports")):
            ports = [int(p) for p in str(row["tcp_ports"]).split("; ") if p.isdigit()]
            unusual_ports = [p for p in ports if p not in [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]]
            if len(unusual_ports) > 5:
                risk += 1
                risk_factors.append("Multiple Unusual Ports")
        
        # No vendor identification
        if pd.isna(row.get("mac_vendor_names")) and pd.isna(row.get("dhcp_vendor_class")):
            risk += 1
            risk_factors.append("Unknown Vendor")
        
        return risk, "; ".join(risk_factors) if risk_factors else None
    
    def extract_firmware_from_sources(row):
        """Extract firmware version from multiple sources"""
        firmware_sources = []
        
        # From HTTP Server headers
        if pd.notna(row.get("http_server_headers")):
            import re
            server_str = str(row["http_server_headers"])
            version_match = re.search(r'[/\s]([vV]?)(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', server_str)
            if version_match:
                firmware_sources.append(version_match.group(2))
        
        # From SNMP sysDescr (check both tshark and Zeek sources)
        snmp_sysdescr = row.get("snmp_sysdescr") or row.get("zeek_snmp_display_string")
        if pd.notna(snmp_sysdescr):
            import re
            sysdescr = str(snmp_sysdescr)
            
            # Try device fingerprinting first (OpenVAS-style)
            if DEVICE_FINGERPRINTING_AVAILABLE:
                fingerprint = fingerprint_device(snmp_sysdescr=sysdescr)
                if fingerprint and fingerprint.get("version"):
                    firmware_sources.append(fingerprint["version"])
            
            # Common patterns in sysDescr: "Firmware v1.2.3", "Version 2.4.1"
            version_match = re.search(r'[vV](\d+\.\d+(?:\.\d+)?)', sysdescr)
            if version_match:
                firmware_sources.append(version_match.group(1))
            else:
                version_match = re.search(r'(\d+\.\d+\.\d+)', sysdescr)
                if version_match:
                    firmware_sources.append(version_match.group(1))
        
        # From SSH version (check Zeek logs first, then tshark)
        ssh_version = row.get("zeek_ssh_version") or row.get("ssh_versions") or row.get("ssh_info")
        if pd.notna(ssh_version):
            import re
            ssh_ver = str(ssh_version)
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', ssh_ver)
            if version_match:
                firmware_sources.append(f"SSH-{version_match.group(1)}")
        
        # From existing firmware_versions column
        if pd.notna(row.get("firmware_versions")):
            firmware_sources.append(str(row["firmware_versions"]))
        
        return "; ".join(sorted(set(firmware_sources))) if firmware_sources else None
    
    def extract_device_model_from_sources(row):
        """Extract device model from multiple sources"""
        models = []
        import re
        
        # First, check if we already have device_models from HTTP aggregation
        if pd.notna(row.get("device_models")):
            models.append(str(row["device_models"]))
        
        # From SNMP sysDescr (most reliable for OT devices)
        snmp_sysdescr = row.get("snmp_sysdescr") or row.get("zeek_snmp_display_string")
        if pd.notna(snmp_sysdescr):
            sysdescr = str(snmp_sysdescr)
            
            # Try device fingerprinting first (OpenVAS-style)
            if DEVICE_FINGERPRINTING_AVAILABLE:
                fingerprint = fingerprint_device(snmp_sysdescr=sysdescr)
                if fingerprint and fingerprint.get("product"):
                    models.append(fingerprint["product"])
            
            # Common OT device patterns: "Schneider Electric Modicon M340", "Siemens SIMATIC S7-1200"
            model_patterns = [
                r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+([A-Z]\d+[A-Z]?\d*)',  # "Schneider Electric M340"
                r'([A-Z]{2,}\d+[A-Z]?\d*)',  # "M340", "S7-1200"
                r'Model[:\s]+([A-Z0-9\-]+)',  # "Model: ABC-123"
            ]
            for pattern in model_patterns:
                match = re.search(pattern, sysdescr)
                if match:
                    models.append(match.group(0))
                    break
        
        # From HTTP Server headers (try fingerprinting and pattern matching)
        if pd.notna(row.get("http_server_headers")):
            server_str = str(row["http_server_headers"])
            
            # Try device fingerprinting (OpenVAS-style)
            if DEVICE_FINGERPRINTING_AVAILABLE:
                fingerprint = fingerprint_device(http_server=server_str)
                if fingerprint and fingerprint.get("product"):
                    models.append(fingerprint["product"])
            
            # Pattern matching for device models in HTTP headers
            model_match = re.search(r'([A-Z]{2,}\d+[A-Z]?\d*)', server_str)
            if model_match:
                models.append(model_match.group(1))
            
            # Also try to extract product names from common server strings
            server_lower = server_str.lower()
            if "apache" in server_lower:
                models.append("Apache HTTP Server")
            elif "nginx" in server_lower:
                models.append("nginx")
            elif "iis" in server_lower or "microsoft-iis" in server_lower:
                models.append("Microsoft IIS")
        
        # From fingerprint_product (from later fingerprinting step)
        if pd.notna(row.get("fingerprint_product")):
            models.append(str(row["fingerprint_product"]))
        
        # From MAC vendor + protocol inference (fallback)
        if pd.notna(row.get("mac_vendor_names")):
            vendor = str(row["mac_vendor_names"])
            if pd.notna(row.get("modbus_func_codes")):
                models.append(f"{vendor} Modbus Device")
            if pd.notna(row.get("s7comm_functions")):
                models.append(f"{vendor} Siemens PLC")
        elif pd.notna(row.get("modbus_func_codes")):
            # Protocol inference without vendor
            models.append("Modbus/TCP Device")
        elif pd.notna(row.get("s7comm_functions")):
            models.append("Siemens S7 PLC")
        
        return "; ".join(sorted(set(models))) if models else None
    
    def classify_device_type(row):
        """Classify device type based on protocols and behavior (Tenable OT style)"""
        device_types = []
        
        # OT/ICS devices
        if pd.notna(row.get("modbus_func_codes")) or pd.notna(row.get("zeek_modbus_functions")):
            device_types.append("Modbus Device")
        if pd.notna(row.get("opcua_service_types")):
            device_types.append("OPC UA Device")
        if pd.notna(row.get("dnp3_func_codes")):
            device_types.append("DNP3 Device")
        if pd.notna(row.get("iec104_type_ids")):
            device_types.append("IEC-104 Device")
        if pd.notna(row.get("s7comm_functions")):
            device_types.append("Siemens PLC")
        
        # Network infrastructure
        if pd.notna(row.get("zeek_services")):
            services = str(row["zeek_services"]).lower()
            if "http" in services:
                device_types.append("Web Server")
            if "ssh" in services:
                device_types.append("SSH Server")
            if "dns" in services:
                device_types.append("DNS Server")
            if "snmp" in services:
                device_types.append("SNMP Device")
        
        # Client devices
        if pd.notna(row.get("http_user_agents")):
            device_types.append("Web Client")
        
        # SNMP devices (often OT/ICS)
        if pd.notna(row.get("snmp_sysdescr")):
            device_types.append("SNMP-Managed Device")
        
        if not device_types:
            device_types.append("Generic Network Device")
        
        return "; ".join(device_types)
    
    # Apply risk scoring and device classification
    risk_data = hosts.apply(lambda row: pd.Series(calculate_risk_score(row), index=["risk_score", "risk_factors"]), axis=1)
    hosts["risk_score"] = risk_data["risk_score"]
    hosts["risk_factors"] = risk_data["risk_factors"]
    hosts["device_type"] = hosts.apply(classify_device_type, axis=1)
    
    # Extract consolidated firmware and device model (Tenable OT / Checkpoint style)
    # Note: We do firmware first, then device_model, then fingerprinting (which may enhance both)
    hosts["firmware_version"] = hosts.apply(extract_firmware_from_sources, axis=1)
    # Initial device_model extraction (before fingerprinting)
    hosts["device_model"] = hosts.apply(extract_device_model_from_sources, axis=1)
    
    # Create consolidated vendor field (Checkpoint style)
    hosts["vendor"] = hosts.apply(
        lambda row: row.get("mac_vendor_names") if pd.notna(row.get("mac_vendor_names")) else 
                   (row.get("device_vendors_http") if pd.notna(row.get("device_vendors_http")) else
                   (row.get("dhcp_vendor_class") if pd.notna(row.get("dhcp_vendor_class")) else None)),
        axis=1
    )
    
    # OpenVAS-style device fingerprinting and CPE generation
    print("Performing OpenVAS-style device fingerprinting...")
    if DEVICE_FINGERPRINTING_AVAILABLE:
        def generate_device_fingerprint(row):
            """Generate comprehensive device fingerprint (OpenVAS-style)"""
            # Get SSH version from Zeek logs (more reliable)
            ssh_version = row.get("zeek_ssh_version") or row.get("ssh_versions") or row.get("ssh_info")
            # Get SNMP sysDescr from Zeek logs (more reliable)
            snmp_sysdescr = row.get("zeek_snmp_display_string") or row.get("snmp_sysdescr")
            
            fingerprint_result = fingerprint_device(
                http_server=row.get("http_server_headers"),
                snmp_sysdescr=snmp_sysdescr,
                ssh_version=ssh_version,
                user_agent=row.get("http_user_agents"),
                modbus_func=row.get("modbus_func_codes"),
                s7comm_func=row.get("s7comm_functions")
            )
            
            # Use fingerprinting results to enhance vendor/model/version if missing
            enhanced_vendor = fingerprint_result.get("vendor") if fingerprint_result else None
            enhanced_product = fingerprint_result.get("product") if fingerprint_result else None
            enhanced_version = fingerprint_result.get("version") if fingerprint_result else None
            cpe = fingerprint_result.get("cpe") if fingerprint_result else None
            confidence = fingerprint_result.get("confidence") if fingerprint_result else None
            
            # Merge with existing data (prefer existing if available)
            final_vendor = row.get("vendor") if pd.notna(row.get("vendor")) else enhanced_vendor
            final_product = row.get("device_model") if pd.notna(row.get("device_model")) else enhanced_product
            final_version = row.get("firmware_version") if pd.notna(row.get("firmware_version")) else enhanced_version
            
            # Generate CPE if we have vendor and product
            if not cpe and final_vendor and final_product:
                cpe = generate_cpe(final_vendor, final_product, final_version)
            
            return pd.Series({
                "fingerprint_vendor": enhanced_vendor,
                "fingerprint_product": enhanced_product,
                "fingerprint_version": enhanced_version,
                "cpe": cpe,
                "fingerprint_confidence": confidence
            })
        
        fingerprint_data = hosts.apply(generate_device_fingerprint, axis=1)
        hosts["fingerprint_vendor"] = fingerprint_data["fingerprint_vendor"]
        hosts["fingerprint_product"] = fingerprint_data["fingerprint_product"]
        hosts["fingerprint_version"] = fingerprint_data["fingerprint_version"]
        hosts["cpe"] = fingerprint_data["cpe"]
        hosts["fingerprint_confidence"] = fingerprint_data["fingerprint_confidence"]
        
        # Update vendor/model/version with fingerprinting results if better
        hosts["vendor"] = hosts.apply(
            lambda row: row.get("fingerprint_vendor") if pd.notna(row.get("fingerprint_vendor")) and 
                       (pd.isna(row.get("vendor")) or row.get("fingerprint_confidence") == "high") 
                       else row.get("vendor"),
            axis=1
        )
        
        # Update device_model: prefer fingerprint_product if available and confidence is high, or if current is generic
        hosts["device_model"] = hosts.apply(
            lambda row: (
                row.get("fingerprint_product") 
                if pd.notna(row.get("fingerprint_product")) and 
                   (pd.isna(row.get("device_model")) or 
                    row.get("fingerprint_confidence") == "high" or
                    str(row.get("device_model", "")).lower() in ["modbus/tcp device", "generic network device", "unknown"])
                else row.get("device_model")
            ),
            axis=1
        )
        
        hosts["firmware_version"] = hosts.apply(
            lambda row: row.get("fingerprint_version") if pd.notna(row.get("fingerprint_version")) and 
                       (pd.isna(row.get("firmware_version")) or row.get("fingerprint_confidence") == "high")
                       else row.get("firmware_version"),
            axis=1
        )
        
        # Re-run device_model extraction to incorporate fingerprinting results
        hosts["device_model"] = hosts.apply(extract_device_model_from_sources, axis=1)
    else:
        hosts["cpe"] = None
        hosts["fingerprint_confidence"] = None
    
    # Reorder columns for better readability (Tenable OT / Checkpoint / OpenVAS firewall-like format)
    column_order = [
        "ip",
        "macs",
        "vendor",
        "mac_vendor_names",
        "device_model",
        "firmware_version",
        "cpe",
        "fingerprint_confidence",
        "device_type",
        "device_role",
        "mac_oui_prefixes",
        "dhcp_vendor_class",
        "host_name",
        "client_fqdn",
        "os_guess",
        "applications",
        "ndpi_applications",
        "ndpi_protocols",
        "ndpi_categories",
        "ndpi_breeds",
        "ndpi_risks",
        "http_methods",
        "http_hosts",
        "http_server_headers",
        "http_x_powered_by",
        "http_user_agents",
        "http_response_codes",
        "http_content_types",
        "dns_queries",
        "server_name",
        "ja3",
        "ja3s",
        "ssh_info",
        "zeek_ssh_version",
        "zeek_ssh_client",
        "zeek_ssh_server",
        "zeek_ssh_server_host_key",
        "zeek_ssh_host_key_alg",
        "snmp_raw",
        "snmp_sysdescr",
        "snmp_sysobjectid",
        "snmp_sysname",
        "snmp_syscontact",
        "snmp_syslocation",
        "snmp_version",
        "zeek_snmp_display_string",
        "tcp_ports",
        "udp_ports",
        "zeek_protocols",
        "zeek_services",
        "modbus_func_codes",
        "opcua_service_types",
        "dnp3_func_codes",
        "iec104_type_ids",
        "s7comm_functions",
        "zeek_modbus_functions",
        "zeek_dnp3_functions",
        "fingerprint_vendor",
        "fingerprint_product",
        "fingerprint_version",
        "risk_score",
        "risk_factors"
    ]
    
    # Add any missing columns
    for col in column_order:
        if col not in hosts.columns:
            hosts[col] = None
    
    # Reorder and select columns
    available_columns = [col for col in column_order if col in hosts.columns]
    hosts = hosts[available_columns + [col for col in hosts.columns if col not in available_columns]]

    output_path = os.path.join(out_dir, "enriched_hosts.csv")
    hosts.to_csv(output_path, index=False)
    print(f"Enriched host data written to: {output_path}")
    print(f"Total hosts: {len(hosts)}")
    print(f"Hosts with vendor identification: {hosts['mac_vendor_names'].notna().sum()}")
    print(f"Hosts with risk indicators: {hosts['risk_score'].gt(0).sum()}")

if __name__ == "__main__":
    main()

