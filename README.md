# PCAP Enhancer (OT-Aware) - Tenable OT / Checkpoint / OpenVAS Style

A repeatable pipeline for enriching PCAP files with comprehensive network analysis using tshark, Zeek, nDPI, and p0f. **Now with OT/ICS protocol support** and **device intelligence** similar to Tenable OT Security, Checkpoint firewalls, and OpenVAS vulnerability scanners.

## Motivation

Network packet capture (PCAP) analysis is essential for security research, incident response, and network forensics. However, extracting meaningful intelligence from raw PCAP files requires multiple specialized tools and significant manual effort. This project addresses several key challenges:

- **Fragmented Tool Ecosystem**: Network analysis typically requires running multiple tools separately (tshark, Zeek, nDPI, p0f) and manually correlating their outputs, which is time-consuming and error-prone.

- **Limited Device Intelligence**: Standard network analysis tools provide basic protocol information but lack the device intelligence capabilities found in enterprise security platforms like Tenable OT, Checkpoint firewalls, and OpenVAS scanners.

- **OT/ICS Protocol Gaps**: Industrial Control Systems (ICS) and Operational Technology (OT) networks use specialized protocols (Modbus, OPC UA, DNP3, IEC-104, Siemens S7comm) that require specific analysis techniques not readily available in standard network analysis workflows.

- **Manual Correlation Overhead**: Identifying devices, extracting firmware versions, correlating MAC addresses with vendors, and building device inventories requires extensive manual work across multiple data sources.

- **Lack of Standardized Output**: Different tools produce outputs in various formats, making it difficult to create a unified view of network activity and device inventory.

This pipeline automates the entire workflow, combining multiple analysis tools into a single, repeatable process that produces enterprise-grade device intelligence and comprehensive network analysis results. It enables security researchers, network analysts, and incident responders to quickly extract actionable intelligence from PCAP files without the overhead of manual tool coordination.

## Overview

This pipeline extracts and enriches network traffic data from PCAP files, providing **firewall-grade device intelligence**:

- **Device Identification**: MAC addresses, vendor names (OUI lookup), device models, firmware versions
- **Vendor & Firmware Detection**: Extracts vendor information and firmware versions from HTTP Server headers, SNMP sysDescr, SSH banners, and device responses
- **OS Fingerprinting**: Passive OS detection via p0f
- **Application-Level Analysis**: Deep packet inspection with nDPI for application identification (similar to Checkpoint App-ID)
- **Protocol Analysis**: TCP/UDP ports, application protocols, services
- **OT/ICS Protocol Analysis**: Modbus/TCP, OPC UA, DNP3, IEC-104, Siemens S7comm
- **Device Inventory**: Comprehensive device catalog with vendor, model, firmware, and role (similar to Tenable OT asset discovery)
- **Device Fingerprinting**: OpenVAS-style device identification with CPE (Common Platform Enumeration) generation
- **Vulnerability Intelligence**: CPE-based device identification for potential CVE lookups (OpenVAS-style)
- **Risk Assessment**: Automated risk scoring based on protocols, behaviors, and indicators

## Prerequisites

### System Requirements

- **Docker**: Docker Engine 20.10 or later (recommended installation method)
- **Disk Space**: At least 2GB free space for Docker image and analysis outputs
- **Memory**: Minimum 2GB RAM (4GB+ recommended for large PCAP files)
- **Operating System**: Linux, macOS, or Windows with Docker support

## Tools Used

1. **[tshark](https://www.wireshark.org/)** (CLI Wireshark) - Extracts raw fields (MAC, IP, ports, protocols, DHCP, HTTP, DNS) and **OT protocols** (Modbus, OPC UA, DNP3, IEC-104, S7comm)

2. **[Zeek](https://zeek.org/)** - Generates structured logs (conn.log, http.log, ssl.log, dhcp.log) and optionally OT logs (modbus.log, dnp3.log) if ICS analyzers are enabled

3. **[nDPI 5.0](https://www.ntop.org/products/deep-packet-inspection/ndpi/)** - Deep Packet Inspection library for application identification, protocol detection, and traffic classification with unified fingerprinting (TCP + JA4 + TLS SHA1)

4. **[p0f](https://lcamtuf.coredump.cx/p0f3/)** - Passive OS fingerprinting from TCP flows

5. **Device Fingerprinting Engine** - OpenVAS-style device identification with signature matching and CPE generation

6. **[Python](https://www.python.org/)** ([pandas](https://pandas.pydata.org/)) - Merges all outputs into a single enriched CSV with comprehensive device and application intelligence

## Quick Start

### Option 1: Using Docker (Recommended)

1. **Build the Docker image:**

   Build the Docker image from the Dockerfile in the project root. This will install all required tools and dependencies.

2. **Prepare your PCAP files:**

   Create directories for your PCAP files and output. Place your `.pcap` or `.pcapng` files in the `pcaps/` directory.

3. **Run the container:**

   Start the Docker container with volume mounts for your PCAP files and output directory. The container will run interactively, giving you access to the analysis tools.

4. **Inside the container, analyze a PCAP:**

   Navigate to the workspace directory and run the analysis script with your PCAP file path and output directory. Then run the enrichment script to merge all analysis results into a single CSV file.

   **Important Notes:**

   - The script automatically resolves relative paths to absolute paths
   - If you modify `analyze_pcap.sh` or `enrich_pcap.py`, you must rebuild the Docker image
   - Files with spaces in their names must be quoted or escaped

5. **View results:**

   Exit the container and check the output directory for the enriched CSV file containing all analysis results.

## Commands

### Building the Docker Image

Build the Docker image with the default Dockerfile. If you encounter build issues with Zeek installation, use the alternative Dockerfile instead.

### Running Analysis

Inside the Docker container, run the analysis script with your PCAP file path and output directory. The analysis script will:

- Extract network flows and protocol information using tshark
- Generate Zeek logs for connections, HTTP, SSL, DHCP, and OT protocols
- Perform OS fingerprinting with p0f
- Run deep packet inspection with nDPI (if available)
- Extract SSH banners, SNMP details, and HTTP headers

After the analysis completes, run the enrichment script to merge all outputs into a single enriched CSV file.

### Analyzing Multiple PCAPs

You can analyze multiple PCAP files by running the analysis and enrichment scripts in a loop for each file. Each PCAP will generate its own output directory with separate analysis results.

## Output Files

After running the analysis pipeline, the output directory contains:

### Raw Analysis Files

- `flows.csv` - Base flows with MAC, IP, ports, protocols
- `dhcp_vendors.csv` - DHCP vendor class IDs (if present)
- `http_requests.csv` - HTTP requests with hosts, URIs, user-agents
- `dns_queries.csv` - DNS queries with domain names
- **OT Protocol Files:**
  - `modbus.csv` - Modbus/TCP function codes (port 502)
  - `opcua.csv` - OPC UA service types (port 4840)
  - `dnp3.csv` - DNP3 function codes (port 20000)
  - `iec104.csv` - IEC-104 type IDs (port 2404)
  - `s7comm.csv` - Siemens S7comm functions (port 102)
- `zeek/` - Directory with Zeek logs:
  - `conn.log` - All connections (IPs, ports, protocols, services)
  - `http.log` - HTTP transactions (methods, status codes, etc.)
  - `ssl.log` - TLS sessions (SNI, JA3/JA3S fingerprints)
  - `dhcp.log` - DHCP exchanges (hostnames, vendor classes)
  - `modbus.log`, `dnp3.log` - OT protocol logs (if ICS analyzers enabled)
- `p0f.log` - OS fingerprint guesses
- `ndpi_flows.csv` - nDPI flow analysis (protocols, applications, categories)
- `ndpi_flows.json` - nDPI detailed JSON output (if available)
- `ssh_banners.csv` - SSH version strings and fingerprints (HASSH)
- `snmp_details.csv` - SNMP device information (sysDescr, sysObjectID, etc.)
- `http_response_headers.csv` - HTTP response headers (X-Powered-By, Server, etc.) for device identification

### Enriched Output

**Tenable OT / Checkpoint Style Device Inventory:**

- `enriched_hosts.csv` - **Main output**: One row per host IP with aggregated data including device identification, vendor information, firmware versions, protocols, applications, and risk scores.

## Enriched Hosts CSV Columns

The `enriched_hosts.csv` file contains comprehensive information per host IP, organized into several categories:

### Device Identification (Primary Fields)

- `ip` - Host IP address
- `macs` - MAC addresses seen (semicolon-separated)
- `vendor` - Consolidated vendor name (from MAC OUI, HTTP headers, or DHCP)
- `mac_vendor_names` - Vendor names from MAC OUI lookup
- `device_model` - Device model extracted from SNMP, HTTP headers, or protocol inference
- `firmware_version` - Firmware version extracted from HTTP Server headers, SNMP sysDescr, SSH banners
- `cpe` - CPE (Common Platform Enumeration) identifier for vulnerability lookup
- `fingerprint_confidence` - Confidence level of device fingerprinting (high, medium, low)
- `device_type` - Device classification (e.g., "Modbus Device", "Siemens PLC", "Web Server")
- `device_role` - Network role (Client, Server, Mixed)

### Network & Protocol Information

- `tcp_ports` - TCP source ports used (semicolon-separated)
- `udp_ports` - UDP source ports used (semicolon-separated)
- `dhcp_vendor_class` - Vendor class from DHCP options
- `host_name` - Hostname from DHCP
- `client_fqdn` - FQDN from DHCP
- `os_guess` - OS fingerprint from p0f

### Application-Level Intelligence

- `applications` - Applications identified from HTTP user-agents
- `ndpi_applications` - Applications identified by nDPI (e.g., Chrome, Firefox, Teams, Zoom)
- `ndpi_protocols` - Protocols detected by nDPI deep packet inspection
- `ndpi_categories` - Traffic categories (e.g., Web, Cloud, P2P, Malware)
- `ndpi_breeds` - Traffic breeds (e.g., Safe, Acceptable, Unacceptable)
- `ndpi_risks` - Risk indicators from nDPI flow analysis

### HTTP/Web Intelligence

- `http_user_agents` - HTTP user-agent strings
- `http_server_headers` - HTTP Server headers (often contain device/firmware info)
- `http_x_powered_by` - HTTP X-Powered-By headers (application/framework identification)
- `http_methods` - HTTP methods used
- `http_hosts` - HTTP hosts accessed
- `http_response_codes` - HTTP response codes
- `http_content_types` - HTTP content types

### Device Identification Sources

- `zeek_ssh_version` - SSH version from Zeek logs
- `zeek_ssh_client` - SSH client identification string
- `zeek_ssh_server` - SSH server identification string
- `zeek_ssh_server_host_key` - SSH server host key fingerprint
- `snmp_sysdescr` - SNMP sysDescr from Zeek logs (device description, often contains model/firmware)
- `zeek_snmp_display_string` - SNMP display string from Zeek (sysDescr equivalent)
- `snmp_sysobjectid` - SNMP sysObjectID (device type identifier)
- `snmp_sysname` - SNMP sysName (device name)
- `snmp_syscontact` - SNMP sysContact
- `snmp_syslocation` - SNMP sysLocation

### Security & Fingerprinting

- `dns_queries` - DNS domain names queried
- `server_name` - TLS SNI (Server Name Indication)
- `ja3` - JA3 TLS client fingerprint
- `ja3s` - JA3S TLS server fingerprint
- `zeek_protocols` - Protocols detected by Zeek
- `zeek_services` - Services detected by Zeek
- `risk_score` - Automated risk score (0-10+)
- `risk_factors` - Risk indicators identified

### OT/ICS Protocol Columns

- `modbus_func_codes` - Modbus function codes used by host
- `opcua_service_types` - OPC UA service types (e.g., CreateSession, Read, Write, Browse)
- `dnp3_func_codes` - DNP3 function codes (e.g., READ, WRITE, DIRECT_OPERATE)
- `iec104_type_ids` - IEC-104 ASDU type IDs
- `s7comm_functions` - Siemens S7comm function identifiers (read/write PLC memory, run/stop)
- `zeek_modbus_functions` - Modbus functions from Zeek ICS analyzers (if enabled)
- `zeek_dnp3_functions` - DNP3 functions from Zeek ICS analyzers (if enabled)

## What You Can Learn from the Enriched Data

### Standard Network Analysis

- **Device Manufacturer**: From MAC OUIs and DHCP vendor classes
- **Operating System**: From p0f fingerprints and HTTP user-agents
- **Applications Used**: From ports, protocols, user-agents, and DNS queries
- **Network Role**: Client vs server behavior, services accessed
- **TLS Fingerprinting**: JA3/JA3S for client/server identification
- **Domain Activity**: What domains/services each host contacted

### OT/ICS-Specific Analysis

- **Modbus Masters**: Identify hosts performing write operations
- **OPC UA Clients**: See which hosts use OPC UA and what service types they access
- **DNP3 Control Operations**: Identify hosts using DIRECT_OPERATE or other control functions
- **IEC-104 Control Commands**: Detect hosts sending control type IDs
- **PLC Communication**: Identify Siemens S7comm traffic and functions
- **Vendor Correlation**: Match OT protocols with device vendors (MAC OUI + DHCP vendor class)
- **Protocol Mix**: Understand which hosts use multiple OT protocols

## Enterprise Security Tool Features

This pipeline mimics the behavior of enterprise security tools:

### Device Intelligence (Like Tenable OT)

- **Vendor Identification**: MAC OUI lookup provides actual vendor names (not just prefixes)
- **Device Model Detection**: Extracts device models from SNMP sysDescr, HTTP Server headers, and protocol inference
- **Firmware Version Extraction**: Identifies firmware versions from HTTP Server headers, SNMP sysDescr, SSH banners, and HTTP user-agents
- **Device Classification**: Automatically classifies devices as Modbus, OPC UA, PLC, Web Server, etc.
- **Asset Inventory**: Creates a comprehensive device catalog similar to Tenable OT asset discovery

### Application Intelligence (Like Checkpoint App-ID)

- **Application Identification**: nDPI identifies specific applications (Chrome, Teams, Zoom) beyond just protocols
- **Deep Packet Inspection**: Analyzes encrypted traffic to identify applications
- **Traffic Classification**: Categorizes traffic (Web, Cloud, P2P, Malware, etc.)
- **Risk Assessment**: Automated risk scoring based on protocols, behaviors, and indicators

### Device Fingerprinting (Like OpenVAS)

- **Signature Matching**: Matches device signatures against known database (Schneider Electric, Siemens, Rockwell Automation, ABB, Cisco, Apache, nginx, etc.)
- **CPE Generation**: Creates Common Platform Enumeration (CPE) identifiers for identified devices
- **Multi-Source Correlation**: Combines HTTP headers, SNMP sysDescr, SSH banners, and protocol inference for comprehensive device identification
- **Confidence Scoring**: Provides confidence levels (high/medium/low) for device identification based on number of matching sources
- **Vulnerability Lookup Ready**: CPE identifiers enable CVE database lookups via NVD API or local CVE database (similar to OpenVAS vulnerability scanning)
- **Firmware Extraction**: Extracts firmware versions from multiple sources and normalizes them
- **Device Model Inference**: Identifies device models from vendor patterns and protocol behavior

## nDPI Deep Packet Inspection

[nDPI 5.0](https://www.ntop.org/products/deep-packet-inspection/ndpi/) provides advanced application identification and traffic classification:

- **Unified Fingerprinting**: Combines TCP fingerprint, JA4 fingerprint, and TLS SHA1 certificate (or JA3S) for better encrypted traffic identification
- **Application Detection**: Identifies specific applications (Chrome, Teams, Zoom, etc.) beyond just protocols
- **Category Classification**: Classifies traffic into categories (Web, Cloud, P2P, Malware, etc.)
- **Risk Detection**: Identifies suspicious flows and potential security risks
- **Unresolved Hostname Detection**: Detects TLS/QUIC/HTTP flows whose hostnames weren't resolved via DNS (potential anomalies)

The pipeline automatically uses nDPI if `ndpiReader` is available. nDPI output is merged into the enriched CSV with columns for applications, protocols, categories, breeds, and risks.

## OpenVAS-Style Device Fingerprinting

The pipeline includes a device fingerprinting engine that:

- **Matches device signatures** against a database of known OT/ICS and network devices
- **Generates CPE identifiers** for identified devices (format: `cpe:2.3:h:vendor:product:version`)
- **Extracts firmware versions** from HTTP Server headers, SNMP sysDescr, SSH banners
- **Provides confidence scores** (high/medium/low) based on number of matching sources

### Supported Device Signatures

The fingerprinting database includes signatures for:
- **OT/ICS**: Schneider Electric Modicon, Siemens SIMATIC S7, Rockwell Automation, ABB PLCs
- **Network Equipment**: Cisco IOS/ASA
- **Web Servers**: Apache, nginx, Microsoft IIS

### CPE and Vulnerability Lookup

CPE identifiers can be used with:
- **NVD API**: Query National Vulnerability Database for CVEs affecting identified devices
- **OpenVAS**: Import CPEs into OpenVAS for vulnerability scanning
- **Local CVE databases**: Match against local vulnerability databases

## Next Steps

You can:

- Open `enriched_hosts.csv` in Excel/Google Sheets for manual analysis
- Load into Jupyter notebooks for further data analysis
- Feed into dashboards (Grafana, Metabase, etc.)
- Extend the pipeline for additional OT protocols (BACnet, PROFINET, EtherNet/IP, etc.)

## Troubleshooting

### Docker Build Issues

- **"Package 'zeek' has no installation candidate"**: If the main Dockerfile fails to build, use the alternative Dockerfile. The alternative Dockerfile installs Zeek from binary packages instead of the repository.

- **Zeek repository errors**: If the OpenSUSE repository is unavailable, the alternative Dockerfile will automatically fall back to installing Zeek from GitHub releases.

- **After updating scripts**: If you modify `analyze_pcap.sh` or `enrich_pcap.py`, rebuild the Docker image.

### Runtime Issues

- **"PCAP file not found"**: Ensure you're running the command from the workspace directory inside the container. Use paths relative to the workspace or absolute paths. If the file has spaces, make sure to quote it. The script will show the current directory and the path it's looking for if the file isn't found.

- **"OUI database not available"** or **"HTTP Error 418"**: The MAC OUI lookup will try alternative sources (Wireshark manuf file). Vendor names will still be extracted from DHCP vendor classes and HTTP headers. You can manually download the OUI database if needed.

- **"Some fields aren't valid"** (SSH/SNMP): This is normal - SSH and SNMP field names vary by Wireshark version. The pipeline uses Zeek logs as the primary source for SSH/SNMP device identification.

- **Empty flows.csv**: The PCAP might not contain IP traffic or may be corrupted.

- **Zeek errors**: Some PCAPs may not generate all Zeek logs (this is normal).

- **p0f warnings**: p0f may not detect OS for all flows (this is expected).

- **nDPI not found**: nDPI analysis is optional; the pipeline will continue without it.

## License

This project is provided as-is for network analysis purposes.
