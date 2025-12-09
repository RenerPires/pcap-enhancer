#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <pcap-file> [output-dir]"
  exit 1
fi

PCAP="$1"
OUTPUT_DIR="${2:-output}"

if command -v realpath >/dev/null 2>&1; then
	PCAP_ABS=$(realpath "$PCAP" 2>/dev/null || echo "$PCAP")
elif command -v readlink >/dev/null 2>&1; then
	PCAP_ABS=$(readlink -f "$PCAP" 2>/dev/null || echo "$PCAP")
else
	PCAP_ABS="$PCAP"
fi

if [ ! "${PCAP_ABS:0:1}" = "/" ]; then
	PCAP_ABS="$(pwd)/$PCAP_ABS"
fi

if [ ! -f "$PCAP_ABS" ]; then
	echo "PCAP file not found: $PCAP_ABS"
	echo "Current directory: $(pwd)"
	echo "Looking for: $PCAP"
	echo "Trying to list pcaps directory:"
	ls -la pcaps/ 2>/dev/null || echo "pcaps/ directory not found"
	exit 1
fi

if [ ! -r "$PCAP_ABS" ]; then
	echo "PCAP file is not readable: $PCAP_ABS"
	exit 1
fi

echo "Using PCAP file: $PCAP_ABS"

mkdir -p "$OUTPUT_DIR"
if command -v realpath >/dev/null 2>&1; then
	OUTPUT_DIR_ABS=$(realpath "$OUTPUT_DIR" 2>/dev/null || echo "$OUTPUT_DIR")
elif command -v readlink >/dev/null 2>&1; then
	OUTPUT_DIR_ABS=$(readlink -f "$OUTPUT_DIR" 2>/dev/null || echo "$OUTPUT_DIR")
else
	OUTPUT_DIR_ABS="$OUTPUT_DIR"
fi

if [ ! "${OUTPUT_DIR_ABS:0:1}" = "/" ]; then
	OUTPUT_DIR_ABS="$(pwd)/$OUTPUT_DIR_ABS"
fi

cd "$OUTPUT_DIR_ABS"

if [ ! -f "$PCAP_ABS" ]; then
	echo "ERROR: PCAP file disappeared after changing directory!"
	echo "PCAP_ABS: $PCAP_ABS"
	echo "Current directory: $(pwd)"
	exit 1
fi

# 1) TSHARK: base flows (MAC/IP/ports/protocol)
echo "Running tshark on: $PCAP_ABS"
tshark -r "$PCAP_ABS" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e frame.time_epoch \
	-e eth.src \
	-e eth.dst \
	-e eth.src.oui \
	-e eth.dst.oui \
	-e ip.src \
	-e ip.dst \
	-e tcp.srcport \
	-e tcp.dstport \
	-e udp.srcport \
	-e udp.dstport \
	-e _ws.col.Protocol \
	> flows.csv

# 2) TSHARK: DHCP vendors (if present)
tshark -r "$PCAP_ABS" \
	-Y "bootp.option.vendor_class_id" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e bootp.option.vendor_class_id \
	> dhcp_vendors.csv || true

# 3) TSHARK: HTTP (enhanced - methods, response codes, content types, server headers, all headers)
tshark -r "$PCAP_ABS" \
	-Y "http" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e http.request.method \
	-e http.host \
	-e http.request.uri \
	-e http.user_agent \
	-e http.server \
	-e http.response.code \
	-e http.content_type \
	-e http.file_data \
	-e http.response.phrase \
	-e http.request.full_uri \
	-e http.response.phrase \
	> http_requests.csv || true

# 3b) HTTP: Extract all response headers for device identification (OpenVAS-style)
echo "Extracting HTTP response headers for device fingerprinting..."
tshark -r "$PCAP_ABS" \
	-Y "http.response" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e http.response.code \
	-e http.server \
	-e http.x_powered_by \
	-e http.www_authenticate \
	-e http.location \
	> http_response_headers.csv || true

# 4) TSHARK: DNS (if any)
tshark -r "$PCAP_ABS" \
	-Y "dns.qry.name" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e dns.qry.name \
	> dns_queries.csv || true

# === OT / ICS protocol extracts ===

# 5) Modbus/TCP (port 502)
echo "Extracting Modbus/TCP data..."
tshark -r "$PCAP_ABS" \
	-Y "modbus" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e tcp.srcport \
	-e tcp.dstport \
	-e modbus.func_code \
	> modbus.csv || true

# 6) OPC UA (often port 4840)
echo "Extracting OPC UA data..."
tshark -r "$PCAP_ABS" \
	-Y "opcua" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e tcp.srcport \
	-e tcp.dstport \
	-e opcua.service_type \
	> opcua.csv || true

# 7) DNP3 (port 20000)
echo "Extracting DNP3 data..."
tshark -r "$PCAP_ABS" \
	-Y "dnp3" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e tcp.srcport \
	-e tcp.dstport \
	-e dnp3.func_code \
	> dnp3.csv || true

# 8) IEC 60870-5-104 (port 2404)
echo "Extracting IEC-104 data..."
tshark -r "$PCAP_ABS" \
	-Y "iec104" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e tcp.srcport \
	-e tcp.dstport \
	-e iec104.typeid \
	> iec104.csv || true

# 9) Siemens S7comm (port 102)
echo "Extracting S7comm data..."
tshark -r "$PCAP_ABS" \
	-Y "s7comm" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e tcp.srcport \
	-e tcp.dstport \
	-e s7comm.param.func \
	> s7comm.csv || true

# 10) ZEEK: full metadata (logs will appear in OUTPUT_DIR/zeek)
mkdir -p zeek
if command -v zeek >/dev/null 2>&1; then
	(
		cd zeek
		zeek -r "$PCAP_ABS"
	)
else
	echo "Warning: zeek command not found. Skipping Zeek analysis."
	echo "Zeek logs will not be available for enrichment."
fi

# 11) P0F: OS fingerprinting
p0f -r "$PCAP_ABS" -o p0f.log || true

# 12) SSH: Extract SSH banners and version strings (device identification)
echo "Extracting SSH device information..."
# Try different field names as they vary by Wireshark version
tshark -r "$PCAP_ABS" \
	-Y "ssh" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e ssh.protocol \
	-e ssh.software \
	-e ssh.client_protocol \
	-e ssh.server_protocol \
	> ssh_banners.csv 2>/dev/null || \
tshark -r "$PCAP_ABS" \
	-Y "ssh" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e frame.protocols \
	> ssh_banners.csv || true

# 13) SNMP: Extract device information (sysDescr, sysObjectID for device identification)
echo "Extracting SNMP device information..."
# Try different approaches as SNMP field names vary
tshark -r "$PCAP_ABS" \
	-Y "snmp" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e snmp.name \
	-e snmp.value.string \
	-e snmp.oid \
	> snmp_details.csv 2>/dev/null || \
tshark -r "$PCAP_ABS" \
	-Y "snmp" \
	-T fields \
	-E header=y -E separator=, -E quote=d \
	-e ip.src \
	-e ip.dst \
	-e snmp \
	> snmp_details.csv || true

# 13b) SNMP: Extract from Zeek logs if available (more reliable)
# This will be handled in enrich_pcap.py

# 14) nDPI: Deep Packet Inspection for application identification
echo "Running nDPI deep packet inspection..."
if command -v ndpiReader >/dev/null 2>&1; then
	ndpiReader -i "$PCAP_ABS" -w "$OUTPUT_DIR_ABS/ndpi_flows.csv" -C "$OUTPUT_DIR_ABS/ndpi_flows.csv" -q 2>/dev/null || \
	ndpiReader -i "$PCAP_ABS" -w "$OUTPUT_DIR_ABS/ndpi_flows.csv" -q 2>/dev/null || \
	ndpiReader -i "$PCAP_ABS" -w "$OUTPUT_DIR_ABS/ndpi_flows.csv" 2>/dev/null || true
	
	# Also try JSON output for more detailed information
	ndpiReader -i "$PCAP_ABS" -j "$OUTPUT_DIR_ABS/ndpi_flows.json" -q 2>/dev/null || \
	ndpiReader -i "$PCAP_ABS" -j "$OUTPUT_DIR_ABS/ndpi_flows.json" 2>/dev/null || true
else
	echo "Warning: ndpiReader command not found. Skipping nDPI analysis."
	echo "nDPI data will not be available for enrichment."
fi

echo "Analysis complete. Raw outputs are in: $OUTPUT_DIR_ABS"
echo "Next step: python3 /usr/local/bin/enrich_pcap.py \"$OUTPUT_DIR_ABS\""

