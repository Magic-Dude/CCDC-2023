#!/bin/bash
# chmod +x network_monitor.sh
# sudo ./network_monitor.sh
# Define network interface and output file
INTERFACE="eth0" # change eth0 to your network interface
OUTPUT_FILE="/var/log/network_traffic_$(date +%Y-%m-%d_%H-%M-%S).pcap"

# Number of packets to capture (0 for unlimited)
PACKET_COUNT=1000

# Capture filter (e.g., 'port 80' for HTTP traffic)
CAPTURE_FILTER=""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Start capturing packets
echo "Starting network traffic capture on interface $INTERFACE..."
tcpdump -i "$INTERFACE" -c "$PACKET_COUNT" -w "$OUTPUT_FILE" $CAPTURE_FILTER

echo "Capture complete. Output saved to $OUTPUT_FILE"