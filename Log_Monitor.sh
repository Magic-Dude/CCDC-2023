#!/bin/bash
#chmod +x log_monitor.sh

# Define the log file to monitor
LOG_FILE="/var/log/auth.log"

# Define patterns to watch for, separated by |
PATTERNS="Failed|Error|Refused"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Tail the log file in real-time and search for patterns
tail -F "$LOG_FILE" | grep --line-buffered -E "$PATTERNS" | while read -r line ; do
    echo "Suspicious activity detected: $line"
    # Here you can add actions to be taken when a pattern is matched
    # For example, send an email, write to another log, etc.
done