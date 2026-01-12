#!/bin/bash
# Logic: Detects log clearing and unauthorized sudo usage.

echo "--- [DETECTION] Unauthorized/Failed Sudo Attempts ---"
sudo grep "COMMAND=" /var/log/auth.log | tail -n 10

echo -e "\n--- [DETECTION] Suspicious Log Clearing ---"
# Check if history file is smaller than expected or missing
HISTORY_SIZE=$(wc -l < ~/.bash_history)
if [ "$HISTORY_SIZE" -lt 10 ]; then
	echo "[!] WARNING: Bash history is suspiciously short ($HISTORY_SIZE lines).
fi

