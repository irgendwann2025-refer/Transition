#!/bin/bash
# Logic: Identifies IPs with more than 5 failed login attempts in the current log.

LOG_FILE="/var/log/auth.log"
THRESHOLD=5
TEMP_BAN_LIST="/tmp/ban_candidates.txt"

echo "[*] Scanning $LOG_FILE for brute force patterns..."

# Extract IPs with "Failed Password" and count occurences
grep "Failed password" "$LOG_FILE" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"| \
sort | uniq -c | sort -nr > "$TEMP_BAN_LIST"

echo "--- [DETECTION] Potential Attackers ---"
printf "%-10s %-20s\n" "ATTEMPTS" "IP ADDRESS"

while read COUNT IP; do
	if [ "$COUNT" -gt "$THRESHOLD" ]; then
		echo -e "\033[0;31m[!] ALERT: $IP has $COUNT failed attempts!\033[0m"
	fi
done < "$TEMP_BAN_LIST"
