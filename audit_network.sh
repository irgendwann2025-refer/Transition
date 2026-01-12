#!/bin/bash
# Logic: Identifies all listening ports and the specific process/user owning them

echo "--- [RECON] Active Listening Ports ---"
printf "%-10s %-10s %-20s %-10s\n" "PROTO" "PORT" "PROCESS" "USER"
echo "--------------------------------------------------------"

# Uses ss to grab TCP/UDP Listening ports and parses the process name
sudo ss -tulpn | grep LISTEN | awk '{
	split($5, addr, ":");
	split($7, proc, "\"");
	printf "%-10s %-10s %-20s %-10s\n", $1 addr[length(addr)], proc[2], $6
}'

echo -e "\n--- [DETECTION] Established External Connections ---"
# Checks for any active outbound connectoin that isn't lcoal
sudo ss -atn | grep ESTAB | grep -v "127.0.0.1"
