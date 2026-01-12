#!/bin/bash
# Logic: Checks whitelist before calling manage_bans.sh

IP_TO_BAN=$1
WHITELIST="/etc/proc_whitelist.txt" # Reusing your existing whitelist file

if grep -q "$IP_TO_BAN" "$WHITELIST"; then
	echo "[!] SKIPPING: $IP_TO_BAN is whitelisted. No action taken."
else
	./manage_bans.sh ban "$IP_TO_BAN"
fi
