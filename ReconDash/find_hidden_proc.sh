#!/bin/bash

WHITELIST_FILE="/etc/proc_whitelist.txt"
SYSTEM_PIDS=$(systemctl status | grep -oP '(?<=-)[0-9]+' | tr '\n' ' ')

# --- Funciton: Generate Whitelist ---
generate_whitelist() {
	echo "[*] Generating whitelist from current running processes..."
	# Get all running process executables, sort them, and remove duplicates
	ps -eo exe | grep -v "EXE" | grep -v "^$" | sort -u > "$WHITELIST_FILE"
	echo "[+] Whitelist created at $WHITELIST_FILE ($(wc -l < "$WHITELIST_FILE") items)."
}

# Check if whitelist exists; if not, ask to create it
if [ ! -f "$WHITELIST_FILE" ]; then
	read -p "No whitelist found. Create one now based on current state? (y/n): " choice
	if [[ "$choice" == "y" ]]; then
		generate_whitelist
		exit 0
	else
		echo "[!] Cannot proceed without a whitelist or a baseline."
		exit 1
	fi
fi

echo "--- [DETECTION] Scanning for Unmanaged & Non-Whitelisted Processes ---"

# Loop through all active PIDs
for pid in $(ps -ef | awk '{print $2}' | tail -n +2); do
	# Skip if PID doesn't exist anymore (race condition)
	[ ! -d "/proc/$pid" ] && continue

	EXE_PATH=$(readlink -f /proc/$pid/exe 2>/dev/null)

	# Check 1: Is it in the Whitelist?
	if ! grep -Fxq "$EXE_PATH" "$WHITELIST_FILE"; then

		# Check 2: Is it managed by Systemd?
		if [[ ! " $SYSTEM_PIDS " =~ " $pid " ]]; then
			CMD_LINE=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
			echo "[ALERT] NEW/UNKNOWN PROCESS: PID $pid | Path: $EXE_PATH"
			echo "	Command: $CMD_LINE"
		fi
	fi
done

# --- Check for Hidden/Deleted Executables ---
echo -e "\n--- [DETECTION] Scanning for processes running from DELETED files ---"
# This detects binaries that were deleted after execution
ls -al /proc/*/exe 2>/dev/null | grep "(deleted)"
