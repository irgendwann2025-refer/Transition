#!/bin/bash
# Logic: Generates/Checks MD5 Hashes for critical system binaries.

CHECK_DIR="/usr/bin"
BINARIES=("ls" "ps" "ss" "netstat" "iptables" "ssh")
HASH_FILE="/root/sys_hashes.txt"

# IF first run, create the baseline
if [ ! -f "$HASH_FILE" ]; then
	echo "Creating initial hash baseline..."
	for bin in "${BINARIES[@]}"; do
		sha256sum "$CHECK_DIR/$bin" >> "$HASH_FILE"
	done
	echo "Baseline created in $HASH_FILE. Protect this file!"
	exit 0
fi

# Compare current hashes to Baseline
echo "--- [DETECTION] File Integrity Check ---"
sha256sum -c "$HASH_FILE" 2>/dev/null | grep "FAILED" || echo "All binaries verified."
