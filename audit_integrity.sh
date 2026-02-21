#!/bin/bash
# audit_integrity.sh - Config File Integrity & Binary Hash Audit

LOG="/tmp/integrity_report.txt"
BASELINE="/tmp/config_baseline.hash"
echo "--- [INTEGRITY] Config & Binary Audit ($(date)) ---" > "$LOG"

# 1. Define Config Naming Conventions & Paths
# Targets common app configs: nginx, apache, mysql, postgres, redis, systemd, etc.
CONFIG_PATHS="/etc /var/www /opt /usr/local/etc"
CONFIG_EXTENSIONS="-name *.conf -o -name *.yaml -o -name *.yml -o -name *.ini -o -name *.xml -o -name .env"

echo "[*] Scanning for application-related config files..." >> "$LOG"

# 2. Identify and Hash Config Files
# This creates a current state of all found config files
find $CONFIG_PATHS -type f \( $CONFIG_EXTENSIONS \) 2>/dev/null | xargs md5sum > /tmp/current_configs.hash

# 3. Detect Changes (If baseline exists)
if [ -f "$BASELINE" ]; then
    echo -e "\n[!] CONFIGURATION DRIFT DETECTED:" >> "$LOG"
    diff "$BASELINE" /tmp/current_configs.hash | grep "^>" | awk '{print "MODIFIED: " $3}' >> "$LOG"
else
    echo "[i] No baseline found. Creating initial baseline now..." >> "$LOG"
    cp /tmp/current_configs.hash "$BASELINE"
fi

# 4. Standard Binary Integrity Check
echo -e "\n[*] Checking Core Binaries (/bin, /sbin)..." >> "$LOG"
debsums -s 2>/dev/null >> "$LOG" || echo "Note: Install 'debsums' for package-level integrity." >> "$LOG"

echo "[+] Integrity Scan Complete."
