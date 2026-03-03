#!/bin/bash
# comp_malware_detect.sh - Behavioral detection for Linux competition hosts
OUT="/tmp/comp_indicators.txt"
echo "--- Competition Threat Scan ---" > $OUT

# 1. Reverse Shell Detection
echo "[!] Checking for active reverse shell patterns (/dev/tcp)..." >> $OUT
lsof -i | grep -E "bash|sh|python|perl|php|ruby" | grep "ESTABLISHED" >> $OUT

# 2. Persistence Check: Malicious systemd services
echo "[!] Checking for non-standard systemd services..." >> $OUT
find /etc/systemd/system/ -type f -mmin -120 >> $OUT

# 3. Hidden File Drift in Public Web Directories
echo "[!] Scanning web roots for hidden scripts (.php, .sh)..." >> $OUT
find /var/www/html -name ".*" -ls >> $OUT

echo "[+] Scan Complete. Results in $OUT"
