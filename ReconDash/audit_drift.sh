#!/bin/bash
# audit_drift.sh - Detect and remediate unauthorized file creations

LOG="/tmp/drift_report.txt"
CURRENT_USER=$(whoami)
# Define target directories for scanning
TARGETS="/tmp /dev/shm /var/www/html /root"

echo "--- [DRIFT DETECTION] Files created in the last 30 mins ---" > "$LOG"
echo "Baseline: $(date -d '30 minutes ago')" >> "$LOG"
echo "--------------------------------------------------------" >> "$LOG"

# 1. Find and Log files
# -not -user ignores your files
# -mmin -30 looks for files modified/created in the last 30 mins
find $TARGETS -not -user "$CURRENT_USER" -mmin -30 -type f 2>/dev/null >> "$LOG"

# 2. Remediation Provision
if [ -s "$LOG" ]; then
    echo -e "\n[!] UNAUTHORIZED FILES DETECTED!" >> "$LOG"
    
    # Prompting via Whiptail happens in the dashboard, 
    # but here is the logic if run standalone:
    while read -r file; do
        if [[ "$file" == /tmp* || "$file" == /var/www/html* ]]; then
             echo "[ACTION] Removing suspicious file: $file" >> "$LOG"
             # rm -f "$file" # Uncomment to enable active deletion
        fi
    done < <(grep "^/" "$LOG")
else
    echo "No unauthorized drift detected." >> "$LOG"
fi
