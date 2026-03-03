#!/bin/bash

# Ensure root
if [[ $EUID -ne 0 ]]; then echo "Run with sudo."; exit 1; fi

REPORT_FILE="security_audit_v4_$(date +%Y%m%d).txt"
IOC_LOG="ioc_analysis_v4.log"

# --- PART 1: INSTALLATION & UPDATES ---
install_rkhunter() {
    echo "[*] Checking for rkhunter..."
    if ! command -v rkhunter >/dev/null; then
        echo "[+] Installing rkhunter..."
        apt-get update -y && apt-get install -y rkhunter
    fi
    # Update rkhunter properties and data files
    rkhunter --versioncheck
    rkhunter --update
    rkhunter --propupd # Baseline system file properties
}

# --- PART 2: DATA COLLECTION & ENUMERATION ---
{
    echo "AUDIT START: $(date)"
    echo "Hostname: $(hostname)"
    echo "Active User: $USER"
    echo "----------------------------------------------------------"
} > "$REPORT_FILE"

# SECTION A: RKHUNTER SCAN
echo -e "\n### SECTION A: RKHUNTER ROOTKIT SCAN ###" >> "$REPORT_FILE"
# Run scan in check mode, skip interactive prompts
rkhunter --check --sk --no-colors --report-warnings-only >> "$REPORT_FILE" 2>&1

# SECTION B: ACTIVE ANALYSIS (lsof & strace)
echo -e "\n### SECTION B: ACTIVE BEHAVIORAL ANALYSIS ###" >> "$REPORT_FILE"
echo "--- LSOF: Hidden/Deleted Binaries in RAM ---" >> "$REPORT_FILE"
lsof +L1 | grep "(deleted)" >> "$REPORT_FILE"

echo "--- STRACE: Sensitive File Access (3s Capture) ---" >> "$REPORT_FILE"
# Monitoring for any process attempting to open the shadow file
timeout 3 strace -e openat -f -p 1 2>&1 | grep "shadow" >> "$REPORT_FILE"

# SECTION C: INTEGRITY & PERSISTENCE
echo -e "\n### SECTION C: PERSISTENCE AUDIT ###" >> "$REPORT_FILE"
ls -laR /etc/cron* >> "$REPORT_FILE"
find / -user root -perm -4000 -print 2>/dev/null >> "$REPORT_FILE" # SUID binaries

# --- PART 3: REAL-TIME IOC ANALYSIS ---
analyze_iocs() {
    # Check if rkhunter found anything
    if grep -i "warning" "$REPORT_FILE" | grep -v "skipped" > /dev/null; then
        echo "[!] FLAG: Rootkit Warning" >> "$IOC_LOG"
        echo "    Reason: Rkhunter detected file property changes or suspected rootkit strings." >> "$IOC_LOG"
        echo "    Resolution: Review /var/log/rkhunter.log for specific file warnings." >> "$IOC_LOG"
    fi
    
    # Check for Keylogger signatures
    if lsmod | grep -E "logkeys|snoopy" > /dev/null; then
        echo "[!] FLAG: Possible Keylogger Module" >> "$IOC_LOG"
        echo "    Reason: Loaded kernel modules associated with input logging." >> "$IOC_LOG"
        echo "    Resolution: Use 'rmmod' to remove the module and investigate its source." >> "$IOC_LOG"
    fi
}

# Run the modules
install_rkhunter
analyze_iocs

echo "Audit Complete. Results saved to $REPORT_FILE and $IOC_LOG"
