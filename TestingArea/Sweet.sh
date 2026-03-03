#!/bin/bash

# Ensure root
if [[ $EUID -ne 0 ]]; then echo "Run with sudo."; exit 1; fi

# --- CONFIG ---
DATA_DIR="/usr/local/share/.sys_data"
CRITICAL_FILES=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/crontab")
REPORT_FILE="security_report_$(date +%Y%m%d).txt"
mkdir -p "$DATA_DIR"

# --- MODULE: IMMUTABILITY ---
manage_immutability() {
    local action=$1 # +i or -i
    for file in "${CRITICAL_FILES[@]}"; do
        if [ -f "$file" ]; then chattr $action "$file" 2>/dev/null; fi
    done
    msg="SYSTEM THAWED" && [ "$action" == "+i" ] && msg="SYSTEM FROZEN"
    wall "SECURITY DASHBOARD: $msg"
}

# --- MODULE: ENUMERATION & AUDIT ---
run_audit() {
    echo "[*] Running Full Enumeration..."
    {
        echo "=== AUDIT: $(date) ==="
        echo "Host: $(hostname) | IP: $(hostname -I)"
        echo "--- ACTIVE CONNECTIONS (LSOF) ---"
        lsof -i -nP -sTCP:ESTABLISHED
        echo "--- DELETED BINARIES IN RAM ---"
        lsof +L1 | grep "(deleted)"
        echo "--- RECENT SENSITIVE MODS ---"
        find /etc /tmp -ctime -1 -ls
    } > "$REPORT_FILE"
    
    # Run rkhunter check
    rkhunter --check --sk --no-colors --report-warnings-only >> "$REPORT_FILE" 2>&1
    
    whiptail --msgbox "Audit Complete. Report: $REPORT_FILE" 10 50
}

# --- MODULE: AIDE INTEGRITY ---
check_integrity() {
    if ! aide --check > /tmp/aide_report 2>&1; then
        CHANGES=$(grep -E "added:|changed:|removed:" /tmp/aide_report | xargs)
        echo -e "\a" | wall
        echo "!! SECURITY ALERT: SYSTEM MODIFICATION DETECTED !!" | wall
        echo "DETAILS: $CHANGES" | wall
        # Auto-re-freeze as a defensive measure
        manage_immutability "+i"
    else
        whiptail --msgbox "Integrity Verified: No unauthorized changes." 8 45
    fi
}

# --- MAIN DASHBOARD ---
while true; do
    CHOICE=$(whiptail --title "CENTRAL SECURITY DASHBOARD" --menu "Select Operation" 20 70 10 \
    "1" "Audit & Enumerate (Generate Report)" \
    "2" "Freeze System (Set Immutable +i)" \
    "3" "Thaw System (Allow Maintenance -i)" \
    "4" "Check File Integrity (AIDE)" \
    "5" "Update AIDE Baseline (After Maintenance)" \
    "6" "Install/Update Tools (rkhunter/AIDE)" \
    "7" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) run_audit ;;
        2) manage_immutability "+i" ;;
        3) manage_immutability "-i" ;;
        4) check_integrity ;;
        5) 
            manage_immutability "-i"
            aide --update && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            manage_immutability "+i"
            whiptail --msgbox "Baseline Updated & Re-Frozen." 8 40
            ;;
        6)
            apt update && apt install -y rkhunter aide lsof strace
            aideinit -y -f && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            rkhunter --update --propupd
            ;;
        *) exit 0 ;;
    esac
done
