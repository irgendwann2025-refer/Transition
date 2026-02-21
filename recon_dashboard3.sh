#!/bin/bash
# ==============================================================================
# FINAL RECON & FORENSIC DASHBOARD
# ==============================================================================

# --- Internal Functions (Forensics & Self-Healing) ---

run_malware_detect() {
    OUT="/tmp/forensic_indicators.txt"
    echo "--- Forensic Threat Scan ---" > "$OUT"
    echo "[!] Unauthorized ptrace (Injection):" >> "$OUT"
    grep -r "ptrace" /proc/*/stack 2>/dev/null | grep -v "self" >> "$OUT"
    echo "[!] Active Reverse Shells:" >> "$OUT"
    lsof -i -P -n | grep -E "bash|sh|python|perl|php|ruby" | grep "ESTABLISHED" >> "$OUT"
    whiptail --title "Malware Scan" --textbox "$OUT" 20 90
}

run_drift_purge() {
    DRIFT_LOG="/tmp/drift_report.txt"
    find /tmp /dev/shm /var/www/html -not -user "$USER" -mmin -30 -type f 2>/dev/null > "$DRIFT_LOG"
    if [ -s "$DRIFT_LOG" ]; then
        if (whiptail --title "Purge Unauthorized Drift?" --yesno "Suspicious files:\n$(cat $DRIFT_LOG)\n\nDelete these files?" 20 80); then
            find /tmp /dev/shm /var/www/html -not -user "$USER" -mmin -30 -type f -delete 2>/dev/null
            whiptail --msgbox "Files Purged." 8 30
        fi
    else
        whiptail --msgbox "No unauthorized drift detected in the last 30m." 8 45
    fi
}

# --- Main UI Loop ---

while true; do
    CHOICE=$(whiptail --title "Ubuntu Security Recon Dashboard" --menu "Select Operation:" 22 75 14 \
    "1" "Network Audit (Listeners & Ports)" \
    "2" "Persistence Check (Cron & Timers)" \
    "3" "Integrity Scan (Binaries & Configs)" \
    "4" "Log Analysis (Sudo & History)" \
    "5" "Find Hidden Services/Processes" \
    "6" "Scan Logs for Attackers" \
    "7" "Show Bans & Jail Status" \
    "8" "Check Services Health" \
    "9" "Forensic Malware Scan (ptrace/injection)" \
    "10" "Credential & Service Log Audit" \
    "11" "Generate Competition Wordlist" \
    "12" "Scan & Purge File Drift (Last 30m)" \
    "13" "AUTO-CONFIGURE FAIL2BAN JAILS" \
    "14" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) clear; ./audit_network.sh ;;
        2) clear; ./audit_persistence.sh ;;
        3) clear; ./audit_integrity.sh ;;
        7) 
            clear; echo "--- Fail2Ban Jail Status ---"
            sudo fail2ban-client status
            echo -e "\nPress Enter to return..." && read
            ;;
        9) run_malware_detect ;;
        10) ./audit_logs.sh ;;
        11) printf "admin:admin\nroot:password\n" > /tmp/comp_creds.txt ;;
        12) run_drift_purge ;;
        13) clear; ./setup_fail2ban.sh; sleep 2 ;;
        14) exit 0 ;;
        *) break ;;
    esac
done
