#!/bin/bash
# ==============================================================================
# RECON & FORENSIC DASHBOARD - UNIFIED COMPETITION EDITION
# Combines Network Recon, Service Auditing, and Malware Indicator Detection
# ==============================================================================

# --- Internal Tool Logic (Implicitly replaces external .sh files if missing) ---

run_malware_detect() {
    OUT="/tmp/comp_indicators.txt"
    echo "--- Forensic Threat Scan ($(date)) ---" > "$OUT"
    echo -e "\n[!] Checking for unauthorized ptrace (Process Injection)..." >> "$OUT"
    grep -r "ptrace" /proc/*/stack 2>/dev/null | grep -v "self" >> "$OUT"
    echo -e "\n[!] Searching for Reverse Shells (ESTABLISHED /dev/tcp)..." >> "$OUT"
    lsof -i -P -n | grep -E "bash|sh|python|perl|php|ruby" | grep "ESTABLISHED" >> "$OUT"
    echo -e "\n[!] Checking for suspicious binary strings (execve/sigsetmask)..." >> "$OUT"
    find /tmp /dev/shm -type f -exec strings {} + 2>/dev/null | grep -E "execve|sigsetmask" >> "$OUT"
    whiptail --title "Malware Indicator Results" --textbox "$OUT" 20 90
}

run_cred_audit() {
    WORDLIST="/tmp/comp_creds.txt"
    AUDIT_LOG="/tmp/cred_audit.txt"
    # Generate list if it doesn't exist
    [ ! -f "$WORDLIST" ] && printf "admin:admin\nroot:root\npostgres:postgres\nmysql:mysql\n" > "$WORDLIST"
    
    echo "--- Credential & Service Log Audit ---" > "$AUDIT_LOG"
    echo -e "\n[!] Checking HTTP/SQL Logs for Auth Failures..." >> "$AUDIT_LOG"
    grep -iE "401|403|access denied|password authentication failed" /var/log/apache2/access.log /var/log/nginx/access.log /var/log/mysql/error.log 2>/dev/null | tail -n 20 >> "$AUDIT_LOG"
    whiptail --title "Credential Audit" --textbox "$AUDIT_LOG" 20 90
}

# --- Main Dashboard UI ---

CHOICE=$(whiptail --title "Ubuntu Security Recon Dashboard" --menu "Choose an audit option to run:" 20 70 12 \
"1" "Network Audit (Listeners & Connections)" \
"2" "Persistence Check (Cron & Timers)" \
"3" "File Integrity (Binary Hashes)" \
"4" "Log Analysis (Sudo & History)" \
"5" "Find Hidden Services/Process" \
"6" "Scan Logs for Attackers (Bruteforce)" \
"7" "Show Current Bans (Fail2Ban/IPTable)" \
"8" "Check Services Health" \
"9" "Forensic Malware Scan (ptrace/injection)" \
"10" "Credential Audit (HTTP/SQL/SSH Logs)" \
"11" "Generate Competition Wordlist" 3>&1 1>&2 2>&3)

# Handle the user's choice
case $CHOICE in
	1)
		clear
		echo "Running Network Audit..."
		./audit_network.sh || ss -tunlp
		;;
	2)
		clear
		echo "Checking Persistence..."
		./audit_persistence.sh || crontab -l
		;;
	3)
		clear
		echo "Checking File Integrity..."
		./audit_integrity.sh
		;;
	4)
		clear
		echo "Analyzing Logs..."
		./audit_logs.sh || tail -n 50 /var/log/auth.log
		;;
	5)
		clear
		echo "Scanning for Hidden Processes..."
		./find_hidden_proc.sh || ps auxf
		;;
	6)
		clear
		echo "Scanning logs for attackers..."
		./detect_bruteforce.sh
		;;
	7)
		clear
		echo "Current Bans:"
		if [ -f "./manage_bans.sh" ]; then
			./manage_bans.sh list
			read -p "Enter IP to UNBAN (or leave blank): " UNBAN_IP
			[ ! -z "$UNBAN_IP" ] && ./manage_bans.sh unban "$UNBAN_IP"
		else
			iptables -L -n
		fi
		;;
	8)
		clear
		echo "Checking Service Health..."
		./serv_health.sh || systemctl list-units --type=service --state=running
		;;
	9)
		run_malware_detect
		;;
	10)
		run_cred_audit
		;;
	11)
		# Quick generation of the competition wordlist we discussed
		printf "admin:admin\nroot:password\npostgres:postgres\nmysql:mysql\ntomcat:tomcat\n" > /tmp/comp_creds.txt
		whiptail --msgbox "Wordlist generated at /tmp/comp_creds.txt" 8 45
		;;
	*)
		echo "Exiting..."
		exit 0
		;;
esac

# Pause so the user can see the output before returning
echo ""
read -p "Press [Enter] to return to dashboard..."
exec "$0"
