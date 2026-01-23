#!/bin/bash

# Define the menu options
CHOICE=$(whiptail --title "Ubuntu Security Recon Dashboard" --menu "Choose an audit option to run:" 15 60 6 \
"1" "Network Audit (Listeners & Connections)" \
"2" "Persistence Check (Cron & Timers)" \
"3" "File Integrity (Binary Hashes)" \
"4" "Log Analysis (Sudo & History)" \
"5" "Find Hidden Services/Process" \
"6" "Scan Logs for Attackers" \
"7" "Show Current Bans" 3>&1 1>&2 2>&3)

# Handle the user's choice
case $CHOICE in
	1)
		clear
		echo "Running Network Audit..."
		./audit_network.sh
		;;
	2)
		clear
		echo "Checking Persistence..."
		./audit_persistence.sh
		;;
	3)
		clear
		echo "Checking File Integrity..."
		./audit_integrity.sh
		;;
	4)
		clear
		echo "Analyzing Logs..."
		./audit_logs.sh
		;;
	5)
		clear
		echo "Scanning for Hidden Processes..."
		./find_hidden_proc.sh
		;;
	6)
		clear
		echo "Scanning logs for attackers..."
		./detect_bruteforce3.sh
		;;
	7)
		clear
		echo "Current Bans:"
		./manage_bans.sh list
		read -p "Enter IP to UNBAN (or leave blank): " UNBAN_IP
		[ ! -z "$UNBAN_IP" ] && ./manage_bans.sh unban "$UNBAN_IP"
		;;
	*)
		echo "Exiting..."
		exit 0
		;;
esac

# Pause so the user can see the output before returning
read -p "Press [Enter] to return to dashboard..."
exec ./recon_dashboard.sh
