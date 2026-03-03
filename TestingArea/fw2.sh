#!/bin/bash

# Ensure root
if [ "$EUID" -ne 0 ]; then echo "Run with sudo: sudo ./fw.sh"; exit 1; fi

# --- 1. CONFIG & STORAGE ---
DATA_DIR="/usr/local/share/.sys_data"
IP_FILE="$DATA_DIR/.accepted_ips"
PORT_FILE="$DATA_DIR/.accepted_ports"
mkdir -p "$DATA_DIR"
touch "$IP_FILE" "$PORT_FILE"

# --- 2. VALIDATION ENGINE ---
is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS; IFS='.'; ip=($ip); IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        return $?
    fi
    return 1
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# --- 3. THE DASHBOARD ---
show_menu() {
    CHOICE=$(whiptail --title "FIREWALL SUITE: PERSISTENT MODE" --menu "Navigate" 20 75 8 \
    "1" "Add Accepted IPs (Safe List)" \
    "2" "Add Allowed Ports" \
    "3" "APPLY ALL SECURITY RULES" \
    "4" "PANIC: Full Lockdown" \
    "5" "View Live Rules (-L)" \
    "6" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) 
            IPS=$(whiptail --inputbox "Enter IPs (comma separated):" 10 60 3>&1 1>&2 2>&3)
            if [ ! -z "$IPS" ]; then
                for ip in $(echo "$IPS" | tr ',' ' '); do
                    is_valid_ip "$ip" && echo "$ip" >> "$IP_FILE" || whiptail --msgbox "Invalid IP: $ip" 8 40
                done
                sort -u -o "$IP_FILE" "$IP_FILE"
            fi
            show_menu ;;
        2) 
            PORTS=$(whiptail --inputbox "Enter Ports (comma separated):" 10 60 3>&1 1>&2 2>&3)
            if [ ! -z "$PORTS" ]; then
                for port in $(echo "$PORTS" | tr ',' ' '); do
                    is_valid_port "$port" && echo "$port" >> "$PORT_FILE" || whiptail --msgbox "Invalid Port: $port" 8 40
                done
                sort -u -o "$PORT_FILE" "$PORT_FILE"
            fi
            show_menu ;;
        3) apply_rules "standard" ;;
        4) apply_rules "panic" ;;
        5) clear; iptables -L -n -v --line-numbers; echo -e "\nPress Enter..."; read; show_menu ;;
        *) exit ;;
    esac
}

# --- 4. THE ENGINE ---
apply_rules() {
    MODE=$1
    
    # Identify CURRENT USER'S IP (Critical Safety Net)
    # SSH_CLIENT format: [IP] [Client Port] [Server Port]
    CURRENT_SESSION_IP=$(echo $SSH_CLIENT | awk '{print $1}')

    iptables -F && iptables -X && iptables -Z
    ip6tables -F 2>/dev/null && ip6tables -P INPUT DROP 2>/dev/null

    # --- PHASE A: PROTECTION ---
    # 1. Loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # 2. State Tracking (Maintain Active Session)
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 3. AUTO-PROTECT CURRENT IP
    if [ ! -z "$CURRENT_SESSION_IP" ]; then
        iptables -A INPUT -s "$CURRENT_SESSION_IP" -m comment --comment "Auto-Protect Active Admin" -j ACCEPT
    fi

    # 4. Whitelist
    while read -r ip; do
        [ -z "$ip" ] && continue
        iptables -A INPUT -s "$ip" -j ACCEPT
    done < "$IP_FILE"

    # --- PHASE B: MODE LOGIC ---
    if [ "$MODE" == "panic" ]; then
        echo "LOCKDOWN INITIATED" | wall 2>/dev/null
        [ -x "$(command -v conntrack)" ] && conntrack -F 2>/dev/null
        
        # Kill SSH sessions NOT originating from your IP
        for pid in $(ps -ef | grep sshd | grep -v grep | awk '{print $2}'); do
            if ! ps -fp $pid | grep -q "$(tty | sed 's|/dev/||')"; then
                kill -9 $pid 2>/dev/null
            fi
        done
        iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
    else
        # Standard Rules: Ports, SSH Guard, and Bad IPs
        while read -r port; do
            [ -z "$port" ] && continue
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done < "$PORT_FILE"

        # Rate-Limited SSH Guard (3 hits / 60s)
        iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
        iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 -j DROP
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    fi

    # --- PHASE C: PERSISTENCE ---
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Save rules for iptables-persistent
    if [ -d "/etc/iptables" ]; then
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
    fi

    whiptail --msgbox "Rules Applied & Saved to /etc/iptables/rules.v4" 10 50
    show_menu
}

show_menu
