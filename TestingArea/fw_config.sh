#!/bin/bash
# Purpose: Secure IPtables firewall with session persistence and auto-lockout protection.

if [[ $EUID -ne 0 ]]; then echo "Run as root."; exit 1; fi

DATA_DIR="/usr/local/share/.sys_data"
IP_FILE="$DATA_DIR/.accepted_ips"
PORT_FILE="$DATA_DIR/.accepted_ports"
mkdir -p "$DATA_DIR"
touch "$IP_FILE" "$PORT_FILE"

is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS; IFS='.'; ip=($ip); IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        return $?
    fi
    return 1
}

apply_rules() {
    MODE=$1
    CURRENT_SESSION_IP=$(echo $SSH_CLIENT | awk '{print $1}')

    iptables -F && iptables -X && iptables -Z
    ip6tables -F 2>/dev/null && ip6tables -P INPUT DROP 2>/dev/null

    # 1. Critical Allows
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    [ ! -z "$CURRENT_SESSION_IP" ] && iptables -A INPUT -s "$CURRENT_SESSION_IP" -j ACCEPT

    # 2. Whitelist
    while read -r ip; do [ ! -z "$ip" ] && iptables -A INPUT -s "$ip" -j ACCEPT; done < "$IP_FILE"

    if [ "$MODE" == "panic" ]; then
        [ -x "$(command -v conntrack)" ] && conntrack -F 2>/dev/null
        iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
    else
        while read -r port; do
            [ ! -z "$port" ] && iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        done < "$PORT_FILE"
        # SSH Rate Limit
        iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH
        iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 3 --name SSH -j DROP
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    fi

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Persistence
    [ -d "/etc/iptables" ] && iptables-save > /etc/iptables/rules.v4
}

# Add whiptail menu logic here as per previous iterations...
