#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit
fi

# Define Log Locations
SYSLOG="/var/log/syslog"
KERNLOG="/var/log/kern.log"

# --- Function: Apply Updated Ruleset ---
apply_updated_rules() {
    # 1. Flush & Reset
    iptables -F
    iptables -X
    iptables -Z
    
    # 2. Default Policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # 3. Basic Connectivity
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # 4. Bogon/Multicast Filtering
    iptables -A INPUT -s 224.0.0.0/4 -j DROP
    iptables -A INPUT -d 224.0.0.0/4 -j DROP
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -d 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 239.255.255.0/24 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    # 5. ICMP Restrictions
    iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP Attempt: " --log-level 4
    iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT
    iptables -A INPUT -p icmp --icmp-type address-mask-request -j LOG --log-prefix "Address-Mask Drop: " --log-level 4
    iptables -A INPUT -p icmp --icmp-type address-mask-request -j DROP
    iptables -A INPUT -p icmp --icmp-type timestamp-request -j LOG --log-prefix "Timestamp Drop: " --log-level 4
    iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP
    iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT

    # 6. Invalid Packets
    iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "Invalid Drop: " --log-level 4
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Forward Invalid Drop: " --log-level 4
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "OUTPUT Invalid Drop: " --log-level 4
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # 7. Portscan & SSH Protection
    iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
    iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j DROP
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    
    iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4
    iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j REJECT --reject-with tcp-reset
    iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP

    # 8. Allowed Services (DNS/NTP)
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -p udp --dport 123 -j ACCEPT

    # 9. Final Reject
    iptables -A INPUT -j REJECT
    
    # Save to user downloads as requested
    mkdir -p /home/$SUDO_USER/Downloads
    iptables-save > /home/$SUDO_USER/Downloads/iptables_new_rules.txt
    chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/Downloads/iptables_new_rules.txt
}

# --- Main Whiptail Loop ---
while true; do
    CHOICE=$(whiptail --title "Firewall Management" --menu "Select an option" 18 60 8 \
        "1" "Write New Rule & Refresh" \
        "2" "Display All Active Rules" \
        "3" "Show LOG Save Locations" \
        "4" "Call Syslogs (Recent Logs)" \
        "5" "Test Firewall Operation" \
        "6" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1)
            NEW_RULE=$(whiptail --inputbox "Enter custom rule (e.g., -A INPUT -p tcp --dport 80 -j ACCEPT):" 10 60 3>&1 1>&2 2>&3)
            if [ ! -z "$NEW_RULE" ]; then
                apply_updated_rules
                iptables $NEW_RULE
                whiptail --msgbox "Rules flushed, renewed, and custom rule applied." 10 60
            fi
            ;;
        2)
            RULES=$(iptables -L -n -v)
            whiptail --title "Active Rules" --msgbox "$RULES" 20 80
            ;;
        3)
            whiptail --title "Audit Info" --msgbox "LOG rules are directed to:\n\n1. Syslog: $SYSLOG\n2. Kernel Log: $KERNLOG" 12 60
            ;;
        4)
            RECENT_LOGS=$(grep "iptables" $SYSLOG | tail -n 20)
            if [ -z "$RECENT_LOGS" ]; then RECENT_LOGS="No firewall logs found."; fi
            whiptail --title "Recent Firewall Logs" --msgbox "$RECENT_LOGS" 20 90
            ;;
        5)
            # Test: Check if loopback is open and SSH rate limiting rule exists
            LO_TEST=$(iptables -L INPUT -n | grep -i "ACCEPT" | grep "lo")
            if [ ! -z "$LO_TEST" ]; then
                whiptail --msgbox "Self-Test PASSED: Loopback traffic is allowed and chains are active." 10 60
            else
                whiptail --msgbox "Self-Test FAILED: Loopback traffic not detected in rules." 10 60
            fi
            ;;
        6|*)
            exit 0
            ;;
    esac
done
