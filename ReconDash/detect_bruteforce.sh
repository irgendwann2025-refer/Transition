#!/bin/bash
set -euo pipefail

########################################
# CONFIGURATION
########################################
CHAIN="BAD-ACTORS"
F2B_JAIL="sshd"
WHITELIST="/etc/proc_whitelist.txt"
BAN_LOG="/var/log/auth.log"

# Persistent save locations (Debian/Ubuntu)
IPTABLES_SAVE_V4="/etc/iptables/rules.v4"

########################################
# ROOT CHECK
########################################
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run as root."
    exit 1
fi

########################################
# FUNCTIONS
########################################
ensure_chain() {
    iptables -N "$CHAIN" 2>/dev/null || true

    if ! iptables -C INPUT -j "$CHAIN" 2>/dev/null; then
        iptables -I INPUT 1 -j "$CHAIN"
    fi
}

save_iptables() {
    echo "[*] Saving iptables rules persistently..."
    iptables-save > "$IPTABLES_SAVE_V4"
}

unban_ip() {
    local IP="$1"

    echo "[*] Unbanning $IP"

    # Remove from iptables (if present)
    while iptables -C "$CHAIN" -s "$IP" -j DROP 2>/dev/null; do
        iptables -D "$CHAIN" -s "$IP" -j DROP
    done

    # Remove from Fail2ban
    if fail2ban-client status "$F2B_JAIL" >/dev/null 2>&1; then
        fail2ban-client set "$F2B_JAIL" unbanip "$IP" || true
    fi

    save_iptables
    echo "$(date '+%F %T'): Unbanned $IP" >> "$BAN_LOG"
}

########################################
# UNBAN MODE (ARGUMENT OR PROMPT)
########################################
if [[ "${1:-}" == "unban" ]]; then
    if [[ -n "${2:-}" ]]; then
        unban_ip "$2"
        exit 0
    else
        read -rp "Enter IP to unban: " IP
        unban_ip "$IP"
        exit 0
    fi
fi

########################################
# NORMAL BAN SYNC MODE
########################################
ensure_chain

echo "[*] Syncing Fail2ban bans from jail: $F2B_JAIL"

BANNED_IPS=$(fail2ban-client status "$F2B_JAIL" \
    | awk -F: '/Banned IP list/ {print $2}')

if [[ -z "$BANNED_IPS" ]]; then
    echo "[+] No Fail2ban bans to process."
    exit 0
fi

for IP in $BANNED_IPS; do

    # Skip whitelisted IPs
    if [[ -f "$WHITELIST" ]] && grep -qx "$IP" "$WHITELIST"; then
        echo "[!] SKIPPING (whitelisted): $IP"
        continue
    fi

    # Skip if already in iptables
    if iptables -C "$CHAIN" -s "$IP" -j DROP 2>/dev/null; then
        continue
    fi

    echo "[!] APPLYING IPTABLES BAN: $IP"
    iptables -A "$CHAIN" -s "$IP" -j DROP
    echo "$(date '+%F %T'): Synced Fail2ban ban for $IP" >> "$BAN_LOG"

done

save_iptables

echo
echo "[*] Active iptables bans:"
iptables -L "$CHAIN" -n --line-numbers
