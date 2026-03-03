#!/bin/bash
# restart_services.sh - Mass Recovery Script

# List of service names (handling both Debian and Fedora variants)
TARGETS=("sshd" "ssh" "nginx" "proftpd" "slapd" "named" "smbd" "smb" "krb5-kdc" "krb5kdc" "xrdp" "dovecot")

echo "--- INITIATING MASS SERVICE RESTART ---"
for SVC in "${TARGETS[@]}"; do
    if systemctl list-unit-files | grep -q "^$SVC.service"; then
        echo "Attempting to restart: $SVC"
        sudo systemctl restart "$SVC"
    fi
done
echo "Recovery complete."
