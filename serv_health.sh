#!/bin/bash
# check_services.sh
SERVICES=("sshd" "nginx" "proftpd" "slapd")
echo "--- SCORED SERVICE STATUS ---"
for SVC in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $SVC; then
        echo "[OK] $SVC is running."
    else
        echo "[CRITICAL] $SVC IS DOWN! Attempting restart..."
        systemctl start $SVC
    fi
done
