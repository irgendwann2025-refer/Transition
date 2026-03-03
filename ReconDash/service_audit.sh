#!/bin/bash
# service_audit.sh - Audit HTTP, SQL, and SSH logs
LOG_OUT="/tmp/service_audit.txt"
echo "--- Service Audit Results ($(date)) ---" > $LOG_OUT

# 1. HTTP Brute Force / Credential Stuffing
echo "[!] Scanning HTTP Access Logs (401/403 errors)..." >> $LOG_OUT
grep -E " 401 | 403 " /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null | tail -n 20 >> $LOG_OUT

# 2. SQL Unauthorized Access (Postgres/MySQL)
echo "[!] Searching SQL logs for 'Access denied' or 'password authentication failed'..." >> $LOG_OUT
grep -iE "access denied|password authentication failed" /var/log/mysql/error.log /var/log/postgresql/*.log 2>/dev/null >> $LOG_OUT

# 3. SSH Successful Logins (Lateral Movement Check)
echo "[!] Recent Successful SSH Logins:" >> $LOG_OUT
last -n 10 -a | grep "pts/" >> $LOG_OUT

echo "[+] Audit Complete. Results in $LOG_OUT"
