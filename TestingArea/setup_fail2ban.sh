#!/bin/bash
# setup_fail2ban.sh - Advanced Competition Jail Configuration

JAIL_LOCAL="/etc/fail2ban/jail.local"

# Define your team's safe IPs here (Jumpbox and other team machines)
SAFE_IPS="127.0.0.1/8 ::1 192.168.1.100 192.168.1.101"

echo "[*] Provisioning Fail2Ban with Advanced Competition Jails..."

# Create or overwrite jail.local with the requested settings
sudo cat <<EOF > "$JAIL_LOCAL"
[DEFAULT]
ignoreip = $SAFE_IPS
bantime  = 500000
findtime  = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 500000
backend = %(sshd_backend)s

[proftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
logpath = /var/log/proftpd/proftpd.log

[nginx-limit-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[pop3-auth]
enabled = true
port = 110,995
filter = dovecot
logpath = /var/log/dovecot.log

[rdp-proxy]
enabled = true
port = 3389
filter = rdp-regex
logpath = /var/log/auth.log

[winrm-auth]
enabled = true
port = 5985,5986
filter = openwsman
logpath = /var/log/syslog
EOF

# Restart to apply changes
sudo systemctl restart fail2ban
echo "[+] Fail2Ban security policy applied successfully."
