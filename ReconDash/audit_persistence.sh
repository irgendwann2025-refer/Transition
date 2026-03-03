#!/bin/bash
# Logic: Scans all system and user cronjobs + systemd timers.

echo "--- [DETECTION] Systemd Timers (Scheduled Tasks) ---"
systemctl list-timers --all | awk '{print $1, $2, $11}' | column -t

echo -e "\n--- [RECON] User Cronjobs ---"
for user in $(cut -f1 -d: /etc/passwd); do
	crotab -u $user -l 2>/dev/null | grep -v "^#" && echo "User: $user has a cronjob!"
done

echo -e "\n--- [RECON] System-wide Cron Directories ---"
ls -lah /etc/cron.* /etc/crontab

