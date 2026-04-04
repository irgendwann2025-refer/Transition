#!/bin/bash

# Define the table header
header_format="%-25s | %-45s | %-30s\n"
separator="---------------------------------------------------------------------------------------------------------------------"

echo "SYSTEM ENUMERATION REPORT"
echo $separator
printf "$header_format" "Category" "Command Used" "Result"
echo $separator

# 1. Active Users
active_users=$(who | awk '{print $1}' | sort -u | xargs)
printf "$header_format" "Active Users" "who" "$active_users"

# 2. Change Password (Note: Showing the command as requested)
printf "$header_format" "Change Password Admin" "sudo passwd <username>" "Command available"

# 3. IP Address
ip_addr=$(hostname -I | awk '{print $1}')
printf "$header_format" "IP Address" "hostname -I" "$ip_addr"

# 4. Hostname
host_name=$(hostname)
printf "$header_format" "Hostname" "hostname" "$host_name"

# 5. Kernel Version
kernel_v=$(uname -r)
printf "$header_format" "Kernel Version" "uname -r" "$kernel_v"

# 6. Installed Services (Sample: showing first two for brevity)
inst_services=$(dpkg -l | grep '^ii' | head -n 2 | awk '{print $2}' | xargs | sed 's/ /, /g')
printf "$header_format" "Installed Services" "dpkg -l" "$inst_services"

# 7. Running Services
run_services=$(systemctl list-units --type=service --state=running | grep '.service' | head -n 2 | awk '{print $1}' | xargs | sed 's/ /, /g')
printf "$header_format" "Running Services" "systemctl list-units" "$run_services"

# 8. Open Ports
open_ports=$(ss -tulnp | grep LISTEN | awk '{print $4}' | awk -F':' '{print $NF}' | sort -un | xargs | sed 's/ /, /g')
printf "$header_format" "Open Ports" "ss -tulnp" "$open_ports"

# 9. MAC Address
mac_addr=$(ip link show | grep 'link/ether' | awk '{print $2}' | head -n 1)
printf "$header_format" "MAC Address" "ip link show" "$mac_addr"

# 10. No Password Users
no_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$no_pass" ]; then no_pass="none"; fi
printf "$header_format" "No Password Users" "awk /etc/shadow" "$no_pass"

# 11. Cron Jobs
cron_jobs=$(crontab -l 2>/dev/null | grep -v '^#' | xargs)
if [ -z "$cron_jobs" ]; then cron_jobs="none"; fi
printf "$header_format" "Cron Jobs" "crontab -l" "$cron_jobs"

echo $separator
