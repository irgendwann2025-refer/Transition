#!/bin/bash
# check_services.sh - Version/Status Detection (No Restart)

declare -A SVC_MAP=(
    ["DNS"]="bind9 named"
    ["FTP"]="proftpd proftpd"
    ["HTTP/S"]="nginx nginx"
    ["LDAP"]="slapd dirsrv"
    ["Kerberos"]="krb5-kdc krb5kdc"
    ["RDP"]="xrdp xrdp"
    ["SMB"]="smbd smb"
    ["SSH"]="sshd sshd"
    ["WinRM"]="openwsman openwsman"
    ["POP3"]="dovecot dovecot"
)

echo "--- RECON DASHBOARD: SERVICE AUDIT ---"
printf "%-15s %-12s %-20s\n" "SERVICE" "STATUS" "VERSION"
echo "------------------------------------------------------------"

for FRIENDLY in "${!SVC_MAP[@]}"; do
    read -r DEB FED <<< "${SVC_MAP[$FRIENDLY]}"
    # Detect which name exists on this distro
    if systemctl list-unit-files | grep -q "$DEB.service"; then SVC=$DEB; 
    elif systemctl list-unit-files | grep -q "$FED.service"; then SVC=$FED; 
    else SVC="N/A"; fi

    if [[ "$SVC" != "N/A" ]] && systemctl is-active --quiet "$SVC"; then
        # Version extraction logic varies by binary
        case $FRIENDLY in
            "DNS") VER=$(named -v | awk '{print $2}') ;;
            "SSH") VER=$(sshd -V 2>&1 | head -n1) ;;
            "HTTP/S") VER=$(nginx -v 2>&1 | cut -d'/' -f2) ;;
            *) VER=$($SVC --version 2>&1 | head -n1 | awk '{print $1,$2}') ;;
        esac
        printf "%-15s %-12s %-20s\n" "$FRIENDLY" "[ONLINE]" "${VER:-Unknown}"
    else
        printf "%-15s %-12s %-20s\n" "$FRIENDLY" "[OFFLINE]" "---"
    fi
done
