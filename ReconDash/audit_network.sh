#!/bin/bash
# Logic: Identifies all listening ports and the specific process/user owning them

echo "--- [RECON] Active Listening Ports ---"
printf "%-10s %-10s %-20s %-10s\n" "PROTO" "PORT" "PROCESS" "USER"
echo "--------------------------------------------------------"

# Uses ss to grab TCP/UDP Listening ports and parses the process name safely
sudo ss -tulpn | grep LISTEN | awk '{
    # Extract the port (last element after the colon)
    split($5, addr, ":");
    port = addr[length(addr)];

    # Safely extract process name if it exists in column 7
    # ss process strings usually look like: users:(("process",pid=123,fd=4))
    if ($7 ~ /"/) {
        split($7, proc, "\"");
        process_name = proc[2];
    } else {
        process_name = "UNKNOWN";
    }

    # Extract User ID/Info (typically column 6 in ss output)
    user_info = $6;

    # Final formatted output
    printf "%-10s %-10s %-20s %-10s\n", $1, port, process_name, user_info
}'

echo -e "\n--- [DETECTION] Established External Connections ---"
# Checks for any active outbound connection that isn't local
# -n prevents DNS resolution for faster, stealthier results in competition
sudo ss -atn | grep ESTAB | grep -vE "127.0.0.1|::1"
