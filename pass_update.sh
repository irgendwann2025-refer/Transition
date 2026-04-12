#!/bin/bash

# --- User Input Section ---
echo "=== Password Configuration ==="
read -rs -p "Enter the new password for whitelisted users: " TESTPASSWORD
echo "" 
read -rs -p "Confirm the new password: " TESTPASSWORD_CONFIRM
echo ""

if [[ "$TESTPASSWORD" != "$TESTPASSWORD_CONFIRM" ]]; then
    echo "ERROR: Passwords do not match. Exiting."
    exit 1
fi

if [[ -z "$TESTPASSWORD" ]]; then
    echo "ERROR: Password cannot be empty. Exiting."
    exit 1
fi

# --- NEW: Gold Team Account Collection ---
GOLD_TEAM_ACCOUNTS=()
while true; do
    read -p "Is there a Gold Team account present on this host? (y/n): " has_gold
    if [[ "$has_gold" =~ ^[Yy]$ ]]; then
        read -p "Enter the username for the Gold Team account: " gold_user
        if id "$gold_user" &>/dev/null; then
            GOLD_TEAM_ACCOUNTS+=("$gold_user")
            echo "[ADDED] $gold_user added to temporary session whitelist."
        else
            echo "[WARN] User '$gold_user' does not exist on this system. Not added."
        fi
    else
        break
    fi
done
# ------------------------------------------

# Configuration
WHITELIST_FILE="/etc/managed_users.whitelist"
EXCEPTIONS_FILE="exceptions.txt"

# 1. Safety & Permission Checks
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root (sudo)." 
   exit 1
fi

if [[ ! -f "$WHITELIST_FILE" ]]; then
    echo "ERROR: $WHITELIST_FILE not found! Run the TUI manager first."
    exit 1
fi

if [[ ! -f "$EXCEPTIONS_FILE" ]]; then
    touch "$EXCEPTIONS_FILE"
fi

echo "=== Starting Optimized User Management Process ==="

# 2. Build Total Whitelist (Including Gold Team)
mapfile -t MANAGED < "$WHITELIST_FILE"
mapfile -t EXCEPTIONS < "$EXCEPTIONS_FILE"
# Combine Managed, Exceptions, and Gold Team accounts into the master whitelist
TOTAL_WHITELIST=("${MANAGED[@]}" "${EXCEPTIONS[@]}" "${GOLD_TEAM_ACCOUNTS[@]}")

# 3. Part 1: Reset Passwords for Managed Users
echo -e "\n=== Resetting Passwords for Managed Users ==="

for user in "${MANAGED[@]}"; do
    # STRICT EXCEPTION: Never change root or SECCDC accounts
    if [[ "$user" == "root" ]]; then
        echo "[SKIP] root user protected."
        continue
    fi

    if [[ "$user" == seccdc* ]]; then
        echo "[SKIP] $user is a protected SECCDC account."
        continue
    fi
    
    # NEW: Protection for Gold Team accounts (prevents password reset)
    for gold in "${GOLD_TEAM_ACCOUNTS[@]}"; do
        if [[ "$user" == "$gold" ]]; then
            echo "[SKIP] $user is a Gold Team account. Password preserved."
            continue 2
        fi
    done

    if id "$user" &>/dev/null; then
        echo "$user:$TESTPASSWORD" | chpasswd
        echo "[DONE] Password updated: $user"
    else
        echo "[WARN] User '$user' in whitelist but not found on system."
    fi
done

# 4. Part 2: Lockdown Unauthorized Accounts
echo -e "\n=== Identifying and Disabling Unauthorized Users ==="

# Fetch all human users (UID >= 1000)
ALL_SYSTEM_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)

for system_user in $ALL_SYSTEM_USERS; do
    is_authorized=false
    
    # Automatic authorization for seccdc prefix
    if [[ "$system_user" == seccdc* ]]; then
        is_authorized=true
    else
        # Standard whitelist check (which now includes Gold Team accounts)
        for auth_user in "${TOTAL_WHITELIST[@]}"; do
            if [[ "$system_user" == "$auth_user" ]]; then
                is_authorized=true
                break
            fi
        done
    fi

    if [ "$is_authorized" = true ]; then
        echo "[SAFE] $system_user is authorized/excepted."
    else
        echo "[LOCK] Disabling Unauthorized User: $system_user"
        
        # Combine all lock actions into one command
        usermod -L -s /usr/sbin/nologin -e 1 "$system_user"
        
        # Security: Physically invalidate the hash in /etc/shadow
        sed -i "s/^$system_user:\([^:]*\):/$system_user:#\1:/" /etc/shadow
        
        echo "[DONE] $system_user has been locked and shell disabled."
    fi
done

echo -e "\n=== User Management Complete ==="
