#!/bin/bash
# Usage: ./manage_bans.sh ban 1.2.3.4 OR ./manage_bans.sh unban 1.2.3.4

ACTION=$1
TARGET_IP=$2
CHAIN="BAD-ACTORS"

# Create the chain if it doesn't exist
sudo iptables -N $CHAIN 2>/dev/null
# Ensure the chain is called by the INPUT chain
sudo iptables -C INPUT -j $CHAIN 2>/dev/null || sudo iptables -I INPUT 1 -j $CHAIN

case $ACTION in
	ban)
		echo "[+] Banning $TARGET_IP..."
		sudo iptables -A $CHAIN -s $TARGET_IP -j DROP
		;;
	unban)
		echo "[-] Unbanning $TARGET_IP..."
		sudo iptables -D $CHAIN -s $TARGET_IP -j DROP
		;;
	list)
		echo "--- Currently banned IPs ---"
		sudo iptables -L $CHAIN -n --line-numbers
		;;
	*)
		echo "Usage: $0 {ban|unban|list} [IP]"
		;;
esac
