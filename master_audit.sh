#!/bin/bash
LOG_FILE="/var/log/daily_recon.log"
{
	echo "=== RECON REPORT $(date) ==="
	audit_network.sh
	audit_persistence.sh
	audit_integrity.sh
	audit_logs.sh
	find_hidden_proc.sh
} > "$LOG_FILE"
