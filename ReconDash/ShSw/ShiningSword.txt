#!/bin/python3

# Credit to Spinjrock's "Kn1gh7" plugin

import sys
import auparse
import logging
import psutil  # Recommendation: Use psutil for cleaner, faster lookups

LOG_FILE="/var/log/audit/kn1gh7.log"

logging.basicConfig(
    filename=LOG_FILE,
    encoding='utf-8',
    level=logging.INFO,
    format='%(asctime)s > %(levelname)s:%(message)s',
    datefmt='%m/%d/%Y %I:%M:%S%p'
)

# Simple cache to prevent redundant system lookups
PROCESS_CACHE = {}

class ProcessInfo:
    def __init__(self, pid: int):
        self.pid = pid
        try:
            p = psutil.Process(pid)
            self.ppid = p.ppid()
            self.cmd = " ".join(p.cmdline())
            self.user = p.username()
            self.status = "ACTIVE"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.ppid = 0
            self.cmd = "[UNKNOWN/TERMINATED]"
            self.user = "UNKNOWN"
            self.status = "INACTIVE"

def get_lineage(pid: int) -> list:
    trace = []
    current_pid = pid
    
    while current_pid > 0:
        if current_pid in PROCESS_CACHE:
            p_obj = PROCESS_CACHE[current_pid]
        else:
            p_obj = ProcessInfo(current_pid)
            PROCESS_CACHE[current_pid] = p_obj
            
        trace.append(p_obj)
        if current_pid == 1 or p_obj.ppid == 0:
            break
        current_pid = p_obj.ppid
    return trace

def process_event(line: str):
    aup = auparse.AuParser(auparse.AUSOURCE_BUFFER, line)
    while aup.parse_next_event():
        is_inet = False
        event_pid = None
        
        # Single pass through fields
        while aup.next_field():
            name = aup.get_field_name()
            val = aup.get_field_str()
            
            if name == "key" and "INET" in val:
                is_inet = True
            if name == "pid":
                event_pid = int(val)
        
        if is_inet and event_pid:
            trace = get_lineage(event_pid)
            log_entry = "\n[LINEAGE - EVENT DETECTED]"
            for p in trace:
                log_entry += f"\n  PID: {p.pid} | User: {p.user} | CMD: {p.cmd}"
            log_entry += "\n[END LINEAGE]"
            logging.warning(log_entry)

if __name__ == '__main__':
    logging.info("Security Monitor Started...")
    try:
        for line in sys.stdin:
            process_event(line)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as err:
        logging.critical(f"Runtime Error: {err}")
