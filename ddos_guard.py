# ddos_guard.py
# Watches a web server access log in real time (like "tail -f").
# When it sees a DoS or DDoS attack it prints the attacking IP, blocks it in the
# firewall and writes everything to guard.log and blocked_ips.txt.
#
# SAFE BY DEFAULT: without --apply it only prints "WOULD BLOCK" and the command.
# Real blocking needs --apply and administrator/root rights.
#
# Educational project. Use it only on systems you own.
#
# Usage: python ddos_guard.py live.log
#        python ddos_guard.py live.log --apply

import os
import platform
import re
import subprocess
import sys
import time
from collections import Counter, deque
from datetime import datetime

# ---- settings ----
WINDOW = 10          # look at the last 10 seconds
IP_LIMIT = 50        # one IP sends this many requests in the window = DoS
TOTAL_LIMIT = 300    # all IPs together send this many in the window = maybe DDoS
MIN_IPS = 20         # ... and there must be at least this many different IPs
DDOS_IP_MIN = 5      # in a DDoS, block IPs that sent at least this many requests
MAX_BLOCKS = 100     # never block more IPs than this
WHITELIST = ["127.", "10.", "192.168."]   # IPs starting like this are never blocked
# add YOUR OWN public IP here so you never block yourself, for example "203.0.113.5"
# ------------------

LOG_FILE = "guard.log"
BLOCKLIST_FILE = "blocked_ips.txt"
line_pattern = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "')

apply_blocking = "--apply" in sys.argv
blocked = set()          # IPs we already blocked
recent = deque()         # (time, ip) of requests in the last WINDOW seconds
last_ddos_alert = 0


def write_log(text):
    line = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " " + text
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def firewall_command(ip):
    if platform.system() == "Windows":
        return ["netsh", "advfirewall", "firewall", "add", "rule",
                "name=ddos-guard " + ip, "dir=in", "action=block", "remoteip=" + ip]
    return ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]


def block_ip(ip, reason):
    if ip in blocked:
        return
    if any(ip.startswith(prefix) for prefix in WHITELIST):
        return
    if len(blocked) >= MAX_BLOCKS:
        write_log("LIMIT   too many blocked IPs, not blocking " + ip)
        return

    command = firewall_command(ip)
    if apply_blocking:
        try:
            subprocess.run(command, check=True, capture_output=True)
            write_log(f"BLOCKED {ip} ({reason})")
        except Exception as error:
            write_log(f"ERROR   could not block {ip}: {error} (run as administrator?)")
            return
    else:
        write_log(f"WOULD BLOCK {ip} ({reason}) | command: {' '.join(command)}")

    blocked.add(ip)
    with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
        f.write(ip + "\n")


def check_request(ip):
    global last_ddos_alert
    now = time.time()

    # keep only requests from the last WINDOW seconds
    recent.append((now, ip))
    while recent and recent[0][0] < now - WINDOW:
        recent.popleft()

    counts = Counter(i for _, i in recent)

    # DoS: one IP is too loud
    if counts[ip] >= IP_LIMIT and ip not in blocked:
        write_log(f"ATTACK  DoS from {ip}: {counts[ip]} requests in {WINDOW}s")
        block_ip(ip, f"DoS, {counts[ip]} requests in {WINDOW}s")

    # DDoS: lots of traffic from lots of IPs
    total = len(recent)
    if total >= TOTAL_LIMIT and len(counts) >= MIN_IPS and now - last_ddos_alert > WINDOW:
        last_ddos_alert = now
        write_log(f"ATTACK  DDoS: {total} requests from {len(counts)} IPs in {WINDOW}s")
        for bad_ip, number in counts.most_common():
            if number < DDOS_IP_MIN:
                break
            block_ip(bad_ip, f"DDoS, {number} requests in {WINDOW}s")


def main():
    if len(sys.argv) < 2 or not os.path.exists(sys.argv[1]):
        print("Usage: python ddos_guard.py access.log [--apply]")
        return

    print("[Educational project - use only on systems you own]\n")
    mode = "REAL BLOCKING" if apply_blocking else "dry run, nothing is blocked"
    write_log(f"START   watching {sys.argv[1]} ({mode})")

    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)          # skip old lines, read only new ones
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)     # nothing new yet, wait a bit
                    continue
                match = line_pattern.match(line)
                if match:
                    check_request(match.group(1))
        except KeyboardInterrupt:
            write_log(f"STOP    guard stopped, {len(blocked)} IPs in the blocklist")


main()
