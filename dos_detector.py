# dos_detector.py
# Looks through a web server access log and finds DoS and DDoS signs.
#
# DoS  = one IP sends too many requests in a short time
# DDoS = total traffic jumps way above normal and comes from many different IPs
#
# Educational project. Use it only on your own logs.
#
# Usage: python dos_detector.py access.log [another.log ...]
#        python dos_detector.py some_folder      (finds every access.log inside)

import os
import re
import sys
import statistics
from collections import Counter, defaultdict
from datetime import datetime

# ---- settings (change them if you want) ----
WINDOW = 60          # size of one time window, in seconds
IP_LIMIT = 100       # more requests than this from ONE ip in a window = DoS
MIN_TOTAL = 300      # a DDoS window needs at least this many requests
SPIKE_FACTOR = 10    # ... and must be this many times above the normal level
MIN_IPS = 20         # ... and come from at least this many different IPs
# --------------------------------------------

# example line: 87.194.216.51 - - [27/Sep/2026:15:51:15] "GET /cart HTTP/1.1" 200 3610
line_pattern = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "')


def find_logs(paths):
    files = []
    for path in paths:
        if os.path.isdir(path):
            for folder, _, names in os.walk(path):
                for name in names:
                    if name.endswith("access.log"):
                        files.append(os.path.join(folder, name))
        else:
            files.append(path)
    return files


def read_log(files):
    # returns a list of (time, ip) for every request
    requests = []
    for file in files:
        with open(file, encoding="utf-8", errors="replace") as f:
            for line in f:
                match = line_pattern.match(line)
                if not match:
                    continue
                ip = match.group(1)
                time_text = match.group(2).split()[0]   # drop timezone if there is one
                try:
                    when = datetime.strptime(time_text, "%d/%b/%Y:%H:%M:%S")
                except ValueError:
                    continue
                requests.append((when, ip))
    return requests


def main():
    if len(sys.argv) < 2:
        print("Usage: python dos_detector.py access.log")
        return

    print("[Educational project - use only on your own logs]\n")
    files = find_logs(sys.argv[1:])
    requests = read_log(files)
    if not requests:
        print("No requests found. Is this an access log?")
        return

    # put every request into a time window and count requests per IP
    windows = defaultdict(Counter)
    for when, ip in requests:
        seconds = int(when.timestamp())
        start = seconds - seconds % WINDOW
        windows[start][ip] += 1

    totals = [sum(c.values()) for c in windows.values()]
    normal = statistics.median(totals)     # typical traffic per window
    ddos_limit = max(normal * SPIKE_FACTOR, MIN_TOTAL)

    print(f"Requests read : {len(requests)}")
    print(f"Windows       : {len(windows)} (each {WINDOW}s)")
    print(f"Normal level  : about {normal:.0f} requests per window")
    print(f"Busiest window: {max(totals)} requests\n")

    alerts = []
    for start in sorted(windows):
        counts = windows[start]
        total = sum(counts.values())
        when = datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M")

        # DoS check: is one IP too loud?
        for ip, number in counts.items():
            if number > IP_LIMIT:
                alerts.append((when, "DoS", ip, number))

        # DDoS check: big spike from many IPs
        if total > ddos_limit and len(counts) >= MIN_IPS:
            alerts.append((when, "DDoS", f"{len(counts)} IPs", total))

    if not alerts:
        print("No DoS or DDoS signs found.")
        return

    print(f"{'TIME':<17} {'TYPE':<5} {'SOURCE':<16} REQUESTS")
    for when, kind, source, number in alerts:
        print(f"{when:<17} {kind:<5} {source:<16} {number}")

    # save the alerts to a csv file so they can be opened in Excel
    with open("alerts.csv", "w", encoding="utf-8") as f:
        f.write("time,type,source,requests\n")
        for when, kind, source, number in alerts:
            f.write(f"{when},{kind},{source},{number}\n")
    print("\nAlerts saved to alerts.csv")


main()
