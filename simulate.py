# simulate.py
# Makes FAKE log lines to test the other two scripts. It only writes text into a file.
# It sends no network traffic. The IPs are from reserved test ranges.
#
# Educational project.
#
# python simulate.py batch   -> creates test_attack.log (for dos_detector.py)
# python simulate.py live    -> slowly writes attack lines into live.log (for ddos_guard.py)

import random
import sys
import time
from datetime import datetime, timedelta

normal_ips = ["198.51.100." + str(i) for i in range(1, 201)]
bot_ips = ["203.0.113." + str(i) for i in range(1, 81)]
pages = ["/", "/product.screen?productId=A1", "/cart.do?action=view", "/category.screen?categoryId=GIFTS"]


def make_line(when, ip, status=200):
    return (f'{ip} - - [{when:%d/%b/%Y:%H:%M:%S}] "GET {random.choice(pages)} HTTP/1.1" '
            f'{status} {random.randint(300, 4000)} "-" "Mozilla/5.0"\n')


def make_batch_file():
    random.seed(42)
    start = datetime(2026, 9, 28, 10, 0, 0)
    rows = []

    # normal traffic: 2 hours, about 5 requests per minute
    for second in range(0, 2 * 3600, 12):
        when = start + timedelta(seconds=second + random.randint(0, 11))
        rows.append((when, make_line(when, random.choice(normal_ips))))

    # DoS: one IP sends 2400 requests in 2 minutes (at 10:40)
    for _ in range(2400):
        when = start + timedelta(minutes=40, seconds=random.randint(0, 119))
        rows.append((when, make_line(when, "192.0.2.77", random.choice([200, 503]))))

    # DDoS: 80 IPs send 6000 requests in 3 minutes (at 11:20)
    for _ in range(6000):
        when = start + timedelta(minutes=80, seconds=random.randint(0, 179))
        rows.append((when, make_line(when, random.choice(bot_ips), 503)))

    rows.sort(key=lambda row: row[0])
    with open("test_attack.log", "w", encoding="utf-8") as f:
        for when, line in rows:
            f.write(line)
    print("test_attack.log created:", len(rows), "lines")


def add_line(ip, status=200):
    with open("live.log", "a", encoding="utf-8") as f:
        f.write(make_line(datetime.now(), ip, status))


def run_live():
    print("1/3 normal traffic for 8 seconds...")
    end = time.time() + 8
    while time.time() < end:
        add_line(random.choice(normal_ips))
        time.sleep(0.2)

    print("2/3 DoS: one IP (192.0.2.77) sends 120 requests fast...")
    for _ in range(120):
        add_line("192.0.2.77", random.choice([200, 503]))
        time.sleep(0.02)
    time.sleep(3)

    print("3/3 DDoS: 80 bot IPs send 600 requests fast...")
    for _ in range(600):
        add_line(random.choice(bot_ips), 503)
        time.sleep(0.01)
    print("done")


if len(sys.argv) > 1 and sys.argv[1] == "batch":
    make_batch_file()
elif len(sys.argv) > 1 and sys.argv[1] == "live":
    run_live()
else:
    print("Usage: python simulate.py batch   or   python simulate.py live")
