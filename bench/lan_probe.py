"""Measure round-trip delivery time to a real LANChat-H server from another device.

On the server computer:   python3 chat.py host --name Lab --accounts probe.db
On a second device, over Wi-Fi or Ethernet (create the account once by signing in through the window):

    python3 bench/lan_probe.py HOST[:PORT] --username probe --password secret [--count 200] [--interval 0.2] [--tls]

Each sample is the time from sending a message to seeing the server's copy of it come back to the
same client, so it covers the network path twice plus the server's work. Prints median, p95, max.
"""
import argparse
import json
import math
import os
import socket
import ssl
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chat_core import connect_and_login, fetch_server_certificate, make_tls_context  # noqa: E402
from events import decode  # noqa: E402
from protocol import receive_message, send_message  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("address")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--count", type=int, default=200)
    p.add_argument("--interval", type=float, default=0.2)
    p.add_argument("--no-tls", action="store_true")
    a = p.parse_args()
    host, _, port = a.address.partition(":")
    port = int(port or 5050)
    context = None if a.no_tls else make_tls_context(cadata=fetch_server_certificate(host, port))
    conn = connect_and_login(host, port, a.username, a.password, context, protocol=2)
    conn.settimeout(5)
    samples, lost = [], 0
    for i in range(a.count):
        tag = f"probe-{os.getpid()}-{i}"
        started = time.perf_counter()
        send_message(conn, json.dumps({"t": "send", "body": tag}))
        deadline = started + 3
        while time.perf_counter() < deadline:
            try:
                event = decode(receive_message(conn))
            except (socket.timeout, ssl.SSLError):
                break
            if event and event.get("t") == "message" and event.get("body") == tag:
                samples.append((time.perf_counter() - started) * 1000)
                break
        else:
            lost += 1
        time.sleep(a.interval)
    conn.close()
    samples.sort()
    pct = lambda q: samples[min(len(samples) - 1, math.ceil(q * len(samples)) - 1)]  # noqa: E731
    print(json.dumps({"host": host, "samples": len(samples), "lost": a.count - len(samples),
                      "median_ms": round(statistics.median(samples), 2), "p95_ms": round(pct(0.95), 2),
                      "max_ms": round(samples[-1], 2)}))


if __name__ == "__main__":
    main()
