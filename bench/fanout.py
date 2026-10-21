"""Delivery latency of one broadcast as the number of receivers grows (LANChat-H server, loopback).

    python3 bench/fanout.py [--tls] [--clients 1 5 10 25 50 100] [--messages 100]

The server runs in this process; receivers and the sender run in separate processes so that
Python's GIL does not couple them. Latency is arrival time minus send time on the same machine's
monotonic clock.
"""
import argparse
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LANCHAT_HOME", tempfile.mkdtemp())

from accounts import AccountStore  # noqa: E402
from server import ChatServer, default_tls_context  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def percentile(values, q):
    values = sorted(values)
    if not values:
        return float("nan")
    index = min(len(values) - 1, max(0, math.ceil(q * len(values)) - 1))
    return values[index]


def run(clients, messages, interval, size, tls, per_process=20):
    tmp = tempfile.mkdtemp()
    accounts = AccountStore(os.path.join(tmp, "bench.db"))
    for name in ["sender"] + [f"r{i}" for i in range(clients)]:
        accounts.create_account(name, "bench-password")
    context = default_tls_context()[0] if tls else None
    server = ChatServer("127.0.0.1", 0, accounts=accounts, tls_context=context, quiet=True,
                        rate_limit=None, connection_limit=None, enforce_password_policy=False)
    server.start()
    port = server.bound_port
    duration = messages * interval + 4
    procs = []
    flags = ["--tls"] if tls else []
    for first in range(0, clients, per_process):
        count = min(per_process, clients - first)
        procs.append(subprocess.Popen(
            [sys.executable, os.path.join(HERE, "_load.py"), "receivers", "--port", str(port), "--first", str(first),
             "--count", str(count), "--duration", str(duration)] + flags,
            stdout=subprocess.PIPE, text=True))
    for proc in procs:
        assert proc.stdout.readline().strip() == "ready"
    sender = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "_load.py"), "sender", "--port", str(port), "--messages", str(messages),
         "--interval", str(interval), "--size", str(size)] + flags,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert sender.stdout.readline().strip() == "ready"
    time.sleep(0.5)
    sender.stdin.write("go\n")
    sender.stdin.flush()
    sender.stdout.readline()
    latencies, received = [], []
    for proc in procs:
        data = json.loads(proc.stdout.readline())
        latencies += [lat for _seq, lat in data["latencies"]]
        received += data["received_per_client"]
        proc.wait(10)
    sender.wait(10)
    server.stop()
    expected = clients * messages
    return {
        "clients": clients, "tls": tls, "messages": messages, "delivered": len(latencies), "expected": expected,
        "median_ms": statistics.median(latencies), "p95_ms": percentile(latencies, 0.95),
        "max_ms": max(latencies), "mean_ms": statistics.fmean(latencies),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, nargs="+", default=[1, 5, 10, 25, 50, 100])
    parser.add_argument("--messages", type=int, default=100)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    print(f"# python {sys.version.split()[0]}, platform {sys.platform}, tls={args.tls}, "
          f"{args.messages} messages of about {args.size} bytes every {args.interval}s")
    print("clients  delivered/expected  median_ms  p95_ms   max_ms")
    for count in args.clients:
        r = run(count, args.messages, args.interval, args.size, args.tls)
        print(f"{r['clients']:>7}  {r['delivered']:>9}/{r['expected']:<9}  {r['median_ms']:>9.2f}  {r['p95_ms']:>6.2f}  {r['max_ms']:>7.2f}",
              flush=True)


if __name__ == "__main__":
    main()
