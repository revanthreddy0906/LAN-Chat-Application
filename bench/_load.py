"""Helper process for the benchmarks: runs receivers or one sender against a chat server."""
import argparse
import json
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chat_core import connect_and_login, fetch_server_certificate, make_tls_context  # noqa: E402
from protocol import receive_message, send_message  # noqa: E402

STAMP = re.compile(r"T:(\d+):(\d+):")


def context_for(port, tls):
    if not tls:
        return None
    return make_tls_context(cadata=fetch_server_certificate("127.0.0.1", port))


def receivers(args):
    context = context_for(args.port, args.tls)
    names = [f"r{args.first + i}" for i in range(args.count)]
    sockets = [connect_and_login("127.0.0.1", args.port, name, "bench-password", context) for name in names]
    print("ready", flush=True)
    lock = threading.Lock()
    latencies = []
    seen = []

    def read(connection):
        local, count = [], 0
        while True:
            try:
                text = receive_message(connection)
            except (OSError, ValueError):
                break
            if text is None:
                break
            arrival = time.monotonic_ns()
            found = STAMP.search(text)
            if found:
                local.append((int(found.group(2)), (arrival - int(found.group(1))) / 1e6))
                count += 1
        with lock:
            latencies.extend(local)
            seen.append(count)

    threads = [threading.Thread(target=read, args=(s,), daemon=True) for s in sockets]
    for thread in threads:
        thread.start()
    time.sleep(args.duration)
    for connection in sockets:
        try:
            connection.close()
        except OSError:
            pass
    for thread in threads:
        thread.join(2)
    print(json.dumps({"latencies": latencies, "received_per_client": seen}), flush=True)


def sender(args):
    context = context_for(args.port, args.tls)
    connection = connect_and_login("127.0.0.1", args.port, "sender", "bench-password", context)
    print("ready", flush=True)
    sys.stdin.readline()  # wait for the go signal
    padding = "x" * args.size
    for seq in range(args.messages):
        send_message(connection, f"T:{time.monotonic_ns()}:{seq}:{padding}")
        time.sleep(args.interval)
    time.sleep(0.5)
    connection.close()
    print("done", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["receivers", "sender"])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--first", type=int, default=0)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--messages", type=int, default=100)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--size", type=int, default=100)
    args = parser.parse_args()
    (receivers if args.role == "receivers" else sender)(args)


if __name__ == "__main__":
    main()
