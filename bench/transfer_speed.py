"""File transfer speed through the ticket-and-data-connection path (loopback), plain and TLS.

    python3 bench/transfer_speed.py [--sizes 1 5 20] [--runs 3]
"""
import argparse
import hashlib
import json
import os
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LANCHAT_HOME", tempfile.mkdtemp())

import transfer  # noqa: E402
from accounts import AccountStore  # noqa: E402
from chat_core import connect_and_login, fetch_server_certificate, make_tls_context  # noqa: E402
from events import decode  # noqa: E402
from protocol import receive_message, send_message  # noqa: E402
from server import ChatServer, default_tls_context  # noqa: E402


def trial(megabytes, tls):
    tmp = tempfile.mkdtemp()
    accounts = AccountStore(os.path.join(tmp, "t.db"))
    accounts.create_account("alice", "bench-password")
    server = ChatServer("127.0.0.1", 0, accounts=accounts, tls_context=default_tls_context()[0] if tls else None,
                        quiet=True, rate_limit=None, connection_limit=None, max_upload=64 * 1024 * 1024,
                        user_quota=1024 * 1024 * 1024)
    server.start()
    port = server.bound_port
    context = make_tls_context(cadata=fetch_server_certificate("127.0.0.1", port)) if tls else None
    chat = connect_and_login("127.0.0.1", port, "alice", "bench-password", context, protocol=2)
    path = os.path.join(tmp, "payload.bin")
    with open(path, "wb") as handle:
        handle.write(os.urandom(megabytes * 1024 * 1024))
    data = open(path, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    started = time.perf_counter()
    send_message(chat, json.dumps({"t": "upload", "req": 1, "name": "payload.bin", "size": len(data), "sha256": digest}))
    while True:
        event = decode(receive_message(chat))
        if event["t"] == "upload_ready":
            break
    transfer.upload("127.0.0.1", port, context, event["ticket"], path)
    up = time.perf_counter() - started
    message_id = None
    while message_id is None:
        event = decode(receive_message(chat))
        if event["t"] == "message" and event.get("att"):
            message_id = event["id"]
    started = time.perf_counter()
    send_message(chat, json.dumps({"t": "download", "req": 2, "id": message_id}))
    while True:
        event = decode(receive_message(chat))
        if event["t"] == "download_ready":
            break
    transfer.download("127.0.0.1", port, context, event["ticket"], event["size"], event["sha256"],
                      os.path.join(tmp, "copy.bin"))
    down = time.perf_counter() - started
    chat.close()
    server.stop()
    return megabytes / up, megabytes / down


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", type=int, nargs="+", default=[1, 5, 20])
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    print(f"# python {sys.version.split()[0]}, loopback; MB/s includes hashing, the ticket exchange and verification")
    print("size_MB  TLS    upload_MBps  download_MBps")
    for size in args.sizes:
        for tls in (False, True):
            runs = [trial(size, tls) for _ in range(args.runs)]
            print(f"{size:>7}  {str(tls):<5} {statistics.median(r[0] for r in runs):>11.1f}  "
                  f"{statistics.median(r[1] for r in runs):>13.1f}", flush=True)


if __name__ == "__main__":
    main()
