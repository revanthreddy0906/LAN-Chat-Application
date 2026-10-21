"""Does one stalled receiver delay everyone else?  Sequential relay vs the LANChat-H bounded outbox.

    python3 bench/slow_receiver.py [--fast 10] [--messages 300] [--size 2000] [--interval 0.02]

Both servers speak the same wire protocol (4-byte length prefix). The "sequential relay" is a
minimal thread-per-client server written for this experiment that sends to every recipient in turn
with a blocking sendall(), the design the paper's Section V describes as the naive baseline. The
stalled receiver connects first (so it is first in the relay order), shrinks its receive buffer and
never reads.
"""
import argparse
import os
import re
import socket
import statistics
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LANCHAT_HOME", tempfile.mkdtemp())

from accounts import AccountStore  # noqa: E402
from chat_core import connect_and_login  # noqa: E402
from protocol import receive_message, send_message  # noqa: E402
from server import ChatServer  # noqa: E402

STAMP = re.compile(r"T:(\d+):(\d+):")


class SequentialRelay:
    """Thread per client; broadcast = a blocking send to each client in turn, outside any queue."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.port = self.listener.getsockname()[1]
        self.clients, self.lock = [], threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        try:
            send_message(connection, "USERNAME")
            name = receive_message(connection)
            send_message(connection, "PASSWORD")
            receive_message(connection)
            send_message(connection, "OK")
            send_message(connection, "Connected")
            with self.lock:
                self.clients.append(connection)
            while True:
                text = receive_message(connection)
                if text is None:
                    return
                with self.lock:
                    recipients = [c for c in self.clients if c is not connection]
                for other in recipients:
                    try:
                        send_message(other, f"[00:00] {name}: {text}")
                    except OSError:
                        pass
        except (OSError, ValueError):
            pass

    def stop(self):
        self.listener.close()
        with self.lock:
            for c in self.clients:
                try:
                    c.close()
                except OSError:
                    pass


def run_trial(kind, fast, messages, size, interval, stalled):
    tmp = tempfile.mkdtemp()
    if kind == "relay":
        server = SequentialRelay()
        port = server.port
    else:
        accounts = AccountStore(os.path.join(tmp, "b.db"))
        for name in ["stalled", "sender"] + [f"f{i}" for i in range(fast)]:
            accounts.create_account(name, "bench-password")
        server = ChatServer("127.0.0.1", 0, accounts=accounts, quiet=True, rate_limit=None,
                            connection_limit=None, enforce_password_policy=False)
        server.start()
        port = server.bound_port
    held = []
    if stalled:  # connects first, so it is first in the relay order
        raw = socket.socket()
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        raw.connect(("127.0.0.1", port))
        raw.close()  # replaced below by a logged-in socket with a tiny buffer
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.connect(("127.0.0.1", port))
        assert receive_message(sock) == "USERNAME"
        send_message(sock, "stalled")
        assert receive_message(sock) == "PASSWORD"
        send_message(sock, "bench-password")
        assert receive_message(sock) == "OK"
        time.sleep(0.2)
        held.append(sock)  # never read again
    results, lock = [], threading.Lock()
    done = threading.Event()

    def read(connection):
        while not done.is_set():
            try:
                text = receive_message(connection)
            except (OSError, ValueError):
                return
            if text is None:
                return
            arrival = time.monotonic_ns()
            found = STAMP.search(text)
            if found:
                with lock:
                    results.append((int(found.group(2)), (arrival - int(found.group(1))) / 1e6))

    receivers = []
    for i in range(fast):
        connection = connect_and_login("127.0.0.1", port, f"f{i}", "bench-password")
        receivers.append(connection)
        threading.Thread(target=read, args=(connection,), daemon=True).start()
    sender = connect_and_login("127.0.0.1", port, "sender", "bench-password")
    time.sleep(0.3)
    padding = "x" * size
    started = time.monotonic()
    sender.settimeout(2)
    sent = 0
    for seq in range(messages):
        try:
            send_message(sender, f"T:{time.monotonic_ns()}:{seq}:{padding}")
            sent += 1
        except (OSError, TimeoutError):
            break
        time.sleep(interval)
    time.sleep(2.0)
    done.set()
    elapsed = time.monotonic() - started
    still_connected = None
    if kind == "chat" and stalled:
        with server._lock:
            still_connected = any(c.username == "stalled" for c in server._clients.values())
    delivered = len(results)
    lat = sorted(l for _s, l in results)
    summary = {
        "kind": kind, "stalled": stalled, "sent": sent, "expected": sent * fast, "delivered": delivered,
        "median_ms": statistics.median(lat) if lat else float("nan"),
        "p95_ms": lat[int(0.95 * (len(lat) - 1))] if lat else float("nan"),
        "elapsed_s": elapsed, "stalled_still_connected": still_connected,
    }
    for s in receivers + [sender] + held:
        try:
            s.close()
        except OSError:
            pass
    server.stop()
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", type=int, default=10)
    parser.add_argument("--messages", type=int, default=300)
    parser.add_argument("--size", type=int, default=2000)
    parser.add_argument("--interval", type=float, default=0.02)
    args = parser.parse_args()
    print(f"# python {sys.version.split()[0]}, {args.fast} fast receivers, {args.messages} messages of "
          f"{args.size} bytes every {args.interval}s")
    print("server              stalled  sent  delivered/expected   median_ms   p95_ms")
    for kind, label in (("relay", "sequential relay"), ("chat", "LANChat-H outbox")):
        for stalled in (False, True):
            r = run_trial(kind, args.fast, args.messages, args.size, args.interval, stalled)
            print(f"{label:<19} {str(stalled):<8} {r['sent']:>4}  {r['delivered']:>8}/{r['expected']:<8}  "
                  f"{r['median_ms']:>9.2f}  {r['p95_ms']:>7.2f}"
                  + ("" if r["stalled_still_connected"] is None else
                     f"   stalled connection dropped: {not r['stalled_still_connected']}"), flush=True)


if __name__ == "__main__":
    main()
