"""Robustness fuzzing of a live LANChat-H server (our own testing, not an independent audit).

    python3 security_tests/fuzz.py [--seed 1] [--connections 1500] [--events 60]

1. Before sign-in: random bytes, bad lengths, truncated frames, malformed JSON hellos, odd types.
2. After sign-in (protocol 2) as a member and as an administrator: every event type the server
   knows, with fields replaced by random hostile values (None, huge numbers, long strings,
   nested containers, wrong types) and with random extra keys.
3. The file data port: random bytes and made-up tickets.

Pass condition: no unhandled exception in any server thread, the server still accepts and serves
a fresh client afterwards, and memory stays bounded. Prints one JSON summary line.
"""
import argparse
import json
import os
import random
import resource
import socket
import struct
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

errors = []


def hook(args):
    errors.append(f"{args.exc_type.__name__}: {args.exc_value}")


threading.excepthook = hook

WEIRD = [None, True, False, 0, -1, 1, 2 ** 31, 2 ** 63, -2 ** 63, 1.5, 1e308, "", " ", "A" * 3000, "\x00", "../../etc/passwd",
         "<script>", "'; DROP TABLE messages;--", "‮", "😀" * 400, [], [1, "a", None], {}, {"a": {"b": [1, 2, {"c": None}]}},
         [[[[[[]]]]]], "@everyone", "everyone", "admin", 'id', {"__proto__": 1}]
KEYS = ["id", "text", "to", "name", "emoji", "reply_to", "before", "after", "limit", "q", "query", "pinned", "mentions", "att", "size",
        "sha256", "req", "value", "user", "role", "setting", "key", "enc", "env", "epoch", "ids", "files", "password", "old", "new", "ticket"]


def mutate(rng, event_type):
    event = {"t": event_type}
    for key in rng.sample(KEYS, rng.randint(0, 8)):
        event[key] = rng.choice(WEIRD)
    if rng.random() < 0.3:
        event[rng.choice([w for w in WEIRD if isinstance(w, str)])] = rng.choice(WEIRD)
    return event


def drain(conn, stop):
    conn.settimeout(0.2)
    while not stop.is_set():
        try:
            if receive_message(conn) is None:
                return
        except socket.timeout:
            continue
        except (OSError, ValueError):
            return


def raw_send(sock, text):
    """Frame text without the client library's own size check, so oversize frames reach the server."""
    data = text.encode("utf-8", "surrogatepass")
    sock.sendall(struct.pack("!I", len(data)) + data)


def pre_auth(port, rng, n, stats):
    for i in range(n):
        try:
            s = socket.create_connection(("127.0.0.1", port), 2)
            s.settimeout(0.3)
            kind = i % 9
            if kind == 0:
                s.sendall(os.urandom(rng.randint(1, 300)))
            elif kind == 1:
                s.sendall(struct.pack("!I", 2 ** 32 - 1) + b"x" * 10)
            elif kind == 2:
                s.sendall(struct.pack("!I", 0))
            elif kind == 3:
                s.sendall(struct.pack("!I", 50) + b"short")  # truncated frame, then close
            elif kind == 4:
                try:
                    receive_message(s)
                except OSError:
                    pass
                raw_send(s, rng.choice(['{"v":2,"username":', '{"v":"x","username":["a"]}', '{"v":2,"username":null,"token":5}',
                                            '{"v":99,"username":"fuzz"}', "\xff", "{" * 2000, '{"v":2,"username":"' + "a" * 5000 + '"}']))
            elif kind == 5:
                try:
                    receive_message(s)
                    raw_send(s, "fuzzuser")
                    receive_message(s)
                    raw_send(s, "x" * rng.randint(1, 4000))
                except (OSError, ValueError):
                    pass
            elif kind == 6:
                for _ in range(rng.randint(2, 6)):
                    s.sendall(struct.pack("!I", 4) + os.urandom(4))
            elif kind == 7:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            else:
                pass  # connect and say nothing
            try:
                s.recv(4096)
            except OSError:
                pass
            s.close()
            stats["pre_auth"] += 1
        except OSError:
            stats["conn_errors"] += 1


def post_auth(port, user, rng, events_per_type, event_types, stats):
    conn = connect_and_login("127.0.0.1", port, user, "fuzz-password", None, protocol=2)
    stop = threading.Event()
    threading.Thread(target=drain, args=(conn, stop), daemon=True).start()
    for event_type in event_types:
        for _ in range(events_per_type):
            payload = json.dumps(mutate(rng, event_type))
            if len(payload.encode()) > 4096:  # the framing layer refuses these on the client side already
                stats["oversize_skipped"] = stats.get("oversize_skipped", 0) + 1
                continue
            try:
                send_message(conn, payload)
                stats["events"] += 1
            except OSError:
                # the server may drop a hostile client; reconnect and carry on
                stats["dropped"] += 1
                stop.set()
                try:
                    conn.close()
                except OSError:
                    pass
                time.sleep(0.05)
                conn = connect_and_login("127.0.0.1", port, user, "fuzz-password", None, protocol=2)
                stop = threading.Event()
                threading.Thread(target=drain, args=(conn, stop), daemon=True).start()
    time.sleep(0.5)
    stop.set()
    conn.close()


def data_port(port, rng, n, stats):
    """Data connections: a hello naming a transfer kind with a made-up or malformed ticket, then junk."""
    for _ in range(n):
        try:
            s = socket.create_connection(("127.0.0.1", port), 2)
            s.settimeout(0.3)
            receive_message(s)
            send_message(s, json.dumps({"v": 2, "data": rng.choice(["up", "down", "x", None, 5, ["up"]]),
                                        "ticket": rng.choice([os.urandom(16).hex(), "", None, 7, "A" * 4000, {"a": 1}])}))
            try:
                s.recv(100)
                s.sendall(os.urandom(rng.randint(1, 2000)))
            except OSError:
                pass
            s.close()
        except (OSError, ValueError):
            pass
        stats["data"] += 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--connections", type=int, default=1500)
    p.add_argument("--events", type=int, default=60)
    a = p.parse_args()
    rng = random.Random(a.seed)
    tmp = tempfile.mkdtemp()
    accounts = AccountStore(os.path.join(tmp, "f.db"))
    accounts.create_account("member1", "fuzz-password")
    accounts.create_account("boss", "fuzz-password", role="admin")
    accounts.create_account("probe", "fuzz-password")
    server = ChatServer("127.0.0.1", 0, accounts=accounts, quiet=True, rate_limit=None, connection_limit=None,
                        enforce_password_policy=False)
    server.start()
    port = server.bound_port
    types = sorted(server._EVENT_HANDLERS) + ["nonexistent", "", "ping"]
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024)
    stats = {"pre_auth": 0, "conn_errors": 0, "events": 0, "dropped": 0, "data": 0}
    started = time.time()
    pre_auth(port, rng, a.connections, stats)
    for user in ("member1", "boss"):
        post_auth(port, user, rng, a.events, types, stats)
    data_port(port, rng, 200, stats)
    alive = False
    try:
        probe = connect_and_login("127.0.0.1", port, "probe", "fuzz-password", None, protocol=2)
        send_message(probe, json.dumps({"t": "send", "body": "still alive"}))
        deadline = time.time() + 3
        probe.settimeout(1)
        while time.time() < deadline and not alive:
            try:
                alive = "still alive" in (receive_message(probe) or "")
            except (socket.timeout, OSError, ValueError):
                break
        probe.close()
    except Exception as error:  # noqa: BLE001
        errors.append(f"probe: {error}")
    rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024)
    server.stop()
    unique = sorted(set(errors))
    print(json.dumps({"seed": a.seed, "event_types": len(types), **stats, "unhandled_exceptions": len(errors),
                      "unique": unique[:10], "server_alive": alive, "rss_growth_mb": round(rss1 - rss0, 1),
                      "seconds": round(time.time() - started, 1)}))


if __name__ == "__main__":
    main()
