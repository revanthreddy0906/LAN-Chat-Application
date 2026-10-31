"""A mixed, more realistic workload: many clients chatting at random times, plus file uploads,
over TLS with every default limit switched on, optionally through a delayed network path.

    python3 bench/workload.py [--clients 40] [--duration 60] [--delay-ms 0] [--jitter-ms 0]

Each client sends a text message after an exponentially distributed pause (mean --mean-gap seconds)
with a log-normal size (median about 60 bytes), and reads everything the others send. One more
client uploads a --file-mb file every --file-gap seconds while the chat runs, so chat latency is
measured while a transfer shares the server. Prints delivery, latency percentiles, file times
and the server's CPU and peak memory.
"""
import argparse
import hashlib
import json
import math
import os
import random
import re
import resource
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.environ.setdefault("LANCHAT_HOME", tempfile.mkdtemp())

STAMP = re.compile(r"T:(\d+):(\d+):")


def client_process(args):
    """Runs --count chat clients; signs them all in first, waits for the go signal, then prints one JSON line."""
    from chat_core import connect_and_login, fetch_server_certificate, make_tls_context
    from protocol import receive_message, send_message
    context = make_tls_context(cadata=fetch_server_certificate("127.0.0.1", args.tls_port))
    indexes = list(range(args.first, args.first + args.count))
    conns = {}

    failed = []

    def login(index):
        for attempt in range(6):  # a burst of 100 TLS sign-ins can overflow the listen queue; retry, and count what still fails
            try:
                conns[index] = connect_and_login("127.0.0.1", args.port, f"u{index}", "bench-password", context)
                return
            except (OSError, ValueError, Exception):  # noqa: BLE001
                time.sleep(0.2 * (attempt + 1))
        failed.append(index)

    threads = [threading.Thread(target=login, args=(i,)) for i in indexes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    indexes = [i for i in indexes if i in conns]
    print(json.dumps({"ready": len(conns), "failed": len(failed)}), flush=True)
    sys.stdin.readline()  # go: every client in every process is signed in, so nobody misses the start
    stop = time.monotonic() + args.duration
    sent, lat, lock = [], [], threading.Lock()

    def run(index):
        conn = conns[index]
        local = []

        def read():
            while True:
                try:
                    text = receive_message(conn)
                except (OSError, ValueError):
                    return
                if text is None:
                    return
                now = time.monotonic_ns()
                found = STAMP.search(text)
                if found:
                    local.append((int(found.group(2)), (now - int(found.group(1))) / 1e6))

        threading.Thread(target=read, daemon=True).start()
        r = random.Random(args.seed * 1000 + index)
        seq = 0
        while True:
            pause = r.expovariate(1 / args.mean_gap)
            if time.monotonic() + pause >= stop:
                break
            wake = time.monotonic() + pause
            while time.monotonic() < wake:  # a real client pings every 10 s, which keeps the server's 30 s idle timeout away
                time.sleep(min(10.0, max(0.0, wake - time.monotonic())))
                if time.monotonic() < wake:
                    send_message(conn, "/ping")
            size = max(5, min(1200, int(r.lognormvariate(math.log(60), 0.9))))
            send_message(conn, f"T:{time.monotonic_ns()}:{index * 100000 + seq}:" + "x" * size)
            with lock:
                sent.append(index * 100000 + seq)
            seq += 1
        end = stop + 1.5  # everyone stays connected until the end, still pinging
        while time.monotonic() < end:
            time.sleep(min(10.0, max(0.0, end - time.monotonic())))
            if time.monotonic() < end:
                send_message(conn, "/ping")
        conn.close()
        with lock:
            lat.extend(local)

    threads = [threading.Thread(target=run, args=(i,)) for i in indexes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(json.dumps({"sent": sent, "lat": lat}), flush=True)


def uploader(args):
    import transfer
    from chat_core import connect_and_login, fetch_server_certificate, make_tls_context
    from events import decode
    from protocol import receive_message, send_message
    context = make_tls_context(cadata=fetch_server_certificate("127.0.0.1", args.tls_port))
    conn = connect_and_login("127.0.0.1", args.port, "uploader", "bench-password", context, protocol=2)
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "f.bin")
    data = os.urandom(int(args.file_mb * 1024 * 1024))
    open(path, "wb").write(data)
    digest = hashlib.sha256(data).hexdigest()
    times, stop = [], time.monotonic() + args.duration
    n = 0
    while time.monotonic() < stop - 3:
        n += 1
        started = time.perf_counter()
        send_message(conn, json.dumps({"t": "upload", "req": n, "name": f"f{n}.bin", "size": len(data), "sha256": digest}))
        while True:
            ev = decode(receive_message(conn))
            if ev["t"] == "upload_ready":
                break
        transfer.upload("127.0.0.1", args.port, context, ev["ticket"], path)
        times.append(time.perf_counter() - started)
        time.sleep(args.file_gap)
    conn.close()
    print(json.dumps({"file_s": times}), flush=True)


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, max(0, math.ceil(q * len(values)) - 1))]


def orchestrate(args):
    from accounts import AccountStore
    from server import ChatServer, default_tls_context
    tmp = tempfile.mkdtemp()
    accounts = AccountStore(os.path.join(tmp, "w.db"))
    for name in [f"u{i}" for i in range(args.clients)] + ["uploader"]:
        accounts.create_account(name, "bench-password")
    server = ChatServer("127.0.0.1", 0, accounts=accounts, tls_context=default_tls_context()[0], quiet=True,
                        max_upload=64 * 1024 * 1024, user_quota=1024 * 1024 * 1024)  # all default limits stay on
    drops = []
    original_log = server._log
    server._log = lambda code, text: (drops.append(text) if "Dropping" in text else None)
    server.start()
    real = server.bound_port
    port, proxy = real, None
    if args.delay_ms or args.jitter_ms:
        port = real + 1
        while True:
            import socket
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", port))
                s.close()
                break
            except OSError:
                port += 1
        proxy = subprocess.Popen([sys.executable, os.path.join(HERE, "netem.py"), "--listen", str(port), "--target", str(real),
                                  "--delay-ms", str(args.delay_ms), "--jitter-ms", str(args.jitter_ms)], stdout=subprocess.PIPE, text=True)
        proxy.stdout.readline()
    cpu0 = time.process_time()
    common = ["--port", str(port), "--tls-port", str(real), "--duration", str(args.duration), "--mean-gap", str(args.mean_gap),
              "--file-mb", str(args.file_mb), "--file-gap", str(args.file_gap)]
    procs = []
    per = 10
    for first in range(0, args.clients, per):
        procs.append(subprocess.Popen([sys.executable, __file__, "_clients", "--first", str(first), "--count", str(min(per, args.clients - first)),
                                       "--seed", str(args.seed + first)] + common, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True))
    connected = 0
    for p in procs:
        connected += json.loads(p.stdout.readline())["ready"]
    for p in procs:
        p.stdin.write("go\n")
        p.stdin.flush()
    up = None
    if args.file_mb > 0:
        up = subprocess.Popen([sys.executable, __file__, "_upload"] + common, stdout=subprocess.PIPE, text=True)
    sent, lat = [], []
    for p in procs:
        out = json.loads(p.stdout.readline())
        sent += out["sent"]
        lat += [l for _s, l in out["lat"]]
        p.wait(30)
    file_s = json.loads(up.stdout.readline())["file_s"] if up else []
    cpu = time.process_time() - cpu0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024)
    server.stop()
    if proxy:
        proxy.terminate()
    expected = len(sent) * (connected - 1)
    res = {"clients": args.clients, "connected": connected, "delay_ms": args.delay_ms, "jitter_ms": args.jitter_ms, "messages": len(sent),
           "delivered": len(lat), "expected": expected, "median_ms": statistics.median(lat), "p95_ms": pct(lat, 0.95),
           "p99_ms": pct(lat, 0.99), "max_ms": max(lat), "files": len(file_s),
           "dropped_clients": len(drops), "file_median_s": statistics.median(file_s) if file_s else None, "cpu_s": cpu, "rss_mb": rss}
    print(json.dumps(res), flush=True)
    return res


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("role", nargs="?", default="run", choices=["run", "_clients", "_upload"])
    p.add_argument("--clients", type=int, default=40)
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--mean-gap", type=float, default=6.0)
    p.add_argument("--delay-ms", type=float, default=0)
    p.add_argument("--jitter-ms", type=float, default=0)
    p.add_argument("--file-mb", type=float, default=1.0)
    p.add_argument("--file-gap", type=float, default=5.0)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--first", type=int, default=0)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--port", type=int)
    p.add_argument("--tls-port", type=int)
    a = p.parse_args()
    {"run": orchestrate, "_clients": client_process, "_upload": uploader}[a.role](a)
