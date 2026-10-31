"""Repeated trials for the paper: fan-out latency and the stalled-receiver test, several servers.

    python3 bench/repeat.py fanout   [--trials 8]    ->  bench/results/fanout.jsonl
    python3 bench/repeat.py stalled  [--trials 10]   ->  bench/results/stalled.jsonl
    python3 bench/repeat.py summary                  ->  mean, standard deviation and range per setting

Each fan-out trial runs in a fresh process so the peak memory figure belongs to that trial.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")
os.makedirs(RESULTS, exist_ok=True)


def fanout(trials, messages):
    plan = [(kind, n, False) for n in (10, 50, 100) for kind in ("relay", "asyncio", "asyncio-db", "chat")]
    plan += [("chat", 100, True), ("chat", 200, False)]
    with open(os.path.join(RESULTS, "fanout.jsonl"), "a") as out:
        for kind, n, tls in plan:
            for t in range(5 if n == 200 or tls else trials):
                cmd = [sys.executable, os.path.join(HERE, "fanout.py"), "--clients", str(n), "--messages", str(messages),
                       "--kind", kind, "--json"] + (["--tls"] if tls else [])
                line = subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout.strip().splitlines()[-1]
                out.write(line + "\n")
                out.flush()
                print(kind, n, tls, t, line[:90], flush=True)


def stalled(trials):
    sys.path.insert(0, HERE)
    import slow_receiver
    with open(os.path.join(RESULTS, "stalled.jsonl"), "a") as out:
        for kind in ("relay", "asyncio", "asyncio-db", "chat"):
            for t in range(trials):
                r = slow_receiver.run_trial(kind, 10, 600, 2000, 0.02, True)
                r["trial"] = t
                out.write(json.dumps(r) + "\n")
                out.flush()
                print(kind, t, r["delivered"], r["expected"], flush=True)


def ms(values):
    values = list(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return f"{statistics.fmean(values):.2f} ± {sd:.2f} [{min(values):.2f}–{max(values):.2f}]"


def summary():
    path = os.path.join(RESULTS, "fanout.jsonl")
    rows = [json.loads(l) for l in open(path)] if os.path.exists(path) else []
    groups = {}
    for r in rows:
        groups.setdefault((r["kind"], r["clients"], r["tls"]), []).append(r)
    print("FANOUT kind clients tls trials | median_ms | p95_ms | cpu_s | rss_mb | delivered%")
    for (kind, n, tls), g in sorted(groups.items(), key=lambda x: (x[0][1], x[0][2], x[0][0])):
        ok = statistics.fmean(100 * r["delivered"] / r["expected"] for r in g)
        print(f"{kind:<11}{n:>4} {str(tls):<5}{len(g):>3} | {ms(r['median_ms'] for r in g)} | {ms(r['p95_ms'] for r in g)} | "
              f"{ms(r['cpu_s'] for r in g)} | {ms(r['rss_mb'] for r in g)} | {ok:.1f}")
    path = os.path.join(RESULTS, "stalled.jsonl")
    rows = [json.loads(l) for l in open(path)] if os.path.exists(path) else []
    groups = {}
    for r in rows:
        groups.setdefault(r["kind"], []).append(r)
    print("\nSTALLED kind trials | delivered/expected (mean) | delivered range | median_ms | dropped stalled")
    for kind, g in groups.items():
        frac = [100 * r["delivered"] / r["expected"] for r in g]
        dropped = [r["stalled_still_connected"] for r in g if r["stalled_still_connected"] is not None]
        print(f"{kind:<11}{len(g):>3} | {statistics.fmean(frac):.1f}% ± {statistics.stdev(frac) if len(frac) > 1 else 0:.1f} | "
              f"{min(r['delivered'] for r in g)}–{max(r['delivered'] for r in g)} of {g[0]['expected']} | "
              f"{ms(r['median_ms'] for r in g)} | {sum(1 for d in dropped if not d)}/{len(dropped) if dropped else 0}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("what", choices=["fanout", "stalled", "summary"])
    p.add_argument("--trials", type=int, default=8)
    p.add_argument("--messages", type=int, default=60)
    a = p.parse_args()
    {"fanout": lambda: fanout(a.trials, a.messages), "stalled": lambda: stalled(a.trials),
     "summary": summary}[a.what]()
