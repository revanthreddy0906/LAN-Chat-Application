#!/bin/sh
# Mixed workload at several emulated network delays; one JSON line per run.
cd "$(dirname "$0")/.."
for cfg in "40 0 0" "40 5 1" "40 20 4" "40 50 10" "40 100 20" "100 0 0"; do
  set -- $cfg
  python3 bench/workload.py --clients $1 --delay-ms $2 --jitter-ms $3 --duration 60 >> bench/results/workload.jsonl 2>> bench/results/workload.err
done
echo finished >> bench/results/workload.err
