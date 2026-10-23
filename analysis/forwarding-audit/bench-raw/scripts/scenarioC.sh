#!/bin/bash
# Scenario C: absolute performance of the new client forward listeners, compared
# against the SOCKS5 baseline measured in the same process/config (client-head-b).
set -u
cd /tmp/mq2-bench
source ./harness.sh
start_targets
CLI=$CLI_HEAD
start_pair client-head-b.toml "fwd"
: > "$LOGS/forward.out"
{
  echo "### scenario C forward listeners $(date -u +%FT%TZ)"
  echo '--- startup log lines'
  grep -E 'forward' "$LOGS/fwd-client.log" || true
  echo '--- udp forward: warmup + verify'
  python3 bench_forward.py udp-pps 127.0.0.1:18282 100 8 1000
  python3 bench_forward.py udp-lat 127.0.0.1:18282 50 64
  echo '--- udp forward pps (1000B payload, n=10000, batch=64) x5'
  for i in 1 2 3 4 5; do python3 bench_forward.py udp-pps 127.0.0.1:18282 10000 64 1000; done
  echo '--- udp forward serial latency (payload 64) x5'
  for i in 1 2 3 4 5; do python3 bench_forward.py udp-lat 127.0.0.1:18282 500 64; done
  echo '--- udp forward multi-peer 50 peers x 2000 dgrams batch 32 payload 128'
  python3 bench_forward.py udp-multi 127.0.0.1:18282 50 2000 32 128
  python3 bench_forward.py udp-multi 127.0.0.1:18282 50 2000 32 128
  echo '--- tcp forward: warmup + verify'
  python3 bench_forward.py tcp-lat 127.0.0.1:18181 50 64
  echo '--- tcp forward bulk 8MiB x4'
  for i in 1 2 3 4; do python3 bench_forward.py tcp-bulk 127.0.0.1:18181 8388608; done
  echo '--- tcp forward raw latency (payload 64) x5'
  for i in 1 2 3 4 5; do python3 bench_forward.py tcp-lat 127.0.0.1:18181 500 64; done
  echo '--- client log tail'
  grep -cE 'forward' "$LOGS/fwd-client.log" || true
  uptime
} 2>&1 | tee -a "$LOGS/forward.out"
stop_pair
stop_targets
cleanup
echo "FORWARD DONE" | tee -a "$LOGS/forward.out"
