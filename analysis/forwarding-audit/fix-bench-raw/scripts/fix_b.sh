#!/bin/bash
# Plan B: external admission checks for the post-fix forward listeners.
set -u
cd /tmp/mq2-bench
source ./harness.sh
CLI=$CLI_HEAD
OUT="$LOGS/fix-b.out"
: > "$OUT"
start_targets
BENCH=/tmp/mq2-target-head/release/examples/hotpath_bench

show_log() { grep -E 'tcp_forward|udp_forward' "$LOGS/$1-client.log" | grep -Ev 'max_conns=|max_sessions=|max_sessions=[0-9]+, per-peer|tcp_forward .* via QUIC \(bound\)' | head -8; }

echo "### B1: tcp_forward max_conns=2, 5 concurrent raw TCP connections, hold 2, then close+new" | tee -a "$OUT"
start_pair client-fix-b1.toml fix-b1
python3 tcp_admit.py 127.0.0.1:18181 5 --after-close 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
show_log fix-b1 | tee -a "$OUT"
stop_pair

echo "### B2: max_forward_conns=2 (listener max_conns=5), 5 concurrent, hold 2" | tee -a "$OUT"
start_pair client-fix-b2.toml fix-b2
python3 tcp_admit.py 127.0.0.1:18181 5 --after-close 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
show_log fix-b2 | tee -a "$OUT"
stop_pair

echo "### B3: udp_forward max_sessions=2, 5 distinct source ports (1 datagram each), then age 5.2 s + new peer" | tee -a "$OUT"
start_pair client-fix-b3.toml fix-b3
python3 udp_admit.py peers 127.0.0.1:18282 5 5.2 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
show_log fix-b3 | tee -a "$OUT"
stop_pair

echo "### B4: eviction, max_sessions=1, peer A replies then idle, peer B retries (reply-activity path)" | tee -a "$OUT"
start_pair client-fix-b4.toml fix-b4
python3 udp_admit.py evict 127.0.0.1:18282 0.5 60 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
show_log fix-b4 | tee -a "$OUT"
stop_pair

echo "### B4b control: eviction with black-hole target (no reply activity), max_sessions=1" | tee -a "$OUT"
start_pair client-fix-b4b.toml fix-b4b
python3 udp_admit.py evict-noreply 127.0.0.1:18282 6.0 20 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
show_log fix-b4b | tee -a "$OUT"
stop_pair

echo "### B5: forwarding path regression sanity (default limits): udp_forward pps, 50 peers, SHA-256 TCP bulk" | tee -a "$OUT"
start_pair client-head-b.toml fix-b5
echo "-- udp_forward pps 1000B n=10000 batch=64 x5" | tee -a "$OUT"
for i in 1 2 3 4 5; do python3 bench_forward.py udp-pps 127.0.0.1:18282 10000 64 1000 2>&1 | tee -a "$OUT"; done
echo "-- udp_forward 50 peers x 2000 dgrams 128B batch 32 x2" | tee -a "$OUT"
for i in 1 2; do python3 bench_forward.py udp-multi 127.0.0.1:18282 50 2000 32 128 2>&1 | tee -a "$OUT"; done
echo "-- tcp_forward SHA-256 8MiB x10" | tee -a "$OUT"
for i in $(seq 1 10); do python3 tcpverify.py 127.0.0.1:18181 8388608 fwd-$i 2>&1 | tee -a "$OUT"; done
stop_pair

stop_targets
cleanup
echo "FIX_B_DONE $(date -u +%FT%TZ)" | tee -a "$OUT"
