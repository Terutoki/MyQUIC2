#!/bin/bash
set -u
cd /tmp/mq2-bench
source ./harness.sh
CLI=$CLI_HEAD
OUT="$LOGS/fix-b4c.out"
: > "$OUT"
python3 flaky_echo.py 19003 > "$LOGS/flaky-echo.log" 2>&1 & FLAKY=$!
ALL_PIDS+=("$FLAKY")
sleep 0.3
BENCH=/tmp/mq2-target-head/release/examples/hotpath_bench
$BENCH echo 19001 > "$LOGS/target-echo-b4c.log" 2>&1 & E1=$!
ALL_PIDS+=("$E1")
$BENCH techo 19000 > "$LOGS/target-techo-b4c.log" 2>&1 & E2=$!
ALL_PIDS+=("$E2")
sleep 0.3
echo "### B4c control: eviction idle floor with no reply activity (flaky target drops 1st datagram/source)" | tee -a "$OUT"
start_pair client-fix-b4c.toml fix-b4c
python3 udp_admit.py evict-noreply 127.0.0.1:18282 6.0 20 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
grep -E 'udp_forward .*(limit|budget|exhausted)' "$LOGS/fix-b4c-client.log" | head -5 | tee -a "$OUT" || true
stop_pair
kill "$E1" "$E2" "$FLAKY" 2>/dev/null
echo "B4C_DONE" | tee -a "$OUT"
