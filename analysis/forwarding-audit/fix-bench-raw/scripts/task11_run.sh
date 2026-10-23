#!/bin/bash
# task-11: focused B4 eviction re-run after the replied-fold fix (+ B4c control).
set -u
cd /tmp/mq2-bench
source ./harness.sh
CLI=$CLI_HEAD
OUT="$LOGS/fix-b4-followup.out"
: > "$OUT"
BENCH=/tmp/mq2-target-head/release/examples/hotpath_bench
{
  echo "### task-11 B4 follow-up (post-fold) $(date -u +%FT%TZ)"
  sha256sum "$CLI" "$SRV"
  uptime
} | tee -a "$OUT"
$BENCH echo 19001 > "$LOGS/t11-echo.log" 2>&1 & E1=$!
ALL_PIDS+=("$E1")
$BENCH techo 19000 > "$LOGS/t11-techo.log" 2>&1 & E2=$!
ALL_PIDS+=("$E2")
python3 flaky_echo.py 19003 > "$LOGS/t11-flaky.log" 2>&1 & F1=$!
ALL_PIDS+=("$F1")
sleep 0.5
echo "### B4 reply-active peer: udp_forward max_sessions=1, A sends+gets reply, A idle, B retries every 100ms" | tee -a "$OUT"
start_pair client-fix-b4.toml t11-b4
python3 udp_admit.py evict 127.0.0.1:18282 0.5 20 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
grep -E 'udp_forward .*(limit|budget|exhausted)' "$LOGS/t11-b4-client.log" | head -3 | tee -a "$OUT" || true
echo "-- client log eviction debug lines (if RUST_LOG=debug not set, expected empty):" | tee -a "$OUT"
grep -i 'evict' "$LOGS/t11-b4-client.log" | head -3 | tee -a "$OUT" || true
stop_pair
echo "### B4c control: flaky target drops 1st datagram/source (no reply activity), max_sessions=1" | tee -a "$OUT"
start_pair client-fix-b4c.toml t11-b4c
python3 udp_admit.py evict-noreply 127.0.0.1:18282 6.0 20 2>&1 | tee -a "$OUT"
echo "-- client log refusal lines:" | tee -a "$OUT"
grep -E 'udp_forward .*(limit|budget|exhausted)' "$LOGS/t11-b4c-client.log" | head -3 | tee -a "$OUT" || true
stop_pair
kill "$E1" "$E2" "$F1" 2>/dev/null
echo "TASK11_DONE $(date -u +%FT%TZ)" | tee -a "$OUT"
