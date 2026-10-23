#!/bin/bash
# A2: paced-loss knee sweep, parent vs HEAD, to test for a steady-state UDP
# throughput regression independent of the blast-mode harness.
set -u
cd /tmp/mq2-bench
source ./harness.sh
start_targets
: > "$LOGS/knee.out"
for rep in 1 2; do
  for rate in 32000 36000 40000 44000; do
    if [ $((rep % 2)) -eq 1 ]; then order="parent headA"; else order="headA parent"; fi
    for arm in $order; do
      case "$arm" in parent) CLI=$CLI_PARENT; cfg=client-parent.toml ;; *) CLI=$CLI_HEAD; cfg=client-head-a.toml ;; esac
      tag="knee-$arm-r$rep-$rate"
      start_pair "$cfg" "$tag"
      echo "### rate=$rate arm=$arm rep=$rep $(date -u +%FT%TZ)" | tee -a "$LOGS/knee.out"
      run udppaced 127.0.0.1:18080 127.0.0.1:19001 4 128 "$rate" | tee -a "$LOGS/knee.out"
      stop_pair
    done
  done
done
stop_targets
cleanup
echo "KNEE DONE" | tee -a "$LOGS/knee.out"
