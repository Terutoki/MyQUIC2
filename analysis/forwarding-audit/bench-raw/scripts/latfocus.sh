#!/bin/bash
# A3: isolated serial-latency A/B on a fresh client with no prior blast phase.
set -u
cd /tmp/mq2-bench
source ./harness.sh
start_targets
: > "$LOGS/latfocus.out"
for rep in 1 2 3; do
  if [ $((rep % 2)) -eq 1 ]; then order="parent headA"; else order="headA parent"; fi
  for arm in $order; do
    case "$arm" in parent) CLI=$CLI_PARENT; cfg=client-parent.toml ;; *) CLI=$CLI_HEAD; cfg=client-head-a.toml ;; esac
    tag="lat-$arm-r$rep"
    start_pair "$cfg" "$tag"
    {
      echo "### latfocus arm=$arm rep=$rep $(date -u +%FT%TZ)"
      run lat 127.0.0.1:18080 127.0.0.1:19001 200 64 | tail -1   # warmup, not used
      for i in 1 2 3 4 5; do run lat 127.0.0.1:18080 127.0.0.1:19001 500 64 | tail -1; done
      run lattcp 127.0.0.1:18080 127.0.0.1:19000 300 64 | tail -1
    } 2>&1 | tee -a "$LOGS/latfocus.out"
    stop_pair
  done
done
stop_targets
cleanup
echo "LATFOCUS DONE" | tee -a "$LOGS/latfocus.out"
