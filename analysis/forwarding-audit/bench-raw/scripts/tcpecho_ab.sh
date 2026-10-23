#!/bin/bash
set -u
cd /tmp/mq2-bench
source ./harness.sh
start_targets
: > "$LOGS/tcpecho-ab.out"
for rep in 1 2 3; do
  if [ $((rep % 2)) -eq 1 ]; then order="parent headA"; else order="headA parent"; fi
  for arm in $order; do
    case "$arm" in parent) CLI=$CLI_PARENT; cfg=client-parent.toml ;; *) CLI=$CLI_HEAD; cfg=client-head-a.toml ;; esac
    start_pair "$cfg" "tcpx-$arm-r$rep"
    {
      echo "### tcpecho-ab arm=$arm rep=$rep $(date -u +%FT%TZ)"
      for i in 1 2 3; do run tcpecho 127.0.0.1:18080 127.0.0.1:19000 8388608 | tail -1; done
      echo "# measured"
      for i in 1 2 3 4 5; do run tcpecho 127.0.0.1:18080 127.0.0.1:19000 8388608 | tail -1; done
    } 2>&1 | tee -a "$LOGS/tcpecho-ab.out"
    stop_pair
  done
done
stop_targets; cleanup
echo TCPECHO_AB_DONE | tee -a "$LOGS/tcpecho-ab.out"
