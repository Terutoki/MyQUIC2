#!/bin/bash
# Supplementary A/B campaign: parent vs HEAD (no forwards), UDP/TCP echo focus,
# more samples per arm-run for loss-frequency and TCP throughput stability.
set -u
cd /tmp/mq2-bench
source ./harness.sh
start_targets
: > "$LOGS/supplement.out"
for rep in 1 2 3 4; do
  if [ $((rep % 2)) -eq 1 ]; then order="parent headA"; else order="headA parent"; fi
  for arm in $order; do
    case $arm in parent) cfg=client-parent.toml ;; *) cfg=client-head-a.toml ;; esac
    case "$arm" in parent) CLI=$CLI_PARENT ;; *) CLI=$CLI_HEAD ;; esac
    out="$LOGS/raw2-$arm-r$rep.log"
    {
      echo "### supplement arm=$arm rep=$rep cfg=$cfg date=$(date -u +%FT%TZ)"
      uptime
    } > "$out"
    start_pair "$cfg" "sup-$arm-r$rep"
    {
      echo '--- warmup'
      run udp 127.0.0.1:18080 127.0.0.1:19001 2000 64
      run tcpecho 127.0.0.1:18080 127.0.0.1:19000 2097152
      run udppaced 127.0.0.1:18080 127.0.0.1:19001 2 128 20000
      echo '--- measured'
      echo "# udp n=10000 x10"
      for i in $(seq 1 10); do run udp 127.0.0.1:18080 127.0.0.1:19001 10000 64; done
      echo "# lat 500 x3"
      for i in 1 2 3; do run lat 127.0.0.1:18080 127.0.0.1:19001 500 64 | tail -1; done
      echo "# lattcp 200 x3"
      for i in 1 2 3; do run lattcp 127.0.0.1:18080 127.0.0.1:19000 200 64 | tail -1; done
      echo "# tcpecho 8MiB x5"
      for i in $(seq 1 5); do run tcpecho 127.0.0.1:18080 127.0.0.1:19000 8388608 | tail -1; done
      echo '--- load'
      uptime
    } 2>&1 | tee -a "$out" | tee -a "$LOGS/supplement.out"
    stop_pair
  done
done
stop_targets
cleanup
echo "SUPPLEMENT DONE $(date -u +%FT%TZ)" | tee -a "$LOGS/supplement.out"
