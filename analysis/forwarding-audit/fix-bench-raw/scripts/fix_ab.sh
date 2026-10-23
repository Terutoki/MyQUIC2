#!/bin/bash
# Plan A: post-fix HEAD client vs parent client, SOCKS5 ECHO A/B, interleaved.
set -u
cd /tmp/mq2-bench
source ./harness.sh
CLI_HEAD=/tmp/mq2-target-head/release/myquic2-client
start_targets
: > "$LOGS/fix-ab.out"
for rep in 1 2 3; do
  if [ $((rep % 2)) -eq 1 ]; then order="parent fixed"; else order="fixed parent"; fi
  for arm in $order; do
    case "$arm" in parent) CLI=$CLI_PARENT; cfg=client-parent.toml ;; *) CLI=$CLI_HEAD; cfg=client-head-a.toml ;; esac
    tag="fix-$arm-r$rep"
    out="$LOGS/fix-ab-$arm-r$rep.log"
    { echo "### fix-ab arm=$arm rep=$rep $(date -u +%FT%TZ)"; uptime; } > "$out"
    start_pair "$cfg" "$tag"
    {
      echo '--- warmup'
      run udp 127.0.0.1:18080 127.0.0.1:19001 3000 64
      run tcpecho 127.0.0.1:18080 127.0.0.1:19000 2097152 | tail -1
      run udppaced 127.0.0.1:18080 127.0.0.1:19001 2 128 20000
      run lat 127.0.0.1:18080 127.0.0.1:19001 100 64 | tail -1
      echo '--- measured udp blast n=10000 x10'
      for i in $(seq 1 10); do run udp 127.0.0.1:18080 127.0.0.1:19001 10000 64; done
      echo '--- measured udppaced 30k x3'
      for i in 1 2 3; do run udppaced 127.0.0.1:18080 127.0.0.1:19001 6 128 30000; done
      echo '--- measured udpbidir 20k x2'
      for i in 1 2; do run udpbidir 127.0.0.1:18080 127.0.0.1:19001 6 128 20000; done
      echo '--- measured lat x5'
      for i in 1 2 3 4 5; do run lat 127.0.0.1:18080 127.0.0.1:19001 500 64 | tail -1; done
      echo '--- measured lattcp x3'
      for i in 1 2 3; do run lattcp 127.0.0.1:18080 127.0.0.1:19000 200 64 | tail -1; done
      echo '--- measured tcpecho 8MiB x5'
      for i in 1 2 3 4 5; do run tcpecho 127.0.0.1:18080 127.0.0.1:19000 8388608 | tail -1; done
      echo '--- load'; uptime
    } 2>&1 | tee -a "$out" | tee -a "$LOGS/fix-ab.out"
    stop_pair
  done
done
stop_targets; cleanup
echo "FIX_AB_DONE $(date -u +%FT%TZ)" | tee -a "$LOGS/fix-ab.out"
