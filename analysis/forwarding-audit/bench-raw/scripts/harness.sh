#!/bin/bash
# Benchmark harness for MyQUIC2 forwarding audit (task-4).
# Starts echo targets once, then per arm-run starts a fresh HEAD server + the
# arm's client binary/config, runs the SOCKS5 bench suite, and kills them.
set -u
BENCH=/tmp/mq2-target-head/release/examples/hotpath_bench
SRV=/tmp/mq2-target-head/release/myquic2-server
CLI_HEAD=/tmp/mq2-target-head/release/myquic2-client
CLI_PARENT=/tmp/mq2-target-parent/release/myquic2-client
DIR=/tmp/mq2-bench
LOGS=$DIR/logs
SOCKS=127.0.0.1:18080
UTGT=127.0.0.1:19001
TTGT=127.0.0.1:19000

declare -a ALL_PIDS=()
cleanup() {
  for p in "${ALL_PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 0.2
}
trap cleanup EXIT

start_targets() {
  $BENCH echo 19001 > "$LOGS/target-echo.log" 2>&1 & echo $! >> "$LOGS/target.pids"
  $BENCH techo 19000 > "$LOGS/target-techo.log" 2>&1 & echo $! >> "$LOGS/target.pids"
  sleep 0.5
  for p in $(cat "$LOGS/target.pids"); do ALL_PIDS+=("$p"); done
}

stop_targets() {
  for p in $(cat "$LOGS/target.pids" 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -f "$LOGS/target.pids"
}

# start_pair <config> <logtag> ; sets PAIR_PIDS
start_pair() {
  local cfg=$1 tag=$2
  $SRV --config "$DIR/server.toml" > "$LOGS/$tag-server.log" 2>&1 & local srv=$!
  sleep 0.7
  $CLI --config "$DIR/$cfg" > "$LOGS/$tag-client.log" 2>&1 & local cli=$!
  for _ in $(seq 1 100); do
    grep -q 'socks5 listening' "$LOGS/$tag-client.log" 2>/dev/null && break
    sleep 0.1
  done
  if ! grep -q 'socks5 listening' "$LOGS/$tag-client.log" 2>/dev/null; then
    echo "FATAL: client did not start ($tag)"; tail -5 "$LOGS/$tag-client.log"; exit 1
  fi
  sleep 0.6   # let the QUIC pool finish its startup handshakes
  PAIR_PIDS=("$srv" "$cli")
}

stop_pair() {
  for p in "${PAIR_PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 0.25
}

run() { echo "== $*"; $BENCH "$@"; }

# one arm-run: config label rep
run_arm() {
  local cfg=$1 label=$2 rep=$3
  local out="$LOGS/raw-$label-r$rep.log"
  {
    echo "### arm=$label rep=$rep cfg=$cfg date=$(date -u +%FT%TZ)"
    uptime
  } > "$out"
  case "$label" in
    parent) CLI=$CLI_PARENT ;;
    *)      CLI=$CLI_HEAD ;;
  esac
  start_pair "$cfg" "$label-r$rep"
  {
    echo '--- warmup'
    run udp 127.0.0.1:18080 $UTGT 3000 64
    run tcpecho 127.0.0.1:18080 $TTGT 2097152
    run udppaced 127.0.0.1:18080 $UTGT 2 128 20000
    run lat 127.0.0.1:18080 $UTGT 100 64
    run lattcp 127.0.0.1:18080 $TTGT 50 64
    echo '--- measured'
    echo "# udp_clean pps (n=10000 batch=64) x5"
    for i in 1 2 3 4 5; do run udp 127.0.0.1:18080 $UTGT 10000 64; done
    echo "# udp_wall_fixed 5s stall counts as lossy run"
    echo "# lower_lat"
    for i in 1 2; do run lat 127.0.0.1:18080 $UTGT 500 64 | tail -1; done
    echo "# tcp_lat"
    for i in 1 2; do run lattcp 127.0.0.1:18080 $TTGT 200 64 | tail -1; done
    echo "# tcp_echo_8MiB"
    for i in 1 2; do run tcpecho 127.0.0.1:18080 $TTGT 8388608 | tail -1; done
    echo "# udp_paced_30k"
    run udppaced 127.0.0.1:18080 $UTGT 6 128 30000
    echo "# udp_bidir_20k"
    run udpbidir 127.0.0.1:18080 $UTGT 6 128 20000
    echo "# udp_multipaced_4x4000"
    run udpmultipaced 127.0.0.1:18080 $UTGT 4 6 128 4000
    echo '--- load'
    uptime
  } 2>&1 | tee -a "$out"
  stop_pair
}

"$@"
