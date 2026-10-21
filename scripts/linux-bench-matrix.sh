#!/usr/bin/env bash
# MQP-3 rev2 acceptance matrix on a Linux target (2-4 cores + netem).
#
#   scripts/linux-bench-matrix.sh [--quick] [--no-netem] [--out DIR]
#
# Why: every rev2 gain in the change set is a model number until it is measured
# on the deployment shape (Linux, 2-4 cores, 70/140 ms RTT, 0/0.5/2 % loss).
# macOS loopback proves correctness only; pinning/GSO/GRO/ksoftirq behavior all
# differ, so this script is the gate for performance claims.
#
# What it does:
#   1. builds release binaries + hotpath_bench;
#   2. shapes `lo` with `tc netem` (needs root; `--no-netem` skips);
#   3. starts the UDP echo / multi-port echo targets, one server, one client
#      with temporary configs in $OUT (the repo configs are untouched);
#   4. runs the rev2 matrix and writes one log per cell plus summary.txt;
#   5. captures the client/server 60 s reporter lines (rev2 counters, drops,
#      frag counts) and the per-cell hotpath_bench output;
#   6. restores `lo` and kills every process it started.
#
# Result interpretation: compare cells against the Phase-1a/1b model in
# MQP3_REFACTOR_ANALYSIS.md (small-packet wire/CPU) and against the same cells
# on the parent commit; a cell that loses loss/p99 is a regression even if bytes
# drop. `--quick` runs 2 s cells; the default runs 10-15 s cells.
set -euo pipefail

cd "$(dirname "$0")/.."

QUICK=0
NETEM=1
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) QUICK=1 ;;
        --no-netem) NETEM=0 ;;
        --out) OUT="$2"; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$(uname -s)" != "Linux" ]; then
    echo "this matrix targets Linux (netem + GSO/GRO); current host: $(uname -s)" >&2
    exit 2
fi

OUT="${OUT:-/tmp/mqp3-rev2-matrix-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
H=./target/release/examples/hotpath_bench
SRV=./target/release/myquic2-server
CLI=./target/release/myquic2-client
SOCKS=127.0.0.1:11080
ECHO_PORT=19000
FAN_PORT=19100

echo "== build =="
cargo build --release --bins --example hotpath_bench

# ---- temp configs (repo configs untouched) ---------------------------------
python3 - "$OUT" <<'PY'
import sys
out=sys.argv[1]
s=open('config-server.toml').read()
s=s.replace('listen = "[::]:8443"', 'listen = "127.0.0.1:18443"')
s=s.replace('congestion = "bbr"', 'congestion = "bbr"\nquic_endpoints = 1\ndns_ip_preference = "ipv4"', 1)
open(f'{out}/server.toml','w').write(s)
c=open('config-client.toml').read()
c=c.replace('socks_listen = "[::]:1080"', 'socks_listen = "127.0.0.1:11080"')
c=c.replace('server_addr = "127.0.0.1:8443"', 'server_addr = "127.0.0.1:18443"')
open(f'{out}/client.toml','w').write(c)
PY

cleanup() {
    [ -n "${CL_PID:-}" ] && kill "$CL_PID" 2>/dev/null || true
    [ -n "${SV_PID:-}" ] && kill "$SV_PID" 2>/dev/null || true
    [ -n "${E1_PID:-}" ] && kill "$E1_PID" 2>/dev/null || true
    [ -n "${E2_PID:-}" ] && kill "$E2_PID" 2>/dev/null || true
    if [ "$NETEM" = 1 ]; then
        tc qdisc del dev lo root 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [ "$NETEM" = 1 ]; then
    if [ "$(id -u)" != 0 ]; then
        echo "-- netem needs root; re-run with sudo or --no-netem" >&2
        exit 2
    fi
    tc qdisc del dev lo root 2>/dev/null || true
    tc qdisc add dev lo root netem delay 70ms
    echo "netem: lo 70 ms (run the script again with delay/loss edits for the 140 ms / 0.5 % / 2 % cells)"
fi

$H echo "$ECHO_PORT" >"$OUT/echo.log" 2>&1 & E1_PID=$!
$H echomulti "$FAN_PORT" 8 >"$OUT/echomulti.log" 2>&1 & E2_PID=$!
sleep 0.3
$SRV --config "$OUT/server.toml" >"$OUT/server.log" 2>&1 & SV_PID=$!
sleep 0.8
$CLI --config "$OUT/client.toml" >"$OUT/client.log" 2>&1 & CL_PID=$!
sleep 2.0

SECS=10; [ "$QUICK" = 1 ] && SECS=2
cell() {
    local name="$1"; shift
    echo "== $name =="
    timeout 180 "$@" >"$OUT/$name.log" 2>&1 || echo "[cell failed: $name]" | tee -a "$OUT/summary.txt"
    cat "$OUT/$name.log" >>"$OUT/summary.txt"
    tail -n 2 "$OUT/$name.log"
}

cell warmup             $H udp "$SOCKS" 127.0.0.1:$ECHO_PORT 50 1
cell udp_1k_single_data $H udp "$SOCKS" 127.0.0.1:$ECHO_PORT 2000 16
cell udppaced_128_rev2  $H udppaced "$SOCKS" 127.0.0.1:$ECHO_PORT "$SECS" 128 5000
cell udpdomain_rev2     $H udpdomain "$SOCKS" localhost:$ECHO_PORT 1000
cell udpfanout_8flows   $H udpfanout "$SOCKS" 127.0.0.1:$FAN_PORT 8 2000 16
cell udpsweep_all       $H udpsweep "$SOCKS" 127.0.0.1:$ECHO_PORT 300 8,128,512,1000,2000,3000,5000,8000 4
cell udpbidir           $H udpbidir "$SOCKS" 127.0.0.1:$ECHO_PORT "$SECS" 128 5000
cell lat                $H lat "$SOCKS" 127.0.0.1:$ECHO_PORT 200 64
cell udpmulti_8assoc    $H udpmulti "$SOCKS" 127.0.0.1:$ECHO_PORT 8 2000 64

# Let the 60 s reporter fire once so the log carries the rev2 counters.
if [ "$QUICK" = 0 ]; then
    echo "== waiting for the 60 s rev2 reporter =="
    sleep 50
fi
grep -E "mqp3 rev2|udp relay|udp budget|udp write|udp late" "$OUT/client.log" >>"$OUT/summary.txt" || true
grep -E "WARN|ERROR" "$OUT/server.log" "$OUT/client.log" | grep -v "connection lost\|close reason" >>"$OUT/summary.txt" || true

echo
echo "matrix written to: $OUT"
echo "next: repeat with netem delay 140ms / loss 0.5% / loss 2% and compare cells;"
echo "      a small-packet cell must not lose 0-loss status or regress p99 to be a win."
