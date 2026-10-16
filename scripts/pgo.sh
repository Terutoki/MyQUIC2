#!/usr/bin/env bash
# Profile-guided release builds for myquic2 (PGO, optionally + BOLT).
#
#   scripts/pgo.sh          # PGO: instrument -> train on loopback -> optimize
#   scripts/pgo.sh bolt     # the above, then BOLT (Linux only; llvm-bolt)
#   scripts/pgo.sh clean    # remove PGO/BOLT artifacts (cargo pgo clean)
#
# Why: the hot path is a thin layer of small functions (frame encode/decode,
# the TCP pump, the memo lookups) whose branch and layout the compiler mostly
# guesses at statically. Profile-guided builds let it place the taken paths
# and lay out code from measured behavior; there is no semantic risk (same
# source, same tests) and the cost is one extra build cycle per release.
#
# Requirements:
#   cargo install cargo-pgo
#   rustup component add llvm-tools-preview     # provides llvm-profdata
#   llvm-bolt on PATH                           # only for `bolt` (Linux ELF)
#
# Training workload: one server + one client on loopback (the shipped sample
# configs) driven by `hotpath_bench` — byte-verified TCP echo, a TCP flow
# burst, the UDP sweep (fragment path included) and a short `udpps` burst.
# Nothing leaves the machine. Both instrumented binaries exit through their
# SIGTERM handlers (clean `main` return), which is what makes llvm's runtime
# flush their .profraw files.
#
# Result: cargo-pgo rebuilds into target/<host-triple>/release/ (the same
# directory it instrumented in), i.e. the optimized binaries land at
#   target/<host-triple>/release/myquic2-{server,client}
# Copy them wherever you stage releases from. Run `scripts/pgo.sh clean`
# before an unrelated build to drop stale profiles.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-pgo}"
HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
OUT_DIR="target/${HOST_TRIPLE}/release"

if [ "$MODE" = "clean" ]; then
    cargo pgo clean
    exit 0
fi

command -v cargo-pgo >/dev/null || {
    echo "cargo-pgo not found: cargo install cargo-pgo" >&2
    exit 1
}
if ! cargo pgo info 2>/dev/null | grep -q '^\[llvm-profdata\]: found'; then
    echo "llvm-profdata not found: rustup component add llvm-tools-preview" >&2
    exit 1
fi

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
B=./target/release/examples/hotpath_bench

echo "== build the training harness (normal release build) =="
cargo build --release --example hotpath_bench

echo "== instrumented build of the two shipped binaries =="
cargo pgo instrument build -- --release --bin myquic2-server --bin myquic2-client

echo "== train on loopback (instrumented server + client) =="
"$B" echo 19290 >"$T/echo.log" 2>&1 & ECHO=$!
"$B" techo 19291 >"$T/techo.log" 2>&1 & TECHO=$!
sleep 1
RUST_LOG=warn "$OUT_DIR/myquic2-server" --config config-server.toml >"$T/srv.log" 2>&1 & SRV=$!
sleep 1
RUST_LOG=warn "$OUT_DIR/myquic2-client" --config config-client.toml >"$T/cli.log" 2>&1 & CLI=$!
sleep 2
"$B" tcpecho 127.0.0.1:1080 127.0.0.1:19291 262144 | tail -n1
"$B" tcp 127.0.0.1:1080 127.0.0.1:19291 200 4 | tail -n1
"$B" udpsweep 127.0.0.1:1080 127.0.0.1:19290 64 8,512,2000,8000 1 | tail -n1
"$B" udpps 127.0.0.1:1080 127.0.0.1:19290 2 128 | tail -n1
# Both binaries handle SIGTERM by returning from main, so their profile
# runtime flushes on the normal exit path.
kill -TERM "$SRV" "$CLI" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
wait "$CLI" 2>/dev/null || true
kill "$ECHO" "$TECHO" 2>/dev/null || true

echo "== PGO-optimized rebuild =="
cargo pgo optimize build -- --release --bin myquic2-server --bin myquic2-client

if [ "$MODE" = "bolt" ]; then
    if command -v llvm-bolt >/dev/null; then
        echo "== BOLT: instrumented build + second training run + optimize =="
        cargo pgo bolt build --release --bin myquic2-server --bin myquic2-client
        "$B" echo 19290 >"$T/echo2.log" 2>&1 & ECHO2=$!
        "$B" techo 19291 >"$T/techo2.log" 2>&1 & TECHO2=$!
        sleep 1
        RUST_LOG=warn "$OUT_DIR/myquic2-server" --config config-server.toml >"$T/srv2.log" 2>&1 & SRV2=$!
        sleep 1
        RUST_LOG=warn "$OUT_DIR/myquic2-client" --config config-client.toml >"$T/cli2.log" 2>&1 & CLI2=$!
        sleep 2
        "$B" tcpecho 127.0.0.1:1080 127.0.0.1:19291 262144 | tail -n1
        "$B" udpsweep 127.0.0.1:1080 127.0.0.1:19290 64 8,512,2000,8000 1 | tail -n1
        kill -TERM "$SRV2" "$CLI2" 2>/dev/null || true
        wait "$SRV2" 2>/dev/null || true
        wait "$CLI2" 2>/dev/null || true
        kill "$ECHO2" "$TECHO2" 2>/dev/null || true
        cargo pgo bolt optimize --release --bin myquic2-server --bin myquic2-client
    else
        echo "llvm-bolt not found on PATH; skipping BOLT (PGO result is already in $OUT_DIR)" >&2
    fi
fi

echo "== done: optimized binaries in $OUT_DIR =="
ls -l "$OUT_DIR"/myquic2-server "$OUT_DIR"/myquic2-client
