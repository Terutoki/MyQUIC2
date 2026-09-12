# MyQUIC2

**An ultra-high-performance QUIC-based SOCKS5 proxy** — multiplexes TCP and UDP traffic
over a single QUIC connection, written in Rust.

MyQUIC2 speaks standard SOCKS5 (RFC 1928) on the ingress side, so browsers, CLIs and
apps work unchanged (`curl --socks5`, system proxy settings, etc.), while the wire
between client and server is a purpose-built minimal binary protocol (**MQP-2**) over
QUIC (TLS 1.3, BBR congestion control, GSO/GRO batching, 0-RTT resumption,
ALPN `myquic2/2` so version-skewed peers fail closed at the handshake).

```
[ App ] --TCP/UDP--> [ myquic2-client :1080 ] ==QUIC (1 connection)==> [ myquic2-server :8443 ] --TCP/UDP--> [ Internet ]
```

The 2026-09 hardening revision adds optional shared-secret client authentication,
process-wide resource caps, PMTU-aware DATAGRAM sizing, 0-RTT-safe authentication, and
a corrected reconnect path. The latest pass removes a **process-abort** reachable from
normal network conditions (an MTU reduction could trip an accounting bug inside
quinn-proto's drop-oldest DATAGRAM path) and strips the remaining per-flow allocations
from the TCP-open path — see
[Hardening notes](#2026-09-hardening-pass-5). Every behaviour documented below was
re-verified end-to-end on this revision — see
[Verification & E2E Tests](#verification--e2e-tests).

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [The MQP-2 Protocol](#the-mqp-2-protocol)
- [Security Model](#security-model)
- [Verification \& E2E Tests](#verification--e2e-tests)
- [Requirements](#requirements)
- [Building](#building)
- [Configuration](#configuration)
- [Running](#running)
- [Certificates \& Authentication](#certificates--authentication)
- [Resource Limits \& Tuning](#resource-limits--tuning)
- [SOCKS5 Compliance](#socks5-compliance)
- [Reconnect \& High-RTT Behavior](#reconnect--high-rtt-behavior)
- [OpenWrt Deployment](#openwrt-deployment)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)
- [Hardening Notes (this revision)](#hardening-notes-this-revision) — includes [pass 5](#2026-09-hardening-pass-5)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Area | Detail |
|---|---|
| **Proxy ingress** | Standard SOCKS5: `CONNECT` (TCP) + `UDP ASSOCIATE`, IPv4 / domain / IPv6 targets. SOCKS itself is no-auth by design; the QUIC link can be protected with a token |
| **Transport** | QUIC (quinn 0.11), TLS 1.3 only, one long-lived connection per client process shared by all flows |
| **Handshake path** | Per-incoming accept/handshake tasks — one slow client can never stall new connections |
| **Congestion** | BBR by default (Cubic available as escape hatch), ECN + pacing on |
| **Offload** | GSO/GRO auto-probed (`UDP_SEGMENT`); 4 MB QUIC socket buffers; 1 MB DATAGRAM send/receive buffers |
| **Custom protocol** | MQP-2 binary framing: TCP costs **0 extra bytes** after the first header; UDP costs **+12 B (IPv4) / +24 B (IPv6)** per datagram |
| **0-RTT** | Session resumption with early data, verified end-to-end (`accepted=true`). The auth token rides early data and is automatically re-sent if the server rejects it |
| **Reconnect** | Survives server restarts: ~15–20 s silent-path detection, backoff redial (200 ms → 5 s, decayed only after 5 s of stable connectivity), fail-fast old streams, UDP sessions self-heal |
| **Dual-stack** | IPv4 + IPv6 everywhere: listeners, relays, dial-out; v4-mapped handling on BSD/macOS |
| **Identity** | Client pins the exact Ed25519 server cert; optional `auth_token` (constant-time compare, ≤ 256 B) prevents open-relay abuse |
| **Hard bounds** | 4096 concurrent QUIC connections (256 pre-auth), 8192 UDP sessions process-wide, 8 MB per-connection receive window |
| **DNS** | Resolved **server-side** (correct egress geo, no client resolver cost): 60 s positive / 10 s negative cache, single-flight, 1024-entry slow-path limiter |
| **High-RTT tuned** | 2 MB per-stream window, 8 MB aggregate receive window, 4 MB send window — halved in the gaps-death hardening pass (bounds in-flight bytes so burst loss can't flood the receiver's reassembly); covers ~114 Mb/s single-stream at ~140 ms |
| **Releases** | Static musl binaries for OpenWrt x86-64 at four CPU levels (v1–v4), ~4.1–4.2 MB stripped each (rebuilt from this revision) |

---

## Architecture

Single crate, three units sharing one protocol library:

| Unit | Source | Role |
|---|---|---|
| `myquic2` (lib) | `src/lib.rs` | MQP-2 codec (owned + borrowed forms), TOML config schema, TLS/cert helpers, QUIC transport builder, TCP↔QUIC bridge |
| `myquic2-server` | `src/bin/myquic2-server.rs` | QUIC ingress → dials TCP/UDP targets; per-session UDP sockets; token auth; self-signed cert issuance |
| `myquic2-client` | `src/bin/myquic2-client.rs` | SOCKS5 ingress → QUIC egress; reconnect loop; per-association UDP relay; DATAGRAM dispatcher; token auth |
| `zero_rtt_probe` | `examples/zero_rtt_probe.rs` | End-to-end 0-RTT verification probe (with token support) |

**Data-plane mapping:**

- **TCP**: 1 TCP connection = 1 QUIC bidirectional stream. First bytes carry the MQP
  target header; the rest is a raw byte stream. The client answers SOCKS success
  optimistically and the server's MQP-2 dial ACK is validated on the reply path, so
  application bytes never wait for the remote dial. `FIN` ↔ QUIC `finish()`,
  dial failure ↔ closed/reset flow.
- **UDP**: 1 SOCKS association = 1 session id (`sess_id`), carried in QUIC **DATAGRAMs**
  (unreliable, no head-of-line blocking — a lost DNS packet never stalls other flows).
  Each datagram must fit `min(live path max_datagram_size, 1350 B)` including the MQP
  header; larger packets are dropped per UDP semantics.
- **Control**: when `auth_token` is set, connection setup carries exactly one
  **authentication uni stream** (≤ 256 B). After that there is no control traffic
  beyond QUIC itself — no SOCKS username/password.

**Concurrency model:** Tokio multi-threaded runtime. The server spawns one task per
incoming connection (handshake included), one DATAGRAM reader and one session sweeper
per connection, and one lightweight reader task per UDP session. The client runs one
process-wide DATAGRAM dispatcher, one reconnect loop, one task per SOCKS connection,
and one relay + reply task per UDP association. Subscriptions die with their
association, so stale tasks can never steal another session's packets.

---

## The MQP-2 Protocol

All integers little-endian unless noted. Address encoding mirrors SOCKS5
(`0x01` IPv4 + 4 B, `0x04` IPv6 + 16 B, `0x03` domain + 1 B len + N B), followed by
port in big-endian — so IP headers can be reused byte-for-byte.

### TCP stream open (stream head, sent once)

```
atyp u8 | addr bytes | port u16 BE
IPv4 total: 7 B. Everything after is raw application bytes (zero overhead).
```

The server replies with a status byte plus the address its dialed socket was
bound to:

```
0x00 | atyp u8 | addr bytes | port u16 BE
```

`0x00` = dial accepted. The client answers SOCKS success **immediately after writing
the target header**, before the ACK: waiting for the ACK would serialize the
application's first bytes behind the remote dial and costs one full client↔server
RTT on every connection (juicity/Hysteria-class clients answer immediately for the
same reason). The ACK is consumed by the reply direction; a reset or non-zero status
(dial refused/timeout) tears the TCP flow down, so a failed dial surfaces as a closed
connection rather than a SOCKS error code. BND.ADDR/PORT in the SOCKS reply is
therefore `0.0.0.0:0` (unknown) — the ACK still carries the real bound address and is
validated. The address is always `0x01` IPv4 or `0x04` IPv6 (the server's dialed
local socket, never a domain), so the ACK is 8 B (IPv4) or 20 B (IPv6) in total.

### UDP datagram (each QUIC DATAGRAM)

```
type=0x02 u8 | sess u32 LE | atyp u8 | addr bytes | port u16 BE | payload
```

`sess` scopes the packet to one UDP ASSOCIATE; the server echoes it back on replies
so the client dispatcher can route without any per-target state lookup. The client
sizes each datagram against the connection's live `max_datagram_size()` (PMTU-aware,
never above 1350 B); the server caps replies the same way.

### Connection authentication (`auth_token` non-empty)

```
client → server : uni stream (stream type 0x02) carrying the token bytes, FIN
server          : waits ≤ 5 s, reads ≤ 256 B, constant-time compare
mismatch        : CONNECTION_CLOSE 0x01 "unauthorized"
```

- The server reads the token **before** accepting any bidi stream or DATAGRAM, so an
  unauthenticated peer cannot dial anything.
- No ACK exists: a wrong token surfaces as a closed connection. The client keeps
  backing off and logs the close reason.
- **0-RTT**: the token is written into early data like any other stream. If the
  server rejects early data (e.g. its session store restart), QUIC discards it with
  the rest of 0-RTT; the client observes `accepted=false` and re-sends the token on
  the established connection within one RTT — no auth timeout, no extra handshake.
- Token length is capped at 256 B; empty on both sides disables the feature.

### Versioning

ALPN is **`myquic2/2`**. It was bumped from `myquic2/1` when the TCP-open ACK gained
the bound address: a version-skewed pair now fails the TLS handshake with a clear
error instead of misparsing the ACK as application data, so **upgrade both sides
together**. The UDP DATAGRAM layout and the auth uni stream are unchanged from MQP-1.

### Design rationale

- TCP gets reliable streams (ordering + retransmission + flow control for free —
  never reimplement reliability on top).
- UDP gets DATAGRAMs (loss is semantic, not a bug).
- No serde/JSON/protobuf on the hot path: hand-rolled codec with a borrowed form
  (`TargetAddrRef`) so domain-typed packets do not allocate, `bytes::Bytes`
  forwarding, allocation-free DNS cache hits, and 32 KB pump buffers per TCP
  direction; DNS results cached 60 s.
- Per-flow work allocates once, not four times: the MQP-2 header is decoded out of a
  259-byte stack buffer, the IP-literal dial path borrows the decoded address instead
  of building a one-element `Vec`, and the DATAGRAM send wrapper drops on a full send
  buffer rather than using quinn's drop-oldest path (see pass 5 below).

---

## Security Model

**Server authenticity (always on).** The client pins the server's self-signed
Ed25519 certificate. This proves the client reached the genuine server.

**Client authenticity (optional, recommended).** TLS client auth is intentionally
absent (`with_no_client_auth`), so without `auth_token` the server is an *open
relay*: anyone who can reach the port can proxy TCP/UDP through it. A non-empty
`auth_token` (shared secret, constant-time compared, sent inside the QUIC-encrypted
uni stream) is the client-side gate. Keep the port firewalled as well.

**Egress policy.** With `allow_private = false`, resolved targets are filtered
against private/loopback/link-local/CGNAT/documentation/benchmark/multicast ranges;
NAT64 (`64:ff9b::/96`) and deprecated IPv4-compatible addresses are validated via
their embedded IPv4, so they cannot be used to reach private space. The sample
config sets `true` for LAN testing — turn it off on public exit nodes.

**Replay.** 0-RTT early data is theoretically replayable; rustls's stateful,
single-use session tickets bound it. The worst case is a duplicated outbound dial or
UDP datagram (no traffic amplification). TCP application bytes ride the 1-RTT keys
established by the handshake, so replay cannot duplicate an application request;
only the auth token in early data is exposed to the theoretical replay window.

**Denial-of-service bounds.** See [Resource Limits & Tuning](#resource-limits--tuning):
connection/session caps, process-wide TCP dial and per-connection stream limits, DNS
slow-path limiter, bounded detached UDP sends, and a single 5 s deadline for
unauthenticated connections (auth stream accept + token read share one budget).

**What is *not* protected.** SOCKS5 ingress is no-auth (RFC 1929 is intentionally not
implemented). The UDP relay accepts datagrams only from the SOCKS control
connection's source IP, but not its port (RFC 1928 clients legitimately use a
different socket), so a process on the same host can still race for the relay —
run it on a trusted host / bind `socks_listen` to localhost when exposing UDP.
UDP replies are not further source-validated (roadmap item).

---

## Verification & E2E Tests

Run on the 2026-09 revision (latest pass), macOS (Apple Silicon), `cargo build
--release`, with local TCP/UDP echo servers and a raw Python SOCKS5 client. All
payloads are verified byte-for-byte; UDP checks the echoed payload and the reply's
source address.

| # | Test | Result |
|---|---|---|
| 1 | `cargo test` (codec round-trips, borrowed-datagram round-trip, DNS key normalization/injectivity, `is_global_ip` filter, DATAGRAM send-buffer saturation, MQP/SOCKS header length + framing) | ✅ 16/16 |
| 2 | TCP ECHO via SOCKS5 `CONNECT` (1 MiB random) | ✅ repeated runs |
| 3 | UDP ECHO via `UDP ASSOCIATE` (25 × 1000 B) | ✅ repeated runs, BND = relay address |
| 4 | Server `kill -9` → restart → reconnect → TCP+UDP ECHO | ✅ detects in ~15 s (idle timeout; 20 s watchdog backstop), redial < 0.4 s, kill→usable 17.5 s; a UDP association opened *before* the kill and one opened *during* the outage both self-heal |
| 5 | Optimistic CONNECT: SOCKS success returns without waiting for the remote dial | ✅ blackhole target → reply in 0.1 ms (was ~4 s waiting for the dial ACK); a failed dial closes the flow |
| 6 | 0-RTT probe with token, same server process | ✅ `accepted=true`, bound address parsed, echo over 0-RTT |
| 7 | Empty token on both sides (auth disabled) | ✅ TCP+UDP ECHO |
| 8 | Wrong token | ✅ server logs `auth token mismatch`, client sees SOCKS `0x04`, backoff grows 200 ms→5 s (no redial storm) |
| 9 | 20 concurrent TCP (256 KiB) + 8 concurrent UDP associations | ✅ 28/28, ~1.7 s wall clock |

Additional checks run on the pass-5 revision (macOS, loopback):

| # | Test | Result |
|---|---|---|
| 10 | DATAGRAM send-buffer saturation (`try_send_datagram_saturates_without_panicking`) | ✅ passes; the same test **aborts** when the send path is switched back to `Connection::send_datagram` (verified) |
| 11 | `read_mqp_target` framing: IPv4 / IPv6 / domain byte accounting, empty-domain and unknown-atyp rejection | ✅ 3/3 |
| 12 | SOCKS5 address reader: IPv4 / IPv6 / domain decode, bad-atyp, lenient variant | ✅ 3/3 |
| 13 | Domain-target `CONNECT` end-to-end (server-side DNS, `localhost`) | ✅ 5/5 transfers, no `bad connect target` |
| 14 | UDP at 20–25k datagrams/s, windowed round trip | ✅ 0.00% loss, RTT p50 0.11–0.13 ms |
| 15 | 128-datagram bursts ×300 | ✅ 100% replied, burst completion p50 1.8 ms |

0-RTT probe (expect the last four lines):

```sh
cargo run --release --example zero_rtt_probe -- 127.0.0.1:8443 test.com <auth_token>
# conn1: full handshake ok
# conn2: client HAD resumption tickets, 0-RTT offered
# conn2: server bound address 127.0.0.1:53619
# conn2: 0-RTT echo ok: "zero-rtt-echo"
# conn2: server accepted 0-RTT early data = true
```

Representative reconnect trace (client log after `kill -9` of the server):

```
07:26:37 kill server
07:26:52.870 WARN QUIC connection lost, reconnecting...   (idle timeout; watchdog backs it up at 20 s)
07:26:52.871 WARN QUIC close reason: timed out
07:26:53.174 INFO QUIC connected to 127.0.0.1:8443         (server restarted at :40)
07:26:53.175 DEBUG QUIC resumption: 0-RTT keys accepted=false  (stale ticket)
07:26:53.176 server INFO new QUIC conn                     (token re-sent, auth passed)
07:26:55     TCP echo OK / UDP echo OK
```

The E2E harness is intentionally not vendored; it is a plain Python SOCKS5 client
(`CONNECT` + `UDP ASSOCIATE`) plus `asyncio` TCP/UDP echo servers on ports 18081/18082.

---

## Requirements

- **Rust** 1.88+ (MSRV driven by `time 0.3.55` / `rcgen 0.14.10`; developed and
  tested on stable 1.97.1; deps: quinn 0.11.11 / quinn-proto 0.11.17, rustls
  0.23.44, tokio 1.53.1)
- **Linux** (production; GSO/GRO + BBR fully effective) or **macOS** (development;
  dual-stack verified, GSO degrades gracefully)
- For OpenWrt cross builds: `zig` + `cargo-zigbuild` (see [Building](#building))

---

## Building

```sh
# native release
cargo build --release
# binaries: ./target/release/myquic2-server ./target/release/myquic2-client

# tests + lints
cargo test
cargo clippy --all-targets
```

### Cross-compile for OpenWrt x86-64 (static musl, from macOS)

```sh
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild   # needs `zig` on PATH
```

Build one CPU level at a time (sequentially — each flag set invalidates codegen) and
copy each result into `dist/` before the next level overwrites it:

```sh
# v1 = any x86-64 (J4125/N100 safe default); v2 = SSE4.2; v3 = AVX2; v4 = AVX512
set -e
for v in x86-64 x86-64-v2 x86-64-v3 x86-64-v4; do
  case $v in x86-64) n=v1;; x86-64-v2) n=v2;; x86-64-v3) n=v3;; x86-64-v4) n=v4;; esac
  cargo zigbuild --release --target x86_64-unknown-linux-musl \
    --config 'profile.release.strip="symbols"' \
    --config "target.x86_64-unknown-linux-musl.rustflags=[\"-C\", \"target-cpu=$v\"]" \
    --bin myquic2-server --bin myquic2-client
  cp target/x86_64-unknown-linux-musl/release/myquic2-server dist/openwrt-x86_64/myquic2-server-$n
  cp target/x86_64-unknown-linux-musl/release/myquic2-client dist/openwrt-x86_64/myquic2-client-$n
  echo "built $n"
done
```

> ⚠️ Pick the level your CPU actually supports (`grep avx512 /proc/cpuinfo` for v4).
> A v4 binary on a non-AVX512 CPU dies with `illegal instruction`. When in doubt,
> ship **v1**.

Prebuilt artifacts live in [`dist/openwrt-x86_64/`](dist/openwrt-x86_64/)
(`*-v1` … `*-v4` for both binaries, plus sample configs). The shipped binaries were
rebuilt from the pass-5 revision: static musl, x86-64, stripped, ~4.1–4.2 MB each.
They contain the DATAGRAM process-abort fix, so binaries built before pass 5 must be
replaced on **both** sides of a deployment.

---

## Configuration

TOML files, CLI flags override via `--config <path>` (defaults:
`config-server.toml` / `config-client.toml` in the working directory).

### Server (`config-server.toml`)

```toml
listen = "[::]:8443"          # QUIC ingress (dual-stack wildcard recommended)
cert_file = "server-cert.pem" # cert+key auto-generated on first run only when BOTH are absent
key_file = "server-key.pem"   # Ed25519; a lone missing half is a hard error (never overwritten)
server_name = "test.com"      # SAN for the self-signed cert + expected SNI
congestion = "bbr"            # bbr | cubic (unknown values warn and fall back to bbr)
gso = true                    # informational: quinn-udp auto-probes GSO/GRO
keep_alive_secs = 5           # clamped to 1..3600; idle timeout = max(3x, 15s)
allow_private = true          # dial RFC1918/loopback targets; default is false!
auth_token = ""                # shared secret ≤ 256 B; empty = disabled (firewall only).
                               # Set a private random value here and on the client.
```

### Client (`config-client.toml`)

```toml
socks_listen = "[::]:1080"    # SOCKS5 ingress (dual-stack)
server_addr = "127.0.0.1:8443"     # QUIC server (IP or hostname; re-resolved every redial)
server_name = "test.com"           # SNI; MUST match the cert SAN
server_cert_file = "server-cert.pem"  # pinned server cert (copied out-of-band)
congestion = "bbr"
gso = true
keep_alive_secs = 5           # clamped to 1..3600; idle = max(3x,15s), watchdog = max(4x,20s)
reconnect_timeout_secs = 5    # new flows wait this long for a QUIC connection
auth_token = ""                     # must match the server (empty on both = disabled)
```

Field notes:

- `allow_private` defaults to **false** in code; the sample config sets `true` for
  local testing. Disable it for any public exit node.
- `auth_token` empty on both sides = no authentication. Non-empty on the server but
  empty/wrong on the client = connection closes with `unauthorized` and the client
  retries with growing backoff.
- `reconnect_timeout_secs` only bounds how long a *new SOCKS flow* waits for a live
  QUIC connection; it does not control redial backoff.
- Paths are resolved against the process CWD — use absolute paths on OpenWrt.

---

## Running

```sh
# 1. server first (generates server-cert.pem/key on first run)
./myquic2-server --config config-server.toml

# 2. copy server-cert.pem (ONLY the cert, never the key) to the client machine

# 3. client (loads + pins the cert, fails fast if missing)
./myquic2-client --config config-client.toml

# 4. use it
curl --socks5 127.0.0.1:1080 http://example.com
```

Background: `nohup ./myquic2-server --config config-server.toml > server.log 2>&1 &`

Logging honours `RUST_LOG`, e.g. `RUST_LOG=myquic2_client=debug,myquic2_server=debug`;
the default filter is `info`.

---

## Certificates & Authentication

- **Server identity**: the client pins the server's self-signed **Ed25519**
  certificate (`server_cert_file`, 444 bytes). The `ring` provider picks the
  AEAD suite (TLS13_AES_256_GCM_SHA384 observed in the probe logs on both
  x86-64 and Apple Silicon; ChaCha20-Poly1305 elsewhere), both hardware
  accelerated. This proves the client is
  talking to the genuine server — it does **not** authenticate clients.
- **Client identity (`auth_token`)**: the server has no client certs, so a
  non-empty `auth_token` is required to keep it from being an open relay. The
  client opens a one-way uni stream immediately after the handshake and writes
  the shared secret; the server refuses all streams and datagrams until it
  matches, then closes unauthorized connections. Set the same value in both
  configs. Empty token = feature disabled → only expose the port behind a
  firewall. On 0-RTT rejection the client re-sends the token automatically.
- **Server** auto-generates the cert on first run: SAN = `server_name`,
  validity **500 years backdated 7 days**. The backdating is deliberate: routers
  without a battery clock (NTP not yet synced at boot) would otherwise fail with
  `certificate not valid yet`.
- **Client** only loads and pins (`server_cert_file`). Missing file = startup error
  (it must never self-generate — a self-generated cert would never match the server).
- **Rotation rule**: any regeneration changes the key → all deployed clients need the
  new `server-cert.pem`. Compare fingerprints when in doubt:
  `openssl x509 -in server-cert.pem -noout -fingerprint -sha256` (must match exactly
  on both sides).
- **0-RTT replay note**: early data can theoretically replay; worst case is a
  duplicated outbound dial (no amplification). Tickets live in memory on both ends —
  either side restarting falls back to a 1-RTT full handshake automatically, and the
  client re-authenticates in that case.

---

## Resource Limits & Tuning

All limits are constants in the sources; the table shows where to change them.

| Resource | Limit | Where |
|---|---|---|
| Concurrent QUIC connections (server) | 4096 (new `Incoming` refused) | `MAX_CONNECTIONS` |
| Concurrent *unauthenticated* connections | 256 (pre-auth slot, released after token check) | `MAX_UNAUTH_CONNECTIONS` |
| TLS session store (server, 0-RTT/resumption) | 8192 sessions | `server_tls_config` |
| UDP sessions, process-wide | 8192 permits (fail closed) | `MAX_SESSIONS_GLOBAL` |
| UDP session socket buffers | 512 KB send + 512 KB receive per session | `udp_socket_dual_small` |
| UDP sessions per connection | 4096 (O(n) sweep above) | `LOCAL_SESS_MAX` |
| Concurrent TCP dials, process-wide | 4096, 2 s permit wait (released after connect) | `dial_limiter` |
| Concurrent bidi streams per connection | 1024 | `build_transport` |
| Concurrent TCP stream tasks (server, process-wide) | 16384 (excess streams reset) | `MAX_STREAM_TASKS` |
| Client SOCKS connections | 8192 (excess connections dropped) | `socks_conn_limiter` |
| Client UDP associations | 4096 (excess replies REP=0x01, 256-datagram queue each) | `UdpHub::alloc_sess` |
| DNS slow-path lookups (TCP + UDP) | 1024, 5 s each, single-flight | `dns_slow_path_limiter` |
| Deferred UDP sends (fresh-socket / full buffer) | 4096 | `udp_send_limiter` |
| Receive window (aggregate) | 8 MB/connection | `build_transport` |
| Receive window (per stream) | 2 MB | `build_transport` |
| Send window | 4 MB/connection | `build_transport` |
| DATAGRAM buffers | 1 MB each direction | `build_transport` |
| Keepalive / idle / watchdog | clamp 1–3600 s; idle `max(3×,15 s)`; watchdog `max(4×,20 s)` | `build_transport`, client |
| Server auth wait | 5 s per connection (one deadline for accept+read) | `authenticate()` |
| TCP stream idle reap | 300 s | `copy_tcp_quic_idle` call sites |
| UDP association idle reap | 180 s (both directions; TCP control activity counts) | server sweeper / client interval |
| DNS cache | 60 s positive (4096+512 slack), 10 s negative (4096) | `DNS_CACHE_*`, `DNS_NEG_MAX` |
| Client TCP dial ACK budget | 20 s (5 s header + 3 s DNS permit + 5 s DNS + 2 s dial permit + 4 s connect + margin) | `TCP_DIAL_ACK_TIMEOUT` |

Kernel-side tuning: raise `net.core.wmem_max` / `net.core.rmem_max` so the 4 MB
(QUIC socket) and 512 KB (per-session) socket buffers are not silently clamped; the
first clamp logs one warning per
process (per-socket warnings were removed because session churn flooded the log).

---

## SOCKS5 Compliance

Against RFC 1928 / RFC 1929:

| Item | Status |
|---|---|
| Handshake, no-auth (`0x00`) | ✅ |
| `CONNECT`, IPv4/domain/IPv6 | ✅ (curl-verified) |
| BND.ADDR/BND.PORT for `CONNECT` | ⚠️ `0.0.0.0:0` (unknown): the success reply is sent before the remote dial completes to avoid an extra RTT; the MQP-2 ACK still carries the real bound address and is validated |
| `UDP ASSOCIATE` + relay + TCP control held | ✅ (`FRAG≠0` dropped, as most implementations do) |
| BND.ADDR for `UDP ASSOCIATE` | ✅ the proxy's own interface address + relay port (LAN clients work; no longer the app's own address) |
| Username/password (`0x02`) | ❌ intentionally absent |
| `BIND` | ❌ replies `0x07` (FTP active mode; obsolete in practice) |
| Error REPs (`0x01/0x04/0x05`…) | ⚠️ success is replied optimistically; a failed remote dial closes the TCP flow (the app reconnects) instead of returning `0x04`. A missing QUIC connection still fails the flow fast |
| UDP source validation | ⚠️ relay learns the app address from the first packet; fine behind NAT/home use, tighten before public exposure |
| Association lifetime | ⚠️ idle UDP associations are reaped after 180 s to bound sockets/tasks (RFC has no fixed lifetime) |

---

## Reconnect & High-RTT Behavior

- **Idle**: keepalive every `keep_alive_secs` (default 5 s) vs idle timeout
  `max(3×keepalive, 15 s)` — the connection lives indefinitely while both processes
  run (verified: 45 s idle, zero new handshakes, traffic flows instantly after).
- **Dirty network (< 15 s outage)**: QUIC retransmission + BBR absorb it; streams
  stall then resume, **no new handshake**.
- **IP change (NAT rebinding, WiFi→cellular)**: QUIC connection migration keeps the
  *same* connection alive without a handshake.
- **Long outage / server restart**: ~15–20 s silent-path detection (15 s QUIC idle
  timeout, backed up by a `max(4×keepalive, 20 s)` no-inbound-traffic watchdog) →
  exponential redial (200 ms → 5 s, jittered). The backoff only decays after 5 s of
  stable connectivity, so a misconfigured peer (e.g. wrong token) cannot cause a
  redial storm. A stale 0-RTT ticket is rejected once and the token is re-sent on the
  established connection (verified: server `kill -9` → reconnect → TCP+UDP ECHO pass).
- **A dial is not accepted until the connection is proven alive** (pass 7). quinn's
  `Connecting` future resolves `Ok` even for a connection that terminated instead of
  handshaking: the `on_connected` oneshot it awaits carries the 0-RTT accept flag, but
  `Connecting::poll` discards that flag and always yields `Ok(Connection)`, while
  `ConnectionInner::terminate` fires the same oneshot (with `false`) for *every*
  connection that ends — including one that never established. The reconnect loop used
  to publish that dead handle to `shared` and log `QUIC connected` for it, so every new
  SOCKS flow in the meantime was handed a dead connection until quinn's idle timeout
  fired (~15 s). `dial_once` now treats a refused/short 0-RTT handshake as a failed
  dial, verifies `close_reason()` after one yield, and bounds each attempt with
  `DIAL_ATTEMPT_TIMEOUT` (5 s) instead of QUIC's ~15 s Initial-retransmission budget —
  so the first attempt after a restart succeeds instead of waiting out the previous
  one's timeout. Measured: server `kill -9` → detection ≈ 20 s → reconnect ≈ 0.3–0.4 s
  after the server is back (before: a false `connected` every ~15 s plus 15.6 s
  recovery).

- **After reconnect**: UDP sessions self-heal (the server recreates `sess_id` state on
  the next packet); old TCP streams reset fast so apps reconnect instead of hanging.
- **140 ms links**: tuned for trans-Pacific BDP — 2 MB per-stream / 8 MB aggregate
  receive window, 4 MB send window, BBR; the SOCKS success reply is sent
  optimistically (no 1-RTT wait for the remote dial), so the application's TLS
  handshake overlaps the server-side dial; server-side DNS avoids geo-misresolved IPs.

---

## OpenWrt Deployment

```sh
scp dist/openwrt-x86_64/myquic2-server-v1 dist/openwrt-x86_64/myquic2-client-v1 root@openwrt:/usr/bin/
# rename on target as you like, chmod +x, absolute paths in the tomls!
```

Checklist from real field issues:

1. **Absolute paths** in `server_cert_file`/`cert_file` (relative paths resolve
   against CWD — the classic `os error 2`).
2. **Correct binary**: the client build for SOCKS ingress; don't mix up the two.
3. **Cert first**: start server → copy `server-cert.pem` → start client.
4. **Token**: set the same `auth_token` in both configs (or leave empty on both and
   firewall the port); a mismatch shows up as `unauthorized` close loops.
5. **Clock**: ensure NTP is up (`date` sane) — belt-and-braces alongside the
   7-day backdating.
6. `server_addr` = server's **public** IP on the client; `server_name` unchanged
   (SNI/cert check only, needs no DNS).
7. **CPU level**: v1 is safe everywhere; v2+/v4 need the matching CPU features
   (`grep avx512 /proc/cpuinfo`).

---

## Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `os error 2` at client startup | Relative `server_cert_file` vs CWD → absolute path |
| `UnknownIssuer` | Client cert ≠ server cert (stale copy after regen) → compare fingerprints, re-copy |
| `certificate not valid yet (N seconds in future)` | Router clock behind (no RTC/NTP) → sync NTP; backdating covers ±7 days |
| `closed by peer: unauthorized (code 1)` in client log | `auth_token` missing or mismatched → set the same value on both sides |
| `auth_token is empty: the QUIC endpoint accepts any peer` on server start | Intentional if firewalled; otherwise set a token |
| `auth_token is a placeholder from the sample config` | Set a private shared secret (or an empty token with firewall isolation) |
| `cert/key pair incomplete: cert_file … and key_file …` at server start | Only one of the pair exists → restore the missing file, or delete both to regenerate; the surviving file is never overwritten |
| Handshake fails between two installs (`no application protocol`) | Mixed MQP-1/MQP-2 binaries (ALPN `myquic2/2`) → upgrade both sides together |
| One extra reconnect right after server restart | Stale session ticket → 0-RTT rejected; the client re-auths automatically. Expected once |
| New TCP hangs after server restart | Old stream on dead QUIC conn → fail-fast RST is by design; app reconnects, new flows work immediately |
| UDP fails for LAN/remote SOCKS clients | Fixed in this revision (BND.ADDR is the proxy address); upgrade both binaries |
| UDP loss under load | Check loss% first: sustained overload is QUIC DATAGRAM backpressure (UDP semantics — app should retransmit) |
| `udp send buffer clamped to ...` warning | Raise `net.core.wmem_max`/`rmem_max`; the effective value is printed |
| Client cannot connect at all after a token change | The token travels inside QUIC, not TLS: no cert re-copy needed, only the config |

---

## Project Layout

```
MyQUIC2/
├── Cargo.toml / Cargo.lock
├── src/
│   ├── lib.rs                 # MQP-2 codec (owned+borrowed), config, TLS, transport, bridge, DNS cache
│   └── bin/
│       ├── myquic2-server.rs  # QUIC ingress + token auth + dial-out + session caps
│       └── myquic2-client.rs  # SOCKS5 ingress + token auth + reconnect + UDP dispatcher
├── examples/
│   ├── zero_rtt_probe.rs      # 0-RTT end-to-end verification probe (token-aware)
│   └── hotpath_bench.rs       # hot-path benchmark harness (owns its own targets)
├── config-server.toml / config-client.toml
└── dist/openwrt-x86_64/       # static musl release bins (v1–v4) + sample configs
```

---

## Hardening Notes (this revision)

- Optional `auth_token` connection authentication, constant-time compare, enforced
  before any stream/DATAGRAM is accepted; 0-RTT-safe re-send on early-data rejection.
- Server accept/handshake runs in per-connection tasks (no slowloris serialization);
  process-wide connection cap; `accept() == None` now exits with an error instead of
  spinning.
- Explicit 32 MB aggregate receive window (quinn’s default is effectively unlimited)
  plus per-connection stream/session/dial caps. *(Superseded in pass 3: the
  aggregate receive window is now 8 MB.)*
- UDP session liveness now counts inbound replies (long one-way downloads are not
  reaped); session/DNS eviction is O(n) with bounded lock hold time.
- `UDP ASSOCIATE` BND.ADDR is the proxy’s own address (LAN clients work).
- Client DATAGRAMs respect the live PMTU; `udp_try_send()` never stalls a shared
  reader and never drops the first packet of a fresh socket.
- DNS: atomic single-flight ownership with cancellation recovery, allocation-free
  cache hits, borrowed-domain datagram decoding, negative caching.
- Reconnect: auth re-send after 0-RTT rejection, jittered exponential backoff that
  decays only after stable connectivity, `RUST_LOG` support.
- SSRF filter validates NAT64 and IPv4-compatible embedded IPv4; extra
  documentation/benchmark prefixes rejected.
- QUIC socket no longer sets `SO_REUSEADDR`; UDP buffer clamping is reported;
  redundant warnings removed; dead code dropped; `dist/` rebuilt.

### 2026-09 hardening pass 2

- DNS single-flight waiters now reclaim ownership when the owner is cancelled, so
  `resolve_all_cached` can no longer hang forever; only the owner warms the
  positive/negative cache (ending N-writer stampedes), and a duplicate-lookup race
  window is closed by re-checking the cache before claiming ownership.
- 0-RTT is only exposed to application flows after the server accepts early data:
  quinn discards streams/DATAGRAMs sent in rejected early data, so the client now
  waits for the accept/reject decision (the token still rides early data) and
  re-sends auth on 1-RTT rejection. This removes lost SOCKS flows and stale stream
  handles after a server restart.
- `copy_tcp_quic_idle` cancels the peer direction as soon as one side fails, so a
  dead QUIC connection releases target TCP fds immediately instead of waiting out
  the 300 s idle window; the old `join!` could pin a silent stream for minutes.
- `allow_private` also validates the RFC 2765 IPv4-translated prefix
  (`::ffff:0:a.b.c.d`) and additional IANA non-global ranges (AS112, AMT, PCP/TURN
  anycast, DRIP, SRv6, `2001:4:112::/48`, `2620:4f:8000::/48`).
- Client UDP dispatcher table is sharded (32 locks) with an exact process-wide cap;
  the DNS hot-path memo compares full keys instead of a 64-bit hash, and negative
  entries short-circuit the per-packet resolver spawn.
- Server: extra uni streams are drained/stopped (no unbounded receive buffering), a
  global stream-task cap bounds header/DNS/dial queueing, the handshake has its own
  timeout, and session creation checks the global permit before creating a socket
  and never inserts a dead reply reader.
- SOCKS control writes are bounded by a 10 s timeout; the UDP-associate control drain
  is bounded per readiness event so a flooding local app cannot starve the relay.
- `dist/openwrt-x86_64/` rebuilt from this revision for all four CPU levels
  (v1–v4, static musl, stripped).

### 2026-09 hardening pass 3

- **Memory amplification bounds.** Per-connection transport windows lowered
  (aggregate receive 32→8 MB, DATAGRAM 4→1 MB), per-session socket buffers
  1→0.5 MB, global UDP session cap 16384→8192, and a 256-connection pre-auth cap
  (`MAX_UNAUTH_CONNECTIONS`): an unauthenticated peer can no longer pin the whole
  4096-connection receive budget.
- **0-RTT at scale.** rustls' default server session store holds only 256
  sessions; it is now sized to 8192, so resumption no longer silently degrades to
  a full handshake under load.
- **Hot-path costs removed.** The server UDP reply reader uses one 60 s periodic
  tick instead of a fresh timeout per `recv_from`; the client relay caches
  `(connection, PMTU limit)` for ≤1 s instead of calling
  `close_reason()`/`max_datagram_size()` (both take quinn's connection-state
  mutex) per datagram; server→target datagrams reuse the received `Bytes` slice
  instead of copying the payload.
- **`send_datagram` semantics corrected.** quinn silently drops the oldest queued
  datagram when its buffer is full (it never returns `Blocked`), so error
  handling now keys on `TooLarge` / `ConnectionLost` / `UnsupportedByPeer` /
  `Disabled` and comments match reality.
- **MQP-2.** The TCP-open ACK carries the server's dialed bound address and ALPN is
  bumped to `myquic2/2`, so version-skewed peers fail closed at the handshake instead
  of misparsing the ACK. *(Superseded in pass 4: the SOCKS reply is now optimistic and
  BND.ADDR for `CONNECT` is `0.0.0.0:0`.)*
- **Misc.** SOCKS5 RSV fields validated on requests and UDP headers; token
  comparison no longer leaks length; DNS cache values are `Arc<[SocketAddr]>`
  (O(1) cache-hit clones); the server header reader no longer stacks a second
  timeout per field; cert/key pairs are never partially regenerated (a missing
  half is a hard error); samples ship an empty token with a startup warning for
  placeholder secrets; `cargo fmt` clean.

### 2026-09 hardening pass 4

- **Latency parity with juicity/Hysteria-class clients.** The SOCKS success reply
  is no longer gated on the MQP-2 dial ACK: the client answers immediately after
  writing the target header and consumes the ACK on the reply direction. That
  removes one client↔server RTT from every TCP connection (verified: a blackhole
  target gets its SOCKS success in 0.1 ms instead of waiting out the ~4 s dial
  budget). A failed dial now closes the TCP flow; BND.ADDR for `CONNECT` is
  `0.0.0.0:0` because the reply precedes the dial result.

### 2026-09 hardening pass 5

- **Removed a process-abort reachable from normal network conditions.** quinn-proto
  0.11.17 corrupts its own DATAGRAM bookkeeping: when the path MTU shrinks,
  `Connection::drop_oversized` decrements `datagrams.outgoing.payload_bytes` for
  datagrams that `DatagramState::write` had already accounted for via `pop_front`, so
  a payload re-queued by the packet builder is subtracted twice. The counter underflows
  to `usize::MAX`, `memory_used()` then looks astronomical while the queue is empty,
  and the next `Connection::send_datagram` panics on
  `.expect("datagrams.outgoing.payload_bytes desynchronized")` — *while holding quinn's
  connection-state mutex*, which poisons it and aborts the whole process. Because both
  UDP paths used `send_datagram`, an MTU reduction on either side could kill the proxy.
  The new `try_send_datagram()` helper polls `send_datagram_wait` once with a no-op
  waker instead (non-blocking, drop-on-full, and it never touches the drop-oldest
  path; the pending future is dropped immediately, so nothing can leak) and reports
  `Sent` / `Blocked` / `TooLarge` / `Unsupported` / `ConnectionLost` explicitly, so the
  server refreshes its cached PMTU on `TooLarge` and the client invalidates its cached
  egress handle exactly as before. Its correctness also depends on the send buffer
  holding at least one maximum-size datagram, which `build_transport` now asserts at
  compile time. Reproduced on loopback (1200 B payload, peer `max_datagram_size` shrunk
  to 1162 B) and now covered by a live saturation test that aborts on the old path and
  passes on the new one.
- **Per-flow allocation removed from the TCP-open path.** `read_mqp_target` decodes the
  header out of one 259-byte stack buffer instead of three `Vec`s plus the owned
  domain `String` (a domain target went from four heap allocations to one); the dial's
  candidate list is filtered into a fixed array, so an IP-literal target — the dominant
  case — allocates nothing, and the domain case resolves into a stack array rather than
  a `Vec`. `dial_happy_eyeballs` now takes `&[SocketAddr]`, keeping its single-candidate
  fast path and its abort-on-cancel semantics (a plain handle list replaces `JoinSet`).
  The MQP-2 header length is a pure function (`mqp_hdr_len`) with unit tests for every
  wire form; the SOCKS5 reader keeps its proven shape and gained framing tests instead
  (see the next bullet).
- **Measured and rejected: batching the DATAGRAM readers.** A drain loop that polled
  `read_datagram` up to 32 times per wakeup was implemented, instrumented and reverted.
  Instrumentation showed an average batch of **1.06** datagrams (the reader is faster
  than the inbound queue, so batching never triggers), and an A/B run showed no
  difference in CPU, latency or throughput — the per-datagram cost is inside quinn's
  packet processing, not in our lock or waker handling. It is not shipped.
- **Measured and rejected: a client-side stack-buffer rewrite of the SOCKS5 reader.**
  It reproducibly lost the last byte of a domain target on macOS (`bad connect target`
  on every domain `CONNECT`, 0/5 transfers, twice, versus 5/5 with the original
  two-`read_exact` shape), so the reader keeps its proven shape with a note explaining
  why. The per-flow `Vec`s it would have saved never appeared in a profile.
- **Where the time actually goes.** On loopback a single QUIC connection saturates at
  roughly 2 Gbit/s and adding connections does not raise it; `/usr/bin/sample` shows
  10–45% of non-idle CPU in quinn's per-operation connection-state mutex (every
  `read`/`write`/`send_datagram` takes it, and the protocol driver needs it too).
  Application codec work measures 1.9 ns per address decode and ~49 ns per datagram
  encode, i.e. noise. Copy-buffer size (16 KB–256 KB) made no measurable difference
  because quinn's `read` already fills a whole buffer under one lock acquisition.
  Treat ~2 Gbit/s per connection as the library ceiling of this revision, not a
  tuning failure — a 1 Gbit/s WAN link is well inside it.
- **Rebuilt release binaries.** `dist/openwrt-x86_64/` was rebuilt from this revision
  for all four CPU levels (v1–v4: static musl, x86-64, stripped, ~4.1–4.2 MB each).
  The previous binaries predate the DATAGRAM abort fix, so **re-copy them to the
  router**; the fix is server- and client-side.

### 2026-09 hardening pass 6 — per-packet work audit

A line-by-line audit of the packet paths, followed by A/B measurement against the
previous revision on the same loopback host.

**Removed from the per-packet / per-flow path**

- **One allocation per DATAGRAM, built in one pass.** `encode_datagram*` validated the
  address *while* appending it, so the buffer could not be sized first: it started at
  40 bytes and grew once the payload was appended, copying the payload a second time.
  A new `TargetAddrRef::header()` validates and measures the address up front (still the
  same rules, still one definition of the wire format), so the buffer is `with_capacity`ed
  to the exact final size and filled in a single pass. A test pins the encoder's output
  byte-for-byte against the old two-step form for every address type.
- **The UDP reply path no longer copies the payload twice.** `send_reply` took a
  `&[u8]` and `udp_try_send` took a borrowed slice, so every reply that hit the socket's
  slow path did `payload.to_vec()` — a fresh allocation *and* a copy of data that already
  sat in an owned, refcounted `Bytes`. `udp_try_send` now takes `Bytes` and *moves* it
  into the queued write (unwrapping to its `Vec` first when it is unshared, so the common
  case is zero-copy); the reply path passes a `Bytes::slice` of the received datagram,
  which is a refcount bump. The per-reply `Vec` scratch buffer became a persistent
  `BytesMut` sized to the datagram.
- **A lock-free session lookup on the server's datagram path.** Every inbound datagram
  took the connection's session-table read lock and did a hash lookup — but a UDP flow
  sends long runs of packets to *one* session. A thread-local single-slot memo now
  answers the common case with one atomic load and no lock, and the reply reader clears
  its liveness flag as it exits so a dead session still falls through and is recreated.
- **The session sweeper no longer aborts readers while holding the write lock.** Removed
  entries are returned to the caller and aborted after the guard drops, and the key
  vectors it allocated under the lock are gone.
- **DNS: a lock-free hit, no per-packet clock, cheaper eviction.** The thread-local memo
  grew from one slot to two (positive and negative), so an interleaved stream of good and
  bad names no longer evicts the other class on every packet. A memo lookup no longer
  reads the clock before it knows the key matches, and the positive+negative cache probe
  now shares a single clock read. Eviction (`evict_if_needed`) no longer runs an O(n)
  `min_by_key` scan — or a full collect+sort — *under the write lock* on every insert past
  the cap: it evicts the whole overflow in one batch using `select_nth_unstable`.
- **One receive future per connection, not per datagram.** `read_datagram()` was rebuilt
  inside the loop on both sides, re-registering its `Notify` and re-taking the connection
  lock for every packet. It is now constructed once per connection and pinned
  (`read_datagram` is cancel-safe: a buffered datagram is returned before the first await
  point). The client's dispatcher additionally caches the last session's `Sender`, so a
  burst to one association skips the shard lock and the refcount bump.
- **Per-chunk work in the TCP↔QUIC pump.** The two 32 KB buffers were heap-allocated (and
  freed) per stream direction; they now come from a small per-thread pool with a
  bounded depth, so a steady stream of flows reuses the same memory. The throttled
  liveness stamp no longer did what it claimed — the non-multiple-of-8 branch still read
  the clock *and* reloaded the atomic on every chunk — and is now one local comparison
  plus (at most) one shared store per 100 ms.
- **Smaller fixed costs.** The UDP replies-to-app loop dropped a per-packet atomic reload
  (local shadow of the liveness stamp); the server's per-stream `Vec` for the 20-byte
  MQP-2 ACK became a stack buffer (`encode_bnd_addr_into`); per-session/relay socket
  buffers went from 512 KiB to 256 KiB per direction (they are caps, not reservations, and
  one association only ever carries one DATAGRAM flow), halving the worst-case kernel
  memory at the configured session caps; and the "buffer clamped" warning is now
  per-direction instead of a single flag in which whichever direction was probed first
  permanently silenced the other.

**Measured — and the honest headline: the proxy is not the bottleneck.**

Two full A/B runs against the previous revision on the same host, loopback, each doing
512 MiB of bulk download (8 concurrent), 4 000 SOCKS flows (16 concurrent) and 30 000
UDP datagrams through one association; CPU read from `ps -o time=` on both processes.

| Revision | server CPU | client CPU | bulk | flows/s | UDP recv pps | conn latency (median) |
|---|---|---|---|---|---|---|
| previous | 5.38 s | 7.52 s | 209 MB/s | 11 430 | 43 430 | 476 µs |
| this pass | 5.41 s | 7.41 s | 208 MB/s | 11 282 | 44 015 | 495 µs |

**Everything is within run-to-run noise.** The per-packet work this pass removed is on
the order of a few hundred nanoseconds, while the same packet costs microseconds inside
quinn: quinn takes its connection-state mutex once per DATAGRAM, runs through the
congestion controller and packet builder, and performs its own allocation per received
datagram. Against that, deleting one application-side `Vec` and one `RwLock::read` is not
visible in a loopback benchmark — which is the same conclusion the earlier DATAGRAM-reader
batching experiment reached (average batch 1.06, no measurable difference).

Where they do matter is the reason they were removed anyway: they are **per-packet,
per-flow costs that multiply with concurrency and core count**. A per-packet allocation
and a shared read lock are the kinds of things that turn into allocator contention and
cache-line ping-pong when hundreds of thousands of packets per second cross several
worker threads, even though they vanish into the noise of a single-flow loopback run.
Treat these changes as removing application-side tax, not as a throughput increase: if a
future profile shows the proxy's own per-packet code above noise, the microbenchmark
harness in `examples/hotpath_bench.rs` is what should measure the next change.

Correctness was verified after every step: `cargo test` (19 tests), `cargo clippy
--all-targets` and `cargo fmt --check` clean, and end-to-end runs of TCP `CONNECT` (IP and
domain targets), UDP `ASSOCIATE` (8 B and 1200 B payloads), 0-RTT resumption with early
data, and the token-auth accept/reject paths — all identical to the previous revision.
A harder mixed load (12 000 flows, 120 000 datagrams, 1 GiB bulk) kept both processes
within ~23 MB / ~13 MB RSS with no descriptor growth.

**Already optimal, left alone.** The DATAGRAM **encode** was never the problem: it
measures ~49 ns, i.e. noise next to the QUIC work around it. A drain loop that polled
`read_datagram` up to 32x per wakeup was tried and rejected — instrumentation showed an
average batch of 1.06 datagrams — and this pass did not re-litigate it.

**Outside this codebase's control.** The single biggest cost on the UDP path is that
quinn takes the connection-state mutex once per DATAGRAM, on both `read_datagram()` and
`send_datagram_wait()` (whose `poll` also calls `state.wake()`), and quinn 0.11 exposes no
batched receive or a wake/transmit-only entry point to avoid it. Reading one datagram per
lock acquisition is therefore a floor this revision cannot go below without patching
quinn; the changes above remove everything the application was adding *on top* of it. The
same applies to the second allocation quinn itself performs per received datagram when it
copies the frame out of its packet buffer.

### 2026-09 hardening pass 7 — reconnect race + DNS overload paths

- **Client `shared` TOCTOU.** The `open_bi` failure path did read-then-write
  (`read` the `stable_id`, drop, `write` `None`): a reconnect installing a fresh
  connection in between was unconditionally cleared, blackholing new flows until
  that connection died. It now takes a single write lock and re-checks
  `stable_id` inside, matching the reconnect loop's own clear path.
- **DNS eviction no longer scans under the write lock.** `evict_if_needed` did a
  full O(n) collect + `select_nth_unstable` plus per-victim key clones, and the
  negative cache did an O(n) `retain`, both while holding the global write lock —
  stalling every packet-path reader during a miss storm. Both now evict
  arbitrary entries in O(over)/O(1) with no clock reads; expired entries are
  still treated as misses by the TTL check on read, so correctness is unchanged.
- **TCP domain dials fail fast when the DNS budget is gone.** They waited up to
  3 s for `dns_slow_path_limiter` while holding a `stream_task_limiter` permit,
  so a unique-domain flood parked up to `MAX_STREAM_TASKS` permits and starved
  IP-literal flows. They now use `try_acquire` like the UDP path; the client
  retries a reset stream.

Verified: `cargo test` (19 tests), `cargo clippy --all-targets` and `cargo fmt
--check` clean; end-to-end TCP `CONNECT` (IP + `localhost` domain targets) and
UDP `ASSOCIATE`, plus `kill -9` → restart reconnect (~20 s silent-path
detection, stale-ticket redials, then TCP+UDP self-heal).

- **Rebuilt release binaries.** `dist/openwrt-x86_64/` was rebuilt from this
  revision for all four CPU levels (v1–v4: static musl, x86-64, stripped).
  Re-copy them to the router; the fix is server- and client-side.

---

## Roadmap

- [x] Optional client authentication (`auth_token`)
- [x] Process-wide connection/session caps + receive-window bound
- [x] 0-RTT-safe authentication and corrected reconnect/backoff behaviour
- [ ] Mutual TLS as an alternative to the shared token
- [ ] SOCKS error REPs + UDP source validation (strict-compliance mode)
- [ ] Ticket-key persistence for 0-RTT across server restarts
- [ ] Per-stream metrics endpoint (Prometheus) — BBR state, GSO batch size, sess table
- [ ] `procd` init script for OpenWrt
- [ ] MQP datagram fragmentation for > 1350 B UDP payloads
- [ ] Fuzz the MQP-2 codec (cargo-fuzz)
- [x] Remove the quinn-proto DATAGRAM drop-oldest process abort (`try_send_datagram`)
- [x] Per-flow allocation on the TCP-open path (stack-buffer header, borrowed dial candidates)
- [x] Per-packet allocation / lock / clock-read audit of the UDP and stream paths (pass 6)
- [x] Reconnect `shared` TOCTOU + DNS overload-path write-lock stalls (pass 7)
- [ ] Re-evaluate DATAGRAM-reader batching if a future quinn exposes a batch receive API
      (measured useless with quinn 0.11: avg batch 1.06, see pass 5)
- [ ] Pin the quinn-proto patch release once the upstream DATAGRAM accounting fix lands

---

## License

MIT — see `Cargo.toml` (`license = "MIT"`).
