# MyQUIC2

**An ultra-high-performance QUIC-based SOCKS5 proxy** — multiplexes TCP and UDP traffic
over QUIC (dual connections by default for loaded-latency isolation), written in Rust.

MyQUIC2 speaks standard SOCKS5 (RFC 1928) on the ingress side, so browsers, CLIs and
apps work unchanged (`curl --socks5`, system proxy settings, etc.), while the wire
between client and server is a purpose-built minimal binary protocol (**MQP-2**) over
QUIC (TLS 1.3, BBR congestion control, GSO/GRO batching, 0-RTT resumption,
ALPN `h3` by default for masquerade, `myquic2/2` opt-in for a versioned fail-closed handshake).

```
[ App ] --TCP/UDP--> [ myquic2-client :1080 ] ==QUIC (2 connections by default)==> [ myquic2-server :8443 ] --TCP/UDP--> [ Internet ]
```

The 2026-09 hardening revision adds optional shared-secret client authentication,
process-wide resource caps, PMTU-aware DATAGRAM sizing, 0-RTT-safe authentication, and
a corrected reconnect path. A previous pass removed a **process-abort** reachable from
normal network conditions (an MTU reduction could trip an accounting bug inside
quinn-proto's drop-oldest DATAGRAM path) and stripped the remaining per-flow allocations
from the TCP-open path; an intermediate pass briefly tracked upstream `main` (0.12) for
that fix, and the latest pass is back on crates.io (quinn 0.11.12 / proto 0.11.18),
which backports the DATAGRAM fix plus the assembler coalescing and three security
fixes — see [Hardening notes](#2026-09-hardening-pass-10--back-to-cratesio-quinn-01118).
Every behaviour documented below was re-verified end-to-end on this revision — see
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
- [Hardening Notes (this revision)](#hardening-notes-this-revision) — includes [pass 5](#2026-09-hardening-pass-5), [pass 8](#2026-09-hardening-pass-8--quinn-crates-moved-to-upstream-main) and [pass 9](#2026-09-hardening-pass-9--tcp-windows-re-sized-for-300-mbs-at-140-ms)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Area | Detail |
|---|---|
| **Proxy ingress** | Standard SOCKS5: `CONNECT` (TCP) + `UDP ASSOCIATE`, IPv4 / domain / IPv6 targets. SOCKS itself is no-auth by design; the QUIC link can be protected with a token |
| **Transport** | QUIC (quinn 0.11.12 / proto 0.11.18 from crates.io), TLS 1.3 only, dual QUIC connections per client by default (bulk round-robin, interactive pinning, failover) — `quic_conns = 1` restores a single shared connection |
| **Handshake path** | Per-incoming accept/handshake tasks — one slow client can never stall new connections |
| **Congestion** | BBR by default (Cubic available as escape hatch), ECN + pacing on |
| **Offload** | GSO/GRO auto-probed (`UDP_SEGMENT`); 4 MB QUIC socket buffers; 1 MB DATAGRAM send/receive buffers |
| **Custom protocol** | MQP-2 binary framing: TCP costs **0 extra bytes** after the first header; UDP costs **+12 B (IPv4) / +24 B (IPv6)** per datagram, plus **+16 B per additional fragment** once a payload exceeds one QUIC DATAGRAM |
| **0-RTT** | Session resumption with early data, verified end-to-end (`accepted=true`). The auth token rides early data and is automatically re-sent if the server rejects it |
| **Reconnect** | Survives server restarts: ~15–20 s silent-path detection, backoff redial (200 ms → 5 s, decayed only after 5 s of stable connectivity), fail-fast old streams, UDP sessions self-heal |
| **Dual-stack** | IPv4 + IPv6 everywhere: listeners, relays, dial-out; v4-mapped handling on BSD/macOS |
| **Identity** | Client pins the exact Ed25519 server cert; optional `auth_token` (constant-time compare, ≤ 256 B) prevents open-relay abuse |
| **Hard bounds** | 4096 concurrent QUIC connections (256 pre-auth), 8192 UDP sessions process-wide, 8 MB per-connection receive window default |
| **DNS** | Resolved **server-side** (correct egress geo, no client resolver cost): 60 s positive / 10 s negative cache, single-flight, 1024-entry slow-path limiter |
| **High-RTT tuned** | 4 MB per-stream / 8 MB aggregate receive window, 4 MB send window by default (~240 Mb/s at 140 ms, ~half the loaded queue) — 8/16/8 MB opt-in for 300 Mb/s — plus a 190 ms `initial_rtt`, ACK-every-2nd-packet with 5 ms `max_ack_delay` by default, and a 1472 B PMTU search ceiling |
| **Releases** | Static musl binaries for OpenWrt x86-64 at four CPU levels (v1–v4), ~4.2 MB stripped each (rebuilt from this revision) |

---

## Architecture

Single crate, three units sharing one protocol library:

| Unit | Source | Role |
|---|---|---|
| `myquic2` (lib) | `src/lib.rs` | MQP-2 codec (owned + borrowed forms), TOML config schema, TLS/cert helpers, QUIC transport builder, TCP↔QUIC bridge |
| `myquic2-server` | `src/bin/myquic2-server.rs` | QUIC ingress → dials TCP/UDP targets; per-session UDP sockets; token auth; self-signed cert issuance |
| `myquic2-client` | `src/bin/myquic2-client.rs` | SOCKS5 ingress → QUIC egress; dual-connection pool with reconnect loop + DATAGRAM dispatcher per slot; per-association UDP relay; token auth |
| `zero_rtt_probe` | `examples/zero_rtt_probe.rs` | End-to-end 0-RTT verification probe (with token support) |

**Data-plane mapping:**

- **TCP**: 1 TCP connection = 1 QUIC bidirectional stream. First bytes carry the MQP
  target header; the rest is a raw byte stream. The client answers SOCKS success
  optimistically and the server's MQP-2 dial ACK is validated on the reply path, so
  application bytes never wait for the remote dial. `FIN` ↔ QUIC `finish()`,
  dial failure ↔ closed/reset flow.
- **UDP**: 1 SOCKS association = 1 session id (`sess_id`), carried in QUIC **DATAGRAMs**
  (unreliable, no head-of-line blocking — a lost DNS packet never stalls other flows).
  A payload that fits one frame (`max_datagram_size() - 12 B` for an IPv4 target,
  `- 24 B` for IPv6/domain) is sent as a single `type=0x02` datagram; anything larger
  is split across `type=0x05` fragments and reassembled by the peer, up to
  `MQP_FRAG_MAX_PAYLOAD` (8 KiB). A datagram missing a fragment is discarded, never
  delivered short — fragmentation buys size, not reliability. Payloads past the
  reassembly cap are dropped and counted in `myquic2::dgram_drops`.
- **Control**: when `auth_token` is set, connection setup carries exactly one
  **authentication uni stream** (≤ 256 B). After that there is no control traffic
  beyond QUIC itself — no SOCKS username/password.

**Concurrency model:** Tokio multi-threaded runtime. The server spawns one task per
incoming connection (handshake included), one DATAGRAM reader and one session sweeper
per connection, and one lightweight reader task per UDP session. The client keeps a
pool of QUIC connections (2 by default, `quic_conns`) sharing one Endpoint/UDP socket,
each slot with its own reconnect loop and DATAGRAM dispatcher; one task per SOCKS
connection and one relay + reply task per UDP association. Subscriptions die with their
association, so stale tasks can never steal another session's packets.

**Connection isolation (client):** quinn 0.11 exposes no per-stream priority, so
separate congestion windows are the isolation mechanism. Bulk TCP spreads round-robin
across the pool while ports in `interactive_ports` (default DNS/NTP/STUN) plus **all
UDP** pin to the interactive connection, so a latency probe never queues behind bulk
on the same cwnd. Routing is liveness-aware: a dead preferred slot fails over to the
live one (returning flows stay on their slot; both dead fails the flow fast via the
normal reconnect timeout). Isolation holds while both connections are alive: with a
single live connection every flow shares one cwnd. UDP egress is sticky to its
connection while it lives (no flap-back churn when the preferred slot recovers;
new associations prefer the interactive slot again). The TCP open header is always its own write, never batched
behind first application bytes, so server-first peers (game logins, banners) see it
within ~100 ms.

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
**unclamped**); the server caps replies the same way.

### UDP fragment (only when one frame is not enough)

```
type=0x05 u8 | sess u32 LE | id u16 LE | idx u8 | total u8 | atyp | addr | port | chunk
```

A QUIC DATAGRAM cannot carry a full 1472 B UDP payload — the 12/24 B MQP header plus
the QUIC packet and DATAGRAM-frame overhead exceed the path MTU — so a proxy built
only on single-frame datagrams is *strictly worse* than a direct UDP path for the
packets conferencing stacks actually emit (DTLS handshake flights, non-WebRTC media,
TURN-wrapped payloads, modest IP fragmentation). `type=0x05` lifts that ceiling to
`MQP_FRAG_MAX_PAYLOAD` without buying reliability.

- **Address on every fragment.** It costs 7 B (IPv4) / 19 B (IPv6) per fragment and
  buys a reassembler with no special case for out-of-order arrival and no way for a
  lost fragment 0 to strand the rest — every fragment is self-describing.
- **`(sess, id)` is the reassembly key.** `id` is a per-sender `u16` counter (one per
  SOCKS association on the client, one per UDP session on the server), so a wrapped
  id reused with a different `total` restarts the partial instead of splicing two
  unrelated datagrams together.
- **Bounded.** A partial is at most `MQP_FRAG_MAX_PAYLOAD`; in aggregate a connection
  holds at most `FRAG_MAX_HELD_BYTES` and evicts the oldest partial past that.
  Partials whose first fragment is older than `FRAG_TIMEOUT_MS` are swept on insert.
- **All-or-nothing.** A datagram missing any fragment is dropped, never delivered
  short. UDP peers do not retransmit, so nothing waits longer than one expiry.
- Both relays send through `myquic2::DgramFragmenter::send` — the single send path —
  so every drop is counted, and a payload above the reassembly cap is refused rather
  than truncated.

The fragment frame is additive: a peer that predates it rejects `type=0x05` in
`decode_datagram_ref` and drops the datagram (the pre-fragmentation behaviour for
oversized payloads), so a version-skewed pair loses only large datagrams and can
never misparse. Both ends must be on this revision to carry them.

### Connection authentication (`auth_token` non-empty)

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

ALPN defaults to **`h3`** (masquerade: hides only the ALPN label — the self-signed
cert and MQP framing stay fingerprintable). Set `alpn = "myquic2/2"` explicitly on
both sides to restore the versioned identifier below.

`myquic2/2` was bumped from `myquic2/1` when the TCP-open ACK gained
the bound address: a version-skewed pair now fails the TLS handshake with a clear
error instead of misparsing the ACK as application data, so **upgrade both sides
together**. The UDP DATAGRAM layout and the auth uni stream are unchanged from MQP-1.

Pass 12 added the `type=0x05` UDP fragment frame *without* a bump, because it is
purely additive: a peer that predates it rejects the unknown type and drops the
datagram — its own pre-pass-11 behaviour for oversized payloads — so misparsing is
impossible. The cost of a skewed pair is that UDP payloads above one frame are lost,
which is why **both ends should still be upgraded together** if you carry large UDP.

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
| 1 | `cargo test --all-targets` (codec round-trips, borrowed-datagram round-trip, DNS key normalization/injectivity, `is_global_ip` filter, DATAGRAM send-buffer saturation, MQP/SOCKS header length + framing) | ✅ 19/19 |
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

Additional checks run on the pass-8 revision (quinn 0.12 from upstream `main`,
macOS, loopback, `cargo build --release`, token auth enabled on both sides):

| # | Test | Result |
|---|---|---|
| 16 | TCP ECHO via SOCKS5 `CONNECT` (1 MiB random) over a full handshake | ✅ 1048576 B byte-for-byte |
| 17 | UDP ECHO via `UDP ASSOCIATE` (25 × 1000 B) | ✅ 25/25, BND = relay address |
| 18 | Server `kill -9` → restart → reconnect: the client offers a **stale 0-RTT ticket** the restarted server rejects | ✅ `QUIC 0-RTT rejected: re-sending auth at 1-RTT` then TCP (64 KiB) + UDP (25/25) echo pass — the rejection is detected through `SendStream::stopped()`, not a redial |
| 19 | 0-RTT probe with token, same server process | ✅ `0-RTT offered`, `server accepted 0-RTT early data = true`, echo over early data; acceptance derived from `stopped()` in 3.0 s (the probe's own sleep) |
| 20 | `cargo clippy --all-targets` + `cargo fmt --check` | ✅ clean |

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
  tested on stable 1.97.1; deps: quinn 0.11.12 / quinn-proto 0.11.18 /
  quinn-udp 0.5.15 from crates.io, rustls 0.23, tokio 1.53.1). The quinn crates
  are plain crates.io dependencies; `cargo update` moves them within the 0.11 line.
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
rebuilt from the pass-12 revision (MQP-2 UDP fragmentation plus the DATAGRAM
payload-budget fix): static musl, x86-64, stripped, ~4.2 MB each. Two upgrade
notes, both requiring **both** sides to be replaced together:

- A binary built before pass 9 carries the old 2/8/4 MB windows and caps a single
  stream at ~114 Mb/s; a mixed pair is limited by whichever end is older, since a
  download is capped by the receiver's advertised window.
- A binary built before pass 12 loses every UDP payload above one QUIC DATAGRAM
  (~1422 B on a 1472 B path) and truncates relay reads at 2048 B. Payloads above
  one frame are *silently* lost against an older peer, because it rejects the
  `type=0x05` fragment frame — no misparse, but no error either.

Verified by running the v1 pair on an x86-64 CPU reporting **no** `sse4_2`, `avx` or
`avx2` (QEMU's baseline `qemu64`, which is what the emulated test container
exposes): the QUIC handshake completed and a 256 KiB SOCKS5 `CONNECT` transfer came
back byte-for-byte. The AVX2 instructions the v1 binary does contain live in `ring`'s
VAES/AVX2 AES-GCM path and in `core`'s slice helpers, both behind runtime CPU
detection — the handshake on that CPU is the proof they were not executed. The same
CPU makes the **v4** binary die immediately with `Illegal instruction`, which is the
expected consequence of selecting a level the CPU does not implement.

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
# Optional tuning, mirrors the client (download capped by receiver window,
# upload by sender window — change both sides together):
# stream_receive_window_mb = 4, receive_window_mb = 8, send_window_mb = 4,
# ack_threshold = 2, max_ack_delay_ms = 5, alpn = "h3"
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
# Optional tuning (defaults = 4/8/4 MB windows, ACK 2/5ms, dual connections):
# stream_receive_window_mb, receive_window_mb, send_window_mb,
# ack_threshold, max_ack_delay_ms, quic_conns = 1 (single), interactive_ports, alpn
```

Field notes:

- `allow_private` defaults to **false** in code; the sample config sets `true` for
  local testing. Disable it for any public exit node.
- `auth_token` empty on both sides = no authentication. Non-empty on the server but
  empty/wrong on the client = connection closes with `unauthorized` and the client
  retries with growing backoff.
- `reconnect_timeout_secs` only bounds how long a *new SOCKS flow* waits for a live
  QUIC connection; it does not control redial backoff.
- Transport tuning (`stream/receive/send_window_mb`, `ack_threshold`,
  `max_ack_delay_ms`) defaults to the low-latency preset (4/8/4 MB, ACK 2/5 ms,
  ~240 Mb/s @140 ms); set 8/16/8 MB + ACK 8/10 ms on **both sides** for 300 Mb/s
  peak at ~2x loaded latency. Optimal total in flight ≈ link BDP — e.g. a
  200M/140ms link (BDP 3.5 MB) wants 2/4/2 MB, which halves single-thread speed
  (~114 Mb/s) while multi-thread still fills the link with minimal loaded latency.
- `quic_conns = 2` (default) isolates bulk from interactive traffic; `1` restores
  the legacy single connection. `interactive_ports` pins latency-sensitive TCP
  ports to the interactive connection (default 53/123/3478–3481); all UDP always
  rides it. A dead slot fails over automatically.
- `alpn` defaults to `h3` masquerade (label only); `myquic2/2` restores the
  versioned fail-closed handshake. Same value required on both sides.
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
| Receive window (aggregate) | 8 MB/connection default (16 MB opt-in) | `TransportTuning` (`RECEIVE_WINDOW`) |
| Receive window (per stream) | 4 MB default (8 MB opt-in) | `TransportTuning` (`STREAM_RECEIVE_WINDOW`) |
| Send window | 4 MB/connection default (8 MB opt-in) | `TransportTuning` (`SEND_WINDOW`) |
| Initial RTT / PMTU ceiling | 190 ms / 1472 B | `build_transport` |
| DATAGRAM buffers | 1 MB each direction | `build_transport` |
| Keepalive / idle / watchdog | clamp 1–3600 s; idle `max(3×,15 s)`; watchdog `max(4×,20 s)` | `build_transport`, client |
| Server auth wait | 5 s per connection (one deadline for accept+read) | `authenticate()` |
| TCP stream idle reap | 300 s | `copy_tcp_quic_idle` call sites |
| UDP association idle reap | 180 s (both directions; TCP control activity counts) | server sweeper / client interval |
| DNS cache | 60 s positive (4096+512 slack), 10 s negative (4096) | `DNS_CACHE_*`, `DNS_NEG_MAX` |
| Client TCP dial ACK budget | 25 s (5 s header + 3 s DNS permit + 5 s DNS + 2 s dial permit + 4 s connect + scheduling margin) | `TCP_DIAL_ACK_TIMEOUT` |

Kernel-side tuning: raise `net.core.wmem_max` / `net.core.rmem_max` so the 4 MB
(QUIC socket) and 256 KB (per-session) socket buffers are not silently clamped; the
first clamp logs one warning per
process (per-socket warnings were removed because session churn flooded the log).
For the 300 Mb/s @ 140 ms target, 8 MB is the recommended value for both
(`sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608`): 4 MB covers
only ~110 ms of that rate.

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
- **A dial is not accepted until the connection is proven alive** (pass 7, reworked in
  pass 8, ported back to 0.11 in pass 10). quinn-0.11's `Connecting` future resolved `Ok`
  even for a connection that terminated instead of handshaking, so the 0-RTT path gates
  on the `ZeroRttAccepted` future (true = early data kept; false = rejected or died)
  plus `close_reason()`: a timeout or a closed connection fails the dial, a live
  connection with rejected early data re-sends the token at 1-RTT, so a dead dial cannot
  be published; `dial_once` bounds each attempt with `DIAL_ATTEMPT_TIMEOUT` (5 s)
  instead of QUIC's ~15 s Initial-retransmission budget — so the first attempt after a
  restart succeeds instead of waiting out the previous one's timeout. Measured:
  server `kill -9` → detection ≈ 20 s → reconnect ≈ 0.3–0.4 s after the server is back
  (before: a false `connected` every ~15 s plus 15.6 s recovery).

- **After reconnect**: UDP sessions self-heal (the server recreates `sess_id` state on
  the next packet); old TCP streams reset fast so apps reconnect instead of hanging.
- **140 ms links**: tuned for the trans-Pacific BDP — 4 MB per-stream / 8 MB
  aggregate receive window, 4 MB send window, BBR, ACK-every-2nd-packet with a
  5 ms `max_ack_delay` by default (~240 Mb/s, ~half the loaded queue); opt in to
  8/16/8 MB for 300 Mb/s. The SOCKS success reply is sent
  optimistically (no 1-RTT wait for the remote dial), so the application's TLS
  handshake overlaps the server-side dial; server-side DNS avoids geo-misresolved IPs.
  A lossy path is the tradeoff: 8 MB allows ~6200 packets in flight per RTT, which
  is more room than the legacy 2 MB to approach quinn's 1024-chunk reassembly
  limit, so `too many gaps in stream buffer` on a burst-loss link means stepping
  `SEND_WINDOW` / `STREAM_RECEIVE_WINDOW` back to 4 MB (~240 Mb/s).

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
| Handshake fails between two installs (`no application protocol`) | ALPN mismatch: default is `h3` now, pre-h3 binaries use `myquic2/2` → upgrade both sides together / set the same `alpn` on both |
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
`send_datagram_wait()` (whose `poll` also calls `state.wake()`), and quinn 0.12 exposes no
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

### 2026-09 hardening pass 8 — quinn crates moved to upstream main

- **Dependency swap.** `quinn`, `quinn-proto` and `quinn-udp` are no longer taken
  from crates.io (0.11.11 / 0.11.17 / 0.5.15); all three now come from one git
  source, [`quinn-rs/quinn` `main`](https://github.com/quinn-rs/quinn) at
  `621e38ab` (0.12.0 / 0.12.0 / 0.6.2). `Cargo.lock` pins the exact commit, so
  builds stay reproducible; `cargo update -p quinn` moves the three forward
  together. This is what retires the pass-5 workaround: upstream moved the
  counter into the datagram buffer itself, so every mutation keeps it in sync
  (`drop_oversized` now decrements exactly what it removes), and the
  `.expect("datagrams.outgoing.payload_bytes desynchronized")` abort path no
  longer exists. `try_send_datagram` is kept — not for safety any more, but
  because the relay wants `Blocked` reports and drop-*newest* semantics, where
  `send_datagram` silently evicts the oldest queued datagram.
- **0-RTT API migration (breaking upstream change).** 0.12 removed the
  `ZeroRttAccepted` future that `Connecting::into_0rtt()` returned, and
  `Connection::authenticated()` reports only "handshake finished or connection
  lost" — it does **not** carry the early-data decision. The client still refuses
  to publish a connection before the handshake completes (now by awaiting
  `authenticated()`, which also surfaces a dead dial as `Err`), and detects
  rejection the way upstream documents: `SendStream::stopped()` on the finished
  early auth stream yields `ZeroRttRejected`. On rejection the token is re-sent
  over the established 1-RTT connection instead of failing the dial and
  redialing, so a server that declines early data no longer costs a dial.
- **Server handshake gate.** The 0.5-RTT accept path awaits
  `Connection::authenticated()` in place of the removed `ZeroRttAccepted`, and
  now also aborts on a failed handshake rather than only on the timeout.
- **`Connecting` no longer hides a dead dial.** 0.12 returns the terminal error
  instead of `Ok` for a connection that terminated before its handshake;
  `ensure_dialed_alive` stays as a cheap guard.
- **Minor API churn.** `Endpoint::set_default_client_config` takes `&self` (the
  now-redundant `mut` endpoint bindings are gone); `examples/zero_rtt_probe.rs`
  derives the "server accepted 0-RTT" line from `stopped()` and falls back to the
  echoed early data as its own proof when no auth token is configured.

Verified end-to-end on loopback with token auth on both sides (tests 16–20 in
[Verification & E2E Tests](#verification--e2e-tests)): `cargo test --all-targets`
19/19, `cargo clippy --all-targets` and `cargo fmt --check` clean, TCP `CONNECT`
(1 MiB) and UDP `ASSOCIATE` (25 × 1000 B) byte-for-byte, and a `kill -9` →
restart cycle in which the client's **stale 0-RTT ticket is rejected** and the
token is re-sent at 1-RTT before the flows recover. `dist/openwrt-x86_64/` was
rebuilt from the pass-8 revision for all four CPU levels.

### 2026-09 hardening pass 9 — TCP windows re-sized for 300 Mb/s at 140 ms

- **`dist/openwrt-x86_64/` rebuilt again** from this pass for all four CPU levels
  (v1–v4, static musl, stripped, ~4.2 MB each) and smoke-tested under x86-64
  emulation on a CPU without AVX: see
  [Cross-compile for OpenWrt x86-64](#cross-compile-for-openwrt-x86-64-static-musl-from-macos).
- **The bottleneck was flow control, not congestion control.** At 140 ms, 300 Mb/s
  costs ~5.25 MB in flight (37.5 MB/s × 0.14 s, plus the QUIC short header and
  IPv4/UDP headers). Every flow-control window is a hard ceiling of
  `window / RTT`, and the previous sizing capped single-stream at **~114 Mb/s
  receive / ~228 Mb/s send** long before BBR's congestion window mattered:
  `stream_receive_window` 2→8 MB, `receive_window` 8→16 MB, `send_window` 4→8 MB.
  Both endpoints build their transport from `build_transport`, and a download is
  capped by the *receiver's* advertisement while an upload is capped by the
  *sender's* budget, so both sides had to change for either direction to improve.
- **8 MB, not the ~5.25 MB BDP.** quinn only emits `MAX_STREAM_DATA` once the
  advertised window is short by `stream_receive_window / 8`, so the cushion that
  must still cover a BDP is `8 − 1 = 7 MB`. At 6 MB it would be 5.25 MB — the BDP
  exactly, with nothing left for scheduler jitter or a slow application read.
- **Reverse-path ACK rate.** `AckFrequencyConfig` now requests an ACK every 8th
  ack-eliciting packet with a 10 ms `max_ack_delay` (was quinn's default of every
  2nd packet, `None` delay): ~14k ACK/s per 300 Mb/s stream is real work for the
  single writer thread. A threshold of 32+ was rejected — it makes BBR's
  bandwidth estimate too coarse and slows the startup ramp.
- **`initial_rtt` 333 → 190 ms** (quinn's default is a spec-derived placeholder
  that makes the first PTO and the initial bandwidth estimate pessimistic for
  this link), and the PMTU search ceiling 1452 → 1472 B (`EndpointConfig`'s
  default `max_udp_payload_size`, so 1452 was leaving 1.4% of the path unused).
  The search still starts at the 1200 B QUIC minimum and climbs only on
  successful probes.
- **Known cost, carried over from pass 2's gaps-death halving.** 8 MB allows
  ~6200 packets in flight per RTT (1350 B) or ~3700 (1452 B), so a burst-loss or
  reordering episode has more room than 2 MB did to approach quinn's
  `MAX_CHUNKS = 1024` reassembly limit, which kills the whole connection with
  `too many gaps in stream buffer`. A clean path is unaffected. On a lossy one,
  step `SEND_WINDOW` / `STREAM_RECEIVE_WINDOW` back to 4 MB (~240 Mb/s) rather
  than reverting the ACK/MTU work, which is independent of loss.
- **What is not tested here.** The invariant lives in named constants
  (`STREAM_RECEIVE_WINDOW`, `RECEIVE_WINDOW`, `SEND_WINDOW`) asserted in `const`
  blocks, so re-tightening a window fails the *build*. A live loopback test was
  written and rejected: with a 2 MB window the cushion is still 1 MB, which at a
  ~0.2 ms loopback RTT is worth ~40 Gb/s, so it passed against the very
  regression it was meant to catch. Confirming the 300 Mb/s figure needs a
  ~140 ms path and `conn.stats()` (`path.cwnd`, `path.pacing_rate`), as the
  README's measurement notes describe.

### 2026-09 hardening pass 10 — back to crates.io quinn 0.11.18

- **Dependency switch.** `quinn`, `quinn-proto` and `quinn-udp` are crates.io
  dependencies again (quinn 0.11.12 / proto 0.11.18 / udp 0.5.15) instead of the
  upstream-`main` git pin (pass 8) and the `MAX_CHUNKS = 16384` fork patch built
  on it. Upstream's 0.11.18 backports everything this project needed from `main`:
  the DATAGRAM `payload_bytes` accounting fix, the assembler contiguous-chunk
  coalescing, and three security fixes (unordered-read panic, drop-oldest
  double-subtraction, ACK_FREQUENCY min-delay panic) — so the fork has no
  remaining value and its maintenance cost is gone. `cargo update` moves the
  trio within the 0.11 line.
- **0-RTT ported back to the 0.11 API.** `Connecting::into_0rtt()` yields
  `(Connection, ZeroRttAccepted)` again; the client gates publication on that
  future plus `close_reason()` (false = rejected or died, timeout = dead), and
  re-sends the token at 1-RTT on rejection; the server awaits the same future
  (always true incoming-side) bounded by `HANDSHAKE_TIMEOUT` before consuming
  the auth token. The `stopped()`-based rejection signal and `mut`-less
  `set_default_client_config` from pass 8 are reverted with it. Transport tuning
  (`AckFrequencyConfig`, `initial_rtt`, MTU ceiling, windows, `send_datagram_wait`
  helper) needed no changes — all present in 0.11.
- **Known regression vs the fork.** `MAX_CHUNKS` is 1024 again, so the 8 MB
  stream window is gap-kill-prone on lossy links as analyzed in pass 9; the
  mitigation is unchanged (step back to 4 MB). Single-user deployment accepted.

### 2026-09 hardening pass 11 — the DATAGRAM budget was a payload cap

Found while explaining a `speed.cloudflare.com` verdict of *Video chatting: Poor*
on a China-Mobile → LAX path. The TCP side was not at fault (that verdict is
driven by TCP-measured jitter); the UDP relay had a real defect of its own.

- **The bug.** Both relays sized outgoing DATAGRAMs against
  `max_datagram_size().min(1350)`. The `min` looks like a harmless MTU safety
  margin, but `1350` is compared against the **whole** MQP-2 body
  (`encode_datagram_ref_with_limit`: `DGRAM_PREFIX_LEN + header + payload`), so
  it is in fact a *payload* cap of `1350 - 5 - 7 = 1338 B` for an IPv4 target
  and `1326 B` for IPv6 — no matter how large the discovered path MTU was. Every
  larger UDP payload was dropped with a `debug!`-level log, i.e. silently at the
  default log level. Measured on loopback against the previous binary:
  1338 B → 0 % loss, 1350 B → **100 % loss**. A 1400 B DTLS record or a
  TURN-wrapped media packet that a direct UDP path delivers fine simply vanished.
- **Fix.** The relays now pass `max_datagram_size()` unclamped — that value is
  exactly the largest DATAGRAM body quinn will carry on the current path, with
  the QUIC packet and DATAGRAM-frame overhead already subtracted, so using it
  directly is the API contract rather than a policy choice. On a 1472 B path the
  usable UDP payload is now ~1436 B (IPv4) instead of 1338 B. The dynamic-PMTU
  behaviour that motivated the `min` is preserved by the existing refresh paths
  (`TooLarge` → re-read the limit, client also re-reads once per second).
- **New `dgram_payload_cap()`** states the relationship once, so callers and
  tests reason about the *payload* budget instead of re-deriving the header
  arithmetic. `DGRAM_MAX_WIRE = 1472` replaces the old
  `DATAGRAM_BUFFER >= MQP_DGRAM_MAX` send-buffer invariant, which only ever
  proved that a 264 B header fits — it never covered a full-size datagram.
- **Drops are now visible.** `try_send_datagram`'s two drop outcomes were
  `debug!`-only, which is why a 100 % loss of large datagrams could go unnoticed.
  `send_udp_datagram()` is now the single encode+send entry point for both
  relays; it bumps `dgram_drops::TOO_LARGE` / `dgram_drops::BUFFER_FULL`
  (`snapshot()` reads them) and emits one rate-limited `warn!` per 10 s naming
  the path limit and the usable payload budget.
- **Not a fix: `Blocked` under TCP load.** The 1 MB datagram send buffer was
  suspected of dropping UDP when bulk TCP streams occupy the congestion window.
  Measured with four saturating TCP flows on the same connection: 1200 B UDP at
  200 pps lost **0 %** both with and without the TCP load; only a full-rate flood
  (~190 kpps offered) lost packets, and the rate was essentially unchanged by the
  TCP load (70.5 % vs 66.5 %). DATAGRAM loss here is driven by the offered UDP
  rate filling the send buffer, not by TCP competing for cwnd. The counters above
  make that distinction observable in production.

### 2026-09 hardening pass 12 — MQP-2 UDP fragmentation

Pass 11 removed an artificial clamp, which moved the single-frame ceiling from
1338 B to ~1422 B. That is still **not enough to be transparent**: a full 1472 B
UDP payload can never fit a QUIC DATAGRAM, because the 12 B MQP header plus the
QUIC packet and DATAGRAM-frame overhead exceed a 1472 B path MTU. Video calling
is exactly the workload that notices — DTLS handshake records, non-WebRTC
conferencing stacks, TURN-wrapped media and modest IP fragmentation all exceed
one frame, and every such packet was being dropped 100 %.

- **`type=0x05` fragments.** A payload too large for one frame is split into
  `total` fragments carrying `(sess, id, idx, total)` plus the address header, and
  reassembled by the peer. Small packets keep the byte-identical `type=0x02`
  single-frame path, so nothing pays for this unless it needs it.
- **Ceiling raised to 8 KiB** (`MQP_FRAG_MAX_PAYLOAD`), 5.5x the largest
  datagram any real-time medium produces (1472 B on a 1500 B MTU), so it is not
  a limit the target workload can reach. The per-session read buffer is the same
  8 KiB, which bounds worst-case relay memory at 8 KiB × `MAX_SESSIONS_GLOBAL`
  (64 MiB).
- **Why not the 65507 B UDP maximum.** Reassembly is all-or-nothing, so a
  payload's delivery probability is `(1-p)^F` while its cost stays `F` fragments.
  At 1 % loss a 64 KiB payload is 47 fragments: 62 % delivery for 47x the bytes,
  and at 5 % loss it is 9 % — bandwidth spent on a datagram that will not
  arrive. 8192 B is 6 fragments, 94 % at the same 1 % loss. Fragmentation still
  beats dropping outright, which is why the **wire format is sized for the full
  UDP maximum**: the compile-time assertion next to `MQP_FRAG_MAX_TOTAL` proves a
  `u8` count reaches 65507 B even at QUIC's minimum 1200 B MTU (58 of 64
  fragments), so raising the constant is a one-line change and never a
  wire-format change. `fragment_count_documents_the_loss_amplification_tradeoff`
  pins the arithmetic.
- **Buffers were a second, earlier cliff.** Both relays read into a 2048 B socket
  buffer, so anything past ~2 KiB was truncated *by the kernel* before any counter
  could see it. Buffers now cover the full protocol cap, plus one byte of slack:
  `recv_from` reports the same length for "exactly filled" and "truncated", so the
  slack is what makes the `n == buf.len()` warning mean truncation and nothing
  else. Truncations now log instead of vanishing.
- **Bounded and all-or-nothing.** A partial is capped by
  `MQP_FRAG_MAX_PAYLOAD`, a connection holds at most `FRAG_MAX_HELD_BYTES`
  (evicting the oldest partial past it), and partials expire after
  `FRAG_TIMEOUT_MS`. A datagram missing any fragment is dropped rather than
  delivered short — the failure mode this whole pass exists to remove.
- **Additive on the wire.** An older peer rejects the new frame type and drops
  the datagram, which is exactly its pre-pass-11 behaviour for oversized payloads,
  so no misparse is possible and ALPN stays `myquic2/2`. Both ends must be on this
  revision to carry large datagrams.
- **The dispatcher is a second decode site (found by the Meet simulation).** The
  client's per-connection reader routes each datagram to its association by
  reading `sess` — and it did so behind a hard-coded `d[0] != 0x02` check, so
  every `0x05` fragment was discarded before the reassembler could see it. The
  symptom was precise: a 1438 B DTLS record (the only packet in a Meet call that
  needs a second frame) was lost 100 % of the time, every run, while everything
  at or below one frame was perfect. `dgram_sess()` is now the single place that
  knows which frame types are routable, with
  `dgram_sess_routes_both_frame_types` pinning it.
- **Verified end to end, round trip.** The earlier sweep counted only what the
  echo peer received, i.e. the outbound half — which is why it passed while the
  reply direction was broken. `udp.mjs` now counts replies at the client too:
  1200 / 1420 / **1430** / **1472** / 2000 / 4000 / 8000 / **8192** B all at 0 %
  loss in *both* directions (1422 B and 1430 B were 100 % loss before), and
  8300 B refused with one warning naming the cap.
- **Google Meet simulation** (`meet_sim.mjs`): 250 pps of 1200/200/100 B media
  plus a 1236–1438 B DTLS burst, run through the real binaries. 6/6 handshake
  and 4680/4680 media packets, 0 % loss, 0 reorder, 0 size mismatch, RTT median
  0.6 ms / p95 0.8 ms, RFC 3550 jitter 0.17 ms — and unchanged with two
  saturating bulk TCP downloads sharing the tunnel. Unit tests cover order
  independence, a lost fragment, duplicate fragments, malformed headers, id
  reuse with a changed shape, expiry, the memory bound, and a real-connection
  round trip.

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
- [x] MQP datagram fragmentation for UDP payloads above the path budget
      (`type=0x05`, up to `MQP_FRAG_MAX_PAYLOAD` = 8 KiB; see pass 12)
- [ ] Fuzz the MQP-2 codec (cargo-fuzz)
- [x] Remove the quinn-proto DATAGRAM drop-oldest process abort (`try_send_datagram`)
- [x] Per-flow allocation on the TCP-open path (stack-buffer header, borrowed dial candidates)
- [x] Per-packet allocation / lock / clock-read audit of the UDP and stream paths (pass 6)
- [x] Reconnect `shared` TOCTOU + DNS overload-path write-lock stalls (pass 7)
- [ ] Re-evaluate DATAGRAM-reader batching if a future quinn exposes a batch receive API
      (measured useless with quinn 0.11: avg batch 1.06, see pass 5)
- [x] Track quinn `main` (0.12) instead of the crates.io 0.11.x line, picking up the
      upstream DATAGRAM accounting fix (pass 8; superseded — back on crates.io
      0.11.18, which backports it, see pass 10)

---

## License

MIT — see `Cargo.toml` (`license = "MIT"`).
