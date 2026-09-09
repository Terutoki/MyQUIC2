# MyQUIC2

**An ultra-high-performance QUIC-based SOCKS5 proxy** — multiplexes TCP and UDP traffic
over a single QUIC connection, written in Rust.

MyQUIC2 speaks standard SOCKS5 (RFC 1928) on the ingress side, so browsers, CLIs and
apps work unchanged (`curl --socks5`, system proxy settings, etc.), while the wire
between client and server is a purpose-built minimal binary protocol (**MQP-1**) over
QUIC (TLS 1.3, BBR congestion control, GSO/GRO batching, 0-RTT resumption).

```
[ App ] --TCP/UDP--> [ myquic2-client :1080 ] ==QUIC (1 connection)==> [ myquic2-server :8443 ] --TCP/UDP--> [ Internet ]
```

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [The MQP-1 Protocol](#the-mqp-1-protocol)
- [Performance](#performance)
- [Requirements](#requirements)
- [Building](#building)
- [Configuration](#configuration)
- [Running](#running)
- [Certificates \& Authentication](#certificates--authentication)
- [SOCKS5 Compliance](#socks5-compliance)
- [Reconnect \& High-RTT Behavior](#reconnect--high-rtt-behavior)
- [OpenWrt Deployment](#openwrt-deployment)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Area | Detail |
|---|---|
| **Proxy ingress** | Standard SOCKS5: `CONNECT` (TCP) + `UDP ASSOCIATE`, IPv4 / domain / IPv6 targets, no-auth |
| **Transport** | QUIC (quinn), TLS 1.3 only, single long-lived connection shared by all flows |
| **Congestion** | BBR by default (Cubic available as escape hatch), ECN + pacing on |
| **Offload** | GSO/GRO auto-probed (`UDP_SEGMENT`); 4 MB socket buffers; 8 MB DATAGRAM buffers |
| **Custom protocol** | MQP-1 binary framing: TCP costs **0 extra bytes** after the first header; UDP costs **≤ 24 B**/packet |
| **0-RTT** | Session resumption with early data, verified end-to-end (`accepted=true`) |
| **Reconnect** | Survives server restarts: backoff redial (200 ms → 5 s), fail-fast old streams, UDP sessions self-heal |
| **Dual-stack** | IPv4 + IPv6 everywhere: listeners, relays, dial-out; v4-mapped handling on BSD/macOS |
| **Crypto identity** | Ed25519 self-signed cert, 500-year validity backdated 7 days (routers without RTC), client pins exact cert |
| **DNS** | Resolved **server-side** (correct egress geo, no client resolver cost) |
| **High-RTT tuned** | 4 MB stream window / 8 MB send window sized for ~140 ms trans-Pacific BDP |
| **Releases** | Static musl binaries for OpenWrt x86-64 at four CPU levels (v1–v4), ~4.7 MB each |

---

## Architecture

Single crate, three units sharing one protocol library:

| Unit | Source | Role |
|---|---|---|
| `myquic2` (lib) | `src/lib.rs` | MQP-1 codec, TOML config schema, TLS/cert helpers, QUIC transport builder, zero-copy bridge |
| `myquic2-server` | `src/bin/myquic2-server.rs` | QUIC ingress → dials TCP/UDP targets; per-session UDP sockets; self-signed cert issuance |
| `myquic2-client` | `src/bin/myquic2-client.rs` | SOCKS5 ingress → QUIC egress; reconnect loop; per-association UDP relay; DATAGRAM dispatcher |
| `zero_rtt_probe` | `examples/zero_rtt_probe.rs` | E2E 0-RTT verification probe (see [Reconnect](#reconnect--high-rtt-behavior)) |

**Data-plane mapping:**

- **TCP**: 1 TCP connection = 1 QUIC bidirectional stream. First bytes carry the MQP
  target header; the rest is a raw byte stream. `FIN` ↔ QUIC `finish()`, errors ↔
  `RESET_STREAM`.
- **UDP**: 1 SOCKS association = 1 session id (`sess_id`), carried in QUIC **DATAGRAMs**
  (unreliable, no head-of-line blocking — a lost DNS packet never stalls other flows).
  Oversize datagrams (> 1350 B on the wire) are dropped per UDP semantics.
- **Control**: none on the wire beyond QUIC itself (auth is the TLS handshake +
  pinned cert; no SOCKS username/password by design).

**Concurrency model:** Tokio multi-threaded runtime; one task per inbound connection,
one dispatcher task per QUIC connection routing inbound DATAGRAMs to live
associations by `sess_id`. Subscriptions die with their association, so stale tasks
can never steal another session's packets.

---

## The MQP-1 Protocol

All integers little-endian unless noted. Address encoding mirrors SOCKS5
(`0x01` IPv4 + 4 B, `0x04` IPv6 + 16 B, `0x03` domain + 1 B len + N B), followed by
port in big-endian — so IP headers can be reused byte-for-byte.

### TCP stream open (stream head, sent once)

```
atyp u8 | addr bytes | port u16 BE
IPv4 total: 7 B. Everything after is raw application bytes (zero overhead).
```

### UDP datagram (each QUIC DATAGRAM)

```
type=0x02 u8 | sess u32 LE | atyp u8 | addr bytes | port u16 BE | payload
```

`sess` scopes the packet to one UDP ASSOCIATE; the server echoes it back on replies
so the client dispatcher can route without any per-target state lookup.

### Design rationale

- TCP gets reliable streams (ordering + retransmission + flow control for free —
  never reimplement reliability on top).
- UDP gets DATAGRAMs (loss is semantic, not a bug).
- No serde/JSON/protobuf on the hot path: hand-rolled codec, `bytes::Bytes`
  forwarding (one small allocation per UDP datagram for the framed buffer;
  TCP uses 64 KB pump buffers per direction), DNS results cached 60 s.

---

## Performance

Measured on Apple Silicon (10-core), loopback, `release` profile, byte-exact echo
verification (any mismatch = fail). Throughput is **up+down combined**.

### TCP via SOCKS5 (Mb/s)

| Scenario | Via proxy | Direct | Proxy/direct |
|---|---|---|---|
| Single stream 16 MB | **426** (connect 0.5 ms) | 635 (connect 0.2 ms) | 67% |
| 50 conns × 2 MB | **1732**, 50/50 ✅ | — | — |
| 200 conns × 512 KB | **1470**, 200/200 ✅ | ~19448 | ~7% |
| 500 conns × 256 KB | **837**, 500/500 ✅ | — | — |
| Conn rate 2000 × 64 B | **≈8700 conns/s**, 2000/2000 ✅ | ≈14300/s | 61% |

Reading guide: single-stream overhead is one userspace copy + QUIC framing (~30%).
The 200-flow gap is architectural and expected — 200 native TCP flows each own kernel
buffers and a congestion window, while the proxy funnels 200 streams through **one**
QUIC connection. On loopback (zero RTT) parallelism always wins; on real networks the
single handshake + 0-RTT + no per-flow slow-start reverses the math.

### UDP via SOCKS5 (Mb/s, 1200 B packets, paced sender)

| Offered | Goodput via proxy | Loss | Direct |
|---|---|---|---|
| 3.7 kpps | **29.5** | 0% | — |
| 15.5 kpps | **124.3** | 0% | — |
| 29.2 kpps | **234.0** | 0% | — |
| 46 kpps | **288.2** | 21.7% | — |
| ~20 kpps (IPv6 target) | **158.6** | 0% | 164.4 |

Plus: 256 B packets → 37 Mb/s at 0 loss; **10 parallel associations → ~226 Mb/s
aggregate at 0 loss** (sess_id demux verified under concurrency).

> Note: debug builds are ~10× slower (unoptimized QUIC crypto). All numbers above
> are `release`. UDP is inherently lossy under overload — that is semantics, and the
> harness reports loss% alongside goodput instead of hiding it.

---

## Requirements

- **Rust** 1.75+ (developed on stable 1.97)
- **Linux** (production; GSO/GRO + BBR fully effective) or **macOS** (development;
  dual-stack verified, GSO degrades gracefully)
- For OpenWrt cross builds: `zig` + `cargo-zigbuild` (see [Building](#building))

---

## Building

```sh
# native release
cargo build --release
# binaries: ./target/release/myquic2-server ./target/release/myquic2-client

# run unit tests
cargo test
```

### Cross-compile for OpenWrt x86-64 (static musl, from macOS)

```sh
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild   # needs `zig` on PATH
```

Build one CPU level at a time (sequentially — each flag set invalidates codegen):

```sh
# v1 = any x86-64 (J4125/N100 safe default); v2 = SSE4.2; v3 = AVX2; v4 = AVX512
for v in x86-64 x86-64-v2 x86-64-v3 x86-64-v4; do
  cargo zigbuild --release --target x86_64-unknown-linux-musl \
    --config 'profile.release.strip="symbols"' \
    --config "target.x86_64-unknown-linux-musl.rustflags=[\"-C\", \"target-cpu=$v\"]" \
    --bin myquic2-server --bin myquic2-client
  # then copy target/.../myquic2-{server,client} aside BEFORE the next level
  # overwrites them, e.g. to myquic2-server-v3
done
```

> ⚠️ Pick the level your CPU actually supports (`grep avx512 /proc/cpuinfo` for v4).
> A v4 binary on a non-AVX512 CPU dies with `illegal instruction`. When in doubt,
> ship **v1**.

Prebuilt artifacts live in [`dist/openwrt-x86_64/`](dist/openwrt-x86_64/)
(`*-v1` … `*-v4` for both binaries, plus sample configs).

---

## Configuration

TOML files, CLI flags override via `--config <path>` (defaults:
`config-server.toml` / `config-client.toml` in the working directory).

### Server (`config-server.toml`)

```toml
listen = "[::]:8443"          # QUIC ingress (dual-stack wildcard recommended)
cert_file = "server-cert.pem" # auto-generated on first run if missing
key_file = "server-key.pem"   # dito (Ed25519)
server_name = "test.com"      # SAN for the self-signed cert + expected SNI
congestion = "bbr"            # bbr | cubic
gso = true                    # informational: quinn-udp auto-probes GSO/GRO
keep_alive_secs = 5
allow_private = true          # dial RFC1918/loopback targets (disable for public exit nodes!)
```

### Client (`config-client.toml`)

```toml
socks_listen = "[::]:1080"    # SOCKS5 ingress
server_addr = "127.0.0.1:8443"     # QUIC server (IP or hostname)
server_name = "test.com"           # SNI; MUST match the cert SAN
server_cert_file = "server-cert.pem"  # pinned server cert (copied out-of-band)
congestion = "bbr"
gso = true
keep_alive_secs = 5
reconnect_timeout_secs = 5    # new flows wait this long for a QUIC connection
```

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

---

## Certificates & Authentication

- **No passwords, no user database.** Authentication = TLS 1.3 handshake against a
  pinned self-signed **Ed25519** certificate (444 bytes; `ring` provider negotiates
  AES-128-GCM on AES-NI, ChaCha20-Poly1305 otherwise).
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
  either side restarting falls back to a 1-RTT full handshake automatically.

---

## SOCKS5 Compliance

Against RFC 1928 / RFC 1929:

| Item | Status |
|---|---|
| Handshake, no-auth (`0x00`) | ✅ |
| `CONNECT`, IPv4/domain/IPv6 | ✅ (curl-verified) |
| `UDP ASSOCIATE` + relay + TCP control held | ✅ (`FRAG≠0` dropped, as most implementations do) |
| Username/password (`0x02`) | ❌ intentionally absent |
| `BIND` | ❌ replies `0x07` (FTP active mode; obsolete in practice) |
| Error REPs (`0x01/0x04/0x05`…) | ⚠️ success paths reply correctly; on QUIC outage the connection fails fast (RST) instead of sending a SOCKS error code |
| UDP source validation | ⚠️ relay learns the app address from the first packet; fine behind NAT/home use, tighten before public exposure |

---

## Reconnect & High-RTT Behavior

- **Idle**: 5 s keepalive vs 15 s idle timeout — the connection lives indefinitely
  while both processes run (verified: 45 s idle, zero new handshakes, traffic flows
  instantly after).
- **Dirty network (< 15 s outage)**: QUIC retransmission + BBR absorb it; streams
  stall then resume, **no new handshake**.
- **IP change (NAT rebinding, WiFi→cellular)**: QUIC connection migration keeps the
  *same* connection alive without a handshake.
- **Long outage / server restart**: ~15–20 s silent-path detection (15 s QUIC idle
  timeout plus a 20 s no-inbound-traffic watchdog that force-closes a blackholed
  path) → 200 ms…5 s backoff redial → new connection (0-RTT when resuming
  against the same server process; verified `accepted=true` end-to-end with
  `examples/zero_rtt_probe.rs`).
- **After reconnect**: UDP sessions self-heal (server recreates `sess_id` state on
  next packet); old TCP streams reset fast so apps reconnect instead of hanging.
- **140 ms links**: tuned for trans-Pacific BDP — 4 MB stream window (~239 Mb/s per
  stream), 8 MB connection send window, BBR; SOCKS replies before remote dial
  (saves a full RTT per connection); server-side DNS avoids geo-misresolved IPs.

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
4. **Clock**: ensure NTP is up (`date` sane) — belt-and-braces alongside the
   7-day backdating.
5. `server_addr` = server's **public** IP on the client; `server_name` unchanged
   (SNI/cert check only, needs no DNS).

---

## Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `os error 2` at client startup | Relative `server_cert_file` vs CWD → absolute path |
| `UnknownIssuer` | Client cert ≠ server cert (stale copy after regen) → compare fingerprints, re-copy |
| `certificate not valid yet (N seconds in future)` | Router clock behind (no RTC/NTP) → sync NTP; backdating covers ±7 days |
| New TCP hangs after server restart | Old stream on dead QUIC conn → fail-fast RST is by design; app reconnects, new flows work immediately |
| UDP loss under load | Check loss% first: loopback sustains ~234 Mb/s at 0 loss; beyond that is QUIC DATAGRAM backpressure (UDP semantics — app should retransmit) |

---

## Project Layout

```
MyQUIC2/
├── Cargo.toml / Cargo.lock
├── src/
│   ├── lib.rs                 # MQP-1 codec, config, TLS, transport builder
│   └── bin/
│       ├── myquic2-server.rs  # QUIC ingress + dial-out
│       └── myquic2-client.rs  # SOCKS5 ingress + reconnect + UDP dispatcher
├── examples/zero_rtt_probe.rs # 0-RTT end-to-end verification probe
├── config-server.toml / config-client.toml
└── dist/openwrt-x86_64/       # static musl release bins (v1–v4) + sample configs
```

---

## Roadmap

- [ ] SOCKS error REPs + UDP source validation (strict-compliance mode)
- [ ] Ticket-key persistence for 0-RTT across server restarts
- [ ] Per-stream metrics endpoint (Prometheus) — BBR state, GSO batch size, sess table
- [ ] `procd` init script for OpenWrt
- [ ] MQP datagram fragmentation for > 1350 B UDP payloads

---

## License

MIT — see `Cargo.toml` (`license = "MIT"`).
