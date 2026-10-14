<div align="center">

# ⚡ MyQUIC2

**High-performance · TCP and UDP over one blazing-fast QUIC tunnel**

SOCKS5 in · QUIC / TLS 1.3 out · purpose-built minimal MQP-2 protocol · built for speed and low latency

[![Rust](https://img.shields.io/badge/Rust-1.99%2B-dea584?logo=rust&logoColor=white)](#-building)
[![QUIC](https://img.shields.io/badge/QUIC-TLS%201.3-38bdf8)](#-architecture)
[![Performance](https://img.shields.io/badge/Performance-blazing%20fast-f97316)](#-performance-design)
[![Protocol](https://img.shields.io/badge/Protocol-MQP--2-f59e0b)](#-the-mqp-2-protocol)
[![Tests](https://img.shields.io/badge/Tests-215%20passing-16a34a)](#-verification)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20OpenWrt-6366f1)](#-building)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](#-license)

[✨ Highlights](#-highlights) · [🏗️ Architecture](#-architecture) · [🚀 Quick Start](#-quick-start) · [⚙️ Configuration](#-configuration) · [📡 Protocol](#-the-mqp-2-protocol) · [🔒 Security](#-security-model) · [🚀 Performance](#-performance-design) · [📊 Limits](#-limits--memory) · [📦 Building](#-building)

</div>

---

## ✨ Highlights

| | Feature | Detail |
|---|---|---|
| 🚀 | **TCP + UDP, fully covered** | Standard SOCKS5 (`CONNECT` / `UDP ASSOCIATE`); IPv4 / IPv6 / domain targets |
| 🧬 | **Minimal MQP-2 protocol** | Zero extra bytes past the TCP stream head; UDP fragmentation and reassembly up to 8 KiB per payload, plus small-reply batching (≤16 payloads per DATAGRAM) |
| ⚡ | **Extreme performance** | Zero-copy TCP ↔ QUIC pump, BBR + GSO/GRO, reused staging buffers — one frame buffer per outgoing QUIC DATAGRAM frame (a batch frame carries up to 16 payloads); one connection saturates the link, connection count scales linearly |
| 🔀 | **Connection isolation** | 4 TCP connections + 2 class-split UDP connections; UDP never competes with TCP for a congestion window |
| 🛡️ | **Secure by design** | TLS 1.3 + pinned Ed25519 server cert; optional `auth_token` (constant-time) keeps it from being an open relay |
| 🌐 | **Server-side DNS** | Resolved at the exit with 120 s positive / 10 s negative caches and single-flight, so results match the egress |
| ♻️ | **Self-healing** | ~20 s detection after a server crash, second-scale redial, UDP associations recover automatically |
| 📦 | **OpenWrt-ready** | Static musl binaries (four CPU levels, v1–v4), ~4.4 MB each |

---

## 🏗️ Architecture

```mermaid
flowchart LR
    APP["🖥️ Apps (curl / browser / games)"] -->|"SOCKS5 · :1080"| C["🚀 myquic2-client"]
    C -->|"QUIC · TLS 1.3 · MQP-2"| S["🛰️ myquic2-server · :8443"]
    S -->|"TCP / UDP"| NET["🌐 Targets"]
```

| Unit | Source | Role |
|---|---|---|
| `myquic2` (lib) | `src/*.rs` + `src/{mqp,config,tls,transport,dns,udp,tcp,stats,time,sync}/` | MQP-2 codec · config · TLS · transport · DNS · reassembly · stats (`src/lib.rs` is the thin facade) |
| `myquic2-client` | `src/bin/myquic2-client/` | SOCKS5 ingress → connection pool → QUIC egress; reconnect, classified UDP egress, dispatcher-side relay |
| `myquic2-server` | `src/bin/myquic2-server/` | QUIC ingress → token auth → dial-out; session table, reassembly, egress scheduling |

**Data-plane mapping**

- **TCP**: one TCP connection = one QUIC bidirectional stream; everything after the stream head is raw bytes. The SOCKS success reply is optimistic (sent without waiting for the remote dial).
- **UDP**: one SOCKS association = one session id over QUIC DATAGRAMs (unreliable, no head-of-line blocking). Payloads larger than one frame are fragmented and reassembled by the peer — **delivered whole or dropped whole**, never truncated.

---

## 🚀 Quick Start

```sh
# 1️⃣ Start the server (generates a self-signed Ed25519 certificate on first run)
./myquic2-server --config config-server.toml

# 2️⃣ Copy only server-cert.pem (the certificate — never the key) to the client side

# 3️⃣ Start the client
./myquic2-client --config config-client.toml

# 4️⃣ Use it (same story for browser / system proxy settings)
curl --socks5 127.0.0.1:1080 https://example.com
```

> 💡 Control logging with `RUST_LOG`: `RUST_LOG=myquic2_client=debug,myquic2_server=debug`

---

## ⚙️ Configuration

<details>
<summary><b>Server <code>config-server.toml</code></b> — click to expand</summary>

<br>

```toml
listen = "[::]:8443"           # QUIC ingress (dual-stack)
cert_file = "server-cert.pem"  # self-signed, generated on first run
key_file = "server-key.pem"
server_name = "test.com"       # certificate SAN + expected SNI
congestion = "bbr"             # bbr | cubic
keep_alive_secs = 5            # 1–300; idle = max(3x, 15s)
# dns_ip_preference = "ipv6"   # ipv6 (default) | ipv4: family tried first for resolved targets
allow_private = false          # keep false on public exit nodes
auth_token = ""                # shared secret; must match the client (empty = no auth; firewall otherwise)

# max_connections = 4096       # connection cap (defaults to 256 without a token)
# max_peer_memory_mb = 512     # cap on peer-pinnable memory (UDP session pool charged first)
```

</details>

<details>
<summary><b>Client <code>config-client.toml</code></b> — click to expand</summary>

<br>

```toml
socks_listen = "[::]:1080"
server_addr = "127.0.0.1:8443"
server_name = "test.com"              # must match the certificate SAN
server_cert_file = "server-cert.pem"  # pinned server certificate
congestion = "bbr"
keep_alive_secs = 5
reconnect_timeout_secs = 5
# dns_ip_preference = "ipv6"           # ipv6 (default) | ipv4: family tried first (incl. server_addr)
auth_token = ""                       # must match the server
quic_conns = 4                        # TCP pool size, 1–8 (UDP has its own connections)

# udp_split = true                    # split interactive/bulk UDP egress (default on)
# udp_fail_closed = true              # drop rather than degrade when UDP has no connection
# interactive_ports = [53, 123, 3478, 3479, 3480, 3481]
```

</details>

| Note | Detail |
|---|---|
| 🔐 `auth_token` | Strongly recommended; an empty token makes the server an open relay (firewall isolation only). At most 256 B on the wire (a longer token can never authenticate and is rejected at startup) |
| 🧵 `quic_conns` | TCP pool size; interactive ports (DNS/NTP/STUN) pin to slot 0; UDP gets 2 class-split connections |
| 🛡️ `allow_private` | Whether private/loopback targets may be dialed (default `false`) |
| 🌐 `dns_ip_preference` | Family tried first for resolved names: `"ipv6"` (default, RFC 6724-style) or `"ipv4"`; applies to exit-side targets and the client's `server_addr` |
| 🧮 `max_peer_memory_mb` | Optional admission cap. The ~1.06 GiB UDP session pool is charged first, then the remainder is divided by the 8.25 MiB per-connection transport figure — see [Limits & memory](#-limits--memory) |

---

## 📡 The MQP-2 Protocol

```text
TCP open (stream head, once)   atyp | addr | port                            -> reply: "MQ" | 0x00 | bound address
UDP datagram                   0x02 | sess u32le | atyp | addr | port | payload
UDP fragment                   0x05 | sess u32le | id u16le | idx u8 | total u8 | atyp | addr | port | chunk
UDP batch                      0x06 | sess u32le | atyp | addr | port | count u8 | (len u16le | payload)*
Auth                           uni stream carrying the token bytes verbatim (sent at 1-RTT, never in 0-RTT)
```

- 🎯 Address encoding mirrors SOCKS5 exactly (IPv4 / IPv6 / domain), so IP headers can be reused byte-for-byte.
- 🧩 Every fragment is self-describing (it carries the full address), so out-of-order arrival reassembles directly; losing any fragment drops the whole datagram (UDP semantics — no retransmission).
- 📦 A batch frame packs up to 16 consecutive same-destination payloads of ≤512 B each into one DATAGRAM (one quinn lock + one AEAD instead of N): the reply path stages small target replies, the association path pairs consecutive small app datagrams. Both flush at burst end, so nothing waits; a frame that does not fit is split back into single datagrams.
- ⏱️ A partial expires after 2 s, and reassembly memory is capped at 256 KiB per connection. That budget covers the in-flight chunks *and* the compact per-generation replay guards used to refuse stale id reuse; overflow reclaims the guards first and only falls back to evicting the oldest in-flight partial when no guard is left.
- 🔒 The token is sent at 1-RTT only: 0-RTT early data is replayable, so a bearer secret never rides it.

---

## 🔒 Security Model

- **Server identity**: the client pins the self-signed Ed25519 certificate (always on).
- **Client identity**: an optional shared-secret `auth_token`, compared in constant time; no stream or datagram is accepted before it passes.
- **Egress policy**: with `allow_private = false`, private / loopback / CGNAT / documentation and other non-global ranges are filtered (including IPv4 embedded in NAT64, IPv4-mapped, IPv4-translated and IPv4-compatible IPv6 forms).
- **UDP anti-spoofing**: the client accepts app datagrams only from the SOCKS control connection's peer **IP** (ports are not pinned — RFC 1928 clients may send from another port) and then locks the first full `(ip, port)` for reply delivery; the server validates reply sources against a 16-entry per-session **IP** allowlist (a target answering from a different port still gets through, by design).

---

## 🚀 Performance Design

- **Hot paths kept razor-thin**: zero-copy TCP ↔ QUIC pump (`write_chunk`/`read_chunks` hand owned buffers to quinn, one vectored write to TCP), lock-free thread-local memos (DNS, session, egress), and reused staging buffers. A relayed UDP payload costs **one frame allocation per outgoing QUIC DATAGRAM frame** — quinn's `send_datagram` takes an owned `Bytes` and frees it on its own task, so it cannot be pooled — plus, at most, one copy into a per-session/per-association staging buffer that is never reallocated. Batching amortizes the frame over up to 16 payloads; a fragmented payload costs one frame per fragment.
- **Modern congestion control**: BBR by default (Cubic as an escape hatch), ECN + adaptive PMTU, and GSO/GRO batched I/O — a single connection can saturate the link.
- **Built for high latency**: default transport parameters are tuned for long-haul links and prioritize low queued latency.
- **Connection-level isolation**: TCP, interactive UDP and bulk UDP each keep their own congestion window — no bandwidth fights, no queuing behind each other.
- **Socket buffers that hold on Linux**: the QUIC endpoint asks for 4 MB and session sockets 64 KiB of `SO_RCVBUF`/`SO_SNDBUF` (`MYQUIC2_SESS_SOCKET_BUF=32768` on RAM-tight routers, `=131072` for the zero-loss point the burst test measured; clamped to 16 KiB–4 MiB); where `net.core.{r,w}mem_max` clamps that (OpenWrt ships ~208 KiB), the service retries with `SO_*BUFFFORCE` whenever it holds `CAP_NET_ADMIN` — root-run OpenWrt included — so burst headroom survives stock sysctls; a clamp warning names the sysctl otherwise.
- **Signal-driven shutdown**: SIGTERM/SIGINT closes the QUIC endpoint at once, so peers receive CONNECTION_CLOSE and redial within seconds instead of waiting out the ~20 s silence watchdog; in-flight flows restart through the reconnect loops (no drain window).
- **Tunable ceiling**: widen the transport windows on both ends to match your link's BDP and push throughput higher; pure TOML, no rebuild required — see [Limits & memory](#-limits--memory).

---

## 📊 Limits & memory

Numbers are for the shipped defaults (2/4/2 MB windows, 64 KiB session buffers); each one comes from a named constant in the source, and the constants — windows, caps, admission arithmetic — are pinned by unit tests.

| Quantity | Default | Where it comes from |
|---|---|---|
| Single-flow throughput ceiling | ~114 Mb/s @ 140 ms RTT | default `stream_receive_window` 2 MB / `send_window` 2 MB — the window, not the congestion controller, is the ceiling on a high-BDP link |
| Opt-in high-throughput preset | ~240 Mb/s @ 140 ms (4/8/4 MB), ~300 Mb/s @ 140 ms (8/16/8 MB) | set `stream_receive_window_mb` / `receive_window_mb` / `send_window_mb` (and `ack_threshold = 8`, `max_ack_delay_ms = 10`) on **both** ends |
| Peer-pinnable memory per admitted connection | 8.25 MiB | receive window + send budget + both DATAGRAM buffers + the 256 KiB reassembly budget |
| Peer-pinnable memory, UDP session pool (process-wide) | ~1.06 GiB | `MAX_SESSIONS_GLOBAL` 8192 × (2 × 64 KiB socket caps + 8 KiB reader buffer); lower `MYQUIC2_SESS_SOCKET_BUF` to shrink it |
| Worst case, no memory budget (default preset) | ~33 GiB transport + ~1.06 GiB session pool | 4096 connections × 8.25 MiB |
| Worst case, no memory budget (opt-in 8/16/8 MB preset) | ~105 GiB transport + ~1.06 GiB session pool | 4096 connections × 26.25 MiB — `max_peer_memory_mb` is the only thing that bounds this (a 4096 MiB budget admits ~114 connections) |
| UDP sessions | 8192 process-wide, 4032 per client process | global semaphore, and `fair_sess_cap()` = `clamp(8192 / session-holding connections, 1024, 4096)` per connection |
| Concurrent TCP flows | 8192 per client, 16384 stream tasks process-wide on the server | `MAX_SOCKS_CONNS` / `MAX_STREAM_TASKS`, with a 1024 floor per connection |
| QUIC connections | 4096 with a token, 256 without | `max_connections` / `max_peer_memory_mb`; the tokenless cap is what keeps an unauthenticated peer from pinning the full transport budget (256 × 8.25 MiB ≈ 2.06 GiB) |

`max_peer_memory_mb` charges the session pool **once**, globally, and only then divides what is left by the per-connection figure — so the startup log's "worst case" line is the memory this process can actually pin, not just the transport share. A budget at or below the session pool admits exactly one connection and says so explicitly in the log.

---

## 📦 OpenWrt Deployment

```sh
# Built by the cross-compile loop below; the repository ships only the samples
# in dist/openwrt-x86_64/ (the binaries are gitignored — CI rebuilds them).
scp dist/openwrt-x86_64/myquic2-{server,client}-v1 root@router:/usr/bin/
# Rename + chmod +x on the target; always use absolute paths in the configs
```

| CPU level | When to use |
|---|---|
| **v1** | Any x86-64 (N100 / J4125 and friends — the safe default) |
| v2 / v3 / v4 | Require SSE4.2 / AVX2 / AVX512; a mismatch dies with `Illegal instruction` |

---

## 🗂️ Project Layout

```text
MyQUIC2/
├── src/
│   ├── lib.rs                 # thin facade: module declarations + re-exports
│   ├── mqp/                   # MQP-2 codec (address / datagram / fragment / batch / ACK)
│   ├── config/                # TOML config schema and transport parameters
│   ├── tls/                   # certificate generation + client / server TLS
│   ├── transport/             # QUIC transport builder (BBR / GSO / windows / limits)
│   ├── dns/                   # moka-backed caches · single-flight · memos · egress policy
│   ├── time/ · sync/          # clocks (mono / coarse) · lock helpers
│   ├── stats/                 # drop / relay counters and rate-limited warnings
│   ├── udp/                   # send path · fragmenter · reassembler · last-hop batching · retry pool
│   ├── tcp/                   # TCP ↔ QUIC pump
│   └── bin/
│       ├── myquic2-client/    # pool · egress · hub · dispatcher · socks · assoc · auth · reporter
│       └── myquic2-server/    # accept · auth · table · memo · forward · reader · tcp · pin · reporter
├── examples/                  # zero_rtt_probe · hotpath_bench
└── dist/openwrt-x86_64/       # sample configs (the v1–v4 musl binaries are build outputs, gitignored)
```

---

## ✅ Verification

- `cargo test --all-targets`: **215 passed / 0 failed**
- `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`: clean (no cargo features are defined)
- Real binaries, end to end: TCP 1 MiB verified byte-for-byte ✅ · UDP sweep 8–8000 B (fragment path included) with 0 lost ✅ · `kill -9` + restart: automatic detection and redial, TCP and UDP green again ✅
- UDP N=1 soak (`hotpath_bench udpps`, single association, IPv4 target, macOS dev box): open-loop 128 B blast delivers **~40k recv pps** at ~66k sent pps (was ~2.6k recv pps before the last-hop batching pass); closed-loop windowed holds **~30k pps / 0 loss**; `udpraw` loopback control ~82k pps
- Cost-critical invariants are pinned by unit tests, not just by the numbers above: byte-identity of every encoder fast path against its reference implementation, one address validation per steady destination (`prefix_cache_steady_state_one_validation`), exact reassembly/`held` accounting on every operation (including that a completed generation costs only its compact replay guard), the batch decoder's up-front validation over every truncated prefix, the reply/uplink staging paths with their fallback and exactly-once drop accounting, and the admission arithmetic.

---

## 🛠️ Building

```sh
cargo build --release          # native
cargo test --all-targets       # tests
```

<details>
<summary><b>Cross-compile static musl for OpenWrt (v1–v4)</b> — click to expand</summary>

<br>

```sh
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild   # requires zig on PATH

# Build one CPU level at a time (sequentially, so they cannot overwrite each other)
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

</details>

---

## 📄 License

MIT © MyQUIC2

<div align="center">
<sub>Built with 🦀 Rust</sub>
</div>
