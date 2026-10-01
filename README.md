<div align="center">

# ⚡ MyQUIC2

**High-performance · TCP and UDP over one blazing-fast QUIC tunnel**

SOCKS5 in · QUIC / TLS 1.3 out · purpose-built minimal MQP-2 protocol · built for speed and low latency

[![Rust](https://img.shields.io/badge/Rust-1.88%2B-dea584?logo=rust&logoColor=white)](#-building)
[![QUIC](https://img.shields.io/badge/QUIC-TLS%201.3-38bdf8)](#-architecture)
[![Performance](https://img.shields.io/badge/Performance-blazing%20fast-f97316)](#-performance-design)
[![Protocol](https://img.shields.io/badge/Protocol-MQP--2-f59e0b)](#-the-mqp-2-protocol)
[![Tests](https://img.shields.io/badge/Tests-188%20passing-16a34a)](#-verification)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20OpenWrt-6366f1)](#-building)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](#-license)

[✨ Highlights](#-highlights) · [🏗️ Architecture](#-architecture) · [🚀 Quick Start](#-quick-start) · [⚙️ Configuration](#-configuration) · [📡 Protocol](#-the-mqp-2-protocol) · [🚀 Performance](#-performance-design) · [📦 Building](#-building)

</div>

---

## ✨ Highlights

| | Feature | Detail |
|---|---|---|
| 🚀 | **TCP + UDP, fully covered** | Standard SOCKS5 (`CONNECT` / `UDP ASSOCIATE`); IPv4 / IPv6 / domain targets |
| 🧬 | **Minimal MQP-2 protocol** | Zero extra bytes past the TCP stream head; UDP fragmentation and reassembly up to 8 KiB per payload |
| ⚡ | **Extreme performance** | Hand-written zero-copy hot paths + BBR + GSO/GRO; one connection saturates the link, connection count scales linearly |
| 🔀 | **Connection isolation** | 4 TCP connections + 2 class-split UDP connections; UDP never competes with TCP for a congestion window |
| 🛡️ | **Secure by design** | TLS 1.3 + pinned Ed25519 server cert; optional `auth_token` (constant-time) keeps it from being an open relay |
| 🌐 | **Server-side DNS** | Resolved at the exit with 60 s positive/negative caches and single-flight, so results match the egress |
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
| `myquic2` (lib) | `src/lib.rs` | MQP-2 codec · config · TLS · transport · DNS · reassembly · stats |
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
allow_private = false          # keep false on public exit nodes
auth_token = ""                # shared secret; must match the client (empty = no auth; firewall otherwise)

# max_connections = 4096       # connection cap (defaults to 256 without a token)
# max_peer_memory_mb = 512     # cap on peer-pinnable memory
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
auth_token = ""                       # must match the server
quic_conns = 4                        # TCP pool size, 1–8 (UDP has its own connections)

# udp_split = true                    # split interactive/bulk UDP egress (default on)
# udp_fail_closed = true              # drop rather than degrade when UDP has no connection
# interactive_ports = [53, 123, 3478, 3479, 3480, 3481]
```

</details>

| Note | Detail |
|---|---|
| 🔐 `auth_token` | Strongly recommended; an empty token makes the server an open relay (firewall isolation only) |
| 🧵 `quic_conns` | TCP pool size; interactive ports (DNS/NTP/STUN) pin to slot 0; UDP gets 2 class-split connections |
| 🛡️ `allow_private` | Whether private/loopback targets may be dialed (default `false`) |

---

## 📡 The MQP-2 Protocol

```text
TCP open (stream head, once)   atyp | addr | port                            -> reply: "MQ" | 0x00 | bound address
UDP datagram                   0x02 | sess | atyp | addr | port | payload
UDP fragment                   0x05 | sess | id | idx | total | atyp | addr | port | chunk
Auth                           uni stream (type 0x02) carrying the token (sent at 1-RTT, never in 0-RTT)
```

- 🎯 Address encoding mirrors SOCKS5 exactly (IPv4 / IPv6 / domain), so IP headers can be reused byte-for-byte.
- 🧩 Every fragment is self-describing (it carries the full address), so out-of-order arrival reassembles directly; losing any fragment drops the whole datagram (UDP semantics — no retransmission).
- ⏱️ A partial expires after 2 s, and reassembly memory is capped at 256 KiB per connection (overflow reclaims replay guards first and never touches in-flight payloads).
- 🔒 The token is sent at 1-RTT only: 0-RTT early data is replayable, so a bearer secret never rides it.

---

## 🔒 Security Model

- **Server identity**: the client pins the self-signed Ed25519 certificate (always on).
- **Client identity**: an optional shared-secret `auth_token`, compared in constant time; no stream or datagram is accepted before it passes.
- **Egress policy**: with `allow_private = false`, private / loopback / CGNAT / documentation and other non-global ranges are filtered (including NAT64-embedded IPv4).
- **UDP anti-spoofing**: the client locks the app's first `(ip, port)`; the server validates reply sources against a 16-entry per-session host allowlist.

---

## 🚀 Performance Design

- **Hot paths kept razor-thin**: zero-copy TCP ↔ QUIC pump, lock-free thread-local memos, no per-packet allocation — the proxy itself adds almost no overhead.
- **Modern congestion control**: BBR by default (Cubic as an escape hatch), ECN + adaptive PMTU, and GSO/GRO batched I/O — a single connection can saturate the link.
- **Built for high latency**: default transport parameters are tuned for long-haul links and prioritize low queued latency.
- **Connection-level isolation**: TCP, interactive UDP and bulk UDP each keep their own congestion window — no bandwidth fights, no queuing behind each other.
- **Socket buffers that hold on Linux**: the QUIC endpoint asks for 4 MB and session sockets 64 KiB of `SO_RCVBUF`/`SO_SNDBUF` (`MYQUIC2_SESS_SOCKET_BUF=32768` on RAM-tight routers, `=131072` for the zero-loss point the burst test measured); where `net.core.{r,w}mem_max` clamps that (OpenWrt ships ~208 KiB), the service retries with `SO_*BUFFFORCE` whenever it holds `CAP_NET_ADMIN` — root-run OpenWrt included — so burst headroom survives stock sysctls; a clamp warning names the sysctl otherwise.
- **Signal-driven shutdown**: SIGTERM/SIGINT closes the QUIC endpoint at once, so peers receive CONNECTION_CLOSE and redial within seconds instead of waiting out the ~20 s silence watchdog; in-flight flows restart through the reconnect loops (no drain window).
- **Tunable ceiling**: widen the transport windows on both ends to match your link's BDP and push throughput higher; pure TOML, no rebuild required.

---

## 📦 OpenWrt Deployment

```sh
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
│   ├── mqp/                   # MQP-2 codec (address / datagram / fragment / ACK)
│   ├── config/                # TOML config schema and transport parameters
│   ├── tls/                   # certificate generation + client / server TLS
│   ├── transport/             # QUIC transport builder (BBR / GSO / windows / limits)
│   ├── dns/                   # sharded caches · single-flight · memos · egress policy
│   ├── time/ · sync/          # clocks (mono / coarse) · lock helpers
│   ├── stats/                 # drop / relay counters and rate-limited warnings
│   ├── udp/                   # send path · fragmenter · reassembler · retry pool
│   ├── tcp/                   # TCP ↔ QUIC pump
│   └── bin/
│       ├── myquic2-client/    # pool · egress · hub · dispatcher · socks · assoc · auth · reporter
│       └── myquic2-server/    # accept · auth · table · memo · forward · reader · tcp · pin · reporter
├── examples/                  # zero_rtt_probe · hotpath_bench
└── dist/openwrt-x86_64/       # static musl artifacts (v1–v4) + sample configs
```

---

## ✅ Verification

- `cargo test --all-targets`: **188 passed / 0 failed** (187 with `--no-default-features`)
- `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`: clean on both feature sets
- Real binaries, end to end: TCP 1 MiB verified byte-for-byte ✅ · UDP sweep 8–8000 B (fragment path included) with 0 lost ✅ · `kill -9` + restart: automatic detection and redial, TCP and UDP green again ✅
- UDP N=1 soak (`hotpath_bench udpps`, single association, macOS dev box): open-loop 128 B blast delivers **~40k recv pps** at ~66k sent pps (was ~2.6k recv pps before the last-hop batching pass); closed-loop windowed holds **~30k pps / 0 loss**; `udpraw` loopback control ~82k pps

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
