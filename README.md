<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/hero-dark.svg">
  <img src="assets/readme/hero-light.svg" alt="MyQUIC2 — the small-packet QUIC proxy. SOCKS5 in, QUIC/TLS 1.3 out, MQP-3 wire rev2 in between." width="100%">
</picture>

[![Release](https://img.shields.io/badge/Release-v0.2.1-16a34a?style=flat-square)](https://github.com/Terutoki/MyQUIC2/releases/latest)
[![Tests](https://img.shields.io/badge/Tests-424_passing-16a34a?style=flat-square)](#-verification)
[![CI](https://github.com/Terutoki/MyQUIC2/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/Terutoki/MyQUIC2/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.99%2B-dea584?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![QUIC](https://img.shields.io/badge/QUIC-TLS_1.3-38bdf8?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc9000)
[![Protocol](https://img.shields.io/badge/Protocol-MQP--3-f59e0b?style=flat-square)](#-mqp-3-rev2-wire)
[![Platform](https://img.shields.io/badge/Platform-Linux_%7C_macOS_%7C_OpenWrt-6366f1?style=flat-square)](#-install)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](https://github.com/Terutoki/MyQUIC2/blob/main/LICENSE)

**SOCKS5 in · QUIC / TLS 1.3 out · MQP-3 rev2 in between**

[Architecture](#-architecture) · [Wire](#-mqp-3-rev2-wire) · [Full duplex](#-full-duplex) · [Stager](#-cross-session-stager) · [Performance](#-performance) · [Security](#-security) · [Mermaid atlas](#-mermaid-atlas) · [Install](#-install) · [Quick start](#-quick-start) · [Verify](#-verification)

</div>

> [!IMPORTANT]
> **Wire-breaking by design.** This tree speaks **MQP-3 wire rev2**. It does not interoperate with v0.2.0 (v3 wire) or v0.1.x / MQP-2. Upgrade client and server together; mixed-version deployment is not supported.
>
> The protocol is still called **MQP-3**. The revision lives in `CTL HELLO/CAPS wire_ver = 2`, not in the name. There is no MQP-4.

---

## ✨ What it is

A SOCKS5 proxy made of **two binaries, one wire, and very little ceremony**.

- **TCP is a QUIC stream.** The SOCKS5 success reply is optimistic; payload bytes are pumped with zero-copy buffers and borrowed QUIC halves.
- **UDP is an MQP-3 rev2 DATAGRAM plane.** Connection-scoped flow ids, 2 B steady headers, full-duplex flows, cross-association TRAIN packing, compact 8 KiB FRAG.
- **One client, one server, one config each.** No mixed-version negotiation, no payload compression, no hidden control stream.
- **UDP stays unreliable.** A lost fragment drops that payload; a lost TRAIN drops the payloads it carried. Bounded reassembly and stager queues cap the fate sharing.

## 🧭 Architecture

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/architecture-dark.svg">
  <img src="assets/readme/architecture-light.svg" alt="Architecture: SOCKS5 client pool, QUIC/TLS tunnel and MQP-3 rev2 data plane, admission-first server ingress" width="100%">
</picture>
</p>

- **Pool-first client.** Every pool slot owns a QUIC endpoint, a UDP socket and a pinned runtime. TCP and UDP egress are isolated; the thread-local egress memo is lock-free.
- **One wire, two transports.** TCP rides a QUIC stream; UDP rides MQP-3 rev2 DATAGRAMs. Shared pieces: TLS 1.3, BBR, PMTU discovery, GSO/GRO.
- **Admission-first server.** `SO_REUSEPORT` ingress endpoints, token auth, memory/connection admission, one 64 KiB session socket per association.

## 📡 MQP-3 rev2 wire

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/wire-dark.svg">
  <img src="assets/readme/wire-light.svg" alt="MQP-3 rev2 frames: DATA 2 B, DATA OPEN/INLINE, TRAIN same/dict, FRAG 8 B, CTL" width="100%">
</picture>
</p>

- **`DATA` — 2 B steady.** A connection-scoped monotonic `wire_id` and the payload. No session, no address, no length.
- **`DATA OPEN / INLINE` — the first frame.** Self-describing `(session, address)`; OPEN repeats until ACKed. INLINE is the table-full fail-safe.
- **`TRAIN` — one frame, many payloads.** Same-flow: 3 B header + 1 B/item. Dict form mixes flows and associations in one DATAGRAM.
- **`FRAG` — 8 B steady.** Payloads up to 8 KiB; `(wire_id, frag_id)` reassembly; context only on the first fragment.
- **First-byte safety.** All rev2 frames start with `0x0X`, disjoint from MQP-2 and the v0.2.0 wire; old parsers drop them safely. A non-rev2 peer fails fast at HELLO/CAPS.

**Implementation contract:** [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md)

## 🔁 Full duplex

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/duplex-dark.svg">
  <img src="assets/readme/duplex-light.svg" alt="Full-duplex MQP-3 rev2 lifecycle: client-owned and server-owned flows, domain rebind, SESS_CLOSE" width="100%">
</picture>
</p>

- **Both endpoints can open a flow.** Client-owned and server-owned ids share one table. `FLOW_ACK` confirms; a compressed downlink is also an implicit ACK.
- **Everything worth compressing compresses.** Domain targets, pure-uplink flows, and — with `udp_full_cone = true` — server-owned flows for unsolicited sources. The app replies on the same id.
- **Source changes rebind the same id.** One `OPEN|SRC` teaches the actual reply source; the client writes it into the SOCKS5 reply header, unchanged for apps.
- **Optimistic first packet.** A new UDP connection does not wait for CAPS: the first payload can leave immediately. The server buffers up to 8 pre-HELLO frames (16 KiB) and releases them in order after a valid HELLO. Wrong-version HELLOs never release the buffer.
- **Close means close.** `SESS_CLOSE` / `FLOW_CLOSE` purge bindings, queued stager items and in-flight partials on both ends.

## 🚀 Cross-session stager

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/stager-dark.svg">
  <img src="assets/readme/stager-light.svg" alt="Cross-session stager packs payloads from several associations into one round-robin TRAIN dict" width="100%">
</picture>
</p>

One stager per QUIC connection, not per association. Small payloads from every app share a per-session FIFO with a round-robin cursor; one `TRAIN dict` can carry them all. Bounded queue, exact drop accounting, per-session fairness, `CAPS.max_train_items` honored.

## 📊 Performance

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/performance-dark.svg">
  <img src="assets/readme/performance-light.svg" alt="Measured header sizes, DATAGRAM send reduction and loopback smoke results" width="100%">
</picture>
</p>

- **Steady UDP header:** 5–6 B → **2 B**. **FRAG header:** 18–30 B → **8 B**. **TRAIN item:** 2 B → **1 B**.
- **8 associations × 1000 pps × 128 B × 65 s:** 519,992 / 519,990 delivered, **0.000 % loss**, **0.743 frames/payload** (≈ **−25 %** client DATAGRAM sends vs the v0.2.0 wire).
- **All-size sweep:** 8 B … 8 KiB **ALL OK**. **Full duplex:** 30,000 / 30,000. **Paced:** 325,000 / 325,000.
- These are macOS loopback measurements on release binaries. The Linux 2–4 core + `tc netem` matrix is the deployment gate: [`scripts/linux-bench-matrix.sh`](scripts/linux-bench-matrix.sh).

## 🛡️ Security

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/security-dark.svg">
  <img src="assets/readme/security-light.svg" alt="Security model: TLS 1.3, token auth, per-packet authorization, opt-in full-cone" width="100%">
</picture>
</p>

- **Every packet is authorized.** A compressed id resolves only a live binding; unknown ids drop that item, never guess a route. SSRF/private-IP filtering is unchanged.
- **Reply-source policy.** A 16-entry per-session IP allowlist plus the exact live flow mapping; `udp_full_cone` is opt-in, off by default and warned at startup.
- **Transport and token.** TLS 1.3 with ALPN `h3`; the bearer token is sent only on a 1-RTT uni stream, never in 0-RTT. Token comparison is constant-time.
- **No payload compression.** Encrypted or random UDP is left untouched; gains are framing, fewer frames and fewer sends.

## 📦 Install

**Latest published release: [v0.2.1](https://github.com/Terutoki/MyQUIC2/releases/latest).** Assets are profile-guided (PGO) builds made from the tag by the release workflow.

- `myquic2-v0.2.1-x86_64-unknown-linux-musl.tar.gz` — static musl build, runs on any x86-64 Linux.
- `myquic2-v0.2.1-x86_64-unknown-linux-gnu.tar.gz` — glibc ≥ 2.36 (Debian 12+, Ubuntu 23.04+).
- `myquic2-v0.2.1-openwrt-x86_64-v1.tar.gz` — OpenWrt safe default for every x86-64 CPU.
- `myquic2-v0.2.1-openwrt-x86_64-v2..v4.tar.gz` — SSE4.2 / AVX2 / AVX512 tuned (a mismatch dies with `Illegal instruction`).
- `SHA256SUMS` — checksums for every asset.

```sh
sha256sum -c SHA256SUMS
```

Each tarball contains `myquic2-server`, `myquic2-client` and sample configs. Build from source with Rust 1.99+:

```sh
cargo build --release --bins
# target/release/myquic2-server
# target/release/myquic2-client
```

> [!NOTE]
> `v0.2.1` is the latest published release. The `main` branch adds the optimistic first-packet path described above; those changes ship in the next release. macOS and non-x86-64 targets build from source.

## ⚡ Quick start

```sh
# 1. Build
cargo build --release --bins

# 2. Configure
#    config-server.toml: listen, auth_token, server_name, cert/key
#    config-client.toml: server_addr, auth_token (same secret), socks_listen
#    Set a non-empty auth_token on both sides.

# 3. Run
./target/release/myquic2-server --config config-server.toml
./target/release/myquic2-client --config config-client.toml

# SOCKS5 endpoint: 127.0.0.1:1080 (TCP streams + UDP ASSOCIATE)
```

The client and server must run the **same revision**. Certificates are generated on first server start; see [`config-server.toml`](config-server.toml) and [`config-client.toml`](config-client.toml) for every documented key.

## ⚙️ Configuration

- **Wire and memory:** `initial_mtu` (default 1200 = QUIC floor, clamp 1200–1472), `quic_endpoints` (server ingress parallelism), `max_peer_memory_mb` (admission cap), `udp_full_cone` (server opt-in).
- **UDP scheduling:** `udp_split`, `udp_egress_conns`, `max_udp_assocs`, `interactive_ports`, `udp_bulk_ports`, `udp_fail_closed`.
- **Environment knobs:** `MYQUIC2_SESS_SOCKET_BUF`, `MYQUIC2_BUSY_POLL`, `MYQUIC2_TCP_NOTSET_LOWAT`, `MYQUIC2_SHARD_RUNTIME`.

The sample configs are the reference; comments explain defaults and trade-offs.

## ✅ Verification

- **424 tests** on the macOS dev box (lib 199 + client 124 + server 101).
- **428 tests** in the Linux CI-equivalent environment (Linux adds 4 `cfg`-gated tests).
- **GitHub CI:** rustfmt, Clippy `-D warnings`, Test, musl build and glibc build all green.
- **Release-binary smoke:** `udppaced`, `udpbidir`, `udpsweep` 8 B–8 KiB, `udpfanout`, 8-association `udpmultipaced` — all **0.000 % loss**.

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check

# Linux target matrix: netem 70/140 ms, 0/0.5/2 % loss
sudo scripts/linux-bench-matrix.sh
```

## 🧜 Mermaid atlas

The original v0.2.0 README diagram set is preserved here — refreshed for the
rev2 wire where the old labels described v3 — and extended with new deep dives.
Every block below renders natively on GitHub.

### 🏗️ System & modules

#### System overview (restored)

_The original high-level map, kept as a fast orientation._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
    subgraph EDGE["💻  Client edge"]
        direction TB
        APPS["🧑‍💻 Apps<br/>curl · browser · games"]
        SOCKS["🧦 SOCKS5 ingress<br/>CONNECT · UDP ASSOCIATE<br/>:1080"]
        POOL["🎰 ConnPool<br/>4 × TCP + 3 × UDP slots<br/>one Endpoint per slot"]
        APPS -->|"TCP / UDP"| SOCKS
        SOCKS -->|"5 s budgets"| POOL
    end
    subgraph TUNNEL["⚡  QUIC tunnel"]
        direction TB
        TLS["🔐 TLS 1.3<br/>pinned Ed25519"]
        MQP["📡 MQP-3 rev2<br/>streams · DATAGRAMs · flows · TRAIN · FRAG"]
        CC["🚄 BBR + ECN<br/>GSO / GRO"]
        TLS --- MQP --- CC
    end
    subgraph EXIT["🛰️  Exit side"]
        direction TB
        ING["🚪 QUIC ingress<br/>:8443 · SO_REUSEPORT<br/>1 endpoint / core · ≤ 8"]
        AUTH["🔑 token gate<br/>5 s / 5 s / 10 s"]
        ROUTE["🧭 dispatch<br/>TCP dial-out · UDP sessions"]
        TARGETS["🎯 Targets<br/>TCP / UDP"]
        ING --> AUTH
        AUTH --> ROUTE
        ROUTE --> TARGETS
    end
    EDGE ==>|"① 4 TCP + 3 UDP<br/>QUIC connections"| TUNNEL
    TUNNEL ==>|"② encrypted<br/>MQP-3 frames"| EXIT
    style EDGE fill:#f0fdf4,stroke:#34d399,stroke-width:2px,color:#14532d
    style TUNNEL fill:#eef2ff,stroke:#818cf8,stroke-width:2px,color:#1e1b4b
    style EXIT fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef app fill:#ffffff,stroke:#94a3b8,stroke-width:1.5px,color:#0f172a
    classDef edge fill:#dcfce7,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef tun fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef exit fill:#ffedd5,stroke:#ea580c,stroke-width:2px,color:#7c2d12
    class APPS app
    class SOCKS,POOL edge
    class TLS,MQP,CC tun
    class ING,AUTH,ROUTE,TARGETS exit
```

#### End-to-end module map (restored)

_Module boundaries: client, server, codec, transport and stats._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
    subgraph CLI["🚀  myquic2-client · pool-first"]
        direction TB
        SOCKS["🧦 socks.rs<br/>CONNECT / ASSOCIATE"]
        POOL["🎰 pool.rs<br/>ConnPool · per-slot Endpoint<br/>selection-time path health"]
        EGRESS["🧭 egress.rs<br/>SharedEgress + thread memo"]
        HUB["🗂️ hub.rs<br/>UdpHub · 4032 sessions"]
        ASSOC["🔁 assoc.rs<br/>app ↔ QUIC relay"]
        DISP["📥 dispatcher.rs<br/>per-slot DATAGRAM reader"]
        AUTHC["📞 auth.rs<br/>dial · backoff · watchdog"]
        SOCKS --> POOL
        SOCKS --> ASSOC
        POOL --> AUTHC
        ASSOC --> HUB
        HUB --> DISP
        EGRESS -.-> ASSOC
    end
    subgraph SRV["🛰️  myquic2-server · admission-first"]
        direction TB
        ACC["🚪 accept.rs<br/>accept + handle_conn"]
        AUTHX["🔑 auth.rs<br/>constant-time token gate"]
        TABLE["🗃️ table.rs<br/>ShardedSessTable · 8 shards"]
        FWD["➡️ forward.rs + reader.rs<br/>uplink · connection stager reply"]
        TCPS["🌐 tcp.rs<br/>happy-eyeballs dial-out"]
        PIN["📌 pin.rs<br/>ConnPin · DestMemo"]
        ACC --> AUTHX
        AUTHX --> TABLE
        TABLE --> FWD
        FWD --> TCPS
        FWD -.-> PIN
    end
    CLI ==>|"QUIC streams ⟷ DATAGRAMs<br/>TLS 1.3 · MQP-3"| SRV
    style CLI fill:#f0fdf4,stroke:#34d399,stroke-width:2px,color:#14532d
    style SRV fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef cli fill:#dcfce7,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef cli2 fill:#ecfeff,stroke:#0891b2,stroke-width:1.5px,color:#164e63
    classDef srv fill:#ffedd5,stroke:#ea580c,stroke-width:2px,color:#7c2d12
    class SOCKS,POOL,AUTHC cli
    class EGRESS,HUB,ASSOC,DISP cli2
    class ACC,AUTHX,TABLE,FWD,TCPS,PIN srv
```

#### Shared library layers (restored)

_The `src/` layers from primitives up to the two binaries._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
    subgraph L1["🪝  primitives · src/lib.rs facade"]
        direction LR
        S1["dual-stack UDP<br/>SO_REUSEPORT · SO_*BUFFORCE"]
        S2["shutdown_signal<br/>SIGTERM / SIGINT"]
        S3["packet clock<br/>coarse · mono"]
        S1 ~~~ S2 ~~~ S3
    end
    subgraph L2["🧬  codecs · transport · policy"]
        direction LR
        C1["MQP-3 rev2 codec<br/>DATA · TRAIN · FRAG · CTL"]
        C2["TLS 1.3<br/>pinned Ed25519 · 0-RTT"]
        C3["config + admission<br/>tuning · memory math"]
        C1 ~~~ C2 ~~~ C3
    end
    subgraph L3["⚡  data plane"]
        direction LR
        D1["UDP<br/>fragmenter · reassembler · retry"]
        D2["TCP pump<br/>zero-copy · vectored"]
        D3["DNS<br/>memo → moka → hickory"]
        D1 ~~~ D2 ~~~ D3
    end
    subgraph L4["🔭  cross-cutting"]
        direction LR
        O1["stats<br/>drop warnings · throttles"]
        O2["linux knobs<br/>busy poll · notsent-lowat"]
        O3["time<br/>coarse · mono"]
        O1 ~~~ O2 ~~~ O3
    end
    subgraph BIN["🚀  binaries"]
        direction LR
        B1["myquic2-client<br/>pool-first · SOCKS5 ingress"]
        B2["myquic2-server<br/>admission-first · QUIC ingress"]
        B1 ~~~ B2
    end
    L1 ==> L2 ==> L3 ==> BIN
    L4 -.-> BIN
    style L1 fill:#f0fdf4,stroke:#34d399,stroke-width:2px,color:#14532d
    style L2 fill:#eef2ff,stroke:#818cf8,stroke-width:2px,color:#1e1b4b
    style L3 fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    style L4 fill:#f5f3ff,stroke:#a78bfa,stroke-width:2px,color:#2e1065
    style BIN fill:#0f172a,stroke:#334155,stroke-width:2px,color:#f8fafc
    classDef prim fill:#dcfce7,stroke:#059669,stroke-width:1.5px,color:#064e3b
    classDef codec fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#1e1b4b
    classDef data fill:#ffedd5,stroke:#ea580c,stroke-width:1.5px,color:#7c2d12
    classDef cross fill:#ede9fe,stroke:#7c3aed,stroke-width:1.5px,color:#2e1065
    classDef bin fill:#1e293b,stroke:#475569,stroke-width:2px,color:#f8fafc
    class S1,S2,S3 prim
    class C1,C2,C3 codec
    class D1,D2,D3 data
    class O1,O2,O3 cross
    class B1,B2 bin
```

#### Deployment topology (new)

_Where the two binaries sit: LAN / OpenWrt, internet, VPS, targets._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
subgraph LAN["LAN / OpenWrt"]
        APPS["apps"] --> CLIENT["myquic2-client<br/>SOCKS5 :1080"]
    end
    CLIENT ==>|"QUIC / TLS 1.3"| NET(("Internet"))
    NET ==>|"QUIC / TLS 1.3"| SRV["myquic2-server<br/>:8443"]
    SRV --> DNS["resolver"]
    SRV --> TCP["TCP targets"]
    SRV --> UDP["UDP targets"]
```

### 🚀 Client paths

#### Connection pool panorama (restored)

_Seven QUIC connections by default; each slot is its own endpoint and runtime._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
    subgraph APPS["🧑‍💻  application flows"]
        direction LR
        APP2["🎮 DNS · game<br/>interactive"]
        APP1["🖥️ bulk TCP flow"]
        APP4["🔍 small UDP assoc<br/>interactive class"]
        APP3["📞 bulk UDP assoc<br/>VPN · media"]
        APP2 ~~~ APP1 ~~~ APP4 ~~~ APP3
    end
    subgraph POOL["🎰  ConnPool · 7 connections by default"]
        direction TB
        subgraph UDPR["🟠 UDP range · udp_split on"]
            direction LR
            U0["slot 4<br/>⚡ interactive UDP<br/>small flows"]
            U1["slot 5<br/>📦 bulk shard 0"]
            U2["slot 6<br/>📦 bulk shard 1"]
            U0 ~~~ U1 ~~~ U2
        end
        subgraph TCP["🔵 TCP pool · quic_conns = 4"]
            direction LR
            T0["slot 0<br/>📌 interactive<br/>DNS · NTP · STUN"]
            T1["slot 1<br/>📦 bulk RR"]
            T2["slot 2<br/>📦 bulk RR"]
            T3["slot 3<br/>📦 bulk RR"]
            T0 ~~~ T1 ~~~ T2 ~~~ T3
        end
    end
    subgraph SLOT["🔧  inside every slot — no shared receive path"]
        direction LR
        EP["🔌 Endpoint<br/>own UDP socket · CID table · driver"]
        CN["🔗 Connection<br/>ArcSwap · live bit · watch generation"]
        DL["📥 dispatcher<br/>DATAGRAM reader · reassembler"]
        LP["📞 conn_loop<br/>dial · backoff · silence watchdog"]
        EP --- CN --- DL --- LP
    end
    APPS ==>|"pick_tcp → pinned / round-robin<br/>udp_bind → interactive / shard"| POOL
    POOL -.->|"every slot expands to"| SLOT
    style APPS fill:#f8fafc,stroke:#cbd5e1,stroke-width:1.5px,color:#0f172a
    style POOL fill:#f8fafc,stroke:#94a3b8,stroke-width:2px,color:#0f172a
    style TCP fill:#eff6ff,stroke:#60a5fa,stroke-width:2px,color:#1e3a8a
    style UDPR fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    style SLOT fill:#f5f3ff,stroke:#a78bfa,stroke-width:2px,color:#2e1065
    classDef tcp fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a8a
    classDef udp fill:#ffedd5,stroke:#ea580c,stroke-width:2px,color:#7c2d12
    classDef infra fill:#ede9fe,stroke:#7c3aed,stroke-width:1.5px,color:#2e1065
    classDef app fill:#ffffff,stroke:#94a3b8,stroke-width:1.5px,color:#0f172a
    class T0,T1,T2,T3 tcp
    class U0,U1,U2 udp
    class EP,CN,DL,LP infra
    class APP1,APP2,APP3,APP4 app
```

#### TCP echo path (restored)

_One SOCKS CONNECT, one QUIC stream, one exit-side dial._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
    autonumber
    box rgb(236, 253, 245) Client edge
        participant App as 🖥️ App
        participant Socks as 🧦 socks.rs
        participant Pool as 🎰 pool.rs
        participant QC as 🚀 QUIC client
    end
    box rgb(255, 247, 237) Exit side
        participant QS as 🛰️ QUIC server
        participant Dial as 🌐 tcp.rs
        participant Tgt as 🎯 Target
    end
    rect rgb(240, 253, 244)
        Note over App,Socks: ① SOCKS5 CONNECT · atyp + addr + port
        App->>Socks: CONNECT atyp + addr + port
        Socks->>Pool: pick_tcp(target)
        Pool-->>Socks: slot 0 (pinned) or RR bulk slot
    end
    rect rgb(238, 242, 255)
        Note over Socks,QC: ② stream setup · optimistic success
        Socks->>QC: wait_conn + open_bi (5 s budgets)
        Socks->>QC: write AddrHeader (7 / 19 / 259 B)
        Socks-->>App: ✅ 0.0.0.0:0 SUCCESS (optimistic, no dial wait)
        QC->>QS: STREAM head + raw bytes (zero-copy past head)
    end
    rect rgb(255, 247, 237)
        Note over QS,Tgt: ③ exit-side dial · ACK
        QS->>Dial: read target (5 s) + stream-task share
        Dial->>Dial: DNS 8 candidates + happy-eyeballs 250 ms stagger
        Dial->>Tgt: TCP connect + set_nodelay
        Dial-->>QS: ACK MQ + bound address (5 s)
        QS-->>QC: ACK frame
        QC-->>Socks: read_mqp_ack (25 s budget)
    end
    rect rgb(236, 254, 255)
        Note over App,Tgt: ④ bidirectional bulk copy · copy_tcp_quic_idle (300 s)
        loop every chunk
            App->>Tgt: c2s write_chunk ≥ 8 KiB zero-copy
            Tgt->>App: s2c read_chunks(8) + write_vectored
        end
    end
    Note over Socks,Dial: any failure → RST (SO_LINGER=0) + reset/stop 0x04
```

#### TCP relay path (new)

_The modern TCP dial: admission, happy-eyeballs racing, zero-copy pump._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
autonumber
    participant App
    participant Client as MyQUIC2 client
    participant Server as MyQUIC2 server
    participant TCP as Target TCP
    App->>Client: SOCKS5 CONNECT
    Client->>Server: open bi stream + stream head
    Server->>Server: admission + token gate
    Server->>TCP: happy-eyeballs dial (250 ms stagger, 4 s)
    TCP-->>Server: connected
    Server-->>Client: dial ACK
    Client-->>App: SOCKS5 success
    Server->>TCP: zero-copy pump
    Note over Server,TCP: failure -> RST + reset/stop 0x04
```

#### Client egress selection (new)

_Memo -> acquire -> own slot -> sibling -> fail-open or drop._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
D["UDP datagram"] --> M{"thread memo<br/>fresh?"}
    M -->|"hit"| SEND["send_datagram"]
    M -->|"miss"| A["acquire egress"]
    A --> O{"own slot usable?"}
    O -->|"yes"| SEND
    O -->|"no"| S{"same-class sibling?"}
    S -->|"yes"| SEND
    S -->|"no"| F{"udp_fail_closed?"}
    F -->|"false"| TCP["fail-open to TCP"]
    F -->|"true"| DROP["NO_EGRESS<br/>drop + count"]
```

#### Reconnect & watchdog (new)

_Two independent stall detectors; both close and redial below the QUIC idle timeout._

```mermaid
stateDiagram-v2
    [*] --> Connecting
    Connecting --> Negotiating: QUIC established
    Negotiating --> Ready: CAPS(2)
    Negotiating --> Reconnecting: no CAPS after 2 s
    Ready --> Silent: no inbound datagrams
    Ready --> AckStalled: tx advances, acks do not
    Silent --> Reconnecting: close + backoff
    AckStalled --> Reconnecting: close + backoff
    Reconnecting --> Connecting: 200 ms ... 5 s
```

### 📡 Wire & flows

#### UDP echo path (restored)

_Association setup, frame selection and the staged reply path._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
    autonumber
    box rgb(236, 253, 245) Client edge
        participant App as 🎮 App
        participant Assoc as 🔁 assoc.rs
        participant Hub as 🗂️ hub.rs
        participant Egr as 🧭 egress.rs
        participant Disp as 📥 dispatcher.rs
    end
    box rgb(238, 242, 255) QUIC tunnel
        participant QC as 🚀 QUIC client
        participant QS as 🛰️ QUIC server
    end
    box rgb(255, 247, 237) Exit side
        participant Sess as 🔌 session socket
        participant Tgt as 🎯 Target
    end
    rect rgb(240, 253, 244)
        Note over App,Hub: ① association setup
        App->>Assoc: SOCKS5 UDP ASSOCIATE
        Assoc->>Hub: alloc_sess (cap 4032)
        Assoc-->>App: BND relay ip:port
        App->>Assoc: UDP datagram (RSV / FRAG checked)
        Assoc->>Assoc: lock app ip + port on 1st valid packet
    end
    rect rgb(238, 242, 255)
        Note over Assoc,QC: ② pick a frame shape · egress binding
        Assoc->>Egr: with_fresh(bind)
        alt confirmed flow, fits one frame
            Egr->>QC: rev2 DATA · 2 B steady (OPEN while unconfirmed)
        else several small payloads (same or mixed flows)
            Egr->>QC: rev2 TRAIN same/dict · 3–4 B header + 1–2 B/item
        else payload larger than one frame
            Egr->>QC: rev2 FRAG × N · 8 B steady header
        end
        QC->>QS: QUIC DATAGRAM (unreliable, no head-of-line blocking)
    end
    rect rgb(255, 247, 237)
        Note over QS,Tgt: ③ exit-side fan-out
        QS->>QS: FastSess 16 · reassemble 2 s · resolve fast → slow
        QS->>Sess: get_or_create_sess + udp_try_send
        Sess->>Tgt: UDP payload (sendmmsg burst ≤ 32)
        Tgt-->>Sess: reply (IP allowlist 16 + exact live flow fallback)
        Sess->>QS: recvmmsg burst ≤ 32
    end
    rect rgb(236, 254, 255)
        Note over QS,App: ④ staged reply path
        alt small replies (≤ one DATA frame)
            QS->>QC: rev2 DATA/TRAIN · connection stager · cross-session dict
        else large reply
            QS->>QC: rev2 FRAG × N
        end
        QC->>Disp: read_datagram · 4096-entry cache · reassemble
        Disp->>Assoc: StagedReply runs + sendmmsg (zero payload copy)
        Assoc->>App: UDP datagram to the locked app address
    end
```

#### Frame decision (restored)

_Payload shape -> DATA / TRAIN / FRAG, with the send verdicts._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
    P(["📦 payload +<br/>destination"]) --> Q{"does it fit<br/>one frame?"}
    Q -->|"yes · confirmed flow,<br/>within live budget"| S["rev2 DATA<br/>2 B steady · 1 lock"]
    Q -->|"no · several small payloads<br/>same or mixed flows"| B["rev2 TRAIN same/dict<br/>3 B header + 1 B/item"]
    Q -->|"no · larger payload"| F["rev2 FRAG × N<br/>8 B header · (wire_id, frag_id)"]
    S --> SEND["🚀 send_datagram"]
    B --> SEND
    F --> SEND
    SEND -->|"queued"| OK(["✅ delivered whole<br/>or dropped whole"])
    SEND -->|"Blocked"| DROP["🗑️ drop newest<br/>never drop-oldest"]
    SEND -->|"TooLarge"| RE["🔄 re-read live budget<br/>100 ms throttle"]
    RE -.-> Q
    style P fill:#f8fafc,stroke:#94a3b8,stroke-width:2px,color:#0f172a
    classDef decision fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
    classDef frame fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef send fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef ok fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef warn fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    class Q decision
    class S,B,F frame
    class SEND send
    class OK ok
    class DROP,RE warn
```

#### First-byte safety (new)

_Why rev2 coexistence with old decoders cannot misroute._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
B["first wire byte"] --> N{"high nibble"}
    N -->|"0x0X"| R["MQP-3 rev2<br/>DATA / TRAIN / FRAG / CTL"]
    N -->|"0x02 / 0x05 / 0x06"| V2["MQP-2 legacy<br/>receive + tests only"]
    N -->|"0x1X ... 0x4X"| V3["v0.2.0 v3 legacy<br/>receive + tests only"]
    N -->|"anything else"| D["drop"]
```

#### Flow state machine (new)

_Inline -> Opening -> Open -> Closed; ACK is an optimisation, not a gate._

```mermaid
stateDiagram-v2
    [*] --> Inline: no flow id
    Inline --> Opening: DATA OPEN sent
    Opening --> Open: FLOW_ACK / compressed downlink
    Opening --> Inline: FLOW_REJECT
    Open --> Closed: FLOW_CLOSE / SESS_CLOSE
    Inline --> Closed: session ends
    Closed --> [*]

    note right of Opening : OPEN repeats until ACK; loss only delays compression
    note right of Closed : ids are never reused while the connection lives
```

#### Optimistic first packet (new)

_The first UDP payload need not wait for CAPS; the server buffers pre-HELLO frames._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
autonumber
    participant App
    participant Client as MyQUIC2 client
    participant Server as MyQUIC2 server
    Note over Client: QUIC established, rev2 state published
    Client->>Server: CTL HELLO(wire_ver=2)
    App->>Client: first UDP datagram
    Client->>Server: DATA OPEN (optimistic)
    Server->>Server: buffer pre-HELLO frames (8 / 16 KiB)
    Server-->>Client: CTL CAPS(2)
    Server->>Server: flush buffer in arrival order
    Server-->>Client: FLOW_ACK + reply
    Note over Client,Server: CAPS only updates caps, not a first-packet gate
```

#### Domain target + rebind (new)

_Resolve once, learn the real source, then compress both directions._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
autonumber
    participant App
    participant Client as MyQUIC2 client
    participant Server as MyQUIC2 server
    participant Resolver
    participant Target
    App->>Client: UDP to example.com:53
    Client->>Server: DATA OPEN(domain, payload)
    Server->>Resolver: memo -> moka -> hickory
    Resolver-->>Server: A / AAAA
    Server->>Target: payload
    Target-->>Server: reply from actual source
    Server-->>Client: DATA OPEN + SRC (actual source)
    Client-->>App: SOCKS5 UDP reply (learned source)
    Client->>Server: DATA 2 B steady
    Note over Client,Server: source / port changes rebind the same wire id
```

#### Pure-uplink flow (new)

_FLOW_ACK unlocks compression even when no payload ever comes back._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
autonumber
    participant App
    participant Client as MyQUIC2 client
    participant Server as MyQUIC2 server
    participant Target
    App->>Client: one-way datagrams
    Client->>Server: DATA OPEN(payload)
    Server->>Target: payload
    Server-->>Client: FLOW_ACK (no payload)
    Client->>Server: DATA 2 B steady
    Note over Client,Server: no downlink needed<br/>FLOW_ACK unlocks compression
```

#### Server-owned full-cone flow (new)

_The server can open a flow for an unsolicited source; the app replies on the same id._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
autonumber
    participant Source
    participant Server as MyQUIC2 server
    participant Client as MyQUIC2 client
    participant App
    Source->>Server: unsolicited datagram
    Server->>Server: allocate owner=1 wire id
    Server-->>Client: DATA OPEN + SRC (sess, source)
    Client-->>App: deliver (learned source)
    App->>Client: app reply
    Client->>Server: DATA 2 B steady (same id)
    Server->>Source: app reply
    Note over Source,App: requires udp_full_cone = true
```

#### Wire-version compatibility (new)

_Matched deployment: a wrong peer fails at HELLO/CAPS, never silently downgrades._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
A["new client dials"] --> B["send CTL HELLO(wire_ver=2)"]
    B --> C{"peer speaks rev2?"}
    C -->|"yes"| D["CAPS(2) -> UDP enabled"]
    C -->|"no"| E["no CAPS within 2 s"]
    E --> F["close + redial
no downgrade"]
    G["server sees a v3 / MQP-2 first byte"] --> H["drop
matched deployment only"]
```

### 🚪 Server & admission

#### Server ingress & session lifecycle (restored)

_Admission before work: conn caps, token gate, sessions, replies._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
    subgraph G1["🚪  Ingress · admission before work"]
        direction LR
        L["[::]:8443<br/>SO_REUSEPORT<br/>1 endpoint / core · ≤ 8"]
        A["accept_loop × N<br/>own socket · CID table · driver"]
        G{"conn limit?<br/>4096 token · 256 bare"}
        H["🤝 handshake<br/>PRE_AUTH 5 s · HANDSHAKE 10 s"]
        T{"token gate<br/>constant time · 256 B"}
        RF["🚫 implicit refuse<br/>1 / s warn"]
        C1["✂️ close 0x01"]
        L --> A --> G
        G -->|"permit"| H
        G -->|"full"| RF
        H --> T
        T -->|"fail"| C1
    end
    subgraph G2["📡  Session · per connection"]
        direction LR
        HC["handle_conn<br/>sweep 60 s<br/>uni drain · reader"]
        R["DATAGRAM reader<br/>await head · drain 32<br/>FastSess 16 · reassembler"]
        F{"target form?"}
        DN["📌 domain<br/>ConnPin → DestMemo 30 s<br/>→ moka 120 s → hickory 5 s"]
        SS["🛡️ IP gate<br/>is_global_ip_cached<br/>allow_private"]
        HC --> R --> F
        F -->|"domain"| DN
        F -->|"IP"| SS
    end
    subgraph G3["🔌  Egress · UDP sessions"]
        direction LR
        GS["get_or_create_sess<br/>memo → fair share<br/>→ limiter → socket"]
        SO["session socket 64 KiB<br/>+ reader task<br/>recvmmsg ≤ 32"]
        RP["↩️ reply<br/>rev2 DATA/TRAIN · FRAG if >1 frame<br/>IP allowlist 16 + flow fallback"]
        BYE["🧹 teardown<br/>take_idle · drain_all"]
        GS --> SO --> RP
        RP -->|"idle 180 s / conn closed"| BYE
    end
    G1 ==>|"pass / empty token"| G2
    G2 ==>|"resolved · gated<br/>get_or_create_sess"| G3
    style G1 fill:#eff6ff,stroke:#60a5fa,stroke-width:2px,color:#1e3a8a
    style G2 fill:#f5f3ff,stroke:#a78bfa,stroke-width:2px,color:#2e1065
    style G3 fill:#f0fdf4,stroke:#34d399,stroke-width:2px,color:#14532d
    classDef gate fill:#fef2f2,stroke:#f87171,stroke-width:2px,color:#7f1d1d
    classDef good fill:#dcfce7,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef infra fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#1e1b4b
    classDef deny fill:#fff1f2,stroke:#e11d48,stroke-width:1.5px,color:#881337
    class G,T,F gate
    class GS,SO,RP good
    class L,A,H,HC,R,DN,SS infra
    class RF,C1,BYE deny
```

#### Admission decision tree (new)

_Connection permit -> token -> memory budget -> session fair-share._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
C["new QUIC connection"] --> G{"global conn cap?"}
    G -->|"no"| R["implicit refuse<br/>1/s warn"]
    G -->|"yes"| A{"token valid?"}
    A -->|"no"| CL["close 0x01"]
    A -->|"yes"| M{"memory admission?"}
    M -->|"deny"| R
    M -->|"allow"| H["handle_conn"]
    H --> S{"session / fair-share?"}
    S -->|"ok"| SESS["session socket<br/>64 KiB"]
    S -->|"full"| D["refuse / drop"]
```

#### Reply-source authorization (new)

_Restricted allowlist first; full-cone is an explicit opt-in._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
R["UDP reply source"] --> FC{"udp_full_cone?"}
    FC -->|"true"| OK["forward any source<br/>server-owned flow opt-in"]
    FC -->|"false"| EX{"exact live<br/>(sess, flow) source?"}
    EX -->|"yes"| OK
    EX -->|"no"| RING{"16-entry IP ring hit?"}
    RING -->|"yes"| OK
    RING -->|"no"| D["drop + count"]
```

#### DNS resolution layers (new)

_Thread memo -> moka -> hickory, then SSRF policy at the exit._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
Q["host + port"] --> TM["thread memo<br/>64 sets × 2 ways"]
    TM -->|"miss"| MK["moka shared cache<br/>host key · 120 s / 10 s"]
    MK -->|"miss"| H["hickory resolver<br/>5 s · cancellable"]
    H --> C["A / AAAA candidates"]
    C --> P["SSRF / ipnet policy"]
    P --> O["dial or sendmmsg"]
```

### 🚀 Scheduling & transport

#### Cross-session fairness (new)

_Per-session FIFO and a round-robin cursor feed one dict TRAIN._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
subgraph A["assoc A · DNS"]
        A1["p"]:::q
        A2["p"]:::q
    end
    subgraph B["assoc B · game"]
        B1["p"]:::q
    end
    subgraph C["assoc C · VPN"]
        C1["p"]:::q
        C2["p"]:::q
    end
    A2 --> RR["per-session FIFO<br/>round-robin cursor"]
    B1 --> RR
    C2 --> RR
    RR --> T["TRAIN dict 0x04<br/>id list + idx + len + payload"]
    T --> D["🚀 one QUIC DATAGRAM"]
    classDef q fill:#e0f2fe,stroke:#0891b2,color:#0f172a
    style RR fill:#fef3c7,stroke:#d97706,color:#713f12
```

#### PMTU ramp (new)

_Start at the QUIC floor, probe upward, and raise the start on known paths._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
I["initial_mtu<br/>default 1200"] --> P1["probe 1336"]
    P1 --> P2["1404"]
    P2 --> P3["1438"]
    P3 --> P4["1472<br/>ceiling"]
    I --> B["DATAGRAM budget<br/>mtu − 38 = 1162 B"]
    P4 --> W["single frame<br/>up to 1434 B"]
    I -.-> R["raise it<br/>1360 / 1400 / 1472"]
```

### ✅ Verification

#### CI pipeline (new)

_Every push: format, lint, 424/428 tests, musl and glibc builds._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
C["push / PR"] --> F["rustfmt"]
    F --> CL["clippy -D warnings"]
    CL --> T["cargo test --all-targets<br/>424 macOS / 428 Linux"]
    T --> M["musl static build"]
    T --> G["gnu 2.36 build"]
    M --> A["assets + SHA256SUMS"]
    G --> A
```

## 📚 Documentation

- [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md) — wire format, state machine, security contract.
- [MQP3_REFACTOR_ANALYSIS.md](MQP3_REFACTOR_ANALYSIS.md) — design rationale, models, roadmap.
- [analysis/mqp3-refactor/](analysis/mqp3-refactor/) — five deep-dive reports + byte/CPU model.
- [examples/hotpath_bench.rs](examples/hotpath_bench.rs) — TCP/UDP load, correctness, latency and full-duplex harness.
- [scripts/linux-bench-matrix.sh](scripts/linux-bench-matrix.sh) — Linux deployment benchmark matrix.
- [config-server.toml](config-server.toml) · [config-client.toml](config-client.toml) — documented configuration samples.

## 📄 License

[MIT](LICENSE)
