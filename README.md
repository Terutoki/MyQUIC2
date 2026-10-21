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

[Architecture](#-architecture) · [Wire](#-mqp-3-rev2-wire) · [Full duplex](#-full-duplex) · [Stager](#-cross-session-stager) · [Performance](#-performance) · [Security](#-security) · [Install](#-install) · [Quick start](#-quick-start) · [Verify](#-verification)

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

## 📚 Documentation

- [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md) — wire format, state machine, security contract.
- [MQP3_REFACTOR_ANALYSIS.md](MQP3_REFACTOR_ANALYSIS.md) — design rationale, models, roadmap.
- [analysis/mqp3-refactor/](analysis/mqp3-refactor/) — five deep-dive reports + byte/CPU model.
- [examples/hotpath_bench.rs](examples/hotpath_bench.rs) — TCP/UDP load, correctness, latency and full-duplex harness.
- [scripts/linux-bench-matrix.sh](scripts/linux-bench-matrix.sh) — Linux deployment benchmark matrix.
- [config-server.toml](config-server.toml) · [config-client.toml](config-client.toml) — documented configuration samples.

## 📄 License

[MIT](LICENSE)
