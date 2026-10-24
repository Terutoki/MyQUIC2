# MQP-3 Transport Layer Facts, Connection Topology, and "Full-Duplex" Gap Analysis (task-4)

> Baseline: `/Users/eric/WorkSpace/MyQUIC2`, HEAD `d2f9658` / v0.2.0 (2026-10-20).
> Method: **read-only** reading of source + quinn dependency source (`~/.cargo/registry/src/*/`) + `python3` arithmetic modeling.
> **No `cargo build/test` was executed, and no process was started for load testing**; every measured number in this document is annotated with its source; the rest are models/estimates.
> Citation convention: repository files use `src/...:line`; quinn internal source uses `quinn-<ver>/src/...:line`, rooted at
> `~/.cargo/registry/src/index.crates.io-*/`.
> Confidence labels: **[measured]** existing measurements in the repository; **[model]** derived from source constants + formulas; **[estimate]** order-of-magnitude estimate,
> requiring calibration with microbenchmarks on the Linux target machine.
>
> **README line references** below point to the baseline README at `d2f9658`; the README has since been expanded, so its line numbers have shifted. File-level claims are unaffected.

---

## 0. TL;DR (conclusions first)

1. **The transport layer itself is already full-duplex**: quinn/QUIC has independent packet number spaces, congestion control, loss detection,
   RTT/PTO, and flow control in the two directions; data in one direction is not predicated on data in the other. The user requirement "implement full duplex"
   already holds at the QUIC layer; **what is missing is the symmetry of the MQP-3 protocol state surface and the control plane**, not QUIC capability.
2. **Only four things actually couple the two directions together**: (1) the same connection driver task/state lock/CPU core (sending and receiving
   in the same task) (2) reverse ACK traffic and the CPU to generate it (3) the core of the same server ingress shard (4)
   all sessions/flows within the same direction share cwnd/pacing/DATAGRAM FIFO (this is a same-direction problem, not a bidirectional problem).
3. **The two biggest "free" levers in transport config are configuration, not protocol**: `initial_mtu` defaults to 1200 (QUIC lower bound),
   while PMTU discovery only probes when the send queue drains, so a saturated connection may stay at 1200 for a long time; setting a known path to
   1360/1400/1472 lets UDP payloads >1157 B (flow0 single-frame cap) no longer fragment (at 1200 B, packet count
   −50%, wire −6.6%).
   The other is the 4/8/4 MB window (the ~240 Mb/s @140 ms single TCP flow cap is computed from it, not from BBR).
4. **The real cost structure of `send_datagram`**: one `std::sync::Mutex` lock + one `VecDeque` enqueue +
   one driver `wake` (~50–150 ns same-thread); but the driver **holds that lock for the entire poll round** (events,
   sending, encryption, and syscalls all happen inside the lock), so a cross-thread sender may block for microseconds to tens of microseconds—this is
   the main source of tail latency in pps scenarios, and the reason "putting producers on the driver's thread" is cheaper than any protocol change.
5. **quinn already coalesces packets automatically**: multiple DATAGRAM frames queued within the same `poll_transmit` are packed into the same
   QUIC packet (`populate_packet`'s DATAGRAM while loop), so "cross-session aggregation saves a lot of bandwidth"
   is **overestimated**: compared with an already-coalesced single frame, a cross-session super-frame saves only ~1–3 B of MQP header dedup
   per frame (~1–3% wire) + fewer send calls (CPU); TRAIN versus "one send per payload" saves −8% wire on small packets
   (vs single frames already coalesced by quinn), send −18×, and this is already implemented (most of it given by MQP-2 BATCH).
6. **bulk's "1 payload = 1 send_datagram" is not protocol waste**: MTU determines that one packet can hold only one
   near-MTU payload; unless MTU is raised or multiple connections/multiple paths are used, no "super-frame" can reduce packet count.
7. **Protocol-level full-duplex gap list** (ordered by benefit): (a) the flow table is owned only by the client, the server cannot open flows,
   downlink compression depends on uplink install → pure-uplink flows are never compressed (small packets 4–18% wire, worse the smaller the payload / the more v6);
   (b) no control plane (CTL is only reserved, no opcode) → no explicit flow ACK/close/capability negotiation/priority/receive feedback;
   (c) the server cannot proactively push; (d) one TRAIN = one direction + one session;
   (e) payloads above 512 B use MQP-2 fragmentation, with no flow/address compression.
8. **Recommended definition of "MQP-3 full duplex" = D1–D6** (see §3.4): data plane/state plane/control plane three-way symmetry + no direction dependency +
   independent scheduling + benchmark-verifiable. It is **not** "each direction gets 100% bandwidth", nor does it **change** the physical fact that
   each direction shares one cwnd.
9. **Lever ranking (benefit/risk ratio)**: configuration (MTU, window) > architecture (producers on the same thread as driver + per-connection aggregated
   sending) > protocol control plane + per-direction flow table (capability + small packets 4–18%) > server selects transport by class
   (~1–3% CPU, requires port/ALPN architecture) > single-flow multi-connection striping (only single-big-flow scenarios 30–80%,
   high complexity) > FEC/NACK (conditional, not done by default) > cross-session wire aggregation (1–3%).
10. **Honest judgment about "big wins"**: for bulk throughput, the protocol wire rewrite itself is ≤1–3%; the real 10–30% comes from
    MTU/window/same-threading/fragmentation elimination; only the "single-flow ceiling" requires structural changes such as multiple connections/multiple paths.
    "Full duplex" is a **capability/fairness/latency isolation** item, not a throughput multiplier.
11. **Measurement plan**: this version of quinn-udp on macOS **has no GSO/GRO** (`fast-apple-datapath` not enabled), one sendmsg/recvmsg per packet,
    and the server defaults to only 1 shard thread → macOS numbers cannot be extrapolated; must run the §5.4 matrix on Linux 2–4 cores + `tc netem`
    (70/140 ms, 0/0.5/2% loss), and add the §5.3 counters (quinn `stats()` already gives cwnd/RTT/current_mtu/ios, which can be captured directly).
12. **6 open questions** (§6), the most critical: is the target scenario "single big flow" or "many small flows fan-out"? This determines
    whether bonding/topology is in scope.

---

## 1. Transport layer fact baseline (HEAD d2f9658)

### 1.1 Dependency versions (Cargo.toml / Cargo.lock)

| Component | Version | Location |
|---|---|---|
| quinn | 0.11.12 | `Cargo.lock:1294`; `Cargo.toml:42-47` (`default-features=false`, features: log/runtime-tokio/bloom/rustls-aws-lc-rs) |
| quinn-proto | 0.11.19 | `Cargo.lock:1314` |
| quinn-udp | 0.5.16 | `Cargo.lock:1338` |
| rustls | 0.23.46 (aws-lc-rs) | `Cargo.lock:1508` |
| tokio | 1.53.3 | `Cargo.lock` |

The comments at `Cargo.toml:20-41` state explicitly: the 0.11 line floats, `Blocked`-vs-`try_send_datagram` semantics are pinned by regression tests;
**no** fork, no `MAX_CHUNKS` patch. quinn-udp is pulled in by quinn with `default-features=false, features=["tracing"]`
→ **`fast-apple-datapath` is not enabled** (this is the basis for the macOS conclusions later).

### 1.2 Effective transport configuration (item by item, with effective side annotated)

Code locations: `src/transport/build.rs:144-281` (`build_transport_tuned_class`), defaults
`src/config/tuning.rs:207-236`, `src/transport/limits.rs`.

| Parameter | Effective value | Code | Effective side/notes |
|---|---|---|---|
| Congestion control | **BBR** (`BbrConfig::default()`: initial cwnd = 200×1200 B = 234 KiB, min cwnd = 4×MTU) | `build.rs:167-174`; quinn-proto `congestion/bbr/mod.rs:517-537,638-650` | both ends; `congestion="cubic"` is only an escape hatch |
| DATAGRAM → send buffer | interactive **1 MiB** / bulk **2 MiB** | `build.rs:159-163,179-180`; `limits.rs:84,88` | local send queue only; **the server always uses the interactive preset** (next row) |
| DATAGRAM → receive buffer | interactive 1 MiB / bulk 2 MiB | `build.rs:179` | local receive queue (the cap the peer can send); server 1 MiB |
| ACK frequency (requests the **peer**) | interactive: threshold 2 / max_delay 5 ms; bulk: 8 / 10 ms; reordering_threshold 2 | `build.rs:224-229`; `build.rs:150-158` | **the client selects the preset per slot; the server has only the interactive preset for all connections** (`src/bin/myquic2-server/main.rs:126` uses `build_transport_tuned`→`is_bulk=false`) → bidirectional asymmetry |
| initial_rtt | 190 ms | `build.rs:238`; `tuning.rs:163-170` | only affects the first PTO/initial pacing |
| initial_mtu | **1200** (QUIC lower bound) | `build.rs:263`; `tuning.rs:193`; `config-server.toml:74` comment | configured independently at both ends; clamp 1200..=1472 |
| PMTU discovery | enabled, upper_bound 1472, min_mtu 1200, interval 600 s, black-hole cooldown 60 s | `build.rs:243-245`; quinn-proto `config/transport.rs:698-755` | **opportunistic**: probes are sent only in `poll_transmit` when `buf.is_empty() && established` (quinn-proto `connection/mod.rs:950`) → a saturated connection may stay at 1200 for a long time |
| Flow control window | 4 / 8 / 4 MiB (stream_rwnd / conn_rwnd / send_window) | `build.rs:206-212`; `tuning.rs:229-232` | per connection, per direction (send_window is the local send budget); opt-in 8/16/8 |
| Concurrent streams | bidi 8192 / uni 100 | `build.rs:197-198`; `tuning.rs:96` | covers the worst case of 8192 SOCKS connections landing on one connection |
| keepalive / idle | 5 s / 60 s (decoupled; 40 s watchdog, 22 s stale) | `build.rs` | per-connection NAT heartbeat; 7 connections = ~1.4 pkt/s/client |
| GSO/GRO | **quinn-udp auto-probes, no API switch**: Linux GSO=64 segments (quinn then clamps to 10 segments/sendmsg), GRO=64 segments; macOS without `fast-apple-datapath` → GSO=1, GRO=1, one recvmsg per packet | quinn-udp `unix.rs:189,237-252,806-855,978-996`; quinn `connection.rs:1020-1023,1334-1341`; `build.rs:175-178,276-279` | **the `gso` config is inert**: the server only prints it (`myquic2-server/main.rs:163-170`), the client parses it and never reads it (`config/client_conf.rs:20`) |
| ECN | **enabled by default**: quinn-proto `PathData::sending_ecn = true`, sends ECT0, disables if the ACK lacks ECN counts/validation fails | quinn-proto `connection/paths.rs:73,122`, `connection/mod.rs:1006,1563-1600`; quinn-udp `unix.rs:119-140,614-632,719-799` | effective on Linux; the macOS dual-stack socket's `IP_RECVTOS` is unsupported (quinn-udp comment `unix.rs:119-121`) → IPv4 received packets have no TOS → ECN is most likely auto-disabled. **Not a tunable lever** |
| Endpoint socket buffers | each endpoint requests 4 MiB SO_SNDBUF/SO_RCVBUF (Linux kernel records 2×); `SO_*BUFFORCE` best-effort | `src/lib.rs:137-144,336-402,592-603` | per client slot / server endpoint |

**README claims vs reality** (`README.md:755-790`):

- "BBR + GSO/GRO + ECN + PMTU" — BBR/ECN (Linux) is true; GSO/GRO only on Linux (this quinn-udp version
  has it fully off on macOS); the "opportunistic" PMTU description matches the source, but the README does not emphasize that saturated connections may never upgrade.
- "4 TCP + 2 class-split UDP connections" — the default is **7 QUIC connections** (4 TCP + 1 interactive UDP +
  2 bulk UDP; `config-client.toml` comments, `README.md:147-190`, `src/bin/myquic2-client/pool.rs:429-460`).
- "connection count scales linearly" — linear in connection count, but **a single connection with a single shard is single-threaded**, see §1.3.
- `gso = true` config item: **purely decorative** (only affects logging); changing it produces no transport behavior change.
- One small memory accounting discrepancy: `endpoint_recv_buffer_bytes()` (`src/config/tuning.rs:343-351`) records only 1472 B on
  non-Linux, whereas actual quinn `recv_buf = max_udp_payload(1472) × max_receive_segments(1)
  × BATCH_SIZE(32) = 46 KiB` (quinn `endpoint.rs:751-760`, quinn-udp `unix.rs:806-809`) →
  non-Linux undercounts ~46 KiB per endpoint (7 endpoints ≈ 0.3 MiB, order of magnitude irrelevant, but usable for correcting documentation).

### 1.3 Connection/endpoint/thread topology (this determines full-duplex CPU coupling)

**Client** (`src/bin/myquic2-client/main.rs`, `pool.rs`):

- Default 7 pool slots = 4 TCP (slot 0 interactive + slots 1-3 bulk RR) + 1 interactive UDP + 2 bulk UDP
  shards (`pool.rs:429-460`; `udp_split=true`, `udp_egress_conns=2`).
- **Each slot has its own `quinn::Endpoint` + its own UDP socket + its own current-thread tokio runtime**
  (`main.rs:199-232` default shard topology; `MYQUIC2_SHARD_RUNTIME=0` falls back to a shared multi-thread runtime).
  On Linux cores are pinned by priority (interactive first); **`pin_to_core` is a no-op on macOS**
  (`src/linux.rs:184-198`).
- The UDP association relay task (uplink producer) **runs on the main multi-thread runtime**, while the egress
  driver runs on the slot runtime → every uplink DATAGRAM incurs one cross-core state lock + driver wake
  (`PERF_ANALYSIS.md:326-343` F10, still deferred). This is **the structural bulk of the current uplink pps cost**,
  worth more than any wire format optimization.

**Server** (`src/bin/myquic2-server/main.rs`):

- `quic_endpoints` `SO_REUSEPORT` endpoints, Linux default = available cores (clamp 1..=8), non-Linux
  default 1 (`src/config/tuning.rs:151-161`).
- Default sharding: **each endpoint gets its own OS thread + current-thread runtime; the accept loop, all connection
  drivers on that endpoint, all TCP stream pumps, and all UDP session readers all run on this one thread**
  (`main.rs:485-556` `spawn_ingress_shard`; `main.rs:566+` `accept_loop`).
  ⇒ **bidirectional traffic of one connection on a single shard shares one core**; the full-duplex throughput ceiling = single-core
  processing capability, independent of that connection's quinn. In a 2–4 core router form factor the server has only 2–4 shards.
- All connections share **one** `ServerConfig` transport preset → the bulk preset asymmetry described in §1.2
  (bulk connections on the server side still have a 1 MiB DATAGRAM buffer + ACK threshold 2). quinn 0.11 has no hook
  to select a transport config by ALPN/SNI before the handshake; per-class requires separate ports/endpoints.

### 1.4 Verification conclusions on the README "performance design" section

| README claim | Verification result |
|---|---|
| "one exact-capacity allocation + one copy per UDP payload" | holds (`src/mqp/datagram.rs:93-135`); quinn internally copies once more into the packet buffer (`frame.rs:905-913` `extend_from_slice`) → **the send path actually has 2 copies** |
| "zero-copy TCP↔QUIC pump" | holds (`src/tcp/pump.rs`) |
| "GSO/GRO batched I/O" | Linux only; 0 on macOS with this dependency configuration |
| "ECN + PMTU" | ECN on by default (effective on Linux); PMTU opportunistic, may not take effect when saturated |
| "A TRAIN amortizes the frame over every payload that fits" | holds, but only for ≤512 B payloads (`BATCH_SMALL_MAX`); >512 B uses the MQP-2 fragmentation path (one frame per fragment) |

---

## 2. `send_datagram` per-packet cost model (quinn 0.11.12 / quinn-proto 0.11.19)

### 2.1 Call chain (hop-by-hop references)

The application calls `try_send_datagram` (`src/udp/send.rs:84-95`) → `conn.send_datagram_wait(d).now_or_never()`:

1. `SendDatagram::poll`: `state.lock("SendDatagram::poll")` (`quinn-0.11.12/src/connection.rs:846-890`);
2. `Datagrams::send(data, drop=false)` (quinn-proto `connection/datagrams.rs:31-65`):
   - validate whether DATAGRAM is enabled (`datagram_receive_buffer_size.is_none()` → `Disabled`), whether the
     peer supports it (`peer_params.max_datagram_frame_size` → `UnsupportedByPeer`), and the size cap
     `min(max_datagram_size(), send_buffer_size - size_of::<Datagram>())` (`TooLarge`);
   - after the send buffer space check (`Blocked`), `outgoing.push_back(Datagram { data })`;
3. `state.wake()`: take the driver waker and call `Waker::wake` (`connection.rs:1221-1225`);
4. Failure semantics: `Blocked` puts Bytes back into the future, parked on `datagrams_unblocked.notified()`
   (this project's `now_or_never` drops immediately → new packets are dropped and counted, not queued and awaited).

### 2.2 Send-side cost breakdown

| Stage | Cost (estimate/measured) | Notes |
|---|---|---|
| MQP encoding (frame allocation + copy) | **15–30 ns/frame [measured]** | `examples/frame_bench.rs:17-25`: 128 B same-thread 15–19 ns, 1200 B 25 ns |
| `send_datagram_wait` uncontended | **~50–150 ns [estimate]** | std Mutex lock/unlock ~10–20 ns + VecDeque push + `Waker::wake` + future construction/drop |
| **state lock contention (critical)** | **0 or several µs–tens of µs [estimate]** | the driver **holds the lock during the whole `ConnectionDriver::poll` round**: process events→`drive_transmit` (at most 20 datagrams / at most 10 GSO segments per `poll_transmit`, including AEAD encryption and the `try_send` syscall)→timer→event forwarding (`quinn-0.11.12/src/connection.rs:256-287`). A cross-thread sender **blocks** on the `std::sync::Mutex` (no try_lock). A fully loaded Linux GSO round is ~5–25 µs; macOS without GSO (20 sendmsg) ~30–80 µs |
| per DATAGRAM on the driver side | Linux **~0.5–1.1 µs**; macOS **~1.5–3.5 µs [estimate]** | AEAD encryption/decryption of 1.2–1.4 KB ≈ 0.3–0.9 µs (AES-GCM/AES-NI, aws-lc-rs) + packet assembly 0.05–0.15 µs + syscall amortization (Linux GSO 10 segments per sendmsg → 0.02–0.05 µs/packet; macOS 1–3 µs each) |
| GSO intra-batch padding | ≤6–8 B/packet [model] | DATAGRAM max body = MTU−38, actual packet = MTU−8 (2-byte PN) → each packet in the batch pads 8 B to segment_size (quinn-proto `connection/mod.rs:645-700`) |

### 2.3 Receive-side cost breakdown

quinn's receive is two-stage: the **endpoint driver** does the syscall + `PartialDecode` + CID lookup + event delivery;
**each connection driver** does the full decryption/frame parsing/enqueue inside the lock (`quinn-proto/src/endpoint.rs:148-260`;
`quinn-0.11.12/src/endpoint.rs:742-850`; `connection.rs:256-287`).

| Stage | Cost (estimate) | Notes |
|---|---|---|
| recv syscall | Linux ~0.02–0.1 µs/packet (recvmmsg 32 entries + GRO 64 segments amortized); macOS **1–2 µs/packet (one recvmsg per packet)** | quinn-udp `unix.rs:433-581,806-809`; macOS goes through `recv_single` |
| endpoint partial decode + CID routing + event channel | ~0.1–0.3 µs/packet | one `mpsc::UnboundedSender::send` per packet (including node allocation + target task wake) |
| decryption + frame parsing | ~0.3–0.9 µs/packet | inside the connection driver lock |
| DATAGRAM enqueue + `DatagramReceived` notify | ~0.05–0.2 µs/packet | `split_to` zero-copy slice (`frame.rs:567-573`); `read_datagram` locks once per DATAGRAM |
| application consumption (relay forwarding / dispatcher) | Linux ~0.1–0.5 µs (sendmmsg group amortized); macOS ~1–3 µs | the client dispatcher drains ≤32 packets per wake (`client/dispatcher.rs:733-860`); the server has one reader task per session (`server/reader.rs:1132`) |

> Everything above except frame_bench is an **estimate**; the §5.3 counters + an `examples/sendcost_bench.rs` microbenchmark
> can calibrate this table into measured values on the target machine. **The conclusion only needs relative magnitudes**: per-packet
> cost is dominated by "encryption + syscall + task wake"; the `send_datagram` API itself is cheap when uncontended; what is really expensive
> is **cross-thread contention**.

### 2.4 Packet coalescing behavior: what quinn already does, and does not do

**Already does**: within the same `poll_transmit`, `populate_packet` uses a while loop to write multiple queued DATAGRAM
frames into the same QUIC packet (quinn-proto `connection/mod.rs:3351-3368`), provided
`buf.len() + Datagram::SIZE_BOUND < max_size`. GSO then packs at most 10 packets into one sendmsg
(`quinn-0.11.12/src/connection.rs:1020-1023,1341`). Measured implications:

| Scenario | Frames per packet [model] | Packets per sendmsg |
|---|---:|---:|
| 60 B payload, one send per frame and queued in the same poll | 17 | 1 (occupies only 1 segment) |
| 60 B payload using the existing MQP-3 TRAIN | **18** | 1 |
| 1200–1400 B payload (near MTU) | 1 | Linux 10 / macOS 1 |
| 28 B payload (queued in the same poll) | 32 | 1 |

**Does not do (two real boundaries)**:

1. **FIFO head-of-line blocking**: `DatagramState::write` takes the head; if it does not fit in the current packet it `push_front`s and returns false,
   and the loop breaks (quinn-proto `connection/datagrams.rs:212-227`, comment verbatim: *"Future work: we could be
   more clever about cramming small datagrams into mostly-full packets when a larger one is queued
   first"*). ⇒ a near-MTU head-of-line DATAGRAM makes a bunch of small packets behind it open new packets, wasting
   ~1 KB at the packet tail. A connection mixing small and large packets therefore gets a small number of extra packets.
2. **DATAGRAM written before STREAM**: `populate_packet` order is ACK/control → DATAGRAM → STREAM
   (quinn-proto `connection/mod.rs:3350` vs `:3408`), so UDP flooding on the same connection fills the packet
   first, and TCP STREAM can only use the remaining space/the next packet → **TCP and UDP must never share a connection** (the existing topology is correct).

### 2.5 Exact semantics of `Blocked` / `TooLarge` / `max_datagram_size`

- `max_datagram_size() = current_mtu − predict_1rtt_overhead(None) − Datagram::SIZE_BOUND`
  = MTU − 29 − 9 = **MTU − 38** (quinn-proto `connection/datagrams.rs:86-100`;
  `connection/mod.rs:3763-3787`), then min with the peer's `max_datagram_frame_size` (the quinn advertised value =
  `min(receive buffer, u16::MAX)`, i.e. 65535 when the buffer is ≥64 KiB; the path budget is always smaller in practice,
  `transport_parameters.rs:170-172`; both sides advertise `min_ack_delay` so the ACK_FREQUENCY extension is effective in both directions,
  `transport_parameters.rs:176-179`). MTU is "max UDP payload": 1200 → 1162,
  1360 → 1322, 1400 → 1362, 1472 → 1434.
- Two sources of `TooLarge`: path MTU shrink (`drop_oversized` drops over-limit DATAGRAMs from the queue on every MTU
  change, `datagrams.rs:67-83`) and encoder budget expiry (this project does not re-read within 100 ms; see the `TooLarge`
  throttling on both sides in `udp/send.rs:190-212`, `server/reader.rs:86-100`).
- `Blocked`: send buffer full. This project's `try_send_datagram` chooses "drop the new packet and count it",
  while quinn's `send_datagram` "drops the oldest" and returns Ok (`udp/send.rs:43-95` has the detailed rationale).
- Max single-frame application payload (flow 0, no inline address) = `MTU − 38 − 5`: 1200→**1157**,
  1360→1317, 1400→1357, 1472→**1429**. ⇒ **a 1420 B WireGuard inner payload can only be single-frame with
  `initial_mtu=1472`** (1420+5+38=1463 ≤1472); under 1360/1400 it necessarily takes 2 fragments.

### 2.6 Quantification tables (IPv4; formulas in Appendix A)

**Table A: a single MQP SINGLE (flow 0, 5 B header) occupying a packet alone**

| payload | wire | total overhead share | of which MQP header |
|---:|---:|---:|---:|
| 28 B (STUN) | 91 B | 69.2% | 5.5% |
| 60 B (DNS) | 123 B | 51.2% | 4.1% |
| 128 B | 191 B | 33.0% | 2.6% |
| 200 B (game) | 263 B | 24.0% | 1.9% |
| 512 B | 575 B | 11.0% | 0.9% |
| 1000 B | 1063 B | 5.9% | 0.5% |
| 1157 B (1200 MTU cap) | 1220 B | 5.2% | 0.4% |

> Fixed overhead = 20 IP + 8 UDP + 27 QUIC header(1+8 DCID+2 PN+16 tag) + 3 DATAGRAM frame header = 58 B.
> Conclusion from the "total overhead" column: **45–60% of small packets is QUIC/IP fixed overhead, not the MQP header**; the MQP-3 rewrite
> headroom on a 60 B payload is at most ~4–8%, which is exactly the conclusion of PROTOCOL_ANALYSIS; this document's re-verification holds.

**Table B: packing efficiency of the existing MQP-3 TRAIN (MTU 1200, flow 0, item=1B flags+1–2B len)**

| payload | item | items per packet | wire/payload | same payload as a single frame alone |
|---:|---:|---:|---:|---:|
| 28 B | 30 B | 38 | **1.13** | 3.25 |
| 60 B | 62 B | 18 | **1.09** | 2.05 |
| 128 B | 131 B | 8 | **1.09** | 1.49 |
| 200 B | 203 B | 5 | **1.08** | 1.32 |
| 512 B | 515 B | 2 | **1.07** | 1.12 |

**Table C: the same payload using "multiple send_datagram" but coalesced by quinn into the same packet**

| payload | frames per packet | wire/payload | TRAIN relative to it |
|---:|---:|---:|---:|
| 28 B | 32 | 1.35 | −16% |
| 60 B | 17 | 1.19 | **−8.0%** |
| 128 B | 8 | 1.12 | −2.7% |
| 200 B | 5 | 1.10 | −1.5% |
| 512 B | 2 | 1.07 | −0.1% |

⇒ TRAIN's real benefit = small packets 2–8% wire + (up to 64 items) 1 send instead of N; **bulk has no benefit**.

**Table D: reverse ACK overhead (downlink 300 Mb/s, ACK frame ~12 B, v4 packet 70 B)**

| ACK threshold | 1 ACK per N packets | reverse bandwidth | share of downlink bytes | ACK rate @MTU1200 |
|---:|---:|---:|---:|---:|
| 1 (quinn default without the extension) | 2 | 8.98 Mbps | 2.87% | 16.0k/s |
| 2 (interactive preset) | 3 | 5.99 Mbps | 1.91% | 10.7k/s |
| 8 (bulk preset) | 9 | 2.00 Mbps | 0.64% | 3.6k/s |
| 16 | 17 | 1.06 Mbps | 0.34% | 1.9k/s |

> The table computes "ACK only when the count **exceeds** threshold" (quinn semantics, `build.rs:222-223` comment);
> the reverse direction also has ACK-generation CPU (each ~1–3 µs [estimate]); 10.7k ACK/s ≈ 1–3% of a single core.

**Table E: impact of MTU on bulk / fragmentation (MQP single-frame cap & fragmentation elimination)**

| Scenario | MTU 1200 | MTU 1360 | MTU 1400 | MTU 1472 |
|---|---|---|---|---|
| 1200 B payload | 2 fragments (1144+56), wire 1352, 2 sends | **1 frame**, 1263, 1 send | 1 frame, 1263 | 1 frame, 1263 |
| 1420 B payload | 2 fragments, 1572, 2 sends | 2 fragments, 1572 | 2 fragments, 1572 | **1 frame, 1483, 1 send** |
| 1200→1360 benefit | — | wire **−6.6%**, sends/packets **−50%** | same as 1360 | same as 1360 (for 1200B) |
| single-frame cap | 1157 | 1317 | 1357 | 1429 |
| TCP (application bytes per packet) | 1168 | 1328 | 1368 | 1440 |
| TCP packets per MiB | 898 | 790 (−12%) | 767 (−15%) | 728 (−19%) |

PLPMTUD's search sequence from 1200 to 1472 is 1336→1404→1438→1472 (quinn-proto `mtud.rs:315-350`);
each probe has to wait for one ACK (~1 RTT): **a 140 ms link takes ≈560 ms to reach the top, and probes are sent only on a poll where the send queue is empty**
(`connection/mod.rs:950`). ⇒ For continuously saturated bulk connections, **do not expect PMTU to upgrade automatically**.

### 2.7 Conclusion: is "1 frame = 1 send_datagram" worth changing?

- **bulk (≥512 B)**: not worth it. One packet can hold only one near-MTU payload; reducing send calls is only possible by
  "raising MTU" (turning 2 fragments into 1 frame, calls/packets −50%) or "switching to QUIC STREAM" (not applicable: UDP needs unreliability).
  No "super-frame" can fit a 1200 B payload into a 1162 B budget.
- **small packets**: TRAIN already compresses 17–18 payloads per packet into 1 send; the remaining space is cross-session:
  when each session has only one 60 B packet per burst, the current state is N sends + quinn best-effort coalescing
  (N single frames coalesced into 1 packet, wire/payload 1.19), while a cross-session super-frame can reach 1 send + 1.16
  (**wire −2.4%, send −N+1**). **The CPU benefit is real but not huge (5–15% of send path), the wire benefit <3%.**
- Therefore the design document should not present "cross-session aggregation" as a bandwidth item; it is a **CPU/pps item**, and most of it
  can be obtained with an architectural measure (per-connection aggregated sending) without changing the wire.

---

## 3. "Full duplex": precise definition and gaps

### 3.1 Transport layer: what is really coupled

First, be clear: **QUIC's data plane is inherently full-duplex**. Each connection has independent packet number spaces and congestion control instances
(one per endpoint), loss detection/PTO/RTT estimation in the two directions; data in one direction is not predicated on data in the other.
The only real cross-direction couplings are:

| Coupling item | Mechanism/evidence | Magnitude | Can it be eliminated |
|---|---|---|---|
| Same-connection driver task and state lock | receive decryption, send encryption, ACK generation, and the send queue are all inside the same connection driver's lock (`quinn-0.11.12/src/connection.rs:256-287`) | single-task CPU 100% at full load, shared by both directions; cross-thread senders block tail latency 5–50 µs [estimate] | cannot be eliminated; can only **co-locate on the same core/runtime** to reduce scheduling cost, or use independent connections per direction (current class isolation) |
| Reverse ACK traffic + generation CPU | Table D: at 300 Mb/s downlink, reverse 0.6–2.9% bandwidth + 3.6–10.7k ACK/s generation | bandwidth <2%; CPU 1–3% [estimate] | tune `ack_threshold`/`max_ack_delay` (client bulk already has 8/10ms; no bulk preset on the server side) |
| The core of the same server ingress shard | under the default shard topology all connections/flows/sessions of one endpoint are on one core (§1.3) | single-shard unidirectional ~hundreds of Mbps; bidirectional total limited by one core | only more endpoints/multiple processes, not via protocol |
| Multiple sessions/flows within the same direction sharing cwnd/pacing/DATAGRAM FIFO | quinn has no per-flow scheduling (see §4.2) | bulk flows within the same direction can starve latency flows | requires protocol-level scheduling or connection isolation |
| MTU / PMTU / ECN state | one per path, shared by both directions | — | no need to eliminate (it should be shared) |

Couplings that do **not** exist (do not invent them): the cwnd, loss recovery, flow control (STREAM's MAX_DATA is unidirectional),
PTO timers, and 0-RTT/key spaces of the two directions are all independent. **"Full duplex" will not make the uplink faster or the downlink slower—**
the link's uplink/downlink bandwidth is shared to begin with; the protocol can only decide **how to schedule**.

### 3.2 Protocol layer: MQP-3 asymmetry list (the real gap)

Evidence: `src/mqp/v3.rs` (codec), `src/bin/myquic2-client/assoc.rs` (uplink),
`src/bin/myquic2-server/reader.rs` (downlink), README `MQP-3` section (`README.md:590-745`).

| # | Symptom | Evidence | Impact | Quantification |
|---|---|---|---|---|
| P1 | **flow table owned by the client**: the client allocates ids, the server only installs on inline open; the server cannot open flows | `v3.rs:640-780` (FlowTable); `assoc.rs:350-430`; `reader.rs:79-190` | downlink compression depends on uplink install; server-initiated push can only use `NO_FLOW` inline | — |
| P2 | **pure-uplink flows are never compressed**: the client must wait for one "downlink frame that compresses downlink" as an implicit ACK before switching from inline to compressed (`assoc.rs:340-400`) | same as left; README "Flow lifecycle" | uplink-only small-packet flows carry 7/19 B extra address per frame (v4/v6) | 60 B packet +5.7% (v4)/+13% (v6); 128 B +3.7%/+9% |
| P3 | **no control plane**: `MQP3_CTL` has only a constant, no codec/opcode; no FLOW_ACK/CLOSE/CAPS/priority/receive feedback | `v3.rs:25`; README "CTL reserved" | cannot explicitly confirm/close/negotiate; cannot do priority, FEC, receiver credit; protocol evolution can only rely on "matched deployment" | capability item |
| P4 | **the server cannot proactively open flows/push** (full-cone unrequested sources can only be inline) | `reader.rs:102-190` (`MQP3_NO_FLOW`) | WebRTC/P2P inbound and similar scenarios add 7–19 B per frame and cannot compress | 28–60 B inbound: v4 +5.7~7.7%, v6 +13~17% |
| P5 | **one TRAIN = one direction + one session**: no cross-session frame coalescing/scheduling | `v3.rs:286-360` (TRAIN header carries sess) | cross-session small packets can only rely on quinn coalescing; no per-session scheduling | §2.7 |
| P6 | **no in-band ACK/receive credit**: when quinn's receive buffer is full it drops the oldest DATAGRAM, and the sender is unaware | quinn-proto `datagrams.rs:125-155` (`while ... self.recv()`) | slow consumers cause "silent packet loss" (does not affect CC because the packet has already been ACKed) | flood scenarios (README `udpps` baseline 96.9% loss may include this chain) |
| P7 | >512 B payload uses MQP-2 fragmentation: each fragment carries the full address, no flow, no v3 compact header | README "FRAG not wired"; `src/udp/fragmenter.rs` | 18 B (v4)/30 B (v6) header per fragment; no cross-fragment reuse | with 1200 B 2 fragments the header is 3% of payload, wire +6.6% vs a single frame (when MTU allows) |
| P8 | one session is pinned to one connection and one shard (`udp_bind` first packet decides for life) | `pool.rs:429-460` | single assoc throughput ≤ single shard single cwnd; cannot aggregate across connections | §4.4 |

### 3.3 Architecture layer: 7 connections vs 1 connection

| Dimension | Current: 4 TCP + 3 UDP independent connections | If merged into 1 connection + protocol class |
|---|---|---|
| Per-direction congestion isolation | **yes** (independent cwnd/pacing/loss domain per connection) | lost; all flows share one cwnd (quinn has no stream priority) |
| Receive/endpoint parallelism | **yes** (independent endpoint/driver/core per slot; server endpoint count = core count) | single endpoint single recv loop → single-core receive bottleneck |
| Latency isolation (bulk vs interactive) | **yes** (independent queues and cores) | requires protocol-level priority + application-layer scheduler, and cwnd is still shared |
| Memory/admission | transport 7 × 14.25 ≈ 100 MiB, plus endpoint userspace ~20 MiB + kernel caps 112 MiB; 4096 connection cap / 7 ≈ **585 clients** | transport 3 × 14.25 ≈ 43 MiB + endpoint ~9 MiB + kernel caps 48 MiB; ≈ 1365 clients/4096 connections |
| Handshake/keepalive | 7 TLS/heartbeats | 3 |
| Applicability | there is currently no stream priority/multipath; **this is the only real isolation mechanism under quinn 0.11** | only valid after the protocol layer builds a scheduler |

**Conclusion**: do not merge classes into one connection for the sake of "full duplex". Keep **transport-level isolation** (interactive /
bulk, TCP / UDP), and do protocol-level multi-session multiplexing and priority **within each connection**. What can be merged:
multiple connections within the same class (e.g. 4 TCP bulk connections) **after the protocol has session-level scheduling**, but the benefit is
memory/admission/handshake, the risk is loss of isolation; not recommended in this refactor.

### 3.4 Recommended definition: "MQP-3 full duplex" (can go directly into the design document)

> **Definition**: MQP-3 is a "full-duplex tunnel protocol" iff it satisfies the following 6 clauses (each with an acceptance test):
>
> **D1 Data plane symmetry**: any frame type (SINGLE/TRAIN/FRAG) can be sent in both directions; encoding/decoding does not distinguish direction;
> each direction has an independent send queue and scheduler, and backpressure in one direction (that direction's cwnd/send buffer full) must not block
> the other direction's control/data path.
>
> **D2 State plane symmetry**: each session maintains one flow table for "local send direction" and one for "local receive direction"
> at each endpoint; flow ids are allocated by the **sender** and installed by the receiver; flow open/confirm/close are done explicitly over the control channel,
> **not dependent on reverse data frames**. Pure-uplink and pure-downlink flows achieve the same compression ratio.
>
> **D3 Bidirectional control plane**: the control channel (suggest one QUIC stream rather than DATAGRAM; see §4.9) is usable in both directions,
> carrying HELLO/CAPS, FLOW_OPEN/FLOW_ACK (can be bitmap-based)/FLOW_CLOSE, optional PRIORITY/rate hints, and
> receive credit; **both ends can proactively open/close flows**, including server-initiated push.
>
> **D4 No direction dependency**: either side can send when the other side has not yet sent any payload in this direction (subject only to handshake and flow
> open constraints); it does not require "receiving reverse data first" in order to compress/confirm.
>
> **D5 Independent scheduling**: each direction independently performs TRAIN packing, MTU budgeting, priority/weighted scheduling; cross-direction coupling is only allowed to
> share CPU/reverse ACK traffic, and these couplings must be measurable (§5.3 counters).
>
> **D6 Measurable**: add a `udpbidir` benchmark: run both directions simultaneously (20k/50k pps per direction or 100 Mb/s each),
> verify (a) bidirectional aggregate ≥ 1.6× single-direction goodput; (b) interactive-direction p99 degrades ≤10% relative to single-direction;
> (c) neither direction shows >1% silent packet loss (P6).
>
> **Non-goals** (stated clearly to avoid over-promising):
> - not equal to "each direction gets 100% bandwidth": link/congestion control are physically shared;
> - not equal to reliable transport: DATAGRAM semantics remain unreliable, unordered, no retransmission;
> - does not eliminate intra-direction flow competition: requires §4.2 scheduling or connection isolation;
> - not a new QUIC feature: quinn/QUIC is already bidirectional; this definition constrains the MQP-3 protocol state machine.

### 3.5 Gap → action mapping

| gap | corresponding definition clause | minimal action | depends on wire change? |
|---|---|---|---|
| P1/P2/P4/P8 | D2, D4 | per-direction flow table + sender-allocated id + bitmap FLOW_ACK (or reliable ACK on the control stream) | yes |
| P3/P6 | D3 | control channel (QUIC stream) + CAPS/FLOW/CLOSE/priority/credit | yes (new frame semantics), the control stream itself reuses streams |
| P5 | D5 | cross-session frame multiplexing (optional, small benefit) + sender per-connection scheduler | yes (if cross-session coalescing is done) |
| transport coupling | D1, D5 | producers and driver in the same runtime/core; server separate endpoint/port per class | no |
| measurability | D6 | `udpbidir` + quinn stats counters | no |

---

## 4. Transport/protocol lever assessment

> For each item: mechanism / whether quinn can / expected benefit (by §4.10 workload number) / risk / conclusion.
> Benefits are labeled **[measured][model][estimate]**, and distinguish "bandwidth" from "CPU/pps".

### 4.1 Connection-level cross-session / cross-flow aggregation

- **Mechanism**: one send aggregator per connection, packing pending payloads from multiple sessions into one DATAGRAM
  (requires a new cross-session frame with sess in the item) or at least combining them into one batched send.
- **Can quinn**: packet coalescing is already automatic (§2.4); but "one send for multiple DATAGRAMs" **has no API**,
  each DATAGRAM is still one `send_datagram`. Cross-session frame coalescing can only be done at the MQP layer.
- **Expected benefit**: wire **−1–3%** (vs quinn's already-coalesced single frame, 60 B: 1.19→1.16); send calls
  **−N+1** (N=sessions per packet); CPU 5–15% of send path [model]; only effective for "many sessions with sparse small packets";
  0 for bulk/single session.
- **Risk**: cross-session frames amplify fate-sharing (one packet lost → multiple sessions lose simultaneously);
  requires a per-connection shared queue (introduces one cross-task hop, offsetting part of the benefit); fairness must change from task scheduling to explicit round-robin.
- **Conclusion**: **not a bandwidth lever, a pps/CPU lever**; lower priority than "producers on the same thread". If done,
  make it an optional frame type (`TRAIN_MULTI`), as the second step after the control plane/scheduler lands.

### 4.2 Per-flow priority / weighted scheduling

- **Mechanism**: carry 1–2 bit class/priority on items/flows on the wire; both ends maintain per-class queues;
  the sender has one weighted scheduler per connection (DRR/WFQ) taking packets by budget.
- **Can quinn**: **no**. quinn 0.11 has no datagram priority/weighted scheduling; `send_fairness`
  only applies to STREAM (`config/transport.rs:157-158,380`); DATAGRAM is strict FIFO
  (`datagrams.rs:31-65`), and there is no isolation across sessions within a connection.
- **What to do**: must **bypass quinn's FIFO**: one scheduling task per connection at the application layer, taking payloads from per-flow
  queues by priority → encode yourself → one send (still constrained by quinn's FIFO, but enqueue order is priority order).
  If the receiver wants to preserve priority, it also needs per-priority receive queues (quinn has only one incoming FIFO).
- **Expected benefit**: only effective when "multiple flows compete within the same class of connection in the same direction": interactive p99 under bulk competition
  **−30–80% [estimate]** (depends on queue depth/BDP); bandwidth 0. The current architecture already handles
  bulk-vs-interactive with connection isolation; what remains is intra-class competition (e.g. multiple WebRTC flows on one interactive connection).
- **Risk**: the scheduler itself costs CPU; interaction with quinn's pacing/CC is complex; priority starvation needs auditing;
  the receiver's DATAGRAM FIFO will scramble sender priority (unless the protocol guarantees priority-order sending and the network does not reorder—UDP does reorder,
  so the receiver must split queues itself, which requires the dispatcher to demux by class after decoding; the existing hub/dispatcher can be extended).
- **Conclusion**: **part of D3/D5, recommended**; but make clear that it improves latency fairness, not throughput.

### 4.3 Per-class independent connections (status quo) vs single connection + protocol class

See the §3.3 table. Additional quantification:

- Status quo 7 connections: client-side endpoint memory Linux ≈ 20 MiB resident receive scratch + 112 MiB kernel caps
  + 7×14.25 MiB transport budget ≈ 100 MiB; the server admits each client as 7 connections (4096 cap → 585 clients).
- Merged to 3 (TCP pool 1 + UDP interactive 1 + UDP bulk 1): endpoint memory ≈ 9 MiB + 48 MiB +
  43 MiB transport; admission → 1365 clients/4096.
- **But**: quinn has no stream priority → 4 TCP connections are the only source of "multiple cwnd + multi-core receive";
  merging the TCP pool leaves a single bulk flow still limited to one cwnd, and all TCP flows share one cwnd (queue behind each other).
- **Conclusion**: **keep class isolation**. Optional intermediate state: configure connection count within a class by core count (already has `quic_conns`
  1..16, `udp_egress_conns` 1..8); a "full-duplex protocol" should not assume a single connection, but should assume
  "each connection = one scheduling domain (one cwnd, one core, one priority domain)".

### 4.4 Single flow over multiple connections (bonding / multipath)—real benefit or hype?

- **Mechanism**: round-robin/weighted distribute a session's DATAGRAMs across N connections (UDP is unordered, naturally stripable),
  merging by session at the receiver; or do MPTCP/MP-QUIC-style reliable multipath (not needed in this scenario, UDP is unreliable).
- **Can quinn**: quinn 0.11 has no multipath, no cross-connection session; the MQP layer needs a `sess → [conn]`
  mapping, and **the receiver's session table is currently per-connection** (independent `SessionTable` per connection),
  so cross-connection requires the server side to route by global session → large protocol/architecture change.
- **Expected benefit** [estimate]: for **a single big flow** (WireGuard tunnel, single QUIC passthrough, large-file TCP upload/download):
  when limited by "single cwnd/BDP" or "single-flow packet loss limiting BBR throughput", N connections can gain **+30–80%**
  (2–3 connections; the cap is physical bandwidth/peer receive capability). For multi-flow scenarios **0** (total capacity is already shared among flows).
  TCP single-flow striping introduces reordering → requires reliable reordering, **not recommended**; UDP single-assoc striping is feasible.
- **Risk**: reordering (acceptable for RTP, disastrous for TCP inside the tunnel—but inside the tunnel it is UDP, handed back to the inner application);
  different PMTU/loss per connection; receiver merging/dedup; admission/memory ×N; debug complexity.
- **Conclusion**: **only worth it when the target scenario is confirmed to be "single big flow"**. Current `udp_bind` pins each assoc to
  one shard, so a single assoc indeed cannot use the total capacity of 2 bulk shards; but first measure "the actual single-assoc
  ceiling on Linux" before deciding (§5.4 matrix W3/W7). **Do not write it as a default optimization item.**

### 4.5 FEC and NACK/ARQ (for unreliable DATAGRAM)

- **Mechanism**: per-flow XOR/RS parity packets; receiver NACK + sender retransmission or recovery from the FEC group;
  requires in-band feedback (P3 control plane).
- **Can quinn**: DATAGRAM is not retransmitted, not flow-controlled; quinn's CC only sees "packet loss" and reduces rate by loss
  (BBR loss handling), **application-layer repaired packets are invisible to CC** → FEC/ARQ extra traffic worsens congestion,
  unless the protocol rate-limits itself.
- **Benefit**: only on lossy links (0.5–5% loss, mobile/Wi-Fi/cross-border):
  - FEC (10+1 group) at 1% loss raises single-packet arrival from 99% to ~99.9% (in-block recovery), at the cost of +10% bandwidth
    and encoding CPU; for bulk throughput **0 or negative** (BBR already handles loss; 10% redundancy actually lowers effective bandwidth);
  - NACK/ARQ adds ≥1 RTT (unacceptable for real-time traffic on a 140 ms link), only suitable for non-real-time reliable services—
    and reliable services should already use QUIC STREAM (quinn already has it).
- **Risk**: conflict with quinn CC, feedback channel cost, CPU, complexity; misconfiguration is a net loss on clean links.
- **Conclusion**: **not done by default**. Reserve per-flow policy + feedback fields in the control-plane design; as a Phase 3
  option, validate with A/B on real lossy networks. Do not believe "FEC can greatly improve throughput"—it trades latency/arrival rate,
  not bandwidth.

### 4.6 MTU 1200→1360/1400/1472 and GSO

- **Mechanism**: `initial_mtu` (config/both ends) determines bytes per packet and the DATAGRAM single-frame cap;
  GSO/GRO is auto-probed by quinn-udp (Linux), with no config item.
- **Can quinn**: yes (`TransportConfig::initial_mtu`, clamp 1200..=1472); but PMTU discovery is unreliable
  (§2.6), so **it must be configured explicitly**. The `gso` config item is ineffective.
- **Expected benefit** (Table E): bulk UDP 1200 B payload: wire −6.6%, packets/send calls −50%;
  1420 B payload: only 1472 can single-frame (wire −5.7%, calls −50%); TCP: packets −12–15%,
  wire −0.7%, +5–15% when CPU/pps-limited [model]; small packets (60–200 B): packing density +5–11%,
  wire improvement <2%. **GSO benefit only on Linux** (macOS 0).
- **Risk**: actual path MTU smaller than configured → quinn black-hole detection falls back to 1200 (a packet-loss storm);
  middleboxes/VPN encapsulation. Requires deployment-side confirmation; recommend default 1360 (safe for WireGuard-1400 scenarios) or configure per deployment.
- **Conclusion**: **the highest cost-performance single item** (no wire change, no protocol change), should be P0. Note that 1430+ B inner
  payloads need 1472, and 1472 should only be used on confirmed 1500 paths.

### 4.7 0-RTT / connection reuse

- **Mechanism**: quinn/rustls session tickets; this project already implements resumption + `into_0rtt()`
  (`src/bin/myquic2-client/auth.rs:277-320`), but **the auth token forces 1-RTT** (security consideration,
  README security model), and no application DATAGRAM is sent during 0-RTT (the connection is published only after auth).
- **Benefit**: saves one handshake RTT on reconnect/redial (CONNECT/ASSOCIATE first-byte latency −~1 RTT on a 140 ms link);
  steady-state throughput 0. Valuable for "path switching/mobile network" experience, almost no value for performance goals.
- **Conclusion**: **keep the status quo**; if "session recovery across connections" (a mobility extension of full-duplex) is pursued in the future,
  only then would session/flow state need to go into the ticket/control channel.

### 4.8 ECN

- **Mechanism**: quinn defaults to ECT0 (§1.2), effective on Linux; `process_ecn` treats CE as a congestion event.
- **Benefit**: 0–1% on modern shallow-buffered paths; limited significance for BBR; **already enabled, nothing to tune**.
- **Conclusion**: not a lever. The only thing worth considering is "inner ECN passthrough" (tunnel scenarios mapping inner CE to outer)—
  but SOCKS5 UDP does not carry ECN, MQP has no field, benefit/complexity does not justify it, **do not do**.

### 4.9 Additional: control plane / receive credit / server push (the core increment of full duplex)

- **Mechanism**: MQP-3 CTL already has a reserved kind (`v3.rs:25`); recommend **control messages go over a QUIC stream**
  (reliable, ordered, naturally bidirectional), rather than carrying control in DATAGRAM (which would require implementing retransmission yourself).
  Two optional routes:
  - A. **one bidi control stream per session**: cleanest lifecycle, but each session occupies a stream slot
    (server `MAX_STREAM_TASKS` 16384 / session cap 8192; also needs flow-control credit);
  - B. **one control stream per connection + session-id multiplexing**: more economical, recommended; control frame ~6-20 B.
- **Content**: HELLO/CAPS, FLOW_OPEN (sender-allocated id + target address), FLOW_ACK (bitmap, 8 B/64 flows,
  or simply rely on the stream's reliable ordered property to do "open stream = open flow"), FLOW_CLOSE, PRIORITY/CLASS, optional receive credit.
- **Benefit**: pure-uplink flow compression (P2: small packets 4–18% wire, worse on v6); server push/inbound compression
  (P4: inbound small packets 6–18% wire); explicit close reclaims resources (session 180 s idle → earlier release);
  capability negotiation allows the wire to evolve; receive credit/priority are prerequisites for §4.2/§4.5.
- **Cost**: the control stream's own bandwidth (one open/ack per flow, ~20-40 B; for short flows like DNS 1-request-1-reply,
  **explicit open+ack costs more than the 7 B saved**) → must be designed to amortize:
  **short flows keep inline + implicit confirmation; only "flows that send ≥N frames within a session" upgrade to compression** (N≈3),
  or piggyback the FLOW_ACK bitmap in any reverse TRAIN header (1 flag + 8 B).
- **Conclusion**: this is the substance of "full duplex", **recommended**, but design for amortization; do not blindly do per-flow ACK.

### 4.10 Total expected benefit table (by workload × lever)

Workload definitions: **W1** bulk TCP downlink (300 Mb/s); **W2** bulk TCP uplink; **W3** bulk UDP single assoc
(1200–1420 B payload); **W4** bulk UDP multiple assoc/multiple shard; **W5** small packets same session (60–200 B,
20–100k pps); **W6** many sessions small-packet fan-out (60 B); **W7** real-time low latency (p99 priority);
**W8** lossy mobile network (0.5–5%). Benefits are **directional model values** relative to current HEAD (not measured).

| Lever | W1 | W2 | W3 | W4 | W5 | W6 | W7 | W8 | Risk |
|---|---|---|---|---|---|---|---|---|---|
| MTU 1200→1360/1400 (config) | packets −12–15%, throughput +0–5% (CPU-limited +5–15%) | same as W1 | **wire −6.6%, calls/packets −50%** | same as W3 | packing density +5–11%, wire <2% | same as W5 | ~0 | same as W3; fallback risk if the path is unconfirmed | low |
| Window 4/8/4→8/16/8 (config, TCP only) | **single-flow cap 240→300 Mb/s (+25%)** | same as W1 | 0 (DATAGRAM has no flow control) | 0 | 0 | 0 | none (but load queueing worsens) | 0 | low (memory ×1.8/connection) |
| Producers on the same thread as driver + per-connection aggregated sending | CPU −3–10% | same as W1 | CPU −3–10% | same as W4 | **CPU −5–15%, tail latency improvement** | same as W5 | p99 improvement | p99/tail latency improvement | low |
| Protocol control plane + per-dir flow (D1–D5) | 0 | 0 | 0 | 0 | wire −4–8% (pure-uplink flows) | wire −4–13% (60 B, worse on v6; inbound 6–18%) | enables priority/credit | prerequisite for FEC/feedback on lossy links | medium (wire change + amortization design) |
| Cross-session aggregation (wire layer) | 0 | 0 | 0 | 0 | ~0 | **wire −1–3%, send −N+1** | ~0 | ~0 | medium (fate-sharing) |
| Per-flow priority/weighted scheduling | 0 | 0 | 0 | 0 | 0 | 0 | **p99 −30–80% (under intra-class competition)** | p99 −20–50% (loss + competition) | medium (scheduler/CC interaction) |
| Single-flow multi-connection striping | not recommended (TCP reordering) | same as W1 | **+30–80% (single big flow, when limited)** | **0** (multiple flows already share) | +0–20% (when single flow limited) | ~0 | 0 | +20–50% (multipath redundancy) | high (merging/reordering/admission) |
| FEC / NACK | −5–10% (if enabled) | same as W1 | 0/negative | 0 | 0 | 0 | arrival rate + | **residual loss −10–100×, +5–30% bandwidth** | high (conflict with CC) |
| server per-class transport | 0–1% | 0–1% | ACK CPU −1–2% | same as W3 | ~0 | ~0 | ~0 | same as W3 | medium (requires separate ports/ALPN) |
| 0-RTT / connection reuse | reconnect −1 RTT | same as W1 | same as W1 | same | same | same | same | same (already implemented) | low (auth forces 1-RTT) |
| ECN | already on | already on | already on (Linux) | same | same | same | same | same | no lever |

**Ordering recommendation (benefit/risk/effort)**:

- **P0 (no wire change, do first)**: (1) `initial_mtu` deployment value 1360/1400 (use 1472 for 1420 B traffic); (2) windows set to
  8/16/8 per deployment (or at least an 8 MB stream window); (3) F10: put the UDP relay task on the same
  runtime as the egress driver (eliminate cross-core lock/wake); (4) unify the bulk preset on the server side (currently asymmetric: 1 MiB dgram + ACK thr 2);
  (5) add §5.3 counters.
- **P1 (wire change, the full-duplex substance)**: control plane (QUIC stream) + per-direction flow table + bitmap/reliable confirmation
  + server push + item-level priority bit; `udpbidir` benchmark.
- **P2 (depending on measurement results)**: cross-session frame multiplexing; per-connection weighted scheduler; single-assoc striping (if W3 confirms
  it is the target scenario); optional FEC negotiation.
- **Do not do**: payload compression (ineffective for encrypted/random data, not worth the CPU and latency); carrying UDP over QUIC STREAM
  (changes semantics); cross-session aggregation as a "bandwidth" selling point; multi-connection striping as default behavior.

### 4.11 Negative list (explicitly do not do)

1. Do not merge 7 connections into 1 for "full duplex"—quinn 0.11 has no stream priority, and the cost of losing isolation
   far exceeds the memory/handshake saved.
2. Do not treat the `gso` config as a switch—it is ineffective; GSO/GRO is decided by the platform + quinn-udp.
3. Do not expect PMTU to upgrade automatically—a saturated connection may stay at `initial_mtu` forever.
4. Do not replace `send_datagram_wait` (drop-newest) with `send_datagram` (drop-oldest)—the loss-counting
   semantics change silently (`udp/send.rs:43-95`).
5. Do not do per-flow explicit ACK for short flows (DNS 1 request 1 reply)—control overhead exceeds the compression benefit.
6. Do not enable FEC by default on QUIC DATAGRAM—it is a net loss on clean links and conflicts with quinn CC.
7. Do not assume macOS numbers represent Linux: this quinn-udp version has no GSO/GRO on macOS, and the server defaults to a single shard.

---

## 5. Measurement plan and benchmark matrix

### 5.1 Existing evidence (can be cited directly, but none is sufficient to support conclusions)

| Evidence | Content | Limitation |
|---|---|---|
| `README.md:859-866` | 301 tests pass; real-binary TCP 1 MiB verification, UDP 8–8000 B sweep 0 loss, sharded ingress/`SHARD_RUNTIME=0` all verified; MQP-3 release smoke (macOS loopback): `udp`/`udpdomain` 1000/1000, `udpmulti` 4×500, `udppaced` 1k–5k pps 0 loss, `udpps` 2 s 10803/10803, `lat` p50≈0.98 ms | **all macOS loopback**; the README itself notes that Linux 2–4 core numbers are still a deployment gate |
| `examples/hotpath_bench.rs:1228-1241` | macOS baseline (2026-09-30): `udpraw` 73k pps, `udp` batch=64 26.8k pps, `udpps` 5 s/128 B offered 96.5k→goodput 2.6k pps (96.9% loss), 60 s → 370 pps | macOS has no GSO + single shard, not representative of Linux; and it is "blasting" rather than steady state |
| `examples/frame_bench.rs:17-25` | per-frame allocation cost: 128 B 15–19 ns / 1200 B 25 ns (same thread); pooling is worse (+39–324%) | only measures MQP encoding, not quinn |
| `PROTOCOL_ANALYSIS.md` | MQP-2→MQP-3 byte/call model (same order of magnitude as §2) | model, not verified on Linux |
| `PERF_ANALYSIS.md` | F1–F14 code-logic hotspots (mostly fixed); F10 cross-runtime not measured | baseline `d73809f`, earlier than v0.2.0 |

**There is no Linux 2–4 core pps/CPU/RTT data** → the benefit argument for this refactor must first fill this layer.

### 5.2 What macOS loopback can and cannot measure

| Capability | macOS local | Linux 2–4 cores (required) |
|---|---|---|
| Function/correctness (frame decoding, fanout, reconnect, fragment reassembly) | ✅ measurable | ✅ |
| Per-frame MQP encoding cost, allocation cost | ✅ (frame_bench) | ✅ |
| Single-connection p50 latency (no netem) | ✅ but RTT≈0, only the software path is visible | ✅ |
| GSO/GRO amortization, multiple packets per sendmsg | ❌ **this quinn-udp version has no GSO/GRO on macOS, 1 syscall per packet** | ✅ (GSO 64→quinn 10 segments, GRO 64) |
| Multi-core scaling (server shard × N) | ❌ default 1 endpoint/1 shard | ✅ (`quic_endpoints` 1/2/4) |
| Cross-runtime/cross-core send contention | ❌ `pin_to_core` no-op, many cores but isolation is meaningless | ✅ (`MYQUIC2_SHARD_RUNTIME=0/1` A/B) |
| ECN effective | ❌ dual-stack `IP_RECVTOS` unsupported → auto-off | ✅ (tcpdump sees TOS) |
| BDP/CC/window effects | ❌ loopback RTT≈0 | ✅ netem delay 70/140 ms |
| Loss/reordering | ⚠️ dummynet/pfctl available, but not comparable with Linux tc | ✅ `tc qdisc netem` |
| Real NIC/interrupts/softirq | ❌ | ✅ |

### 5.3 Counters to add (layered, sampling cost controllable)

**A. Taken directly from quinn `Connection::stats()` (`connection.rs:554`; note that reading stats takes the state lock →
low-frequency sampling, recommended every 1–10 s, or only in this project's 60 s reporter):**

| Counter | Formula/purpose |
|---|---|
| `udp_tx.datagrams` / `udp_tx.bytes` / `udp_tx.ios` | `bytes/payload` = wire efficiency; `ios/datagrams` = GSO amortization (should be ≪1 on Linux) |
| `udp_rx.*` likewise | receive side |
| `frame_tx.datagram` / `frame_tx.acks` / `frame_tx.stream` | `datagram/udp_tx.datagrams` = DATAGRAM frames per packet (coalescing rate); `acks/datagram` = ACK ratio |
| `path.rtt` / `path.min_rtt` / `path.cwnd` | CC/queue health |
| `path.current_mtu` / `sent_plpmtud_probes` / `black_holes_detected` | **verify whether PMTU actually upgrades** (critical!) |
| `path.lost_packets` / `lost_bytes` / `congestion_events` | distinguish "network loss" from "receiver buffer loss" |

**B. New application-layer counters (thread-local batching, following the existing style):**

| Counter | Location | Purpose |
|---|---|---|
| `send_calls`, `send_blocked`, `send_too_large` (by connection/class/direction) | the three return points in `src/udp/send.rs::try_send_datagram` | real cost per call × number of calls; verify TRAIN/aggregation benefit |
| `payloads_per_frame` (TRAIN items distribution) + `train_bytes` | encoding sites (client `assoc.rs`, server `reader.rs`) | packing efficiency (currently unobserved) |
| `staging_copies` / `frame_alloc` | encoding entry | verify the "copies per payload" assumption |
| `datagram_send_buffer_space` high-water mark | sample `conn.datagram_send_buffer_space()` (`connection.rs:512-519`) | whether the send queue is filled (precursor to drop) |
| `recv_queue_drops` (quinn receive buffer overflow) | existing `dgram_drops` + new | **make P6 silent loss observable**: quinn does not notify the application when dropping the oldest, only the difference between `frame_rx.datagram` and application counts |
| `relay_send_wouldblock` / `sendmmsg` batch size | existing metrics histograms (`udp/batch.rs`) | last-hop bottleneck |
| `direction_payload_bytes` (up/down counted separately) | existing `udp_stats::payload` plus a direction dimension | **full-duplex D6 verification** |

**C. System layer:**

- `perf stat -p <pid>`: cycles/instruction, context-switches, syscalls, page-faults (Linux);
  macOS `sample`/`spindump` only for a rough look.
- `strace -c -f`: sendmsg/recvmsg counts (verify whether GSO/GRO really takes effect).
- `tcpdump -i <if> -v udp port 8443`: packets/bytes/TOS (ECN)/burst; post-process the pcap to compute wire/payload.
- `/proc/<pid>/stat` + `/proc/<pid>/status`: CPU, RSS; qdisc `tc -s qdisc show dev lo` to see queues.

### 5.4 Benchmark matrix (Linux 2–4 core target machine; median of 3 runs per cell)

Prerequisites: `build --release`; server/client on the same machine (loopback or veth); first `tc qdisc del` to clear;
for RTT use `tc qdisc add dev lo root netem delay 70ms` (or 140 ms); for loss use
`loss 0.5%`/`2%`; record `taskset`, `quic_endpoints`, `MYQUIC2_SHARD_RUNTIME`,
`initial_mtu`, and window configuration.

| # | Command (`examples/hotpath_bench`) | Configuration | Metrics | Acceptance/stop-loss |
|---|---|---|---|---|
| M0 | `frame_bench` | — | ns/frame | calibration baseline; changes must not degrade >5% |
| M1 | `udp <socks> <echo> 20000 64` | default | recv_pps, loss | functional regression; loss=0 |
| M2 | `udpmulti <socks> <echo> 1/4/16/64 5000 64` | 1–4 cores | recv_pps, per-flow fairness | multi-assoc scaling linearity |
| M3 | `udppaced <socks> <echo> 30 128 <pps>`, pps=1k/5k/10k/20k/50k | MTU 1200 vs 1400; ACK thr 2 vs 8 | goodput, loss, CPU/pps | find the 0-loss knee; new protocol knee improvement ≥15% |
| M4 | `udpps <socks> <echo> 10 128` | same as above | offered/goodput/loss | record the collapse point, not an acceptance criterion (flood itself is not a goal) |
| M5 | `udp <socks> <echo> 20000 1` payload 1000/1200/1420 | MTU 1200/1360/1400/1472 (both ends) | recv_pps, wire bytes (tcpdump) | verify Table E: 1200→1360 wire −6.6%, calls −50%; `stats().path.current_mtu` must == configured value |
| M6 | `udpdomain <socks> <echo> 1000 64`; `udpdomainmulti 8 domains 4 assocs` | default | recv_pps, loss | domain target path does not degrade |
| M7 | `udpmulti` 200 assocs × 500, 60 B | 1/2/4 bulk shards | total pps, wire/payload | cross-session aggregation A/B (before vs after) |
| M8 | `lat <socks> <echo> 500 60` | netem 70ms; 0/0.5/2% loss | p50/p90/p99/p999 | latency acceptance for full-duplex/priority changes |
| M9 | **new `udpbidir`**: simultaneous downlink generation + uplink echo (or symmetric double echo) | 2–4 cores; 20k/50k pps; netem | per-direction goodput, p99, loss | D6: bidirectional aggregate ≥1.6× unidirectional; p99 degradation ≤10%; no silent loss |
| M10 | `bulk <socks> <server> 256 1` (downlink); uplink version (`server` variant or add `bulku`) | window 4/8/4 vs 8/16/8 | MB/s, wire bytes, CPU | verify 240→300 Mb/s |
| M11 | `lattcp <socks> <techo> 200 1024` | netem 0/70/140 ms | CONNECT p50, first-byte p50 | TCP path regression |
| M12 | A/B: `MYQUIC2_SHARD_RUNTIME=0` vs 1; `quic_endpoints` 1/2/4 | 2 cores/4 cores | pps, CPU, latency | verify same-threading/sharding benefit; revert topology if 0 is better |
| M13 | Long soak: `udppaced` 20k pps × 300 s; `udpmulti` 64 assocs × 10 min | default | RSS, drop counters, `cwnd/rtt/current_mtu` drift | no memory growth, no counter anomalies |
| M14 | Capture: `tcpdump -w` while running M5/M7 | — | wire/payload, DATAGRAM frames/packet, ACK ratio, TOS | validate models (Tables A–E) |
| M15 | `perf record -g -p <server/client>` M5/M9 | — | hotspots (quinn/rustls/relay/tokio) | confirm next optimization direction |

**A/B method**: run the same binary with "config A vs B"; "old HEAD vs refactor" runs two tags (wire-incompatible,
requires paired server/client replacement); each group 3×60 s, 10 s warmup first, take median and min; normalize CPU with `perf stat`
task-clock (pps/CPU-second is more stable than absolute pps). macOS only runs M1/M5/M8 for functional regression.

### 5.5 Three pilots to do first (completable in 1–2 days, directly determines refactor direction)

1. **MTU pilot** (M5 + tcpdump + `stats().path.current_mtu`): confirm the real wire/pps/CPU benefit of 1200→1360 on Linux;
   also verify whether PMTU really does not upgrade.
2. **Same-thread pilot** (M12 + M3): compare `MYQUIC2_SHARD_RUNTIME=0/1` and "relay task migration"
   (F10) pps/CPU/tail latency; this determines architecture change priority.
3. **Single-flow ceiling pilot** (M5 payload 1420, single assoc saturation + 2-shard striping prototype):
   confirm whether W3 is really limited by a single cwnd; this determines whether bonding is worth doing.

---

## 6. Risks and open questions (for Lead decision)

### 6.1 Risks

1. **PMTU assumption wrong**: raising the `initial_mtu` default to 1400/1472 on deployments with a smaller real path MTU triggers
   black-hole fallback (a packet-loss storm; quinn falls back to 1200); must be confirmed by deployment configuration or do startup probing.
2. **Wire change compatibility**: users allow wire incompatibility, but the README's "matched deployment" means both ends
   must upgrade together; `alpn="h3"` has no version gate by default (`src/mqp/ack.rs:3-13`). The refactor should explicitly add
   ALPN/control-plane version negotiation to avoid incidents during gradual rollout.
3. **Control plane complexity**: flow lifecycle + priority + credit + multipath stacked together easily introduces state bugs; recommend doing
   "per-direction flow table + bitmap ACK + server push" first, with priority/credit/FEC in phases.
4. **Short-flow amortization**: when DNS-type traffic dominates, explicit flow control may be worse than inline; must adapt by the N-frame threshold
   and verify in the `udpdomain` benchmark.
5. **Measurement environment**: a macOS dev machine + shared workspace cannot give credible pps; all performance conclusions must be re-measured on a quiet Linux
   target machine; all percentages in this document are directional models.
6. **Memory/admission**: opt-in 8/16/8 windows take each connection from 14.25→26.25 MiB, and 4096 connections from ~57 GiB to ~105 GiB;
   if the server is a small-memory router, windows must not be blindly enlarged (this is a configuration, not protocol, issue, but must go into deployment recommendations).

### 6.2 Open questions

1. **Target workload weight**: single big flow (VPN) vs many small-flow fan-out vs mixed—which is the optimization target? Determines whether bonding
   and cross-session aggregation are in scope.
2. **Is "full duplex" only for the UDP data plane**? (The TCP path (QUIC STREAM) is already full-duplex.)
3. **Is the deployment path MTU known** (WireGuard-1420 / PPPoE 1492 / 1500)? Determines the `initial_mtu` default.
4. **Target hardware**: 2–4 core ARM router or x86 exit node? Determines server endpoint count/thread topology recommendation.
5. **Wire incompatibility window**: can both ends be upgraded simultaneously, with no gradual coexistence requirement? (Affects whether CAPS/version negotiation is mandatory.)
6. **Is it acceptable to use a QUIC stream (one bidi/uni stream) instead of DATAGRAM for the control plane?** This is the decision with the largest
   implementation-complexity difference (see §4.9).

---

## Appendix A: Calculation conventions

- IPv4 fixed overhead/packet = 20 (IP) + 8 (UDP) + 27 (QUIC: 1 flags + 8 DCID + 2 PN + 16 AEAD tag) = **55 B**;
  plus the DATAGRAM frame header of 3 B (1 kind + 2 B varint length, payload ≥64 B) = **58 B**.
  IPv6 adds 20 B.
- `max_datagram_size = current_mtu − 29 (QUIC upper bound) − 9 (Datagram::SIZE_BOUND) = MTU − 38`.
  `current_mtu` is the "maximum UDP payload": IPv4 wire = MTU + 28.
- MQP-3 headers: SINGLE flow0 = 5 B; extra flow = 6 B; inline v4 = +7 B, v6 = +19 B;
  TRAIN header 6 B; item = 1 flags + 1–2 B LEB128 length + (optional 1 B flow) + (optional inline address);
  FRAG prefix = 11 B + address; MQP-2 datagram prefix = 5 B + address.
- Fragment chunk = `max_datagram_size − FRAG_PREFIX_LEN(11) − addr_len(7/19)`;
  the v4 chunk at MTU 1200 = 1162−11−7 = **1144 B** (`src/mqp/fragment.rs:211-216`).
- Throughput = window / RTT; BDP = rate × RTT; BBR initial cwnd = 200×1200 B = 234 KiB; min cwnd = 4×MTU.
- All percentages in this document were computed by `python3` using the formulas above; workload benefit ranges are models/estimates, not measurements.

## Appendix B: Main references

**Repository**: `Cargo.toml:20-47`, `Cargo.lock:1293-1338`; `src/transport/build.rs:130-281`;
`src/transport/limits.rs:1-102`; `src/config/tuning.rs:104-236,282-415`;
`src/config/server_conf.rs:20-34`; `src/config/client_conf.rs:15-30`;
`src/bin/myquic2-client/main.rs:88-107,150-300`; `src/bin/myquic2-client/pool.rs:429-460,806-813`;
`src/bin/myquic2-client/assoc.rs:180-430,960-1010`; `src/bin/myquic2-client/dispatcher.rs:700-870`;
`src/bin/myquic2-server/main.rs:125-170,328-556,566+`; `src/bin/myquic2-server/reader.rs:79-330,1132`;
`src/udp/send.rs:84-212`; `src/mqp/v3.rs:25-60,286-360`; `src/mqp/fragment.rs:29-75,211-216`;
`src/linux.rs:79-120,184-198`; `examples/frame_bench.rs:17-25`; `examples/hotpath_bench.rs:1-120,1228-1241`;
`PERF_ANALYSIS.md:326-343`; `PROTOCOL_ANALYSIS.md:79-184`; `README.md:147-190,590-745,755-790,859-866`;
`config-server.toml:15-17`; `config-client.toml:6-8`.

**quinn / quinn-proto / quinn-udp (registry)**:
`quinn-0.11.12/src/connection.rs:256-287,446-520,846-890,1020-1023,1221-1225,1334-1341,554`;
`quinn-proto-0.11.19/src/connection/mod.rs:463-770,950,3350-3408,3763-3787,1006,1563-1600`;
`quinn-proto-0.11.19/src/connection/datagrams.rs:31-65,86-108,125-155,212-227`;
`quinn-proto-0.11.19/src/connection/paths.rs:73,122`; `.../connection/mtud.rs:69-350,355-430`;
`quinn-proto-0.11.19/src/config/transport.rs:157-158,370-400,698-755`;
`quinn-proto-0.11.19/src/connection/stats.rs:136-176`;
`quinn-udp-0.5.16/src/unix.rs:119-140,189,237-252,433-581,614-632,719-799,806-855,978-996`;
`quinn-0.11.12/src/endpoint.rs:742-850`; `quinn-proto-0.11.19/src/endpoint.rs:148-260`.

---

## Summary for the Lead (≤30 lines)

1. QUIC is already full duplex (independent PN/CC/loss/RTT/PTO in each direction); what "full duplex" lacks is MQP-3 state symmetry plus a control plane.
2. Configuration: quinn 0.11.12/proto 0.11.19/udp 0.5.16; BBR (initial cwnd 234 KiB); DGRAM 1/2 MiB;
   windows 4/8/4 MiB; initial_mtu 1200; ACK thr 2/5ms, bulk 8/10ms; keepalive 5s / idle 60s (watchdog 40s);
   ECN on by default (Linux); the server has only the interactive preset → bulk asymmetry; the gso config is ineffective (log only).
3. GSO/GRO only on Linux (10 segments/sendmsg, GRO 64); this quinn-udp has no GSO/GRO on macOS, one syscall per packet,
   and the server defaults to 1 shard → macOS numbers cannot be extrapolated.
4. `send_datagram` is uncontended ~50–150 ns, but the driver holds the lock for a whole poll round (10–20 packets encrypted + syscall);
   cross-thread blocking can be 5–25 µs (Linux)/30–80 µs (macOS) → putting producer and driver on the same thread is the cheapest pps optimization.
5. quinn already coalesces automatically (17–18 small frames/packet) → cross-session aggregation saves only 1–3% wire plus send calls;
   TRAIN versus "already-coalesced single frames" saves −8% wire/−18× sends for small packets (implemented); no bulk gain, and
   1 payload = 1 send is determined by MTU.
6. MTU 1200→1360: a 1200 B payload goes from 2 fragments to 1 frame (wire −6.6%, calls −50%); 1420 B needs 1472;
   PMTU probes only when the queue drains, so a saturated connection may stay at 1200 forever—the highest value-for-effort configuration lever.
7. Full-duplex gaps: the flow table is client-owned only, the server cannot push → pure-uplink/inbound small packets cost 4–18% more (worse on v6);
   no CTL control plane (ACK/close/caps/priority/receive feedback); one TRAIN carries one direction and one session; 512 B+ goes through MQP-2 fragmentation.
   The only real transport coupling is: same driver task/state lock/core, reverse ACKs (0.6–2.9%), and shared cwnd in the same direction.
8. Recommended definition D1–D6: symmetric data plane / one flow table per session per direction (allocated by the sender) / bidirectional control plane
   (QUIC stream recommended) / no direction dependency (pure uplink also compresses) / independent per-direction scheduling / `udpbidir` acceptance;
   ≠ 100% bandwidth in both directions simultaneously.
9. Lever ranking: configuration (MTU/window) > same-threading/per-connection aggregate send > control plane + per-dir flow (4–18% small packets) >
   server per-class transport > single-flow striping (only single big flow +30–80%, high risk) > FEC/NACK (not by default) > cross-session aggregation.
10. Honest judgment: a protocol wire rewrite for bulk throughput is ≤1–3%; 10–30% comes from MTU/window/fragment elimination/same-threading;
    the single-flow ceiling can only be raised with multiple connections/multipath. Full duplex is a capability/fairness/latency item, not a throughput multiplier.
11. Measurement: must use Linux 2–4 cores + tc netem (70/140 ms, 0/0.5/2% loss); add quinn stats (cwnd/rtt/current_mtu/ios) +
    send_calls/payloads_per_frame/directional bytes; add `udpbidir`; matrix §5.4 M0–M15.
12. P0: set `initial_mtu` to 1400 per deployment (1472 for 1420 B traffic), windows per BDP, F10 same-threading, unify server bulk presets,
    add counters; run the 3 pilots first (MTU/same-thread/single-flow ceiling), then decide P1/P2. Open questions in §6.2 (workload,
    UDP-only, deployment MTU, target hardware, rollout window, whether a QUIC-stream control plane is acceptable).
