<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/hero-dark.svg">
  <img src="assets/readme/hero-light.svg" alt="MyQUIC2 — the small-packet QUIC proxy. SOCKS5 in, QUIC/TLS 1.3 out, MQP-3 wire rev2 in between." width="100%">
</picture>

[![Release](https://img.shields.io/badge/Release-v0.2.1-16a34a?style=flat-square)](https://github.com/Terutoki/MyQUIC2/releases/latest)
[![Tests](https://img.shields.io/badge/Tests-530_passing-16a34a?style=flat-square)](#-verification)
[![CI](https://github.com/Terutoki/MyQUIC2/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/Terutoki/MyQUIC2/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.99%2B-dea584?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![QUIC](https://img.shields.io/badge/QUIC-TLS_1.3-38bdf8?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc9000)
[![Protocol](https://img.shields.io/badge/Protocol-MQP--3-f59e0b?style=flat-square)](#-mqp-3-rev2-wire)
[![Platform](https://img.shields.io/badge/Platform-Linux_%7C_macOS_%7C_OpenWrt-6366f1?style=flat-square)](#-install)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](https://github.com/Terutoki/MyQUIC2/blob/main/LICENSE)

**SOCKS5 in · QUIC / TLS 1.3 out · MQP-3 rev2 in between**

[Architecture](#-architecture) · [Wire](#-mqp-3-rev2-wire) · [Protocol in depth](#-mqp-3-rev2-protocol-in-depth) · [Full duplex](#-full-duplex) · [Stager](#-cross-session-stager) · [Performance](#-performance) · [Security](#-security) · [Mermaid atlas](#-mermaid-atlas) · [Install](#-install) · [Quick start](#-quick-start) · [Verify](#-verification)

</div>

> [!IMPORTANT]
> **Wire-breaking by design.** This tree speaks **MQP-3 wire rev2**. It does not interoperate with v0.2.0 (v3 wire) or v0.1.x / MQP-2. Upgrade client and server together; mixed-version deployment is not supported.
>
> The protocol is still called **MQP-3**. The revision lives in `CTL HELLO/CAPS wire_ver = 2`, not in the product name.

---

## ✨ What it is

MyQUIC2 is a **SOCKS5 proxy built for the shape of modern UDP traffic**: DNS, QUIC handshakes, game state, VoIP, telemetry, small RPCs and multiplexed application fan-out. It accepts ordinary SOCKS5 `CONNECT` and `UDP ASSOCIATE` requests, carries both over one QUIC / TLS 1.3 tunnel, and uses **MQP-3 wire rev2** to keep the UDP data plane small, stateless in the right places, and bounded in memory.

The client is a pool of independent QUIC endpoints. The server is admission-first: it checks the token and the memory budget before it allocates per-connection state, then resolves, authorizes and forwards each datagram. There are exactly two binaries and one wire revision. No mixed-version negotiation, no hidden control stream, no payload compression, and no attempt to turn UDP into a reliable stream.

### Why MyQUIC2

| Property | What it means in practice |
|---|---|
| **Small-packet first** | A steady UDP frame is 2 B with a one-byte flow id, a `FRAG` header is 8 B, and several payloads can share one DATAGRAM. The gains land on DNS, gaming, VoIP and RPC traffic, not on bulk streams that are already header-insignificant. |
| **UDP-native** | UDP stays unreliable and unordered. There is no retransmission layer, no head-of-line blocking and no per-payload ACK. A lost fragment drops that payload; a lost `TRAIN` drops the payloads it carried. |
| **Full-duplex by construction** | Both endpoints allocate flow ids from disjoint halves of the id space. Client-owned, server-owned, domain, port-rebound and full-cone flows all use the same tables and the same frame set. |
| **Cross-session aggregation** | One connection-level stager packs small payloads from every association into same-flow or dictionary `TRAIN` frames, with per-session FIFO order and a round-robin cursor. |
| **Bounded memory** | Every peer-fillable structure has a hard bound: stager, both reassemblers, flow registry, DNS in-flight set, pre-HELLO buffer, quinn's per-stream reassembly metadata (via the parked-header-stream credit) and the admission charge. The admission bound also charges the process-wide pools a peer can drive (retry, DNS waiters, worker scratch, stream assembly). |
| **Zero-copy TCP** | TCP rides a QUIC stream. The SOCKS5 success reply is optimistic, and the relay uses borrowed QUIC halves and vectored writes. |
| **One revision, fail-fast** | `wire_ver=2` lives in `CTL HELLO/CAPS`. A peer that does not answer CAPS is closed after 2 s; there is no silent downgrade to MQP-2 or the v0.2.0 wire. |
| **Observable by default** | Frame kinds, `TRAIN` items, inline fallbacks, flow open/ack/reject/close, compression ratio, drop reasons and transport stats are counted and periodically reported. |

### At a glance

- **TCP is a QUIC stream.** The SOCKS5 success reply is optimistic; payload bytes are pumped with zero-copy buffers and borrowed QUIC halves.
- **UDP is an MQP-3 rev2 DATAGRAM plane.** Connection-scoped flow ids, 2 B steady headers, full-duplex flows, cross-association `TRAIN` packing, compact 8 KiB `FRAG`.
- **One client, one server, one config each.** No mixed-version negotiation, no payload compression, no hidden control stream.
- **UDP stays unreliable.** A lost fragment drops that payload; a lost `TRAIN` drops the payloads it carried. Bounded reassembly and stager queues cap the fate sharing.

## 🧭 Architecture

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/architecture-dark.svg">
  <img src="assets/readme/architecture-light.svg" alt="Architecture: SOCKS5 client pool, QUIC/TLS tunnel and MQP-3 rev2 data plane, admission-first server ingress" width="100%">
</picture>
</p>

MyQUIC2 is split along the only boundary that matters for latency: **per-connection state lives with the connection, and the data plane never shares a receive path**. On the client, every pool slot owns its own QUIC endpoint, UDP socket and pinned runtime; TCP and UDP egress can be isolated by class, and the thread-local egress memo turns a steady flow into a handful of atomic loads. On the server, `SO_REUSEPORT` endpoints accept in parallel, the token gate and memory admission run before per-connection allocation, and each UDP association gets one 64 KiB session socket and one reader task.

| Layer | Responsibility | Key design choice |
|---|---|---|
| **Client pool** | 4 TCP + 3 UDP slots by default; interactive and bulk sharding | One endpoint, socket and runtime per slot; selection-time path health; reconnect watchdog below the QUIC idle timeout |
| **Associations** | SOCKS5 `CONNECT` and `UDP ASSOCIATE`; app address pinning | The first valid UDP packet locks the app address; one association maps to one `session` |
| **Shared codec** | MQP-3 rev2 frames, flow tables, fragmentation, stager, reassembly | One implementation used by both binaries and by the tests |
| **Transport** | QUIC / TLS 1.3, BBR + ECN, PMTU, GSO/GRO | No custom congestion control and no custom crypto; QUIC does the hard part |
| **Server ingress** | `SO_REUSEPORT` endpoints, token gate, connection and memory admission | Admission before per-connection allocation; one endpoint per core, at most 8 |
| **Forwarding** | DNS, SSRF policy, TCP happy-eyeballs, UDP `sendmmsg` / `recvmmsg` | Resolve and authorize at the exit, never at the client |
| **Observability** | Counters, periodic reporter, drop warnings | Every frame kind and every drop reason is observable without a packet capture |

- **Pool-first client.** Every pool slot owns a QUIC endpoint, a UDP socket and a pinned runtime. TCP and UDP egress are isolated; the thread-local egress memo is lock-free, and the UDP hub caps the process at 4032 associations.
- **One wire, two transports.** TCP rides a QUIC stream; UDP rides MQP-3 rev2 DATAGRAMs. Shared pieces: TLS 1.3, BBR, PMTU discovery, GSO/GRO.
- **Admission-first server.** `SO_REUSEPORT` ingress endpoints, token auth, memory/connection admission, one 64 KiB session socket per association.

## 📡 MQP-3 rev2 wire

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/wire-dark.svg">
  <img src="assets/readme/wire-light.svg" alt="MQP-3 rev2 frames: DATA 2 B, DATA OPEN/INLINE, TRAIN same/dict, FRAG 8 B, CTL" width="100%">
</picture>
</p>

MQP-3 rev2 is a compact framing layer inside QUIC DATAGRAMs. It is deliberately **not** a reliable transport: QUIC supplies confidentiality, congestion control, loss detection and PMTU; MQP-3 supplies flow identity, first-frame addressing, aggregation and fragmentation. The revision is negotiated once, in `CTL HELLO/CAPS wire_ver = 2`; the protocol name stays MQP-3.

| Frame | First byte | Job | Steady header |
|---|---|---|---|
| `DATA` | `0x00` / `0x01` | one payload for a known flow, or the first `OPEN` / `INLINE` frame | **2 B** for `wire_id < 128` |
| `TRAIN` | `0x04` | several payloads in one DATAGRAM, same-flow or dictionary form | 3–4 B + ids; 1 B per item length |
| `FRAG` | `0x08` / `0x09` | one payload split across up to 64 fragments | **8 B** |
| `CTL` | `0x0C` | HELLO/CAPS and idempotent flow/session control | 2 B + opcode body |

- **`DATA` — 2 B steady.** A connection-scoped monotonic `wire_id` and the payload. No session, no address, no length.
- **`DATA OPEN / INLINE` — the first frame.** Self-describing `(session, address)`; OPEN repeats until ACKed. INLINE is the table-full fail-safe.
- **`TRAIN` — one frame, many payloads.** Same-flow: 3 B header + 1 B/item. Dict form mixes flows and associations in one DATAGRAM.
- **`FRAG` — 8 B steady.** Payloads up to 8 KiB; `(wire_id, frag_id)` reassembly; context only on the first fragment.
- **First-byte safety.** All rev2 frames start with `0x0X`, disjoint from MQP-2 and the v0.2.0 wire; old parsers drop them safely. A non-rev2 peer fails fast at HELLO/CAPS.

| First byte | Decoder |
|---|---|
| `0x00`, `0x01`, `0x04`, `0x08`, `0x09`, `0x0C` | MQP-3 rev2 |
| `0x02`, `0x05`, `0x06` | MQP-2 legacy — receive/tests only |
| `0x1X` … `0x4X` | v0.2.0 v3 legacy — receive/tests only |
| anything else | drop and count |

**Implementation contract:** [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md) · **Deep dive:** [MQP-3 rev2 protocol in depth](#-mqp-3-rev2-protocol-in-depth)

## 🧬 MQP-3 rev2 protocol in depth

MQP-3 rev2 is the application framing layer that MyQUIC2 runs inside QUIC DATAGRAMs. QUIC already provides the hard transport guarantees: TLS 1.3 confidentiality and integrity, authenticated peers, congestion control, loss detection, PMTU discovery and connection migration. MQP-3 does not duplicate them. It adds the narrow set of things a multiplexed UDP relay needs: a connection-scoped flow id, a compact way to name a session and a target on the first frame, aggregation of several payloads into one DATAGRAM, fragmentation for payloads larger than one DATAGRAM, and an idempotent control plane.

The design center is **small packets, not bulk throughput**. MQP headers are below 1–3% of a bulk stream, so shaving them further would not move a bulk benchmark. The traffic that benefits is the long tail: DNS, QUIC handshakes, game state, VoIP, telemetry, small RPCs and mixed-association fan-out. Rev2 therefore optimizes three things: header bytes per steady datagram, DATAGRAM send calls per payload burst, and the amount of peer-fillable state one connection can pin. It deliberately does **not** add payload compression, retransmission, or a reliable mode on top of QUIC.

### 1. Goals and non-goals

| Goal | Mechanism | Why it matters |
|---|---|---|
| Minimum steady overhead | `wire_id` + payload in `DATA`; no session, address or length | 2 B instead of 5–6 B; the saving repeats on every packet |
| First-frame self-description | `DATA OPEN` / `INLINE` carries `(session, address)` once | A flow can start without a separate handshake |
| Full duplex | Disjoint id halves; both ends can open, ack and close | A server-owned or full-cone flow needs no second protocol |
| Aggregation | `TRAIN` same/dict + connection-level stager | Several associations share one DATAGRAM and one send call |
| Large payloads | `FRAG` with an 8 B steady header and an 8 KiB cap | UDP payloads above one DATAGRAM stay on the same wire |
| Bounded fate sharing | Fixed stager, reassembly, registry and DNS limits | One lost packet or hostile peer cannot pin unbounded memory |
| Idempotent control | HELLO/CAPS/ACK/REJECT/CLOSE may be lost and repeated | Correctness never depends on a control datagram arriving |
| Safe coexistence | `0x0X` first-byte space and `wire_ver=2` | Old parsers drop rev2 frames instead of misrouting them |

**Non-goals.** Bulk-stream header optimization, payload compression, reliable UDP, retransmission, fragment trains, a u16 fragment id, and mixed-version deployment. The protocol name remains MQP-3; the revision is a wire fact, not a product name.

### 2. Revision negotiation and first-byte safety

Every rev2 frame starts with a byte whose high nibble is zero (`0x0X`) and avoids the legacy `0x02`, `0x05` and `0x06` opcodes. Old MQP-2 and v0.2.0 v3 decoders treat that space as unknown and drop it, so a rev2 frame can never be misrouted by an old parser. In the other direction, rev2 decoders reject the old first-byte ranges. This is deliberately a **fail-fast** design, not a compatibility layer.

```text
first byte = 0b0000_0000 | kind
  0x00 DATA steady        0x01 DATA extended
  0x04 TRAIN              0x08 FRAG steady
  0x09 FRAG extended      0x0C CTL
```

The client sends `CTL HELLO(wire_ver=2)` as soon as the QUIC connection is published and retries until `CAPS` arrives or two seconds pass. The server answers each HELLO with `CAPS` (throttled to one per 100 ms). A missing CAPS closes and redials; there is no silent downgrade. `CAPS` carries the negotiated `max_conn_flows`, `max_flows_sess`, `max_train_items`, `max_frame_bytes` and `max_reassembly` values.

**The first UDP packet does not wait for CAPS.** A published connection can carry UDP immediately. The server buffers up to **8 pre-HELLO rev2 data frames / 16 KiB**, releases them in arrival order after a valid `HELLO(wire_ver=2)`, and counts overflow. A wrong-version HELLO gets a CAPS with the server's own version, but does not open the gate or release the buffer. CAPS is a capability update, not a first-packet admission gate.

### 3. Flow identity, ownership and tables

```text
wire_id: u32 = (local_id << 1) | owner
  owner = 0  client-allocated
  owner = 1  server-allocated
  local_id starts at 1, increases monotonically, and is never reused while
  the connection lives.
  wire_id = 0 is reserved (invalid data frame; use INLINE).
  local_id <= 0x7FFF_FFFF; exhaustion falls back to INLINE.
```

`wire_id` is a LEB128 varint. A common active id (local id below 64) encodes in one byte, which is what makes the 2 B steady header possible. Never reusing an id removes the need for tombstones or a reuse window: a late frame either finds the live binding or finds no binding and is dropped. It can never be delivered to a new flow that happens to reuse the number.

The `session` field appears only in the `OPEN` / `INLINE` extension of `DATA` or `FRAG` and in the control plane (`CTL SESS_CLOSE`). A steady frame carries only `wire_id`; the receiver resolves it through a per-connection table.

| Table | Scope | Key | Value | Purpose |
|---|---|---|---|---|
| `FlowRegistry` | one per QUIC connection, both ends | `wire_id` | `Arc<FlowBinding>` | resolve an incoming id; read-mostly, insert only on open |
| `SessionFlows` | one per session | client: `TargetAddr`; server: reply `SocketAddr` | `wire_id` + binding | find the id for an outgoing target; find the flow for an incoming source |
| `FlowBinding` | shared by both tables | — | state + metadata | `wire_id`, `session`, `target`, `state` (`Opening`/`Open`/`Closed`), `reply_src`, `resolved` |

`FlowBinding` keeps the hot state in atomics and `ArcSwap` fields: the data path clones one `Arc`, reads the state and does not take a table lock per packet. The registry is a `parking_lot::RwLock<HashMap<...>>` with a fast hasher because inserts are cold; reads dominate and are short.

Defaults are **4096 live flows per connection** and **64 flows per session**. Both are negotiable through CAPS; the per-connection registry is charged to admission, and the per-session cap bounds one session's share. A sender that cannot allocate a flow falls back to `INLINE`; a receiver that cannot install one answers `FLOW_REJECT` with reason `table_full`. The id space is split by ownership so both endpoints can allocate concurrently without a global allocator.

### 4. Frame catalog

Common rules:

- One MQP frame per QUIC DATAGRAM body; the payload is the rest of the body.
- All integers are LEB128 `u32` varints unless a fixed width is shown.
- The decoder validates lengths and ranges **before** allocating or slicing. A truncated frame, unknown flag or unknown opcode drops only the current frame and increments a counter; it never panics or closes the connection.
- Payload bytes are never compressed, transformed or interpreted. Encrypted and random UDP looks exactly like plaintext to MQP.

#### 4.1 `DATA` — `0x00` steady, `0x01` extended

```text
steady:   0x00 | wire_id:varint | payload
extended: 0x01 | flags:u8 |
          [wire_id:varint if !INLINE] |
          [sess:u32 if OPEN or INLINE] |
          [addr if OPEN or INLINE] |
          payload

flags: OPEN=0x01  INLINE=0x02  SRC=0x04
       OPEN and INLINE are mutually exclusive; every other bit must be zero.
```

- **OPEN** binds `wire_id` to `(session, address)` and carries the first payload. The address is the destination for a client-initiated flow, the observed reply source for a server-owned flow, or the new source on a rebind.
- **INLINE** has no `wire_id`. `session` and `address` make it self-describing. It is the fail-safe for a full table, an exhausted id space, a one-shot target, or a diagnostic payload that should not create state.
- **SRC** marks the address as the actual source rather than the target. `OPEN|SRC` is the rebind frame in both directions.
- `OPEN` is idempotent: the same id with the same `(session, target)` returns the existing binding and re-ACKs. A conflicting target for the same id is rejected.

| Form | IPv4 header | IPv6 header | Domain header |
|---|---:|---:|---:|
| steady, `wire_id < 128` | **2 B** | 2 B | 2 B |
| steady, `wire_id < 16384` | 3 B | 3 B | 3 B |
| `OPEN` | 14 B | 26 B | 11 + L B |
| `INLINE` | 13 B | 25 B | 10 + L B |

`L` is the domain-name length. The first frame costs about the same as the old inline frame; the steady state saves 3–4 B on every subsequent datagram. That trade is the whole point: pay once per flow, save on every packet.

#### 4.2 `TRAIN` — `0x04`

```text
0x04 | form:u8 | count:u8 | ...

form 0 (same):  wire_id:varint | count × (len:varint | payload)
form 1 (dict):  nfl:u8 | nfl × wire_id:varint |
                count × (idx:u8 | len:varint | payload)
```

- `count <= 64` (`CAPS.max_train_items` may lower it); `nfl <= min(count, 64)`; dictionary flow ids are distinct; every item index is below `nfl`.
- Same-flow form is `3 B + one id varint`; each item adds a one-byte length for payloads up to 127 B. Dict form adds one byte per item index.
- Only confirmed (`Open`) flows may appear. A new flow's first payload is always a standalone `DATA OPEN`; `TRAIN` never carries per-item inline context.
- An item whose id is not installed is dropped and counted; the remaining items in the frame are still delivered.
- A dictionary train may carry items for several sessions because each id resolves to its own binding. This is what lets one DATAGRAM serve several associations.

#### 4.3 `FRAG` — `0x08` steady, `0x09` extended

```text
steady:   0x08 | wire_id:varint | frag_id:u32le | idx:u8 | total:u8 | chunk
extended: 0x09 | flags:u8 | [wire_id if !INLINE] | frag_id:u32le |
          idx:u8 | total:u8 | [sess if OPEN or INLINE] |
          [addr if OPEN or INLINE] | chunk
```

- `1 <= total <= 64`, `idx < total`, and `chunk` is non-empty.
- The steady header is **8 B** for a one-byte id: kind, id varint, 4 B `frag_id`, 1 B index, 1 B total. The legacy MQP-2 header was 18 B for IPv4 (up to 30 B for IPv6); the v3 prefix was 11 B plus the address.
- The reassembly key is `(wire_id, frag_id)`, or `(session, frag_id)` for the `INLINE` form. `frag_id` remains 32-bit to keep the reuse guard and late-arrival behavior of the previous wire.
- The first fragment may carry `OPEN` context so a flow can be reassembled before the binding is installed; later fragments are steady. The `INLINE` form has no flow id, so every fragment carries `sess` and the address.
- The payload cap is 8 KiB, the partial timeout is 2 s, and there are at most 256 partials / 256 KiB per connection. Those bounds are protocol invariants, not implementation accidents.

#### 4.4 `CTL` — `0x0C`

```text
0x0C | opcode:u8 | body

0x01 HELLO:       "M3" | wire_ver:u16 (=2) | flags:u16
0x02 CAPS:        "M3" | wire_ver:u16 | flags:u16 | max_conn_flows:u16 |
                  max_flows_sess:u16 | max_train_items:u8 |
                  max_frame_bytes:u16 | max_reassembly:u16
0x10 FLOW_ACK:    wire_id:varint | status:u8 (0 = open/confirmed)
0x11 FLOW_REJECT: wire_id:varint | reason:u8
                  (1 = policy, 2 = table full, 3 = DNS)
0x12 FLOW_CLOSE:  wire_id:varint
0x20 SESS_CLOSE:  sess:u32 | reason:u8
```

Control frames ride DATAGRAMs, are idempotent, and may be lost. Their only jobs are to confirm a binding, refuse one, or reclaim state. Losing one delays compression or reclamation; it never corrupts or blackholes user payload. A HELLO/CAPS exchange is the only version gate; an ACK is not a delivery ACK.

### 5. Flow lifecycle and idempotency

```text
INLINE ── DATA OPEN ──▶ OPENING ── FLOW_ACK / compressed downlink ──▶ OPEN
                           │
                           └── FLOW_REJECT ──▶ INLINE (retry after TTL)

OPEN ── FLOW_CLOSE / SESS_CLOSE / connection close / idle sweep ──▶ CLOSED
```

- **Client-initiated flow.** The first payload is `DATA OPEN(id, sess, target, payload)`. The server validates the SSRF/policy decision, resolves the target if needed, creates or reuses the session, forwards the payload, installs the binding, and replies `FLOW_ACK`. Until the ACK arrives the client keeps sending `OPEN` for that flow; duplicate OPENs are safe.
- **Server-initiated flow.** With `udp_full_cone = true`, an unsolicited source can create an `owner=1` id. The server sends `DATA OPEN|SRC(id, sess, source, payload)`; the client installs the binding and delivers the payload. The app's reply on the same id is a steady frame, so the return path is compressed too.
- **Rebind.** A domain flow, an anycast reply, or a source-port change is handled by `OPEN|SRC` on the existing id. The client updates `reply_src` and the SOCKS5 reply header; the application sees no API change.
- **Reject.** `policy`, `table_full` and `dns` are distinct reasons. The client falls back to `INLINE` for that target and may retry after a TTL; the payload is still delivered without a binding.
- **Close.** `SESS_CLOSE` is sent three times on association exit (idempotent, best-effort). `FLOW_CLOSE` retires one binding. The server also sends `SESS_CLOSE` when *it* reaps a session without a client request (idle sweep, admission-pressure sweep, reply-reader exit), so a client binding never stays `Open` against a session the server no longer holds. The 180 s idle sweep is the backstop. Close purges the registry, the session's stager items and the in-flight reassembly partials; a late frame then finds no live binding.
- **ACK is an optimization.** It unlocks the 2 B steady path. It is not a reliability mechanism, and payload delivery is never acknowledged.

### 6. Uplink: client to server

The uplink path starts at a SOCKS5 `UDP ASSOCIATE`. The association allocates a `session` (the client hub caps the process at **4032** associations), returns the relay address, and locks the app's source IP and port on the first valid UDP packet. From then on, every payload follows the same decision tree:

1. **Find or create a binding.** `SessionFlows` maps the target to a `wire_id`. If there is no id — because the table is full, the id space is exhausted, or the target is one-shot — the payload uses `INLINE`.
2. **Choose the frame.** A confirmed flow that fits the live DATAGRAM budget uses steady `DATA`. Several small payloads use the stager and `TRAIN`. A payload above one frame uses `FRAG`. An opening flow uses `DATA OPEN`.
3. **Stage or send.** Small payloads (at most 512 B) enter the connection-level stager. The stager drains at the end of a burst, before a large payload, when an association exits, and when the queue is full.
4. **Forward at the exit.** The server dispatches on the first byte, resolves the target, applies the SSRF policy, creates or reuses a 64 KiB session socket, and sends with `sendmmsg` bursts of up to 32. The session is subject to the global 8192-session pool and the per-connection fair share.
5. **Confirm.** After a successful install, the server sends `FLOW_ACK`. The client moves the binding from `Opening` to `Open` and starts compressing subsequent payloads.

The stager is covered in detail in §9. The important property here is that the sender never holds a lock across a QUIC send: packing moves item ownership under a short lock, the send happens outside it, and a failed send requeues only the unsent tail. A blocked send buffer is detected with `datagram_send_buffer_space()` before any encoding, so a full buffer costs a cheap check rather than a full-queue re-encode.

### 7. Downlink: server to client, domain targets and rebinding

The server's reply path starts at a session socket and a `recvmmsg` burst. `SessionFlows::match_source` classifies the reply source in **one pass** over the session's bindings:

| Match | Result | Wire |
|---|---|---|
| `reply_src == source` (learned) | strongest match | steady `DATA` / `TRAIN` |
| exact IP target | exact flow | steady `DATA` / `TRAIN` |
| same IP, different port; or domain whose resolved set contains the source IP | rebind candidate | `DATA OPEN\|SRC` once, then steady |
| no match | full-cone (opt-in) or drop | server-owned `OPEN\|SRC`, or nothing |

A domain target is resolved **off the datagram loop**. The lookup walks thread memo → shared moka cache → hickory; a miss is bounded by a 5 s timeout and a global slow-path limiter. The result is filtered through the SSRF policy and capped at **16 resolved addresses per flow**; the first accepted address receives the OPEN. The binding stores the set so a reply from any retained address can be compressed. A reply from an address outside the cap is treated like any other unmatched source: inline under full-cone, refused by the restricted filter.

The first reply from a new source is `DATA OPEN|SRC(id, sess, actual_source, payload)`. The client installs `reply_src`, writes the actual source into the SOCKS5 reply header, and delivers the payload. The server installs the reverse `(session, source) → id` mapping. Every later reply from that source is a 2 B steady frame. Downlink compression is driven by the client's local binding (`reply_src`); it does not wait for an uplink ACK.

With `udp_full_cone = true`, an unmatched source can create a **server-owned** flow using the `owner=1` half of the id space. The flow is counted as unsolicited and is only created under that explicit opt-in. Without it, an unmatched source is dropped and counted. The default remains restricted.

On the client, the dispatcher resolves `wire_id → binding → session`, reassembles `FRAG` when needed, and hands the payload to the association, which sends it to the locked app address with `sendmmsg`. `TRAIN` items are dispatched individually; a missing or closed id drops only that item.

### 8. Fragmentation and reassembly

`FRAG` exists because a UDP payload can be larger than one QUIC DATAGRAM, and because a single lost DATAGRAM should not destroy an arbitrarily large object. The cap is **8 KiB** and **64 fragments**. The first fragment may carry `OPEN` context; the rest carry only `wire_id` and `(frag_id, idx, total)`. The `INLINE` form has no flow id, so it repeats `sess` and the address on every fragment.

Reassembly is keyed by `(wire_id, frag_id)`, or `(session, frag_id)` for `INLINE`. The reassembler:

- validates `total`, `idx`, non-empty chunks and the first-fragment context before allocating;
- holds at most **256 partials** and **256 KiB** per connection;
- expires a partial after **2 s**;
- drops a payload if any fragment is missing — there is no retransmission;
- purges a session's or flow's partials on `SESS_CLOSE` / `FLOW_CLOSE`;
- accounts for the order deque's resident slots in `held_bytes()`, so the sweep still runs after every partial has completed and stale bookkeeping cannot accumulate indefinitely.

Because ids are never reused, the rev2 reassembler needs no tombstone for a completed `(wire_id, frag_id)`; a late fragment that arrives after completion finds no partial and is dropped. The 8 KiB cap bounds both the per-payload reassembly cost and the amount of state one lost fragment can pin.

### 9. `TRAIN` and the cross-session stager

A single association that sends one 40 B datagram at a time would pay one QUIC DATAGRAM and one syscall per payload. At eight associations × 1,000 pps that is 8,000 tiny sends per second, and most of the cost is not the MQP header — it is the per-send overhead. The stager and `TRAIN` attack that cost without changing UDP semantics.

| Form | Header | Per item | Best use |
|---|---:|---:|---|
| Same-flow `TRAIN` | 3 B + one `wire_id` varint | 1 B length (≤127 B payload) + payload | a burst to one target, e.g. a game server or DNS resolver |
| Dictionary `TRAIN` | 4 B + `nfl` id varints | 1 B index + 1 B length + payload | a mixed burst across associations or targets |
| Steady `DATA` | 2 B | — | one payload, no aggregation opportunity |
| `FRAG` | 8 B | — | one payload larger than the DATAGRAM budget |

Packing is deliberately simple and bounded:

1. Each association owns a FIFO queue inside the connection-level stager. A round-robin cursor visits sessions, so one busy association cannot starve the others.
2. A run of steady items for the same flow becomes a same-flow `TRAIN`. A mix of flows or sessions becomes a dictionary `TRAIN`; each item's id resolves through the receiver's registry to its own session.
3. A standalone `OPEN` / `INLINE` is never folded into a `TRAIN`. The first payload of a flow must establish the binding first.
4. A batch is at most **4 frames / 64 items** and at most **64 items per `TRAIN`**, further reduced by `CAPS.max_train_items`. The stager holds at most **1,024 items / 256 KiB** per connection.
5. The stager drains at the end of a burst, before a large payload, when an association exits, and when the queue is full. If the QUIC send buffer is full, only the unsent tail is requeued; already-packed items are not duplicated.
6. If the destination MTU is too small for the packed frame, the send reports `TooLarge`; the stager re-reads the budget (throttled to once per 100 ms) and repacks rather than spinning.

The measured effect is **0.743 frames per payload** on the mixed small-packet benchmark, with about **25% fewer client DATAGRAM sends** than v0.2.0. The gain is conditional: it appears when multiple payloads are ready at the same drain point. A single isolated datagram still pays one frame; the protocol does not add latency waiting for a train to fill.

### 10. Control plane

The control plane is intentionally small and loss-tolerant. `CTL` frames travel as QUIC DATAGRAMs, may be reordered or lost, and are idempotent. Their jobs are to negotiate capabilities, confirm a binding, refuse a binding or reclaim state. No user payload depends on a control frame arriving.

| Opcode | Frame | Cadence | Effect |
|---|---|---|---|
| `0x01` | `HELLO` | immediately after the QUIC connection is published; retried until CAPS | announces `wire_ver=2` |
| `0x02` | `CAPS` | one per HELLO, throttled to 100 ms | publishes flow/train/frame/reassembly limits |
| `0x10` | `FLOW_ACK` | once per successful install; duplicate OPENs are re-ACKed | moves the sender to `Open` and enables compression |
| `0x11` | `FLOW_REJECT` | once per refused OPEN | reason `policy`, `table_full` or `dns` |
| `0x12` | `FLOW_CLOSE` | on flow retirement | removes one binding and its queued state |
| `0x20` | `SESS_CLOSE` | three best-effort datagrams on association exit, and on a server-side reap (idle sweep, admission-pressure sweep, reply-reader exit) | removes a session, its flows, stager items and partials |

- **HELLO/CAPS is the only version gate.** A wrong `wire_ver` is answered with CAPS but does not release buffered data. A missing CAPS for two seconds closes the connection; there is no fallback to MQP-2 or the v0.2.0 wire.
- **CAPS is a capability update, not a first-packet gate.** It can arrive after the first payload. The server's pre-HELLO buffer (8 frames / 16 KiB) holds early rev2 frames and releases them after a valid HELLO, in arrival order.
- **ACK is not delivery.** It confirms that the receiver installed the binding. If an ACK is lost, the sender keeps using `OPEN` for that flow; the duplicate is idempotent. Payload delivery remains the job of the unreliable DATAGRAM.
- **Close is best-effort and symmetric.** `SESS_CLOSE` is repeated three times because losing it only delays reclamation; the server emits the same frame when it reaps a session the client did not close (idle/admission sweeps, reply-reader exit), so a live client binding is never left pointing at a reaped session. The 180 s idle sweep is the correctness backstop. `FLOW_CLOSE` is idempotent and may be repeated; a repeat or an unknown id costs one lookup, not a queue scan.
- **Unknown opcodes, truncated bodies and unknown flags are dropped and counted.** They do not panic and do not tear down the connection. A malformed control frame must not become a denial-of-service primitive.

### 11. Loss, ordering and backpressure

MQP-3 does not add reliability on top of QUIC DATAGRAM. The rules are explicit so applications can reason about them:

- A QUIC DATAGRAM is delivered whole or not at all. One MQP frame occupies one DATAGRAM body.
- A lost `DATA` loses one payload. A lost `TRAIN` loses every item it carried. A lost `FRAG` loses that reassembled payload even if the other fragments arrived.
- There is no retransmission, no per-payload ACK, no retry queue and no head-of-line blocking. A lost datagram does not delay later datagrams.
- Within a session, the stager preserves FIFO order among staged payloads. A large payload that hits `Blocked` while items remain queued may be bypassed (UDP semantics; strict ordering would need retry-later). Across sessions there is no ordering guarantee, and UDP reordering is always allowed.
- `OPEN` and `ACK` are idempotent. A duplicate `OPEN` is safe; a duplicate `ACK` is harmless. Monotonic, never-reused ids prevent a late frame from being misdelivered to a new flow.
- If an application needs reliability or ordered delivery, it must provide it above the SOCKS5 datagram API. MyQUIC2 deliberately does not turn UDP into a stream.

Backpressure is handled at the sender, not by unbounded queues:

| Verdict | Meaning | Action |
|---|---|---|
| `Sent` | the datagram was accepted by QUIC | count the payload and release the buffer |
| `Blocked` | the QUIC send buffer is full | requeue only the unsent tail; retry on the next drain |
| `TooLarge` | the frame exceeds the current DATAGRAM budget | re-read the budget (100 ms throttle) and repack |
| `ConnectionLost` | the QUIC connection is gone | fail the send; the association reconnects |
| `Unsupported` | the peer or transport cannot carry DATAGRAMs | fall back or close with a clear error |

The stager drops the **newest** item when its bound is reached, never the oldest: dropping old data would break per-session FIFO and silently reorder the stream. Every drop is counted by reason, so a full queue is visible rather than silent.

### 12. Resource bounds and admission

Every peer-fillable structure is bounded, and the bounds are part of the protocol contract rather than incidental implementation details.

| Resource | Bound | Enforcement |
|---|---|---|
| Pre-HELLO buffer | 8 frames / 16 KiB per connection | `accept.rs` before HELLO |
| Fast session table | 64 slots | server ingress |
| Flow registry | 4096 live flows per connection | send: `INLINE` fallback; receive: `FLOW_REJECT(table_full)` |
| Flows per session | 64 | same fallback/reject path |
| Resolved addresses | 16 per flow | DNS result truncation |
| DNS positive cache | 10,240 names x at most 32 retained addresses (120 s) | entry-capped moka; per-name address-set cap (`DNS_CACHE_MAX_ADDRS`) so a hostile multi-record answer cannot grow the cache |
| Pending DNS opens | 16 | admission gate on the domain slow path |
| `TRAIN` | 64 items | packer and decoder |
| Stager | 1,024 items / 256 KiB per connection | enqueue admission |
| Pack batch | 4 frames / 64 items | stager drain |
| Reassembly | 2 s / 256 partials / 256 KiB per connection | reassembler sweep (both MQP-2 and rev2; the rev2 ordering index is pruned, not just the partials) |
| QUIC stream reassembly | 1,024 gap spans per peer-opened stream (quinn-proto) | charged process-wide via the parked-header-stream credit |
| Header-stage parked streams | 4,096 process-wide / 256 per connection | `HEADER_TASK_CREDIT` / `HEADER_CREDIT_PER_CONN` fail-fast reset |
| Pre-auth stream credit | 4 bidi + 2 uni streams, raised to 8,192 bidi after the token check | handshake transport parameters / `MAX_STREAMS` |
| Fragmented payload | 8 KiB / 64 fragments | fragmenter and decoder |
| Client associations | 4,032 per process | UDP hub |
| Global sessions | 8,192 | server session pool |
| Connections | 4,096 | admission / listener |
| Per-connection admission | 19,687.5 KiB (20,643,840 B) | checked before state allocation |

The admission charge is a **ceiling**, not a reservation. It assumes the worst case: 14 MiB of QUIC transport buffers (8 MiB receive + 4 MiB send + two 1 MiB DATAGRAM buffers), two 256 KiB reassemblers, a 256 KiB stager plus 1,024 × 96 B × 8 slots (1 MiB), 96 KiB of fixed ingress state (16 KiB pre-HELLO + the 64-slot fast session table with inline destination pins + maps), 4,096 × 904 B of flow-registry capacity (3.53 MiB), and the quinn receive assemblers for the handshake's pre-auth stream credit (6 streams × 1,024 gap spans × 96 B = 576 KiB; the server advertises 4 bidi + 2 uni streams until the token is verified, then raises bidi to 8,192). The total is 19.6875 MiB. At the full 4,096 connections that is **78.75 GiB** of worst-case peer-fillable state, which is why `max_peer_memory_mb` exists and why the default is a hard ceiling rather than a promise that every connection will use it.

A second, **process-wide fixed term** is subtracted from the budget once before the remainder is divided into connections. It covers state a peer can drive regardless of the connection count:

- **UDP session pool** — 8,192 sessions. Each session charges the kernel's 64 KiB socket caps per direction (doubled by Linux's `SO_*BUF` bookkeeping) plus both per-session flow tables at their worst case: the MQP-3 v0.2 table at 64 domain targets (**22 KiB**, not the old IP-only 4 KiB) and the rev2 copy-on-write bookkeeping (2 KiB). That is **~2.25 GiB on Linux**, ~1.25 GiB where the kernel does not double the caps.
- **QUIC ingress endpoints** — each endpoint's resident GRO receive buffer plus its kernel socket caps.
- **TCP relay pumps** — per stream-task slot, two 16 KiB userspace buffers **plus the relay TCP socket's kernel send/receive buffers**. The kernel half is peer-driven (a target that stops reading, or a fast target while the app stops reading) and is not covered by the QUIC transport windows: by default it is charged at the Linux initial sysctl allowance (128 KiB receive + 16 KiB send = 144 KiB per flow; autotuning can exceed it), or at the exact doubled cap when `MYQUIC2_RELAY_SOCKET_BUF` sets explicit `SO_SNDBUF`/`SO_RCVBUF`. Across 16,384 slots that is **512 MiB userspace + ~2.25 GiB kernel allowance** — the largest fixed term after the session pool, and the reason a memory-tight host should set the override.
- **UDP retry pool** — 16 shards × (256 queued + 16 in flight) × an 8 KiB payload (**34 MiB**); peer-driven, because a black-holed target or a full `SO_SNDBUF` makes `WouldBlock` the steady state.
- **DNS slow-path waiters** — 1,024 permits × (payload + host + task structure) (**8.75 MiB**); each unique unresolvable domain parks one waiter until the lookup times out.
- **Datagram-worker scratch** — the `recvmmsg` burst buffer plus the session read-buffer pool held per worker thread (hundreds of KiB × the shard-thread count).
- **quinn stream-reassembly metadata** — every peer-opened stream can park up to **1,024 gap spans** in quinn's receive assembler, and QUIC flow control counts payload bytes rather than span metadata. The header-read stage caps how many such streams can be parked at once (4,096 process-wide, 256 per connection), so admission charges 4,096 × 1,024 × 96 B ≈ **384 MiB** as a fixed term; previously none of it was charged and one connection could pin hundreds of MiB against a 19 MiB charge.

The per-connection charge covers state that a single connection can pin; the fixed term covers state many connections can pin together. Both are checked before allocation, so a flood of half-open associations cannot consume the budget of established traffic. The client is not exposed to the stream-assembly term at all: it advertises **zero** incoming stream credit (it opens every stream it uses and the server never opens one), so a peer cannot create a receive assembler on it.

### 13. Security invariants

MQP-3 assumes the peer is untrusted and the network is hostile. The invariants are:

- **Authorize before staging.** Every payload is checked against the flow's policy before it enters the stager. An unknown `wire_id`, a closed binding or an id owned by another session is dropped; it cannot be used to reach a target that the sender was never allowed to reach.
- **Session-scoped resolution.** `wire_id` resolves to exactly one `session` and one target. A dictionary `TRAIN` does not bypass this: each item's id is resolved independently, and an item for a closed flow is dropped without affecting the rest.
- **SSRF and private-address policy.** The exit resolves names and filters private, loopback, link-local and otherwise disallowed addresses before dialing or sending. `allow_private` is an explicit opt-in, not a default.
- **Reply-source policy.** A reply is accepted only from the live flow's `reply_src`, from an address in the flow's resolved set, or from an address in the 16-entry per-session allowlist. `udp_full_cone` is opt-in; unsolicited flows are counted separately.
- **No cross-session ids.** The client registry and the server registry are connection-scoped. An id from one session cannot name a target in another session.
- **Transport authentication.** TLS 1.3 with ALPN `h3`; the token is sent on a 1-RTT unidirectional stream and never in 0-RTT. The comparison is constant-time, and the gate is checked before per-connection state is allocated.
- **Fail-fast versioning.** Unknown first bytes, wrong `wire_ver`, missing CAPS and malformed control frames cannot silently fall back to an older wire. They are dropped or closed, with a counter.
- **No payload transformation.** MQP does not compress or inspect payload bytes. Encrypted, random and already-compressed UDP traffic is carried as-is; there is no compression oracle and no per-payload CPU surprise.
- **Bounds are security controls.** The stager, reassembly, DNS, flow and admission limits are what stop a peer from turning small packets into unbounded memory. They are tested as invariants, not tuned as best-effort heuristics.

### 14. Interaction with QUIC and transport tuning

MQP-3 is a passenger, not a replacement. The transport choices that matter most:

- **DATAGRAM budget.** The usable payload is `MTU − 38` bytes: 1,162 B at the initial 1,200 B MTU, 1,434 B at 1,472 B. The budget is re-read on `TooLarge`, not assumed to be constant.
- **PMTU.** The path starts at 1,200 B and probes 1,336, 1,404, 1,438 and 1,472 B. A probe failure falls back without losing the connection; the stager repacks to the smaller budget.
- **Congestion control.** BBR with ECN, not a custom controller. MQP has no window, no slow start and no retransmission timer of its own.
- **GSO/GRO.** The server uses UDP segmentation and coalescing offload where the platform supports it; the client does the same per pool slot.
- **Receive isolation.** Each pool slot owns its endpoint, socket and runtime; the server uses `SO_REUSEPORT` with one endpoint per usable core, capped at 8. There is no shared receive lock between slots.
- **No incoming streams on the client.** The client advertises `max_concurrent_bidi_streams = 0` and `max_concurrent_uni_streams = 0`. It opens every stream it uses (one bidi stream per SOCKS TCP relay, one uni stream for the auth token) and the server never opens one, so an advertised slot would only let the peer pin quinn receive-assembler state (up to 1,024 gap spans per stream) on a side that never accepts a stream. A peer that opens one anyway is violating our transport parameters, and quinn closes the connection before buffering any stream data.
- **Pre-auth stream credit on the server.** The server's handshake advertises only 4 bidi + 2 uni streams; the unauthenticated peer must not be able to park a receive assembler per advertised stream while it stalls the token exchange (the full 8,192-stream credit would allow hundreds of MiB on one connection). `MAX_STREAMS` is increase-only, so the accept loop raises bidi to 8,192 as soon as authentication succeeds — one client may still legitimately place every admitted TCP flow on one connection. The post-auth parked-stream bound is charged process-wide; the pre-auth one is charged per connection.
- **Runtime topology.** The client pins one current-thread runtime per pool slot (7 at the shipped defaults) and sizes the multi-threaded main runtime to the cores those pinned threads leave over, so saturation cannot put `cores + slots` runnable threads on `cores` CPUs. `MYQUIC2_SHARD_RUNTIME=0` restores the single shared runtime (full worker width).
- **Session sockets.** Each UDP association gets one 64 KiB socket and one reader. `recvmmsg` and `sendmmsg` batch up to 32 datagrams; the per-session fair share prevents one association from monopolizing the exit.
- **TCP path.** TCP rides a QUIC bidirectional stream: optimistic SOCKS5 success, borrowed QUIC halves, vectored writes, 300 s idle timeout, 250 ms happy-eyeballs delay, and `RST`/`STOP_SENDING` (`0x04`) on failure.
- **Liveness.** The QUIC idle timeout is `max(3 × keepalive, 15 s)`; the client watchdog is `max(2 × keepalive, 8 s)`; reconnect backoff is 200 ms to 5 s. A dead path is detected below the QUIC idle timeout so the next request does not wait for it.

### 15. Implementation map and observability

| Area | Files | Responsibility |
|---|---|---|
| Codec | `src/mqp/r2.rs` | frame encode/decode, CTL bodies, limits, first-byte dispatch |
| Flow state | `src/mqp/r2_flow.rs` | `FlowBinding`, `FlowRegistry`, `SessionFlows`, `match_source`, id allocation |
| Stager | `src/udp/r2_stage.rs` | per-session FIFO, round-robin, batch packing, bounds |
| Fragmenter | `src/udp/r2_frag.rs` | rev2 fragmentation on the client |
| Reassembler | `src/udp/r2_reasm.rs` | rev2 reassembly on the server; legacy `src/udp/reassembler.rs` remains for MQP-2 receive/tests |
| Client lifecycle | `src/bin/myquic2-client/rev2.rs` | open/ack/reject/close, downlink dispatch, `SESS_CLOSE` |
| Client dispatch | `src/bin/myquic2-client/dispatcher.rs` | DATAGRAM receive path and per-frame routing |
| Client pool | `src/bin/myquic2-client/pool.rs`, `egress.rs` | slot selection, reconnect, thread-local egress memo |
| UDP hub | `src/bin/myquic2-client/hub.rs`, `assoc.rs` | SOCKS5 UDP association, 4,032 cap, app address lock |
| Server ingress | `src/bin/myquic2-server/accept.rs` | HELLO/CAPS, pre-HELLO buffer, flow install, admission |
| Server forwarding | `src/bin/myquic2-server/reader.rs`, `table.rs`, `forward.rs`, `pin.rs` | session sockets, source matching, DNS/SSRF, reply pinning |
| Observability | `src/stats/*`, reporter | frame/item/drop/flow counters and periodic summaries |
| Benchmarks | `examples/hotpath_bench.rs`, `scripts/linux-bench-matrix.sh` | all-size sweep, mixed small-packet load, pacing, full duplex |

The counters are intentionally granular: bytes and frames by kind, `TRAIN` items, inline fallbacks, flow opens/acks/rejects/closes, compression ratio, reassembly partials, stager depth, drop reason and transport stats. A regression in framing shows up as a ratio change, not as a vague latency wobble. For packet-level work, qlog and `tcpdump` see one MQP frame per DATAGRAM; for CPU work, the hot-path bench isolates encode, decode, staging and send.

### 16. Compatibility and failure behavior

| Situation | Behavior |
|---|---|
| Rev2 client + rev2 server | full feature set; steady 2 B headers, TRAIN, FRAG, full duplex |
| Rev2 client + old server | HELLO is dropped, no CAPS arrives, the client closes and retries; optimistic early datagrams are unknown first bytes and are dropped. No silent downgrade. |
| Old client + rev2 server | rev2 frames are unknown to the client and counted/dropped; the server does not fall back. Mixed versions are unsupported. |
| MTU shrinks | `TooLarge` triggers a budget re-read and repack; the connection survives |
| Flow table full (send) | fall back to `INLINE`; the payload still goes out |
| Flow table full (receive) | `FLOW_REJECT(table_full)`; the sender falls back to `INLINE` |
| DNS failure | `FLOW_REJECT(dns)`; the sender falls back to `INLINE` or drops with a reason |
| SSRF/private target | policy refusal before dial/send; counted |
| Stager full | drop the newest item, count the reason; FIFO is preserved for what remains |
| Connection lost | in-flight payloads are lost; the pool reconnects and the association reopens; there is no replay |
| Peer crash | QUIC close or the 180 s idle sweep reclaims flows, stager items and partials |
| Unknown first byte / opcode / flag | drop and count; no panic, no connection teardown |

### 17. Verification snapshot

The current tree has **530 tests** on macOS (lib 262 + client 149 + server 119); the Linux CI-equivalent environment additionally runs the `cfg(target_os = "linux")`-gated tests. `cargo fmt --check`, strict Clippy and the full test suite are clean.

The data-plane evidence is deliberately end-to-end:

- **All-size sweep:** 8 B through 8 KiB payloads, all OK, including the 2 B steady path, `TRAIN`, `FRAG` and the `OPEN` / `INLINE` forms.
- **Mixed small-packet benchmark:** 8 associations × 1,000 pps × 128 B × 65 s delivered 519,992 / 519,990 payloads at 0.000% loss, with 0.743 frames per payload and about 25% fewer client DATAGRAM sends than v0.2.0.
- **Full duplex:** 30,000 / 30,000 payloads in both directions.
- **Paced:** 325,000 / 325,000 payloads with no loss.
- **Safety:** malformed, truncated, unknown-flag, unknown-opcode and wrong-version inputs are covered by unit tests; the first-byte matrix is checked against the legacy decoders.

See [Verification](#-verification) for the exact commands and the CI matrix.

## 🔁 Full duplex

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/duplex-dark.svg">
  <img src="assets/readme/duplex-light.svg" alt="Full-duplex MQP-3 rev2 lifecycle: client-owned and server-owned flows, domain rebind, SESS_CLOSE" width="100%">
</picture>
</p>

Full duplex is not an afterthought in rev2: the id space is split by owner, both endpoints run the same open/ack/rebind/close state machine, and the connection-level tables hold client-owned and server-owned flows side by side. That matters for the traffic MyQUIC2 is built for. A game server or a DNS resolver replies from a source the client never explicitly dialed; an anycast target changes its reply address; a restricted NAT still needs a return path. Rev2 handles all three without a second protocol or a separate control channel.

- **Both endpoints can open a flow.** Client-owned (`owner=0`) and server-owned (`owner=1`) ids share one registry. `FLOW_ACK` confirms; a compressed downlink is also an implicit ACK, so a lost ACK only delays compression.
- **Everything worth compressing compresses.** Domain targets, pure-uplink flows, and — with `udp_full_cone = true` — server-owned flows for unsolicited sources. The app replies on the same id, so the return path is 2 B steady `DATA` too.
- **Source changes rebind the same id.** One `OPEN|SRC` teaches the actual reply source; the client writes it into the SOCKS5 reply header, unchanged for apps. No new association and no new id are required.
- **Optimistic first packet.** A new UDP connection does not wait for CAPS: the first payload can leave immediately. The server buffers up to 8 pre-HELLO frames (16 KiB) and releases them in order after a valid HELLO. Wrong-version HELLOs never release the buffer, so optimism does not weaken the version gate.
- **Close means close.** `SESS_CLOSE` / `FLOW_CLOSE` purge bindings, queued stager items and in-flight partials on both ends. A late frame finds no live binding and is dropped; it can never be misdelivered to a reused id.

## 🚀 Cross-session stager

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/stager-dark.svg">
  <img src="assets/readme/stager-light.svg" alt="Cross-session stager packs payloads from several associations into one round-robin TRAIN dict" width="100%">
</picture>
</p>

One stager per QUIC connection, not per association. This is the difference between compressing one app's burst and compressing the **aggregate** traffic of every SOCKS5 association that shares the tunnel. Small payloads from every app share a per-session FIFO with a round-robin cursor; a single `TRAIN dict` can carry items from several sessions, because each `wire_id` resolves to its own binding at the receiver.

Packing is demand-driven, not timer-driven: a drain happens at the end of a burst, before a large payload, when an association exits, or when the queue is full. The stager never waits to fill a train, so a lone datagram is not delayed for aggregation. A batch carries at most **4 frames / 64 items**, and each frame at most **64 items**, further reduced by `CAPS.max_train_items`. The queue is capped at **1,024 items / 256 KiB per connection**; a full queue drops the newest item and books the exact reason. A blocked QUIC send requeues only the unsent tail, never duplicates a packed item.

Fairness is structural: each session has its own FIFO, and the round-robin cursor means a busy association cannot starve a quiet one. Ordering is per-session FIFO; there is no cross-session order to preserve.

- **Fewer sends, not just fewer bytes.** One DATAGRAM can carry up to 64 payloads, so the per-send cost is amortized across associations.
- **No added latency.** There is no aggregation timer and no “wait for a full train” path. A single ready payload goes out immediately.
- **Bounded and observable.** Depth, items, bytes, drops and pack outcomes are counted; a growing queue is visible before it becomes loss.
- **Negotiated, not assumed.** `CAPS.max_train_items` lets the peer lower the item count; the packer honors it per frame.

## 📊 Performance

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/performance-dark.svg">
  <img src="assets/readme/performance-light.svg" alt="Measured header sizes, DATAGRAM send reduction and loopback smoke results" width="100%">
</picture>
</p>

Performance work is framed around the **small-packet path**, not bulk throughput. The benchmark is deliberately adversarial for framing: many associations, 128 B payloads, a mix of uplink and downlink, and a long enough run to expose queue growth or loss. It measures delivered payloads, frames per payload and DATAGRAM sends, not just throughput.

| Path | Before rev2 | Rev2 steady | Saving |
|---|---:|---:|---:|
| Steady UDP `DATA` | 5–6 B | **2 B** | 3–4 B per frame |
| `FRAG` | 18–30 B | **8 B** | 10–22 B per fragment |
| `TRAIN` item | 2 B | **1 B** | 1 B per item |

The first frame of a flow is not the steady state: `OPEN` / `INLINE` carries the session and address and costs more once. The saving repeats on every subsequent datagram, which is exactly where small-packet traffic spends its budget.

**Measured results:**

- **8 associations × 1,000 pps × 128 B × 65 s:** 519,992 / 519,990 delivered, **0.000 % loss**, **0.743 frames/payload** — fewer than one frame leaves per payload because `TRAIN` amortizes the per-frame overhead. The measured client issued about **25 % fewer DATAGRAM sends** than on the v0.2.0 wire.
- **All-size sweep:** 8 B … 8 KiB **ALL OK**, covering the 2 B steady path, same-flow and dictionary `TRAIN`, `FRAG`, `OPEN` and `INLINE`. No size falls back to a silent copy or a different transport.
- **Full duplex:** 30,000 / 30,000 payloads in both directions, including server-owned and rebind paths. **Paced:** 325,000 / 325,000 with no loss.
- **Where the numbers come from:** macOS loopback on release binaries. The Linux 2–4 core + `tc netem` matrix is the deployment gate: [`scripts/linux-bench-matrix.sh`](scripts/linux-bench-matrix.sh). These are not WAN predictions; they isolate framing and scheduling effects.

## 🛡️ Security

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/security-dark.svg">
  <img src="assets/readme/security-light.svg" alt="Security model: TLS 1.3, token auth, per-packet authorization, opt-in full-cone" width="100%">
</picture>
</p>

The security model assumes an untrusted peer and a hostile network. TLS 1.3 authenticates and encrypts the tunnel; MQP's job is narrower but critical: a compressed id must not become an authorization bypass, a rebind must not become an open relay, and a malformed frame must not become a memory or CPU primitive. The defaults are deliberately restrictive — full-cone off, private targets off, token required, and every peer-fillable structure bounded.

- **Every packet is authorized.** A compressed id resolves only a live, session-scoped binding; an unknown id drops that item and never guesses a route. Authorization happens before the payload enters the stager, so a dictionary `TRAIN` cannot smuggle an item past the target policy. SSRF and private-IP filtering run at the exit.
- **Reply-source policy.** A reply is accepted from the exact live flow mapping, from the flow's resolved address set, or from a 16-entry per-session IP allowlist. `udp_full_cone` is opt-in, off by default, warned at startup, and counts unsolicited flows separately.
- **Transport and token.** TLS 1.3 with ALPN `h3`; the bearer token is sent only on a 1-RTT uni stream, never in 0-RTT. Token comparison is constant-time, and the gate runs before per-connection state is allocated.
- **No payload compression.** Encrypted or random UDP is left untouched; there is no compression oracle and no per-payload CPU surprise. The gains are framing, fewer frames and fewer sends.
- **What is not claimed.** MQP does not inspect or transform payloads, does not provide anonymity, and does not protect a compromised endpoint. The TLS tunnel is the trust boundary; defense in depth lives in the SSRF policy, reply-source checks and admission bounds.

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
- **Environment knobs:** `MYQUIC2_SESS_SOCKET_BUF`, `MYQUIC2_RELAY_SOCKET_BUF`, `MYQUIC2_BUSY_POLL`, `MYQUIC2_TCP_NOTSET_LOWAT`, `MYQUIC2_SHARD_RUNTIME`.

The sample configs are the reference; comments explain defaults and trade-offs.

## ✅ Verification

- **530 tests** on the macOS dev box (lib 262 + client 149 + server 119).
- The Linux CI-equivalent environment additionally runs the `cfg(target_os = "linux")`-gated tests.
- **Coverage of the contract:** codec round-trips and truncation, the first-byte matrix against legacy decoders, id allocation and idempotent open/ack/reject/close, same-flow and dictionary `TRAIN`, `FRAG`/reassembly bounds, stager fairness and drop accounting, admission math, SSRF and reply-source policy, full-duplex ownership, and legacy MQP-2 receive paths.
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

#### System overview

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

#### End-to-end module map

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

#### Shared library layers

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

#### Deployment topology

_Where the two binaries sit: LAN / OpenWrt, internet, VPS, targets._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
subgraph LAN["🏠 LAN / OpenWrt"]
        APPS(["🧑‍💻 Apps"])
        CLIENT["🧦 myquic2-client<br/>SOCKS5 :1080"]
        APPS -->|"TCP + UDP"| CLIENT
    end
    CLIENT ==>|"QUIC · TLS 1.3"| NET["🌍 Internet"]
    NET ==>|"QUIC · TLS 1.3"| SRV["🛰️ myquic2-server<br/>:8443"]
    SRV --> RES(["🔎 resolver"])
    SRV --> TCP(["🌐 TCP targets"])
    SRV --> UDP(["📦 UDP targets"])
    class APPS,CLIENT clientC
    class NET wireC
    class SRV coreC
    class RES,TCP,UDP warmC
    style LAN fill:#f0fdf4,stroke:#bbf7d0,stroke-width:1.5px,color:#14532d

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

### 🚀 Client paths

#### Connection pool panorama

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

#### TCP echo path

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

#### TCP relay path

_The modern TCP dial: admission, happy-eyeballs racing, zero-copy pump._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
    autonumber
        box rgb(236, 253, 245) Client edge
            participant App as 🧑‍💻 App
            participant Client as 🧦 MyQUIC2 client
        end
        box rgb(238, 242, 255) Tunnel
            participant Server as 🛰️ MyQUIC2 server
        end
        box rgb(255, 247, 237) Exit side
            participant Target as 🎯 Target TCP
        end
        rect rgb(248, 250, 252)
            Note over App,Client: ① SOCKS5 CONNECT
            App->>Client: atyp + addr + port
            Client->>Server: open bi stream + stream head
        end
        rect rgb(238, 242, 255)
            Note over Server: ② admission before work
            Server->>Server: token gate + memory admission
            Server->>Target: happy-eyeballs dial<br/>250 ms stagger · 4 s budget
            Target-->>Server: connected
            Server-->>Client: dial ACK
            Client-->>App: SOCKS5 success
        end
        rect rgb(236, 253, 245)
            Note over Server,Target: ③ zero-copy pump
            Server->>Target: write_chunk / read_chunks
            Note over Server,Target: failure → RST (SO_LINGER=0) + reset/stop 0x04
        end
```

#### Client egress selection

_Memo → acquire → own slot → sibling → fail-open or drop._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
D["📦 UDP datagram"] --> M{"memo<br/>fresh?"}
    M -->|"hit"| SEND["🚀 send_datagram"]
    M -->|"miss"| A["🧭 acquire egress"]
    A --> O{"own slot<br/>usable?"}
    O -->|"yes"| SEND
    O -->|"no"| S{"same-class<br/>sibling?"}
    S -->|"yes"| SEND
    S -->|"no"| F{"udp_fail_closed?"}
    F -->|"false"| TCP["🔁 fail-open to TCP"]
    F -->|"true"| DROP["⛔ NO_EGRESS<br/>drop + count"]
    class D,A,SEND clientC
    class M,O,S,F decisionC
    class TCP wireC
    class DROP dangerC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

#### Reconnect & watchdog

_Two independent stall detectors, both below the QUIC idle timeout._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
CONNECT(["🔌 Connecting"]) --> NEG["🤝 Negotiating<br/>HELLO · CAPS"]
    NEG -->|"CAPS(2)"| READY(["✅ Ready"])
    NEG -->|"no CAPS · 2 s"| REDIAL["🔁 Reconnecting"]
    READY --> SILENT["🌑 Silent<br/>no inbound datagrams"]
    READY --> ACKSTALL["⏳ ACK stall<br/>tx advances, acks do not"]
    SILENT -->|"close"| REDIAL
    ACKSTALL -->|"close"| REDIAL
    REDIAL -->|"200 ms … 5 s"| CONNECT
    READY -.-|"timeouts"| CLOCK["⏱️ watchdog = max(2×keepalive, 8 s)<br/>QUIC idle = max(3×keepalive, 15 s)"]
    class CONNECT,NEG,REDIAL muteC
    class READY clientC
    class SILENT,ACKSTALL warmC
    class CLOCK noteC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

### 📡 Wire & flows

#### UDP echo path

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

#### Frame decision

_Payload shape → DATA / TRAIN / FRAG, with the send verdicts._

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

#### First-byte safety

_Why rev2 coexistence with old decoders cannot misroute._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
BYTE(["🧵 first wire byte"]) --> N{"high nibble"}
    N -->|"0x0X"| R2["📡 MQP-3 rev2<br/>DATA · TRAIN · FRAG · CTL"]
    N -->|"0x02 / 0x05 / 0x06"| V2["📼 MQP-2 legacy<br/>receive + tests only"]
    N -->|"0x1X … 0x4X"| V3["📼 v0.2.0 v3 legacy<br/>receive + tests only"]
    N -->|"other"| DROP["⛔ drop"]
    class BYTE clientC
    class R2 wireC
    class V2,V3 muteC
    class DROP dangerC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

#### Flow state machine

_Inline → Opening → Open → Closed; ACK is an optimisation._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
INLINE(["⚪ INLINE"]) -->|"DATA OPEN"| OPENING(["🟣 OPENING"])
    OPENING -->|"FLOW_ACK<br/>or compressed reply"| OPEN(["🟢 OPEN"])
    OPENING -->|"FLOW_REJECT"| INLINE
    OPEN -->|"FLOW_CLOSE<br/>SESS_CLOSE"| CLOSED(["⚫ CLOSED"])
    INLINE -->|"session ends"| CLOSED
    OPEN -.->|"2 B steady"| HOT["📦 id + payload<br/>no session · no address"]
    class INLINE muteC
    class OPENING warmC
    class OPEN clientC
    class CLOSED dangerC
    class HOT noteC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

#### Optimistic first packet

_The first UDP payload need not wait for CAPS; the server buffers pre-HELLO frames._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
    autonumber
        box rgb(236, 253, 245) Client
            participant App as 🧑‍💻 App
            participant Client as 🧦 MyQUIC2 client
        end
        box rgb(238, 242, 255) Server
            participant Server as 🛰️ MyQUIC2 server
        end
        rect rgb(248, 250, 252)
            Note over Client: QUIC established · rev2 state published
            Client->>Server: CTL HELLO(wire_ver=2)
            App->>Client: first UDP datagram
        end
        rect rgb(255, 247, 237)
            Client->>Server: DATA OPEN (optimistic)
            Server->>Server: buffer pre-HELLO frames<br/>8 frames / 16 KiB
            Server-->>Client: CTL CAPS(2)
            Server->>Server: flush buffer in arrival order
            Server-->>Client: FLOW_ACK + reply
        end
        rect rgb(236, 253, 245)
            Note over Client,Server: CAPS only updates caps · not a first-packet gate
        end
```

#### Domain target + rebind

_Resolve once, learn the real source, then compress both directions._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
    autonumber
        box rgb(236, 253, 245) Client
            participant App as 🧑‍💻 App
            participant Client as 🧦 MyQUIC2 client
        end
        box rgb(238, 242, 255) Server
            participant Server as 🛰️ MyQUIC2 server
        end
        box rgb(255, 247, 237) Exit side
            participant Resolver as 🔎 Resolver
            participant Target as 🎯 Target
        end
        rect rgb(248, 250, 252)
            Note over App,Client: ① first datagram names the domain
            App->>Client: UDP to example.com:53
            Client->>Server: DATA OPEN(domain, payload)
            Server->>Resolver: memo → moka → hickory
            Resolver-->>Server: A / AAAA
        end
        rect rgb(255, 247, 237)
            Note over Server,Target: ② learn the actual source
            Server->>Target: payload
            Target-->>Server: reply from actual source
            Server-->>Client: DATA OPEN + SRC (actual source)
            Client-->>App: SOCKS5 reply (learned source)
        end
        rect rgb(236, 253, 245)
            Note over Client,Server: afterwards 2 B both ways · source changes rebind the id
            Client->>Server: DATA 2 B steady
        end
```

#### Pure-uplink flow

_FLOW_ACK unlocks compression even when no payload ever comes back._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
    autonumber
        box rgb(236, 253, 245) Client
            participant App as 🧑‍💻 App
            participant Client as 🧦 MyQUIC2 client
        end
        box rgb(238, 242, 255) Server
            participant Server as 🛰️ MyQUIC2 server
        end
        box rgb(255, 247, 237) Exit side
            participant Target as 🎯 Target
        end
        rect rgb(248, 250, 252)
            Note over App,Client: telemetry · game upload · one-way flows
            App->>Client: outbound datagram
            Client->>Server: DATA OPEN(payload)
            Server->>Target: payload
        end
        rect rgb(236, 253, 245)
            Server-->>Client: FLOW_ACK (no payload)
            Note over Client,Server: the ACK confirms the binding · compression unlocks without downlink
            Client->>Server: DATA 2 B steady
        end
```

#### Server-owned full-cone flow

_The server can open a flow for an unsolicited source; the app replies on the same id._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","actorBkg":"#eef2ff","actorBorder":"#4f46e5","actorTextColor":"#1e1b4b","actorLineColor":"#94a3b8","signalColor":"#334155","signalTextColor":"#0f172a","labelBoxBkgColor":"#e0e7ff","labelBoxBorderColor":"#6366f1","labelTextColor":"#1e1b4b","loopTextColor":"#1e1b4b","noteBkgColor":"#e0e7ff","noteBorderColor":"#6366f1","noteTextColor":"#1e1b4b","activationBkgColor":"#c7d2fe","activationBorderColor":"#4f46e5","sequenceNumberBackgroundColor":"#4f46e5","sequenceNumberColor":"#ffffff"}}}%%
sequenceDiagram
    autonumber
        box rgb(255, 247, 237) Remote
            participant Source as 🌐 Remote source
        end
        box rgb(238, 242, 255) Server
            participant Server as 🛰️ MyQUIC2 server
        end
        box rgb(236, 253, 245) Client
            participant Client as 🧦 MyQUIC2 client
            participant App as 🧑‍💻 App
        end
        rect rgb(248, 250, 252)
            Note over Source,Server: udp_full_cone = true · opt-in
            Source->>Server: unsolicited datagram
            Server->>Server: allocate owner=1 wire id
            Server-->>Client: DATA OPEN + SRC (sess, source)
            Client-->>App: deliver (learned source)
        end
        rect rgb(236, 253, 245)
            Note over App,Source: app replies on the same id
            App->>Client: app reply
            Client->>Server: DATA 2 B steady (same id)
            Server->>Source: app reply
        end
```

#### Wire-version compatibility

_Matched deployment: a wrong peer fails at HELLO/CAPS, never silently downgrades._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart TB
A(["🆕 new client"]) --> B["📨 CTL HELLO(wire_ver=2)"]
    B --> C{"peer answers<br/>CAPS(2)?"}
    C -->|"yes"| D(["✅ UDP enabled"])
    C -->|"no · 2 s"| E["🚫 close + redial"]
    E -.-> F(["no old-wire downgrade"])
    G(["📼 old v3 / MQP-2 peer"]) --> H["🔍 first byte is not 0x0X"]
    H --> I(["⛔ drop on new server"])
    class A,B,C,D clientC
    class E,F dangerC
    class G,H,I muteC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

### 🚪 Server & admission

#### Server ingress & session lifecycle

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

#### Admission decision tree

_Connection permit → token → memory budget → session fair-share._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
C["🔌 new QUIC connection"] --> G["🛡️ global conn cap"] --> A["🔑 token valid"] --> M["🧮 memory budget"] --> H["🛰️ handle_conn"] --> S["🔌 session fair-share"] --> SESS(["✅ admitted<br/>64 KiB socket"])
    G -.->|"full"| R["🚫 refuse<br/>1/s warn"]
    A -.->|"invalid"| CL["✂️ close 0x01"]
    M -.->|"deny"| R
    S -.->|"full"| D["📦 drop"]
    class C,G,A,M,H,S coreC
    class SESS clientC
    class R,CL,D dangerC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

#### Reply-source authorization

_Restricted allowlist first; full-cone is an explicit opt-in._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
R(["📨 reply source"]) --> FC{"udp_full_cone?"}
    FC -->|"true"| OK(["✅ forward any source"])
    FC -->|"false"| EX{"exact live<br/>flow source?"}
    EX -->|"yes"| OK
    EX -->|"no"| RING{"16-entry IP ring?"}
    RING -->|"yes"| OK
    RING -->|"no"| DROP(["⛔ drop + count"])
    OK -.- NOTE["server-owned flow<br/>opt-in only"]
    class R,FC,EX,RING coreC
    class OK clientC
    class DROP dangerC
    class NOTE noteC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

#### DNS resolution layers

_Thread memo → moka → hickory, then SSRF policy at the exit._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
Q(["🌐 host + port"]) --> TM["🔥 thread memo<br/>64 sets × 2 ways"]
    TM -->|"miss"| MK["☁️ moka shared<br/>host key · 120 s / 10 s"]
    MK -->|"miss"| H["📡 hickory<br/>5 s · cancellable"]
    H --> C["🎯 A / AAAA"]
    C --> P["🛡️ SSRF / ipnet"]
    P --> O(["🔌 dial / sendmmsg"])
    class Q,TM coreC
    class MK,H wireC
    class C,P warmC
    class O clientC

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

### 🚀 Scheduling & transport

#### Cross-session fairness

_Per-session FIFO and a round-robin cursor feed one dict TRAIN._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
subgraph APPS["🧑‍💻 associations"]
        A["assoc A<br/>DNS"]
        B["assoc B<br/>game"]
        C["assoc C<br/>VPN"]
    end
    subgraph STAGE["⚙️ connection stager"]
        Q["per-session FIFO<br/>round-robin cursor"]
        F["drain burst<br/>exact DATAGRAM budget"]
    end
    A --> Q
    B --> Q
    C --> Q
    Q --> F
    F --> T["📦 TRAIN dict 0x04<br/>id list + idx + len + payload"]
    T --> D(["🚀 one QUIC DATAGRAM"])
    F -.-> NOTE["fair: a busy assoc cannot starve the rest"]
    class A,B,C clientC
    class Q,F coreC
    class T wireC
    class D clientC
    class NOTE noteC
    style APPS fill:#f0fdf4,stroke:#bbf7d0,stroke-width:1.5px,color:#14532d
    style STAGE fill:#eef2ff,stroke:#c7d2fe,stroke-width:1.5px,color:#312e81

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

#### PMTU ramp

_Start at the QUIC floor, probe upward, and raise the start on known paths._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
subgraph RAMP["📈 PMTU discovery"]
        I["🎚️ initial_mtu<br/>default 1200"] --> P1["1336"]
        P1 --> P2["1404"]
        P2 --> P3["1438"]
        P3 --> P4["1472<br/>ceiling"]
    end
    I --> B["📦 DATAGRAM budget<br/>mtu − 38 = 1162 B"]
    P4 --> W["✅ single frame<br/>up to 1434 B"]
    I -.-> R["💡 raise on known paths<br/>1360 / 1400 / 1472"]
    class I,P1,P2,P3,P4 wireC
    class B warmC
    class W clientC
    class R noteC
    style RAMP fill:#ecfeff,stroke:#a5f3fc,stroke-width:1.5px,color:#164e63

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

### ✅ Verification

#### CI pipeline

_Every push: format, lint, the full macOS/Linux test sets, musl and glibc builds._

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontSize":"14px","lineColor":"#64748b"}}}%%
flowchart LR
subgraph CHECK["✅ checks"]
        C(["📝 push / PR"]) --> F["🎨 rustfmt"]
        F --> L["🧹 clippy -D warnings"]
        L --> T["🧪 cargo test<br/>530 macOS + Linux cfg-gated"]
    end
    subgraph BUILD["📦 builds"]
        M["musl static"]
        G["gnu 2.36"]
    end
    T --> M
    T --> G
    M --> A["📜 SHA256SUMS"]
    G --> A
    A --> R(["🚀 release assets"])
    class C,F,L,T coreC
    class M,G wireC
    class A,R clientC
    style CHECK fill:#f0fdf4,stroke:#bbf7d0,stroke-width:1.5px,color:#14532d
    style BUILD fill:#eef2ff,stroke:#c7d2fe,stroke-width:1.5px,color:#312e81

    classDef clientC fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef coreC fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#1e1b4b
    classDef wireC fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef warmC fill:#fff7ed,stroke:#fb923c,stroke-width:2px,color:#7c2d12
    classDef dangerC fill:#fff1f2,stroke:#e11d48,stroke-width:2px,color:#881337
    classDef muteC fill:#f8fafc,stroke:#cbd5e1,color:#475569
    classDef noteC fill:#e0e7ff,stroke:#8b5cf6,stroke-width:1.5px,color:#312e81
    classDef decisionC fill:#fef9c3,stroke:#eab308,stroke-width:2px,color:#713f12
```

## 📚 Documentation

All project documents are maintained in **English**. The split is deliberate: the README is the operator-facing overview; the spec is the implementation contract; the analyses preserve the reasoning, measurements and fix history behind the current wire.

- [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md) — wire format, state machine, security contract and the implementation checklist.
- [MQP3_REFACTOR_ANALYSIS.md](MQP3_REFACTOR_ANALYSIS.md) — design rationale, byte/CPU models, alternatives considered and roadmap.
- [PROTOCOL_ANALYSIS.md](PROTOCOL_ANALYSIS.md) — end-to-end protocol/architecture analysis and the evidence behind the design.
- [PERF_ANALYSIS.md](PERF_ANALYSIS.md) — performance work, benchmark results and the fix history that produced them.
- [analysis/mqp3-refactor/](analysis/mqp3-refactor/) — five deep dives: [wire](analysis/mqp3-refactor/01-wire.md), [uplink](analysis/mqp3-refactor/02-uplink.md), [downlink](analysis/mqp3-refactor/03-downlink.md), [transport](analysis/mqp3-refactor/04-transport.md) and [evidence](analysis/mqp3-refactor/05-evidence.md).
- [examples/hotpath_bench.rs](examples/hotpath_bench.rs) — TCP/UDP load, correctness, latency and full-duplex harness.
- [scripts/linux-bench-matrix.sh](scripts/linux-bench-matrix.sh) — Linux deployment benchmark matrix.
- [config-server.toml](config-server.toml) · [config-client.toml](config-client.toml) — documented configuration samples.

## 📄 License

[MIT](LICENSE)
