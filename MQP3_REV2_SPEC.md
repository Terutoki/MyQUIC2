# MQP-3 wire rev2 — Implementation Specification (incompatible with older versions, still named MQP-3)

> Baseline: `d2f9658` (v0.2.0) · Decisions: **small packets first**, incompatible with the old wire, no bulk throughput target, uplink/downlink symmetric (full-duplex goals D1–D6).
> This file is the implementation contract: land the codec first, then wire it up phase by phase. All version identification appears only in `wire_ver=2` of `CTL HELLO/CAPS`;
> code/docs/logs **must not contain "MQP-4"**.
>
> **Status (2026-10-22, audit-hardened):** the contract below is current; the implementation-status snapshot in §10 is dated and retains historical test counts. The current tree has **476 macOS tests**, with server-owned full-cone flows, the connection-level stager, the reassembler purge hooks and the full audit-hardening batch (§10.6) landed.

---

## 0. Goals and Phases

| Phase | Content | Main benefit |
|---|---|---|
| **1a** | rev2 codec + production UDP switch (IP flow): remove `sess`, steady-state 2 B header, `DATA/TRAIN/FRAG/CTL`, `FLOW_ACK` (uplink-only), `SESS_CLOSE`; domains remain inline for now | all small packets −3 B/frame; uplink-only sparse −6~−14%; `>512 B` uniformly moves to v3 (−7~−22 B/frame/fragment) |
| **1b** | domain flow binding and downlink compression: first frame `OPEN` (bidirectional), `OPEN\|SRC` rebind, server-owned flow; domain bidirectional compression | domain-class −15~−38% wire (uplink and downlink) |
| **2** | connection-level stager + cross-session `TRAIN dict` + per-session quota/fairness | multiple associations: send calls −90%+, wire −8~−18% (conditional) |
| **3** | optional: B′ 1 B short header, FEC opt-in, larger reassembly cap | <1 B/frame-level |

**Non-goals**: bulk throughput (MQP header <1–3%), payload compression, fragment train, u16 frag id, mixed deployment with v0.2.0.

---

## 1. First-Byte Safety Check (why rev2 can coexist with old implementations without misparsing)

Old code dispatch order (verified):

- Server `accept.rs`: `is_v3(d)` → otherwise `d[0]==0x05` (MQP-2 FRAG) → otherwise `is_batch` (0x06) → otherwise `decode_datagram_ref` (requires 0x02) → otherwise drop.
- Client `dispatcher.rs`: `is_v3` → `is_batch` → `0x05` → `decode_datagram_ref` (0x02) → otherwise drop.

Therefore **the first byte of every rev2 frame is fixed at `0x0X` (high 4 bits == 0) and avoids 0x02/0x05/0x06**,
both the old v2 and old v3 parsers treat it as an unknown frame and drop it, without misrouting:

```text
first byte = 0b0000_0000 | kind/flags
  0x00 DATA steady        0x01 DATA extended
  0x04 TRAIN              0x08 FRAG steady
  0x09 FRAG extended      0x0C CTL
```

- Mixed deployment: a new server encountering an old client (first byte `0x1X/0x2X/0x3X/0x4X`) → dropped as an illegal first byte;
  a new client encountering an old server (rev2 first byte `0x0X`) → the old side drops it.
- **No promise of mixed-version usability**: both sides upgrade; `HELLO/CAPS` only provides fail-fast/capability negotiation (see §6).
- **Optimistic first packet**: once a client connection is published it can send UDP immediately (without waiting for CAPS); the server first places rev2 data frames arriving before HELLO into a
  per-connection bounded buffer (8 frames / 16 KiB), and processes them in arrival order after receiving a valid `HELLO(wire_ver=2)`; a HELLO with a mismatched version only gets CAPS in reply,
  does not open the gate, and does not release the buffer; overflow is counted and dropped. CAPS only updates the negotiated limits/compression, and is no longer a precondition for sending the first packet.

---

## 2. flow id and session

### 2.1 wire id

```text
wire_id u32 = (local_id << 1) | owner
  owner = 0 client-allocated; owner = 1 server-allocated
  local_id starts at 1 and increases monotonically, never reused for the lifetime of the connection
  wire_id == 0 reserved (illegal data frame; when there is no flow, use the INLINE form)
  limit: local_id <= 0x7FFF_FFFF (falls back to INLINE on exhaustion, practically unreachable)
```

- Encoding: LEB128; common active ids < 64 → **1 B**.
- No reuse ⇒ late frames of an old flow only hit a "closed" entry and are dropped, and will not leak into a new target; no tombstone/reuse window is needed.
- Half-space ownership: client only allocates owner=0, server only allocates owner=1. Both ends can open/close/ack (D2).

### 2.2 Data plane no longer carries `sess`

`session u32` appears only in:

1. the `OPEN`/`INLINE` extension header of `DATA/FRAG`;
2. `CTL SESS_CLOSE`;
3. the control plane (HELLO/CAPS do not carry a session).

Steady-state compressed frames carry only `wire_id`. The receiver uses a **per-connection flow table** to map `wire_id → (session, target, state, reply_src)`.

### 2.3 Two tables per endpoint

| Table | Location | key | value | Purpose |
|---|---|---|---|---|
| `FlowRegistry` | one per QUIC connection, client/server symmetric | `wire_id` | `Arc<FlowBinding>` | resolve ids on the receive side; downlink dispatcher / uplink accept |
| `SessionFlows` | one per session (modified from the existing `FlowTable`) | `TargetAddr` (client) / reply `SocketAddr` (server) | `wire_id + Arc<FlowBinding>` | find id by target on the send side; server downlink finds id by source |

`FlowBinding` (shared by both ends):

```text
wire_id: u32
session: u32
target: TargetAddr        // client: request target; server: installed binding target
state: AtomicU8           // Opening(0) / Open(1) / Closed(2)
reply_src: ArcSwapOption<SocketAddr>  // client downlink: source address for the SOCKS5 reply header
resolved: SmallVec<SocketAddr>        // server downlink: resolution results for domain flows (matching source IP)
```

- Allocation/insertion happens only for new flows; the hot path only reads `Arc` + atomics.
- `FlowRegistry` uses `parking_lot::RwLock<HashMap<u32, Arc<FlowBinding>>>` (read-heavy, write-light; Phase 1 prioritizes correctness;
  if profiling shows lock contention, Phase 2 switches to sharded/ArcSwap snapshots).
- Per-connection live flow cap: `max_conn_flows` (default 4096, negotiated via `CAPS`); per-session cap 64 (negotiable).
  Over limit: the send side falls back to `INLINE`; the receive side `FLOW_REJECT`.

---

## 3. Frame Format

> Common rules: one QUIC DATAGRAM body carries exactly one MQP rev2 frame; the `DATA/FRAG` payload is the remaining bytes of the DATAGRAM;
> all varints are LEB128 u32; the decoder must validate length before allocating/slicing; truncation/illegal flag/unknown opcode drops only the current frame.

### 3.1 `DATA` (0x00 / 0x01)

```text
steady:  0x00 | wire_id varint | payload
extended: 0x01 | flags u8 | [wire_id varint if !INLINE] | [sess u32 if OPEN or INLINE]
          | [addr if OPEN or INLINE] | payload

flags: OPEN=0x01, INLINE=0x02, SRC=0x04;  OPEN|INLINE mutually exclusive; other bits must be 0
INLINE:  no wire_id; sess+addr self-describing (fail-safe for table full/one-shot target/diagnostics)
OPEN:    wire_id bound to (sess, addr); semantics of addr:
          - client-initiated flow: destination (normal OPEN)
          - server-initiated flow: reply source address (OPEN|SRC)
          - source drift rebind for an existing flow: same wire_id + OPEN|SRC + new source address
SRC:     addr is the actual source, not the target (downlink port change/anycast/full-cone)
```

| Form | IPv4 header | IPv6 header | Domain L header |
|---|---:|---:|---:|
| steady (id<64) | **2 B** | 2 B | 2 B |
| steady (id<8192) | 3 B | 3 B | 3 B |
| OPEN (v4/v6/domain) | 14 B | 26 B | 11+L B |
| INLINE (v4/v6/domain) | 13 B | 25 B | 10+L B |

> OPEN is 1 B more than old v3 inline (one extra flags byte), but it is paid only on the **first frame/rebind frame of each flow**; steady state saves 3–4 B/frame.
> Later the OPEN flags can be folded into reserved bits, saving 1 B/flow; not a first-phase goal.

### 3.2 `TRAIN` (0x04)

```text
0x04 | form u8 | count u8 | ...
form = 0 (same):  wire_id varint | item*
form = 1 (dict):  nfl u8 | wire_id varint * nfl | item*
item (same):  len varint | payload
item (dict):  idx u8 | len varint | payload
```

- Only **confirmed (Open)** flows are allowed; the first frame of a new flow must be sent separately as `DATA OPEN` (no per-item inline).
- `count ≤ max_train_items` (default 64, negotiated via `CAPS`); `nfl ≤ min(count, 64)` and dict ids are distinct.
- At decode time, any id not installed → drop that item (counted), continue with the rest; the length must consume exactly to the end of the frame.
- Cross-session is allowed: different `wire_id`s in a dict may belong to different sessions (only produced by the connection-level stager in Phase 2).
- Header size: same = 3 B + id varint; dict = 4 B + nfl × id varint (kind/form/count/nfl); same-flow item 1 B len (≤127 B payload), dict item plus 1 B idx.

### 3.3 `FRAG` (0x08 / 0x09)

```text
steady:   0x08 | wire_id varint | frag_id u32 LE | idx u8 | total u8 | chunk
extended: 0x09 | flags u8 | [wire_id if !INLINE] | frag_id u32 | idx u8 | total u8
          | [sess u32 if OPEN or INLINE] | [addr if OPEN or INLINE] | chunk
```

- flags same as DATA (OPEN/INLINE/SRC); steady-state header **8 B** (old v2 18 B / old v3 codec 11 B).
- `1 ≤ total ≤ 64`, `idx < total`, chunk non-empty; key = `(wire_id, frag_id)`.
- The first fragment may carry `OPEN` (inline addr) so reassembly works even if the flow is not installed; subsequent fragments are compressed.
- Retain the existing bounds of u32 `frag_id`, 8 KiB payload cap, 2 s partial, 256 KiB/connection/256 partials.

### 3.4 `CTL` (0x0C, DATAGRAM carrier)

Control frames **travel over DATAGRAM, are idempotent, and may be lost** (loss only delays compression/reclamation; correctness never depends on their arrival).
Old peers always drop the `0x0C` first byte, so it is inherently safe.

```text
0x0C | opcode u8 | body
0x01 HELLO       : "M3" | wire_ver u16 (=2) | flags u16
0x02 CAPS        : "M3" | wire_ver u16 | flags u16 | max_conn_flows u16
                   | max_flows_sess u16 | max_train_items u8 | max_frame_bytes u16
                   | max_reassembly u16
0x10 FLOW_ACK    : wire_id varint | status u8 (0=open/confirmed)
0x11 FLOW_REJECT : wire_id varint | reason u8 (1=policy, 2=table_full, 3=dns)
0x12 FLOW_CLOSE  : wire_id varint
0x20 SESS_CLOSE  : sess u32 | reason u8
```

- **HELLO/CAPS**: the client sends HELLO immediately after the connection is established, but **does not wait for CAPS** before sending the first UDP packet (optimistic first packet);
  the server replies with CAPS once per HELLO received (100 ms throttle), and releases rev2 data frames that arrived before HELLO in order after a valid HELLO.
  Version mismatch → the client closes the connection and reports an error (fail-fast).
- **FLOW_ACK**: sent after the server successfully installs the flow; upon receipt the client moves that flow from `Opening` to `Open` and starts compressing the uplink.
  ACK loss → the client keeps sending OPEN (idempotent); the server reinstalls/re-ACKs, which only delays compression, with no black hole.
- **FLOW_REJECT**: policy/table full/DNS failure; the client falls back to `INLINE` for that target (may retry after TTL).
- **FLOW_CLOSE/SESS_CLOSE**: sent 3 times (~50 ms apart); loss is covered by the 180 s idle fallback.
- Control frames have rate/total caps; unknown opcode/truncation → counted and dropped; the connection is not terminated.

---

## 4. Binding, Confirmation, and Full-Duplex Semantics

### 4.1 Uplink (client→server)

```text
New flow:
  C --DATA OPEN(id, sess, dest, payload)--> S
  S: validate SSRF/policy → create/reuse session → send to target → install flow → CTL FLOW_ACK(id)
  C: Opening → Open; afterwards DATA steady (2 B) or enter TRAIN
Uplink-only flow: confirmed only by FLOW_ACK; sparse flows drop from a 12/13 B header to 2–3 B.
Duplicate OPEN (ACK lost/first frame lost): idempotent reinstall/re-ACK.
```

### 4.2 Downlink (server→client), including domain/port change/full-cone

```text
Exact (session, src) hit → compressed DATA(id) / TRAIN
Domain flow / source port change / anycast:
  S --DATA OPEN|SRC(id, sess, actual_src, payload)--> C
  C: bind reply_src=actual_src (writes the SOCKS5 reply header, behavior identical to today's inline) → set Open
  S: install (session, src)→id reverse mapping; subsequent replies from the same source are compressed
full-cone unsolicited (no matching flow):
  S allocates a new wire_id with owner=1 → DATA OPEN|SRC(id, sess, src) → subsequent compression
  (only when `udp_full_cone=true`; counted as unsolicited)
```

- Multiple addresses for domain/A anycast: the server matches the source IP in the flow's `resolved` set; if it matches, compress; otherwise rebind.
- First-frame byte count is the same as today's inline (v4 13 B / v6 25 B / domain 10+L B) → **0 first-frame cost**.
- Client downlink compression depends only on "the local existing binding.reply_src"; it does not depend on whether the uplink is compressed.

### 4.3 How full duplex (D1–D6) lands on this wire

- D1 data plane: DATA/TRAIN/FRAG use the same codec in both directions;
- D2 state plane: each end can open/close/ack in each direction; id half-space ownership;
- D3 control plane: HELLO/CAPS/ACK/REJECT/CLOSE/SESS_CLOSE bidirectional;
- D4 no direction dependency: uplink-only relies on FLOW_ACK; server-owned flows make downlink-only flows compressible;
- D5 independent scheduling: Phase 2 connection-level stager + per-session quota (Phase 1 keeps per-session flush, no regression);
- D6 testable: `udpbidir` + direction bytes/frame counts (Phase 0 benchmark tooling already in progress).

---

## 5. Safety and Resource Invariants

1. Per-frame/per-item authorization is completed before entering any stager; cross-session TRAIN does not bypass allowlist/flow fallback.
2. SSRF/`allow_private` semantics are unchanged; rev2 only changes "how the source address is expressed".
3. A flow is installed only after the target accepts a real send; unknown/unconfirmed ids drop only the current item.
4. Half-space ids must not be resolved across sessions: registry entries must carry the session; the client looks up its local table by each item's id.
5. full-cone remains opt-in; server-owned flows are created only under full-cone and are counted as unsolicited.
6. Length/range validation before parsing control/data frames; unknown first byte/opcode/flag → counted and dropped, no panic.
7. Tables are bounded and counted in admission; `max_conn_flows`/`max_flows_sess`/`max_frame_bytes` are negotiated by CAPS.
8. Non-reusable wire_id (monotonic) ⇒ no splice risk; exhaustion falls back to INLINE.

---

## 6. Version Negotiation and Mixed Deployment

- Client: connection established → send HELLO (background retry until CAPS or 2 s timeout); once the connection is published it can keep sending UDP (optimistic first packet, without waiting for CAPS).
- Server: rev2 data frames before HELLO enter a per-connection bounded buffer (8 frames / 16 KiB) and are processed in arrival order after a valid HELLO; a HELLO with a mismatched version
  only gets CAPS (its own version) in reply and is counted; the gate is not opened and the buffer is not released; overflow is counted and dropped.
- New client + old server: HELLO is dropped by the old side → no CAPS → the client closes the connection and reports an error after 2 s (no silent downgrade); optimistic first packets are
  dropped by the old side as an unknown first byte and do not produce an error path.
- Old client + new server: old frame first bytes are illegal → dropped; the server may close the connection after the count of consecutive illegal frames on the same connection exceeds a threshold.
- The default ALPN remains `h3`; deployments requiring fail-closed may explicitly bump the ALPN (optional, not part of this phase).
- The protocol name is always **MQP-3**; `wire_ver=2` exists only in CAPS/logs.

---

## 7. Client/Server Integration Points (Phase 1a change list)

### 7.1 Shared library

| File | Change |
|---|---|
| `src/mqp/r2.rs` (new) | codec from this specification + golden/malformed tests |
| `src/mqp.rs` | `pub mod r2;` + re-export |
| `src/mqp/r2_flow.rs` (new, Phase 1a/1b) | `FlowBinding`, `FlowRegistry`, `SessionFlows`, `CtlState` (HELLO/CAPS/confirmation state) |
| `src/stats/udp_stats.rs` | new counters: r2 frame kind, train items, inline fallback, flow open/ack/reject/close, compression ratio |

### 7.2 Client

| File | Change |
|---|---|
| `bin/myquic2-client/assoc.rs` | `PendingTrain` switched to rev2 `DATA/TRAIN`; each target finds its `wire_id` via `SessionFlows`; `Opening→Open` confirmed by ACK/downlink; `>512 B` goes through rev2 FRAG |
| `bin/myquic2-client/hub.rs` | `AssocEntry` gains a `session` and an `Arc<ConnFlowRegistry>` handle; `confirmed` bitmap changed to binding state |
| `bin/myquic2-client/dispatcher.rs` | parse rev2 `DATA/TRAIN/FRAG/CTL`; `wire_id → FlowBinding → session → DispatchCache`; handle `FLOW_ACK/REJECT/CLOSE`, `OPEN\|SRC` rebind |
| `bin/myquic2-client/pool.rs` | create `ConnFlowRegistry`/`CtlState` per connection; send HELLO immediately, CAPS completes asynchronously (does not block the first packet); rebuild on reconnect |
| `bin/myquic2-client/egress.rs` | usable as soon as the connection is published (optimistic first packet, without waiting for CAPS); control frame sending (CLOSE after ACK processing, etc.) |

### 7.3 Server

| File | Change |
|---|---|
| `bin/myquic2-server/accept.rs` | rev2 entry: first byte 0x0X; bounded buffer before HELLO + in-order release after a valid HELLO; decode DATA/TRAIN/FRAG; `wire_id→FlowBinding→session`; send FLOW_ACK after OPEN installation |
| `bin/myquic2-server/reader.rs` | downlink uses rev2 DATA/TRAIN/FRAG; `(session, src)→wire_id` reverse table; domain/port-change `OPEN\|SRC` binding; full-cone server-owned id |
| `bin/myquic2-server/table.rs` | `SessEntry` holds `SessionFlows`/wire_id reverse table; SESS_CLOSE reclaims immediately |
| `bin/myquic2-server/forward.rs` | after resolving the domain, write `resolved` into the flow binding (Phase 1b) |

### 7.4 Removals/Retention

- After Phase 1a completes: remove MQP-2 sending from the UDP production path (the `DgramFragmenter` v2 logic is retained only for tests/compatible decoding for one release).
- The old v3 codec is retained for one release for diagnostics/rollback binaries, but production no longer sends it; remove later.
- TCP path unchanged (QUIC streams have no MQP header).

---

## 8. Testing and Acceptance

### 8.1 Unit

- golden bytes for each frame (steady/open/inline, v4/v6/domain, same/dict train, frag, all CTL opcodes);
- truncation/bad flag/unknown opcode/oversized id/`idx>=total`/out-of-range `count`: no panic, returns `MqpError`;
- **first-byte safety test**: for each rev2 frame assert `is_v3(first)==false`, and first is not in `{0x02,0x05,0x06}`;
- varint boundaries (127/128/16383/16384/2^31-1), TRAIN 64 items, FRAG 64 fragments;
- `FlowRegistry`/`SessionFlows` concurrency/lifecycle/limit tests.

### 8.2 End-to-end

| Scenario | Acceptance |
|---|---|
| `udpsweep` all sizes | all byte checks pass (including 8 KiB fragmentation) |
| `udpdomain` / `udpdomainmulti` | domain uplink/downlink compression in effect (counters); wire model −15%~−37% |
| `udppaced` 1–512 B | p99 regression not more than 5%, 0 silent packet loss |
| `udpfanout` (new) | correct TRAIN/mixed destinations for 1 association × N dest; call count decreases |
| `udpmulti` + churn | SESS_CLOSE reclaims immediately; 8192 pool not exhausted |
| `udpbidir` (new) | bidirectional total ≥1.6× one-way, p99 degradation ≤10% |
| `bulk` / `lat` | bulk no regression; lat p50/p99 no regression (same machine, same round) |
| mixed versions | new client + old server fail-fast; old client + new server only drops and counts |

### 8.3 Benchmark (Linux 2–4 cores + `tc netem` 70/140 ms, 0/0.5/2% loss)

- Counters: rev2 frame kind, TRAIN items, inline fallback, flow open/ack/reject, compression ratio, direction bytes,
  `send_datagram` calls, QUIC packet count (qlog/tcpdump), quinn stats (cwnd/rtt/mtu).
- A/B: rev2 vs HEAD; MTU 1200 vs 1400; `MYQUIC2_SHARD_RUNTIME=0/1`.

---

## 9. Implementation Order (starting this round)

1. **This file + the `src/mqp/r2.rs` codec** (compiles, unit tests pass; production path unchanged).
2. `r2_flow.rs` state types + unit tests.
3. Client/server Phase 1a wiring (temporary feature/constant switches may be added, default off; flip after tests pass).
4. `udpfanout`/`udpbidir` benchmarks (in progress in parallel).
5. Phase 1b domain binding/downlink compression; Phase 2 stager/cross-session.
6. Clean up old send paths, update README/config/stats.

---

## 10. Implementation Status (2026-10-21, Phase 1a landed)

> **Status note (2026-10-22).** This section is a dated implementation snapshot, not a live tracker. Since the snapshot, server-owned/full-cone flows, the connection-level stager with cross-session `TRAIN dict`, `R2Reassembler::{drop_session, drop_flow}` purge hooks and the audit-hardening batch (§10.6) have landed; the current tree has **476 macOS tests**. Items below that describe these as remaining are retained as history. See the README verification section for the current counts.

### 10.1 Delivered

| Layer | Content | Tests |
|---|---|---|
| codec | `src/mqp/r2.rs`: DATA steady/OPEN/INLINE, TRAIN same/dict, FRAG (codec ready), all CTL opcodes, first-byte safety validation, varint/boundary/truncation tests | 15 unit |
| flow state | `src/mqp/r2_flow.rs`: `FlowBinding` (state/reply_src/resolved), `SessionFlows`, `FlowRegistry` (including `remove_session`), `FlowIds`, `CtlState` | 10 unit |
| client | `src/bin/myquic2-client/rev2.rs` (new): per-connection `ConnRev2`, HELLO→CAPS gate, OPEN→steady/TRAIN/INLINE state machine, full-size rev2 (single-frame DATA otherwise `R2Fragmenter`), downlink `R2Reassembler`, burst/deferred flush, FLOW_REJECT TTL fallback, SESS_CLOSE×3; `pool/egress/auth/dispatcher/assoc/...` wiring | 124 bin tests |
| server | `accept.rs`: `R2ConnState`, HELLO/CAPS gate, rev2 entry (OPEN/steady/TRAIN/INLINE/**FRAG**), SSRF/policy reuse, install registry+SessionFlows, FLOW_ACK/REJECT, SESS_CLOSE/FLOW_CLOSE, sweep cleanup; `reader.rs`: `match_source` → steady/TRAIN/OPEN\|SRC downlink + full-size rev2 FRAG/single frame; `table/forward` wiring | 101 bin tests |
| frag | `src/udp/r2_frag.rs`: `R2Fragmenter` + `R2FragFlow::{Steady,Opening,Inline}`, aggregation backpressure gate (all-or-nothing), single-frame embedding/fragment adaptation | 7 unit |
| stage | `src/udp/r2_stage.rs`: Phase 2 connection-level cross-session aggregation primitive `R2Stager` (per-session FIFO + round-robin fairness, `TRAIN dict` cross-session frame coalescing, Open/Inline as separate frames, bounded queue) | 9 unit |
| reasm | `src/udp/r2_reasm.rs`: `R2Reassembler` (`(wire_id,frag_id)`/INLINE key, OPEN ctx consistency, 8 KiB/2 s/256 partials/256 KiB, no tombstone) | 9 unit |
| bench | `examples/hotpath_bench.rs`: `echomulti`, `udpfanout` (IP/domain fanout), `udpbidir` (full duplex) | clippy/rustfmt clean |

### 10.2 Verified (macOS loopback, release binary, temporary configuration; after Phase 1b)

- All UDP sizes go through rev2: `udpsweep` 8/128/512/1000/2000/3000/5000/8000 B **ALL OK** (`>512 B` is rev2
  single-frame DATA or rev2 FRAG in both directions; no legacy frames).
- `udppaced` rev2 128 B @5k pps **325000/325000, 0.000 % loss**; 60 s reporter including FRAG:
  `flow_open=31 open=499 steady=274140 train=358/854 frag=1200/4500/1200 inline=0 unknown_id=0 drops=0`
  (7 UDP connections, `hello=14 caps=14`).
- `udpdomain` domain target 1000/1000; `udpfanout` 8 mixed flows 2000/2000; `udp` 1000 B single frame 2000/2000;
  `udpbidir` full duplex 30000/30000; `lat` p50 ≈ 197 µs; `udpmulti` 8 assoc 15987/16000 (0.08% startup loss).
- `cargo test --all-targets`: **390 passed / 0 failed** (lib 186 + client 114 + server 90);
  `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` clean.
- admission is now charged at **2 × `FRAG_MAX_HELD_BYTES`** (legacy + rev2 reassemblers coexist);
  the default per-connection transport term is 14.25 → **14.5 MiB**.

### 10.3 Phase 2 Completed (2026-10-21)

- **client uplink**: `ConnRev2` holds a connection-level `R2Stager` (`Arc<parking_lot::Mutex<...>>`; the lock covers only a single push/drain and does not span await);
  ≤512 B payloads are enqueued as `Steady/Open/Inline` items, drained at burst end/before large packets/association exit/when the queue is full; `>512 B` uses
  single-frame DATA / `R2Fragmenter` with a drain first (preserving order); teardown records `EGRESS_DEAD` per item.
- **server downlink**: `R2ConnState` holds a connection-level stager (shared by all session reply readers); small replies are enqueued as Exact/Rebind/Inline,
  drained at burst boundaries, and coalesced into `TRAIN dict` across sessions in round-robin; large replies drain first, then take the direct path; `SESS_CLOSE`/`FLOW_CLOSE`
  purge both queued items and in-flight partials.
- **Negotiated caps**: `CAPS.max_train_items` is already used for stager framing; `max_frame_bytes` is already used for client frame sizing.
- **Measurement** (release, macOS loopback, `udpmultipaced` 8 assoc × 1000 pps × 128 B × 65 s):
  519 992/519 992, 0.000 % loss; client `stage=467846p/467180d/347639f/467845i/0x/0full` →
  **0.743 frames/payload, about 26 % fewer client DATAGRAM sends than the Phase-1b baseline of ≈0.99**; `udppaced`/`udpsweep`(8–8000 B)/`udpfanout`/`udpdomain` all pass on the same build.
- **Full-duplex symmetry (D2/D4)**: the server creates a **server-owned flow** for full-cone/unsolicited sources (`DATA OPEN|SRC`, owner bit 1),
  installs registry + session reverse table, and compresses subsequent replies from the same source; the client accepts unknown server-owned `OPEN|SRC` (small packets/first fragment) and installs the binding,
  the app reply reuses the same id (steady/stager/fragment), and server ingress accepts that id and forwards to the remote source; non-full-cone remains inline.
  `SESS_CLOSE` purges queued items on both ends, registry bindings, and in-flight partials.
- **Tests**: `cargo test --all-targets` **424 passed / 0 failed** (lib 199 + client 124 + server 101); Linux CI 428; clippy/fmt clean.

### 10.4 Remaining Work (optional/follow-up)

1. **Linux 2–4 core target machine measurements** (netem 70/140 ms, 0/0.5/2 % loss): scripts are ready; execution on the target machine is required.
3. **Strict ordering under backpressure**: a large reply that hits Blocked while items remain queued may be bypassed (permitted by UDP semantics; strict ordering requires retry-later).
4. **Burst packet loss with the app-facing relay socket's 64 KiB buffer**: the 0.03–0.13 % loss with `udpmulti` batch=64 is localized to the client relay socket
   (threshold 48→64 batch; 0 loss after `MYQUIC2_SESS_SOCKET_BUF=1 MiB`), unrelated to the stager/protocol, and is an existing configuration/implementation item.
5. Final cleanup of the old v3/v2 send paths and documentation/configuration convergence.

### 10.5 Unfinished (rest of Phase 2)

1. **CAPS negotiated limits actually take effect**: of `max_conn_flows/max_flows_sess/max_frame_bytes/max_reassembly`, the client already uses
   `max_frame_bytes` for frame sizing, while the rest still use compile-time defaults; the registry/session/frame length caps need to be
   changed to connection-level negotiated values.
2. **server-owned / full-cone flow** (complete D2/D4): id half-space/FlowIds are ready, not yet wired.
3. **Phase 2**: connection-level stager + cross-session `TRAIN dict` + per-session quota/fairness; `udpbidir` acceptance threshold.
4. **Linux 2–4 core target machine** benchmark (netem 70/140 ms, 0/0.5/2 % loss) — local macOS loopback cannot be extrapolated.
5. Old v3/v2 send path cleanup (the server small-path still has a last-resort legacy fallback) and final README/configuration convergence.
6. `R2Reassembler`'s active purge on SESS_CLOSE/FLOW_CLOSE (currently covered by the 2 s timeout/registry resolution at completion,
   which is part of UDP late-arrival semantics); if strict release is required, add shared-lib `drop_session/drop_flow` hooks.
7. `R2Fragmenter`'s `Blocked` is not counted separately as BUFFER_FULL (consistent with single-frame; observability difference only).

### 10.6 Audit hardening (2026-10-22, post-snapshot)

A full-tree code audit (memory / performance / logic) landed these changes; they are implementation hardening, not wire changes:

1. **Quinn stream-assembly memory bound.** The handshake advertises a small pre-auth credit (4 bidi + 2 uni streams; the previous 8192/100 let an unauthenticated peer park up to `MAX_CHUNKS = 1024` gap spans per advertised stream, hundreds of MiB per connection). After the token check the server raises bidi to 8192 with `MAX_STREAMS` (increase-only, protocol-legal). The client advertises `(0, 0)` incoming credit (it never accepts a stream). The pre-auth bound is charged per connection and the post-auth parked-header bound (4096 streams x 1024 spans x 96 B = 384 MiB) is a process-wide admission term; a per-connection parked-header cap of 256 is the fail-fast defense-in-depth.
2. **Domain `OPEN` x `SESS_CLOSE` race.** In-flight domain lookups carry a cancellation flag; `SESS_CLOSE` flags them before `take_session`, and session creation re-checks the flag inside the shard write lock, so a late DNS answer can no longer recreate a closed session, install a binding or ACK it.
3. **Server-side reaps notify the client.** `CTL SESS_CLOSE` (x3 best-effort) is now also emitted on idle sweep, fair-share/session-pool sweeps and reply-reader exit; the client already handled it, and a live binding can no longer point at a reaped session silently.
4. **Memory-bound enforcement.** The rev2 reassembler's ordering index is pruned and charged against `FRAG_MAX_HELD_BYTES`; the v0.2 per-session flow table is charged at its domain-target worst case (22 KiB); admission additionally charges the process-wide retry pool, DNS waiters, worker scratch and (charge-only) the stream-assembly bound.
5. **Hot-path / lock hygiene.** `FLOW_CLOSE`/`FLOW_REJECT` purge only a known binding's session-scoped stager state; the client `ensure_binding` checks the rejection window and registry capacity before any map scan and allocates wire ids only inside a successful insert; the stager keeps a steady-head-only cursor instead of rotating over standalone heads per item.
6. **Smaller fixes.** Server-reap/reader-exit registry purge is scoped to the removed entry's bindings (a recreated session id keeps its own); `r2_install` rolls back the forward registry when the reverse table fill races; TCP pump buffers reserve exactly; hickory's internal DNS cache is disabled (outer moka is the only TTL authority); the client runtime sizes its multi-thread workers against the pinned shard runtimes.
