# MQP-3 Refactor Feasibility Deep Analysis (wire rev2 · still named MQP-3)

> Analysis date: 2026-10-21 · Baseline: `d2f9658` (v0.2.0, clean worktree)
> Scope: **MQP-3 UDP data plane** (QUIC DATAGRAM). TCP goes over QUIC stream, with no frame header at the protocol layer; this document discusses it only where "why TCP is not part of the refactor" is concerned.
> Method: 5 parallel read-only deep reads + Lead synthesis (the per-topic notes are folded into this document and not shipped separately);
> all benefit numbers are **model/source arithmetic**, not measurements on the target machine; evidence grading see §1.2.
> Naming constraint: the refactored protocol **is still called MQP-3**; the wire version number exists only in the control plane `CAPS.wire_ver=2`, **the string "MQP-4" does not appear**.
> Interaction protocol: the user has explicitly allowed wire incompatibility, the new protocol is still named MQP-3, both uplink and downlink must be optimized, and full duplex must be implemented.

---

## 0. Conclusion (TL;DR)

**In one sentence: MQP-3 indeed still has headroom, but the headroom is uneven—the largest piece is in the "domain-name target", followed by "one-way/sparse flows, multiple associations, large packets/fragments, full-duplex inbound", and not in bulk throughput. The refactor is worth doing, but it should be positioned as "eliminating structural taxes + completing the control plane + true full duplex", and one must not expect it to raise bulk throughput by an order of magnitude.**

1. **The status quo is better than the old documents describe, and also more constrained than the old documents describe.**
   - Already landed: `SINGLE`/`TRAIN`, implicit flow 0, uplink/downlink frame aggregation of small packets in the same burst, downlink mixed-source TRAIN, implicit ACK (compress uplink only after receiving a compressed downlink frame).
   - Not landed / structural gaps: domain-name target **always inline in both directions**; uplink-only flows re-inline across TRAIN; everything `>512 B` falls back to MQP-2; the v3 compact FRAG codec is written but has zero wiring; **no control plane** (no CAPS/HELLO/FLOW_ACK/FLOW_CLOSE/SESS_CLOSE); the TRAIN header carries a unique `sess u32`, **one frame can only carry one session**; each session has its own socket/task/stager, and the downlink cannot aggregate frames across sessions.
2. **The largest benefit realizable at the protocol layer (model, IPv4/MTU1200):**

   | Workload | Status quo | wire rev2 | Δwire | Δsend calls | Evidence level |
   |---|---|---:|---:|---:|---:|
   | DNS-over-SOCKS domain-name query (L=11, 50 B, 1 packet/burst) | 129 B/payload | 109 B | **−15.5%**; at domain L=30, uplink **−37.3%**, downlink v4 −13.1% / v6 −25.9% | 0 | Model |
   | Domain-name target **downlink reply** (compressed after first-frame binding) | 13 B header/frame | 5–6 B | v4 **−7~−8 B/reply**, v6 **−19~−20 B**; small-packet frame body −7~−38% | 0 | Model |
   | Uplink-only sparse flow (100 B, IPv4 / IPv6) | 170 / 182 B | 160 B | **−5.9% / −12.1%** | 0 | Model |
   | High-rate same-flow small packets (60 B, 18 TRAIN items) | 65.9 B | 64.2 B | **−2.7%** | −5.4% | Model |
   | 32 sessions × 60 B (multi-association small packets) | 71.4 B | 65.8 B | **−8.0%** (conditional) | **−93.8%** | Model |
   | VPN 1200 B (MTU1200, 2 fragments) | 1352 B | 1325 B | −2.0% (protocol); **+ configuring MTU1400 → −6.1%** | 0 | Model |
   | bulk TCP / bulk UDP | — | — | **≈0** (MQP header <1–3%) | 0 | Model |

3. **"Substantially improve performance" must distinguish goals:**
   - If the goal is **bulk throughput/large-volume download**: **do not refactor the protocol for it**. MQP headers account for <1–3% of a 1200 B packet; a rewrite gains at most about 1–2%; the real 10–30% comes from `initial_mtu`, window/BDP, same-threading, fewer fragments and packet loss—these are transport configuration/implementation, not wire.
   - If the goal is **constrained uplink, DNS/domain names, multiple associations, multi-flow fan-out, VPN small packets, inbound/server-initiated flows**: the refactor has real benefits, see the table above; domain-name cases are especially pronounced.
   - If the goal includes **full duplex**: the QUIC transport layer is inherently full duplex; what is missing is the symmetry of MQP state, the control plane, and scheduling. The benefit here is "capability/fairness/tail latency", not a throughput multiplier.
4. **Recommended path: do "MQP-3 wire rev2" in phases (candidate B: connection-level flow id + symmetric bidirectional ownership + complete CTL plane), rather than a one-shot teardown.**
   - **Phase 0 (do first, no wire change)**: add measurements (frame count/packet count, send calls, compression ratio/fallback ratio), add `udpfanout`/`udpbidir` benchmarks, set `initial_mtu` per deployment (known paths 1360/1400), fix same-threading/thread topology (F10/F3) and A/B, the server-side per-class transport asymmetry.
   - **Phase 1 (wire rev2 core, incompatible)**: control plane (HELLO/CAPS/FLOW_ACK/REJECT/CLOSE/SESS_CLOSE, over one QUIC bidi stream) + connection-level flow id (u16, client/server halves) + remove `sess u32` + full-size DATA/TRAIN/compact FRAG + domain-name/uplink-only compression. **The name is still MQP-3**.
   - **Phase 2 (structure/full duplex)**: connection-level stager (uplink + downlink) + cross-session TRAIN (decided by Phase 0 measurements) + server-initiated flows (full-cone) + per-flow fairness/priority.
   - **Phase 3 (optional)**: B′ 1 B short header, negotiable reassembly cap, FEC/NACK opt-in.
5. **Core judgment:** If only one thing "with deterministic benefit for most real proxy traffic" is done, it is not refactoring the wire, but **Phase 0's MTU/topology/measurement**; if "protocol refactor" is to be done, the first priority is **domain-name flow compression** (uplink and downlink simultaneously −15~−38%), followed by **control plane + full-size v3 + compact FRAG**, and only then **cross-session frame aggregation** (benefit depends on measured quinn packet coalescing rate, largest engineering effort).
6. **Questions requiring the user's decision** see §9. The three most important: ① ordering of the objective function (constrained uplink bandwidth / per-core pps / tail latency); ② whether same-version deployment is acceptable, fully giving up coexistence with v0.2.0 peers; ③ whether the control plane can use a QUIC bidi stream (rather than DATAGRAM).

---

## 1. Analysis conventions and evidence grading

### 1.1 Data path and byte layers

```text
UDP app payload
  → MQP-3 frame (SINGLE / TRAIN / FRAG; one exact allocation per frame, handed to quinn)
  → quinn DATAGRAM frame (1 B type + 1–2 B varint len)
  → QUIC packet (short header: 1 flags + 8 DCID + 2 PN + 16 AEAD = 27 B)
  → UDP 8 B + IPv4 20 B (IPv6 +20 B)
```

Fixed cost (IPv4): **55 B per QUIC packet**; DATAGRAM budget = `max_datagram_size()` ≈ MTU − 38
(MTU 1200 → 1162 B; MTU 1400 → 1362 B; MTU 1472 → 1434 B).
When multiple `send_datagram()` calls are queued within the same transmit poll, quinn packs multiple DATAGRAM frames into the same
QUIC packet (`PROTOCOL_ANALYSIS.md` has confirmed with quinn-proto source; this repository uses quinn 0.11.12 / proto 0.11.19).
Therefore:

- **The main benefit of TRAIN is not "saving IP/UDP headers" (quinn already coalesces packets), but fewer MQP headers, fewer frame allocations, fewer quinn state locks/wakes**;
- **Packet count is determined by "send timing + quinn coalescing"**, not by the MQP frame format alone;
- Any table that "computes wire from payload" must state both bounds: "quinn coalescing effective / not effective".

### 1.2 Evidence grading (uniform throughout)

| Level | Meaning | Use cases in this document |
|---|---|---|
| **[L measured]** | Measured on Linux target machine | **No MQP-3 end-to-end Linux target-machine measurement exists in this repository**; the only performance-related Linux data is the narrow-scope container A/B in `8eebdca` |
| **[M measured]** | Measured on macOS development machine (loopback/microbenchmark) | frame_bench frame pool rejection table, BATCH N-pack prototype parity, u16 fragment id packet-loss cliff, sharded egress +16%, slow path +8.8% |
| **[Model]** | Source constants + wire arithmetic + single cost × frequency derivation | The vast majority of benefit numbers in this document (including the §0 table) |
| **[Code fact]** | Statically verifiable | Frame formats, constants, state machines, per-session task model |

**Conclusion: all "realizable benefits" in this document must be understood as direction and order of magnitude; before landing they must be re-measured on a Linux 2–4 core target machine with
`hotpath_bench` + `tc netem`; the macOS loopback numbers (the same harness showed three p50 values of 0.30/0.98/0.236 ms) cannot be used as a cross-version baseline.**

### 1.3 Rejected designs—do not bring them up again

From `05-evidence.md` (each has historical measurements/manual conclusions; new analyses must not double-count):

1. Frame buffer pool (`frame_bench`: same-thread +39–52%, cross-thread +128–324%, all slower);
2. Client BATCH N-pack (reverted after prototype parity; already covered by MQP-3 `PendingTrain`);
3. Server downlink BATCH / source-run flush (already superseded by v3 TRAIN mixed source);
4. Change `fragment id` back to u16 (historically at 1k/4k/21.8k payload/s there were 4%/15%/50% packet-loss cliffs);
5. Change the default MTU (1400→1360→1200 is settled; MTU is deployment configuration and does not enter the wire format);
6. fragment train (each fragment approaches MTU, packet count does not decrease);
7. FEC/NACK enabled by default (2 fragments +1 parity = +50% bytes; only opt-in);
8. Rewrite the protocol for bulk throughput (MQP header <1–3%);
9. Cross-session TRAIN **unconditionally** as a benefit item (must first measure quinn coalescing rate / send lock, otherwise count only 1–3%);
10. Assume domain-name targets already save 33–38% (HEAD domain names are inline in both directions; ACK/binding must be built first).

---

## 2. The real level of the current MQP-3

### 2.1 Production path

| Frame | On-wire layout | Steady-state header (IPv4) | Current use |
|---|---|---|---|
| `SINGLE 0x10` | `kind/flags \| sess u32 \| [flow u8] \| [addr] \| payload` | **5 B** (flow 0) / 6 B (extra flow) | A single item ≤512 B that cannot go into TRAIN; large packets fall back |
| `TRAIN 0x20` | `kind/flags \| sess u32 \| count u8 \| item*` | 6 B + 2 B per item for same flow, 3 B per item for different flows | Small packets in the same session and same drain burst |
| `FRAG 0x30` | `kind/flags \| sess u32 \| [flow u8] \| id u32 \| idx \| total \| [addr] \| chunk` | 11/12 B (codec implemented) | **Not wired**; production still uses MQP-2 `0x05` (11 B + full addr = 18/30/15+L B per fragment) |
| `CTL 0x40` | constants only | — | **No implementation** |

Key constants (`src/mqp/v3.rs`): `MQP3_MAX_FLOWS = 64`, `MQP3_MAX_TRAIN_ITEMS = 64`,
`MQP3_FLOW_TABLE_MAX_BYTES = 4096`, `MQP3_NO_FLOW = 0xff`.
Address lengths: IPv4 7 B, IPv6 19 B, domain name `4+L` (`src/mqp/addr.rs`).
flow ids are allocated monotonically and **never reused** during session lifetime; when the table is full, fall back to `NO_FLOW` inline.

### 2.2 Parts already done well (the refactor must not break them)

1. **Same-session small-packet frame aggregation is already close to the model's lower bound**: saturated 60 B uplink is already ~65.9 B wire/payload,
   **55.6 `try_send_datagram` calls/1000 payload** (the old document's "2-pack" conclusion is outdated).
2. **Zero-allocation hot path**: one exact-capacity `Vec` + `Bytes::from` per frame (exact-fit fast path);
   frame pooling has been rejected by measurement.
3. **Downlink mixed-source TRAIN**: multiple-target replies for the same session can be packed into one frame; downlink `run=1` sends SINGLE.
4. **Implicit ACK**: compress uplink only after receiving a compressed downlink frame, avoiding the first-frame loss black hole; this semantics should be retained in the new protocol.
5. **Security invariants**: per-frame SSRF/allowlist authorization, flow installed only after a real send succeeds,
   full-cone opt-in, protocol caps (8 KiB reassembly, 2 s partial, 256 KiB/connection).

### 2.3 The three "taxes" of the status quo

| # | Tax | Current cost | Root cause |
|---|---|---|---|
| T1 | per-frame `sess u32` | 4 B/frame; 4 B of the 5–6 B steady-state header | The data plane uses session as the first-class address |
| T2 | domain name/port change/full-cone always inline | `1+4+1+(4+L)+payload`; 40 B header when L=30 | The server flow table stores `TargetAddr::Domain`, `flow_for_ip` only matches IPs; the client has no resolved IP; no binding/ACK mechanism |
| T3 | `>512 B` falls out of v3 | v2 single frame 12/24 B header; fragmentation 18/30 B/fragment; each fragment has independent send/allocation | v3 FRAG codec not wired + 512 B fate-sharing cap |
| T4 | one TRAIN one session | with multiple associations each session gets its own frame | TRAIN header has a unique `sess`; stager/reader task is also per-session |
| T5 | no control plane | no CAPS/ACK/CLOSE; uplink-only flows re-inline across TRAIN; permanent degradation after 64 flows are used up; short sessions take 180 s to be reclaimed | Design was landed as "same-version deployment, no control plane" |

> Counterintuitive but important correction (`02-uplink.md` §0.5): an uplink-only flow is **not "address on every frame"**.
> `open_mask` lets only the first item of the same flow within the same TRAIN be inline, subsequent items are compressed; the real cost is
> "one inline open per TRAIN". Only at low rates (1 packet/burst) does it degrade to an address on every frame—
> this determines the benefit ordering of `FLOW_ACK`: sparse flows −6~−14%, high-rate flows only on the order of −2%.

---

## 3. The upper bound of improvement space: decomposed by layer

Decompose "the on-wire cost of one UDP payload" into 5 layers to clearly see which layer the protocol can touch and where the ceiling is:

| Layer | Cost | Can the protocol change it | Conclusion |
|---|---|---|---|
| L0 IP/UDP/QUIC packet | **55 B/packet** (IPv4) + 8/20 B IPv6 | **No** | When a small packet is a single frame it accounts for ~42% (60 B)~61% (28 B); can only be amortized via "multiple payloads per packet/frame aggregation/higher MTU" |
| L1 QUIC DATAGRAM frame | 2–3 B/frame | Yes (fewer frames) | TRAIN turns N frames into 1; same for cross-session aggregation |
| L2 MQP header | 5–6 B/frame; domain name +4+L; fragmentation 18–30 B/fragment | **Yes** (core of this document) | Steady-state lower bound ≈ 2 B (kind/flags 1 B + flow id 1 B); fragment lower bound ≈ 5–8 B |
| L3 Protocol semantics | per-frame sess, single-session TRAIN, no ACK/close, address repetition | **Yes** (requires incompatible wire) | domain name/one-way/multi-session/large packets/lifecycle |
| L4 Implementation/architecture | per-session socket/task/stager; 1 recv syscall + 1 wakeup per session; 1 MiB DATAGRAM buffer without fairness | Cannot be solved by wire alone | Connection-level stager/reactor is where CPU and fairness land |

**This yields three hard conclusions:**

1. **bulk has no protocol space.** A 1200 B payload under the MTU1200/IPv4 2-fragment scenario has an MQP header at 2.9% of payload
   (36/1236), v6 4.8% (60/1260); even reducing the steady-state header from 5 B to 2 B and the fragment header from 18 to 8,
   total wire only drops **1–3.5%**. Throughput is determined by QUIC CC/window/MTU/EDT.
2. **The protocol space for small packets/domain names/multi-session genuinely exists, but the ceiling is also limited.** Reducing the MQP header of a single 60 B frame from 5 B to 2 B,
   when it occupies a packet alone gives wire −2.5%; TRAIN has already reduced the per-item overhead of the same flow to 2 B/item, further optimization leaves only ~1 B/item.
   The largest single item is **the 4+L B of a domain-name address** (15 B when L=11, 34 B when L=30)—this requires the control plane/binding, not a simple frame format change.
3. **"Full duplex" is not a throughput multiplier.** QUIC has independent CC/PN/loss recovery in the two directions; the only real coupling on the transport side is
   the same driver task/state lock/core, reverse ACK bandwidth (0.6–2.9%), and a shared cwnd within the same direction.
   The benefit of full duplex is **inbound/server-initiated flows can be compressed, uplink-only can be compressed, bidirectional fair scheduling, acceptance-testable**
   (D1–D6, §4), not "100% bandwidth in each direction".

---

## 4. Full duplex: definition, current gaps, acceptance

### 4.1 Transport-layer fact: QUIC is already full duplex

- The two directions have independent packet number spaces, independent congestion control, independent loss detection/PTO/RTT;
- DATAGRAM can be sent in both directions; a QUIC connection is naturally bidirectionally concurrent;
- The only real cross-direction coupling is: the same connection driver task / state lock / same core,
  reverse ACK traffic (0.6–2.9% of bandwidth), and all flows within the same direction sharing one cwnd and one 1 MiB DATAGRAM buffer.
- Conclusion: **"implementing full duplex" is not changing the transport, but making MQP's state machine/control plane/scheduling symmetric**.

### 4.2 Recommended definition: MQP-3 full duplex = D1–D6

| No. | Definition | Current gap |
|---|---|---|
| **D1 data plane symmetry** | Any frame type (DATA/TRAIN/FRAG) can be sent in both directions; codec does not distinguish direction | The frame format itself is symmetric, but the downlink is constrained by "the flow must first be opened by the uplink"; full-cone/server-initiated flows have no compression path |
| **D2 state plane symmetry** | Each session maintains a flow table at each endpoint for "local send direction" and "local receive direction"; ids are allocated by the sender; both ends can open/close | The current flow table is **client unilateral ownership**, the server only mirrors; the server cannot create its own flow ids; the client's `confirmed` is a one-way bitmap |
| **D3 bidirectional control plane** | The control channel is available in both directions (recommended: one QUIC bidi stream), carrying CAPS/HELLO/FLOW_ACK/REJECT/CLOSE/SESS_CLOSE/priority queues/credits | **Completely missing** (`0x40` is just a reserved constant) |
| **D4 no direction dependency** | Either side can compress/acknowledge even when the peer has not yet sent payload in this direction (uplink-only flows are confirmed by FLOW_ACK; server push is opened by the server-half id) | Uplink-only flows re-inline across TRAIN; the server cannot push; domain names are always inline |
| **D5 independent scheduling** | Each direction independently performs TRAIN packing, MTU budget, priority/weighted scheduling; cross-direction coupling may only share the connection/CC, not share state that "must wait for the peer" | Downlink per-session stager cannot cross sessions; the 1 MiB DATAGRAM buffer is FIFO without fairness, one high-rate flow can cause other sessions on the same connection to be dropped as `Blocked` |
| **D6 testable** | New `udpbidir` benchmark: run both directions simultaneously, acceptance "bidirectional total ≥1.6× unidirectional, p99 degradation ≤10%, no silent packet loss" | The current harness has no bidirectional mode |

### 4.3 The benefit boundary of full duplex

- **Not**: doubling bulk throughput; replacing reliability; making each direction occupy 100% of bandwidth.
- **Is**: inbound/server-initiated flows (full-cone, P2P, push) can be compressed (model −4~−18% small-packet wire,
  more pronounced for v6); uplink-only flows can be compressed (sparse −5.9% v4 / −12.1% v6); multi-session fair scheduling;
  lifecycle control; testable symmetry.
- The benefits of transport coupling (same-threading/per-connection aggregation) belong to CPU/tail-latency items: model −3~−15% CPU
  (`04-transport.md`), not a bandwidth item.

---

## 5. The refactored MQP-3 (wire rev2) design

> **Implementation revision (2026-10-21)**: The formal implementation contract has been landed in [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md), and the codec is implemented in `src/mqp/r2.rs`. To let old v2/v3 parsers safely discard rev2 frames, the actual first byte is changed to `0x0X` (high 4 bits = 0, and avoiding 0x02/0x05/0x06), no longer using `0x1X/0x2X/...`; flow id is changed to **connection-level u32 monotonic, no reuse** (completely eliminating u16 reuse/tombstone risk); the `TRAIN dict` header is `4 B + nfl × idvarint`. The frame table below is retained as design background; where conflicts exist, the SPEC prevails.

> This section is the landing specification for "candidate B: connection-level flow namespace + symmetric bidirectional ownership + complete CTL plane".
> Candidate A (incremental scheme retaining `sess u32`) is compared as a low-risk subset in §5.11; candidate C (u16 sess compromise) has been rejected.

### 5.1 Goals and non-goals

**Goals**
1. Steady-state data frame header close to the lower bound: **2–3 B** (no `sess`, flow id LEB128 1–2 B);
2. One DATAGRAM can carry payloads of **different sessions/flows** (TRAIN dict mode);
3. Domain-name targets, port-changing sources, full-cone sources are compressible in both directions;
4. Uplink-only/one-way flows can enter the compressed state via ACK, without depending on the peer sending data;
5. Large packets and fragmentation uniformly enter v3 (no more v2 data plane / 512 B truncation);
6. Control plane: version gating, explicit ACK/REJECT/CLOSE, session lifecycle;
7. Security/resource boundaries no weaker than the status quo; the name is still MQP-3.

**Non-goals**
- Don't change TCP (QUIC stream);
- Don't change DATAGRAM unreliable semantics;
- Don't introduce FEC/retransmission by default;
- Don't change for bulk throughput (see §6.5);
- Don't introduce an HPACK-style dynamic dictionary (flow binding is sufficient);
- Don't do fragment train (packet count does not decrease when fragments approach MTU).

### 5.2 Naming and version gating

- The protocol is still externally called **MQP-3**; MQP-4 does not appear in the data plane/documents/logs.
- Control plane `HELLO`/`CAPS` carries `wire_ver=2`; **mismatch → close the connection and give a clear error code** (same-version deployment).
- The default ALPN remains `h3` (camouflage feature); deployments needing a hard gate may use ALPN `myquic2/3`.
- Old clients / old servers: a new server receiving old v3 frames may retain one version of read-only decoding for diagnostics; when a new client connects to an old server,
  HELLO gets no response → timeout failure (no silent downgrade, because the wire is already incompatible). **This refactor does not promise mixed-version operation.**

### 5.3 Naming model: connection-level flow id + symmetric halves

```text
connection (QUIC)
 ├── session (UDP association; the full u32 id appears only in open/CTL)
 │    └── flow = (session, target, direction ownership)
 │          ├── client-owned id: 0x0001..0x7FFE   (allocated by client, mirrored by server)
 │          └── server-owned id: 0x8001..0xFFFE   (allocated by server, mirrored by client)
 └── flow id 0x0000 = inline/no-flow (table full, one-shot source, diagnostics)
```

- **id encoding**: u16 values use LEB128; common active ids <128 → **1 B**; the `HI` flag indicates the server half,
  on decode `id |= 0x8000` (actually encoding `id-0x8000`, still 1 B).
- **Two halves** let both ends independently open/close without coordinating id allocation; `0x7FFF`/`0xFFFF` are reserved.
- **open frame self-describing**: `OPEN` flag + `sess u32` + `addr`. The first frame is still inline (no extra first-packet RTT),
  repeated open is idempotent; same id with different `(sess,addr)` → discard and count (prevent cross-flow leakage).
- **Confirmation**: a compressed frame in either direction implicitly confirms (receipt proves the peer has installed the mapping); uplink-only/one-way is explicitly confirmed by control plane
  `FLOW_ACK`; `FLOW_REJECT` indicates policy/table full/DNS failure, and the client falls back to inline.
- **Close/reuse**: after `FLOW_CLOSE` the id enters tombstone, **≥3 s** (= 2×FRAG_TIMEOUT + sweep,
  same argument as `FRAG_ID_SAFE_WINDOW_MS`) before reuse; when ids are exhausted fall back to `DATA INLINE`.
- **Table limits**: per connection `max_conn_flows` (recommended 4096, CAPS negotiated) + per session 64 (or negotiated value);
  over limit go inline/REJECT; memory is charged by admission (the current 4 KiB/session accounting model must be updated in sync).

### 5.4 Data frames (same set in both directions)

First byte: high 4 bits kind, low 4 bits flags. **Data frames no longer carry `sess`** (`sess` only in OPEN/CTL).

| Frame | Layout | Steady-state header | open header (IPv4/IPv6/domain) | Notes |
|---|---|---|---:|---|
| `DATA 0x10` | `0x1X \| idvarint \| [sess u32 + addr if OPEN] \| payload` | **2 B** (id≤127)/3/4 | 13 / 25 / 40 | no length field, payload = remaining DATAGRAM |
| `DATA INLINE 0x12` | `0x12 \| sess u32 \| addr \| payload` | — | 12 / 24 / 39 | table full/one-shot source fail-safe, ≈v2 single frame |
| `TRAIN same 0x21` | `0x21 \| count u8 \| idvarint \| item*`; item = `len varint \| payload` | header **3 B** (id≤127; 2 B id gives 4 B); item **1–2 B** | — | whole frame same flow, all compressed; lower-bound form for small packets |
| `TRAIN dict 0x22` | `0x22 \| count u8 \| nfl u8 \| idvarint[nfl] \| item*`; item = `idx u8 \| len varint \| payload` | header **3+nfl** (id≤127); item **2–3 B** | — | mixed flows; **items may span sessions** (flow→session in the table) |
| `FRAG 0x30` | `0x3X \| idvarint \| frag_id u32 \| idx u8 \| total u8 \| [sess u32 + addr if OPEN] \| chunk` | **8 B** (id≤127), open first fragment 19/31/46 | — | key = `(flow, frag_id)`; reassembly caps follow the status quo |

**Key behaviors**
- `TRAIN same` is a first-class citizen: for a 60 B payload `3 + N×(1+60)`, vs the status quo `6 + N×(2+60)` saves 1 B per item,
  and 2 B on the frame header; this covers the mainstream "single-flow high pps" scenario.
- The header of `TRAIN dict` contains a **flow dictionary** (`3+nfl` bytes, nfl ids), items reference it with a 1 B idx; saves 1 B/item over "id per item",
  suitable for 8–32 flow fan-out; when spanning sessions, the session is resolved from the flow table.
- The byte count of the first OPEN frame is the same as the current inline (v4 13 B / v6 25 B / domain from 40 B), **no first-packet penalty**.
- The decoder must validate before parsing: frame length ≤ `max_datagram_size()`, id within the negotiated range, count ≤ the negotiated limit,
  each item len ≤ min(8192, remaining), TRAIN consumes exactly to the end of the frame, unknown kind/opcode/reserved flags → count and discard without panic.
- **Not adopted**: 1 B short header (B′), `sess u24`, 12/20-bit bit-packing—all are <1 B/frame cosmetic;
  kind space is reserved, re-evaluate in Phase 3.

### 5.5 Control plane (one QUIC bidi stream)

| opcode | Direction | Content | Semantics |
|---|---|---|---|
| `0x01 HELLO` | C→S | magic `M3` + `wire_ver u16` + flags | send immediately after connection establishment; mismatch → close |
| `0x02 CAPS` | S→C | ver + flags + max_conn_flows + max_flows/session + max_train_items + max_reassembly + capability bits | server capabilities; may be resent |
| `0x10 FLOW_ACK` | both | `sess u32 \| id \| status \| [resolved addr]` | install success/uplink-only confirmation/domain resolution result |
| `0x11 FLOW_REJECT` | both | `sess u32 \| id \| reason` | policy rejection/table full/DNS failure; client falls back to inline |
| `0x12 FLOW_CLOSE` | both | `sess u32 \| id` | release flow, enter tombstone window |
| `0x20 SESS_CLOSE` | both | `sess u32 \| reason` | immediately release server socket/task/flow table/permit |
| `0x30 PING` | both | timestamp/sequence | optional, can be omitted when QUIC keepalive is sufficient |

- **Reliability**: over a QUIC stream, QUIC handles retransmission/ordering; the control plane does not need a custom ACK state machine;
- **Idempotent**: all opcodes may be repeated; unknown opcodes skip that frame (length-prefixed), no panic;
- **Bounded**: single frame ≤ 512 B, rate/total volume on the stream limited, length validation before parsing; the control stream is **untrusted input**;
- **Ordering with the data plane**: the control stream and DATAGRAM are ordered independently of each other; therefore **the first data frame must be self-describing** (OPEN),
  and must not rely on "receive OPEN before DATA". This preserves the existing safety semantics of "first frame inline, subsequent compressed".
- **Why not use DATAGRAM for the control plane**: would require implementing retransmission/dedup/ordering yourself; control frames are low-frequency, small, and idempotent,
  one bidi stream is the least troublesome and most reliable. If future "control plane also unreliable" is desired, CTL DATAGRAM can be added as a hint,
  but correctness does not depend on it.

### 5.6 Compression and confirmation: bidirectional binding semantics (the most important behavior change of this design)

The existing implicit ACK only covers flows "with downlink data". rev2 makes "binding" bidirectionally symmetric:

```text
Uplink (client→server, domain-name target as example)
  C --DATA OPEN(sess, flow=5, domain, payload)--> S     # first frame inline, 0 extra bytes vs today
  S: parse/SSRF/create session socket/send; install flow->(session, domain, resolved_ip)
  S --CTL FLOW_ACK(sess, 5, [resolved_ip])-----> C     # uplink-only is also confirmed; domain-name carries the resolution result
  C: enter compressed state
  C --DATA(flow=5, payload)-------------------> S     # 2 B header
  S: reply source == resolved_ip? yes→compress; no→first-frame inline binding (see below)

Downlink (server→client, domain name/port change/full-cone as example)
  S --DATA(flow=5, INLINE actual_src)---------> C     # same 13 B as today's NO_FLOW inline, 0 cost
  C: record flow->reply_src (this is the address written into the SOCKS5 reply header, behavior same as today)
  C --DATA(flow=5, payload)-------------------> S     # the client's next compressed uplink frame = implicit ACK
  S: switch to compressed; source drift (multiple A/anycast/port change) → resend one INLINE binding frame, fall back to BindPending
```

- **Domain-name replies**: the client uses **the actual source IP of the first inline reply** to write the SOCKS5 reply header—**does not change existing behavior**,
  no need for the controversial semantics of "echoing the domain name back to the app"; `FLOW_ACK.resolved_ip` is only used for **uplink** compression/prediction,
  not to replace the actual source.
- The **`SRC` flag** is formally enabled in the new protocol: the inline address is "actual source", not the flow-bound target; used for port changes/anycast.
- **Binding frame loss**: degrades to today's inline (no black hole); the binding table has a TTL and is refreshed with the source.
- **Security**: binding/compression only changes "how the source address is expressed", **does not expand reachable targets**; per-reply authorization still goes through
  the allowlist ring + exact flow fallback; `udp_full_cone` is still opt-in; server-owned flows are created only in
  full-cone mode and are counted in unsolicited statistics.
- **Uplink-only flows**: compressed after `FLOW_ACK`; ACK loss only delays compression (the client keeps inline),
  correctness never depends on ACK arrival—consistent with the conservatism of the existing implicit ACK.

### 5.7 Large packets and fragmentation: unified into v3, remove the v2 data plane

- `DATA` single frame can carry up to `max_datagram_size()`; **513 B up to the single-frame limit** no longer falls back to v2 (saves 7/22 B/frame).
- Exceeding a single frame → `FRAG` (8 B header, no repeated address in steady state); key = `(flow, frag_id)`;
  retain u32 frag id (historical u16 packet-loss cliff), 8 KiB payload cap, 2 s partial, 256 KiB/connection budget.
- The first fragment/the first few fragments of a new flow may carry `OPEN` (inline addr), ensuring reassembly even if the flow is not confirmed; afterwards compressed.
- **The 512 B fate-sharing cap is renegotiated**: the new protocol no longer needs the protocol-layer truncation of "≤512 B to enter v3";
  but the fate-sharing risk that "loss of one TRAIN/packet loses multiple payloads at once" remains, and should be controlled by
  `max_train_items`/`max_frame_bytes` policy, not hardcoded 512. Recommendation: interactive class default
  `max_train_items=16`, bulk class may negotiate larger; cross-session frame aggregation is enabled by default only for the bulk class.
- The v2 decoder is retained for one version for diagnostics/large-packet compatibility (not needed; wire incompatible), but **there is no longer a v2 send path**.

### 5.8 Session lifecycle and resource accounting

| Item | Status quo | rev2 |
|---|---|---|
| Short session reclamation | 180 s idle (`SESS_IDLE_MS`) | `SESS_CLOSE` immediately releases socket/task/flow table/permit; idle is only a fallback |
| flow release/reuse | ids never reused; permanent inline after 64 full | `FLOW_CLOSE` + 3 s tombstone then reuse; table full `REJECT` fallback inline |
| churn cap | >45 association/s may exhaust the 8192 pool (268 KiB/session accounting) | after explicit close no more zombie accumulation; admission accounting updated with table limits/connection-level table |
| cross-session | cannot aggregate frames | `TRAIN dict` can mix (optional, Phase 2) |
| per-connection fairness | 1 MiB DATAGRAM buffer FIFO, no fairness | connection-level stager + per-session/flow quota (DRR) or priority classes |

### 5.9 Security and resource invariants (any implementation must preserve)

1. **Per-item authorization unchanged**: cross-session/cross-flow frame aggregation is only a loading method; each item must have passed
   the existing source authorization (allowlist ring or exact flow fallback) **before** entering the stager.
2. **SSRF unchanged**: target filtering only happens on uplink/resolution; downlink compression only changes "how the source address is expressed"; `allow_private` semantics unchanged.
3. **flow installation condition unchanged**: install only after "the target accepted a real send" (`accepted` condition).
4. **Connection-level ids must not be resolved across sessions**: a flow table entry must carry the session; client/server must look up each item's flow
   in its own table by that item's flow; resolving an A-session id to B's source is forbidden.
5. **full-cone still opt-in**: server-owned flows are created only under full-cone; unsolicited statistics retained.
6. **Untrusted input**: all length/range validation before parsing control streams/data frames; unknown kind/opcode discarded without panic;
   the control stream has rate/total caps; tables are bounded and charged to admission.
7. **id reuse safety window**: can only be reused ≥3 s after FLOW_CLOSE; the tombstone covers the reassembly window; exhaustion falls back to inline.
8. **No new memory amplifiers**: connection-level flow tables/control stream buffers must have hard caps and be included in `max_peer_memory_mb` accounting.

### 5.10 Optional and follow-up (Phase 2/3)

- **Connection-level egress stager (uplink + downlink)**: one send queue/aggregator per connection; session readers/assoc push items
  in, the aggregator frames by path budget, aggregates across sessions, and schedules by session quota. **This is where cross-session TRAIN and
  D5 fairness land**; benefit depends on the quinn coalescing rate measured in Phase 0 (non-coalescing bound −34%~−61%, ideal coalescing bound −1.6%);
  CPU model server −11~−14%, 50k pps ≈1% of a single core. **Measure first, then decide whether to roll out fully.**
- **server-owned flow / full-cone**: when the server first sees an unsolicited source, it uses a server-half id + inline binding;
  afterwards compression (model −37% for that scenario). Only allowed when `udp_full_cone=true`.
- **B′ 1 B short header**: kind space reserved `0x50..0x5F` to denote "the most recent 16 hot flows", steady state 1 B;
  benefit −1.6% at 60 B, −3.3% at 28 B; cosmetic, Phase 3.
- **Negotiable reassembly cap** (CAPS) and **FEC/NACK opt-in**: decide only by measurement on lossy links, do not make default.
- **Single-flow striping/multiple connections**: study only for "single large flow + high loss/high RTT", high risk, do not mix into the protocol core.

### 5.11 Candidate A / B / C comparison

| Dimension | A: incremental retaining `sess u32` | **B: connection-level flow id (recommended)** | C: u16 sess compromise (rejected) |
|---|---|---|---|
| Steady-state header | 5/6 → 5/6 (only CTL/FRAG/large packets change) | **2–3 B** | 3/4 B (wrap risk) |
| Domain name/uplink-only compression | ✅ (requires FLOW_ACK/binding) | ✅ | ✅ |
| Large packets/compact FRAG | ✅ | ✅ | ✅ |
| Cross-session TRAIN | ❌ | ✅ (dict) | partial (MULTI_SESS) |
| Server-initiated flow (D2/D4) | ❌ | ✅ (halves) | ❌ |
| Full duplex D1–D6 | partial | ✅ | partial |
| Engineering/risk | low (incremental) | medium-high (new namespace/table/control plane) | high (id wrap + cross-association leakage risk) |
| Role | low-risk subset/fallback | **target architecture** | not doing |

Candidate C rejection rationale (`01-wire.md` §6.3): client session ids are monotonic u32, and the server reclaims via 180 s idle;
shrinking to u16 wraps after 65,536 allocations, and >364 assoc/s may cause a new association to get an id the server still considers belonging to the old
association → reply cross-flow leakage. The benefit is only 2 B/frame, not worth it.

---

## 6. Benefit quantification

### 6.1 Uniform assumptions (model)

- IPv4; MTU 1200 → DATAGRAM budget 1162 B (1362 also listed);
- 55 B fixed per packet, 2–3 B per DATAGRAM frame;
- one QUIC packet carries one MQP frame, unless noted "quinn coalescing/connection-level stager";
- no packet loss, no ACK-only packets, no PMTU jitter; no FEC;
- "send calls/1000" = number of `try_send_datagram`; the TCP row is the number of `write_chunk`.
- Detailed formulas and assumptions: §6.1 (the reproducible model script and the per-topic cross-validation notes are not shipped separately).

### 6.2 Per-workload benefits

| Workload | Status quo | rev2 | Change | Attribution |
|---|---:|---:|---:|---|
| DNS domain query L=11, 50 B, 1/burst | 129 B/payload | 109 B | **−15.5%** | domain ACK + compression (100% from address/flow/sess bytes) |
| Domain L=30, 60 B uplink (wire report basis) | 97,564 B/1000 | 61,189 B/1000 | **−37.3%** | same as above; header 40 B→2 B |
| Domain-name target downlink reply (after first-frame binding) | 13 B header | 5–6 B | **v4 −7~−8 B, v6 −19~−20 B/reply** (wire report basis: per 1000 payload v4 −12.8%, v6 −25.7%) | binding + compression; small-packet frame body −7~−38% |
| Uplink-only sparse 100 B (IPv4 / IPv6) | 170 / 182 B | 160 B | **−5.9% / −12.1%** | FLOW_ACK; v6 address is more expensive |
| Uplink-only sparse 60 B (wire report) | 72,000 B/1000 | 62,000 B/1000 | **−13.9%** | same as above + 2 B steady-state header |
| High-rate same-flow 60 B (TRAIN 18 items) | 65.9 B/payload, 55.6 calls | 64.2 B, 52.6 calls | −2.7% / −5.4% | frame header 2 B + item 1 B + elimination of first-item inline |
| 8-flow same-session fan-out 200 B | 226 B | 218 B | −3.5% | COMPACT item/frame header |
| 32 sessions × 60 B (1 packet/session/burst) | 71.4 B, 1000 calls | 65.8 B, 62.5 calls | **−8.0% / −93.8%** | conditional: requires connection-level stager + quinn coalescing; worst case status quo 123 B/payload |
| VPN/bulk UDP 1200 B @MTU1200 (2 fragments) | 1352 B | 1325 B | −2.0% | compact FRAG 8 B vs 18 B/fragment |
| Same @MTU1400 (1 frame, configuration) | 1270 B | 1260 B | −0.8% | protocol; MTU configuration itself gives another −6.1% |
| bulk TCP 16 KiB chunk | 17,299 B | 17,299 B | **0** | no MQP header on the stream |
| full-cone downlink 60 B (server-originated) | 97,564 B/1000 | 61,328 B/1000 | **−37.1%** | server-half id + binding |
| Short session churn (>45 assoc/s) | 180 s zombies ×268 KiB | reclaimed immediately | memory/fd/tasks deterministically decrease | SESS_CLOSE |

> The percentages in the table are the MQP incremental byte savings "for that workload class", not end-to-end application throughput improvement.
> For bulk, end-to-end improvement mainly comes from MTU/window/topology (10–30%), MQP protocol ≤2%.

### 6.3 CPU / send calls / latency

| Item | Order of magnitude | Notes |
|---|---|---|
| Same-association small packets | status quo already 55.6 calls/1000; rev2 52.6 | protocol saves only ~5% more calls |
| Multiple associations (32 sessions) | 1000 → 62.5 calls/1000 (**−94%**) | connection-level stager; server CPU model −11~−14%, 50k pps ≈1% of a single core |
| Domain ACK | does not reduce calls | only changes wire |
| Same-threading (F10, implementation) | 0.1–0.3 µs/frame → 40–50k pps **0.5–1.5% of a single core** + tail latency | no wire change; decide after Linux `MYQUIC2_SHARD_RUNTIME=0` A/B |
| Connection-level stager added cost | enqueue/dequeue ~0.04–0.08 µs/item | requires "send as soon as drained", must not introduce artificial waiting; interactive class does not aggregate across sessions by default |
| Latency | TRAIN/binding do not add waiting; fate-sharing makes one packet loss correlate across sessions | interactive class can be configured "do not participate in cross-session aggregation"; p99 acceptance see §7 |

### 6.4 fate-sharing / packet-loss semantics (must be explicitly accepted)

- Loss of one TRAIN/QUIC packet loses N payloads at once: **expected loss rate unchanged** (N items per packet, packet count 1/N),
  but **correlated across flows in time** (one qdisc drop hits multiple sessions/flows at once).
- No impact for DNS/one-shot requests; for RTP/game/interactive flows, recommend:
  - interactive class default `max_train_items` small (16), does not participate in cross-session frame aggregation;
  - bulk class may aggregate across sessions;
  - provide a configuration switch (by flow/port classification), and accept p99 under `udpbidir`/`netem`.
- This also addresses the repository's existing concern about BATCH "fate-sharing": **expectation unchanged, burst-correlated, must be configurable**.

### 6.5 Reality check: where "substantial" is possible, where not

| Goal | What protocol refactor can give | The real big head |
|---|---:|---|
| bulk TCP/UDP throughput | ≤1–2% | MTU (1200→1400: VPN −6.1%, frame count 2→1), window/BDP, same-threading, loss recovery; single-flow ceiling can only be raised with multiple connections |
| Domain name/DNS-over-SOCKS | **−15~−38% wire** | already at that model's ceiling; what remains is control-plane/semantic work |
| Constrained uplink small packets | −2~−14% (depends on burst shape) | part already captured by TRAIN; domain name/one-way is new |
| Multi-association small packets | −8~−18% wire + 94% calls (conditional) | connection-level stager; quinn coalescing rate determines where wire lands |
| Per-core pps / CPU | 1–5% (50–100k pps) | same-threading/thread topology/GSO (transport/implementation) |
| Tail latency/fairness | improvement (stager scheduling/quota) | reactor-ization (I5) is needed to eliminate per-reply wakeups |
| Lifecycle/memory | deterministic fix of churn and 64-flow degradation | admission/table caps |

**If the user's "substantial" = doubling bulk throughput: the answer is "protocol refactor cannot do it"; turn to transport/multiple connections/MTU.**
**If "substantial" = wire/calls/resources for specific workloads: domain-name class 15–38%, multi-session 8–18%+94%, full-duplex inbound 4–18%, these are real.**

---

## 7. Implementation path (phased, name always MQP-3)

### Phase 0: no wire change, measure first + capture transport/config gains (1–2 week scale)

1. **Add measurements** (prerequisite for all protocol acceptance):
   - `try_send_datagram` frame count/direction; QUIC packet count (tcpdump/qlog); per-connection frame/packet ratio (determines cross-session benefit);
   - MQP frame-level counters: kind, TRAIN items, flow compression ratio, inline fallback ratio, FLOW_REJECT ratio;
   - quinn `stats()`: cwnd/rtt/current_mtu/PLPMTU probing/loss;
   - add `udpfanout` (1 association × N destination rotation) and `udpbidir` (both directions simultaneously).
2. **Transport/config** (non-protocol, largest benefit and low risk):
   - set `initial_mtu=1360/1400` per deployment for known paths (keep the default 1200 unchanged, to avoid black holes on unknown paths);
   - verify window/BDP presets (4/8/4 default vs 8/16/8);
   - fix server-side per-class transport asymmetry (the server currently only has the interactive preset);
   - decide after `MYQUIC2_SHARD_RUNTIME=0` A/B + thread topology (F10/F3) measured on Linux 2–4 cores.
3. **Implementation-layer low-risk items**: `last_flow` multi-slot memo/reuse flow id at the authorization stage, run==1 avoiding arena copy,
   >512 B direct v3 SINGLE (first verify within the compatible format).
4. **Acceptance**: Linux 2–4 cores + `tc netem` (70/140 ms, 0/0.5/2% loss) baseline; same machine same round A/B.

### Phase 1: wire rev2 core (incompatible; still named MQP-3)

1. Control plane bidi stream: `HELLO/CAPS` (wire_ver=2) + `FLOW_ACK/REJECT/CLOSE/SESS_CLOSE`;
2. Connection-level flow id (u16, client/server halves) + `DATA`/`TRAIN`/`FRAG` without `sess`;
3. Full-size v3 (remove the v2 send plane) + compact FRAG wiring + `(flow, frag_id)` reassembly key;
4. Domain name/port change/full-cone binding + bidirectional implicit ACK + uplink-only `FLOW_ACK`;
5. flow close/reuse (3 s tombstone), table limits, admission accounting update;
6. Naming: code/documents/logs all still call it MQP-3; `CAPS.wire_ver=2` is only an internal version.

**Acceptance thresholds (model targets, require Linux measurement)**:
- `udpdomain` domain-name class wire **−15% or more** (L=11) / **−30% or more** (L=30);
- `udppaced` (1–512 B) p99 no regression >5%, loss does not increase;
- `udpsweep` full size (including 8 KiB fragmentation) correct;
- uplink-only sparse flow wire −5% or more (v6 −10% or more);
- churn stress test: after `SESS_CLOSE` the 8192 pool is not exhausted by zombies; 64-flow degradation is recoverable.

### Phase 2: structure/full duplex (dependent on Phase 0/1 measurements)

1. Connection-level stager (uplink + downlink): cross-session `TRAIN dict`, per-session quota/DRR, flush policy "send as soon as drained";
2. server-owned flow / full-cone compression;
3. per-flow priority/credit (optional, solves the lack of fairness in the 1 MiB DATAGRAM buffer);
4. `udpbidir` acceptance: bidirectional total ≥1.6× unidirectional, p99 degradation ≤10%, no silent packet loss;
5. Multi-session goal: frames/calls/allocations **−90% or more** (32 sessions); wire −8~−34% depending on quinn coalescing rate.

### Phase 3: optional

- B′ 1 B short header (kind space already reserved);
- CAPS negotiated larger reassembly cap;
- FEC/NACK opt-in (decide only by netem measurement);
- Single-flow striping/multiple connection research (high risk, not mixed into the protocol core).

### Migration and rollback

- **Same-version deployment**: the protocol does not promise coexistence with v0.2.0 peers; `HELLO/CAPS` mismatch closes with an error (fail-fast),
  no silent downgrade.
- Default ALPN remains `h3`; deployments needing a hard gate may explicitly bump ALPN (optional, does not affect camouflage default).
- Each Phase has an independent feature/build switch; before Phase 1, land Phase 0's baseline and counters, ensuring every step can be A/B.

---

## 8. Risks, counterarguments, and unresolved evidence

### 8.1 Risks

| Risk | Description | Mitigation |
|---|---|---|
| **No Linux target-machine measurement** | all benefits are models; macOS loopback cannot be extrapolated (GSO/GRO/pin all differ) | Phase 0 builds the Linux + netem baseline first; each change same machine same round A/B |
| Control plane complexity | bidi stream, state machine, version gating, failure paths | control frames idempotent; correctness does not depend on ACK arrival; control stream bounded, untrusted input |
| Domain name/SOCKS semantics | multiple A/anycast/port drift; which IP to use in the reply header | use "the actual source of the first inline reply" to write the SOCKS header (keep status quo); resolved IP only for uplink compression; source drift rebinds |
| fate-sharing | cross-session frame aggregation makes packet loss correlated across flows | interactive class does not participate/small `max_train_items`; only bulk class enables; netem acceptance for p99 |
| Connection-level table memory/attack surface | 4096 flow table per connection | CAPS negotiated limit + admission accounting + pre-parse validation + unknown id discard |
| id reuse cross-flow leakage | reuse after close may splice old delayed frames onto a new flow | 3 s tombstone (covers reassembly window); exhaustion falls back to inline |
| quinn limits | no per-flow scheduling, 1 MiB DATAGRAM buffer FIFO | connection-level stager/quota in the application layer; do not change quinn |
| Benefits overestimated | the old document's 2-pack baseline and −18× calls are outdated | this report uses HEAD actual behavior; all numbers marked [Model], two coalescing bounds given |
| Version camouflage | default ALPN `h3` conflicts with hard wire gating | in-band HELLO/CAPS; ALPN bump only when fail-closed is required |

### 8.2 Counterarguments (must be answered directly)

1. **"quinn already coalesces packets, TRAIN/cross-session is meaningless"**: true for **packet count**; still meaningful for MQP headers, frame allocations,
   quinn state locks/wakeups, and the coalescing-failure scenarios of low-rate multi-session (see §6.3/§6.5).
   But **the wire benefit of cross-session must be determined by Phase 0's frame/packet ratio measurement**, it cannot be assumed upfront.
2. **"Full duplex is just a concept, QUIC is already bidirectional"**: correct at the transport layer; incorrect at the protocol layer—uplink-only cannot be compressed,
   the server cannot push, TRAIN cannot cross sessions, there is no control plane. D1–D6 are implementable symmetries, not marketing words.
3. **"The refactor can substantially improve throughput"**: it cannot. bulk header <1–3%, refactor ≤2%; the real 10–30% is in MTU/window/topology/loss.
4. **"Using DATAGRAM for the control plane is simpler"**: would require implementing retransmission/dedup yourself; control frames are low-frequency, small, and idempotent, a QUIC stream is more reliable.
   If tail latency is a concern, "non-essential hints" can go in DATAGRAM, but the correctness path goes over the stream.
5. **"Domain-name compression changes app behavior"**: it does not—downlink still uses the actual source IP to write the SOCKS reply header;
   only the uplink address changes from inline to flow id, invisible to the app.
6. **"Just remove the 512 B cap"**: removing truncation alone can reduce the v2 12 B header of 513–1150 B to 5–6 B,
   but the real big head is the domain name (4+L B) and per-frame `sess`; and fate-sharing must be redesigned.

### 8.3 Questions not yet answered / requiring evidence

- quinn's real coalescing rate (frame/packet ratio) under "multiple sessions, low rate"—determines where cross-session benefit lands;
- on a Linux 2–4 core target machine, whether send state locks/cross-core wakeups are really the bottleneck (determines F10/connection-level stager priority);
- the real proportion of domain-name targets, >64 flow long connections, and multiple associations in production traffic;
- the integration cost of a control stream bidi with the existing auth uni stream;
- the MTU distribution (1200/1400/1472) and packet loss rate of the target environment (determines FEC/MTU benefit).

---

## 9. Final recommendations and questions requiring decision

### 9.1 Recommendations

1. **Do not treat "refactoring the protocol" as bulk throughput optimization**; for bulk do Phase 0's MTU/window/topology first.
2. **If the goal includes domain name/DNS, constrained uplink, multiple associations, VPN small packets, inbound/server-initiated flows**:
   do **MQP-3 wire rev2 (candidate B)**, landing Phase 1→2; expectation is
   **domain-name class −15~−38% wire, uplink-only −6~−14%, multi-session −8~−18% wire + ~94% fewer sends,
   full-duplex inbound −4~−18% small-packet wire**, not orders-of-magnitude throughput.
3. **If only low-risk benefit is wanted**: do the **candidate A subset** first (retain `sess u32`: FLOW_ACK/domain-name binding +
   full-size v3 + compact FRAG + SESS_CLOSE/FLOW_CLOSE), which captures most of the byte/lifecycle benefit,
   but without "true full duplex/cross-session".
4. **Whichever is chosen, Phase 0's measurement and transport configuration should be done first**; without a Linux baseline, any "substantial" claim is not acceptable.
5. **Naming/compatibility**: the new wire is still called MQP-3; `CAPS.wire_ver=2` gates it; give up coexistence with v0.2.0 peers
   (the user has allowed it); do not introduce the string "MQP-4".

### 9.2 Questions requiring the user's decision

1. **Objective function ordering**: constrained uplink bandwidth (wire) / per-core pps/CPU / tail latency—determines whether to do domain-name ACK,
   connection-level stager, or same-threading first.
2. **Is same-version deployment acceptable** (completely giving up coexistence with v0.2.0 peers)? If mixed versions are required, additional ALPN/dual-stack
   release engineering is needed, with unchanged benefit and significantly increased complexity.
3. **Can the control plane use one QUIC bidi stream** (rather than DATAGRAM)? This is the decision with the largest implementation complexity difference.
4. **Domain-name reply SOCKS5 semantics**: confirm that "the actual source IP of the first inline reply" can continue to be used (does not change app behavior),
   and the rebinding strategy under multiple A/anycast/port drift.
5. **Whether server-initiated/full-cone flows should get first-class compression** (determines whether to keep the server-half id).
6. **Target hardware and MTU distribution**: Linux 2–4 core ARM router vs x86 exit? Known path MTU 1200/1400/1472?
7. **Acceptance definition of "substantial"**: domain-name class −30% wire, multi-session −90% calls, or doubling bulk throughput?
   The first two are doable; the third should not be promised by a protocol refactor.

---

## Appendix A: New frame byte examples (rev2 actual implementation, goldens from `src/mqp/r2.rs`)

> First byte fixed `0x0X` (high 4 bits=0, avoiding 0x02/0x05/0x06), old v2/v3 parsers will safely discard; flow id is
> connection-level u32 monotonic no reuse (`wire_id = local<<1 | owner`). Full specification see [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md).

```text
DATA steady wire_id=5, payload "abc":
  00 05 61 62 63                                   ; 2 B header
DATA open wire_id=5, sess=7, 192.0.2.1:53, "abc":
  01 01 05 07 00 00 00 01 C0 00 02 01 00 35 61 62 63   ; 14 B header
DATA inline (no flow), sess=7, 192.0.2.1:53, "z":
  01 02 07 00 00 00 01 C0 00 02 01 00 35 7A        ; 13 B header
TRAIN same wire_id=5, "abc"+"de":
  04 00 02 05 03 61 62 63 02 64 65                 ; 3 B header + id
TRAIN dict flows 5,9, items(0=abc,1=de):
  04 01 02 02 05 09 00 03 61 62 63 01 02 64 65     ; 4 B header + 2 ids
FRAG steady wire_id=5, frag_id=0x12345678, idx=1/3, "abc":
  08 05 78 56 34 12 01 03 61 62 63                 ; 8 B header
CTL HELLO (M3, wire_ver=2, flags=0):
  0C 01 4D 33 02 00 00 00                          ; 8 B
CTL FLOW_ACK(wire_id=5, status=open):
  0C 10 05 00                                      ; 4 B
CTL SESS_CLOSE(sess=7, reason=0):
  0C 20 07 00 00 00 00                             ; 7 B
```

## Appendix B: Supporting reports and recomputation materials

The five per-topic deep dives (`01-wire`, `02-uplink`, `03-downlink`, `04-transport`, `05-evidence`) and the wire-model script (`model.py` / `model-output.txt`) were the working materials behind this synthesis. They are not shipped in the repository; their conclusions are folded into the sections above, and the implementation contract is [`MQP3_REV2_SPEC.md`](MQP3_REV2_SPEC.md).

## Appendix C: List of invariants that must be preserved (for implementation review)

> The landed rev2 implementation supersedes one item below: flow ids are monotonic and never reused, so no 3 s reuse tombstone is needed (`MQP3_REV2_SPEC.md` §3). The rest of the checklist still applies.

- [ ] Per-frame/per-item authorization is completed before entering any stager; cross-session frame aggregation does not bypass allowlist/flow fallback.
- [ ] SSRF/`allow_private` semantics unchanged; downlink compression only changes the source address expression.
- [ ] flow is installed only after the target accepts a real send; unknown id/unconfirmed open drops only the current item.
- [ ] Connection-level ids are not resolved across sessions; each item uses the session its flow belongs to.
- [ ] full-cone still opt-in; server-owned flows are created only under full-cone and counted in unsolicited.
- [ ] Length/range validation before parsing control streams/data frames; unknown kind/opcode counted and discarded, no panic.
- [ ] id reuse ≥3 s tombstone; tables bounded and charged to admission; no new memory amplifiers.
- [ ] Each frame ≤ `max_datagram_size()`; reassembly 8 KiB / 2 s / 256 KiB caps unchanged (unless CAPS explicitly negotiates).
- [ ] Default ALPN still `h3`; no "MQP-4" naming; wire_ver appears only in CAPS/logs.

---

## 10. Implementation progress (2026-10-21)

> This section records the landing status of the analysis; the implementation contract and details are subject to [MQP3_REV2_SPEC.md](MQP3_REV2_SPEC.md).
>
> **Status note (2026-10-22).** This is a dated progress log. The current tree has **436 macOS / 440 Linux** tests; the 390/416/424 counts below are the counts at the time of each landing. The completed items and the remaining optional/external items are retained as history.

- **Phase 1a + 1b landed**: rev2 codec (`src/mqp/r2.rs`, 15 unit), flow state (`src/mqp/r2_flow.rs`, 10 unit),
  rev2 fragmentation/reassembly (`src/udp/r2_frag.rs` + `src/udp/r2_reasm.rs`, 16 unit),
  client full-size rev2 (single-frame DATA or `R2Fragmenter`, downlink `R2Reassembler`), server rev2 ingress FRAG/downlink full-size;
  `cargo test --all-targets` **390 passed / 0 failed** (lib 186 + client 114 + server 90),
  `clippy --all-targets -D warnings`, `fmt --check` clean.
- **Real loopback matrix**: `udpsweep` 8–8000 B all pass (>512 B bidirectional rev2 FRAG), `udppaced` 325000/325000
  (0% loss, 60 s reporter `steady=274140 train=358/854 frag=1200/4500/1200 inline=0 drops=0`),
  domain name 1000/1000, 8-flow fan-out 2000/2000, `udpbidir` 30000/30000, 1000 B single frame 2000/2000.
- **Phase 2 landed**: `R2Stager` wired into client uplink + server downlink (connection-level cross-session `TRAIN dict`, round-robin fairness,
  bounded queue, CAPS max_train_items, SESS_CLOSE/FLOW_CLOSE purge); `R2Reassembler::drop_session/drop_flow` strict teardown;
  Linux netem matrix script `scripts/linux-bench-matrix.sh`.
- **Measured**: 8 assoc × 1000 pps × 128 B × 65 s: 519 992/519 992, 0% loss; client **0.743 frames/payload** (Phase-1b ≈0.99,
  about −26% DATAGRAM sends), stage 0 lost/0 queue full; 416 tests all green.
- **Full-duplex symmetry complete**: server-owned full-cone flow (server OPEN|SRC + client accept/reuse + server ingress forwarding)
  landed; `SESS_CLOSE` purges on both ends; 424 tests all green.
- **Still incomplete (optional/external)**: Linux target-machine measurement, strict ordering under Blocked, final cleanup of old v3/v2 send paths.
