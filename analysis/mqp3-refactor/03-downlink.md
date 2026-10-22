# MQP-3 Downlink (server → client) Data Path In-Depth Analysis

> **Baseline**: `HEAD d2f9658` / `v0.2.0` (all `file:line` references in this document refer to that commit)
> **Scope**: the **protocol structure + implementation structure** of the downlink path by which the server sends target replies back to the client, and
> downlink scalability under the workload of "one QUIC connection carrying a large number of UDP sessions".
> **Method**: read-only code review + model arithmetic; **cargo build/test not run, no perf**.
> All ns / CPU numbers are **model estimates** (anchors in §3.4); byte counts are deterministic protocol arithmetic.
> Byte accounting follows the repository's existing analysis: `PROTOCOL_ANALYSIS.md:108-110` (55 B per packet: IP 20 + UDP 8 +
> QUIC short header 27), `PROTOCOL_ANALYSIS.md:509-516` (MTU 1200 → DATAGRAM budget 1162 B;
> budget 1362 B corresponds to a 1400 B path; each DATAGRAM frame has an additional 3 B frame header).
> Note: the two conventions of 55 B/packet and 1162 B/frame come from estimates at different layers (adding the two slightly exceeds 1200 B);
> this document follows them as specified by the task; they only affect **absolute** wire bytes and do not change the relative ranking of the options (see §3.6).

---

## 0. TL;DR

1. **The structural bottleneck on the downlink is not "a few extra bytes of MQP header per reply", but "one independent send context per session"**:
   each session has one socket + one reader task + one private TRAIN stager (`reader.rs:720-766`,
   `reader.rs:1132-1143`), and the `TRAIN` frame header carries a single `sess u32` (`v3.rs:63`), so
   **replies from different sessions on the same QUIC connection can never be merged into one DATAGRAM at the protocol level**.
2. **Small replies (≤512 B) are already batched well within a single session** (a burst from the same session fills up to 64 items / the budget,
   `reader.rs:629-664`); the gap is concentrated in "multiple sessions have replies at the same time" and "a single session alternates replies across multiple flows".
   The former cannot coalesce frames due to protocol, and the latter is defeated by the single `last_flow` memo + 64-slot linear scan (`reader.rs:137-145`,
   `v3.rs:730-733`).
3. **Quantified result for "32 sessions per connection, 1 flow per session, 88 B replies"** (1000 replies, B=1162):
   status quo = **1000 DATAGRAM frames / 1000 `send_datagram` calls / 1000 frame allocations**;
   connection-level stager (each item carries sess) = **84 frames / 84 calls / 84 allocations** (11.9×).
   Wire bytes: if quinn's "multiple DATAGRAMs in the same poll coalesce into one packet" does not take effect → **−34.4%**;
   if ideal coalescing (12 frames/packet) → **only −1.6%**. **The real value lies between the two; the quinn coalescing rate must be measured first** (§3.6).
   The gain the protocol can guarantee is **12–36× in frame count/call count/allocation count**, not an order of magnitude in throughput.
4. **The bytes that are truly "free" on the downlink are in compression semantics, not frame coalescing**: domain-name target replies and port-changing/full-cone replies are currently
   always inline (`reader.rs:146-154`), 13 B header vs 5–6 B compressed header; and **the first-frame binding cost is 0 bytes**
   (`flow + inline` and today's `NO_FLOW + inline` are both 13 B) → a single "downlink flow→source address binding"
   protocol semantic can save these replies **7–8 B (v4)/19–20 B (v6)/reply** (small packets ≈ 7–38% of frame body).
5. **The control-plane gap is downlink lifecycle cost, not bandwidth**: no `SESS_CLOSE/FLOW_CLOSE`; short-session zombies occupy slots for
   180 s → association churn > **45/s** may fill the global 8192 session pool (§4.2); after the 64 slots of the flow table are full,
   all new targets of that session **permanently degrade to inline** (§4.3).
6. **Protocol vs implementation must be sold separately**:
   - **Protocol layer (wire must change)**: P1 cross-session TRAIN, P2 downlink flow source binding (domain name/port-changing/full-cone),
     P3 control plane close/ack, P4 v3 large frames for >512 B, P5 compact FRAG, P6 CAPS, P7 connection-level id.
   - **Pure implementation layer (wire unchanged)**: I1 reuse the flow id already looked up during authentication + per-reader source→flow small memo,
     I2 avoid arena copy for a single run, I3 index the flow table/allowlist, I4 connection-level stager and fair scheduling,
     I5 per-connection reply reactor (remove per-session task/timer), I6 send >512 B directly as v3 SINGLE.
   Among these, **I1/I2/I6 are risk-free net gains**; **P1 is only meaningful together with I4** (see §5.3 milestones).

---

## 1. Status Quo: Downlink End-to-End Path

### 1.1 Session Model: One Session = One Socket + One Task + One Stager

| Resource | Location | Notes |
|---|---|---|
| Kernel UDP socket | `reader.rs:1102-1121` | `udp_socket_dual_small("[::]:0")`, one ephemeral port per session; `SO_*BUF` = 64 KiB/direction (`lib.rs:244`) |
| reader task | `reader.rs:1132-1143` | one `tokio::spawn(sess_reader_task)` per session |
| read buffer | `reader.rs:7-15, 739` | 8 KiB+1 (`UDP_RECV_MAX+slack`); the thread-local pool only recycles buffers and does not share sockets/tasks (`reader.rs:28-65`) |
| 60 s timer | `reader.rs:732-733` | one interval per session: idle determination + PMTU refresh |
| reply stager | `reader.rs:758-766` | `arena: Vec<u8>` + `staged: Vec<ReplyItem>` **private to the task**, at most one frame |
| flow table handle | `reader.rs:1130-1131`, `table.rs:51-56` | `Arc<ArcSwap<FlowTable>>`, shared with the uplink (client open, server mirror) |
| allowlist mirror | local to reader task (`reader.rs:748-757`) | epoch-gated `Arc<RecentAddrs>` |

> Key conclusion: **the granularity of the downlink send context (connection, stager, cache) is the session, not the QUIC connection.**
> 4032 sessions on one connection (`tuning.rs:116` `MAX_UDP_ASSOCS=4032`) means 4032 sets of the above resources.

### 1.2 Phase-by-Phase (file:line evidence)

```text
Target reply
  ① Target socket becomes readable → reader task wakes up
  ② rs.recv_from(&mut buf) fetches head (reader.rs:768-772)
  ③ Within one wakeup, drain up to 31 more: recvmmsg into thread-local scratch,
     process in place within the borrow (reader.rs:806-902; udp/batch.rs:528-546, 591-611)
  ④ handle_session_reply (fully synchronous, reader.rs:480-717):
     ④a truncation detection → ④b limit==0 handling → ④c unmap source address
     ④d reply source authentication: epoch-gated allowlist 16-ring (reader.rs:579-594, pin.rs:22-54)
        └ on ring miss, use the per-session flow table as the second authorization source (reader.rs:596-608, v3.rs:730-733)
     ④e FullCone exception (reader.rs:609-618)
     ④f source address → flow id: `flow_for_ip` (one-slot memo, 64-slot linear scan on miss)
        (reader.rs:124-145; v3.rs:722-733)
     ④g ≤ 512 B → arena copy + staged.push (reader.rs:629-664, 124-174)
  ⑤ burst end/budget exhausted → flush_reply_train (reader.rs:906-915, 665-674)
  ⑥ run==1 → v3 SINGLE; run>1 → v3 TRAIN; encoder computes exact length against budget
     (reader.rs:215-298; v3.rs:151-198, 285-347)
  ⑦ try_send_datagram → quinn::send_datagram_wait single poll (one connection-state
     mutex per frame) → enters quinn send queue (udp/send.rs:84-95; reader.rs:503-511)
  ⑧ quinn driver: DATAGRAM frame encoding (body copied again into packet) + AEAD + sendmsg/GSO
  ⑨ client dispatcher: read_datagram pops frame by frame → decode/restore flow → write back to app socket
     (client/dispatcher.rs:225-344, 663-723, 769-849)
```

Large reply branch: `n > BATCH_SMALL_MAX(512)` → first flush the staged TRAIN, then use **MQP-2**
`DgramFragmenter::send` (`reader.rs:665-716`, `udp/fragmenter.rs:178-394`): if it fits, a `0x02` single frame (12 B header, IPv4); if not, `0x05` fragmentation (18 B header per fragment + repeated address).

### 1.3 Per-Reply Cost Account (small reply ≤512 B, IP flow, steady state)

The granularity of the table below is **one reply**; the "per frame" column is amortized only when run>1. Assume Linux + sharded runtime (current default).

| Cost item | Count per reply | Evidence / notes |
|---|---|---|
| syscall — recv | 1 `recv_from` (head) | `reader.rs:769`; subsequent replies in the same wakeup amortize 1 `recvmmsg` per 31 (`udp/batch.rs:528`) |
| syscall — send | ≈1 per quinn packet (amortized by frame count) | driver-level sendmsg/GSO; `send_datagram` itself does not directly syscall |
| quinn mutex | **1 per frame** | connection-state lock inside `SendDatagram::poll`, `udp/send.rs:84-95`, `reader.rs:503-511` |
| userspace memcpy | **3** (arena 1 + encoding 1 + quinn packet 1) | arena: `reader.rs:164-165`; encoding: `v3.rs:196, 343`; packet: quinn-proto `Datagram::encode` (`PROTOCOL_ANALYSIS.md:79-95`) |
| allocation | **1 per frame** (exact-size `Vec`→`Bytes`, no secondary control block) | `v3.rs:313`, `v3.rs:174`, `mqp/datagram.rs:44-72` comments |
| task switch | **0** (whole processing is synchronous, no channel) | `reader.rs:471-478`, `reader.rs:814-842` |
| wakeup | 1 per socket readiness (≈1/reply); 1 quinn driver wakeup per frame | single-poll `now_or_never` of `try_send_datagram` (`udp/send.rs:71-83`) |
| table scan — allowlist | 16-slot linear scan | `pin.rs:24-27, 47-53` (`RecentAddrs` 280 B, clone-on-write) |
| table scan — flow | 0 (memo hit)/**64 slots + ArcSwap load** (memo miss) | `reader.rs:137-145`; on ring miss **scan again** (`reader.rs:601` + `607` invalidates memo) |
| atomic operations | coarse clock 2 relaxed loads, epoch 1 load, `last2` ≤1 store/s, stats thread-local | `time/coarse.rs`, `stats/udp_stats.rs:89-121` |
| wire — fixed per frame | TRAIN header 6 B (`v3.rs:63`) + 2 B per item (same flow)/3 B (different flow) | `v3.rs:261-267` |
| wire — per payload | 0 (flow 0 compressed)/1 B (extra flow)/+7·19 B (inline) | `v3.rs:143-149` |
| wire — QUIC/DATAGRAM | 3 B DATAGRAM frame header + 55 B/packet (amortized by frames in the same packet) | `PROTOCOL_ANALYSIS.md:108-110` |

**The "per frame vs per payload" split (this is the important one)**:

- **Per frame (amortizable)**: quinn lock, frame allocation, TRAIN header, DATAGRAM frame header, 55 B packet overhead, driver
  AEAD+syscall. These are what "frame coalescing" can save.
- **Per payload (not amortizable)**: recv syscall, socket wakeup, allowlist scan, flow lookup, arena copy,
  encoding copy, quinn packet copy, kernel send/receive copy. These can only be reduced by "fewer replies / fewer copies / fewer scans".
- The **bulk of CPU is per payload** (recv syscall ≈1 µs, driver amortized ≈0.1 µs, wakeup ≈0.2 µs), so
  **the upper bound of protocol frame coalescing on downlink CPU ≈ 0.2–0.3 µs/reply (about 10–15%)**; this is why the §3 table says
  "frame count 12–36×↓ but CPU only drops ~10–15%".

### 1.4 Cost Differences by Reply Shape

| Shape | Which path | Fixed header | Additional per-reply cost |
|---|---|---|---|
| ≤512 B, IP flow known | v3 TRAIN (within same session) | 5–6 B | arena copy; when run==1 the arena copy is **pure waste** (§1.5) |
| ≤512 B, domain-name target | v3 SINGLE/TRAIN **inline** | 13 B(v4)/25 B(v6) | no flow compression, no cross-frame reuse |
| ≤512 B, port-changing/full-cone | `NO_FLOW` inline | 13/25 B | same as above; `MQP3_FLAG_SRC` is defined but the server never sets it (`v3.rs:31-34`, `reader.rs:189,258`) |
| 513 B–B (fits in a single frame) | **MQP-2** `0x02` | 12 B(v4)/24 B(v6) | falls out of v3: no flow compression, client uses v2 decoding, prefix cache rebuilt per session |
| >B | **MQP-2** `0x05` fragmentation | 18/30 B/fragment | F allocations, F quinn locks, F send queue entries; address repeated per fragment |

### 1.5 A Concrete Implementation-Layer Waste: the run==1 Arena Copy

`handle_session_reply` first copies the payload into the arena (`reader.rs:164-165`); at burst end
`flush_reply_train`, if it finds `staged.len()==1`, calls `flush_reply_single`, which encodes
**the same arena slice** again into a new frame (`reader.rs:231-240`, `179-206`). For the steady state of "one wakeup has only one
reply" (DNS request/response, game keepalive, single-stream media), this is **one full payload copy extra per reply**. Fix: the first
entry only records a borrow, and only writes to the arena when the second arrives (I2, §5.2). This is a pure implementation change, 0 risk.

### 1.6 Task/CPU Scalability (one task stack per session)

- Per session: 1 task + 1 60 s interval + 1 socket + 8 KiB userspace buffer. 4032 sessions/
  connection = 4032 tasks/timers/sockets (`tuning.rs:116`); global 8192 (`table.rs:374`) → userspace
  read buffer cap 64 MiB (the buffer pool only recycles, does not share across tasks, `reader.rs:28-65`).
- Per reply: 1 socket wakeup + 1 schedule; on the sharded runtime's current-thread runtime, all session readers of the same connection
  run serially on one core (`main.rs:466-536`), so the CPU of "multiple sessions" is
  **linearly additive** with no parallelism; thread topology can only scale horizontally via multiple QUIC connections/multiple ingress endpoints.
- Each connection shares 1 MiB of DATAGRAM send buffer (`transport/limits.rs:84`, `build.rs:158-164`);
  a session's high-rate target replies can fill it, at which point **other sessions' replies are judged `Blocked` and dropped**
  (`udp/send.rs:28-41, 60-69`) — no cross-session fairness, no isolation. This is a structural problem, see §2 G8.

---

## 2. Downlink Gap List (with evidence and magnitude)

| # | Gap | Evidence | Magnitude / consequence |
|---|---|---|---|
| **G1** | TRAIN header has only one `sess u32`, **protocol cannot coalesce frames across sessions** | `v3.rs:63` (`1+4+1`), `reader.rs:263` (`encode_train(s, …)`), `reader.rs:215-298` | When multiple sessions reply simultaneously, frame count = reply count (§3); this is the root cause of P1 |
| **G2** | Stager/arena is private per reader task, **cannot share one frame buffer** | `reader.rs:758-766`, `reader.rs:720-766` | Cross-session frame coalescing requires a "connection-level stager", the root cause of I4; also the solution for G8 fairness |
| **G3** | >512 B replies fall entirely out of v3 | `reader.rs:629`, `reader.rs:665-716`, `mqp/batch.rs:9` | 7 B(v4)/18 B(v6) extra header per frame; loses flow compression; client uses v2 path; >B fragmented per MQP-2 (18/30 B per fragment) |
| **G4** | Domain-name target replies are always inline | `reader.rs:146-154`; flow table entry stores `Domain` (`accept.rs:745`), while `flow_for_ip` matches only IP entries (`v3.rs:730-733`) | 13 B vs 5–6 B per reply (v4): 7–38% of frame body for small packets; see §4.4 |
| **G5** | Port-changing/full-cone sources are always `NO_FLOW` inline; `SRC` flag never used | `v3.rs:31-34` (definition), `reader.rs:189,258` (never set true), `reader.rs:609-618` | Same 13 B; "port-changing" traffic such as TFTP/game redirect/WebRTC all pays this tax |
| **G6** | Auth ring only 16 entries; after a miss, flow fallback requires **two lookups** (one for auth + one for staging), and the single-slot `last_flow` memo is ineffective for alternating sources | `pin.rs:35`, `reader.rs:596-608`, `reader.rs:137-145`, `reader.rs:602-608` | 32-flow fan-out: ~50–200 ns extra per reply (ArcSwap load + 2×64-slot scan); see §3.5 |
| **G7** | No control plane: no `SESS_CLOSE/FLOW_CLOSE/FLOW_ACK/CAPS` | `v3.rs:25` (0x40 reserved, but no encoder/decoder); both ends ignore with `_ => {}` (`accept.rs:718-725`, `client/dispatcher.rs:330-338`); the repo itself leaves a TODO (`client/hub.rs:55`) | Lifecycle/memory/churn: §4; also leaves no acknowledgment channel for "domain downlink compression/uplink-only flow compression" |
| **G8** | 1 MiB DATAGRAM buffer per connection has no cross-session fairness | `transport/limits.rs:84`, `build.rs:158-164`, `udp/send.rs:60-69` | A high-rate flow can cause other sessions' replies on the same connection to be judged `Blocked` and dropped; no protocol-level fairness, only stager scheduling |
| **G9** | Per-session task/socket/timer, reply path has no cross-session batching | `reader.rs:1132-1143, 732-733, 739` | 1 recv syscall + 1 wakeup per reply; multi-session CPU adds linearly; §1.6 |
| **G10** | Arena copy is pure waste when run==1 | `reader.rs:164-165` vs `231-240` | 1 extra payload copy per reply (§1.5) |

---

## 3. Quantifying "One Connection Carrying Many Sessions"

### 3.1 Conventions and Assumptions

- Workload **W32**: 32 independent UDP sessions on one QUIC connection (e.g., 32 DNS clients, 32
  independent VPN associations, 32 concurrent UDP applications), 1 flow per session (flow id 0), **88 B** payload per reply
  (typical DNS/EDNS response), **1000 replies** total; target replies arrive interleaved.
- Budget **B = 1162** (1200 path)/**1362** (1400 path); **3 B** QUIC frame header per DATAGRAM frame;
  **55 B** IP/UDP/QUIC overhead per UDP packet (`PROTOCOL_ANALYSIS.md:108-110`).
- **quinn coalescing**: within the same transmit poll, quinn writes multiple queued DATAGRAM frames into the same QUIC
  packet (`PROTOCOL_ANALYSIS.md:79-95`, quinn-proto `connection/mod.rs`). **Whether it happens depends on
  when the driver is scheduled**: on the sharded current-thread runtime, one `send_datagram` from a reader may
  wake the driver immediately, or it may be merged with other readers' sends. So we give **two bounds**:
  - **No coalescing**: each frame occupies its own QUIC packet (55 B overhead/frame);
  - **Ideal coalescing**: fill the same packet with `floor(B/(3+frame body))` frames (55 B overhead amortized).
  Real deployment lies between the two; **frame count/call count/allocation count are unchanged in both cases**, so this is a guaranteed gain.
- Status-quo modeling: "replies from each session are interleaved, and one wakeup usually has only 1 reply" → run==1 → one
  SINGLE per reply (5 B header, flow 0); when multiple replies occur within the same session, the status quo combines them into a TRAIN (§3.5).
- Three variants of the connection-level scheme (all **retain the existing per-session flow id semantics**, and only change "put items of multiple
  sessions in one DATAGRAM"):
  - **A (recommended first step)**: new frame shape `TRAIN_X`: header `kind/flags + count` (2 B), **each item carries sess u32**
    (`flags 1 + sess 4 + len varint 1 + payload`). **No connection-level id space needed**; the client can dispatch each item by
    sess.
  - **B**: header contains "this frame's session table" (`2 + 4×k + count`), and each item has a 1 B session index.
  - **C (the "connection-level id" mentioned in the task)**: connection-level u16 flow id, items no longer carry sess (`1+2+1+P`).

### 3.2 Main Table: 1000 replies / 32 sessions / 88 B (status quo vs connection-level stager)

**B = 1162 (MTU 1200)**

| Option | Items per frame | DATAGRAM frames | quinn send calls | Frame allocations | Packets/bytes (no coalescing) | Packets/bytes (ideal coalescing) | Wire B/reply (coalescing bound) | payload efficiency |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Status-quo per-session stager | 1 (interleaved across sessions under W32) | **1000** | **1000** | **1000** | 1000 / **151.0 KB** | 84 / 100.6 KB | 100.6 | 87.5% |
| Connection-level A (sess u32 per item) | 12 | **84** | **84** | **84** | 84 / 99.0 KB | 84 / 99.0 KB | 99.0 | 88.9% |
| Connection-level B (in-frame session table) | 12 | 84 | 84 | 84 | 84 / 100.2 KB | 84 / 100.2 KB | 100.2 | 87.9% |
| Connection-level C (connection-level u16 id) | 12 | **84** | **84** | **84** | 84 / 97.0 KB | 84 / 97.0 KB | 97.0 | 90.7% |

- **For the "no coalescing" bound: A saves 34.4%, C saves 35.7%** (the saving is the 55 B overhead of 1000→84 packets);
- **For the "ideal coalescing" bound: A saves only 1.6%, C saves 3.6%** (coalescing already amortizes the 55 B, leaving only the MQP/DQH header);
- **Guaranteed gain: frame count/send calls/allocation count 1000 → 84 (11.9×)**, independent of quinn coalescing;
- **A vs C**: only 2 B difference per reply (sess u32 vs u16 + no session table); C is not worth introducing a connection-level id
  space for 2 B; **A is the "smallest protocol change, almost all the gain" option**.

**B = 1362 (MTU 1400)**

| Option | Items per frame | Frames | No-coalescing bytes | Ideal-coalescing bytes | Wire B/reply |
|---|---:|---:|---:|---:|---:|
| Status quo | 1 | 1000 | 151.0 KB | 72 packets / 100.0 KB | 100.0 |
| Connection-level A | 14 | **72** | 98.3 KB (−34.9%) | 72 / 98.3 KB (−1.6%) | 98.3 |
| Connection-level C | 14 | 72 | 96.3 KB (−36.2%) | 72 / 96.3 KB (−3.6%) | 96.3 |

> Raising B from 1162 to 1362 yields only ~1% for W32 (2 more items per frame, 55 B spread thinner);
> **the main value of MTU is "fewer fragments" and large replies** (`tuning.rs:186-193`), not small-reply frame coalescing.

### 3.3 Sensitivity: smaller replies make frame coalescing more valuable; larger ones less so

| payload | Status-quo frame count | Connection-level A frame count | Status-quo wire B/reply (no/ideal coalescing) | A wire B/reply | A vs no coalescing | A vs ideal coalescing |
|---:|---:|---:|---:|---:|---:|---:|
| 28 B | 1000 | **30** | 91.0 / 37.8 | 35.8 | **−60.7%** | **−5.2%** |
| 88 B | 1000 | 84 | 151.0 / 100.6 | 99.0 | −34.4% | −1.6% |
| 200 B | 1000 | 200 | 263.0 / 219.0 | 218.0 | −17.1% | −0.5% |

(B=1162. For scheme C at 28 B: 28 frames / 33.7 B/reply, −10.8% vs ideal coalescing.)

**How to read it**: the value of W32 depends on the quinn coalescing rate.
- If the wire measurement shows "1000 replies ≈ 1000 QUIC packets" (no coalescing) → frame coalescing saves 17–61% of bytes.
- If the measurement shows "≈84 packets" (coalescing effective) → only 0.5–11% saved; **the main gain is turning "coalescing that depends on
  scheduling coincidence" into "protocol-guaranteed coalescing"**, plus a 12–36× reduction in send calls/allocations/client frame pops.
- **Must measure first**: the ratio of DATAGRAM frame count to QUIC packet count under the status quo (§7).

### 3.4 CPU Account: The Real Upper Bound of the Connection-Level Stager

Per-event estimation anchors: recv syscall (including kernel copy) ≈1.0 µs; quinn `send_datagram_wait` ≈250 ns
(`PROTOCOL_ANALYSIS.md:542-557` uses 200–300 ns); frame allocation ≈35 ns; 88 B memcpy ≈8 ns;
current-thread runtime wakeup+schedule ≈200 ns; client `read_datagram` pop ≈150 ns;
client write to app socket 1 syscall ≈0.8 µs. The following are **model estimates**:

| Per-reply CPU (W32, 88 B) | Status quo | Connection-level A | Change |
|---|---:|---:|---:|
| recv syscall (cannot be eliminated) | 1.0 µs | 1.0 µs | 0 |
| socket wakeup/schedule (cannot be eliminated unless reactorized) | 0.20 µs | 0.20 µs | 0 |
| auth+flow lookup+staging copy | ~0.05 µs | ~0.05 µs | 0 |
| quinn `send_datagram` (per frame) | 0.25 µs | 0.25/12 ≈ 0.02 µs | **−0.23 µs** |
| frame allocation | 0.035 µs | 0.003 µs | −0.03 µs |
| stager enqueue/dequeue (new) | 0 | ~0.04–0.08 µs | **+0.04–0.08 µs** |
| driver per-packet amortized (AEAD+sendmsg ≈0.95 µs/packet, amortized by frames per packet) | 0.08 µs (12 frames/packet) | 0.08 µs (frames become full) | ≈0 |
| **server net change** | | | **≈ −0.18 ~ −0.22 µs/reply (−11~14%)** |
| client: frame pop+decode+cache (84 frames instead of 1000) | ~0.20 µs | ~0.02 µs | **−0.18 µs/reply** |

- 50k replies/s: server saves ≈ **9–11 ms/s ≈ 1% of one core**, client saves ≈ **0.9% of one core**;
  200k replies/s: total ≈ **4–5% of one core**.
- **Conclusion**: P1+I4 is "low single-digit CPU% + a deterministic ceiling on wire bytes", not an order-of-magnitude speedup;
  its real value is (a) reducing wire bytes when coalescing does not take effect, (b) providing a landing point for G8's fair scheduling,
  (c) freeing up structure for later connection-level id/large-frame unification.
- The real bulk is "1 recv syscall + 1 send syscall + 1 wakeup per reply"; only **I5 (per-connection
  reactor)** can touch the ~0.2 µs of wakeup/scheduling; the syscall count still cannot be eliminated.

### 3.5 Comparison: Single Session with 32 Flows (One VPN Association) — Cross-Session Frame Coalescing Does Not Help

- One session has one relay socket: replies from 32 flows all come back from **the same socket**, and the
  current per-session stager can already combine them into one TRAIN: `n = floor((B−6)/(P+3))`
  (header 6 B + 3 B per item flags/flow/len) → at 88 B, 12 items/frame, **1000 replies = 84 frames**, already close to optimal.
- Therefore the gain in this scenario is **not in P1**, but in:
  1. **flow lookup**: 32 sources alternate replies → the one-slot `last_flow` memo is invalidated on every reply →
     `flows.load()`(ArcSwap) + `flow_for_ip` 64-slot scan, **~50–150 ns per reply** (I1);
  2. **allowlist ring 16 < 32**: ring miss → auth goes through the flow table scan again + invalidates the memo →
     ~100–200 ns for ring-miss replies (I1/I3);
  3. **compression for domain-name/port-changing flows** (P2) and **v3-ification of >512 B** (P4/I6).
- Quantified: with 32 flows at 100k pps, flow lookup/ring miss is about **0.5–1.5% of one core**, "free but small";
  for domain-name targets, P2 is a **deterministic byte gain** of 7–8 B/reply (§3.3/§4.4).

### 3.6 Boundary Notes (Consistency of Accounting)

- 55 B/packet and 1162 B/frame come from estimates at different layers (the two add up to > 1200 B), but the conclusions of this report depend only on the **difference**:
  after removing the 55 B term, the "ideal coalescing" gain of W32/88 B changes from 1.6% to ~5.2% (only the DQH+MQP header difference remains),
  and the "no coalescing" bound is unchanged (still one packet per frame) → **ranking and conclusions unchanged**.
- If the actual quinn `max_datagram_size` differs slightly from 1162/1362, items per frame change by ±1, and table numbers change by <2%.

---

## 4. Session Lifecycle and the Control Plane's Impact on the Downlink

### 4.1 The Real Cost of 180 s idle, sweeper, teardown

- **idle determination**: the reader's own 60 s tick does both idle determination and PMTU refresh, condition
  `now - last2 >= SESS_IDLE_MS(180 s)` (`reader.rs:773-789`, `table.rs:382`);
  each connection also has a 60 s sweeper calling `sweep_all` (`accept.rs:798-818`, `table.rs:310-333`),
  and `drain_all` on connection close (`table.rs:297-308`).
- **normal teardown**: break outside the burst → recycle the read buffer, clear the thread memo, remove from the shard, release the global
  permit (`reader.rs:921-940`). Cost O(1)/session.
- **sweep cost**: once per connection every 60 s, 8 shards each perform one read-lock scan + remove expired entries under the write lock
  (`table.rs:310-333`). With 4032 sessions/connection, a single sweep is ~4032 atomic loads + comparisons, **microsecond level**;
  but 4096 connections each have a sweeper task (`accept.rs:801-817`) → ~68 wakeups/s, negligible.
- **The real cost is "dead sessions staying alive"**: after a client exits an association, the server's session/socket/task/
  flow table/KV are retained for **up to 180 s** (no `SESS_CLOSE`). During this period:
  - the global permit is occupied (`MAX_SESSIONS_GLOBAL=8192`, `table.rs:374`),
  - the kernel socket and 8 KiB read buffer are occupied, the reader task and 60 s timer are occupied,
  - replies still sent by the target are delivered to a session nobody reads (dropped after forwarding).

### 4.2 Memory and Churn Quantification (the value of SESS_CLOSE)

`per_session_memory_bytes()` (`config/tuning.rs:309-317`) under Linux/64 KiB defaults:
`2×(2×64 KiB) + 8 KiB+1 + 4 KiB = 274,433 B ≈ 268 KiB` (`lib.rs:244`,
`v3.rs:51` MQP-3 flow table accounting). 8192 sessions → **2.14 GiB** accounted memory.

Zombie steady-state count = association close rate × 180 s:

| Association churn | Zombies after 180 s | vs global 8192 pool | Zombie accounted memory |
|---:|---:|---|---:|
| 10 /s | 1,800 | 22% | 471 MiB |
| **45 /s** | 8,100 | **≈ 100% (critical)** | 2.12 GiB |
| 100 /s | 18,000 | **over limit → new sessions rejected with `SESSION_FULL`** | 4.71 GiB |
| 806 /s (theoretical upper bound of 4032 concurrency × 5 s lifetime) | 145,080 | severely over limit | about 38 GiB (accounting basis) |

> **When short-lived association churn > about 45/s, the server's global session pool is filled by "dead but unreclaimed" sessions**,
> manifesting as new associations failing to establish (when the global pool is exhausted, `get_or_create_sess` returns `None`:
> `reader.rs:1077-1097` `SESSION_FULL` branch; the uplink call site's `?` at `forward.rs:357` drops the packet directly),
> and since DATAGRAM has no acknowledgment, the client only sees UDP packet loss.
> `SESS_CLOSE` (P3) changes reclamation from "after ≤180 s" to "immediately"; this is an **availability fix**, not a performance tweak.
> It also saves 268 KiB/session of accounted memory and kernel fd pressure.
> `FLOW_CLOSE`, in turn, solves the permanent degradation in §4.3.

### 4.3 Flow Table 64 Slots Full → Permanent Degradation

- Client flow ids are allocated monotonically and **never reused during their lifetime** (`v3.rs:683-690` comment, `insert`/`next`,
  `MQP3_MAX_FLOWS=64`). The server mirrors the same table (`accept.rs:731-757`).
- After the table is full: new uplink targets can only be `NO_FLOW` inline (client, `assoc.rs`); when the server flow table is full, replies can also only be
  `NO_FLOW` inline (`reader.rs:150-154`).
- **The degradation is irreversible**: after a long-lived association (game/WebRTC/resident VPN) accesses more than 64 targets, all subsequent
  targets **permanently** pay 7–8 B/reply extra (v4; 13 B header vs 5–6 B header), up to +24% on small replies (41 B vs 33 B frame body
  at 28 B payload). `FLOW_CLOSE` + reuse after a safety window (`FRAG_ID_SAFE_WINDOW_MS=3 s`,
  `fragment.rs:145`) can restore compression, and the id reuse risk is controllable (only the reassembly window needs to be covered).
- Quantified: for a long-lived connection with 10 new targets/hour, it enters permanent inline after about 6.4 h; thereafter +7–8 B per reply.

### 4.4 Domain Name Resolution Path and "Can the Downlink Compress Domain-Name Targets?"

Current uplink resolution chain (paid only once on the first uplink datagram, not on the reply path):
`resolve_forward_target` (thread DNS memo → session `DestMemo`, `forward.rs:286-321`) →
on miss, `DnsGate.claim` merges + `tokio::spawn` a resolver (`forward.rs:383-426`,
`DNS_GATE_SLOTS=8`, `forward.rs:13`) → moka positive cache (TTL 120 s, 10240 entries,
`dns/store.rs:56,67`) → `sess_dest_store` writes `DestMemo` (`pin.rs:79-88,546-580`).
**The downlink path itself does no DNS**: the reader only sees the reply source IP.

Gap: the domain-name entry in `FlowTable` stores `TargetAddr::Domain` (`accept.rs:745`),
and `flow_for_ip` matches only IP entries (`v3.rs:730-733`), so domain-name target replies are **always inline**
(the comment at `reader.rs:146-154` means exactly this). And the client indeed does not know the resolved IP,
so it cannot use the domain name to fill the source address of the SOCKS5 UDP reply.

**Key insight (P2): it can be fixed without a new control frame, and the first frame costs 0 bytes.**

Today a domain-name reply = `NO_FLOW + inline`, SINGLE header = `1+4+1+7 = 13 B` (v4);
if changed to `flow + inline` (`MQP3_FLAG_INLINE`, flow non-zero) → still `1+4+1+7 = 13 B`,
**not a single byte more**. The semantics are upgraded to "the inline address in this frame = the actual source address of this flow":
1. After the client receives `flow + inline`, it records `flow → source address(IP:port)` in the downlink binding table,
   and later, when it receives a **compressed frame** (`flow`, no inline), uses it to construct the SOCKS5 reply header;
2. The client's next uplink frame for that flow can then be compressed (it already compresses only after "having received a downlink frame for that flow",
   `client/dispatcher.rs:286-288` `confirm_flow`) — this **compressed uplink frame is the implicit ACK**;
3. After the server observes a compressed uplink frame for that flow, it switches the state from `BindPending` to `Bound`, and subsequent replies are compressed;
   if the source address changes (DNS rotation/port drift) → send a `flow + inline` binding frame again and fall back to `BindPending`.
- Gain: domain-name target replies **−7~8 B/reply(v4) / −19~20 B(v6)** (8/20 B saved at flow 0, 7/19 B saved with an extra flow; ≈−7% of frame body at 88 B payload, ≈−19% at 28 B, ≈−38% at 8 B). Port-changing sources use the same mechanism (binding frame 13 B = today's `NO_FLOW` inline 13 B, 0 cost).
- Cost: during the binding RTT round, replies are still inline (at most 1 RTT); uplink-only flows (no replies) are unaffected;
  the server needs to attach a `reply_src: Option<SocketAddr>` to the flow table entry (+24 B/entry, max 64 entries → +1.5 KiB/
  session, `MQP3_FLOW_TABLE_MAX_BYTES` accounting must be adjusted accordingly, `v3.rs:51`).
- **The `FLOW_ACK` control frame still has independent value, but it is not a prerequisite for downlink compression**: it can make "uplink-only flows"
  compress immediately (uplink gain), and it can also provide a fallback confirmation when "the binding frame is lost + the peer does not resend uplink".
  If a control plane is built, `FLOW_ACK` should carry `(sess, flow, source_ip[:port])`, semantically consistent with the binding frame above.

### 4.5 full-cone / server-initiated flow

- `udp_full_cone` (`config/server_conf.rs:36-56`, `reader.rs:609-618`): any source is accepted and
  counted as `unsolicited`. Such sources **have no uplink flow**, so today they can only be `NO_FLOW` inline.
- "server-initiated flow" can make them first-class citizens: when the server first sees a source, it sends a frame
  `new flow id + inline source address` (bytes equal to today's inline frame), and the client compresses after establishing the binding.
  But the flow id space is currently **allocated by the client** (`hub.rs:alloc_sess`/assoc flow table);
  server-generated ids require a protocol convention (e.g., reserve `128..=255` for server-initiated, or introduce a `FLOW_OPEN` control frame).
- The policy boundary is unchanged: this only affects "how the source address is expressed" and **does not widen** the opening already made by `udp_full_cone`;
  it is recommended that server-initiated flows only be created under `ReplyFilter::FullCone` and counted in unsolicited statistics.

---

## 5. Protocol Change Ranking (Protocol Layer vs Pure Implementation Layer)

### 5.1 Protocol Layer (wire must change; the user has allowed incompatible refactoring, the name remains MQP-3)

| Order | Change | Specifics | Expected gain | Risk | Prerequisite |
|---|---|---|---|---|---|
| **P1** | **Cross-session TRAIN (`TRAIN_X`)** | New frame shape: header `kind/flags + count` (no sess), **each item explicitly carries sess u32** (option A; §3.2). Keep the existing same-session TRAIN unchanged (1-item run falls back to SINGLE, bytes equal to today); the receiver dispatches item by item by sess. Option C (connection-level u16 id) saves only another 2 B/item, **not recommended for the first version** | Multi-session workload: **frames/send calls/allocations 11.9×↓** (32 sessions, 88 B); wire bytes: no-coalescing bound **−34%**, ideal-coalescing bound **−1.6%**; client frame pop drops likewise. CPU ≈ −0.2 µs/reply (server) | **Medium-high**: must be paired with I4 (connection-level stager); flush timing (cannot wait, rely on "flush when stager drains"); loss correlation changes when multiple sessions share a packet (expected loss rate unchanged, see §5.4); client per-item demux | I4 |
| **P2** | **Downlink flow→source address binding** | First reply `flow + inline` (bytes = today's `NO_FLOW+inline`) establishes binding → client learns source → compressed uplink acts as implicit ACK → server switches to compressed. Covers: domain-name targets, port-changing sources, full-cone sources (with P3/reserved id range) | Domain-name/port-changing replies **−7~8 B(v4)/−19~20 B(v6)/reply** (small packets −7~38% frame body); makes `FLAG_SRC` actually useful; removes the structural tax of "domain names always inline" | **Medium**: server flow table needs `reply_src` (+accounting); source drift rebinding; binding frame loss degrades to today's inline (no black hole) | None (can do domain names first, see §4.4) |
| **P3** | **Control plane: `SESS_CLOSE` / `FLOW_CLOSE`** (optionally add `FLOW_ACK`/`CAPS`) | 0x40 already reserved (`v3.rs:25`); idempotent, repeatable, idle fallback. `SESS_CLOSE` immediately releases socket/task/flow table/permit; `FLOW_CLOSE` releases the flow and allows id reuse after a safety window | Availability: churn **>45 associations/s** no longer fills the 8192 pool (§4.2); each session immediately reclaims **268 KiB** of accounting + fd; `FLOW_CLOSE` fixes 64-flow permanent inline (+7~8 B/reply degradation) | **Low**: idempotent frame, worst case on loss degrades to today; add `CAPS` only when gradual rollout is needed | None |
| **P4** | **v3-ify >512 B replies** | Replies that fit in a single frame are sent as **v3 SINGLE** (may carry compressed flow); >B fragments are sent as **v3 `FRAG`** (11–12 B fragment header, no address) and reassembly is wired on both ends (key becomes `(sess, flow, id)`) | Saves **6–7 B(v4) / 18 B(v6)** per large packet/per fragment; an 8000 B payload with 6–7 fragments saves 42–49 B in total (v4); also removes the client's v2 decoding branch | **Low**: codec already implemented (`v3.rs:542-671`), only "server willing to send + client willing to receive/reassemble" is missing; reassembly needs flow→address resolution | None (can be merged with P2) |
| **P5** | **Compact FRAG full chain** | Same origin as P4; merge this item if P4 is done. Larger gain for IPv6 | Same as above | Low | P4 |
| **P6** | **CAPS/HELLO negotiation** | First connection negotiates `max_train_items`, whether `TRAIN_X` is supported, connection-level id, etc. | Only needed for gradual rollout/mixed deployment; the user allows incompatibility → can be omitted if shipped together with P1 | Low | None |
| **P7** | **Connection-level flow id (u16)/session id u16** | On top of P1, saves another 2–3 B/item; requires a connection-level id table (memory/limit/reclamation) | Another ~2 B per item (~2% at 88 B) | **High**: who owns the id space, connection-level table limit, coupling with per-session flow lifecycle/ACK semantics; **recommend deferring**, decide by measurement | P1 |

### 5.2 Pure Implementation Layer (wire entirely unchanged)

| Order | Change | Evidence | Gain | Risk |
|---|---|---|---|---|
| **I1** | If the auth phase has already looked up the flow id, **pass it directly to staging**; expand `last_flow` from 1 slot to a small memo (4–8 slots) or add an IP index to the flow table | `reader.rs:601` discards flow id; `reader.rs:137-145` one slot; `v3.rs:722-733` 64-slot linear | 32-flow fan-out **−50~150 ns per reply**; eliminates the second scan on ring miss | Low (purely local) |
| **I2** | No arena copy when run==1 (first item borrows, only the second lands in the arena) | `reader.rs:164-165` vs `231-240` | Saves 1 payload copy per reply (~8–10 ns + cache pressure) | Very low |
| **I3** | allowlist fast path: store IPv4 as u32 comparison; or expand to 32 entries | `pin.rs:22-54` | 16-slot scan → 4 word comparisons; ring miss rate halved | Low (memory 280 B→~0.6 KiB/session) |
| **I4** | **connection-level stager** (shared arena + single flush + per-session quota/DRR) | `reader.rs:758-766`; G8 | Landing point for P1; also fixes G8 fairness and centralizes TooLarge detection/PMTU cache at connection level | Medium-high: new task/lock/anchor; flush policy determines the gain (only burst-type workloads benefit) |
| **I5** | per-connection reply reactor (one task polls all session sockets) | `reader.rs:1132-1143` | Removes 4032 tasks/timers; saves one wakeup/schedule per reply (~0.2 µs) | High: state moves from task-local to shared tables (allowlist/flow/last_flow all need to move); recommend measuring I4 first before deciding |
| **I6** | >512 B sent directly as v3 SINGLE (codec already exists), without waiting for P4 | `reader.rs:665-716` | Saves 6–7 B per large reply; removes the v2 prefix cache | Low (client can already decode v3 SINGLE) |
| **I7** | merge reply-side stats/counters (once per frame instead of once per reply) | `reader.rs:267-272` | Minimal (thread-local, already cheap) | Low |
| **I8** | `initial_mtu` 1200→1400 (config default) | `tuning.rs:186-198` | Fewer fragments for large replies (18–23% packet count); ~1% for W32 small replies | Low (mirror both ends; black-hole fallback already exists) |

### 5.3 Combinations and Milestone Recommendations

1. **M0 (zero protocol risk, do first)**: I1 + I2 + I6 + I8, and **add measurement** (§7): obtain "status-quo DATAGRAM frame count
   vs QUIC packet count" and "multi-session downlink pps/CPU baseline".
2. **M1 (downlink bytes, low risk)**: P2 (first only "domain-name/IP flow binding", server-side `reply_src` +
   client binding table + compressed uplink confirmation) → domain-name/port-changing replies immediately save 7–8 B(v4)/19–20 B(v6). Can run in parallel with M0.
3. **M2 (control plane, availability)**: P3 `SESS_CLOSE` + `FLOW_CLOSE` (+ `CAPS` optional). This is the solution for churn and
   long-lived association degradation, independent of frame coalescing, with a guaranteed gain and low risk.
4. **M3 (structure, gain depends on measurement)**: I4 connection-level stager + P1 `TRAIN_X`. Only worth full investment if M0 measures
   "quinn coalescing does not take effect, and multi-session workloads account for a high share"; otherwise only do the fair scheduling
   part of I4 (G8).
5. **M4 (optional)**: P4/P5 v3-ification of large frames + compact FRAG; P7 connection-level id deferred.
6. **Full-duplex note**: the id/ACK semantics of P1/P2/P3 should serve the uplink as well — both sides share one connection-level stager
   abstraction (client uplink per-connection merging + server downlink per-connection merging),
   `FLOW_ACK/CLOSE` reused bidirectionally, avoiding another split where "the uplink is optimized but the downlink remains per-session".

### 5.4 Policy and Security Invariants (must be maintained by any scheme)

1. **Authentication is still done per flow/reply**: cross-session frame coalescing is only a "loading method"; each item must have passed the existing source authentication of `handle_session_reply`
   **before** entering the stager (allowlist ring or flow table fallback,
   `reader.rs:579-618`); flow installation still only happens "after the target has accepted a real send"
   (the `accepted` condition at `accept.rs:730-757`).
2. **SSRF unchanged**: target filtering happens on the **uplink/resolution** (`forward.rs:343-345`, `443-473`);
   downlink compression only changes "how the source address is expressed" and adds no reachable targets; `allow_private` semantics unchanged.
3. **Connection-level ids must not be resolved across sessions**: even with P7, the id table entry must carry its session,
   and the server must not resolve session A's id to session B's source; the client must look up its own table item by item using **the item's sess**
   (today's frame-level sess check is at `client/dispatcher.rs:251-254, 296-299`).
4. **full-cone remains opt-in**: server-initiated flows are only allowed under `ReplyFilter::FullCone`,
   and counted as unsolicited (`reader.rs:609-618`).
5. **Loss correlation**: the loss of one cross-session packet affects 1 datagram in each of N sessions simultaneously.
   By expectation, **the loss probability of each application datagram is unchanged** (N per packet, 1/N packets), but loss is
   **correlated across flows in time** (one qdisc drop hits 32 flows at once). No impact for DNS/one-shot requests;
   for RTP/games, it is recommended to give the stager a switch for "low-latency flows do not participate in cross-session frame coalescing"
   (classify by flow/port, or flush by item age). This also responds to the repository's
   "fate-sharing" concern about BATCH (`udp/send.rs:214-223`) — the conclusion is **expectation unchanged, bursts correlated, must be configurable**.

---

## 6. TCP Downlink (`src/tcp/pump.rs`)

- **Accuracy of the "zero-copy" claim**: for the QUIC→TCP (s2c) direction **it is accurate in userspace**:
  `recv.read_chunks(&mut batch)` fetches up to 8 `Bytes` at a time (slices from quinn's assembler,
  `pump.rs:367-390`), then `write_batch_vectored` hands them to the kernel in one syscall via `write_vectored`
  (`pump.rs:168-227, 412-416`) — **there is no payload memcpy inside the pump**.
  The copies that still exist are: the enqueue copy quinn itself does when receiving stream data, and the kernel's `copy_from_user`; neither can be
  eliminated by the application layer. The reverse direction (c2s) uses `write_chunk` to transfer ownership and avoid a copy (`pump.rs:306-322`,
  ≥8 KiB threshold `pump.rs:74`), also matching the comment.
- **Protocol-layer headroom: zero**. MQP-3 adds **no frame header** on TCP streams (the stream prefix is the address header; the dial ACK at
  `pump.rs:53-61` is only read once at connection establishment), so there is no "protocol header" to save on downlink bandwidth.
- All that remains is implementation/transport layer, and none of it is large:
  - `COPY_BATCH=8` (`pump.rs:83`) → each `write_vectored` handles at most ~11 KiB; raising it to 16/32 can
    reduce syscall count under heavy traffic (currently one write per ~11 KiB + one read lock per 8 segments);
  - idle watchdog/progress stamp already throttled to 100 ms (`pump.rs:91, 149-166`), no per-chunk overhead;
  - `initial_mtu`/window (§5.2 I8, `tuning.rs`) have greater impact;
  - each stream's 2×16 KiB double buffer is counted in `stream_pump_memory_bytes` (`tuning.rs:377-379`); it is a memory
    issue, not a bandwidth issue.
- Conclusion: **TCP downlink has no protocol-level optimization space**; do not change MQP-3 for TCP.

---

## 7. Validation Plan (not run in this task; gives the minimum credible measurement set)

1. **Measure the quinn coalescing rate (prerequisite for whether P1 is worth it)**:
   same connection, 32 sessions, 88 B replies, fixed pps; three numbers needed:
   (a) application reply count — `udp_stats::datagrams` (one count per `payload()`, `stats/udp_stats.rs:89-121`);
   (b) the **frame count** of `try_send_datagram` — the repo has no ready-made counter; the minimal change is to add a thread-local/atomic counter at the
   entry point `udp/send.rs:84-95` (measurement only);
   (c) **QUIC packet count** — server `tcpdump -i lo udp port <listen>` or quinn qlog (the
   `send_syscalls` statistic in `batch_report` counts syscalls **to the target on the last hop**, `udp/batch.rs:72-74`, unrelated to the downlink).
   `frame count/packet count` is the current coalescing rate; it determines which end of §3.2 the byte gain of P1 lands on.
2. **Downlink baseline of the status-quo per-session stager**: `examples/hotpath_bench.rs`'s `udpps/udppaced/
   udpmulti` (README already has loopback results, Linux 2–4 cores still missing, `README.md:866` acknowledges the gap);
   add a "32 sessions × 1 flow, 88 B, 50k pps" case.
3. **Multi-flow fan-out**: 1 session × 32 flows, 50k pps, compare server CPU/pps before and after I1.
4. **M1 (P2) byte validation**: packet capture of domain-name target replies, confirm the first frame `flow+inline` (13 B) then switches to compressed frames (5–6 B),
   and verify that when the binding frame is lost, falling back to inline does not black-hole.
5. **M2 (P3) availability validation**: churn stress test (100 associations/s, 5 s lifetime), compare `SESSION_FULL` counts
   (`stats/drops.rs`) with and without `SESS_CLOSE`.
6. **Correctness**: P1 needs new unit tests for "TRAIN_X per-item sess demux / out-of-order / cross-session authentication";
   P2 needs a "binding frame loss + rebinding" unit test; follow the end-to-end style of `server/tests.rs`.

---

## Appendix A: Key Arithmetic (reproducible)

- W32/88 B/B=1162: status-quo SINGLE body = `1+4+0+88 = 93`; packet = `55 + 3 + 93 = 151 B`.
  1000 replies → 1000 frames → **151,000 B**. Ideal coalescing: `floor(1162/(3+93)) = 12` frames/packet →
  `84 packets × 55 + 1000 × 96 = 100,620 B`.
- Connection-level A: item = `1+4+1+88 = 94`; `floor((1162−2)/94) = 12` items/frame → 84 frames →
  `84 × (55+3+2+12×94) ≈ 99,040 B` (one packet per frame, because frame body 1131 B plus 55+3 is already close to 1200).
- Connection-level C: item = `1+2+1+88 = 92`; `floor(1160/92) = 12` items/frame → 84 frames → 97,040 B.
- Single session 32 flows: item = `1+1+1+88 = 91`; `floor((1162−6)/91) = 12` items/frame → 84 frames (already close to optimal).
- Domain-name/port-changing inline: `1+4+1+7+88 = 101 B`; compressed: `1+4+88 = 93 B` (extra flow adds another +1 B = 94) →
  v4 saves 7–8 B; v6 inline `1+4+1+19+88 = 113` → saves 19–20 B.
- Session memory: `2×(2×64 KiB) + 8 KiB + 1 + 4 KiB = 274,433 B`;
  churn critical point = `8192 / 180 s ≈ 45.5 /s`.

## Appendix B: Index of Key Symbols Cited in This Document

- Downlink reader: `src/bin/myquic2-server/reader.rs:720-941` (task), `:480-717` (per reply),
  `:215-298` (flush), `:124-174` (staging)
- Session table/lifecycle: `table.rs:12-57` (SessEntry), `:310-333` (sweep), `:374-382` (limit/idle)
- Authentication/allowlist: `pin.rs:22-54`, `reader.rs:579-618`
- Protocol codec: `mqp/v3.rs:22-66` (constants), `:151-198` (SINGLE), `:285-347` (TRAIN),
  `:542-671` (FRAG), `:684-792` (FlowTable)
- Send: `udp/send.rs:84-95`, `udp/fragmenter.rs:178-394`
- Client downlink: `client/dispatcher.rs:225-344` (v3 dispatch), `:663-723` (flush), `:769-849` (drain)
- Config/memory: `config/tuning.rs:116-133, 282-317`, `lib.rs:244`, `transport/limits.rs:84`

---

## Summary for the Lead

1. The downlink root cause is **send context granularity = session**: one socket/task/private stager per session (reader.rs:720-766,1132-1143), while the TRAIN header carries a single sess (v3.rs:63) → cross-session replies cannot be frame-coalesced at the protocol level.
2. Small replies are **already batched well within a single session** (≤64 items within budget); what is missing is multiple sessions replying at the same time, and a single session alternating replies across multiple flows.
3. W32 (32 sessions, 1 flow, 88 B, 1000 replies, B=1162): status quo 1000 frames/1000 sends/1000 allocations; connection-level stager (TRAIN_X, sess u32 per item) = 84/84/84 (11.9×).
4. Wire bytes: **−34.4% if quinn coalescing does not take effect; only −1.6% if ideal coalescing** (B=1362: −34.9% / −1.6%). The real value is between the two; **11.9× frames/calls/allocations is a guaranteed gain**.
5. 28 B small packets: 30 frames, no-coalescing bound −60.7%, ideal-coalescing bound −5.2%; 200 B: −17.1% / −0.5%. The smaller the reply, the more valuable frame coalescing.
6. CPU: frame coalescing only saves quinn send+allocation ≈0.25 µs/reply, minus stager enqueue ≈ −0.18~−0.22 µs (server −11~14%), 50k pps ≈ 1% of one core; the bulk is 1 recv syscall + 1 send syscall + 1 wakeup per reply, which the protocol cannot change.
7. The downlink's "free" bytes are in compression: domain-name/port-changing/full-cone replies are always inline (13 B vs 5–6 B). **First-frame binding has 0 byte cost** (flow+inline and NO_FLOW+inline are both 13 B) → saves **7–8 B(v4)/19–20 B(v6)** per such reply; this is P2, more deterministic than P1.
8. P2 mechanism: first reply flow+inline establishes binding → client learns source → its compressed uplink frame is the implicit ACK → server switches to compressed; source drift rebinds; no new control frame needed (FLOW_ACK's independent value is uplink-only flows).
9. The control-plane gap is lifecycle, not bandwidth: churn > **45 associations/s** may fill the 8192 pool (zombie×268 KiB); without FLOW_CLOSE, after 64 flows are used up the association is **permanently inline** (+7–8 B/reply).
10. >512 B falls out of v3 (MQP-2 12 B header; fragmentation 18 B/fragment): large replies save 6–7 B(v4)/18 B(v6), the codec already exists (v3 SINGLE/FRAG), it is a "wiring"-level change.
11. Protocol ranking: P2 (domain binding, deterministic bytes) → P3 (close, deterministic availability) → P4/I6 (large frames v3) → P1+I4 (cross-session frame coalescing, gain depends on coalescing measurement) → P6 CAPS → P7 connection-level id (deferred).
12. Do the pure implementation layer first: I1 reuse the flow id from auth + per-reader source→flow memo (32-flow fan-out −50~150 ns/reply), I2 no arena copy when run==1, I6 >512 B send directly as v3 SINGLE, I8 initial_mtu 1400.
13. The single-session 32-flow VPN scenario **cannot benefit from P1** (already frame-coalesced); its gains are in I1/P2/I6.
14. G8: the 1 MiB DATAGRAM buffer shared per connection has no fairness; one flow can cause other sessions to be judged Blocked and dropped; the connection-level stager (I4) is the landing point.
15. Security invariants: per-reply authentication unchanged (reader.rs:579-618), SSRF unchanged, connection-level ids must not be resolved across sessions, full-cone remains opt-in.
16. The TCP downlink zero-copy claim holds in userspace (read_chunks+write_vectored); MQP-3 has no frame header on streams → **TCP downlink has no protocol-level gain**.
17. Must measure first: status-quo "1000 replies = how many QUIC packets" (determines where P1's gain lands) + 32 sessions × 88 B pps/CPU baseline (README:866 acknowledges the Linux gap).
18. Recommended milestones: M0=I1+I2+I6+I8+measurement; M1=P2; M2=P3; M3=I4+P1 (depending on measurement); M4=P4/P5.
19. The highest risk is P1: it requires a new connection-level stager (I4), a flush policy (flush on drain, no artificial waiting), and handling cross-session loss correlation (expected loss rate unchanged, but bursts correlated, needs a configurable switch).
20. Full-duplex: the id/ACK semantics of P1/P2/P3 should share one connection-level abstraction for uplink/downlink, avoiding a split between the two sides.
