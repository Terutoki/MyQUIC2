# MQP-2 Protocol-Layer Performance Analysis and MQP-3 Redesign Recommendations

> Analysis date: 2026-10-20 · Baseline commit: `348c52d`
> Scope: **analyzes only the MQP-2 wire protocol / frame semantics / protocol state machine**.
> Code-level hotspots (thread topology, recvmmsg copies, reassembler eviction, statistics atomics, etc.) are covered in `PERF_ANALYSIS.md` and are not repeated here.
> All byte counts/percentages in this document are **model estimates** (no packet loss, IPv4, MTU 1200, quinn coalescing DATAGRAM frames),
> intended to judge magnitude and direction; final gains must be re-measured on a Linux target machine with `examples/hotpath_bench.rs`.

---

## 0. Conclusion (TL;DR)

1. **MQP-2's wire format is already close to optimal for bulk traffic.**
   The 12 B IPv4 header of a single frame is only 0.9% of a 1200 B payload; in a 60 B small packet it accounts for 16% of the incremental bytes,
   but the IP+UDP+QUIC fixed overhead in the same packet is 55 B, 4.6× the former.
   **Therefore "rewriting the protocol" has a very low ceiling for throughput-oriented workloads (≤1%), and is not worth doing for throughput.**

2. **The protocol layer still has four areas of real headroom, concentrated in "small packets / multiple destinations / domain targets / high pps":**

   | ID | Structural problem | Current cost | Eliminable ratio (model) |
   |---|---|---|---|
   | P1 | Each frame repeatedly carries the destination address; session and destination are not decoupled | IPv4 7 B, IPv6 19 B, domain 4+L B/frame; downlink replies also echo the source address | 9–11% for small packets, 33–38% for domains |
   | P2 | BATCH only supports the same destination; the client only does 2-pack; downlink flushes whenever the source changes | Multi-destination/multi-source bursts degrade to per-packet sends | 15% bandwidth in fan-out scenarios, 5–18× send calls |
   | P3 | Fragment headers repeat the full address + sess; the reassembly key is redundant | v4 18 B/fragment, v6 30 B/fragment, domain 15+L B/fragment | Saves 6–19 B per fragment; saves 30+ B for domains |
   | P4 | No control plane: no capability negotiation, no explicit close, no flow reject/ack | Sessions are reclaimed via 180 s idle; new features require same-version deployment; the default ALPN `h3` cannot enforce version gating | Resource reclamation/gradual-rollout capability, not pure byte savings |

3. **The proposed redesign is not a "tear-down and rebuild", but an incremental MQP-3 extension:**
   - Introduce **two-level session → flow multiplexing**: a flow binds one `(association, destination)`; data frames carry only
     `type|flags | sess u32 | [flow u8]` (5 B in steady state, 6 B with flow), and the address appears only once in the first frame that creates the flow.
   - Introduce **TRAIN**: a single QUIC DATAGRAM can aggregate payloads from multiple flows / multiple destinations, with lengths encoded as varint;
     consecutive items of the same flow are 2 B/item, items of different flows are 3 B/item.
   - Introduce **compact FRAG**: remove the per-fragment address; the reassembly key becomes `(sess, flow, id)`; the fragment header is 11–12 B.
   - Introduce **CAPS/HELLO negotiation + CLOSE control frames**: old peers automatically fall back to MQP-2, new peers enable it progressively; sessions/flows are released explicitly,
     with 180 s idle only as a fallback.

4. **Quantified expectations (model, conservatively keeping sess as u32):**
   - Small single-frame packets: wire −9.4% (IPv4 60 B, without batching); domain targets −33.4%.
   - Multi-destination fan-out: wire −15.4% (IPv4), −37.8% (domain); quinn send calls reduced **18×**.
   - Same-destination small packets: relative to the current 2-pack, wire −10.8% and 9× fewer calls; but relative to the same wire protocol with
     "16-pack already implemented", only −1.4% / 1.1× remain — **showing that the main gain for same-destination traffic comes from the implementation-layer N-pack, not the new protocol**.
   - 1200–1420 B bulk/fragments: wire −0.9–1.1%, calls unchanged — the protocol redesign is essentially imperceptible for bulk.
   - CPU: estimated at 200–300 ns per `send_datagram` call, small-packet scenarios at 50–100k pps can save **1–3% of one core**;
     this is the gain from "fewer quinn calls/allocations", not from protocol header bytes.

5. **Prioritization recommendations:**
   - **Phase 0 (no wire changes, do first)**: client N-pack (F8), batch by budget rather than fixed 16/512,
     raise `initial_mtu` from 1200 to 1360/1400 on known paths. This batch captures most of the CPU gains in same-destination scenarios.
   - **Phase 1 (MQP-3 core)**: HELLO/CAPS + flow address compression + TRAIN + compact FRAG.
   - **Phase 2 (control plane/robustness)**: explicit CLOSE, FLOW_ACK/REJECT, optional per-flow FEC,
     negotiated larger reassembly limit.
   - **Phase 3 (optional)**: cross-session train, session id u16, NACK/retransmission. Not done by default.

> In short: **MQP-2 is not the main bottleneck for current performance; if the goal is high pps, constrained uplink, domain targets, or multi-destination fan-out,
> MQP-3's flow-ification + train-ification is worth doing; if the goal is only bulk throughput, tune MTU/window first and leave the protocol alone.**

---

## 1. Analysis Basis and Key Facts

### 1.1 Data Path

```text
TCP:  QUIC stream head (atyp|addr|port) + raw bytes        (already zero-copy, no protocol header issue)
UDP:  MQP-2 frame → quinn DATAGRAM → QUIC packet → IP/UDP
```

MQP-2's UDP frames have exactly three shapes (`src/mqp/`):

| Frame | Wire format | Fixed header (IPv4 / IPv6 / domain L) |
|---|---|---|
| DATAGRAM | `0x02 \| sess u32 \| atyp \| addr \| port \| payload` | 12 / 24 / 9+L |
| FRAGMENT | `0x05 \| sess u32 \| id u32 \| idx u8 \| total u8 \| atyp \| addr \| port \| chunk` | 18 / 30 / 15+L |
| BATCH | `0x06 \| sess u32 \| atyp \| addr \| port \| count u8 \| (len u16 \| payload)*` | 13 / 25 / 10+L + 2/item |

Sources: `src/mqp/datagram.rs:11` (`DGRAM_PREFIX_LEN=5`), `src/mqp/fragment.rs:29`
(`FRAG_PREFIX_LEN=11`), `src/mqp/batch.rs:5-9`. Address encoding is consistent with SOCKS5
(`src/mqp/addr.rs:114-160`).

### 1.2 quinn Already Coalesces Multiple DATAGRAM Frames into the Same QUIC Packet

This determines the real benefit boundary of "MQP-layer batching". The send path in quinn-proto 0.11.19:

```rust
// quinn-proto-0.11.19/src/connection/mod.rs:3352
while buf.len() + Datagram::SIZE_BOUND < max_size && space_id == SpaceId::Data {
    match self.datagrams.write(buf, max_size) { ... }
}
```

`Datagram::encode` adds only `1 B type + varint len` per frame (`frame.rs:896-907`). That is:
**multiple independent `send_datagram()` calls share one UDP/IP packet as long as they are queued in the same transmit poll.**
Therefore the benefit of MQP `BATCH` is not "saving IP/UDP headers" (quinn already does that), but:

1. N−1 fewer `send_datagram_wait()` calls: each requires taking the quinn connection-state mutex, checking the send buffer,
   and waking the driver (quantified in PERF_ANALYSIS F8/F10);
2. N−1 fewer exact-capacity allocations for MQP frames (`Vec::with_capacity` → `Bytes::from`);
3. N−1 fewer QUIC DATAGRAM frame headers (1+varint per frame, about 2–3 B);
4. N−1 fewer sets of MQP `type|sess|addr` headers (currently 12 B/frame).

Items 1 and 2 are CPU gains; items 3 and 4 are bandwidth gains. **Items 1 and 2 are unrelated to the wire format**, so
the implementation-layer N-pack in Phase 0 captures most of them; only item 4 requires MQP-3's address compression.

### 1.3 Per-Packet Overhead Model

With IPv4 and MTU 1200:

- `max_datagram_size()` ≈ 1162 B (QUIC DATAGRAM body budget; `src/mqp/datagram.rs:32-42`);
- Fixed overhead of every QUIC packet carrying data: IP 20 + UDP 8 + QUIC short header
  (flags 1 + DCID 8 + PN 2 + AEAD 16) = **55 B**;
- Each DATAGRAM frame adds 1 + varint(len) = 2 B (≤63 B body) or 3 B.

Thus the wire cost of a single 60 B payload frame is approximately `60 + 12 (MQP) + 3 (DQH) + 55 = 130 B`;
of which the MQP header is 9.2% and QUIC/IP/UDP is 42.3%. **This is exactly where the "ceiling" for the MQP header sits.**

---

## 2. MQP-2 Byte Costs and Structural Boundaries

### 2.1 Single-Frame Cost and MQP Header Share (IPv4)

| payload | Frame body | Wire (single frame occupies one packet) | MQP header share of wire | MQP header share of incremental bytes* |
|---:|---:|---:|---:|---:|
| 28 B (STUN) | 40 | 97 B | 12.4% | 28.6% |
| 60 B (DNS) | 72 | 129 B | 9.3% | 16.0% |
| 200 B (game) | 212 | 269 B | 4.5% | 5.6% |
| 1200 B | 1212 | 1269 B | 0.95% | 0.99% |
| domain 30 + 60 B | 99 | 156 B | 25.0% | 39.6% |

\* Incremental bytes = payload + MQP header + DATAGRAM header, excluding the 55 B IP/UDP/QUIC fixed overhead.
When quinn coalesces multiple frames into one packet, the 55 B is amortized and the MQP header's share moves toward the "incremental bytes" column.

This table yields two conclusions:

- **bulk (≥1200 B)**: MQP header <1%, changing the protocol is meaningless;
- **tiny (≤60 B)**: MQP header accounts for 16–29% of incremental bytes, with domain targets approaching 40%; there is real headroom here,
  but at most this 16–40% can be compressed to 7–9%.

### 2.2 Boundaries of BATCH

`MAX_BATCH_ITEMS = 16`, `BATCH_SMALL_MAX = 512` (`src/mqp/batch.rs:7-9`):

- With a 28 B payload, 16 items fill only `13 + 16×30 = 493 B`, less than 43% of the 1162 B budget;
- For 60 B it is `13 + 16×62 = 1005 B`, close to the budget;
- The 512 B cap means two 600 B payloads cannot be combined into one frame even with the same destination;
- The client currently only does **2-pack** (`src/bin/myquic2-client/assoc.rs:295-360`);
- Server downlink batches by `(ip, port)` run, flushing as soon as the source changes (`src/bin/myquic2-server/reader.rs:138-161`).

So "multi-destination/multi-source bursts" are structurally beyond BATCH's reach: when a DNS client queries 32 resolvers in turn,
or a game session receives packets from 8 peers simultaneously, every packet is currently an independent frame.

### 2.3 Fragment Path

`DgramFragmenter` carries the full address in every fragment (`src/mqp/fragment.rs:180-192` explicitly states this is for
"self-describing / no special handling required for out-of-order"). The cost:

- 2 fragments for 1420 B (typical WireGuard at MTU 1200): 18 B header per fragment, 36 B total, 2.5% of the payload;
- Domain 30 + 2 fragments: 45 B per fragment, 90 B total, 6.3% of the payload;
- Each fragment is an independent `send_datagram` + one exact allocation + one quinn state lock;
- The reassembler key is `(sess, id)`; the address is repeated but does not participate in the key.

At the same MTU, the number of fragment packets is determined by the chunk size, and **TRAIN cannot reduce the packet count when "each fragment is close to full MTU"**,
so fragment optimization is mainly "shorter per-fragment headers", not "fewer packets". This is also why "fragment train" is not listed as core later.

### 2.4 Downlink Address Echo

Every UDP downlink reply carries the destination address because the client needs it to fill the SOCKS5 UDP response header
(`stage_reply` / `send_reply` in `src/bin/myquic2-client/dispatcher.rs`). This is a **protocol semantic requirement**,
not redundancy; but it can be replaced by flow binding: the client already knows the destination when sending, and the flow id can be used to look it up.

### 2.5 Fixed Costs the Protocol Cannot Solve

Every outbound datagram still involves:

- One exact-capacity allocation for the MQP frame (the in-place fast path of `Bytes::from(Vec)`, already optimal);
- One payload copy into the frame;
- One state lock for quinn `send_datagram_wait` + one driver wake;
- Another copy inside quinn into the packet buffer.

MQP-3 can reduce the "number of times" for items 1 and 3, but **cannot eliminate a single copy**, nor bypass quinn's API.
This is the upper bound when evaluating "how much the redesign can bring".

---

## 3. List of Structural Problems

### P1 [Protocol Core] Repeated Address per Frame, Session and Destination Not Decoupled

**Current state**: `sess` identifies a UDP ASSOCIATE, but every DATAGRAM/FRAGMENT must carry the destination or source address again.
- An association usually communicates with only one target (DNS resolver, game server, WireGuard peer),
  and the address is basically unchanged over the session lifetime; repeating it per packet is pure redundancy.
- Domain targets have the largest redundancy: a 30 B domain + port is 35 B per packet, so a 60 B DNS query has an actual MQP header of 39 B,
  65% of the payload.
- On downlink the server already knows the `(sess, source)` correspondence of a reply, yet still has to echo the address in every frame.

**Impact**:
- Small-packet bandwidth (especially domain targets);
- Per-frame `AddrHeader::header()` validation / encoding (although `DgramPrefixCache` has reduced the steady-state same-target cost to
  one comparison, domain comparison is still a string comparison);
- **Prevents cross-destination frame aggregation** (the BATCH header has only one address).

### P2 [Structure] BATCH's "Same Destination" Constraint + Client 2-pack + Downlink source-change flush

**Current state**:
- The client only does 2-pack when two adjacent ≤512 B payloads have the same destination and the same egress bind;
- Server downlink stages ≤512 B replies by `(ip, port)` run, flushing when the source changes;
- `MAX_BATCH_ITEMS=16` fills only 43% of the budget for a 28 B payload.

**Impact**:
- Multi-destination fanout (DNS / games / WebRTC) degrades completely to per-packet;
- Even same-destination small packets are combined only 2 at a time;
- Downlink multi-source burst aggregation is limited by source changes.

**Note**: Half of this is an **implementation problem** (F8 is deferred), and half is a **protocol problem** (there is no flow concept,
so the batch header can share only one address). Phase 0 solves the same-destination half; MQP-3 solves the multi-destination half.

### P3 [Structure] FRAGMENT Header and Reassembly Key Redundancy

- Each fragment repeats 11 B fixed + full address;
- Reassembly key `(sess, id)`, but the address does not participate in the key;
- Each fragment is an independent quinn send / allocation;
- The 32-bit id is necessary (16-bit has a packet-loss cliff at 21845/s under a 3 s reassembly window,
  and the comment at `src/mqp/fragment.rs:19-28` already provides historical data), **do not change it back to u16 just to save 2 B**.

### P4 [Structure] No Control Plane

Currently there is no:
- Capability negotiation: new frame types rely on "same-version deployment"; the default ALPN is `h3` (`src/mqp/ack.rs:8-24`),
  with no version gating; `myquic2/3` also requires explicit configuration;
- Explicit session close: after the client's SOCKS TCP connection is closed, the server session still lives for `SESS_IDLE_MS = 180000`
  (`src/bin/myquic2-server/table.rs:365`), holding a socket + 64 KiB kernel buffer + reader task during that time;
- flow reject / ack: if address compression is implemented in the future, it is necessary to know "whether the peer has established the mapping";
- Negotiable reassembly limit: 8 KiB is a compile-time constant (`src/mqp/fragment.rs:47`) and cannot be adjusted per deployment.

This is not purely a bandwidth issue, but it directly affects "whether incremental protocol upgrades can be done safely" and "resource usage under short-session churn".

### P5 [Optional] No Recovery Mechanism for Fragments

The arrival rate of an `F`-fragment payload is `(1−p)^F`; at MTU 1200 a 1420 B payload is 2 fragments,
and with 1% packet loss the arrival rate is 98.01% (loss doubles relative to no packet loss). The protocol layer can optionally:
- **FEC**: add 1 XOR parity per k data fragments to recover any 1 lost fragment;
- **NACK/selective retransmission**: requires an ACK channel, latency +1 RTT.

Neither is worth enabling by default: FEC has high overhead when k is small (2 fragments + 1 parity = +50% bytes),
and NACK changes UDP semantics and requires a new state machine. Defer to Phase 2/3, opt-in per deployment and packet-loss rate.

### P6 [Non-Protocol] MTU Starting Value

`DEFAULT_INITIAL_MTU = 1200` (`src/config/tuning.rs:192`). At MTU 1200:
- DATAGRAM budget 1162 B, IPv4 MQP payload cap 1150 B;
- Any UDP payload >1150 B will be fragmented;
- Before PMTU discovery ramps up, there are 18–23% more packets.

On known paths (WireGuard-1420, PPPoE, Ethernet), raising `initial_mtu` to 1360/1400/1472
is **a cheaper single change with larger gains than any MQP redesign**. What the protocol layer can do is negotiate "the reassembly limit acceptable to the peer",
but MTU itself is a transport configuration and should not be mixed into the MQP frame format.

---

## 4. MQP-3: A Flow-Centric Incremental Protocol

### 4.1 Design Goals and Hard Constraints

**Goals**:
1. Steady-state data frames carry no address; the smaller the packet, the greater the gain;
2. A single QUIC DATAGRAM can aggregate payloads from multiple destinations/multiple sessions;
3. Shorter fragment headers and a shorter reassembly key, without changing the UDP semantics of "any lost fragment discards the whole packet";
4. No added first-packet RTT, no waiting, no change to the existing TCP path;
5. Old peers can continue using MQP-2; new peers negotiate via CAPS;
6. All tables/queues are bounded; no new memory amplifier may be given to unauthenticated peers.

**Hard constraints** (from the existing implementation):
- QUIC DATAGRAM is the only suitable carrier; QUIC streams would introduce HOL + retransmission into UDP and cannot be used for the data plane;
- Frame decoding must "drop only one DATAGRAM on an unknown type" and must not break the connection (the existing decoder already satisfies this);
- Keep the 32-bit fragment id (reassembly window safety);
- Keep the 8 KiB payload cap, 2 s partial timeout, and 256 KiB/connection reassembly budget;
- auth/SSRF/full-cone/allowlist semantics unchanged;
- Default ALPN `h3` unchanged (in-band CAPS is used for capability gating).

### 4.2 Core Abstraction: Session and Flow

```text
session (u32, preserves existing semantics: one UDP ASSOCIATE)
  └── flow (u8, client-assigned, 0 = primary)
        = one destination (atyp|addr|port)
        + one server-side session socket
        + one client-side relay/app binding
```

- **flow 0**: the session's first destination, and the default reply path; data frames can omit the flow byte entirely.
- **flow 1..255**: additional destinations of the same association. Data frames carry a 1 B flow id.
- Once a flow is established, its dest does not change; the client sends on the flow, and the server uses `(sess, flow)` to recover
  the dest / allowlist / session socket; downlink replies use the flow id to express "which target's reply this is",
  and the client uses its local flow table to reconstruct the SOCKS5 response header.
- Within the same session, the same dest reuses the same flow; different sessions are different flows even if the dest is the same
  (because the relay socket / app binding differs).

**Why not "one QUIC connection per destination"**: connection-level state (handshake, CC, 14 MiB transport budget)
is far larger than a flow table; and MQP's connection multiplexing exists precisely to avoid this.

**Why not an HPACK-style dynamic dictionary**: flow binding is already sufficient, and there is no need to maintain a bidirectionally synchronized compression context;
the flow id is assigned by the client and mirrored by the server, which is simple semantics.

### 4.3 Frame Format (MQP-3, Enabled After Negotiation)

The first byte uses **high 4 bits for type + low 4 bits for flags**:

```text
bit 7..4 : kind    0x1 SINGLE, 0x2 TRAIN, 0x3 FRAG, 0x4 CTL
bit 3..0 : flags   I=INLINE_ADDR, F=FLOW_PRESENT, S=SRC_OVERRIDE, R=reserved

Common part: sess u32 LE (keeps the current width; see the u16 discussion in §4.10)
```

#### (a) SINGLE — single payload

```text
[0x10 | flags] [sess u32] [flow u8 if F] [atyp|addr|port if I] [payload]
```

- Steady state, flow 0: `0x10 | sess | payload` = **5 B header**;
- Additional flow: `0x12 | sess | flow | payload` = **6 B header**;
- First frame of a new flow / new session: `0x13 | sess | flow | addr | payload`, 12 B for IPv4,
  the same as MQP-2's 12 B (v6 20 B vs 24 B, domain 1 B worse), **no penalty on the first frame**.

#### (b) TRAIN — multi-payload frame aggregation

```text
[0x20 | flags] [sess u32] [count u8]
  [flow u8 if same-flow and flow != 0]
  item*: [iflg u8] [flow u8 if iflg.F] [len varint] [atyp|addr if iflg.I] [payload]
```

- Header 6 B; consecutive same-flow items: `iflg + len8` = 2 B/item (same as the current BATCH's `len u16`);
- The `SAME_FLOW` flag is only used for **non-zero flows**: flow 0 is implicit; if set, the decoder would
  misread the first item's `iflg` as the flow. An all-compressed TRAIN for flow 0 uses the mixed form
  (flag cleared, no flow byte per item); the wire size is the same as when the flag is set.
- Mixed flows: +1 B flow = 3 B/item;
- One-off destinations: +7/19/4+L B inline addr, but still share one quinn send with the other items;
- `count` has no fixed 16 cap: the encoder fills up to `limit`, and the decoder validates `count` and boundaries;
  the negotiated `max_train_items` provides a defensive cap (e.g. 64).
- Same-destination small packets (28 B): `6 + 38×30 = 1146 B`, about 38 items/frame;
- Mixed 8 destinations, 200 B: `6 + 5×(3+200) = 1021 B`, 5 items/frame.

**Flush rules are the same as now**: only packets that have already arrived in the current drain burst are included, and the frame is sent when the burst ends, without waiting for it to fill.
Thus latency is not increased; the `count` cap is only defensive and does not participate in scheduling.

#### (c) FRAG — fragment

```text
[0x30 | flags] [sess u32] [flow u8 if F] [id u32] [idx u8] [total u8] [addr if I] [chunk]
```

- Steady state (flow 0): 11 B header; additional flow: 12 B; currently v4 is 18 B;
- The address is no longer repeated per fragment; only the first few fragments of a new flow carry `I`, ensuring routability before the flow is established;
- The reassembly key becomes `(sess, flow, id)`, where `id` is still u32;
- Out-of-order/lost-fragment semantics unchanged: if any fragment is missing, the partial expires after 2 s.

**No fragment train**: at MTU 1200 each fragment chunk is ≈1144 B, so one QUIC DATAGRAM can basically hold only one fragment;
packing multiple fragments into one train does not reduce the packet count and only adds encoding complexity. What is actually worth doing is "shorter fragment headers".

#### (d) CTL — control frame

```text
[0x4X] [opcode u8] [body]
```

| opcode | Direction | Semantics |
|---|---|---|
| `HELLO` | C→S | magic `M3` + version + flags; sent after the connection is established, retried several times |
| `CAPS` | S→C | version + flags + `max_train_items` + `max_flows/session` + `max_reassembly` |
| `FLOW_ACK` | S→C | `(sess, flow)` established (acknowledgment for uplink one-way flows) |
| `FLOW_REJECT` | S→C | `(sess, flow, reason)`; the client falls back to inline for that destination |
| `FLOW_CLOSE` | C→S | release one flow (retryable; idle as fallback) |
| `SESS_CLOSE` | C→S | release the entire session (socket/task/flow reclaimed immediately) |

Control frames are all idempotent and may be repeated; loss of a control frame does not cause connection failure — at worst it delays compression/release.

### 4.4 Self-Healing Process of Address Compression

UDP is unreliable, so "once a flow is established it can always still route" cannot be assumed. The design is **inline on the first frame, confirmed after a reply is received**:

```text
client                                          server
  |-- SINGLE I|F (sess,flow=0,addr,payload) ---->|  validate SSRF; create/reuse session; register flow
  |                                               |  send to target
  |<------------- SINGLE (sess,flow=0,payload) --|  reply carries flow; client confirms mapping
  |-- SINGLE (sess,flow=0,payload) ------------->|  all subsequent frames have 5 B headers
```

- The client maintains `state = Inline | Compressed` for each flow;
- The first N frames of a new flow (e.g. 3 frames) continue to carry `I`; after receiving a downlink frame for that flow, it transitions to `Compressed`;
- For pure uplink flows (no reply), the server sends `FLOW_ACK` after registration; the client transitions to `Compressed` after receiving the ack;
- On `FLOW_REJECT`/table full, it stays `Inline` (equivalent to today's 12 B header) and will not black-hole;
- Server table entries exist only within the session lifetime; **active flows are not evicted while the session is alive**; if the table is full, the request is rejected and
  the client falls back to inline. The whole table is released when the session is destroyed.
- flow ids are not reused within a session; if all 256 are exhausted, new destinations continue inline. This avoids the splice risk of
  "reusing an id and splicing leftover fragments of the old flow into the new flow" (analogous to the safety window for fragment ids).
- If reuse is desired in the future, it must satisfy `now - last_close >= FRAG_ID_SAFE_WINDOW_MS` and the old flow must have no partial.
  The first version recommends not doing reuse at all.

> **Current implementation (2026-10-20)**: there is no FLOW_ACK/REJECT. An IP flow stays inline
> until a **compressed downlink frame** for that flow is received and successfully staged
> (the server only encodes it this way when its flow table is installed), and only then
> is it compressed. Pure uplink flows that receive no reply remain inline; the cost is
> 1 extra B of flow + address per frame, but it will not permanently black-hole due to
> loss of the first few frames. Domain targets are inline every frame (see §4.5).

### 4.5 Downlink Addresses and full-cone

- Normal replies: the server marks them with the flow id, and the client obtains `(atyp|addr|port)` from its local flow table and writes the SOCKS5 header;
  **the address no longer appears on the wire**. The current implementation only does this for **IP targets**; a domain target's flow table entry is
  `TargetAddr::Domain`, and the client has no resolved source IP, so the downlink remains inline.
- A target replies from another port of the same IP (allowed by the existing allowlist): the server sets `S` on that flow's frame and inlines
  the actual source address; the client uses the in-frame address to write the SOCKS5 header. +7/19 B, occurring only for exceptional sources.
- Unsolicited sources with `udp_full_cone = true`: no flow is found, so delivery uses `SINGLE I` (sess + inline addr);
  the client routes by `sess`. Semantics are exactly the same as now, just without compression.
- The server's reply allowlist ring (16 entries) is retained; the flow table only provides the flow id after a ring hit,
  and does not add per-packet lookup cost.
- However, the ring has only 16 IPs, and fan-out such as 32 resolvers will evict early targets. The current implementation uses the
  **exact `(sess, flow) -> IP` mapping** as a second authorization source when the ring misses: the target has already passed SSRF/send validation
  when the flow was established, so even if the ring later evicts it, its replies can still pass; domain flows (no resolved IP) do not participate in this path.
  This avoids expanding the ring to 32/64 and avoids enabling full-cone.

### 4.6 Capability Negotiation and Gradual Rollout

> **The current implementation (2026-10-20) does not enable the mechanisms in this section.** Under the
> deployment assumption of "no longer compatible with MQP-2 peers", the client sends MQP-3 directly,
> and the server accepts both MQP-2/3 decoding but also uses MQP-3 on the downlink; there is no
> HELLO/CAPS, and no `mqp3=false` rollback switch. The following is retained as the design for when
> gradual rollout is needed.

```text
new client                                  old server
  |-- CTL HELLO (0x4x, "M3", ver, flags) --->|   unknown type → drop that DATAGRAM, connection unaffected
  |   (retry 3x)                              |
  |-- MQP-2 data ---------------------------->|   continues to work
```

```text
new client                                  new server
  |-- HELLO -------------------------------->|   recognized
  |<--------------------------- CAPS --------|   MQP-3 supported
  |-- MQP-3 frames ------------------------->|   server RX always accepts both; TX switches after the first MQP-3 frame is received
  |<--------------------------- MQP-3 -------|
```

- **New client + old server**: HELLO is dropped, no CAPS → the client stays on MQP-2 forever.
- **Old client + new server**: the old client does not send HELLO → the server does not send CAPS and continues with MQP-2.
- The server switches downlink encoding only **after receiving the first MQP-3 frame**, avoiding reply black-holing when CAPS is lost
  by sending the new format to a client that has not yet upgraded.
- CAPS lost: the client retries HELLO; the server resends CAPS for every HELLO.
- The default ALPN can still remain `h3`; deployments requiring hard gating can explicitly set `alpn = "myquic2/4"`.
- Provide a configuration switch (e.g. `mqp3 = false`) for rollback; when disabled, CAPS is not sent and MQP-3 is not used proactively.

**Why not "just bump ALPN"**: `h3` masquerading is the current default; forcing a bump would lose this feature.
CAPS is in-band capability negotiation, which neither breaks the masquerade nor prevents safe gradual rollout. ALPN bump remains an option for deployments that need
fail-closed behavior.

### 4.7 Security and Resource Boundaries

| Resource | Cap | Notes |
|---|---|---|
| flows / session | 64 (currently fixed; safety margin left in the u8 id space) | `FlowTable` is a fixed array; when full, the client falls back to `NO_FLOW` inline |
| flows / connection | no additional global table (one 64-slot table per session) | server sessions globally 8192, about 4 MiB memory |
| train items | negotiated 64 | validated by the decoder; defensive only, encoding is by budget |
| reassembly | existing 8 KiB / 256 KiB / 2 s | unchanged |
| flow table memory | ≈ 40–64 B per entry | 8192 sessions × 64 flows × 64 B ≈ 32 MiB (worst case) |

- On the server, **every frame** still goes through the SSRF and allowlist checks of `resolve_fast` / `forward_server_dgram`;
  the flow table itself does not bypass SSRF. The exact IP it records serves as a second authorization source only when the 16-entry
  allowlist ring misses (it already passed send validation before installation), and it cannot authorize a target that was never sent to
  out of thin air. Domain flows are also re-filtered when re-resolved, preventing DNS rebinding from turning an established flow into an
  internal-network stepping stone.
- The flow id is chosen by the client, and the server only accepts mappings "within an authenticated connection"; it will not route across
  sessions due to flow id conflicts.
- If the same flow id is inlined with a different address, the server deletes that mapping and subsequent compressed frames are dropped as
  an unknown flow, so the payload will not be redirected to the old target.
- full-cone unsolicited sources take the inline path and are not written to the flow table (avoiding being flooded by arbitrary sources).
- Does not change auth, TLS, connection admission, session fair-share, or UDP full-cone policy.

### 4.8 Relationship with the TCP Path

**Unchanged.** The TCP address appears only once in the stream head, which is already optimal at the protocol layer; MQP-3 only changes UDP DATAGRAM.

### 4.9 Explicitly Out of Scope

- Do not put UDP on QUIC streams: HOL + retransmission would turn "packet loss" into "latency";
- No fragment train: each fragment is close to MTU, so the packet count will not decrease;
- No cross-session train (first version): it would require a connection-level shared send queue; quinn already coalesces packets,
  and what remains is just the state lock; the gain is uncertain, so it is not done for now;
- No payload compression: payloads are mostly encrypted/random data;
- Do not shrink the fragment id: there is already data on the historical packet-loss cliff with u16;
- Do not enable FEC/NACK by default: it changes UDP semantics/amplifies bandwidth, so it is left as opt-in.

### 4.10 Optional Further Compression: session id u16

All quantifications in this document are computed with **sess kept as u32** (5 B steady-state header), which is the lowest-risk option. If the following are subsequently confirmed:

- the client hub's session id allocation is changed to 16-bit + free-list (4032 concurrent sessions is sufficient);
- closed ids are not reused within the server's 180 s idle window (or are reused only after an explicit SESS_CLOSE);
- all logs/statistics/table keys are widened synchronously;

then the steady-state header can save another 2 B (5 B → 3 B; additional flow 6 B → 4 B). This saves about another 2–3% bandwidth for small packets,
but it touches the id semantics in `hub.rs` / `table.rs` / tests, so it is recommended as an independent Phase 3 change
and should not be mixed with flow/train.

---

## 5. Quantified Gains (Model)

### 5.1 Assumptions

- IPv4; MTU 1200 → DATAGRAM budget 1162 B; fixed overhead 55 B per packet; 2–3 B per DATAGRAM frame;
- quinn coalesces multiple DATAGRAM frames from the same poll into one packet (confirmed by source code);
- Current client uplink is modeled as **2-pack** (actual state); server downlink is modeled as same-source runs of at most 16 items and ≤512 B;
- MQP-3 is modeled as sess u32 + flow (5 B steady state, 6 B for an additional flow) + TRAIN (2 B/same-flow item, 3 B/different-flow item);
  FEC/ACK overhead is not counted;
- Packet loss, ACK-only packets, GSO padding, and PMTU changes are not considered.

### 5.2 Uplink (client → server)

| Scenario | MQP-2 wire | MQP-2 send calls | MQP-3 wire | MQP-3 send calls | Bandwidth | Calls |
|---|---:|---:|---:|---:|---:|---:|
| DNS 60 B, same destination, 50k pps (current 2-pack) | 3.67 MB/s | 25.0k/s | 3.28 MB/s | 2.8k/s | **−10.8%** | **9.0×** |
| Same, assuming 16-pack already implemented (Phase 0) | 3.32 MB/s | 3.1k/s | 3.28 MB/s | 2.8k/s | −1.4% | 1.1× |
| DNS 60 B, 32 destinations, 50k pps | 3.93 MB/s | 50.0k/s | 3.33 MB/s | 2.8k/s | **−15.4%** | **18.0×** |
| Same, domain 30 B | 5.35 MB/s | 50.0k/s | 3.33 MB/s | 2.8k/s | **−37.8%** | **18.0×** |
| STUN 28 B, same destination, 100k pps (2-pack) | 3.98 MB/s | 50.0k/s | 3.17 MB/s | 2.6k/s | **−20.5%** | **19.0×** |
| 60 B single frame, 50k pps | 3.93 MB/s | 50.0k/s | 3.56 MB/s | 50.0k/s | −9.4% | 1.0× |
| 60 B single frame, domain 30 B, 20k pps | 2.14 MB/s | 20.0k/s | 1.42 MB/s | 20.0k/s | **−33.4%** | 1.0× |
| Game 200 B, 8 destinations, 20k pps | 4.52 MB/s | 20.0k/s | 4.32 MB/s | 4.0k/s | −4.5% | **5.0×** |
| VPN 1420 B (2 fragments), 5k pps | 7.86 MB/s | 10.0k/s | 7.79 MB/s | 10.0k/s | −0.9% | 1.0× |

### 5.3 Downlink (server → client)

| Scenario | MQP-2 wire | MQP-2 send calls | MQP-3 wire | MQP-3 send calls | Bandwidth | Calls |
|---|---:|---:|---:|---:|---:|---:|
| 60 B same source, 50k pps | 3.32 MB/s | 3.1k/s | 3.28 MB/s | 2.8k/s | −1.4% | 1.1× |
| 60 B, 8 sources alternating, 50k pps | 3.93 MB/s | 50.0k/s | 3.33 MB/s | 2.8k/s | **−15.4%** | **18.0×** |
| 200 B, 4 sources alternating, 20k pps | 4.52 MB/s | 20.0k/s | 4.32 MB/s | 4.0k/s | −4.5% | **5.0×** |
| 1000 B same source, 20k pps | 21.52 MB/s | 20.0k/s | 21.30 MB/s | 20.0k/s | −1.0% | 1.0× |
| 1420 B (2 fragments), 5k pps | 7.86 MB/s | 10.0k/s | 7.79 MB/s | 10.0k/s | −0.9% | 1.0× |

### 5.4 CPU Estimates

F8 in PERF_ANALYSIS estimates 200–300 ns per `send_datagram`; a single frame also includes one exact allocation
(about 30–50 ns). Using 250 ns + 40 ns:

| Scenario | Calls saved/s | Estimated single-core CPU |
|---|---:|---:|
| DNS 60 B same destination, 50k pps (2-pack → train) | 22.2k | 0.6–0.7% |
| DNS 60 B 32 destinations, 50k pps | 47.2k | 1.3–1.5% |
| STUN 28 B same destination, 100k pps | 47.4k | 1.3–1.5% |
| Game 200 B 8 destinations, 20k pps | 16k | 0.4–0.5% |
| Single frame / bulk / fragments | 0 | ≈0 |

**Conclusion**: the CPU gain from the protocol redesign is on the order of "1–3% of one core" (in 50–100k pps small-packet scenarios),
not an order-of-magnitude improvement. Its real value lies in **constrained uplink bandwidth** (10–38%) and the **per-core pps ceiling** (5–19× fewer calls).

### 5.5 Optional Gains from Fragmentation/FEC

| Scenario | Arrival rate without FEC (p=1%) | +1 parity | Extra bytes |
|---|---:|---:|---:|
| 2 fragments (1420 B) | 98.01% | 99.97% (3 fragments, any 1 recoverable) | +50% |
| 8 fragments (8 KiB) | 92.3% | 99.64% (9 fragments, any 1 recoverable) | +12.5% |

FEC is not worthwhile for small F (2 fragments +1 parity is +50% bytes); it is opt-in only for large payloads, high packet loss, and applications willing to pay
bandwidth for "one fewer retransmission". Not done by default.

### 5.6 When It Is Worth It

| Workload | MQP-3 value | Recommendation |
|---|---|---|
| Large-packet bulk (≥1200 B), LAN/data center | ≈0 | Do not do; tune MTU/window |
| Same-destination small packets, client single-flow | Medium (mostly from N-pack) | Do Phase 0 first; MQP-3 depends on CPU |
| Multi-destination fan-out (DNS/games/WebRTC) | **High** (5–18× fewer calls, 15% bandwidth) | Do Phase 1 |
| Domain-target UDP | **Highest** (33–38% bandwidth) | Do Phase 1 |
| Constrained uplink / metered links | High (9–38% for small packets) | Do Phase 1 |
| Need fast reclamation of short sessions | Medium | Do Phase 2's SESS_CLOSE |
| High packet loss with large payloads | Medium (FEC) | Phase 2/3, opt-in |

---

## 6. Implementation Roadmap

### Phase 0: No Wire Changes (do first, highest benefit/risk ratio)

1. **Client N-pack**: extend the 2-pack in `assoc.rs` to 16 items by budget (copy
   the `reply_stage` / `flush_reply_batch` pattern from `server/reader.rs`).
   - Only include the current drain burst, no waiting;
   - Preserve `PendingPack`'s "no carry-over across bursts" semantics;
   - Target: reduce same-destination small-packet call count from 25k/s to ~3k/s (50k pps).
2. **Batch cap by budget**: `MAX_BATCH_ITEMS=16` fills only 43% for a 28 B payload;
   raise it to 64 under CAPS negotiation or same-version deployment, still computed by `limit`.
   - Note: the default ALPN `h3` does not provide version gating; in cross-version deployments, old decoders will reject an entire frame with >16 items.
     Therefore this step must either ship together with CAPS (Phase 1) or require both ends to upgrade to the same version.
3. **MTU**: on known paths, raise `initial_mtu` from 1200 to 1360/1400;
   UDP payloads `>1150 B` are no longer split in two by default, reducing the packet count by 18–23%.
4. **Validation**: `cargo test --all-targets` + `hotpath_bench udpps/udppaced/udpmulti/udpdomain`
   + Linux 2–4 core CPU/pps.

> **Phase 0 landing status (2026-10-20)**
>
> - **Client N-pack implemented**: the 2-pack in `AppDgramCtx` is changed to a run of at most
>   `MAX_BATCH_ITEMS=16` items within a burst; items with the same destination and
>   `batch_frame_len(...) <= limit` are appended, otherwise the current run is flushed immediately.
>   The run is sent when the burst ends, the destination changes, the budget is insufficient,
>   a non-batchable large packet is encountered, or the table is full; only the current drain burst
>   is included, with no waiting across await points.
> - **Single packets are not wrapped in BATCH**: when the run length is 1, the normal `0x02` is used,
>   byte-for-byte identical to the old path; only when the length is ≥2 is `0x06` encoded.
> - **Unified budget arithmetic**: `mqp::batch::batch_frame_len` is added and used by both the client
>   stager and the server's `reply_stage`; `encode_batch`'s acceptance condition and the stager's
>   pre-check use the same formula, avoiding "copy first, reject the frame later".
> - **`MAX_BATCH_ITEMS` not raised to 64**: the default ALPN is still `h3`, with no CAPS/version
>   gating; the old decoder rejects the whole frame for >16 items. This item is deferred until after
>   Phase 1's CAPS.
> - **`BATCH_SMALL_MAX=512` retained**: it is a fate-sharing cap, not a budget cap;
>   payloads above 512 B in a single packet continue to use single frames/fragments.
> - **MTU default unchanged**: still 1200. For known paths, explicitly set
>   `initial_mtu = 1360/1400` in the configuration; changing the default would affect unknown paths,
>   so no implicit switch is made.
> - **Validation**: `cargo test --all-targets` all pass,
>   `cargo clippy --all-targets -- -D warnings` passes; new client 16-item
>   BATCH ordering/single-frame tests, and consistency tests between `batch_frame_len` and the encoder.
>   The pps/CPU numbers on Linux 2–4 cores still need to be re-measured on the target machine with `hotpath_bench`.
>
> After Phase 1 landed, the client production path's N-pack has switched to MQP-3 `TRAIN`; the
> `0x06 BATCH` client code described here is retained under `#[cfg(test)]`, only for MQP-2 decoding/historical tests.

### Phase 1: MQP-3 Core (wire extension)

1. Add `src/mqp/v3.rs` (or `mqp3/`):
   - `FrameKind/Flags`, `SINGLE/TRAIN/FRAG/CTL` encoding/decoding;
   - golden vectors + boundary/fuzz tests;
   - coexist with the MQP-2 encoder; the decoder accepts both.
2. CAPS/HELLO negotiation + configuration switch; old peer fallback.
3. Client flow table / server flow table; `Inline → Compressed` state machine; FLOW_ACK/REJECT.
4. Client uplink TRAIN (mixed flows within the same association's burst);
5. Server downlink: remove "flush on source change"; use one TRAIN per burst;
6. Compact FRAG header + `(sess, flow, id)` key;
7. Statistics: frame type, flow count, train items, number of inline fallbacks.

> **Phase 1 core landing status (2026-10-20)**
>
> This round was implemented under the deployment assumption of "**no longer compatible with
> MQP-2 peers**", so HELLO/CAPS/FLOW_ACK/FLOW_REJECT were not introduced:
>
> - **`src/mqp/v3.rs` implemented**: `SINGLE`/`TRAIN`/`FRAG` encoding/decoding, LEB128
>   length, `FlowTable`, golden/boundary tests. `SINGLE` is 5 B in steady state
>   (flow 0) or 6 B (additional flow); the `TRAIN` header is 6 B, with same-flow
>   additional items at 2 B and different-flow items at 3 B; the `FRAG` header is 11/12 B + optional address.
> - **Client uplink switched to v3**: the N-pack in `assoc.rs` is changed to `PendingTrain`,
>   allowing multiple flows to be mixed within the same drain burst; when the run is 1, `SINGLE`
>   is sent, and when ≥2, `TRAIN` is sent. Payloads >512 B or that cannot be encoded still use MQP-2 single frames/FRAG.
> - **flow opening**: the client first inlines every IP flow; only after receiving and successfully
>   staging a compressed downlink frame for that flow does it switch to compression. With no ACK,
>   pure uplink flows remain inline; this avoids the first few frames being lost and permanently
>   black-holing the entire flow. "First item inline, subsequent items compressed" within a TRAIN is
>   also safe, because the server registers items in wire order before decoding subsequent items.
>   The per-session flow table counts 4 KiB per session toward the `per_session_memory_bytes` admission budget.
> - **Domain targets remain inline (`MQP3_NO_FLOW`)**: the first domain is resolved asynchronously by
>   the server, when the session/flow table may not yet be established; forcing compression would
>   black-hole before resolution completes. Moreover, the client only has the domain, not the resolved
>   IP, so the downlink also cannot safely use the domain to fill the SOCKS5 response header.
>   Therefore domain targets carry an inline address every frame, but TRAIN still shares the sess/QUIC
>   frame; only IP targets get flow compression. Domain gains are therefore lower than the
>   "fully compressed" upper bound in the model.
> - **Server uplink**: `accept.rs` recognizes v3 before v2 FRAG/BATCH; it obtains the flow table per
>   session from FastSess/the session table; an inline open is registered after forwarding to the
>   target, and compressed items are looked up and forwarded. Unknown flows drop only that item and
>   count `REFUSED`, without guessing routes.
> - **Server downlink**: `reader.rs` uses the same session flow table to map reply source back to
>   the flow id; IP flows are compressed on an exact `(ip, port)` match, while domain flows, port
>   changes, and full-cone unsolicited sources are always inline. Downlink runs no longer require
>   "same source"; one TRAIN can mix multiple sources; when the run is 1, `SINGLE` is sent. The flow
>   table also serves as the **exact IP authorization fallback** when the 16-entry allowlist
>   ring misses, so a 32-resolver fan-out will not lose replies because early targets were evicted
>   from the ring.
> - **FRAG not yet wired**: v3 compact FRAG encoding/decoding is ready, but the reassembler still
>   handles MQP-2 fragments by `(sess, id)`; large payloads continue to use v2 FRAG on both ends.
>   The next step is to extend the reassembler key to `(sess, flow, id)` and make `DgramFragmenter` support v3.
> - **No configuration switch / no CAPS**: currently same-version deployment; a new client will not
>   fall back for an old server. If gradual rollout is needed, Phase 2's CAPS + `mqp3=false` must be added.
> - **Validation**: `cargo fmt --all`, `cargo test --all-targets`,
>   `cargo clippy --all-targets -- -D warnings` pass. New v3 codec,
>   client open/compress, mixed-flow TRAIN, server downlink compression/mixed sources/domain
>   inline, and end-to-end unit tests for "open + compressed to target within a TRAIN" were added.
>   macOS release binary smoke: `udp`/`udpdomain` 1000/1000,
>   `udpmulti` 4×500 0 loss, `udppaced` 1k–5k pps 0 loss,
>   `udpps` 2 s 9985/9985; same order of magnitude as the HEAD baseline at 5k pps / `lat` p50.
>   `udpps/udppaced/udpmulti/udpdomain` on Linux 2–4 cores still need re-measurement on the target machine.

**Acceptance gates**:
- `udpdomain` / new `udpfanout`: wire −10% (v4) / −30% (domain);
- `udpfanout` send calls reduced ≥5×;
- `lat` p50/p99 do not regress (≤1%), packet-loss rate does not increase;
- `bulk` throughput does not regress.

### Phase 2: Control Plane and Robustness

1. `SESS_CLOSE` / `FLOW_CLOSE`: short sessions release socket/task/flow immediately; 180 s idle is only a fallback.
2. Metrics and alerts for `FLOW_ACK` timeouts/rejections.
3. Negotiable `max_reassembly` (currently an 8 KiB compile-time constant).
4. Optional FEC (opt-in per flow / port), optional NACK (separate design, not mixed into the first version).
5. Observability: flow table high-water mark, rejection count, inline fallback rate.

### Phase 3 (Optional)

- Cross-session TRAIN (requires a connection-level shared stager; only do it if profiling proves the state lock is the bottleneck);
- session id u16 (saves another 2 B/frame, but touches the id lifecycle);
- More aggressive fragmentation strategies (e.g. per-flow adaptive FEC).

---

## 7. Validation Plan

### 7.1 Unit/Compatibility

- Golden bytes for every frame (v4/v6/domain, flow 0/non-zero, inline/compressed, train with 1/2/64 items);
- Decoder fuzz/truncation tests: no arbitrary prefix may panic; unknown types drop only one frame;
- Cross-version:
  - new server + old client (old client does not send HELLO → stays on MQP-2);
  - new client + old server (HELLO is dropped → stays on MQP-2);
  - CAPS/HELLO lost → no black-holing, retryable.
- flow lifecycle:
  - same-destination reuse, fanout, source port changes, full-cone unsolicited, flow table full rejection,
  - id reuse after session close (forbidden within the 3 s window), fragments crossing flows.

### 7.2 End-to-End

Add/reuse in `examples/hotpath_bench.rs`:
- `udpdomain` / `udpdomainmulti` (domain targets);
- new `udpfanout`: one association, N destinations, round-robin per packet (covering TRAIN/flow);
- `udpps` / `udppaced` (high-pps small packets);
- `udpmulti` (multiple associations);
- `lat` / `lattcp` (latency regression);
- `bulk` (throughput regression).

Use `tc netem loss 1%` to validate fragmentation/FEC; use `perf stat` (context-switch, cycles, instructions)
and `strace -c` to confirm the number of send calls/system calls; use `tcpdump -s 0 -w` or user-space counters to verify wire bytes.

### 7.3 Target Machine

Linux 2–4 cores (OpenWrt/router form factor) is the focus: protocol gains come mainly from "fewer calls/fewer bytes",
while on macOS `pin_to_core` is a no-op and the kernel path is different, so it cannot serve as the final conclusion.

---

## 8. Counterarguments and Risks

1. **"quinn already coalesces packets, so MQP batch is meaningless"**: that is true for **packet count**, but not for the **state lock,
   allocation, and driver wake per send**. The benefit of protocol TRAIN is mainly the latter; if profiling shows send calls are not a hotspot,
   MQP-3's CPU value decreases.
2. **"Synchronized state for header compression is troublesome"**: true. This design uses "inline first frame + compress only after a reply/ACK + inline when the table is full"
   to avoid black-holing; the cost is that pure uplink flows need one ACK, or the first N frames are inline.
3. **"The flow table is a new memory attack surface"**: bounded + only within authenticated connections + reject when full + released on session destruction;
   worst case 8192 sessions × 64 flows × 64 B ≈ 32 MiB, which can be included in admission accounting.
4. **"Cross-session train is more thorough"**: quinn already coalesces packets; cross-session requires a connection-level shared queue,
   which introduces one queue hop (latency/lock), the gain is uncertain, and it is not done in the first version.
5. **"FEC should be on by default"**: 2 fragments +1 parity is +50% bytes; not worthwhile for small F. Off by default, opt-in per deployment.
6. **"A protocol redesign can improve throughput"**: it cannot. Throughput is determined by QUIC CC + window + MTU; the MQP header is <1% for bulk.
   If throughput is the goal, do MTU/window first.
7. **"Version cannot be guaranteed under the default ALPN h3"**: CAPS is in-band capability negotiation, which solves exactly this problem;
   deployments needing fail-closed behavior can explicitly bump ALPN.

---

## 9. Final Recommendations

- **Do not treat "rewriting MQP-2" as a throughput optimization**: it is already close to the achievable limit; the bottleneck on the bulk path is QUIC/kernel/thread topology,
  not the 12 B header.
- **Do Phase 0 first**: client N-pack, budget-based batch, MTU. These three do not change the wire, are low risk,
  and capture most of the CPU gains for same-destination small packets.
- **If the goals include multi-destination/domain/high pps/constrained uplink**, then do **MQP-3 Phase 1**:
  flow-ification (address appears only once) + TRAIN (cross-flow aggregation) + compact FRAG + CAPS gradual rollout.
  This is the **only direction that can simultaneously reduce wire bytes and send call count** under the current protocol structure.
- **Phase 2's SESS_CLOSE** has resource-reclamation value for short-session churn independent of performance, and should be scheduled together.
- **FEC/NACK, cross-session train, session id u16** are all left until there is measurement evidence before deciding.

---

## Appendix A: Model Parameters and Recalculation

- Fixed overhead per packet 55 B = IPv4 20 + UDP 8 + QUIC short header (1 flags + 8 DCID + 2 PN + 16 AEAD).
- DATAGRAM body budget 1162 B (MTU 1200, quinn has already deducted QUIC overhead); MQP IPv4 single-frame payload cap 1150 B.
- QUIC DATAGRAM header per MQP frame = 1 + varint(len); 2 B for a body ≤63 B, otherwise 3 B.
- Current uplink is modeled as 2-pack; server downlink as same-source runs, ≤16 items, ≤512 B.
- MQP-3 with sess u32: SINGLE 5 B / 6 B with flow; TRAIN 6 B + 2 B (same-flow item) / 3 B (different-flow item);
  FRAG 11/12 B; first-frame inline address is counted separately.
- Recalculation script: during analysis, Python was used to bin-pack the above frame lengths packet by packet (upper limit 1162+9 B) and then sum; the tables in this document are the output of that script.
  The script was not committed to the repository, to avoid solidifying "analysis assumptions" into product code.

## Appendix B: Relationship to `PERF_ANALYSIS.md`

| Item in this document | Relationship to the code-level report |
|---|---|
| P2 client 2-pack | i.e. **F8** in PERF_ANALYSIS (deferred); this document lists it as the first Phase 0 item |
| P2 server source-change flush | corresponds to `staged_src` in `reader.rs`; this document recommends using TRAIN to remove that constraint |
| P3 fragment header | F4/F13 in PERF_ANALYSIS are **reassembler CPU**; this document is about the **wire header**, the two are independent |
| P4 control plane | not covered by PERF_ANALYSIS; it is protocol/lifecycle, not a hotspot |
| §2.5 fixed costs | corresponds to the allocation/quinn-lock conclusion in PERF_ANALYSIS §4 "confirmed optimized, not recommended to change" |
| MTU | a configuration item; PERF_ANALYSIS explicitly does not analyze configuration; this document lists it separately as Phase 0 |
