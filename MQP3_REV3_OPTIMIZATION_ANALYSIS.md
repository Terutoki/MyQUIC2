# MQP-3 rev3 — Minimum Round Trips, Minimum Parse Cost (deep analysis)

> **Date:** 2026-10-28 · **Baseline:** `ed329e4` (v0.2.2 tree, MQP-3 wire rev2)
> **Question:** the application-layer protocol should need *the fewest possible round trips* and the
> *lowest possible parse/encode cost* for maximum performance. Backward compatibility with older wire
> revisions is **explicitly not required**.
> **Method:** 4 parallel read-only deep-dives (client RTT, server RTT/latency, parse/encode/bytes, clean-slate
> design), Lead synthesis + independent re-verification of every decisive claim against the tree, plus a new
> micro-benchmark run on this machine.
> **Supporting evidence (not shipped as part of the main tree):**
> `analysis/rev3/rtt-client.md`, `analysis/rev3/rtt-server.md`, `analysis/rev3/parse-cost.md`,
> `analysis/rev3/design-options.md`, `analysis/rev3/wire_model.py`, `examples/rev3_bench.rs`.
> **Evidence grades:** `[C]` verified in code (file:line), `[D]` derived by arithmetic from code constants,
> `[M]` measured (this repository, this machine), `[E]` engineering estimate — must be measured before being
> promised. Nothing here is implemented; `src/` was not modified.

---

## 0. TL;DR — what the analysis actually found

1. **The warm-path delivery RTT floor is already reached.** No MQP round trip sits on the payload path in
   either direction: the client's UDP uplink is fire-and-forget, and the server forwards a `DATA OPEN`
   payload **before** it installs the binding or sends `FLOW_ACK`
   `[C src/bin/myquic2-client/rev2.rs:733-805,964-998; src/bin/myquic2-server/accept.rs:2223-2252,2333-2350]`.
   First-payload delivery is one one-way delay — identical to any IP proxy. **"Fewer round trips" on the
   warm path is already true; the remaining round-trip-shaped costs are bytes, loss windows and CPU.**
2. **Exactly one MQP round trip exists in the protocol: the per-flow `OPEN → FLOW_ACK` confirmation.** It
   gates *compression/aggregation* (1 RTT), never delivery. It is redundant for every flow that has a reply
   (any compressed downlink frame already implicitly confirms `[C dispatcher.rs:1132-1135]`), it is a net
   wire loss for one-shot flows (a DNS-style flow pays a whole QUIC packet for it — see §4.4), and its
   replacement (bounded context redundancy) costs no round trip at all.
3. **The only application RTT still on the table is 1 RTT on a *resumed* connection**, and it requires
   (a) identity in the TLS handshake (mTLS) and (b) an explicit replay-tolerant policy for 0-RTT payloads
   `[D/C]`. Everything else that looks like an RTT is either network-inherent (resolver, target dial) or a
   **latency cliff**, not a round trip: a lost `HELLO` stalls data up to **200 ms**, a missing `CAPS` tears a
   working connection down after **2 s**, a domain-path failure **loses the triggering payload** (app
   retransmits after 100 ms–5 s), and a blackholed path is detected only after **40 s** plus a 0.2–5 s
   backoff `[C]`.
4. **Parse/encode cost is real but bounded.** Measured on this machine: decoding a steady `DATA` frame is
   **2.0–2.2 ns**, encoding one is **~17 ns** (allocation+copy dominated), `TRAIN` decode is
   **16 ns (1 item) / 27 ns (8) / 260 ns (64)** — a single-pass decoder needs **1.5 / 5.4 / 46 ns**, i.e. the
   current double pass wastes **~70–90 %** of TRAIN decode CPU; the flow registry lookup is
   **4.4 ns → 1.5 ns** with a direct-indexed table. The MQP layer is only **~40–80 ns/payload (≈5–10 %) of
   per-datagram app CPU**, but the encoder is **~20–30 % of the staged send path** and one avoidable
   allocation+copy per staged payload is removable `[M examples/rev3_bench.rs]`.
5. **Wire bytes: the published "2 B steady header" is a 63-flow illusion.** `wire_id=(local<<1)|owner` is
   LEB128; the **64th flow an endpoint ever opens** makes every later steady header **3 B**, and because ids
   are never reused it becomes **4 B after 8192 cumulative opens** and grows from there
   `[D src/mqp/r2.rs:143-148,172-179; src/mqp/r2_flow.rs:743-778]`. A 4096-flow connection averages
   **2.985 B**, not 2 B. A cleanup that removes the ACK and the varint makes the steady header **2 B constant**
   for the whole 4096-flow cap.
6. **Where the wire money is:** one-shot flows, not bulk. A one-shot UDP request/response flow costs
   **3 packets (291 B wire) for an IP target** and **4 packets (372 B) for a domain target** today; a rev3
   design lands at **230 B / 246 B**, i.e. **−21 % / −34 % and one to two packets fewer**
   `[D analysis/rev3/wire_model.py]`. Steady flows, `TRAIN` and bulk gain ≤1 B/frame (≤0.2–0.8 % of a packet):
   the 55 B IP/UDP/QUIC floor dominates.
7. **Recommended direction:** “**MQP-3 rev3**” = identity/contract in the TLS handshake (mTLS + versioned
   ALPN + static caps) + a self-describing data plane with a **constant 2 B packed header, no varints**,
   **bounded context redundancy (K=2) with reliable `NEED_CONTEXT` recovery instead of `FLOW_ACK`**, one
   reliable control stream for rare close/reject messages, `TRAIN` kept with a new equal-length form, `FRAG`
   and the TCP path unchanged. **0-RTT payloads stay off by default** (replayable; the only RTT win, opt-in).
   The warm path stays at the floor; the gains are bytes, CPU, determinism and removed cliffs — plus a
   one-time **1 RTT** on resumed reconnects if the replay policy is accepted.
8. **Do the no-wire-change work first (Phase 0).** Five of the eight most valuable fixes (HELLO gate, 2 s
   CAPS cliff, pre-auth stream-credit stall, drop-not-queue during reconnect, domain-path payload loss) can
   ship without touching the wire, or are pure client/server policy. They remove the largest *user-visible*
   latency risks before the rev3 rewrite begins.

---

## 1. Scope, constraints, and how to read this document

* **In scope:** the application-layer framing carried in QUIC DATAGRAMs (the UDP path) and the MQP header
  used on QUIC bidi streams (the TCP path), i.e. `src/mqp/**`, the UDP stager/fragmenter/reassembler, and
  the client/server integration points that decide when frames are sent and waited on.
* **Out of scope but used as levers:** QUIC transport configuration (MTU, ACK frequency, keepalive/idle,
  DATAGRAM sizing), DNS placement, mTLS provisioning, connection-pool policies.
* **Constraint honored:** backward compatibility is *not* required. Single-version deployment is assumed;
  fail-fast is mandatory (a mixed-version peer must fail at the TLS/ALPN boundary, never at the frame layer).
* **Prior rejections honored** (`MQP3_REFACTOR_ANALYSIS.md §1.3`): no frame-buffer pooling, no BATCH
  re-introduction, no u16 fragment id, no default-MTU/wire coupling, no fragment trains, no FEC/NACK default,
  no cross-session TRAIN “unconditional win”, no bulk-throughput rewrite. This analysis does not re-propose
  any of them.
* **Document map:** §2 baseline, §3 RTT analysis, §4 parse/byte analysis, §5 consolidated levers, §6 the
  recommended rev3 design, §7 alternatives/do-not-do, §8 decisions needed, §9 measurement plan, appendices.

---

## 2. Baseline: what MQP-3 rev2 actually does

### 2.1 Wire in one table (IPv4, exact)

| Form | Bytes | Notes |
|---|---:|---|
| `DATA` steady | `1 + LEB128(wire_id)` = **2 B** for the first 63 flows/owner, **3 B** after, **4 B** after 8192 cumulative | payload is the rest of the DATAGRAM; no length |
| `DATA OPEN` | `2 + id + 4(sess) + addr` = **14 B** (id<128) / 15 B (id≥128), v6 26/27 B, domain 11+L/12+L | first frame of a flow |
| `DATA INLINE` | `2 + 4 + addr` = **13 B** v4 / 25 v6 / 10+L domain | stateless fail-safe |
| `TRAIN` same | `3 + id + Σ(1 + payload)` | items for one confirmed flow |
| `TRAIN` dict | `4 + Σ id(1–2 B) + Σ(1 idx + 1 len + payload)` | mixed flows/sessions |
| `FRAG` steady | `1 + id + 4(frag_id) + 1 + 1` = **8 B** (id<128) / 9–10 B later | chunk is the rest |
| `CTL HELLO` / `CAPS` / `FLOW_ACK` / `FLOW_REJECT` / `FLOW_CLOSE` / `SESS_CLOSE` | 8 / 17 / 4–5 / 4–5 / 3–4 / 7 | DATAGRAM-carried, loss-tolerant |
| Address | IPv4 **7 B**, IPv6 **19 B**, domain **4+L B** | SOCKS5-format `atyp|addr|port`, shared with the TCP stream header |

Per isolated QUIC packet (IPv4): 55–57 B fixed (20 IP + 8 UDP + 26–27 QUIC short header/tag + 2–3 DATAGRAM
frame header). **quinn packs multiple DATAGRAM frames into one packet** when they are sent in the same
transmit poll `[C quinn-proto 0.11.19 connection/mod.rs:3347-3359]`, so “one frame = one 57 B packet” is the
worst case, not the norm — this weakens the byte case for any new header and strengthens the parse/CPU case
`[C]`.

### 2.2 Interaction inventory (what is actually exchanged)

| Event | Exchanges today |
|---|---|
| Connection setup | QUIC/TLS 1.3 handshake (1 RTT); bearer token on a 1-RTT uni stream; `CTL HELLO` → `CTL CAPS` (DATAGRAMs, retried 200 ms, hard 2 s cap) |
| First uplink payload of a flow | `DATA OPEN` (id + session + full address + payload), repeated on every payload until `FLOW_ACK` |
| Server installs flow | forwards the payload first, then registry insert, then one `CTL FLOW_ACK` **per accepted OPEN frame** (duplicates re-ACK) |
| Server→client first reply | steady `DATA`/`TRAIN` for IP targets; for domain targets / port changes `DATA OPEN\|SRC` until the client's `CTL FLOW_ACK` arrives |
| Client confirms a learned reply source | one `CTL FLOW_ACK` per `OPEN\|SRC` decoded |
| Small-payload bursts | client-side connection stager packs confirmed flows into same-flow/dict `TRAIN` (≤64 items, ≤4 frames/drain) |
| Large payload (> DATAGRAM budget) | `FRAG` ≤64 fragments, 8 KiB cap, 2 s reassembly expiry |
| Flow retirement | `FLOW_CLOSE` is **decoded but never sent in production** `[C: only test constructors]`; flows retire with the session |
| Association close | `CTL SESS_CLOSE` ×3 best-effort DATAGRAMs on client exit; ×3 on server reap |
| TCP path | raw address header (7/19/4+L B) as the first stream bytes; optimistic SOCKS success; in-band 10/22 B dial ACK from server; **no MQP frames per payload** |

### 2.3 Published claims that this analysis corrects

| Claim (README / comment) | Reality | Evidence |
|---|---|---|
| “steady `DATA` header **2 B**” | true only for the **first 63 flows per endpoint per connection**; 64th+ = 3 B forever, 8192nd+ = 4 B, because ids are monotone and never reused | `[D] r2.rs:143-148,172-179,275-277`; `r2_flow.rs:743-778` |
| “downlink compression does not wait for an uplink ACK” | false for **domain targets and port changes**: the server's `match_source` returns `Rebind` until the client's `FLOW_ACK` sets `reply_src_acked`; only `target == reply_src` short-circuits | `[C] r2_flow.rs:325-366; README.md:293` |
| “reply outside the resolved cap ⇒ inline under full-cone” | full-cone creates a **server-owned flow and sends `OPEN\|SRC`**, not `INLINE`; `INLINE` is only the table-bound fallback | `[C] server/reader.rs:1060-1072; README.md:291` |
| “`FLOW_CLOSE` on flow retirement” | no production sender exists; opcode is dead wire surface | `[C] grep: only decode handlers + unit tests`; `README.md:347` |
| “the egress cache refuses to publish until CAPS” | false; the cache publishes pre-CAPS deliberately and the server buffers pre-HELLO frames | `[C] client/egress.rs:414-425` vs stale comment `client/auth.rs:88-93` |
| “`FLOW_ACK` once per installed flow” | once per **accepted `OPEN` frame**; duplicates are re-ACKed (a burst before the first ACK can yield N ACKs) | `[C] accept.rs:2205-2219,2333-2350` |

These are documentation/comment drifts, not code bugs; they matter because a redesign must not inherit the
wrong model (and §2.3 rows 2–3 change how the downlink compression cost is accounted).

---

## 3. Round-trip analysis

### 3.1 Reconciled timing model (the one correction to the input reports)

Let `d = RTT/2`. TLS 1.3 over QUIC, full or resumed handshake, as actually observable by these endpoints:

| t | client | server |
|---|---|---|
| 0 | sends ClientHello (+ 0-RTT packets if it chose to) | |
| d | | receives CH, sends SH/EE/Finished |
| 2d = 1 RTT | receives server flight; rustls/`quinn` report Connected; **publishes the connection**; sends token + HELLO + first 1-RTT data | |
| 3d = 1.5 RTT | | receives client Finished + token + HELLO + first data; `authenticate()` returns (token already there); `handle_conn` starts; **first payload forwarded / TCP target dial starts** |

Two consequences:

* **Cold-dial first forward = 1.5 RTT after ClientHello; the client can send at 1 RTT.** `auth.rs` timing
  therefore adds **0 RTT** — the token rides the same flight as the first data. (One input report used a
  one-one-way clock shift and reported 1 RTT / 0.5 RTT; the deltas are unchanged, but the 0-RTT opportunity
  is **1 RTT**, not 0.5 — see Appendix B.)
* **Resumption without early data is not faster than a full handshake** at the application level: both are
  1 RTT to send / 1.5 RTT to receive. 0-RTT tickets currently save certificate bytes and server CPU only,
  because the client awaits handshake completion and sends no early application data
  `[C client/auth.rs:356-410]`.

### 3.2 Per-operation RTT ledger

`floor` = the minimum *application-layer* RTT any design can add on top of the transport. `current` = rev2
today. `gap` = current − floor.

| # | Operation | floor (added) | current (added) | gap | Notes |
|---|---|---|---:|---:|---:|---|
| 1 | First UDP datagram, unknown target, **warm** conn | 0 | **0** | 0 | self-describing `OPEN` carries session+address+payload |
| 2 | Same, **cold** conn | 1 RTT (1.5 RTT server-forward is transport) | 1 RTT | 0 | token/HELLO share the flight; no MQP RTT |
| 3 | Same, **resumed** conn | 0 with replay-tolerant early data | 1 RTT | **1 RTT** | only real RTT win; 0-RTT payloads currently impossible |
| 4 | Steady UDP, either direction | 0 | 0 | 0 | no waits anywhere |
| 5 | TCP SOCKS5 CONNECT / forward accept, warm pool | 0 added (0.5 RTT one-way + target dial is inherent) | 0 | 0 | optimistic SOCKS success; c2s pump not gated on the dial ACK `[C socks.rs:246-272; tcp/pump.rs:47-61]` |
| 6 | Reconnect after path failure | detection + transport floor | **detection (40 s watchdog) + 0.2–5 s backoff** + 1.5 RTT | ≤1 RTT via 0-RTT class; detection dominates | the wire cannot fix detection; the transport can |
| 7 | New flow: compression starts | 0 (context redundancy) | **1 RTT** (until `FLOW_ACK`) | 1 RTT of *header bytes*, not delivery | every payload before the ACK is a standalone `OPEN` (+12 B v4, +9+L domain) and cannot join a `TRAIN` `[C r2.rs:280-283; r2_stage.rs:462-495]` |
| 8 | Downlink first reply of a domain flow / rebind | 0 | **1 RTT more `OPEN\|SRC` headers** until the client ACKs | header bytes only | `[C r2_flow.rs:325-366; reader.rs:398-444]` |
| 9 | Flow close | 0 user-visible | 0 RTT, but `SESS_CLOSE`×3 best-effort; a lost close has **no repair path** | determinism | §3.4 |
| 10 | One-shot flow existence (server) | — | **+1 DATAGRAM packet per flow** (`FLOW_ACK`) | −1 packet | for a DNS-style flow this is a net wire loss until ~7 frames |

**Bottom line:** “fewest round trips” is achieved on the delivery path already. The only place a round trip
can still be *removed* is the resumed-connection 0-RTT opportunity (#3); the rest of this document is about
removing the *cost* the current control exchanges impose (packets, bytes, state, loss windows, CPU).

### 3.3 What each control exchange actually buys

| Exchange | Buys | Costs if kept | If removed |
|---|---|---|---|
| `HELLO`/`CAPS` | version fail-fast + 5 limits | 25 B + 2 packets/conn; 8-frame/16 KiB pre-HELLO buffer; per-frame `hello_seen` gate; **a lost HELLO stalls all data up to 200 ms** and drops frames 9..N of the first burst; **a lost CAPS kills a working connection after 2 s** | version moves to ALPN (immediate, unambiguous); limits are protocol constants; no gate, no buffer, no cliff |
| `FLOW_ACK` (server→client) | unlocks steady headers | 1 packet/flow (≈61 B isolated); `Opening → Open` gate; repeated OPEN headers until it arrives; no ACK coalescing (duplicates re-ACK) | bounded context redundancy (K=2) + implicit confirmation by any inbound frame for the fid; reliable `NEED_CONTEXT` repairs the rare all-Lost case |
| `FLOW_ACK` (client→server for `OPEN\|SRC`) | unlocks compressed replies | 1 packet per learned source; server re-sends `OPEN\|SRC` until it arrives | same: repeat `SRC`/`OPEN_SRC` for the first K replies; any client uplink frame for the fid is implicit confirmation |
| `SESS_CLOSE` ×3 | frees server state / resets client bindings | 3 packets on every association exit (~192 B) | one reliable control-stream message (~67 B); deterministic reclaim instead of a 180 s sweep backstop |
| `FLOW_CLOSE` | — | dead wire code | delete |
| auth token stream | authentication | 1 packet + ≤256 B per connection; 256 pre-auth slots; post-auth `MAX_STREAMS` raise; structural ban on 0-RTT payloads | mTLS: 0 MQP bytes, identity in handshake, 0-RTT structurally possible |

### 3.4 Latency cliffs (these matter more than micro-RTT, and most are not wire)

| Cliff | Today | Effect | Owner |
|---|---|---|---|
| Blackholed path | client watchdog = 2/3 × 60 s idle = **40 s**, then 0.2–5 s backoff | every flow on that egress class waits 40 s+ before redial | transport/config — the single largest user-visible latency in the system |
| UDP during reconnect | `udp_fail_closed = true` ⇒ **dropped, not queued** when no egress exists | total-loss window during a reconnect for the fail-closed class | client policy |
| Interactive UDP class | its own single dedicated connection (bulk traffic uses 2 shards); no sibling to fail over to | one connection's death = every DNS/STUN/game flow lost while it redials | client policy |
| Lost `HELLO` | retry every 200 ms, data buffered behind it | up to **200 ms** first-payload stall, plus 8-frame overflow drops | MQP — removable |
| Missing `CAPS` | hard **2 s** cap → close + redial | a lost control datagram tears down a live connection and all its flows | MQP — removable |
| Domain path failure | DNS error/timeout, all-records-filtered, session refusal ⇒ reject + return | **the triggering payload and queued duplicates are lost**; app retransmits after 100 ms–5 s | MQP/server — removable (deliver via INLINE with re-validated policy) |
| Domain path DNS | resolver RTT before the first payload moves (memo → moka → hickory, 5 s budget) | 1 resolver RTT on cold names; up to 5 s worst case | external/semantics |
| Pre-auth bidi credit | 4 streams advertised until the token is verified, then raised to 8192 | the 5th+ concurrent TCP `open_bi` right after a dial can park up to ~1 RTT `[D]` | transport policy — a config-sized lever, not wire |
| Lost `SESS_CLOSE` | no repair path; client keeps using purged ids | one-way blackhole until redial/180 s if all 3 closes are lost | MQP — fix with the reliable control stream |

---

## 4. Parse/encode and byte analysis

### 4.1 The id-width cliff (the model error to fix first)

`wire_id = (local_id << 1) | owner`, allocated monotonically, **never reused**, encoded as LEB128.

| Cumulative flows opened per endpoint | `wire_id` | id bytes | steady `DATA` header | Share of frames in that state |
|---:|---:|---:|---:|---:|
| 1 – 63 | 2 – 127 | 1 | **2 B** | only the first 63 |
| 64 – 8191 | 128 – 16383 | 2 | **3 B** | the normal long-lived case |
| ≥ 8192 | ≥ 16384 | 3 | **4 B** | grows: 2^21 threshold next |

A 4096-live-flow connection therefore averages **2.985 B/frame**, not 2 B `[M examples/rev3_bench.rs;
D r2.rs:172-179; r2_flow.rs:743-778]`. Ids are never reused precisely to make delayed-frame misdelivery
impossible; the price is header growth over a long-lived connection. **A fixed-width 2 B packed header fixes
both the bytes and the parse cost without reintroducing id reuse** (14-bit fid = 8192 ids/owner = 2× the
4096 live cap; exhaustion falls back to `INLINE`).

### 4.2 Measured parse/encode cost (release, Apple M-series, this tree)

`examples/rev3_bench.rs`, min of 5 rounds; compare cells only within one run `[M]`:

| Operation | Current | Reference single-pass | Waste |
|---|---:|---:|---:|
| `decode_data` steady (2/3/4 B id) | 2.06 / 2.05 / 2.21 ns | ~1–2 ns | negligible |
| `decode_data` OPEN v4 / v6 / domain L=11 | 4.72 / 4.32 / 8.95 ns | — | domain pays UTF-8+addr work |
| `decode_data` INLINE v4 | 3.23 ns | — | — |
| `decode_train` + iterate once, n=1/8/64 | 16.2 / 17.5 / 186.7 ns | — | eager validation pass |
| `decode_train` + iterate twice (production: dedupe + dispatch) | 21.0 / 27.7 / **260.5 ns** | **1.5 / 5.4 / 46.0 ns** | **~70–90 %** of TRAIN CPU |
| dict TRAIN nfl=64, production shape | **631.2 ns** | **118.1 ns** | double pass + 256 B array copies |
| `decode_frag` steady | 2.73 ns | — | — |
| `encode_data` steady (1 alloc + 1 copy) | **16.6–17.9 ns** | — | alloc+memcpy dominates |
| `encode_data` OPEN v4 / INLINE v4 | 21.0 / 18.1 ns | — | — |
| `encode_train` same n=64 | 292.5 ns | — | `train_same_len` pass = 26 ns; write = rest |
| `encode_train` dict nfl=64 | 606.6 ns | write-only 310.7 ns | O(nfl²) dedupe + length pass |
| `FlowRegistry::get` + Arc clone vs direct table | **4.4 ns** vs **1.45 ns** | — | lock+hash per frame |
| `get_batch`(64 ids, one lock hold) | 118.5 ns (1.85 ns/item) | — | already batched |
| `SessionFlows::find` slot 0 / slot 63 | 3.7 / 40.9 ns | — | linear scan, memo covers steady hit |
| `match_source` per reply, n=1/8/64 | 20 / 34–38 / **160–168 ns** | — | lost legacy one-entry memo |
| `frame_bench` 128 B frame alloc+copy+free | 17.0 ns (same-thread), 25.2 ns (1200 B) | pooled: 22.7 ns / +33 % | pooling stays rejected |

**Interpretation (`[E]`, honest ceiling):** the MQP layer accounts for **~40–80 ns/payload**, roughly
**5–10 %** of per-datagram application CPU in the steady UDP path; the encoder is **~20–30 %** of the staged
send path because it is the allocation+copy. The actionable parse wins are therefore, in order:
(1) remove the second pass and the by-value `[u32;64]` copies in `TRAIN` decode (measured above);
(2) make the registry a direct-indexed table (lock/hash off the packet path);
(3) restore a one-entry reply-source memo before the ≤64-binding scan;
(4) `mark_open()` load-then-CAS instead of an unconditional CAS per downlink frame;
(5) one allocation+copy less per staged payload (frame built at push) — a design change, not pooling;
(6) dedupe first-byte classification, memoize the uplink target's last hit, batch the per-item stats clock.
Everything together is **low-single-digit % of one core at 50–100 kpps** and a *tail* improvement (no lock
handoff on the packet path), not a throughput multiplier.

### 4.3 Byte cost by workload (IPv4, isolated-packet lower bound)

From `analysis/rev3/wire_model.py` (formula-based, `[D]`):

| Workload | Current wire | Clean-slate rev3 | Δ |
|---|---:|---:|---:|
| One-shot UDP, IP target: 50 B request + 100 B reply | 3 pkts / **344 B** | 2 pkts / **277 B** | **−19 %**, −1 pkt |
| One-shot UDP, domain target L=11: 50 B + 100 B | 4 pkts / **426 B** | 2 pkts / **294 B** | **−31 %**, −2 pkts |
| 1000 one-shot domain flows, uplink-only | 2000 pkts / 187.5 KB | 1000 pkts / 123.0 KB | **−34 %**, −1000 pkts |
| Steady 128 B flow | 188 B/payload | 187 B | −0.5 % |
| 64 × 60 B fan-out TRAIN over 8 flows | 4159 B (3 frames) | 4141 B | −0.4 % |
| Bulk 1200 B at MTU 1400 | ~1259 B | ~1258 B | <0.2 % |
| New-connection MQP control | 25 B `HELLO+CAPS` + token, 2–3 pkts | **0** (TLS/ALPN) | removed |
| Association close | 3 pkts / ~192 B | 1 reliable msg / ~67 B | −65 % |

**Conclusion:** the wire win is concentrated in **one-shot flows and control**, exactly the DNS/telemetry/
QUIC-handshake shape that motivates the small-packet path. Steady/bulk header shaving is not worth design
risk; it is a free by-product of the fixed-width header, not the goal.

---

## 5. Consolidated levers (prioritized)

### 5.1 Phase 0 — no wire change (ship first)

| # | Lever | Gain | Risk / effort | Evidence |
|---|---|---|---|---|
| W1 | **Server: dispatch rev2 frames before/without `HELLO`** (HELLO stays as the CAPS trigger) | removes the 200 ms loss stall, the 8-frame/16 KiB overflow drop class, and the per-frame `hello_seen` branch | very low / low | `[C] accept.rs:2659-2696,1100-1104,1450-1470` |
| W2 | **Client: tolerate a late/missing `CAPS`** (CAPS only updates limits; never kill a live connection at 2 s) | removes the “lost control datagram ⇒ redial” cliff | low / low | `[C] client/rev2.rs:46-50,473-519` |
| W3 | **Queue-until-publish instead of drop** for UDP when no egress exists (bounded, e.g. 64 datagrams / 100 ms; overflow still drops) | removes the total-loss window during reconnect for the fail-closed/interactive class | low-medium / medium | `[C] assoc.rs:487-509; client_conf.rs:117-141` |
| W4 | **Domain-path failure must not lose the payload**: deliver via `INLINE` with the same pre-forward policy check (already validated IP/address), or hold it | removes 100 ms–5 s app retransmissions on DNS/policy/session failure | low-medium / medium | `[C] accept.rs:2067-2089,2110-2130,1200-1210` |
| W5 | **Synchronous memo/moka fast path in `r2_ingress_open`** (mirror `resolve_forward_target`) | warm-cache domain flows skip a spawn+await; ACK/compression start earlier | very low / low | `[C] accept.rs:2253-2325 vs forward.rs:388-423` |
| W6 | **Pre-auth bidi credit**: raise `SERVER_PRE_AUTH_BIDI_CREDIT` 4 → e.g. 64 (header-task credit still bounds parked streams); recalculate the admission term | removes the ~1 RTT `open_bi` stall for the 5th+ concurrent TCP flow after a dial | medium / low | `[C] config/tuning.rs:161; server/main.rs:878` |
| W7 | **Faster failure detection** (transport/config): lower idle/keepalive pair or add an app-level probe; document the trade | the 40 s watchdog dominates every reconnect; this is the largest user-visible latency | medium / low | `[C] transport/build.rs:179-183; auth.rs:21-43` |
| W8 | **CPU cleanup**: direct-indexed `FlowRegistry`; one-entry reply-source memo; `mark_open` load-then-CAS; dedupe first-byte classification; memoize uplink last-hit; batch stats clock | ~3–8 ns/frame each, ~30–150 ns/frame on the reply path; no wire change | very low / low | `[M] rev3_bench; [C] r2_flow.rs:146-153,325-366,436-441; accept.rs:2477,2497` |
| W9 | **Observability**: publish the existing `r2_stats` counters in the 60 s report | every claim above becomes measurable in the bench matrix (currently read only by tests) | very low / low | `[C] accept.rs:848-1010; server/reporter.rs:148-226` |

W1+W2 are the two “round-trip-shaped risk” removals that need no wire change and no protocol redesign.
W4 is the only lever that removes a *multi-second* avoidable latency.

### 5.2 Wire-change levers (rev3)

| # | Lever | Gain | Risk / effort | Verdict |
|---|---|---|---|---|
| R1 | Fixed **2 B packed header**, no varints: 2-bit class + 14-bit never-reused owner-split fid | removes the 63-flow cliff and the 3→4→5 B growth; O(1) decode; 2 B constant | low / medium | **do** |
| R2 | **K=2 context redundancy + implicit confirmation + reliable `NEED_CONTEXT`** replacing `FLOW_ACK`/`Opening` | one-shot: −1 packet (−21 % IP / −34 % domain); no ACK-gated header window; no `Opening` gate | medium / medium | **do** |
| R3 | **mTLS identity + ALPN version + static caps**; delete auth stream, `HELLO`, `CAPS`, pre-HELLO buffer, 2 s cliff | −1 token packet, −25 B/−2 pkts HELLO+CAPS per connection; removes the version-gate loss windows; precondition for R8 | medium (cert provisioning) / medium | **do if operator accepts mTLS** (else keep token, still delete HELLO/CAPS via constants) |
| R4 | **One reliable control stream** for `ASSOC_CLOSE`/`SESS_CLOSE`/`REJECT`/`NEED_CONTEXT`; delete `CTL` DATAGRAMs, `SESS_CLOSE`×3, CTL rate budget, hot-path CTL branch | close −65 % and deterministic; lost-close blackhole gone; fewer HOT-path branches | medium / medium | **do** |
| R5 | **`TRAIN` equal-length form** (`SAME_EQUAL`: item length once) + single-pass decode/encoder | −1 B/item for constant-size datagrams; −70–90 % TRAIN decode CPU | low / low | **do** |
| R6 | Encoder writes the header into payload headroom (frame built at push) | −1 alloc + 1 copy per staged payload (~15–25 ns) | medium (buffer ownership) / medium | **trial** |
| R7 | Forward-mode fixed TCP target bound once on the control stream ⇒ 0 B per-stream header | 7/19/4+L B per forwarded TCP flow | low / low | **optional** |
| R8 | **0-RTT payloads for an explicit replay-tolerant class** | **the only 1 RTT win**, on resumed reconnects only | high (replay semantics) / medium | **opt-in only, default off** |

### 5.3 Rejected (do not do)

| Do not | Why |
|---|---|
| Reuse flow ids with an epoch to shrink to 1 B | needs epoch bytes on the wire (≥3 B header — no win) or an ack/FREE-BIND handshake (reintroduces the RTT being removed); unsafe reuse misdelivers a delayed frame to a **new flow's target** |
| One-byte header universally | 4096 live flows need ≥12 id bits; only a reserved 64-fid short range is safe, worth ~1 B on a handful of flows — deferred, not v1 |
| Address dictionary for steady frames | steady frames already *are* dictionary-compressed (fid → binding); only one-shot `INLINE` benefits; complexity/benefit fails |
| Per-payload/datagram control (ACK/CLOSE) | each is a whole QUIC packet; move rare messages to the reliable stream |
| `FRAG` replaced by reliable streams | converts “drop” into “deliver late” + HOL; changes UDP semantics no app opted into; keep `FRAG`, prefer fewer fragments via higher `initial_mtu` |
| Aggregation timer / wait-to-fill TRAIN | adds latency; the stager already drains at burst end |
| Enable 0-RTT payloads by default | TLS 1.3 early data is replayable; a proxy carries non-idempotent UDP |
| Runtime wire negotiation / fallback | single version, ALPN fail-fast; a runtime switch is how mixed deployments happen |
| Frame-buffer pooling | already measured slower (same-thread +33–52 %, cross-thread +129–333 %) |

---

## 6. Recommended design — MQP-3 rev3

> Naming: the protocol name is a product decision (prior docs pin “MQP-3”, revision is the wire fact). This
> document calls the wire **rev3** and the ALPN placeholder `myquic2/r3`.

### 6.1 Principles

1. **Warm path stays at the RTT floor.** No control exchange may gate a payload.
2. **Self-describing first frame.** A flow's first payload carries `(session, address)`; no separate
   handshake, no cross-plane ordering dependency.
3. **No delivery ack, no install ack.** Context is redundant for a bounded window (K=2 frames) and repaired
   by a rare reliable `NEED_CONTEXT`, never by a per-flow round trip.
4. **Fixed width, no varints, no length on steady payloads.** Decode = class mask + two loads + table index.
5. **Identity, version and caps live in the TLS handshake** (mTLS, ALPN, constants). The application layer
   has no authentication or negotiation state machine.
6. **Rare correctness messages are reliable; payload is not.** One control stream per connection.
7. **Every peer-fillable structure stays bounded**, and no id is ever reused within a connection.

### 6.2 Wire format (exact)

All integers fixed-width little-endian. Byte 0 top 2 bits = class:

```text
bits 7..6  class
  00  DATA       steady, 2-byte header:  b0 = 00 fid[13:8]     b1 = fid[7:0]
  01  DATA_EXT   binding-carrying: OPEN / SRC / OPEN_SRC / INLINE (flags in b0 low bits)
  10  TRAIN      b0 = 10 form[5:4] reserved[3:0]
  11  FRAG       steady or extended (flags in b0 low bits)
fid ranges: 0x0000-0x1FFF client-allocated, 0x2000-0x3FFF server-allocated (8192 each,
            never reused while the connection lives; >= 2x the 4096 live-flow cap)
```

```text
DATA steady            2 B header + payload
DATA_EXT flags: 0x01 OPEN, 0x02 SRC, 0x04 INLINE
  OPEN       (0x01): fid:u16 | sess:u32 | addr | payload        header 14 B v4 / 26 v6 / 11+L dom
  SRC        (0x02): fid:u16 | addr | payload                    header 10 B v4 / 22 v6 /  7+L dom
  OPEN_SRC   (0x03): fid:u16 | sess:u32 | addr | payload         same as OPEN (server-owned flow)
  INLINE     (0x04): sess:u32 | addr | payload                   header 12 B v4 / 24 v6 /  9+L dom
TRAIN (count <= 64; nfl <= count; fids distinct; zero-length items allowed)
  SAME       (form 0): b0 | fid:u16 | count:u8 | count x (len:u8 [0xFF=>u16] | payload)
  SAME_EQUAL (form 1): b0 | fid:u16 | count:u8 | len:u8 [0xFF=>u16] | count x payload   <-- new
  DICT       (form 2): b0 | nfl:u8 | count:u8 | nfl x fid:u16 | count x (idx:u8 | len | payload)
FRAG (1 <= total <= 64, idx < total, chunk non-empty, 8 KiB cap)
  steady : b0 | fid:u16 | frag_id:u32 | idx:u8 | total:u8 | chunk                 header 9 B
  OPEN   : + sess:u32 | addr
  SRC    : + addr
  INLINE : b0 | frag_id:u32 | idx:u8 | total:u8 | sess:u32 | addr | chunk
```

Control stream (client-opened bidi; first byte `0xFF`; the server's stream classifier already distinguishes
by first byte, and a valid SOCKS atyp is only `0x01|0x03|0x04`):

```text
message = type:u8 | len:u16le | body        (len <= 64; unknown type/len => drop+count)
  0x01 ASSOC_CLOSE  C->S { sess:u32, reason:u8 }        (replaces SESS_CLOSE x3)
  0x02 FLOW_CLOSE   both { fid:u16,  reason:u8 }        (optional eager release)
  0x81 REJECT       S->C { fid:u16,  reason:u8 }        (policy / table-full / DNS)
  0x82 NEED_CONTEXT both { fid:u16 }                    (repair hint; rate-limited)
  0x83 SESS_CLOSE   S->C { sess:u32, reason:u8 }        (server reaped the session)
  0x84 GOAWAY       S->C { }                            (optional; id-space/health)
```

### 6.3 Interaction protocol

```text
FLOW send side (per endpoint):
  Free --(fid alloc + first payload)--> Context(K=2) --send K payloads--> Steady
  any  --recv ANY frame carrying fid--> Steady            (implicit confirmation, no ACK)
  any  --recv NEED_CONTEXT(fid)------> Context(K=2)       (reliable repair)
  any  --recv REJECT(fid)------------> INLINE(target) for the reason TTL

FLOW receive side:
  absent  --DATA_EXT OPEN/SRC/OPEN_SRC (policy-checked, forwarded, installed)--> Installed
  absent  --DATA steady fid --> drop + rate-limited NEED_CONTEXT (never guess)
  Installed --DATA/TRAIN/FRAG--> deliver
  Installed --ASSOC_CLOSE/SESS_CLOSE/FLOW_CLOSE/sweep--> absent (late frames drop)

SESSION (server): created by first valid OPEN; ASSOC_CLOSE purges; idle sweep + reliable SESS_CLOSE on reap.
CONNECTION: mTLS handshake + ALPN version gate; data plane and control stream usable immediately;
            fid low-water (<1024 of 8192) => new flows use INLINE (never a black hole).
```

The first K=2 frames carry full context; on a clean path only frame 1 pays the extra header. If the context
frame(s) are lost, later steady frames for that fid are dropped and the receiver asks once
(`NEED_CONTEXT`); the sender re-arms K frames. Recovery is one reliable message + the next payload — no ACK
state machine, no per-flow packet on the happy path.

### 6.4 Preserved invariants (and new ones)

| Invariant | rev3 |
|---|---|
| Bounds | 4096 live flows/conn, 64/session; 8 KiB/64 fragments, 2 s, 256 partials/256 KiB; stager 1024 items/256 KiB, TRAIN ≤64 items; **unchanged** |
| Flow-id safety | 14-bit owner-split, never reused per connection; a delayed frame finds no binding and can never alias a new flow |
| Per-item authorization | unchanged: every payload resolves to `(session, target/source)` and is policy-checked before forward; TRAIN items independently; unknown fid drops only that item |
| SSRF / private-IP policy, reply-source pinning, full-cone opt-in | unchanged (server-side at OPEN/DNS and on the reply path) |
| Version | ALPN fail-fast; a wrong-version peer fails the TLS handshake, never a frame parse |
| Control stream | one per conn, ≤64 B messages, length-validated before body, message-rate cap (e.g. 4096/s), pending-work bounded, untrusted input |
| Context redundancy | ≤K·16 B per flow, charged at admission (live flows × 32 B worst case) |
| Registry memory | paged fid table ≤16 384 × 8 B = 128 KiB/conn worst case, lazily paged (today's admission charges 4096 × 904 B ≈ 3.53 MiB) |
| Identity | mTLS verified in handshake; resumption via PSK ticket; ticket lifetime is a security parameter (revocation only on full handshake — documented trade) |
| Replay | 0-RTT payloads **off by default**; opt-in replay-tolerant class only; credentials never in early data |

### 6.5 Before/after per operation

| Operation | RTT added | Wire bytes | Parse/encode |
|---|---|---|---|
| First UDP, warm | 0 → 0 | OPEN 14 B v4 (same); steady later 2 B constant | fixed-width decode (2–3 ops) + direct table |
| One-shot IP target, 50 B + 100 B reply | 0 → 0 | **344 → 277 B**, 3 → 2 pkts | −1 ACK dispatch, −1 control branch |
| One-shot domain L=11 | 0 → 0 | **426 → 294 B**, 4 → 2 pkts | as above + repeat-context only on loss |
| Steady 128 B | 0 → 0 | 188 → 187 B | registry 4.4 → 1.5 ns; no varint |
| First-payload cold dial | 1 RTT → 1 RTT | −token, −HELLO/CAPS (≈196 B, 3 pkts) | −auth stream task, −version gate |
| First-payload resumed dial | 1 RTT → **0 (opt-in 0-RTT)** | as cold | as cold |
| Reconnect | detection + 1 RTT → detection + 0 (opt-in) | as cold | as cold |
| TCP CONNECT / forward | 0 → 0 | 7/19/4+L B header (unchanged; optional 0 B via R7) | unchanged (stream-native) |
| Flow close / session close | 0 user-visible | **192 → ~67 B**, deterministic | −×3 repeats, −CTL hot-path branch |

### 6.6 Phased implementation plan

* **Phase 0 (no wire change):** W1–W9 from §5.1. Acceptance: HELLO-loss fault injection shows <1 ms stall
  instead of 200 ms; no 2 s CAPS redial; domain-failure payload loss = 0; first-payload p99 unchanged or
  better; `r2_stats` visible in the report.
* **Phase 1 (codec only):** new `src/mqp/r3.rs` (DATA/EXT/TRAIN/FRAG + control messages), golden vectors for
  every form, decoder fuzz/property tests (truncation, flag pollution, count/len overruns), 2-byte id packing
  unit tests, `SAME_EQUAL` round-trips. Feature-gated, not wired.
* **Phase 2 (identity + contract):** mTLS verifier/client certs, ALPN `myquic2/r3`, delete token stream,
  `HELLO`/`CAPS`, pre-HELLO buffer, post-auth MAX_STREAMS raise; startup config fail-fast.
* **Phase 3 (UDP data plane):** paged fid registry, context-K sender, implicit confirmation, `NEED_CONTEXT`,
  `REJECT` TTL fallback, control stream, stager/FRAG ported; switch client+server together; delete ACK/CTL
  datagram machinery.
* **Phase 4 (TCP + cleanup):** control-stream accept dispatch, optional R7 target binding, delete rev2/v3/MQP-2
  production paths, rewrite README protocol sections, re-run the Linux netem matrix.
* **Acceptance gates (every phase):** bytes within ±5 % of the §6.5 model; p50/p99 first-payload and reply
  latency not worse; decode ns/frame and allocations/frame improve or hold; zero new loss/duplication in the
  E2E matrix; a mixed-version peer fails at the TLS handshake, never at the frame layer.

### 6.7 Migration and rollback

Single version, no runtime negotiation, no fallback: ALPN is the gate; a rev2 peer simply cannot complete the
handshake. Deploy matched client/server pairs (canary with paired binaries); rollback = redeploy previous
binaries; keep rev2 code behind a compile-time feature for exactly one release, then delete. Startup rejects
`alpn = "h3"` unless the operator explicitly accepts the masquerade trade (a less clear version failure), and
rejects/repurposes `auth_token` if mTLS is adopted. Monitor unknown-fid drops, `NEED_CONTEXT`, `REJECT` and
control-stream errors in the first hours.

### 6.8 Variant H− (if mTLS is rejected)

Keep the bearer-token stream and the pre-auth MAX_STREAMS raise, but still adopt everything else: ALPN
version, static caps (delete HELLO/CAPS + pre-HELLO buffer + 2 s cliff), 2 B fixed header, context-K instead
of `FLOW_ACK`, reliable control stream, `SAME_EQUAL`. This ships all parse/byte/risk wins and loses exactly
the one RTT win (0-RTT), because a replayable credential must not enter early data.

---

## 7. Open decisions requiring the user

1. **Auth model:** mTLS client certificates (recommended if provisioning is acceptable) vs keep the bearer
   token (H−). mTLS is the precondition for 0-RTT and removes an auth stream + pre-auth credit split; it adds
   certificate lifecycle/rotation and a revocation-window trade (short tickets).
2. **0-RTT payload policy:** default off (recommended) vs an opt-in replay-tolerant class (port/flow
   allowlist, e.g. DNS 53 / NTP 123 / telemetry). This is the only available RTT lever (1 RTT on resumed
   reconnects); the risk is datagram duplication, not impersonation.
3. **DNS ownership:** keep server-side resolution (recommended: preserves exit-side geo/policy and privacy
   model) vs add a client-side-resolution option (removes the resolver RTT from the first payload but changes
   which address a name maps to and leaks names to the client's resolver). A middle option exists: client
   supplies a speculative address inside OPEN, server SSRF-validates and keeps its own resolution as the
   authority for later frames — decide if that complexity is wanted.
4. **Naming / versioning:** keep “MQP-3 rev3” + dedicated ALPN vs a new name/“MQP-4”; and h3 masquerade vs
   clean ALPN (censorship resistance vs fail-fast clarity). Prior docs pin the MQP-3 name; this is a product
   decision.
5. **Id-exhaustion policy:** INLINE fallback for new flows after 8192 ids/conn + optional pool-driven
   connection recycling (recommended, no wire risk) vs any form of id reuse (rejected).
6. **Control-stream scope:** rare messages only (recommended) vs also moving binding/OPEN traffic onto it
   (rejected: cross-plane ordering hazards, extra state).
7. **TCP optimization:** keep the raw address header + in-band dial ACK (recommended) vs add forward-mode
   target binding on the control stream (0 B per-stream header) vs also remove the dial ACK (failure
   attribution gets worse; not recommended).
8. **Rollout:** matched-pair change window (recommended) vs any mixed-version tolerance (not recommended;
   defeats the fail-fast property).

---

## 8. Measurement plan (prove each claim before/after)

Existing machinery: `examples/hotpath_bench.rs` (`udp`, `udpdomain`, `udpmulti`, `udpfanout`, `udpps`,
`udppaced`, `udpbidir`, `udpsweep`, `tcp`, `bulk`), `scripts/linux-bench-matrix.sh`, `examples/frame_bench.rs`,
and the new `examples/rev3_bench.rs` (run: `cargo run --release --example rev3_bench`).

| Claim | Cell |
|---|---|
| One-shot flow packet/byte overhead (−33…−36 %) | `udpdomain` vs `udp` at 8–512 B; count client/server DATAGRAM sends and wire bytes from `ConnectionStats`; expect 4 pkts/flow (domain) today vs 2 after |
| ACK-gated compression window | `udpps`/`udppaced` 64–200 B; frames/payload in first 50 ms vs steady; `r2_stats` OPEN/STEADY ratio over time |
| HELLO-loss stall, pre-HELLO overflow | netem 0.5 %/2 % + fault-inject a dropped first HELLO; `PRE_HELLO_BUFFERED/DROPPED`; expect 200 ms stall before, <1 ms after W1 |
| Domain-path payload loss | `udpdomain` with cold/failing/filtered names; count lost datagrams and app retransmits; expect exactly 0 lost after W4 |
| DNS critical path | cold vs warm name first-reply p50/p99; DNS cache hit/miss events |
| Pre-auth credit stall | open >4 concurrent TCP CONNECTs immediately after a dial; `open_bi` wait histogram before/after W6 |
| Reconnect latency | blackhole fault injection: time from path death to first forwarded payload; W3/W7 targets |
| Parse/encode | `rev3_bench` (unchanged today vs after R1/R5/R6); ns/frame and allocations/frame |
| Byte model correctness | `wire_model.py` recomputation vs `ConnectionStats` on the all-size sweep (`udpsweep` 8 B–8 KiB) |
| No regression | full Linux matrix: netem 70/140 ms, 0/0.5/2 % loss, all modes, plus `udpbidir` p99 |

---

## Appendix A — current rev2 byte layouts (reference)

```text
DATA steady : 0x00 | wire_id:varint | payload
DATA ext    : 0x01 | flags:u8 | [wire_id:varint] | [sess:u32] | [addr] | payload
              flags: OPEN=0x01 INLINE=0x02 SRC=0x04
TRAIN       : 0x04 | form:u8 | count:u8 | (form 0: id:varint) | (form 1: nfl:u8 | nfl x id:varint)
              items: [idx:u8 if dict] | len:varint | payload
FRAG        : 0x08 steady / 0x09 ext | flags:u8 | [wire_id] | frag_id:u32 | idx:u8 | total:u8 | ...
CTL         : 0x0C | opcode:u8 | body   (HELLO 0x01, CAPS 0x02, FLOW_ACK 0x10, FLOW_REJECT 0x11,
              FLOW_CLOSE 0x12, SESS_CLOSE 0x20)
addr        : atyp:u8 (0x01 v4 | 0x03 domain | 0x04 v6) | addr | port:u16 BE   => 7 / 4+L / 19 B
```

## Appendix B — timeline reconciliation (why the 0-RTT saving is 1 RTT)

Input report `rtt-client.md` uses a timing table where the server's handshake flight arrives at the client
after one one-way delay (`t = d`). That is one one-way optimistic: the ClientHello itself needs `d` to reach
the server, and the server flight needs another `d` back. Correct timeline: client publishes at **1 RTT**
(after receiving the server flight), the server receives the client's Finished + token + first data at
**1.5 RTT**, so that is the first forward. With 0-RTT application data (and identity from a resumed ticket),
the client sends at `t = 0` and a server that starts its reader before handshake completion can forward at
**0.5 RTT** — a **1 RTT** saving. Under either reading, the *deltas* and the design conclusions are
unchanged; only this magnitude differs. It needs a measured confirmation (timestamp first-payload at client
and at target under a resumed connection, with and without early data).

## Appendix C — artifacts

| Artifact | Content |
|---|---|
| `analysis/rev3/rtt-client.md` | client RTT audit: event table, F1–F22, L1–L12, verbatim code, contradictions (`src/` untouched) |
| `analysis/rev3/rtt-server.md` | server RTT/latency audit: step table, S1–S20, L1–L13, byte arithmetic, measurement cells |
| `analysis/rev3/parse-cost.md` | exact wire layouts, id-width math, op-count tables, P1–P16, C1–C15 vs W1–W7, clean-slate proposal |
| `analysis/rev3/design-options.md` | lower bounds, candidates A/B/C, 14-lever verdicts, target wire layout, invariants, phase plan, 12 decisions |
| `analysis/rev3/wire_model.py` | reproducible byte/interaction model for current vs rev3 (tables in §4.3) |
| `examples/rev3_bench.rs` | new micro-benchmark (decode/encode/TRAIN/registry/session tables + wire tables); run with `cargo run --release --example rev3_bench` |

---

## Appendix D — implementation status (2026-10-28)

The recommendations above were implemented in this tree, with one explicit deviation requested by the
operator: **maximum 0-RTT was prioritized over the security recommendation**. The security/replay waiver is a
user decision, not an oversight.

### D.1 What shipped

**Phase 0 — no-wire fixes (shipped, revision-independent):**
- HELLO no longer gates rev2 data frames; the 8-frame/16 KiB pre-HELLO buffer, its drops and its per-frame
  `hello_seen` branch are gone (`server/accept.rs`). A lost HELLO can no longer stall/drop data.
- Missing/late CAPS never tears down a live connection; HELLO retries continue in the background at a slow
  cadence; only an explicit wrong-version answer stays fatal (`client/rev2.rs`).
- Bounded queue-until-publish for UDP (per-association 64 items / 64 KiB / 500 ms, drop-newest, FIFO flush)
  instead of dropping datagrams whenever no egress connection exists (`client/rev2.rs`, `client/assoc.rs`).
- Synchronous warm-DNS fast path for rev2 domain OPENs; distinct DNS/policy/session failure counters
  (`server/accept.rs`).
- One-entry reply-source memo in front of `match_source` (`server/reader.rs`), `mark_open` load-then-CAS,
  single first-byte classification, per-burst coarse clock, r2 counters in the 60 s report.
- Pre-auth stream credit 4/2 → 64/8 with admission math updated (needed by max-0-RTT TCP streams).
- Faster/late-CAPS-tolerant client handshake plus the 0-RTT publish described below.

**Max 0-RTT (implemented; replay accepted):**
- Client writes the bearer token on a **0-RTT uni stream**, returns the 0.5-RTT `quinn::Connection`
  immediately (`dial_once` no longer awaits `ZeroRttAccepted`), publishes it, and sends HELLO / rev2 or rev3
  OPEN frames / TCP target headers in the first flight. A detached monitor detects rejection and re-sends the
  token on a 1-RTT stream; `authenticate()` tolerates reset/discarded early uni streams.
- Server accepts the 0.5-RTT connection, authenticates and starts `handle_conn` **before** the handshake
  settles; the pre-auth permit/IP guard is held until auth completes.
- TCP `open_bi` + header write happens on a 0-RTT stream; on `ZeroRttRejected` the helper waits for the
  handshake phase and retries on a 1-RTT stream without consuming app bytes.
- TLS: early data enabled both sides, client resumption store 1024 sessions, server mints 4 single-use
  tickets per handshake. Known residual race (documented in README): a 0-RTT write can be accepted by quinn
  and discarded when rejection resolves after the write-ok; that flow fails closed and the tunnel survives.
  Closing the race would re-add the handshake RTT in front of TCP app bytes.
- The only requested security deviation: the bearer token may appear in replayable early data (an observer
  that captures one handshake can replay the credential inside the ticket window), and replayable application
  datagrams are accepted. Do not use this configuration on an untrusted path without accepting that.

**rev3 wire (shipped, default; rev2 selectable for one release):**
- New codec `src/mqp/r3.rs`: fixed-width little-endian, 2-byte packed DATA header (2-bit class + 14-bit
  owner-split never-reused fid), no varints; OPEN/SRC/OPEN_SRC/INLINE; TRAIN SAME / SAME_EQUAL / DICT; FRAG
  steady/OPEN/OPEN_SRC/SRC/INLINE; bounded validation with no panics.
- `src/mqp/wire.rs` revision adapter keeps the internal `u32 wire_id` tables (`r2_flow`, `r2_stage`,
  `r2_reasm`) unchanged via a fid⇄wire_id mapping; `src/mqp/ctl_stream.rs` implements the reliable control
  plane (`type|len|body`, ASSOC_CLOSE/FLOW_CLOSE/REJECT/NEED_CONTEXT/SESS_CLOSE/GOAWAY, rate budget, marker
  byte 0xFF vs TCP atyp classification).
- No per-flow FLOW_ACK on rev3: the sender carries binding context for the first K=2 payloads and then
  self-marks the binding open; the receiver repairs a missed context with a reliable `NEED_CONTEXT`. For
  downlink rebinds the server sends SRC/OPEN_SRC context for K=2 replies then steady, without waiting for an
  ACK. **Fixed during integration:** payloads sent before the handshake is known complete (i.e. 0-RTT early
  data) always carry binding context and never consume the K=2 window, because early DATAGRAMs can be
  discarded on resumption rejection and would otherwise spend the window on frames the server never saw.
- No HELLO/CAPS on rev3: the revision comes from configuration (`wire_rev`), limits are static constants, and
  there is no wire-level version exchange. **Both revisions default to the shared `h3` ALPN masquerade**, so
  ALPN is a deployment label, not a revision switch: a mismatched pair with the same label completes the TLS
  handshake and then fails silently at the data plane (nothing forwarded or misrouted), so deployments must
  run matched binaries. Operators who want a TLS-level skew gate pin distinct `alpn` labels on both sides
  (`Wire::versioned_alpn()`: `myquic2/3` for rev2, `myquic2/r3` for rev3). rev2 additionally keeps
  `CTL HELLO/CAPS wire_ver=2` and remains the one-release rollback wire.
- Connection-scoped id limits: 8192 rev3 fids per owner; exhaustion falls back to `INLINE` without burning
  ids. SESS_CLOSE×3 and FLOW_REJECT datagrams are replaced by the reliable control stream on rev3; a lost
  close has a reliable, deterministic delivery path.
- TCP data plane stays stream-native (address header + optimistic SOCKS success), with rev3's 0xFF control
  stream distinguished from atyp 0x01/0x03/0x04 by a consumed-first-byte dispatcher; the in-band dial ACK is
  unchanged.

**Configuration:** `wire_rev = 2 | 3` in `config-client.toml` / `config-server.toml`; unset = build default
(**3**). Both peers must match; with the default shared `h3` label a mismatch is not rejected at the
handshake (it fails closed at the data plane), while distinct `alpn` labels restore a TLS-level fail-fast
gate. Rollback for one release: set `wire_rev = 2` on both sides. mTLS was **not** adopted (the operator
chose max 0-RTT with the token in early data instead).

### D.2 Verification snapshot

- Codec/unit: lib 350 tests; rev3 codec 47; wire adapter 12; control stream 5; fragmenter/reassembler rev3
  coverage.
- Binaries: client 198, server 142 (both include 0-RTT pre-handshake and rev3 data-plane tests).
- Process-level: `tests/forward_e2e.rs` 7/7 (including the server-restart recovery test, now anchored on the
  restarted server's "new QUIC conn from" line), new `tests/rev3_e2e.rs` 8/8 (rev3 UDP/TCP/forward/domain/
  FRAG, rev2 rollback, distinct-ALPN-label TLS rejection both directions, rev3 0-RTT resumption after a forced
  path break).
- Gates: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`
  green in the final gate run (see the Lead's final report for exact counts).
- Measured pre-implementation baselines and the expected deltas remain in §3/§4; the implemented rev3 removes
  the per-flow ACK datagram, the 63-flow header cliff, the HELLO gate and the rev2 control-DATAGRAM set, as
  designed.

### D.3 Deviations from the recommendation (deliberate)

0. **rev3 defaults to the `h3` ALPN masquerade, like rev2.** The design recommendation was a dedicated
   `myquic2/r3` ALPN as the revision gate. The implemented behavior follows the operator's later instruction
   that rev3 must default to `h3` exactly like rev2: ALPN is a deployment label (shared default, custom
   labels optional), so revision skew is not detected at the handshake unless distinct labels are pinned;
   matched binaries are required. The dedicated labels remain available via
   `Wire::versioned_alpn()` / `alpn = "myquic2/r3"` for operators who want the fail-fast gate.
1. **mTLS not adopted**; identity remains the bearer token, now sent in 0-RTT (user instruction: maximize
   0-RTT, ignore the security recommendation).
2. **rev2 retained as a config-selectable rollback wire for one release** instead of a hard single-version
   cutover. The default is rev3; runtime negotiation does not exist, so a mixed deployment still fails at
   ALPN.
3. **K=2 context redundancy** (rather than K=1 or a reliable OPEN stream) is the no-ACK policy; it bounds the
   loss window to two context frames while keeping the zero-ACK happy path.
4. **No address dictionary** (analysis §6.3): only one-shot/INLINE traffic would benefit; not worth the
   complexity for v1.
5. **FRAG stays on the unreliable plane**; large-payload reliability remains out of scope.
