# MQP rev3 — clean-slate wire design options (independent analysis)

> **Task:** `task-4` (owner `wire-design`). **Deliverable:** this file only.
> **Status:** analysis, no code changed, no build/test run. Backward compatibility is explicitly *not* required.
> **Scope:** application-layer wire revision ("rev3") carried in QUIC DATAGRAMs (UDP path) and QUIC bidi streams
> (TCP path), optimized in this order: (1) round trips / first-payload latency, (2) parse/encode cost,
> (3) wire bytes, (4) preservation of the security/resource invariants.


**Bottom line (for the synthesis).**

1. **The warm path is already at the information-theoretic RTT floor for every operation, and no wire revision can
   improve it.** The only application-layer RTT anywhere is **1 RTT on a resumed connection**, and it needs
   handshake-verified identity (mTLS) plus an explicit replay-tolerant-payload policy — a security decision, not a
   codec decision. HELLO/CAPS, FLOW_ACK and the auth stream add **zero** RTT today; what they add is risk, bytes,
   parse cost and a 2 s redial cliff.
2. **Recommended target (`rev3`):** C's identity/contract layer (mTLS + ALPN/static caps, no token stream, no
   HELLO/CAPS) + A's self-describing data plane with fixed 2 B / 14-bit never-reused fids, K=2 context redundancy
   instead of FLOW_ACK, a new equal-length TRAIN form, and B's reliable stream restricted to the rare
   close/reject/need-context messages. TCP path unchanged (already at floor).
3. **Quantified wins vs current:** one-shot DNS/DNS-over-SOCKS flow wire **−21 % (IP target) / −34 % (domain)**;
   steady payload header **2 B constant vs 3 B typical, growing to 4–5 B**; association close **−65 %** and
   deterministic; new-connection MQP overhead **−196 B + token, 3 packets**; steady decode **20–35 → 8–12 ops**
   `[E]`; **1 alloc + 1 copy saved per staged payload** `[E]`; no 2 s CAPS cliff, no pre-HELLO buffer, no
   FLOW_ACK/Opening state machine.
4. **Biggest risk/decision:** mTLS provisioning (and the 0-RTT replay policy). If mTLS is rejected, use variant
   `H−` (A + items 2–10 of §4.1) — still a strict improvement, but it loses the only RTT win and keeps the token
   stream.
5. **Where this contradicts the premise/README:** the advertised "2 B steady header" is real only for the first
   63 flows/owner per connection (then 3 B, then 4–5 B as never-reused ids grow); quinn packs several DATAGRAM
   frames per packet, which weakens TRAIN's *byte* case and strengthens its send-call/CPU case; HELLO/CAPS never
   delays a payload; FLOW_ACK is not a delivery ACK but cannot be deleted without a replacement; FLOW_CLOSE is
   dead wire code.

**Evidence grades used throughout** (kept explicit so the Lead can price each claim):

| Tag | Meaning |
|---|---|
| `[C]` | verified in code at the cited `file:line` (or verified absent: "no production call site") |
| `[D]` | derived by arithmetic from `[C]` constants/encodings; the derivation is shown |
| `[E]` | engineering estimate/model (latency, ns, CPU); must be measured before it is promised |
| `[M]` | measured number copied from this repo's docs (no new measurement was run for this analysis) |

Numbers marked `[D]` are reproducible from the formulas in Appendix A. Numbers marked `[E]` are the ones a
benchmark must confirm. Where this analysis contradicts the mission brief or the repo docs, the contradiction is
called out explicitly in Appendix B.

---

## 0. Cost model and vocabulary

### 0.1 Per-packet wire overhead

A UDP payload carried by the current stack costs, on IPv4:

| Layer | Bytes | Source |
|---|---:|---|
| IPv4 + UDP | 28 | protocol |
| QUIC short header (flags 1 + DCID 8 + PN 1–2 + AEAD tag 16) | 26–27 | `[C]` quinn-proto 0.11.19 `src/cid_generator.rs:55-63` (default CID 8), TLS 1.3 GCM tag 16 |
| QUIC DATAGRAM frame (type 1 + length varint 2) | 3 | `[C]` quinn-proto `src/frame.rs:901-918` |
| **Total per packet, isolated frame** | **≈57** | `[D]`; 77 on IPv6 |

The live DATAGRAM body budget is `Connection::max_datagram_size()` = `current_mtu − 38` `[C]`
(quinn-proto `connection/datagrams.rs:82-95`: `mtu − predict_1rtt_overhead − Datagram::SIZE_BOUND`), i.e.
**1162 B at the shipped 1200 B initial MTU** and 1434 B at 1472 `[D]`; this matches `README.md:436` and
`src/config/tuning.rs:287`.

**Quinn packs several DATAGRAM frames into one QUIC packet.** The transmit path loops
`while buf.len() + Datagram::SIZE_BOUND < max_size { self.datagrams.write(...) }` `[C]`
(quinn-proto 0.11.19 `src/connection/mod.rs:3347-3359`; `write` pops exactly one datagram,
`src/connection/datagrams.rs:200-221`). Consequences used repeatedly below:

* The 54 B fixed part (IP/UDP/QUIC header) is shared by `k` frames packed in one packet; only the 3 B
  DATAGRAM frame header is per frame. For `k` frames/packet: effective overhead `54/k + 3` per frame.
* The prior design docs' model "one QUIC packet carries one MQP frame" (`MQP3_REFACTOR_ANALYSIS.md:405`) is
  only true for isolated sends; bursty sends already amortize the packet header via quinn, so `TRAIN`'s byte win
  is the per-frame 3 B + MQP header + send-call, not the whole 57 B. This makes the byte case for any new header
  encoding *weaker* than the earlier model, and the parse/CPU case *relatively stronger*.

### 0.2 RTT definitions

* `RTT` = client↔server tunnel RTT. One-way = `RTT/2`.
* **warm** = a live QUIC connection with keys and (where relevant) a confirmed binding.
* **cold** = no live connection and no resumption ticket: a fresh 1-RTT QUIC/TLS 1.3 handshake is required
  before *any* 1-RTT payload can be decrypted by the server. Server processes client 1-RTT data at ≈1.5 RTT
  after the client's first Initial (0.5 server flight, 0.5 client flight, 0.5 app data); this is a transport
  floor, not an MQP choice.
* **resumed** = live resumption ticket (`Connecting::into_0rtt()`), 0-RTT keys available immediately.
* "Added RTT" below always means *application-layer* RTT on top of the transport floor; the floor itself is
  stated once per operation.

### 0.3 Current-implementation facts this analysis is built on

All `[C]`; these are the "current" column of every table.

| Fact | Evidence |
|---|---|
| Wire codec: rev2 frames in DATAGRAMs; TCP uses raw address header + app bytes on a bidi stream | `src/mqp/r2.rs:1-43`, `src/bin/myquic2-server/tcp.rs:44-52`, `232-260` |
| Flow id `wire_id = (local_id << 1) \| owner`, LEB128 varint; local id monotonic, **never reused**; live cap 4096/conn, 64/session | `src/mqp/r2.rs:143-148`, `src/mqp/r2_flow.rs:36,40,743-778` |
| Steady DATA = `0x00 \| wire_id:varint \| payload` (1 + 1–2 B header); OPEN = 14 B v4 / 26 B v6 / 11+L domain; INLINE = 13/25/10+L; TRAIN same = 4–5 B + 1–2 B/item; FRAG steady = 8–9 B; CTL HELLO 8, CAPS 17, FLOW_ACK 4–5, FLOW_REJECT 4–5, SESS_CLOSE 7 | `[D]` from `src/mqp/r2.rs:275-289,430-456,686-700,903-914`; `[C]` goldens `src/mqp/r2.rs:1113-1314` |
| HELLO/CAPS handshake: client sends HELLO immediately, retries every 200 ms until CAPS; **hard 2 s cap after which it closes and redials**; server answers CAPS (always `Caps::default()`) throttled to 1/100 ms; pre-HELLO frames are buffered (8 frames / 16 KiB) then replayed — data is *not* blocked on CAPS | `src/bin/myquic2-client/rev2.rs:46-53,473-535`; `src/bin/myquic2-server/accept.rs:826-848,1103-1104,1437-1466,1823-1836`; optimistic publish `src/bin/myquic2-client/egress.rs:414-425` |
| CAPS is constant: the server never constructs anything but `Caps::default()`; client consumes only `max_frame_bytes` and `max_train_items`, both equal to protocol constants (1472 / 64); `max_conn_flows`/`max_flows_sess` are documented as reserved/not enforced | `[C]` `src/bin/myquic2-server/accept.rs:1832-1835`, `src/mqp/r2.rs:99-105,876-888` (only test constructors elsewhere), `MQP3_REV2_SPEC.md:98-99` |
| FLOW_ACK: server ACKs each accepted client OPEN; client ACKs each downlink `OPEN\|SRC`; sender keeps sending `OPEN` (full sess+addr) until the ACK arrives; server keeps re-sending `OPEN\|SRC` until the client's ACK arrives | `src/bin/myquic2-server/accept.rs:2165-2170,2336-2341,1846-1852`; `src/bin/myquic2-client/dispatcher.rs:861-882,993-996,1117-1135,1362`; `src/mqp/r2_flow.rs:92-118,325-366` (reply_src only "Steady" after ack) |
| FLOW_CLOSE is **never emitted in production**: encode/decode exist plus tests, no constructor outside tests | `[C]` `grep` over `src/bin`: only `dispatcher.rs:985,1016` (decode) and `accept.rs:1816,1862` (decode); tests only |
| SESS_CLOSE is sent 3× best-effort on association exit (client) and 3× per reaped session (server); loss is backstopped by the 180 s idle sweep | `src/bin/myquic2-client/rev2.rs:557-640`; `src/bin/myquic2-server/accept.rs:1533-1576`; `README.md:347,352` |
| Auth: bearer token (≤256 B) written on a **new 1-RTT uni stream after handshake**; server awaits `accept_uni` + token before starting the datagram reader; 256 pre-auth connection slots; bidir credit raised only after auth | `src/bin/myquic2-client/auth.rs:412-447`; `src/bin/myquic2-server/auth.rs:22-47`; `src/bin/myquic2-server/main.rs:849-880`; `src/mqp/ack.rs:54`; `accept.rs:12-20` |
| 0-RTT: client and server both enable early data (server `max_early_data_size = u32::MAX`, stateful single-use tickets); **but the client awaits the handshake-complete future before writing the token, and writes no application data in early data**, so a resumed connection saves no application RTT; the only use today is cheaper handshake bytes/CPU | `[C]` `src/bin/myquic2-client/auth.rs:356-410`; `src/tls/client_cfg.rs:20-22`; `src/tls/server_cfg.rs:20-37`; `src/bin/myquic2-server/main.rs:796-830`; `examples/zero_rtt_probe.rs:36-60` |
| Session id: monotonic `u32` per process, 4032 associations, ids effectively never reused (`0`/`u32::MAX` skipped) | `src/bin/myquic2-client/hub.rs:335-360`; `src/lib.rs` `MAX_UDP_ASSOCS`; `README.md:270` |
| TCP path: client writes the address header, sends **optimistic SOCKS5 success with 0.0.0.0:0 BND**, then relays app bytes immediately; server reads header (5 s), dials (Happy Eyeballs, 4 s, 8 candidates), writes a 10 B (v4) / 22 B (v6) "MQ" ACK on the same stream, then relays; the ACK is consumed in the reply direction and a failed dial resets the stream | `src/bin/myquic2-client/socks.rs:7-9,228-258`; `src/bin/myquic2-server/tcp.rs:44-52,170-205`; `src/mqp/ack.rs:41-49,127-135` |
| Client UDP egress: dedicated interactive + bulk UDP connections (default 1 + 2), may fail over to sibling UDP connections (`udp_fail_closed = false`) or TCP slots | `src/config/tuning.rs:80-111`; `src/bin/myquic2-client/egress.rs:317-348`; `config-client.toml:59-67` |
| Transport: BBR, keepalive 5 s, idle 60 s → client watchdog 40 s, selection stale gate 22 s, reconnect backoff 200 ms–5 s; DATAGRAM buffers 1/2 MiB; ACK freq 2/5 ms (interactive) or 8/10 ms (bulk) | `src/config/tuning.rs:296-345`; `src/transport/build.rs:279-407`; `src/bin/myquic2-client/auth.rs:21-43`; `src/transport/limits.rs:86-102` |

**Flow-id reality check (contradicts the "2 B steady header" headline).** A one-byte LEB128 holds ids 0–127.
With `wire_id = (local_id << 1) | owner [C]` only **63 flows per owner** per connection get a one-byte id
(local 1..=63). From the 64th flow on, the id is ≥128 and costs 2 B → **steady header = 1 B kind + 2 B id = 3 B**.
Because live flows are capped at 4096/conn `[C]`, a connection carrying more than ~63 flows (the normal
connection-level-multiplexing case) pays 3 B, not 2 B. Worse: ids are *never reused* `[C]`, so after 8192
cumulative opens per owner the id needs 3 varint bytes → **4 B header**, and grows from there over a long-lived
connection. The README table (`README.md:193-200`) is technically correct in its "wire_id < 128" rows but the
§1/§4.1 headline "2 B instead of 5–6 B" describes only the first 63 flows of a connection. **This is a real,
measurable regression-in-waiting of the current id encoding, and one of the strongest arguments for a
fixed-width id plus a bounded id-lifetime policy.**

---

## 1. Lower-bound analysis

### 1.1 The four information rules

Every operation below is bounded by what each endpoint must *know* before it can act. The rules:

* **R1 — payload knowledge.** Endpoint B cannot forward a payload it has not received. Earliest delivery to a
  target is `send_time + 0.5·RTT + server work` (+ target-side RTT if the target needs a handshake).
* **R2 — peer knowledge.** The client cannot know anything only the server knows (e.g. the real BND address,
  that a dial failed, that a session was reaped) without a server→client message: **≥0.5 RTT** after the server
  learns it. It is never possible to remove this; it can only be moved off the critical path.
* **R3 — binding knowledge.** A receiver can route a *compressed* (id-only) frame only after it knows
  `id → (session, target/source)`. Sending the binding information **in the same flight, in a self-describing
  first frame, or on a reliable channel whose loss is repaired** costs zero *extra* round trips. Any scheme
  that requires the sender to *learn that the receiver installed the binding* before compressing costs
  ≥1 RTT of compression delay (not delivery delay) unless the install is guaranteed by redundancy or by a
  reliable channel.
* **R4 — transport floor.** Cold connections pay the QUIC/TLS handshake (1 RTT until the client can send 1-RTT
  data; the server can decrypt it one one-way RTT later). Resumed connections with accepted 0-RTT can send
  application bytes immediately (0 RTT *added*); without early data they pay the same 1-RTT handshake.

### 1.2 Per-operation lower bounds

`floor` = minimum *added* application-layer RTT any design can achieve. `current` = what rev2 does today
(`[C]`/`[D]`), `gap` = current − floor. All warm unless stated.

| # | Operation | What each side must know before it can act | floor (added) | current (added) | gap |
|---|---|---|---|---|---:|
| 1 | **First UDP datagram to an unknown target**, warm conn | client: tunnel keys (have), target (app), session (local). server: target+session+payload (must arrive), auth (already done). No server→client info needed. | **0** (payload arrives 0.5 RTT after send; floor is transport, not MQP) | **0** — self-describing `DATA OPEN` carries payload | 0 |
| 1b | same, **cold** conn | + TLS/QUIC handshake keys | **1 RTT** (server decrypts 1-RTT payload at ≈1.5 RTT) | 1 RTT; HELLO/CAPS and the token stream share that flight and add **no** RTT | 0 |
| 1c | same, **resumed** conn, replay-tolerant early data allowed | + PSK/0-RTT keys; server must trust the client identity from the handshake | **0** (payload at 0.5 RTT) | 1 RTT: client awaits handshake completion, then writes auth token; it deliberately sends **no** early application data | **1 RTT** |
| 2 | **Steady UDP datagram**, confirmed flow, warm | receiver: existing binding; no new information | **0** | **0** | 0 |
| 3 | **New TCP CONNECT through SOCKS** (warm) | server: target address (from stream header), then target dial 1 RTT; client must *not* wait for the server's dial ACK or it loses 1 RTT (SOCKS success can be optimistic) | **0** added over direct TCP; app's first byte reaches target at ≈1.5 RTT after the SOCKS request (0.5 tunnel + 1 target dial) — same as a direct TCP connect+send | **0**: optimistic SOCKS success + pipelined app bytes; the real BND is traded away (0.0.0.0:0) | 0 |
| 3b | same, **real BND.ADDR in the SOCKS reply** | client must receive server's bound-address ACK (R2) | **+1 RTT** vs optimistic (ACK arrives ≈1.5 RTT after request) | 0 added — current *rejects* the real BND to stay at the floor | 0 (feature is deliberately dropped) |
| 4 | **TCP forward-mode accept** (fixed configured destination) | server: target may be known out-of-band; still must dial it (1 RTT) | **0** added over direct TCP; header bytes can be **0** if target is pre-bound to the connection | 0 added; still sends a 7/19/4+L B address header per flow | 0 RTT; **7–19 B/flow** |
| 5 | **Reconnect after path failure** | detection (transport-level) is the real cost; after detection, first queued payload needs either early data (0.5 RTT) or a full handshake (1.5 RTT) | **detection + 0** (0-RTT, replay-tolerant class) or **detection + 1 RTT** (fresh handshake) | detection (22–40 s today, transport) + 1 RTT; auth stream does not add an RTT (token rides the first post-handshake flight) | **1 RTT** (only with 0-RTT early payloads); detection gap is transport, not wire |
| 6 | **New downlink reply source / rebind** | server: source address (recvfrom) + local flow match; client: actual source (R2) to write the SOCKS reply header | **0** (first reply carries self-describing source; later replies compressed) | **0** delivery; but server re-sends `OPEN\|SRC` and waits for a `FLOW_ACK` before compressing; every reply until that ACK is 14 B header, and the client sends a 4–5 B ACK datagram per flow | 0 RTT; **~1 ack packet + up to 1 RTT of repeated context** |
| 7 | **Flow close / session close** | peer must learn the release to reclaim state (R2); user payload unaffected | **0 user-visible**; reclamation needs ≥0.5 RTT one-way (or a timeout) | best-effort `SESS_CLOSE`×3 (7 B each) or idle sweep; no correctness dependency | 0 RTT; **~190 B/association** and nondeterministic reclaim |
| 8 | **One-shot DNS-query flow** (UDP query to a resolver, or SOCKS UDP with a domain target) | same as #1/#2; for a *domain* target the server additionally resolves (external resolver RTT on cache miss, not tunnel RTT) | **0** added; query at server 0.5 RTT, reply at client 0.5 RTT after the resolver answers | **0** added; extra wire: `FLOW_ACK` packet + repeated `OPEN` context for the first RTT | 0 RTT; **~20–35 % of the flow's wire** (§4.6) |

### 1.3 Where the current design actually wastes RTT (and where it does not)

* **HELLO/CAPS never delays a payload.** The egress cache publishes a connection before CAPS
  `[C] src/bin/myquic2-client/egress.rs:414-425`, and the server buffers pre-HELLO frames
  `[C] accept.rs:2645-2698,1450-1466`. Its cost is **bytes, complexity, and a failure mode** (the 2 s redial
  cap can kill a working connection; a reconnect burst can overflow the 8-frame pre-HELLO buffer and drop
  payloads). It also imposes a per-frame version-gate atomic load/branch in the hot path `[C] accept.rs:2688-2694`.
* **FLOW_ACK does not change delivery latency; it changes header bytes and *when* compression starts.** It is
  explicitly not a delivery ACK (`README.md:266,351`). The only latency-shaped effect is that a lost ACK delays
  compression for up to one RTT (uplink-only flows) or indefinitely-but-retried (downlink rebinds). It costs one
  DATAGRAM packet per flow plus the `Opening → Open` state machine, and it is *why* current code on a lossy path
  degrades to per-payload 14 B `OPEN` headers instead of compressing.
* **0-RTT currently saves no application RTT.** The client awaits `accepted_fut` and only then sends the token
  and publishes the connection `[C] auth.rs:366-410`. The early-data slot is enabled on both sides
  (`client_cfg.rs:20-22`, `server_cfg.rs:20-37`) but unused for application data. The *only* way to turn it into
  RTT is (a) auth that is verified in the handshake (mTLS) and (b) a deliberate replay policy — see §2C.
* **OPEN repetition until ACK is the current design's loss-recovery for bindings.** There is no other mechanism:
  if the first `OPEN` is lost, the flow is unusable until a later `OPEN` installs it; the sender keeps paying
  the 14 B header until an ACK (or a lost-ACK retry) lands. On a 70 % loss bench link this is a permanent
  per-payload tax for the flow's life, not a transient.
* **Per-flow control datagrams are pure overhead.** `FLOW_CLOSE` is dead code on the send side `[C]`; `FLOW_ACK`
  is replaceable by bounded redundancy; `FLOW_REJECT` matters only for fallback decisions. Moving the rare,
  correctness-relevant ones (close/reject) to a reliable channel and deleting the rest is a net win in bytes,
  parse cost and code size — but it is **not an RTT win**.
* **The TCP path is at the floor.** Optimistic SOCKS success + pipelined bytes means the proxy adds 0 RTT over a
  direct TCP connect; the only things left are the 7–19 B header and 10–22 B ACK bytes, and the *real BND*
  trade (deliberately dropped). Any rev3 work here is bytes/parse, not latency.

### 1.4 Latency cliffs (these matter more than micro-RTT and are mostly not wire)

| Cliff | Current | Owner | Consequence |
|---|---|---|---|
| Dead-path detection | 40 s silence watchdog; 22 s selection-time stale gate `[C]` `src/transport/build.rs:179-183`, `auth.rs:84-200` | transport config | A flow assigned before detection loses 22–40 s of payload; wire cannot fix. A shorter keepalive or `idle_timeout_secs` trades NAT tolerance. |
| CAPS fail-fast | 2 s `[C] rev2.rs:52` on a lossy link → P(all HELLOs lost) at 70 % loss × 10 tries ≈ 2.8 % of dials kill a usable connection | protocol (removable) | Redial backoff 200 ms–5 s + handshake. **Remove HELLO/CAPS** and this cliff disappears. |
| Pre-HELLO overflow | 8 frames/16 KiB `[C] accept.rs:1103-1104` | protocol (removable) | On a fast reconnect burst, pre-HELLO frames beyond the cap are dropped (payload loss). With version gating in the handshake this machinery does not exist. |
| FLOW_ACK loss / FLOW_REJECT latency | compression delayed 1 RTT; `FLOW_REJECT` learns fallback after 0.5 RTT (payloads still forwarded because `OPEN` carries them) | protocol | Replace with bounded context + reliable reject. |
| Server-side DNS on domain targets | resolver RTT on cache miss (external, potentially seconds under load) `[C] accept.rs:2051-2184` | policy decision | Client-side resolution would remove the server resolver RTT but changes DNS/SSRF policy; open decision (§5). |
| TCP dial failure after optimistic SOCKS success | 25 s ACK timeout budget `[C] socks.rs:5-9` | transport/TCP | Only on failure; not steady state. |
| First-flight cwnd/pacing | BBR slow start / initial window, `initial_rtt` seed 190 ms `[C]` `config/tuning.rs:260,332`, `README.md:446` | transport | Burst apps can queue behind slow start; not wire. |
| Single-connection head-of-line for UDP DATAGRAM buffer | 1 MiB shared buffer, newest-dropped `[C]` `transport/limits.rs:86-102` | implementation | A high-rate flow can starve a latency flow on the same connection; the egress-class split mitigates. Not wire. |

### 1.5 The RTT verdict for rev3

**On the warm path every operation is already at the information-theoretic floor, and no wire revision can
improve it.** The only application-layer RTT available anywhere is **operation 1c/5: 1 RTT on a resumed
connection**, and it is not a wire-format problem: it requires (i) authentication that is verified in the
handshake (so early data is attributable to a client identity) and (ii) a policy decision to accept replayable
payloads. That is a security decision (§2C, §5), not a codec decision.

Therefore the order of the priorities implies a specific program:

1. **Remove RTT *risks*** (CAPS redial cliff, per-flow ACK dependence, nondeterministic close) and make the
   1-RTT-on-resumption option structurally available (mTLS + no auth stream + self-describing first frame).
2. **Cut parse/encode cost** (fixed-width ids, direct-indexed registry, no CTL datagram path, zero-copy encode,
   equal-length TRAIN) — this is where a wire revision has the most measurable effect.
3. **Cut bytes** where they are not marginal (one-shot flows: FLOW_ACK/HELLO/CAPS/auth stream; constant 2 B
   steady header instead of 3 B growing to 4–5 B; `SESS_CLOSE`×3; TRAIN item headers). At 60 B payloads packed
   into trains the byte ceiling is a few percent; for one-shot DNS/rebind flows it is 20–35 %.

---

## 2. Three candidate designs

Common notation for all candidates: `fid` = flow id; `sess` = session (UDP association); `addr` = SOCKS address
encoding reused from `src/mqp/addr.rs:198-245` (v4 = 7 B, v6 = 19 B, domain = 4+L B); `P` = payload;
"packet" = `P + frame header + 57 B` IPv4 if the frame travels alone in a packet (`[D]`, §0.1).
Header byte counts exclude TCP-specific framing.

### 2A. Conservative evolution of rev2 (A)

**Thesis:** keep everything a rev2 operator already runs (DATAGRAM control plane, self-describing OPEN, bearer
token, HELLO/CAPS) and fix only the codec-level defects: varint id growth, the FLOW_ACK state machine, the
per-flow control datagrams, and the hash-map registry. Lowest risk, no auth/provisioning change, no new stream.

**Wire (one DATAGRAM body = one frame):**

```text
steady DATA:   0x00 | fid:u16le | payload                               (3 B header; constant)
OPEN:          0x01 | flags:u8 | fid:u16le | sess:u32le | addr | payload
               flags: OPEN=1 INLINE=2 SRC=4                               (8+addr B)
INLINE:        0x01 | INLINE | sess:u32le | addr | payload                (1+1+4+addr B)
TRAIN same:    0x04 | 0x00 | count:u8 | fid:u16le | count x (len:u16le | payload)
TRAIN dict:    0x04 | 0x01 | count:u8 | nfl:u8 | nfl x fid:u16le | count x (idx:u8 | len:u16le | payload)
FRAG steady:   0x08 | fid:u16le | frag_id:u32le | idx:u8 | total:u8 | chunk
FRAG ext:      0x09 | flags:u8 | fid:u16le | sess:u32le | addr | frag_id | idx | total | chunk
CTL:           0x0C | opcode:u8 | body        (HELLO, CAPS, REJECT, SESS_CLOSE; FLOW_ACK/FLOW_CLOSE deleted)
```

Flow id: 16-bit, split by owner (bit 15: client 0 / server 1) → 32768 ids per owner, **never reused**; the
14-bit (8192 per owner) variant with a 2-byte packed header is possible but A deliberately keeps the rev2
first-byte shape. Live cap stays 4096/conn, 64/session; exhaustion falls back to INLINE (as today).

**Bindings without FLOW_ACK.** Replace the confirmation RTT with *bounded context redundancy*:

* the sender puts the full OPEN/OPEN|SRC context on the first **K = 2** payloads of a flow (and on the first
  payload after any idle gap > 1 s), then sends steady frames;
* the receiver treats *any* frame arriving on a fid as implicit confirmation (a reverse-direction frame proves
  the peer has the binding), and a sender that receives one stops re-arming context;
* a sender with no inbound evidence NEVER dies on a lost context: the **receiver** of an unknown steady fid
  sends `CTL NEED_CONTEXT { fid }` (rate-limited, idempotent), and the sender re-arms K contexts; this recovers
  a flow within ~0.5 RTT after the first dropped frame instead of waiting for an ACK forever;
* one-shot flows only carry the initial context (their payload is already in it), so the loss semantics are
  exactly today's UDP semantics.

`FLOW_REJECT` stays a best-effort datagram, but its meaning is narrowed to "stop compressing for this target for
TTL"; the context-carrying frames in the K window are forwarded inline-style even when install fails, so the
reject does not lose the triggering payload. `SESS_CLOSE` stays best-effort ×2 (reliability is the idle sweep's
job, as today). `FLOW_CLOSE` is deleted from the wire (no sender exists `[C]`).

Address dictionary (A includes it, flagged optional): `CTL ADDR {sess, addr}` registers a connection-scoped
address under a `u16` dictionary slot; `INLINE`/one-shot frames may then carry `dict_id:u16` instead of `addr`.
Bound 256 entries/conn, LRU; benefit only when many one-shot flows share an address (typical: one resolver /
one game server) and the flow table is full or the flow is deliberately one-shot.

Registry: two fixed-capacity sliding windows, one per owner (`local_id & 0x0FFF` → 4096 slots, tag-validated;
per-owner live ids ≤ 4096 and monotonic, so the live span cannot alias) with per-slot `Arc<FlowBinding>`; one
array load + one tag compare instead of `RwLock<HashMap>` hash+probe `[E]`.

**State machine (flow):**

```text
sender:   Free --send payload (ctx K)--> Bound(ctx=K-1) --send payloads--> Bound(0)
          Bound(any) --recv any frame for fid--> Confirmed (stop re-arming)
          Bound(0)   --recv NEED_CONTEXT--> Bound(K)         (recovery, 0.5 RTT)
          any        --REJECT/CLOSE--> Closed (INLINE for target until TTL/retry)
receiver: absent --OPEN ctx--> Installed(knows sess+target) [ACK is implicit: no reply]
          Installed --REJECT/CLOSE--> Closed; late frames fail lookup
```

**Invariants / bounds (unchanged from rev2 unless listed):** 4096 live flows/conn, 64/session, 16 resolved
addresses/flow, 8 KiB/64-fragment reassembly, 2 s partial expiry, 1024-item/256 KiB stager, 64-item TRAIN;
+NEED_CONTEXT sorted-dedup set ≤64 ids/conn and ≤256 requests/s; address dictionary ≤256 entries/conn;
UNKNOWN ctx budget per frame (no allocation on the hot path).

**Failure semantics:** lost OPEN context → that payload lost; subsequent steady frames dropped until
NEED_CONTEXT + re-armed context (≤1 RTT + 1 payload); lost steady → payload lost; lost TRAIN → all items lost;
lost REJECT → client keeps compressing until retry TTL, no delivery loss (server still forwards context frames;
steady frames for an uninstalled fid are dropped); lost SESS_CLOSE → idle sweep backstop (unchanged).

**Security:** identical trust model and per-item authorization rules; fid ranges split by owner; contexts carry
session and are validated exactly like today's OPEN; NEED_CONTEXT is a hint that never grants a binding by
itself (receiver still validates the re-sent context); no replay surface added (contexts are not 0-RTT).

**Per-operation table (A vs current):**

| Op | Added RTT (A) | Wire bytes (A vs current, P=50, v4) | Decode ops/frame (A; `[E]`) | Notes |
|---|---|---|---|---|
| First UDP to unknown target | 0 (same) | OPEN 15+50+57 = **122** vs 121; no FLOW_ACK packet (−61) → **−61 B for the one-payload flow** | 15–20 vs 25–35 | stable 3 B steady header from the 2nd payload |
| Steady UDP | 0 | 3+P+57 = **110** vs 109–110 (2–3 B) | 8–12 vs 20–35 | constant forever (no varint growth) |
| TCP CONNECT | 0 (same) | header 7 + ACK 10 unchanged | unchanged | A does not touch TCP |
| TCP forward accept | 0 | header 7 unchanged | unchanged | dictionary could bind target (optional) |
| Reconnect | 0 (same; CAPS 2 s cliff remains) | −token packet − HELLO/CAPS if connection is new | — | A does not fix 0-RTT |
| Rebind / new reply source | 0 | OPEN\|SRC 15 vs 14; no client FLOW_ACK (−61) | 15–20 | context-K instead of ack |
| Flow close | 0 | SESS_CLOSE ×2 (14) vs ×3 (21) | — | best-effort |
| One-shot DNS/domain query | 0 | OPEN 23 (domain L=11) + P+57 + reply 15+P+57; **−61 B ack, −repeat ctx** vs current | 15–25 | ≈ −30 % for the one-shot domain flow |

**Verdict (A):** removes the worst codec defects and most per-flow control packets with the smallest possible
engineering risk, but keeps the two structural costs that matter for rev3's goals: a runtime HELLO/CAPS
handshake (with its redial cliff) and the bearer-token stream (with its replay constraint on 0-RTT). It also
buys no RTT and actually *adds* 1 B to OPEN/FRAG headers relative to rev2's first-63-flows fast case. A is the
fallback if the auth change is rejected, not the target.

### 2B. Split planes — control on a reliable QUIC stream, data in DATAGRAMs (B)

**Thesis:** put *all* binding/control state on a reliable ordered stream (QUIC retransmits for us), so the data
plane carries only a minimal id and payload — the speculative "1 B steady header" end state. Solve the
cross-plane reorder problem with either inline-context fallback (zero RTT) or a receiver parking window.

**Wire:**

```text
control (one client-opened bidi stream, first byte 0xFF = control; 0x01/0x03/0x04 = TCP atyp):
  msg: type:u8 | len:u16le | body
  0x01 HELLO  {alpn_ver, caps}       C->S   (if not replaced by ALPN/static contract)
  0x02 CAPS   {caps}                 S->C
  0x10 OPEN   {fid:u16, sess:u32, addr, flags}   C->S | S->C
  0x11 ACK-BIND {fid:u16}            both   (receiver installed)
  0x12 REJECT {fid:u16, reason:u8}   both
  0x13 CLOSE  {fid:u16}              both
  0x20 SESS_CLOSE {sess:u32, reason} both
data (DATAGRAM):
  steady: 0xB0 | tag:u8 | payload                    (2 B header; or 1 B if the tag byte carries kind bits)
  steady id16: 0xB1 | fid:u16le | payload            (3 B; safe without any tag/ack machinery)
  TRAIN/FRAG: as A, with fid u16 / tag u8
```

**The ordering hazard.** QUIC stream frames and DATAGRAM frames share a packet-number space but are different
frame types in different streams-of-logic. Even when the client writes `OPEN` to the control stream and sends
the first data datagram in the same flight, (i) they can land in different packets, (ii) either can be lost, and
(iii) a lost control packet is retransmitted at the next PTO while later datagrams keep flowing. Therefore a
compressed data frame *can* arrive before the receiver has the binding. Four safe sender policies:

| Policy | Added app RTT | Cost | Verdict |
|---|---:|---|---|
| **B1 inline context on first K frames** (stream OPEN is only a redundancy/observability path) | 0 | +15 B on K frames, no parking, no timer | works, but the stream adds nothing over A's in-band context |
| **B2 receiver parks unknown-id datagrams for T** until binding arrives; drop on expiry | 0 nominal (same flight); +1 PTO when the OPEN packet is lost; payloads after T are lost | bounded park budget (e.g. 64 frames / 64 KiB/conn), timer/sweep, drop path, reorder re-validation; O(1) miss branch | the only policy that lets the first frame be *pure* id-compressed with zero RTT; pays in memory+complexity and turns control loss into a 1-PTO latency spike |
| **B3 per-flow epoch + parking only for the first frame** | 0 nominal; +1 PTO on control loss | epoch must be on the wire (2–4 B) or derived from the stream; does not remove parking | variant of B2 |
| **B4 ack-gated compression**: first payload self-describing, steady only after `ACK-BIND` | +1 RTT to start compression (payload delivery unchanged) | this is exactly today's FLOW_ACK semantics over a reliable channel; one round trip per flow | no better than current |

The 1-byte `tag:u8` is the only real byte prize, and it is **not safely reusable without a round trip**: a
delayed data frame carrying tag `t` that was freed and reassigned would be resolved against the new flow's
target — a cross-flow leak, the exact failure the current never-reuse rule exists to prevent. Making tag reuse
safe needs the sender to know the receiver processed FREE+BIND, i.e. an ACK (B4) — so the 1 B header costs the
same 1-RTT compression start as today. Without reuse a u8 tag space gives 128 never-reused tags per owner
(256 total), exhausted after 128 flow opens per owner — 32x below the 4096 live-flow target. **Verdict on tags: not worth it; use `fid:u16` (2 B header total with the kind byte folded, see §4).**

**Quantified header/latency trade for B (single first payload, v4, P=50):**

| | A (inline ctx) | B (OPEN stream + pure steady, B2) | B (OPEN stream + first ctx inline, B1) |
|---|---:|---:|---:|
| data frame | 15+50 = 65 B body (122 wire) | 3+50 = 53 B (110 wire) | 3+50 = 53 B (110 wire) |
| control/stream bytes | 0 | ~15 B body + ~3 B STREAM frame, possibly its own packet (+57) | ~15 B + 3 B (redundant) |
| nominal first-payload RTT | 0 | 0 (same flight) / +1 PTO on control loss | 0 |
| steady after first | 3 B (A) / 2 B (packed §4) | 2 B | 2 B |
| extra state | ctx counter | park queue + timer + miss branch | stream + ctx counter |

B2's nominal byte advantage over A is at most ~12 B on the very first frame of a flow and ~0 thereafter (the
2 B steady header is available to A too by moving to a packed 14-bit id, §4); its costs are a new parking/timer
subsystem, a 1-PTO latency cliff under control loss, and the same never-reuse id discipline. **B as a whole is
dominated for OPEN.** The reliable stream *does* pay for itself for the rare, correctness-relevant messages
(REJECT/CLOSE/SESS_CLOSE), where it replaces best-effort ×3 datagrams, the CTL rate budget, and the idle-sweep
correctness reliance. That subset is folded into the recommendation (§4).

**Per-operation table (B, with B2 parking + B1 fallback):**

| Op | Added RTT (B) | Steady wire (B) | Decode ops/frame (B; `[E]`) | Notes |
|---|---:|---|---:|---|
| First UDP to unknown target | 0 nominal; +1 PTO if the OPEN packet is lost (parking) | first frame 3 B header (110 B wire for P=50 v4) + control OPEN ≈15 B; then 2 B header | 10–15 + parking-miss branch | B's only byte win is on the first frame; A's in-band context is 15 B in the same packet |
| Steady UDP | 0 | 2–3 B header depending on fid form | 8–12 (u16) / 6–9 (u8 tag) | 1 B tag only with ack-gated reuse (B4) = +1 RTT |
| TCP CONNECT / forward | 0 (B does not touch TCP) | unchanged | unchanged | |
| Reconnect | 0 (B2) | control OPEN again after redial | | |
| Rebind | 0 nominal; +1 PTO on control loss | 3 B + control msg vs 14 B inline | | |
| Flow close | 0 | reliable CLOSE message | | |
| One-shot DNS | 0 | pay control OPEN + 3 B data vs A's 14 B inline once; saves FLOW_ACK | | roughly byte-neutral vs A |

**State machine (B2, for completeness):**

```text
client flow:  Open-sent --(stream OPEN written)--> Bound --(ACK-BIND)--> Confirmed
server recv:  data(fid unknown) --park--> Installed --(flush park, stream ACK)--> delivering
              data(fid unknown, park full/expired) --> drop, count
              stream OPEN unknown session --> REJECT/SESS_CLOSE on stream
```

**Invariants/bounds (B):** one control stream/conn, ≤512 B message, ≤4096 pending messages, bounded read
budget; park ≤64 frames / 64 KiB / conn, T = clamp(2·RTT, 20 ms, 200 ms); same table/reassembly/stager bounds;
unknown-id rate cap. **Failure semantics:** control stream loss → QUIC retransmission (reliable; no app logic);
data loss → payload loss; park expiry → payload loss (counted); connection loss → all state lost, rebuild on
redial. **Security:** OPEN on the stream must be authenticated per-item exactly like today's OPEN (session
ownership, policy/SSRF before install and before forwarding), parked frames must be re-validated against the
binding when flushed, and the stream is untrusted input (length/rate bounds).

### 2C. Handshake-integrated — mTLS auth, static contract, early data (C)

**Thesis:** move identity and the protocol contract into the TLS handshake so the application layer has no
authentication round trip, no token stream, no HELLO/CAPS, and *can* use 0-RTT application data when policy
allows. C is orthogonal to the data codec: it replaces the auth/caps layer under whichever data plane is chosen.

**Auth options and their real availability:**

| Option | RTT cost | Replay story | Available with quinn 0.11 / rustls 0.23? |
|---|---|---|---|
| Bearer token on 1-RTT stream (current) | 0 extra (token rides the first post-handshake flight) | token never in early data; a resumed connection cannot carry app data before the token | yes (today) |
| **mTLS client certificate** | 0 extra on full handshake (client cert is in the client's second flight, same flight that carries its 1-RTT app data); 0 bytes on resumption | identity is proven in the handshake; resumption authenticated by the ticket/PSK; early data attributable to a real identity; **payload replay remains** | **yes** — `WebPkiClientVerifier` on the server, `with_client_auth_cert` on the client `[E: rustls 0.23 API]` |
| PSK-bound token (token as external PSK) | 0 | token never on the wire after first use; replay-resistant identity | **not reachable through quinn's config surface** — rustls 0.23 exposes ticket resumption, not external PSKs; would need a custom crypto layer. Not recommended. |
| Token in 0-RTT early data | 0 | replaying the captured flight replays the credential; an attacker can act as the client | forbidden (and correctly so in the current code `[C] auth.rs:356-364`) |

**Capabilities:** all values HELLO/CAPS currently carries are protocol constants server-side (`Caps::default()`
`[C] accept.rs:1832-1835`; `max_frame_bytes=1472`, `max_train_items=64`, `max_conn_flows=4096`,
`max_flows_sess=64`, `max_reassembly=8192`) `[C] src/mqp/r2.rs:99-105`. Server-side configured limits need no
negotiation: the peer discovers a full table via `REJECT`, and oversized frames via the transport's
`max_datagram_size()`. quinn 0.11 exposes no custom QUIC transport parameters and no TLS-extension hook, so the
practical contract carriers are **ALPN (wire version / fail-fast)** plus **compile-time constants** (all caps).
That is strictly sufficient for a single-version protocol.

**0-RTT replay analysis (the only place C turns into RTT):**

* TLS 1.3 0-RTT is replayable. The server currently accepts it (`max_early_data_size = u32::MAX`, stateful
  single-use tickets `[C] server_cfg.rs:20-37`) and rustls' single-use tickets narrow the window but cannot
  close the race: if an attacker replays the captured flight **before** the original arrives, the replay is
  processed as the first attempt and the client's original is then rejected as 0-RTT and retransmitted at
  1-RTT — the payload can be executed **twice**. A proxy cannot make that safe for arbitrary UDP.
* **Safe early-data content by default: none.** The handshake can still be completed early; only *payload*
  bytes must wait for 1-RTT.
* **Opt-in class:** if the user wants the 1 RTT, the only defensible model is an explicit replay-tolerant class
  (destination port allowlist, e.g. DNS 53 / NTP 123 / telemetry; or per-association opt-in by the local app)
  where the application already tolerates duplicated datagrams. This needs a wire/config-visible marker so the
  server can refuse early data for every other flow; it must never be a global switch that silently applies to
  all UDP.
* **Security trade of allowing auth in 0-RTT vs not:** with mTLS the *identity* is as strong in 0-RTT as in
  1-RTT (the PSK ticket was issued only after a cert-auth handshake); the residual risk is purely
  **payload duplication/reordering**, not impersonation. With the current bearer token, early auth is
  impersonation-on-replay and must stay forbidden. A secondary mTLS trade: **resumption bypasses revocation**
  until the ticket expires, so ticket lifetime becomes a security parameter (short tickets, no long-lived
  PSK-only access).

**Connection state machine (C):**

```text
client: Idle --dial (mTLS ClientHello)--> Handshaking
        Handshaking --handshake complete (cert verified, or ticket resumed)--> Live
        Live --opt-in 0-RTT policy + resumption--> Live (early datagrams may leave at t=0)
        Live --path failure / watchdog--> Idle (pool redials; a resumed handshake is 0-RTT again)
        Handshaking --cert/ALPN rejection--> Failed (clean TLS alert; redial with backoff)
server: Accept --> Handshaking --client cert verified + ALPN match--> Live
        Handshaking --cert/ALPN failure--> Closed (alert, counted; no app state allocated)
        Handshaking --opt-in: valid single-use ticket--> EarlyData (payloads accepted under replay policy)
        Live/EarlyData --idle timeout / close--> Closed (idle sweep only for app state)
```

**Failure semantics (C):** wrong wire/ALPN → TLS alert at handshake, no data ever crosses versions; missing or
invalid client cert → handshake failure (clean, no auth timeout wait); resumption ticket rejected/evicted or
server restart → falls back to a full handshake (one-off +1 RTT, no data loss); early data rejected (opt-in
mode) → the client resends queued payloads at 1-RTT — this is exactly the duplicate-delivery window that keeps
the default policy off; server ticket-store eviction → full-handshake CPU spike, not data loss.

**Wire impact of C alone:** delete HELLO (8 B) and CAPS (17 B) frames and the pre-HELLO buffer; delete the
auth uni stream and its token packet; ALPN value carries the version (`normalize_alpn` already exists,
`src/mqp/ack.rs:16-24`). Keep the data plane of whichever codec design is chosen (C does not by itself change
frame layouts). Keep a control channel for close/reject (the reliable stream from B, or datagrams).

**Per-operation table (C only, data codec unchanged):**

| Op | Added RTT (C) | Wire bytes | Decode ops | Notes |
|---|---|---|---|---|
| Cold first UDP | 0 change (1 RTT floor) | −token packet (−57−T), −HELLO/CAPS (−26 B, 2 packets) | −version-gate branch | mTLS full handshake adds cert bytes once per ticket lifetime (amortized over long-lived pooled connections) |
| Steady UDP | 0 | unchanged | −hello_seen atomic/branch per frame | |
| TCP CONNECT | 0 | unchanged | unchanged | |
| Reconnect | **−1 RTT only if early payloads are enabled**; else 0 | −auth token, −HELLO/CAPS | −auth stream task | today's resumption saves 0 app RTT `[C] auth.rs:366-410` |
| New reply source | 0 | unchanged (control channel still needed for reject/close) | | |
| Flow close | 0 | REJECT/CLOSE now reliable via stream or datagram | | |
| One-shot DNS | 0 | −FLOW_ACK if combined with A's context scheme; −HELLO/CAPS per connection | | |

**Verdict (C):** the only candidate that can produce an RTT win (1 RTT on resumed connections), but that win
is *conditional on a replay-policy decision* that only the user can make. Independently of early data, mTLS +
ALPN/static caps remove a stream, two control frames, a version gate, a 2 s redial cliff and the pre-HELLO
buffer — a large simplification whose payoff is mostly risk/CPU, not latency. It is the right identity layer
for rev3 if the operator accepts certificate provisioning.

---

## 3. Lever-by-lever verdicts

Each lever is judged against the priorities: **RTT > parse/encode cost > bytes > invariants**. "Evidence" is the
current-code fact that decides it.

| # | Lever | Verdict | Evidence and quantified effect |
|---|---|---|---|
| L1 | **Eliminate FLOW_ACK** | **YES — replace, don't just delete** | FLOW_ACK is explicitly not a delivery ACK `[C] README.md:266,351`; it costs one DATAGRAM packet per flow (≈61 B isolated, ≈9 B if packed with other datagrams) plus the `Opening→Open` state machine and the repeated-OPEN tax until it arrives `[C] r2.rs:82-88, r2_flow.rs:56-65,92-118; dispatcher.rs:993-996; accept.rs:1846-1852`. Deleting it without a replacement blackholes any flow whose first OPEN is lost. Replacement: **first-K context redundancy + implicit confirmation (any inbound frame for the fid) + reliable NEED_CONTEXT recovery** (§4). RTT effect: 0. Bytes: −1 packet/flow, −(K·12–15 B) on the first K payloads; removes the lossy-path per-payload 14 B tax. |
| L2 | **Eliminate the HELLO/CAPS round trip** | **YES — eliminate the frames and the runtime negotiation entirely** | It never delays a payload `[C] egress.rs:414-425, accept.rs:2645-2698`, so its only claimed RTT value is fail-fast. But every value CAPS carries is a protocol constant (`Caps::default()` is the only construction `[C] accept.rs:1832-1835`) and two of the five fields are documented reserved `[C] MQP3_REV2_SPEC.md:98-99`. Cost removed: 25 B + 2 packets/connection, 8-frame/16 KiB pre-HELLO buffer with its drop path `[C] accept.rs:1103-1104,1450-1466`, per-frame `hello_seen` atomic/branch `[C] accept.rs:2688-2694`, and the **2 s kill-a-working-connection cliff** `[C] rev2.rs:52`. Version fail-fast moves to ALPN (a TLS-handshake error instead of a 2 s timeout). |
| L3 | **Auth placement: mTLS/PSK vs 1-RTT token stream** | **YES to mTLS *if* provisioning is acceptable; PSK-bound token is not implementable; token-in-early-data stays forbidden** | Current token rides the first post-handshake flight, so it adds no RTT; its costs are one packet + ≤256 B, a 5 s auth budget, 256 pre-auth connection slots, a MAX_STREAMS raise after auth, and the structural ban on 0-RTT payloads `[C] auth.rs:356-410,412-447; server/auth.rs:22-47; main.rs:849-880; accept.rs:16-20`. mTLS moves identity into the handshake (0 MQP bytes, no auth task, no pre-auth stream-credit split), makes resumption authentication sound, and is the *precondition* for the only 1-RTT win available (L4). It does **not** reduce RTT by itself; early-data payloads do, and only under an explicit replay policy (§2C). rustls 0.23 exposes no external-PSK API through quinn → "PSK token" is not a real option. |
| L4 | **Use 0-RTT for application data** | **STRUCTURALLY YES, DEFAULT NO** | Today the client awaits handshake completion and sends no early data `[C] auth.rs:366-410`; both sides have early data enabled `[C] client_cfg.rs:20-22, server_cfg.rs:20-37`. Turning it on is the *only* available 1-RTT win (resumed connection: payload at 0.5 RTT vs 1.5 RTT), but TLS 1.3 0-RTT is replayable and a proxy carries non-idempotent UDP: a racing replay can execute a datagram twice. Default must stay off for payloads; an opt-in replay-tolerant class (port/flow allowlist) is a user decision. |
| L5 | **Fixed-width ids + generation/epoch with id reuse** | **Fixed-width YES; reuse/epoch NO** | Fixed 2 B ids end the varint growth: rev2's "2 B header" only exists for the first 63 flows/owner, is 3 B for every flow after that, and grows to 4–5 B as ids are never reused `[C,D] r2.rs:143-148,172-179; r2_flow.rs:743-778; README.md:193-200`. A 2-byte packed kind+14-bit id gives constant 2 B with 8192 ids/owner (2× the 4096 live cap) and O(1) decode. Reuse with an epoch needs either epoch bytes on the wire (≥3 B steady header — loses the byte win) or a guard/ack to make delayed frames safe (loses the RTT/parse win and risks cross-flow misdelivery). Keep **never-reuse**; handle exhaustion with INLINE fallback (correct, rare) and optional pool-driven connection recycling. |
| L6 | **Connection-level address/flow dictionary** | **NO for steady; optional for one-shot only** | Steady frames are already dictionary-compressed: the fid *is* the dictionary handle (`wire_id → binding`), and rev2 removed the per-frame session/address `[C] r2.rs:1-43`. A second address dictionary only helps INLINE/one-shot frames (table-full fallback, one-shot targets): it saves 5–19 B on those, but needs entries, IDs, LRU and reuse validation, and the steady path gains nothing. Not worth it for rev3 v1; revisit only if INLINE traffic measures >5 %. |
| L7 | **TRAIN vs one payload per DATAGRAM** | **KEEP TRAIN, add an equal-length form; do not make it mandatory or timer-driven** | Measured 0.743 frames/payload on the mixed small-packet bench `[M] README.md:334,492`. Quinn already packs multiple DATAGRAM frames per packet `[C] quinn-proto connection/mod.rs:3347-3359`, so the packet header is partly amortized even without TRAIN; TRAIN's remaining win is the per-frame 3 B DATAGRAM header + 2–3 B MQP header + one `send_datagram` per payload. An **equal-item-length same-flow form** removes the 1 B/item length byte and the per-item length branch (RTP/game/telemetry send constant-size datagrams). Do not add an aggregation timer (adds latency) and keep `max_train_items` configurable for fate-sharing. |
| L8 | **1-byte frame header + control piggyback** | **Uniform 2-byte packed kind+14-bit id for v1; a 1-byte short form is safe but only for a reserved 64-fid range (optional Phase 3); piggyback NO** | A *uniform* 1-byte header cannot address 4096 live flows (the id alone needs 12 bits; +2 kind bits = 14 → 2 B). A 1-byte form becomes safe **without any tag table or ack** if the short code space *is* part of the fid space: reserve fids 0–63 for the short DATA form (e.g. 32 client + 32 server), keep the 14-bit long form for all other fids; there is no reuse and no ambiguity, and delayed-frame safety is unchanged. Cost: one extra class branch in the decode match and a non-uniform id space; win: 1 B on steady frames for the first ≤64 flows of a connection — statistically where long-lived high-rate flows live — ≈1–2 % at 60–128 B payloads. Deferred out of v1 (id uniformity and parse simplicity first); keep as a measured Phase-3 option. Control piggybacking is unnecessary once the rare control messages move to the reliable stream. |
| L9 | **FRAG vs reliable stream for large UDP payloads** | **KEEP FRAG; do not route large payloads over streams** | UDP large payloads are best-effort by contract: a reliable stream would convert "drop" into "deliver late", changing application semantics (and adding head-of-line blocking), which is a protocol-level decision no app can opt out of. FRAG's cost is 8–9 B/fragment + 8 KiB/64-fragment bound `[C] r2.rs:686-700, fragment.rs:47,55`. Loss amplification is the real problem (one lost fragment of a 6-fragment payload loses the payload); the cheap mitigation is fewer fragments, i.e. **raise `initial_mtu`** on known paths (config, not wire) and keep PMTU discovery. Revisit an opt-in "reliable-large-payload" flow class only with a user decision. |
| L10 | **TCP path reuse / unify with UDP codec** | **KEEP stream-native; share only the handshake contract and (optionally) a target-binding message** | The TCP path is already at the RTT floor: optimistic SOCKS success + pipelined bytes, 0 added RTT over direct TCP `[C] socks.rs:228-258`. Adding a frame layer to the stream would add bytes/parse to bulk data for no latency; moving the dial ACK to a control channel does not save an RTT and complicates failure attribution. The only real (byte/semantic) win: forward-mode fixed targets can be bound once over the control stream → **0-byte per-stream header** (7/19/4+L B saved per flow), and SOCKS could omit the header only if a target binding already exists (not possible: target varies per SOCKS request). Keep the 10/22 B ACK. |
| L11 | **ACK_FREQUENCY / DATAGRAM size / pacing** | **Transport levers only; do not encode in the wire** | Interactive preset 2/5 ms and bulk 8/10 ms `[C] tuning.rs:332-333, build.rs:279-286` are reasonable for the two classes; ACK frequency cannot change application RTT, only reverse-path CPU and loss-detection sharpness. `initial_mtu=1200` is the most expensive default in the stack (DATAGRAM budget 1162, every >1150 B payload splits; PMTU discovery is opportunistic and a busy connection can sit at 1200 for a long time) — recommend 1360–1400 on known paths `[C] tuning.rs:267-292, build.rs:371-392`. Pacing/GSO/GRO are transport; the wire must stay MTU-agnostic and use the live `max_datagram_size()`. |
| L12 | **Per-flow control datagrams (ACK/CLOSE/REJECT)** | **DELETE ACK/CLOSE; move REJECT/SESS_CLOSE/NEED_CONTEXT to a reliable control stream** | FLOW_CLOSE has no production sender `[C]`; FLOW_ACK is L1; remaining control is rare and correctness-relevant (a lost SESS_CLOSE can blackhole a client binding until the next payload fails, a lost REJECT delays INLINE fallback). One reliable stream removes the ×3 repeats, the 8192/s CTL rate budget `[C] r2_flow.rs:799-868`, the pre-HELLO/CTL branch in the datagram hot path, and the idle-sweep-as-correctness dependency. Control messages are ≤16 B; one stream/connection is negligible. |
| L13 | **Compact session field (u32 → u8/u16 tag)** | **NO for v1** | The session appears only in OPEN/INLINE/FRAG-ext and control messages, not in steady frames; saving 2 B per *flow open* cannot pay for an extra mapping. Note the distinction: a **per-connection u16 session index** (allocated per connection, never reused inside it, ≤4032 associations < 65536) is *safe*, unlike a u16 global session id; it is simply not worth the mapping code in v1. Keep monotonic `u32` sessions `[C] hub.rs:335-360`. |
| L14 | **Keep SOCKS address encoding on the wire** | **YES** | `atyp\|addr\|port` = 7/19/4+L B is already minimal for a self-describing form, is shared with the TCP stream path, and is validated for unspecified/scoped/domains `[C] addr.rs:122-196`. Only 1 B could be squeezed (atyp folded into a kind byte) — not worth a second codec. |

---

## 4. Recommendation — target design `rev3`

**One target design**, synthesized from the analysis: **C's identity/contract layer + A's self-describing data
plane with fixed-width ids and bounded context redundancy + B's reliable stream restricted to the rare,
correctness-relevant control messages.** Nothing in it is speculative about *latency*: every warm-path operation
is already at the floor; this design removes the current design's latency cliffs and RTT risks, cuts decode/encode
work, and cuts the bytes that are not marginal (one-shot flows, control traffic, header growth).

Name: protocol name decision open; this document calls the wire revision **rev3** (ALPN placeholder
`myquic2/r3`). Single version, no mixed deployment, no runtime fallback.

### 4.1 Design decisions (fixed)

1. **Identity in the handshake.** mTLS client certificate, verified by rustls in the TLS 1.3 handshake
   (`WebPkiClientVerifier`); per-client identity available for logs/ACLs. The bearer-token uni stream and the
   token config are removed. Full handshakes pay the client certificate once per ticket lifetime; resumed
   connections send no certificate.
2. **Contract in the handshake / compile time.** ALPN carries the wire revision and is the fail-fast gate
   (`normalize_alpn` already exists `[C] ack.rs:16-24`); all caps are protocol constants. No HELLO, no CAPS,
   no pre-HELLO buffer, no `hello_seen` hot-path gate.
3. **0-RTT payloads: off by default.** The wire is structurally ready (self-describing first frame, no
   dependency on a control message), but early application datagrams are gated by an explicit opt-in
   replay-tolerant class (user decision, §5). Identity in 0-RTT is sound because of (1); payload replay is not.
4. **14-bit never-reused flow ids, owner-split, fixed 2 B steady header.** client `fid ∈ [0x0000,0x1FFF]`,
   server `fid ∈ [0x2000,0x3FFF]` (8192 each, 2× the 4096 live cap). Ids are allocated monotonically and never
   reused while the connection lives (preserves the delayed-frame safety invariant). Exhaustion → INLINE
   fallback for new flows (correct; header 12/24/9+L B) and the pool may proactively recycle the connection.
   A measured 1-byte short form for a reserved 64-fid range is a safe Phase-3 byte option (L8) and is
   deliberately not in v1.
5. **No per-flow ACK.** First K=2 payloads of a flow carry binding context; any inbound frame on the fid is
   implicit confirmation and stops re-arming; a receiver seeing an unknown fid sends `NEED_CONTEXT` on the
   control stream, and the sender re-arms context. No `Opening` data-path gate.
6. **One reliable control stream** (client-opened bidi, first byte `0xFF`), messages ≤64 B, carrying only
   `ASSOC_CLOSE`, `SESS_CLOSE`, `REJECT`, `NEED_CONTEXT` (+ optional `FLOW_CLOSE`, `GOAWAY`). It never carries
   OPEN/binding-for-data: first frames stay self-describing in the datagram, so there is no cross-plane
   ordering hazard on the payload path.
7. **Session stays `u32`** in extended frames/control messages; steady frames stay session-free (as rev2).
8. **TCP path stays stream-native** (address header + optimistic SOCKS success + 10/22 B ACK). Optional phase:
   bind fixed forward-mode targets once on the control stream to make the per-flow header 0 B.
9. **Registry stays connection-scoped, direct-indexed.** fid → binding via a paged/ring table (`[Option<Arc>]`
   indexed by fid, tag-validated) instead of `RwLock<HashMap>`. Session reverse table (≤64) stays a small array.
10. **One DATAGRAM frame per body**, encoder writes the header into payload headroom to avoid a second
    allocation/copy; TRAIN packs when a burst is ready; no aggregation timer.

### 4.2 Exact wire format

All integers little-endian and fixed width; **no varints anywhere**. First byte's top 2 bits are the class:

```text
bit 7..6   class
  00       DATA        steady, 2-byte header: b0 = fid[13:8], b1 = fid[7:0]
  01       DATA_EXT    OPEN / SRC / OPEN_SRC / INLINE (binding-carrying first frames and rebinds)
  10       TRAIN       SAME / SAME_EQUAL / DICT
  11       FRAG        steady / extended (same flags as DATA_EXT)
```

```text
DATA (steady; 2 B header)
  b0: 00 fid[13:8]          b1: fid[7:0]          b2..: payload
  fid range: 0x0000-0x1FFF client-allocated, 0x2000-0x3FFF server-allocated

DATA_EXT (1 + optional fields; flags in b0 low 6 bits)
  b0: 01 reserved[5:4] flags[3:0]   flags: 0x01 OPEN, 0x02 SRC, 0x04 INLINE (reserved bits must be 0)
  OPEN      (0x01): fid:u16 | sess:u32 | addr | payload
                     header = 1+2+4+addr  ->  v4 14, v6 26, domain 11+L
  SRC       (0x02): fid:u16 | addr | payload                 (rebind an existing flow; no sess)
                     header = 1+2+addr    ->  v4 10, v6 22, domain 7+L
  OPEN_SRC  (0x03): fid:u16 | sess:u32 | addr | payload      (server-owned new flow)
                     header = 1+2+4+addr  ->  v4 14, v6 26, domain 11+L
  INLINE    (0x04): sess:u32 | addr | payload
                     header = 1+4+addr    ->  v4 12, v6 24, domain 9+L

TRAIN (b0: 10 form[5:4] reserved[3:0])
  SAME      (form 0): b0 | fid:u16 | count:u8 | count x (len:u8 [0xFF -> u16] | payload)
                      header 4 B; item 1 B (3 B if len>254)
  SAME_EQUAL(form 1): b0 | fid:u16 | count:u8 | item_len:u8 [0xFF -> u16] | count x payload
                      header 5-7 B; item 0 B                        <-- new form
  DICT      (form 2): b0 | nfl:u8 | count:u8 | nfl x fid:u16 | count x (idx:u8 | len | payload)
                      header 4+2*nfl; item 2 B
  count <= 64; nfl <= count; each fid distinct; zero-length items allowed.

FRAG (b0: 11 reserved[5:4] flags[3:0]; same flags as DATA_EXT)
  steady   : b0 | fid:u16 | frag_id:u32 | idx:u8 | total:u8 | chunk            header 9 B
  OPEN     : b0 | fid:u16 | frag_id:u32 | idx:u8 | total:u8 | sess:u32 | addr | chunk
  SRC      : b0 | fid:u16 | frag_id:u32 | idx:u8 | total:u8 | addr | chunk
  INLINE   : b0 | frag_id:u32 | idx:u8 | total:u8 | sess:u32 | addr | chunk
  1 <= total <= 64, idx < total, chunk non-empty; fragment payload cap 8 KiB (unchanged)
```

Control stream (first byte `0xFF` distinguishes it from a TCP flow, whose first byte is a valid atyp
`0x01|0x03|0x04` `[C] addr.rs:198-245`):

```text
message: type:u8 | len:u16le | body      (len <= 64; unknown type/len -> drop frame, count)
  0x01 ASSOC_CLOSE  C->S  { sess:u32, reason:u8 }            (replaces SESS_CLOSE x3)
  0x02 FLOW_CLOSE   both  { fid:u16, reason:u8 }             (optional; eager release)
  0x81 REJECT       S->C  { fid:u16, reason:u8 }             (policy/table-full/DNS)
  0x82 NEED_CONTEXT both  { fid:u16 }                        (recovery hint)
  0x83 SESS_CLOSE   S->C  { sess:u32, reason:u8 }            (server reaped the session)
  0x84 GOAWAY       S->C  {}                                 (optional; id-space/health)
  (all lengths below 512; one control stream per connection; a second 0xFF stream is reset)
```

### 4.3 Flow / session / connection state machines

```text
FLOW (each endpoint's own send side)
  Free --payload for (sess,target), fid allocated--> Context(K=2)
  Context(n>0) --send payload (DATA_EXT OPEN/SRC/OPEN_SRC)--> Context(n-1)
  Context(0)   --send payload (DATA steady)--> Steady
  any          --recv any frame carrying fid--> Steady (implicit confirmation; no more context)
  any          --recv NEED_CONTEXT(fid)--> Context(K)
  any          --recv REJECT(fid)--> Inline(target) until TTL (1 s transient / 30 s policy)
  any          --ASSOC_CLOSE / SESS_CLOSE / connection loss--> Free

FLOW (receive side)
  absent --DATA_EXT OPEN/OPEN_SRC (validated, forwarded, installed)--> Installed
  absent --DATA steady fid--> drop + maybe NEED_CONTEXT (rate-limited)
  Installed --DATA steady / TRAIN / FRAG--> deliver
  Installed --SESS_CLOSE / FLOW_CLOSE / table sweep--> absent (late frames drop)

SESSION (server)
  absent --first valid OPEN (creates socket, admission, DNS/SSRF)--> Installed
  Installed --ASSOC_CLOSE--> purged (socket, flows, stager, reassembly)
  Installed --idle sweep / admission pressure--> purged + SESS_CLOSE(S->C, reliable)
  (client session ids are monotonic u32; never reused, so no stale-session alias)

CONNECTION (client)
  Dialing(mTLS) --> Live (control stream opened; data plane usable immediately after handshake)
  Live --allocator low-water (<1024 of 8192)--> DrainNew (new flows use INLINE or a new pooled conn)
  Live --watchdog/path failure--> Dead, pool redials (TCP/UDP egress class rules unchanged)
```

### 4.4 Invariants and bounds (all preserved or strengthened)

| Invariant | rev3 |
|---|---|
| Live flows/conn, flows/session | 4096 / 64 (unchanged) |
| Flow-id safety | 14-bit, never reused per connection, owner-split ranges; a delayed frame for a closed flow finds no binding (and no other flow can own that fid, because fids are never reused) |
| Per-item authorization | unchanged: every payload is resolved to (session, target/source) and policy-checked before forward; TRAIN items resolve independently; unknown/closed fid drops only that item |
| SSRF / private-IP policy | unchanged, server-side at OPEN/resolution (uplink) and reply-source authorization (downlink) |
| Reply-source pinning, full-cone opt-in | unchanged |
| Reassembly | 8 KiB / 64 fragments, 2 s expiry, 256 partials / 256 KiB per conn `[C] src/mqp/fragment.rs:47,55,107,165,176` (unchanged) |
| Stager / TRAIN | 1024 items / 256 KiB per conn (unchanged); TRAIN ≤64 items, ≤4 frames/drain (unchanged) |
| Control stream | one per conn, ≤64 B messages, length-validated before body, message-rate cap (e.g. 4096/s), pending-work bounded; untrusted input |
| Context redundancy | K=2 additional context frames per flow, ≤16 B each; per-conn context bytes bounded by live flows × 32 B (charged at admission) |
| NEED_CONTEXT/REJECT rate | ≤256/s/conn and sorted/deduped request set ≤64 ids; unknown-fid steady frames never allocate |
| Registry memory | paged fid table ≤ 16384 × 8 B = 128 KiB/conn worst case (lazily paged; typically ≤32 KiB at 4096 dense flows) — strictly less than the current 4096 × 904 B admission charge `[M] README.md:404` |
| Identity | mTLS cert verified in handshake; resumption via PSK ticket; ticket lifetime is a security parameter; revocation on full handshake only (documented trade) |
| Replay | no 0-RTT payloads by default; opt-in replay-tolerant class only |
| Version | ALPN fail-fast; no runtime negotiation; unknown first-byte classes dropped+counted, never reinterpreted |

### 4.5 Failure semantics

| Event | rev3 behaviour |
|---|---|
| Lost DATA steady / TRAIN / FRAG | payload(s) lost — unchanged UDP semantics |
| Lost OPEN/OPEN_SRC/SRC context frame | that payload lost; later steady frames for the fid are dropped until receiver's `NEED_CONTEXT` (reliable) reaches the sender and it re-arms context; recovery ≈0.5 RTT + next payload, counted |
| Control message lost | QUIC retransmits (reliable); no app-level repeat logic |
| REJECT received | client sends INLINE for that target for the reason's TTL (1 s table-full/DNS, 30 s policy), then retries OPEN |
| Flow table full | server forwards the context-carrying payload inline-style (no payload loss in the K window) and sends REJECT; client falls back to INLINE |
| DNS failure / policy refusal | REJECT(DNS/POLICY); INLINE retry path unchanged |
| Server reaps session (idle/admission/reply-reader exit) | `SESS_CLOSE` on the reliable stream; client invalidates all session bindings and re-OPENs lazily; idle sweep remains the last-resort backstop for dead peers |
| Client exits association | `ASSOC_CLOSE` once on the reliable stream; server purges immediately (no ×3, no idle wait) |
| Id-space low-water | new flows use INLINE (not a black hole) or a new pooled connection; existing flows continue |
| Connection dies | all connection-scoped state lost; pool redials; associations re-OPEN lazily (unchanged) |
| Wrong build/version peer | TLS handshake fails on ALPN (clean, immediate); no data ever crosses a version boundary |
| Malformed frame | drop frame + count; never panic, never tear down the connection (unchanged contract) |

### 4.6 Byte accounting — rev3 vs current (IPv4, P=50, isolated packets; `[D]`)

Header sizes only (add `P + 57` for an isolated packet):

| Frame form | current rev2 | rev3 | Δ |
|---|---:|---:|---:|
| DATA steady, 1st 63 flows/owner | 2 B (kind+1 B id) | 2 B | 0 |
| DATA steady, all later flows | 3 B; grows to 4–5 B after 8192+ opens/owner | 2 B constant | **−1 to −3 B** |
| DATA OPEN v4 | 14 B | 14 B | 0 |
| DATA INLINE v4 | 13 B | 12 B | −1 B |
| downlink rebind `OPEN\|SRC` v4 | 14 B | **10 B** (`SRC`) | **−4 B** |
| TRAIN same, per item | 1–2 B len | 1 B len; **0 B** in SAME_EQUAL | −1 B/item |
| FRAG steady | 8 B (<128 id) / 9 B | 9 B | 0 / +1 B |
| HELLO+CAPS per connection | 25 B in 2 packets | **0** (ALPN/static) | −25 B, −2 packets |
| auth token per connection | token + stream frame, 1 packet | **0** (mTLS handshake) | −(57+T) B, −1 packet |
| FLOW_ACK per installed flow | 4–5 B, 1 packet | **0** | −(57+4) B packet, −state |
| SESS_CLOSE per association exit | 7 B ×3, 3 packets (192 B) | 8 B msg + 2 B STREAM framing in one packet (≈67 B) | ≈ **−125 B (≈ −65 %)** |
| NEED_CONTEXT/REJECT | n/a (FLOW_ACK/REJECT datagrams) | ≤6–8 B control msg, rare | neutral |

Worked per-operation totals (both directions where applicable):

| Operation | current | rev3 | Δ |
|---|---:|---:|---:|
| One-shot UDP, IP target, P=50 (open + ACK + steady reply) | 121 + 61 + 109 = **291 B** | 121 + 109 = **230 B** | **−21 %** |
| One-shot UDP, domain target L=11, P=50 (open + ACK + rebind reply + client ACK) | 129 + 61 + 121 + 61 = **372 B** | 129 + 117 = **246 B** | **−34 %** |
| Steady UDP P=50, confirmed | 109–110 B | **109 B** | −0…−1 B |
| Steady UDP P=8 | 67–68 B | **67 B** | −0…−1 B |
| 18×60 B same-flow train, per payload | ≈64.3 B | ≈63.4 B (SAME_EQUAL) | **−1.4 %** |
| Association close traffic | ≈192 B (3 packets) | ≈67 B (1 reliable msg; less if packed/coalesced) | **−65 %** |
| New connection MQP overhead | HELLO+CAPS+token: 25 B frames + 3 packets (≈196 B + T) | **0 MQP bytes** (mTLS handshake instead) | ≈ **−196 B + T**, −3 packets (once per connection) |

### 4.7 Parse/encode accounting (`[E]`; the Lead's parse-cost audit should benchmark these)

"ops" = peer-controlled byte loads/branches + table probes + allocations on the per-frame path; ranges are for
the steady data frame unless stated.

| Step | current rev2 | rev3 | why |
|---|---|---|---|
| Class/id decode | kind match + LEB128 loop (1–3 iterations, 4–10 ops) | `b0>>6` + two loads + shift/or (2–3 ops) | fixed width |
| Validity | `id != 0`, flags mask | class/flags mask, fid range | fewer branches |
| Binding lookup | RwLock acquire + foldhash + probe + Arc clone + release (10–20 ops) | paged-array index + tag compare + Arc clone (3–5 ops) | direct index |
| Version gate / CTL branch per datagram | atomic load + branch `[C] accept.rs:2688-2694` | none | HELLO/CAPS gone |
| Control frames on hot path | CTL branch + rate budget | none (stream task) | split planes |
| **Total steady decode** | **20–35 ops** | **8–12 ops** | |
| Steady encode, staged payload | `Bytes` copy (alloc+memcpy) then encoder `Vec` (alloc+memcpy) = 2+2 `[C] rev2.rs:772,791; r2.rs:299-304` | header written into payload headroom = **1 alloc + 1 copy** | buffer ownership |
| TRAIN SAME_EQUAL decode | n/a | per item: pointer advance + slice, zero length branches | new form |
| Domain OPEN decode | + UTF-8 check + String alloc | unchanged | same address codec |

Latency/CPU expectation `[E]`: steady-frame handling 20–40 % fewer decode ops and one fewer allocation per
staged payload; at 50–100 kpps this is a low-single-digit % of one core, and the *tail* benefit (no lock handoff
on the packet path) is larger than the mean. This is where rev3's measurable win is, together with the removed
control-plane packets — not in RTT.

### 4.8 RTT accounting vs the floor

| Operation | floor (added) | rev2 today | rev3 target | comment |
|---|---:|---:|---:|---|
| First UDP to unknown target, warm | 0 | 0 | 0 | already at floor |
| First UDP, cold | 1 RTT | 1 RTT | 1 RTT | transport floor; CAPS/HELLO/token add no RTT |
| First UDP, resumed | 0 (with early data) | 1 RTT | 1 RTT default / **0 opt-in** | only real RTT lever; replay-policy decision |
| Steady UDP | 0 | 0 | 0 | |
| TCP CONNECT / forward accept | 0 added | 0 | 0 | already at floor (optimistic SOCKS success) |
| Reconnect after failure | detection + 0/1 RTT | detection + 1 RTT | detection + 1 RTT default; detection + 0 opt-in | detection dominates (22–40 s); wire cannot fix |
| Downlink rebind | 0 | 0 (delivery); compression delayed by ACK | 0; compression starts after K contexts (no ACK) | |
| Flow close | 0 user-visible | best-effort ×3 | reliable, 0 user-visible | determinism improves |

### 4.9 Phased implementation plan

**Phase 0 — decisions + measurement (no wire change).** Resolve §5 questions (auth model, early-data policy, DNS
ownership, id policy, ALPN/masquerade). Add per-operation benchmarks to `examples/hotpath_bench.rs` /
`scripts/linux-bench-matrix.sh`: bytes per payload per op-class, p50/p99 first-payload and reply latency,
decode ns/frame, allocations/frame. These are the acceptance gates for later phases.

**Phase 1 — codec only.** New `src/mqp/r3.rs`: encode/decode for DATA/EXT/TRAIN/FRAG + control messages; golden
vectors for every form; property/fuzz tests for the decoder (truncation, flag pollution, count/len overruns);
unit tests for the 2-byte id packing and header sizing. No runtime wiring; compile-time feature `wire-r3`
(never a runtime switch).

**Phase 2 — identity + contract.** mTLS server verifier + client cert config; ALPN `myquic2/r3` as the default
and a startup refusal for conflicting configs; delete auth uni stream, `authenticate`, token config validation,
pre-auth connection slots, the post-auth MAX_STREAMS raise; delete HELLO/CAPS `CtlState`, pre-HELLO buffer and
the 2 s handshake loop; client egress publishes as soon as the connection is usable — after handshake completion when early data is off
(the default), immediately at 0-RTT when the opt-in replay-tolerant policy is enabled.

**Phase 3 — UDP data plane.** New flow registry (paged fid table), context-K binding sender, implicit
confirmation, NEED_CONTEXT recovery, REJECT TTL fallback; control stream (client-opened, `0xFF`, message
framing, rate caps); delete FLOW_ACK/FLOW_CLOSE/SESS_CLOSE×3/CTL-rate machinery; stager/FRAG ported to the new
codec with the SAME_EQUAL form; client and server UDP paths switched together.

**Phase 4 — TCP + cleanup.** Control-stream dispatch by first byte on the server accept loop; TCP path keeps the
address header + ACK (optionally add forward-mode target binding on the control stream → 0 B header); delete
rev2 (`r2.rs`, `r2_flow.rs`), v3 and MQP-2 datagram/stream production paths; rewrite README protocol in depth;
re-run the Linux netem matrix.

**Acceptance gates per phase:** (a) every operation's bytes within ±5 % of the model in §4.6; (b) p50/p99
first-payload and reply latency not worse than rev2 on the same host/path; (c) decode ns/frame and
allocations/frame improve or hold; (d) zero payload loss/duplication regressions in the existing E2E matrix;
(e) mixed-version peer fails at the TLS handshake, never at the frame layer.

### 4.10 Migration and fail-fast rollback (single version, no mixed deployment)

* **No runtime negotiation and no fallback.** The only wire is rev3; ALPN is the version gate. A rev2 peer and a
  rev3 peer cannot complete a TLS handshake → the client redials with existing backoff (200 ms–5 s)
  `[C] auth.rs:21-40` and gives a clear log line; no payload is ever interpreted under the wrong wire.
* **Deploy as matched pairs.** Server fleet and client fleet are upgraded inside one maintenance window (or
  canary with paired server+client). The client's reconnect loop already tolerates a server window being
  unreachable; the reverse (new server + old clients) fails cleanly at ALPN.
* **Rollback = redeploy the previous binaries on both sides.** Keep rev2 code for exactly one release behind
  the compile-time feature so rollback is a build, not a runtime toggle; delete it in the next release. No
  "compat mode" flag: a runtime flag that silently changes the wire is how mixed deployments happen.
* **Configuration fail-fast:** startup rejects `alpn = "h3"` unless the operator explicitly acknowledges that
  the h3 masquerade trades the clean version error for a less clear failure mode; rejects a non-empty
  `auth_token` (removed) unless a one-release deprecation shim is compiled in; logs the wire revision and mTLS
  identity at connection establishment.
* **Operational preconditions:** client certificates provisioned/rotated before cutover; server ticket lifetime
  chosen (revocation window); monitoring for REJECT/NEED_CONTEXT rates and unknown-fid drops to catch policy or
  capacity problems in the first hours.

---

## 5. Do-not-do list and open decisions

### 5.1 Do-not-do list (with reasons)

| Do **not** do | Why (evidence) |
|---|---|
| **Do not keep HELLO/CAPS as a runtime negotiation** | All CAPS values are protocol constants (`Caps::default()` is the only server construction `[C] accept.rs:1832-1835`) and the only runtime lever that matters — the path DATAGRAM budget — is already `Connection::max_datagram_size()`. HELLO/CAPS buys no RTT (`[C] egress.rs:414-425`), costs 25 B + 2 packets, an 8-frame/16 KiB pre-HELLO buffer, a per-frame version-gate atomic, and can kill a working connection after 2 s `[C] rev2.rs:52`. Replace with ALPN fail-fast + constants. |
| **Do not enable 0-RTT application payloads by default** | TLS 1.3 early data is replayable; a proxy carries non-idempotent UDP. A racing replay can execute a datagram twice (the original is then rejected as 0-RTT and retransmitted at 1-RTT). Identity is sound with mTLS, payload uniqueness is not. Only an explicit replay-tolerant class may opt in. |
| **Do not send the bearer token (or any credential) in early data** | Already correctly forbidden in the current code `[C] auth.rs:356-364`; a captured flight replays the credential and authenticates the attacker. This is why the token cannot be made 0-RTT-compatible without moving auth into the handshake. |
| **Do not shrink flow ids to u8 / hot-tag tables with reuse** | A 1-byte steady header needs either ≤256 never-reused ids (exhausted after ~256 flow opens, 16x below the 4096 live-flow target) or tag reuse. Reusing a tag safely requires knowing the peer processed FREE+BIND, i.e. an ACK round trip — exactly the FLOW_ACK cost being removed — and an unsafe reuse can deliver a delayed frame to a **new flow's target** (cross-flow leak). The byte win is ≤1 B/payload (≈1–2 % at 60–128 B) — not worth it. |
| **Do not keep FLOW_ACK as a datagram** | It is not a delivery ACK; it costs a packet per flow (≈61 B isolated), an `Opening→Open` state machine, and on lossy paths a permanent per-payload 14 B OPEN tax. Bounded context redundancy + reliable NEED_CONTEXT is strictly better in bytes, losses and code. |
| **Do not put OPEN/binding only on the reliable stream and compress immediately in datagrams without either inline context or a parking window** | Cross-plane ordering hazard: a lost control packet is retransmitted 1 PTO later while later datagrams keep flowing, so the receiver can see id-only frames for an unbound flow; without a safe policy this is payload loss (or, if the id is reused, misdelivery). See §2B. |
| **Do not reuse flow ids without a wire-visible epoch/tombstone** | Late frames must resolve to the live binding or nothing. The current never-reuse rule is the simplest correct answer; reuse needs epoch bytes (kills the 2 B header) or a guard. Keep never-reuse; handle exhaustion with INLINE + connection recycle. |
| **Do not add application-level retransmission, ACKs, or ordering for UDP payloads** | Violates UDP semantics, duplicates payloads, and duplicates QUIC work. Reliability for TCP is QUIC's job on the stream; UDP stays lossy by contract. |
| **Do not put large UDP payloads on reliable streams** | Converts loss into late delivery and adds head-of-line blocking — a global semantic change no application can opt out of. Keep FRAG; reduce fragments with a higher `initial_mtu` (config) instead. |
| **Do not change the fragment id to u16, add fragment trains, or enable FEC by default** | Historically measured loss cliffs and rejected in this repo `[C] MQP3_REFACTOR_ANALYSIS.md:79-92`. The 1–2 B/fragment saving cannot pay for reopening that evidence. |
| **Do not negotiate MTU or frame size in the application layer** | QUIC PMTU is authoritative and can change mid-connection; the wire must always use the live `max_datagram_size()` `[C] README.md:436, transport/build.rs:408-412`. Application-frame-size negotiation is what CAPS pretended to do and could not. |
| **Do not add an address/flow dictionary for steady frames** | The fid already is the dictionary; the only dictionary gain is for one-shot INLINE frames, which are rare and can be handled without new state. |
| **Do not make TCP CONNECT wait for the server dial ACK, and do not move BND.ADDR onto the critical path** | That adds 1 RTT to every SOCKS CONNECT; the current optimistic-success choice is what puts TCP at the floor `[C] socks.rs:241-258`. Keep the 0.0.0.0:0 trade documented. |
| **Do not add a runtime "compat" or wire-version switch** | Single-version deployment is a hard rule; a runtime switch is how mixed deployments and silent downgrade happen. Build-time feature only; ALPN is the gate. |
| **Do not compress, transform, or inspect payload bytes** | The current no-transformation invariant is a security property (no compression oracle, no per-payload CPU surprise) `[C] README.md:429`; keep it. |

### 5.2 Open decisions requiring the user

Each is stated as a decision with the options, the recommendation, and what it changes in the design.

1. **Auth model: mTLS client certs vs keep the bearer token.** mTLS: per-client identity, no auth stream, no
   pre-auth slot/credit split, sound resumption identity, enables early data structurally; cost: certificate
   provisioning/rotation, revocation only on full handshake (ticket lifetime becomes security-relevant).
   Token: zero provisioning change, but keeps the auth stream, the pre-auth machinery, and permanently forbids
   early data. **Recommendation: mTLS.** If mTLS is rejected, rev3 = §2A + §4.1 items 2–10 minus item 1
   (fallback variant "H−"), and the RTT section loses its only win.
2. **0-RTT payload policy.** (a) off for all payloads (default, recommended); (b) opt-in replay-tolerant class
   by destination port/flow allowlist; (c) all payloads (not recommended: duplicate-execution semantics for
   arbitrary UDP). Decision must include whether the current server `max_early_data_size = u32::MAX`
   `[C] server_cfg.rs:34-37` may stay enabled (it must not if policy is (a) — set 0).
3. **DNS ownership for domain targets.** Server-side resolution (current; SSRF/policy enforced at the exit,
   resolver RTT on cache miss is the exit's) vs client-side resolution (saves the exit's resolver RTT and
   exposes client DNS behavior; weakens the server's DNS/SSRF policy). **Recommendation: keep server-side**;
   add cache warming if DNS RTT shows up in latency profiles.
4. **Flow-id policy: 14-bit never-reuse + INLINE/recycle on exhaustion vs 3 B header + u32 ids.** The former is
   recommended (2 B steady, no growth, exhaustion is a correct-but-suboptimal fallback; pool can recycle).
   The latter never exhausts but costs +1 B/frame forever. Needs acceptance of the ~8192-flows-per-owner-per-
   connection budget and the resulting (rare) INLINE fallback.
5. **TCP BND semantics.** Keep optimistic SOCKS success with 0.0.0.0:0 (recommended; 0 added RTT) or report the
   real BND after the server dial ACK (+1 RTT per CONNECT). If any deployment needs real BND, it must be an
   application-visible trade, not a silent change.
6. **ALPN vs h3 masquerade.** Versioned ALPN (`myquic2/r3`) gives clean fail-fast and is recommended; the `h3`
   masquerade is obfuscation only (`[C] ack.rs:1-24`) and turns a wrong-version peer into a confusing
   data-layer failure. If masquerade is required, keep a *one-shot, reply-free* version probe as the first
   client frame (no retry loop, no 2 s kill), and accept a less clear failure mode.
7. **Control-stream scope.** Recommendation: rare messages only (`ASSOC_CLOSE`, `SESS_CLOSE`, `REJECT`,
   `NEED_CONTEXT`). Alternative: keep best-effort CTL datagrams for these (simpler, no new stream task, but
   keeps nondeterministic reclamation and the rate-budget code). Decision affects the implementation plan, not
   the wire contract.
8. **Connection recycling policy for id exhaustion.** Client-driven low-water recycle (new pooled connection,
   old one drains) vs pure INLINE fallback vs both. Recommendation: INLINE fallback mandatory (correctness),
   recycle opportunistic (pool), no GOAWAY required in v1.
9. **Per-client authorization requirements.** mTLS enables ACLs (which clients may reach which destinations).
   Is per-client policy required in rev3 v1, or is one shared authorization policy per server enough (current
   token semantics)? This decides how much identity plumbing ships.
10. **Full-cone / server-owned flows.** Keep (it is the only way unsolicited replies compress and the only user
    of the server half of the id space) or drop for simplicity. **Recommendation: keep**, opt-in as today.
11. **Whether a one-release compile-time `wire-r2` feature is acceptable for rollback**, or rollback must be
    "redeploy previous release" only. Recommendation: keep the feature for one release, then delete; it is
    build-time, never runtime.
12. **Ticket lifetime / revocation posture** (mTLS consequence): how long resumed connections may bypass
    certificate revocation. Recommendation: short server ticket lifetime (hours, not days) for a proxy.

---

## Appendix A — derivations and arithmetic

### A.1 QUIC/DATAGRAM budget (`[D]`)

From quinn-proto 0.11.19:
`max_datagram_size = current_mtu − predict_1rtt_overhead(None) − Datagram::SIZE_BOUND`
= `MTU − (1 + dcid_len + 4 + 16) − 9` = `MTU − 38` with the default 8-byte CID `[C]`
(`src/connection/datagrams.rs:82-95`, `src/connection/mod.rs:3763-3776`, `src/frame.rs:901-918`).
At MTU 1200 → 1162 B; at 1472 → 1434 B. Wire bytes for a full IPv4 packet = 1162 + 38 (UDP) + 20 (IP) = 1220 B;
per-packet non-MQP overhead ≈ 57 B for isolated small frames (28 IP/UDP + 26–27 QUIC + 3 DATAGRAM), skewed by
quinn's 4-byte-PN + 9-byte-DATAGRAM conservative reservation.

Quinn packs DATAGRAM frames: `while buf.len() + Datagram::SIZE_BOUND < max_size { datagrams.write(...) }`
`[C]` `src/connection/mod.rs:3347-3359`; therefore for `k` frames per packet the fixed header is shared and the
per-frame overhead is `54/k + 3`.

### A.2 Current header sizes (`[D]` from `src/mqp/r2.rs`)

| Form | Formula (bytes) | v4 values |
|---|---|---:|
| DATA steady | `1 + LEB128len(fid) + P` | header 2 (fid≤127) / 3 (fid≤16383) / 4 / 5 |
| DATA OPEN | `2 + LEB128len(fid) + 4 + addr` | 14 (id 1 B) / 15 (id 2 B); domain 11+L / 12+L |
| DATA INLINE | `2 + 4 + addr` | 13 / 25 / 10+L |
| TRAIN SAME | `3 + LEB128len(fid) + Σ(LEB128len(len)+P)` | base 4–5; item 1–2 B |
| TRAIN DICT | `4 + Σ LEB128len(fid) + Σ(1 + LEB128len(len) + P)` | base 4+nfl·(1–2); item 2–3 B |
| FRAG steady | `1 + LEB128len(fid) + 4 + 1 + 1 + chunk` | 8 (id 1 B) / 9 (id 2 B) |
| FRAG OPEN | `2 + LEB128len(fid) + 4 + 1 + 1 + 4 + addr + chunk` | v4 19 / 20 |
| CTL | HELLO 8, CAPS 17, FLOW_ACK 3+LEB, FLOW_REJECT 3+LEB, FLOW_CLOSE 2+LEB, SESS_CLOSE 7 | 4 / 4 / 3 |

Cross-checked against the codec goldens `[C]` `src/mqp/r2.rs:1113-1314` and the README table
`README.md:193-200` (the table is right; the §1/§4 headline "2 B instead of 5–6 B" applies only to the first 63
flows/owner).

### A.3 Flow-id size growth (`[D]`)

`fid = (local_id << 1) | owner`; `local_id` starts at 1 and never repeats `[C]` (r2_flow.rs:743-778).
LEB128 one byte holds 0–127 → local 1..63 per owner (63 flows). Two bytes hold ≤16383 → local ≤8191 per owner
(8191 cumulative opens; live cap is 4096, so a connection that opens more than 8191 flows over its life crosses
this). Three bytes cover ≤2 097 151 → 1 048 575 opens. Hence steady header is 2 B for the first 63 flows/owner,
then 3 B, then 4 B, then 5 B — monotonically worse for exactly the long-lived connections that matter.

### A.4 Worked byte examples (IPv4, P=50, isolated packets, `[D]`)

* **One-shot UDP, IP target** — current: `OPEN(14+50+57=121)` + `FLOW_ACK(4+57=61)` + `steady reply(2+50+57=109)`
  = **291 B**; rev3: `OPEN(14+50+57=121)` + `reply(2+50+57=109)` = **230 B** (−21 %).
* **One-shot UDP, domain L=11** — current: `OPEN(22+50+57=129)` + `FLOW_ACK(61)` +
  `OPEN|SRC(14+50+57=121)` + client `FLOW_ACK(61)` = **372 B**; rev3: `OPEN(22+50+57=129)` +
  `SRC(10+50+57=117)` = **246 B** (−34 %).
* **Association close** — current: `3 × (7+57) = 192 B`; rev3: one reliable `ASSOC_CLOSE` (8 B body + 2 B
  STREAM framing; ≈67 B if it owns a packet, less if packed/coalesced) → ≈**−65 %**, deterministic.
* **Steady P=50** — current 2–3 B header → 109–110 B; rev3 2 B → 109 B; at P=8: 67–68 → 67 B.
* **TRAIN 18×60 B (SAME_EQUAL)** — body `1+2+1+1 + 18×60 = 1085`; packet 1142; per payload
  `(57+5)/18 + 60 ≈ 63.4 B`; current SAME: `(3+1) + Σ(1+60) = 1102` body → ≈64.4 B/payload (−1.4 %).

### A.5 Decode-op counting method and caveat

Counted per frame: peer-controlled byte loads, comparisons/branches, table probes/lock operations, heap
allocations/copies. Varint iteration is 4–6 ops per byte plus the loop branch; a 2-byte id costs 8–12; a fixed
2-byte load costs 2–3. A `RwLock<HashMap>` lookup (current registry `[C]` r2_flow.rs:436-441,587-606) is
acquire + foldhash + probe + `Arc` clone + release; a direct paged-array index is bounds check + load + `Arc`
clone. Ranges are `[E]` and should be replaced by measured ns/frame from the Lead's parse-cost audit; the
*direction* (fixed 3–5× fewer ops) is robust to the exact accounting.

### A.6 Measurement plan for the estimates in this document

| Estimate | How to measure |
|---|---|
| bytes per operation | count MQP frame bytes + `try_send_datagram` calls in the existing hotpath bench; validate against §4.6 within ±5 % |
| decode/encode ns per frame | criterion micro-bench over the codec (current r2 vs new r3), 8/60/128/512/1200 B, warm cache |
| allocations/frame | counting allocator in the unit test/bench |
| first-payload and reply p50/p99 | `lat`/`udppaced` modes in `examples/hotpath_bench.rs`; Linux netem matrix `scripts/linux-bench-matrix.sh` at 0/0.5/2 % loss and 70/140 ms |
| reconnect recovery | chaos test: kill path, measure time from last delivered payload to first recovered payload, compare 22/40 s gate + 1-RTT vs shortened idle |
| control-stream cost | bytes/messages per connection in a 1-hour mixed workload; ensure <0.1 % of wire |

---

## Appendix B — where this analysis contradicts the brief or the repo docs

1. **"Current wire: 2 B steady header"** — only for the first 63 flows per owner per connection; the 64th+ flow
   costs 3 B, and because ids are never reused the header grows to 4–5 B over a long-lived connection
   (§0.3, A.3). The brief's "usually 3 B" is correct; the README's §1/§4.1 headline is not representative.
2. **"TRAIN amortizes the 57 B packet header"** — quinn already packs multiple DATAGRAM frames per packet
   `[C] quinn-proto connection/mod.rs:3347-3359`, so TRAIN's byte win is the per-frame DATAGRAM header (3 B) +
   MQP header + send call, not the whole packet header. Prior analyses that assumed one frame per packet
   overstate TRAIN's byte benefit (and understate its send-call/CPU benefit).
3. **"HELLO/CAPS may delay a payload"** — it does not (`[C] egress.rs:414-425`, server pre-HELLO buffer
   `[C] accept.rs:2645-2698`); it is still worth deleting for its cost/failure mode, not for RTT.
4. **"FLOW_ACK enables compression"** — true, but it is not a delivery ACK and does not change delivery latency;
   its removal must be paired with a replacement (context redundancy/NEED_CONTEXT) or flows with lost OPENs
   blackhole. The brief's skepticism is right, but "eliminate FLOW_ACK" alone is not a complete design.
5. **"0-RTT saves no application RTT today"** — confirmed by code: the client awaits the handshake-complete
   future before writing the token/data `[C] auth.rs:366-410`. It is also not usable without moving auth into
   the handshake (`[C] server_cfg.rs:34-37` enables early data, but a replay-safe identity is the blocker).
6. **`FLOW_CLOSE` is specified but dead on the wire** — no production sender exists `[C]` (only tests and
   decode paths). Any lever involving FLOW_CLOSE is about deleting code, not changing behaviour.
7. **The 4096-flows/conn cap is live, but ids are cumulative** — a connection can open far more than 4096 flows
   over its life, which is what makes the varint growth real.
8. **The prior refactor plan's "control plane on one QUIC bidi stream" is the right place for close/reject but
   the wrong place for OPEN** — with self-describing first frames, an OPEN on the stream adds no RTT value and
   creates the parking/reorder hazard analyzed in §2B. The recommendation keeps the stream only for rare
   messages.
9. **Cold-dial timing convention (relevant when reconciling with the other audits).** This document counts
   server-visible first 1-RTT data at **1.5·RTT after ClientHello** (the client can publish and send 1-RTT data
   at 1 RTT; one more one-way to reach the server). An audit that places the *client* receive of the server
   handshake flight at 0.5 RTT (or the server-visible first data at 1 RTT) has shifted the clock by one one-way
   delay; the per-operation *deltas* are unchanged, but the 0-RTT saving becomes **1 RTT** on this timeline, not
   0.5. Check this before merging RTT ledgers.

---

## Appendix C — citation index

| Area | Files/lines |
|---|---|
| rev2 codec | `src/mqp/r2.rs:1-43` (framing/identity), `61-105` (kinds/limits), `143-179` (ids/varints), `275-332` (DATA encode), `356-424` (DATA decode), `430-527` (TRAIN), `586-661` (TRAIN decode), `686-796` (FRAG), `862-1043` (CTL), `1113-1314` (goldens) |
| flow state/registry/alloc | `src/mqp/r2_flow.rs:36-50` (caps), `56-118` (binding/confirmation), `240-406` (session tables), `436-738` (registry), `743-778` (ids), `780-869` (CTL state/rate) |
| address codec | `src/mqp/addr.rs:59,81-106,122-196,198-245` |
| client auth/dial/0-RTT | `src/bin/myquic2-client/auth.rs:21-43,84-200,345-447`; `src/tls/client_cfg.rs:9-22`; `examples/zero_rtt_probe.rs:9-60` |
| server auth/contract | `src/bin/myquic2-server/auth.rs:6-47`; `src/bin/myquic2-server/main.rs:760-890`; `src/tls/server_cfg.rs:9-37` |
| HELLO/CAPS | `src/bin/myquic2-client/rev2.rs:46-53,464-535`; `src/bin/myquic2-server/accept.rs:1103-1104,1437-1466,1823-1836,2645-2698` |
| client uplink/stager | `src/bin/myquic2-client/rev2.rs:640-1130`; `src/udp/r2_stage.rs:60-69,386-700,898-930`; `src/mqp/r2.rs:430-527` |
| client downlink/dispatch | `src/bin/myquic2-client/dispatcher.rs:861-882,971-1135,1150-1365` |
| server ingress/install/ctl | `src/bin/myquic2-server/accept.rs:1517-1576,1606-1690,1780-1915,2030-2470,2531-2735,2750-2930` |
| fragmentation bounds | `src/mqp/fragment.rs:47,55,107,165,176` (8 KiB / 64 / 2 s / 256 / 256 KiB) |
| server reply path | `src/bin/myquic2-server/reader.rs:180-300,500-680,1040-1160` |
| TCP path | `src/bin/myquic2-client/socks.rs:1-9,180-300`; `src/bin/myquic2-server/tcp.rs:1-210`; `src/mqp/ack.rs:41-49,124-135` |
| transport/tuning | `src/transport/build.rs:260-412`; `src/transport/limits.rs:74-102`; `src/config/tuning.rs:80-111,267-345`; `src/config/client_conf.rs:40-120,175,331` |
| TCP flags/ports/egress | `src/bin/myquic2-client/egress.rs:317-425`; `config-client.toml:59-67` |
| docs (secondary) | `README.md:103-200,233-352,432-446,485-497,1501-1800`; `MQP3_REV2_SPEC.md:24-44,98-99,165-203,244-269`; `MQP3_REFACTOR_ANALYSIS.md:79-92,140-165,279-330,399-466,630-646` |
| quinn-proto (dependency) | `0.11.19 src/connection/datagrams.rs:82-100,200-221`; `src/connection/mod.rs:3347-3359,3763-3776`; `src/cid_generator.rs:55-66`; `src/frame.rs:896-918` |

*End of analysis. No source files were modified; no build or test was run.*
