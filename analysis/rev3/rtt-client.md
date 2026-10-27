# MQP-3 rev2 — client-side RTT / interaction audit (rev3 redesign input)

Task: `task-1` (RTT audit A: client-side interactions, connection lifecycle, 0-RTT/auth/ACK gating).
Scope: the **client** half of MyQUIC2 at commit `ed329e4` (working tree), server ingress where it is the
interaction counterpart. No `src/` edits, no builds/tests were run. Analysis only.

**Evidence grading** used throughout:

- `[code F:l]` — verified by reading the cited repository lines.
- `[code-dep P:l]` — verified in a vendored dependency source under
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/{quinn,quinn-proto,rustls}-*`.
- `[derived]` — arithmetic/state-machine consequence of cited code.
- `[estimate]` — model number, not measured (no benchmark was run).

Convention: **`d` = one one-way delay = RTT/2**. I report round trips as `1 RTT = 2d`. When a decision
happens after one one-way, I write `0.5 RTT`. "MQP-attributable RTT" means a round trip caused by an MQP-3
protocol decision that a wire redesign could remove; "QUIC-inherent" means handshake/serialization cost.

---

## 0. Headline

1. **No MQP round trip is on the payload-delivery critical path.** The client's UDP uplink is
   fire-and-forget: `send_uplink` encodes and `try_send_datagram`s synchronously, and the server forwards a
   `DATA OPEN` payload **before** it installs the binding and sends `FLOW_ACK`
   `[code src/bin/myquic2-client/rev2.rs:733-805, 964-998; src/bin/myquic2-server/accept.rs:2144-2177]`.
   There is no `await` on an ACK anywhere in the UDP send path. A first datagram is delivered after one
   one-way delay (0.5 RTT), which is the same as any IP proxy.
2. **Exactly one MQP round trip exists in the whole client protocol: the per-flow confirmation**
   (`DATA OPEN → CTL FLOW_ACK` uplink, `DATA OPEN|SRC → CTL FLOW_ACK` downlink). It is worth **1 RTT**,
   it only gates *compression/aggregation* (not delivery), and both ends already treat any compressed
   downlink frame as an implicit ACK `[code dispatcher.rs:993-999, 1125-1135]`. During that 1-RTT window a
   flow's payloads carry the extended header (`+12 B` IPv4, `+9+L B` domain, `[derived r2.rs:280-283]`) and
   each is a standalone DATAGRAM that cannot join a `TRAIN` `[code src/udp/r2_stage.rs:15-23, 475-490]`.
3. **The 0-RTT machinery is fully plumbed but saves 0 RTT today.** The client enables early data
   `[code src/tls/client_cfg.rs:17]`, the server accepts it `[code src/tls/server_cfg.rs:30-34]`, and
   `dial_once` calls `into_0rtt()` `[code auth.rs:372-389]` — but it awaits `ZeroRttAccepted`, which resolves
   only when the handshake completes (one one-way, i.e. **0.5 RTT**, not one RTT: rustls marks the client
   handshake complete when it processes the server's `Finished` `[code-dep rustls-0.23.46/src/client/tls13.rs:1349-1467,
   common_state.rs:114-116; quinn-proto-0.11.19/src/connection/mod.rs:2565-2616; quinn-0.11.12/src/connection.rs:82-97,126-137]`),
   then publishes and sends the token. Because the server's auth gate (`authenticate()`, a 1-RTT uni stream)
   arrives on the same flight as the first possible 1-RTT data, the server can first forward at **1.0 RTT**
   after ClientHello either way `[code src/bin/myquic2-server/main.rs:798-880; src/bin/myquic2-server/auth.rs:22-46]`.
   Sending datagrams in 0-RTT would therefore save **zero** end-to-end latency; moving *auth* into early
   data is the only lever, and it is worth **0.5 RTT** (see F14/F15).
4. **What dominates user-visible latency after a path failure is not RTT at all**: a blackholed path is
   detected by the client watchdog after `2/3 × idle` = **40 s** (default), then a 0.2–5 s redial backoff is
   paid, and UDP datagrams in the failed egress class are **dropped, not queued** (default
   `udp_fail_closed = true`) `[code auth.rs:21-28,168-190,223-228; src/config/client_conf.rs:318-323;
   egress.rs:266-297,384-402; assoc.rs:487-509]`. The interactive UDP class (which is where DNS/STUN/games
   live, ports 53/123/3478-3481 by default) has exactly **one** egress connection, so this is a total-loss
   window for the most latency-sensitive traffic.
5. **Bytes:** a bound IPv4 flow costs `OPEN 14 B + FLOW_ACK 4 B = 18 B` of MQP control vs. `INLINE 13 B`
   for the same one-shot payload — i.e. binding a flow only pays off from the **second** payload
   `[derived; code r2.rs:280-283,903-914]`. Steady is 2 B for the first 64 ids on a connection, then 3 B
   (varint `wire_id ≥ 128`) `[derived r2.rs:172-179; src/mqp/r2_flow.rs:744-780]`.
6. **The current wire has dead surface relevant to a redesign:** `CTL FLOW_CLOSE` is decoded and handled by
   both ends but **never sent by either endpoint** in production code; flows are only retired by
   `SESS_CLOSE` (whole association) or connection death `[code only decode/handlers at dispatcher.rs:1016-1029,
   accept.rs:1862-1882; the only encoder call is a unit test, r2.rs:1306]`.

---

## 1. Timing model (what "0.5 RTT" and "1 RTT" mean here)

### 1.1 Cold dial, one one-way = d

TLS 1.3 over QUIC, full handshake or resumption (both are 1 RTT total, not 0 RTT, for first *forwarded*
data):

| t | client | server | evidence |
|---|---|---|---|
| 0 | sends ClientHello (+0-RTT packets if resuming; **no app data today**) | | `[code auth.rs:356,372; client_cfg.rs:17]` |
| d | receives server handshake flight; rustls `ExpectFinished::handle` → `start_traffic` → quinn `Connected`; `ZeroRttAccepted` resolves. `dial_once` calls `send_auth` (uni stream, ≤256 B `AUTH_TOKEN_MAX_BYTES`) then returns; conn loop publishes; `CTL HELLO` sent. | | `[code auth.rs:372-409,418-447,68-103; code-dep rustls…tls13.rs:1349-1467; quinn-proto…mod.rs:2565-2616]` |
| d+ε | first app datagram / TCP `open_bi` possible (published) | | `[code auth.rs:77; socks.rs:154-170; assoc.rs:469-513]` |
| 2d = 1 RTT | | receives client `Finished` + token + HELLO + first data in one flight. Server `Connected` → `authenticate()` (token already complete) → `handle_conn` spawns the datagram reader. First UDP payload forwarded; TCP target dial starts. | `[code src/bin/myquic2-server/main.rs:798-880; accept.rs:2750+; src/bin/myquic2-server/auth.rs:22-46]` |

Consequences:

- **Client-side publish latency is 0.5 RTT** (one one-way), not 1 RTT: `accepted_fut` is the quinn
  `Connected` oneshot `[code-dep quinn-0.11.12/src/connection.rs:126-137, 219-227]`, and the client
  considers the TLS handshake complete as soon as it has processed the server's Finished and queued its
  own `[code-dep rustls…client/tls13.rs:1467 → common_state.rs:114-116,478-491]`. A resumed handshake has
  the same client-side timing as a full one; resumption saves certificate bytes/CPU, **not an RTT**.
- **The auth stream adds 0 RTT.** The token is written before publish `[code auth.rs:386-388]`; it rides the
  same flight as the client's `Finished` and the first MQP datagrams, and the server's
  `authenticate()` (`accept_uni()` + `read_to_end`, `[code src/bin/myquic2-server/auth.rs:30-35]`) returns
  as soon as its handshake completes — it never waits an extra round trip. The token costs ≤256 B on the
  wire plus one stream+FIN.
- **Server-visible first data is at 1 RTT** after ClientHello for every dial (full or resumed). The DIAL
  attempt cap is 5 s `[code auth.rs:304-313]`, the watchdog silence is `2/3 × idle = 40 s` at defaults
  `[code src/transport/build.rs:167-183; auth.rs:41]`.

### 1.2 What 0-RTT could and could not buy (derivation)

- **0-RTT datagrams with today's 1-RTT auth → 0 saving.** The client could queue datagrams before
  `accepted_fut` and quinn would send them in 0-RTT packets (technically supported: RFC 9221 §3 explicitly
  allows DATAGRAM frames in 0-RTT packets — I verified this in <https://www.rfc-editor.org/rfc/rfc9221.txt> —
  and quinn-proto carries the remembered transport parameters into 0-RTT so
  `send_datagram`/`max_datagram_size` already work `[code-dep quinn-proto…connection/mod.rs:2059-2094,
  datagrams.rs:24-102]`). They would arrive at the server at 0.5d, but the server refuses to start
  `handle_conn` before `authenticate()` returns `[code server main.rs:853-880]`, and the token cannot be
  sent before the client holds 1-RTT keys (available at d, when the server's Finished is processed), so it
  arrives at 2d. Server first forward: **2d — identical to today**.
  The only benefit would be avoiding client-local drops in the 0…d window (F9/F10), which queue-until-publish
  also fixes without replay risk.
- **0-RTT auth → saves 0.5 RTT.** If the token (or the resumption ticket itself) were accepted from early
  data, the server could authenticate at 1d and forward at 1d instead of 2d. That is the entire 0-RTT
  opportunity on this protocol: **one one-way delay on every re-dial (and only re-dials; a full handshake
  has no ticket).** See F15 for the replay trade-off.

---

## 2. Event table

`d = RTT/2`. Counts are round trips; `0.5` = one one-way delay. "MQP RTT" = removable by a wire redesign.

| # | Event | Datagrams / frames exchanged | MQP-attrib. RTT | QUIC-inherent RTT | Where the payload / app waits (file:line) | Notes |
|---|---|---|---:|---:|---|---|
| 1 | TCP SOCKS5 CONNECT — **warm pool** | 1 bidi stream open; `STREAM` = 7 B IPv4 target header (`16 B` v6, `4+L` domain, `[code src/mqp/addr.rs:52-74]`); app bytes follow; server answers the 11 B MQP dial ACK after target connect; then byte pump. **No rev2 frames** (rev2 is UDP-only). | 0 | 0 (existing conn) | none: SOCKS reply is written locally before the dial ACK `[code socks.rs:246-272]`; the c2s pump is not ACK-gated `[code src/tcp/pump.rs:47-61,495]` | App's first byte leaves immediately; the only added latency is the proxy-inherent server→target RTT. |
| 2 | TCP SOCKS5 CONNECT — **cold pool** (no published slot yet) | as #1, but `wait_conn` first | 0 | 0.5 RTT (publish after `accepted_fut`); up to `reconnect_timeout_secs` = 5 s if the slot is between dials `[code src/config/client_conf.rs:47-48; socks.rs:154]` | SOCKS reply delayed by `wait_conn` `[code socks.rs:154-168]`; app socket unread until the pump starts | On timeout: `REP=0x04` host-unreachable, not a silent drop `[code socks.rs:157-166]`. Fully hiding this would require answering SOCKS success before a connection exists. |
| 3 | TCP SOCKS5 CONNECT — **slot blackholed** | as #1 | 0 | 0.5 RTT redial once the watchdog closes at ~40 s; new-flow steering after ~22.5 s `[derived pool.rs:431-441; code auth.rs:168-190]` | `wait_conn` up to 5 s then `REP=0x04` `[code socks.rs:154-168]` | In-flight flows already assigned to the slot are RST (no retry after the optimistic reply `[code socks.rs:294-302]`). |
| 4 | TCP forward-mode accept — **warm** | same as #1 minus SOCKS negotiation/reply | 0 | 0 | app bytes are not read until `open_bi`+header write complete `[code forward.rs:235-241,278-307]` | Target address is the one-time `AddrHeader`; no SOCKS reply exists, so failures become RST `[code forward.rs:236-241,315-322]`. |
| 5 | TCP forward-mode accept — **cold / redialing** | one `wait_conn` per accepted connection | 0 | 0.5 RTT publish; up to 5 s `wait_conn` stall | app bytes sit in the kernel receive buffer until the stream exists `[code forward.rs:278-307]` | No reply channel: a failed wait is an RST, after up to 5 s of app stall. |
| 6 | UDP ASSOCIATE setup | none on the wire | 0 | 0 | — | Local: hub slot + relay socket bound, entry published **before** the SOCKS reply `[code assoc.rs:568-582]`. There is no MQP/QUIC interaction and no wait. |
| 7 | UDP ASSOCIATE first datagram — **warm** | up: `DATA OPEN` (14 B IPv4, `11+L` domain) + payload; down: server forwards the payload, then `FLOW_ACK` 4 B | 0 | 0 (delivery = 0.5 RTT one-way, not a wait) | none client-side: `send_uplink` stages/encodes synchronously, no ACK await `[code assoc.rs:391-402,469-513; rev2.rs:733-805]` | Payload forwarded **before** install/ACK `[code accept.rs:2144-2177]`; ACK processed async `[code dispatcher.rs:993-999]`. |
| 8 | UDP ASSOCIATE first datagram — **cold pool** (nothing published) | 0 (datagram dropped) | 0 | 0.5 RTT until a connection publishes | **not held — dropped**: `NO_EGRESS` `[code assoc.rs:487-509; tests.rs:4161-4177]` | A one-shot app (DNS query) must retry on its own timer (often 1–5 s): this is the largest cold-start penalty in the client. |
| 9 | UDP steady (per datagram) | 1 steady `DATA` = 2 B header + payload each way | 0 | 0 | stager queue only until the **same** relay poll's burst end `[code assoc.rs:773-775; rev2.rs:1143-1162]` — no timer, no await | Hot path: 1 memo load, brief `parking_lot` stager lock, one `try_send_datagram`; `parking_lot` registry/stager locks are never held across I/O `[code egress.rs:164-190; rev2.rs:264-287; r2_stage.rs:944-1006]`. |
| 10 | **New flow OPEN → FLOW_ACK** | up: `DATA OPEN` 14 B / `11+L` B + payload; down: `CTL FLOW_ACK` 4 B (`3+varint(id)`, `[code r2.rs:906-912,944-948]`) | **1** (confirmation only) | 0 | payload not held; **compression** waits 1 RTT for the binding state `[code dispatcher.rs:993-999]` | While `Opening`: every payload is a standalone `DATA OPEN` (+12 B IPv4 / +9+L domain vs steady) and cannot join a `TRAIN` `[code rev2.rs:778-796; r2_stage.rs:475-490]`. ACK lost → next OPEN is re-ACKed `[code accept.rs:2221-2243,2325-2352]`. Any compressed downlink frame also marks it open `[code dispatcher.rs:1132-1135]`. |
| 11 | **Domain-target flow** | up: each payload in the window repeats the domain `DATA OPEN`; server resolves off-loop, queues duplicates, then forwards + installs + ACKs | 1 (confirmation, delayed by DNS) | 0 | **first payload held up to `DNS_LOOKUP_TIMEOUT` = 5 s** behind the server lookup; later payloads queued `[code accept.rs:2051-2167; src/dns/store.rs:100]` | Buildup is bounded: 16 in-flight opens/connection, 64 payloads and 256 KiB per open `[code accept.rs:1110-1121]`. The 1-RTT window becomes `DNS + 1 RTT` and every payload in it pays the domain header. |
| 12 | **Broken/slow flow — `FLOW_REJECT`** | down: 4 B once; subsequently `DATA INLINE` (13 B IPv4 / `10+L` domain) per payload, unbound | 0 | 0 | no hold; INLINE is forwarded one-shot `[code r2_stage.rs:15-23; accept.rs:602-634]` | TTL: 1 s for `table_full`/`dns`, 30 s for `policy` `[code rev2.rs:83-91,1079]`. The rejected OPEN's payload was already forwarded for IP/resolved-domain targets; policy/DNS rejects drop it. No retry/ack round trip. |
| 13 | **Server-reaped session** (`SESS_CLOSE` received) | down: 7 B ×3; next client payload re-`OPEN`s with a **new** id | 0 | 0 | no hold | `sync()` clears the binding table; ids are never reused `[code rev2.rs:687-704; src/mqp/r2_flow.rs:744-780]`. If all 3 closes are lost, steady frames for that session are silently dropped server-side (unknown id) and nothing tells the client: the flow blackholes until the app times out (F18). |
| 14 | **Reconnect after path failure — TCP** | dial + auth token + HELLO/CAPS + new streams | 0 | 0.5 RTT to publish; 1 RTT to server-visible; + 0.2–5 s backoff after detection | new flows: `wait_conn` ≤5 s; old flows: RST on connection close `[code socks.rs:154; auth.rs:222]` | Detection: 40 s watchdog `[code auth.rs:168-190]`; a cleanly closed slot is re-picked immediately by the dead-handle check `[code pool.rs:848-856]`, a blackholed one stops receiving new flows only after the ~22.5 s stale gate `[derived pool.rs:431-441,816-868]`. Backoff reset only if the dead connection lived ≥5 s `[code auth.rs:223-228]`. |
| 15 | **Reconnect after path failure — UDP** | 0 while down | 0 | as #14 | **dropped, not queued**: `NO_EGRESS` `[code assoc.rs:487-509]` | Default `udp_fail_closed = true` confines a datagram to its class's dedicated slot(s) `[code src/config/client_conf.rs:318-323; pool.rs:676-682; egress.rs:317-348]`; the interactive class has exactly one slot (index 0) `[code pool.rs:697-719]`, so DNS/STUN/game traffic is a total-loss window of ~41 s + backoff after a blackhole. |
| 16 | **Close — UDP association exit** | up: 3 × `CTL SESS_CLOSE` 7 B = 21 B `[code r2.rs:906-912,958-962]` | 0 | 0 | none | No per-flow close frame: `FLOW_CLOSE` is decode-only and never sent (F17). No ack. Skipped entirely if `!rev2.is_ready()` (CAPS not yet received) `[code rev2.rs:600-619,606]`. Server's 180 s idle sweep is the backstop. |
| 17 | **Close — TCP flow** | stream FIN or RST; no MQP frame | 0 | 0 | none | Half-close propagates both ways; abnormal end is RST `[code src/tcp/pump.rs:563-600]`. 300 s idle deadline. |
| 18 | **Close — connection** | QUIC `CONNECTION_CLOSE` | 0 | 0 | in-flight payloads lost, no drain | `retire_dead_slot` clears the rev2 registry and staged payloads and invalidates the egress cache `[code auth.rs:280-302]`; staged payloads are booked as egress deaths, not retried. |
| 19 | **Connection setup (supporting)** — HELLO/CAPS/auth | up: `CTL HELLO` 8 B (retried every 200 ms until CAPS); down: `CTL CAPS` 17 B (≤1/100 ms); up: auth token ≤256 B on a uni stream | 0 | 1 RTT to server-side auth; 0.5 RTT to publish | no payload waits: CAPS is **not** a data gate on the client `[code egress.rs:415-423; tests.rs:5129-5166]` | Only `send_sess_close` reads `is_ready()` `[code rev2.rs:606]`. Missing CAPS for 2 s closes a connection that may already be carrying data (`HANDSHAKE_TIMEOUT = 2 s`) `[code rev2.rs:46-50,473-519; auth.rs:98-103]` → redial + backoff for every flow on it (F8). |

---

## 3. Findings

### F1 — The steady/open UDP path contains **no** round trip; delivery latency is one one-way delay. `[code]`

`AppDgramCtx::process` is fully synchronous (`no .await`, `[code assoc.rs:265-404]`); `send_uplink` →
`stage_or_count` → `push_stage` or `try_single_data` all complete synchronously
`[code rev2.rs:733-805,813-866,964-998]`. The only network send is `try_send_datagram`. On the server,
the `DATA OPEN`/`DATA` payload is sent to the target **before** the binding install and `FLOW_ACK`
`[code accept.rs:2144-2177]`. Therefore Open/steady/FRAG/TRAIN payloads are never held for an MQP reply.
The wire redesign has **zero user-visible RTT to remove on this axis**; its recoverable inefficiency is
bytes and send calls, not latency.

### F2 — Cold/reconnect publish wait is 0.5 RTT, and a resumed handshake is not faster than a full one. `[code + code-dep + derived]`

`dial_once` awaits `ZeroRttAccepted` before `send_auth`/publish `[code auth.rs:372-409]`. That future is
quinn's `Connected` oneshot `[code-dep quinn-0.11.12/src/connection.rs:126-137,219-227]`; for a client the
event fires when rustls reports `is_handshaking() == false`, which happens while processing the server's
`Finished` (`ExpectFinished::handle` → `start_traffic`)
`[code-dep rustls-0.23.46/src/client/tls13.rs:1349-1467, common_state.rs:114-116,478-491]`. The server
flight arrives after one one-way delay, so publish is at 0.5 RTT for both resumed and full handshakes.
Consequences: (a) the client-side "cost of resumption" is bytes/CPU only; (b) the 0-RTT offering is
entirely wasted today (F14); (c) any redesign that wants to reduce cold-start must address **auth** or
publish earlier, not the handshake.

### F3 — The per-flow confirmation round trip is the only MQP round trip; it costs 1 RTT of compression, not 1 RTT of delivery. `[code + derived]`

- Uplink: `ensure_binding` creates a `FlowBinding` in `Opening`; while `!binding.is_open()` every payload
  is staged as `R2StageKind::Open` `[code rev2.rs:778-796]`, encoded as a standalone
  `DATA OPEN` (`2 + varint(id) + 4 + addr` = **14 B** IPv4, `11+L` domain) `[code r2.rs:280-283,307-332;
  r2_stage.rs:475-490]`, and cannot be folded into a `TRAIN` (`TRAIN` is only for confirmed `Open` flows
  `[code r2_stage.rs:15-23; README §4.2]`).
- Confirmation arrives one RTT after the first OPEN (one-way up + one-way down): `handle_r2_ctl` does
  `binding.mark_open()` on `FlowAck` `[code dispatcher.rs:993-999]`. The binding is shared (`Arc`) with the
  association's `SessionFlows`, so the next payload takes the 2 B steady path.
- A compressed **downlink** frame is an implicit confirmation too `[code dispatcher.rs:1132-1135]`, so
  request/response flows usually learn confirmation from the reply rather than from `FLOW_ACK`.
- ACK loss is self-healing: the client keeps sending OPEN (new payload each time) and the server
  "re-installs idempotently and re-ACKs" `[code accept.rs:2221-2243; ACK at 2333-2352]`.
**Quantified cost of the 1-RTT window** (IPv4, one continuous flow at `p` payloads per RTT): `12·p` extra
MQP bytes, `p` extra DATAGRAMs/send calls (each Open item is its own frame, `[code r2_stage.rs:475-490]`),
and the loss of same-flow/dict `TRAIN` aggregation for that window. For domain targets: `(9+L)·p` extra
bytes. This is the lever a redesign can remove without touching delivery semantics (see §4 lever L2).

### F4 — Domain targets make the confirmation round trip `DNS + 1 RTT` and hold the first payload on the server. `[code]`

`r2_ingress_open` hands domain OPENs to `r2_forward_domain_open_bg`, which resolves off the datagram loop
(up to `DNS_LOOKUP_TIMEOUT = 5 s`, `[code accept.rs:2051-2167,1292-1370; src/dns/store.rs:100]`), while duplicate OPENs
for the same id queue their (new) payloads: bounded 64 payloads / 256 KiB per open, 16 opens per connection
`[code accept.rs:1103-1121,1290-1370]`. After resolution the *first* payload is forwarded, queued payloads
follow in arrival order, then the binding is installed and `FLOW_ACK` sent
`[code accept.rs:2144-2177]`. So a domain flow pays (a) a server-side DNS hold (possibly the full 5 s on a
cold resolver; a moka hit is sub-ms), and (b) an enlarged compression window. Neither is a client↔server
round trip, but (a) is a genuine payload hold that the client cannot avoid by changing its own wire
behaviour. If a redesign adds any "template/default target" mechanism (lever L6), domain flows are where
it pays most.

### F5 — Auth costs 0 added RTT and ≤256 B. `[code]`

Client: token is written **before** publish `[code auth.rs:386-388,418-447]`; server: `authenticate()` is
called after the handshake and before `handle_conn` starts the datagram reader
`[code src/bin/myquic2-server/main.rs:853-880]`, and its `accept_uni()`+`read_to_end` completes on the same
flight that carries the client's `Finished` (F2 timing). The original briefing fact holds: the token is
1-RTT-shaped and replay-safe, and it adds no RTT. The *only* hidden cost is the pre-auth stream credit
(F6) and the extra uni-stream/packet bytes.

### F6 — Pre-auth bidi credit (4) can park the 5th+ concurrent TCP flow for up to 1 RTT right after a dial. `[derived]`

The server advertises `SERVER_PRE_AUTH_BIDI_CREDIT = 4` and raises it to `MAX_BIDI_STREAMS_PER_CONN = 8192`
only after `authenticate()` returns `[code src/config/tuning.rs:146,161; src/transport/build.rs:246-262,324-326;
src/bin/myquic2-server/main.rs:866-880]`. Timeline: client publishes at 0.5 RTT; server raises credit at
1.0 RTT; the `MAX_STREAMS` frame reaches the client at **1.5 RTT** (one way later). `quinn::Connection::open_bi`
parks on the stream-budget `Notified` when the advertised limit is reached
`[code-dep quinn-0.11.12/src/connection.rs:331-336,696-700]`. A TCP flow that opens between 0.5 and 1.5 RTT
after the dial is the 5th or later concurrent stream → waits up to 1 RTT in `open_bi`
(`socks.rs:169-215` / `forward.rs:279-288`). Narrow window (requires ≥5 simultaneous new flows inside the
first RTT after a dial), low expected frequency, but it is a real MQP/transport-design RTT on the TCP
control path. Raising the pre-auth credit is the obvious fix but increases pre-auth parked-stream memory
(4 → 8 doubles it to ~786 KiB/conn for 1024-span assemblers), so this may be better left documented.

### F7 — `FLOW_ACK` is not needed for correctness and could be removed from the compression path entirely; the SKETCH's "no ACK, repeat inline context" design is RTT-neutral but must handle the all-context-lost case. `[derived]`

Today `FLOW_ACK` exists so the sender knows it may stop repeating `OPEN`. But payload delivery never
depended on it: an OPEN carries its payload, and duplicate OPENs carry *new* payloads
`[code accept.rs:2221-2243]`. A design that stays optimistic ("send steady immediately after the first
context frame for K frames, then steady only") removes the 1-RTT compression window at the cost of a
silent-dead-flow probability ≈ `q^K` per flow, where `q` is the per-DATAGRAM loss probability (all K
context frames lost before the receiver installs the id): a steady frame for an unknown id is dropped and counted `[code accept.rs:1962-1985]`,
nothing tells the sender. Mitigations: periodic re-context (e.g. every 64 frames or on any 200–500 ms idle
gap) or a single low-rate ACK only when the receiver first installs (the current design). This is the main
"fewest round trips" wire decision: **drop or keep the per-flow confirmation**, with the honest caveat
that dropping it saves compression latency/bytes, not delivery latency.

Is it *safe* to compress before an ACK? Yes, with bounded blast radius: both directions already tolerate
frames that name an id the receiver has not installed — the client drops an unknown-id downlink
`DATA`/`TRAIN` item (`[code dispatcher.rs:1095-1107]`; a standalone server-owned `OPEN|SRC` may install
one, a steady frame never can) and the server resolves each `TRAIN` item independently, dropping the ones
whose id has no live binding and forwarding the rest (`[code accept.rs:2497-2515,1978-1985]`). So the
failure mode of an ack-less design is "the payloads sent before the binding frame lands are lost" — a
loss amplification bounded by the re-context interval `K` — never a protocol error, misdelivery or a
stuck connection. The current ACK design converts that bounded loss into an extra 4 B downlink frame per
flow and a 1-RTT compression window; the redesign can trade them explicitly.

### F8 — A lost `CAPS` can tear down a live connection after 2 s; HELLO/CAPS is otherwise off every payload path. `[code + derived]`

`handshake_with` sends HELLO at t=0 and every 200 ms; it returns `false` at 2 s without CAPS or on a wrong
wire version `[code rev2.rs:46-50,473-519]`; the conn loop then closes the connection
`[code auth.rs:98-103]`. All flows on it fail: UDP associations re-OPEN after the redial (~0.5 RTT +
200–400 ms backoff), TCP flows are RST. Nothing in the data path waits on CAPS: the egress cache publishes
a rev2 generation as soon as `set_rev2`+`publish` happen, before HELLO (explicitly documented and tested
`[code egress.rs:415-423; tests.rs:5129-5166]`, comment drift in auth.rs:88-93 and rev2.rs:126-134
notwithstanding — see §7). Lever: retry HELLO with backoff in the background and only fail a connection
that has never completed the exchange *and* has been up for N seconds (or never close it once payload has
flowed). Cost of the current rule: `2 s + backoff + 1 RTT` imposed on every flow of a connection.

Server side of the gate for completeness: every non-HELLO rev2 frame that beats HELLO is stashed in a
bounded per-connection buffer (8 frames / 16 KiB, `PRE_HELLO_MAX_FRAMES`/`PRE_HELLO_MAX_BYTES`) and released
in arrival order once a valid `HELLO(wire_ver=2)` is seen; overflow is counted and dropped, and a wrong
version never opens the gate `[code src/bin/myquic2-server/accept.rs:1047-1053,1103-1104,2645-2709]`.
So the client's optimistic-first-packet contract is real, but the buffer is small: a burst larger than 8
frames that arrives before HELLO loses its tail `[derived]`.

### F9 — UDP payloads are dropped, not queued, whenever no egress connection exists. `[code]`

`send_payload_uplink` → `with_fresh` miss → `acquire`; on `None` it books `NO_EGRESS` and returns
`[code assoc.rs:469-513]`. The association's relay loop still consumes the datagram (test:
"the first datagram takes the counted NO_EGRESS path" `[code tests.rs:4161-4177]`). There is **no waiting
room anywhere** — not per association, not per egress class. This affects: process cold start (before the
first publish), every dial after a death (egress invalidated by `retire_dead_slot` `[code auth.rs:286-301]`),
and the whole 40 s blackhole window. A bounded hold (e.g. a small per-association ring with a 100–500 ms
deadline, or one "first datagram" slot per flow) would convert a one-shot request's multi-second
application timeout into ≤1 RTT + backoff of added latency; stale delivery is the trade-off, and UDP
semantics make it a policy decision, not a correctness one. Note the same applies to `udp_forward` peers
`[code forward_udp.rs:645-669]`.

### F10 — The interactive UDP class is a single fail-closed connection, and it carries DNS/STUN/games. `[code]`

`udp_class` classifies by port (53/123/3478-3481 default interactive `[code client_conf.rs:302-306]`) or
first payload ≤512 B `[code pool.rs:721-748]`; `udp_class_slots(Interactive) = 0..1` and the default
`udp_fail_closed = true` means the egress scan stops after that one slot
`[code pool.rs:676-682,697-719; egress.rs:317-348; client_conf.rs:318-323]`. If the interactive UDP
connection is down/blackholed (one of 7 dial loops), *all* DNS/STUN/game datagrams are dropped with
`NO_EGRESS` until its redial publishes. This is by design (isolation from TCP and bulk) but it is the
single largest user-visible latency/hairpin on the client. Levers: a per-association hold (F9), a
"warm spare" interactive UDP connection (N+1), or class-aware fail-over after a stale gate (would break
the strict UDP/TCP isolation contract only during an outage; `udp_fail_closed=false` exists as an operator
escape hatch `[code egress.rs:300-348]`).

### F11 — Blackhole detection is a 40 s watchdog; the protocol has no active liveness probe of its own. `[code + derived]`

The reconnect loop force-closes when `udp_rx.datagrams` is frozen for `watchdog_silence = 2/3 × idle` =
40 s (default) or when ACKs stall while we keep sending
`[code auth.rs:104-192; src/transport/build.rs:167-183]`, sampled every 1 s (`WATCHDOG_POLL`).
`data_stale_threshold_ms = (keepalive + watchdog)/2 = 22.5 s` only steers *new TCP flows* away
`[code pool.rs:431-441,816-868]` — and only for a slot that still *looks* live; a slot with a populated
`close_reason()` is re-picked at once by `holds_dead_handle` `[code pool.rs:848-856]`. The UDP egress
cache's stickiness only checks `close_reason()` and
`max_datagram_size()` `[code egress.rs:384-402]` — a blackholed-but-open connection keeps being used for
up to 40 s. MQP does not define a ping. Lever: a CTL probe (e.g. `HELLO`-like `PING`, or reuse the
existing ACK machinery) when no rx progress for 2–3 × keepalive (10–15 s) would let the client close and
redial far earlier; keeping the watchdog below quinn's idle timeout remains the invariant. This is a
seconds-scale lever, not an RTT one, but it dominates every reconnect path.

The 5 s keepalive itself is only the NAT-refresh cadence and never contributes a user-visible RTT; it is
not a liveness probe (the watchdog's ACK-progress detector is the only use of its acknowledgements)
`[code src/transport/build.rs:392-393; auth.rs:104-192]`.

### F12 — Reconnect backoff and its reset semantics. `[code]`

`reconnect_backoff()` = 200 ms min, ×2, capped at 5 s, infinite, with caller-added 0–200 ms jitter
`[code auth.rs:21-28]`; after a death the loop resets the iterator only if the dead connection lived ≥5 s
`[code auth.rs:223-228]`. So: first redial after a long-lived connection fails = 200–400 ms; repeated
dial failures walk 0.2→·→5 s (+0–200 ms), i.e. steady-state redial every 5.0–5.2 s. This is *not* RTT but
it adds directly to every cold UDP/TCP flow's latency after a failure, and it interacts with F9 (datagrams
dropped during the whole backoff+handshake window).

### F13 — The client's own trust in the session is only as good as `SESS_CLOSE`; there is no per-flow liveness signal. `[code + derived]`

Client uplink uses `take_session_closed()` to learn that the server reaped its session and must re-OPEN
`[code rev2.rs:687-704; dispatcher.rs:1033-1052]`. The server sends that close 3× best-effort when it reaps
a session `[code accept.rs:1520-1580,2808]`. If all 3 are lost, the client keeps sending steady frames for
an id the server no longer has; the server drops them silently (unknown id) and never re-notifies, so the
flow is blackholed until the app times out. The symmetric client→server direction (F18) has the same hole, but the
server's 180 s idle sweep is the backstop for its resource half. A wire redesign that removes `FLOW_ACK` (F7) should either make this
failure mode per-flow observable or accept "silent blackhole until app timeout" explicitly. `[estimate]`
with 2 % loss, 3 independent copies → 8·10⁻⁶ per reaped session; small, but unbounded in duration when it
happens.

### F14 — 0-RTT is unused today; the actual saving it could offer is 0.5 RTT, not 1 RTT. `[code + derived]`

Mechanism is ready end-to-end: client `enable_early_data = true` `[code src/tls/client_cfg.rs:5-19]`,
server `max_early_data_size = u32::MAX` with stateful single-use tickets
`[code src/tls/server_cfg.rs:20-35]`, client `into_0rtt()` `[code auth.rs:372]`, server 0.5-RTT accept
`[code server main.rs:798-808]`. But: (a) `dial_once` awaits `accepted_fut` before publish, (b) the token
is deliberately 1-RTT `[code auth.rs:357-365]`, and (c) no stream/datagram is opened before publish, so
**no early-data packet carries application bytes**. Derivation in §1.2: even if datagrams were queued in
0-RTT they could not be forwarded before the token arrives at 2d, so the gain is zero unless auth moves to
early data. Sending the *token* in 0-RTT would enable server auth at 1d (forward at 1d): **saves 0.5 RTT
on every resumed dial** for both the first UDP forward and the server-side target-dial start of TCP flows.
The existing client comment correctly identifies the replay risk `[code auth.rs:357-365]`; a redesign
should decide explicitly between (i) token in 0-RTT with single-use-ticket + replay-cache mitigations,
(ii) ticket-as-auth (bind "authenticated" state to the resumption secret/ticket identity so resumption
itself is the credential), or (iii) full handshake only for auth (status quo, 0 saving). Note also that
0-RTT cannot help a *first-ever* connection (no ticket): the full-handshake cold start stays 1 RTT to the
server.

### F15 — TCP is already RTT-optimal on the client; there is no MQP interaction per payload. `[code]`

`handle_socks` writes the target header as its own flush **before reading app bytes**, sends the optimistic
SOCKS success, then starts the pump `[code socks.rs:216-272]`. The target's first reply is the only
latency: `client→server` one-way + `server→target` RTT + `target→server` one-way + `server→client` one-way,
i.e. the proxy-inherent cost. The MQP dial ACK (11 B IPv4 / 23 B IPv6 `[code src/mqp/ack.rs:41-49;
src/lib.rs:675-709]`) is written by the server immediately after connect and before any target bytes
`[code src/bin/myquic2-server/tcp.rs:182-206]`, and the client's c2s pump is deliberately not gated on it
`[code src/tcp/pump.rs:47-61,495-569]`; only the s2c direction waits (25 s budget), and only as a failure
signal `[code pump.rs:371-392; src/bin/myquic2-client/socks.rs:4-7,265-271]`. Forward mode drops the SOCKS
negotiation entirely and is identical `[code forward.rs:263-307]`.

### F16 — The SOCKS/TCP optimistic reply is already one step more optimistic than the QUIC pool. `[code]`

SOCKS success is sent after `open_bi`+header write but **before** the server dial ACK
`[code socks.rs:246-264]`; it is *not* sent before `wait_conn`, so a cold/redialing slot still delays the
app's SOCKS reply by up to 0.5 RTT (usually) or up to 5 s (slot between dials)
`[code socks.rs:151-168]`. If the redesign wants the last 0.5 RTT on the cold-TCP path, the SOCKS success
must be decoupled from connection availability and app bytes buffered until a stream exists; failure then
becomes an RST after success (the forward-mode contract already does exactly this
`[code forward.rs:236-241,315-322]`). This trades a truthful immediate `REP=0x04` for a hidden RST, so it
needs an explicit product decision.

### F17 — `FLOW_CLOSE` never goes on the wire; per-flow retirement is unimplemented. `[code]`

Both endpoints decode and handle `CTL FLOW_CLOSE` `[code dispatcher.rs:1016-1029; accept.rs:1862-1882]`, but
no production call site encodes/sends one (the only `encode_ctl(&Ctl::FlowClose…)` is a unit test at
`src/mqp/r2.rs:1306`). Flows die only with their session (`SESS_CLOSE`) or the connection. Consequences:
(a) a long-lived association that talks to more than 64 distinct targets fills `SessionFlows`
(`R2_MAX_FLOWS_PER_SESSION = 64`, `[code r2_flow.rs:36,240-247]`); `flows.is_full()` then routes every **new**
target to `INLINE` (13 B/payload, no binding, no TRAIN, no ACK) `[code rev2.rs:1069-1071]`, and the server
keeps reverse-table entries for unused targets; (b) the README/spec "FLOW_CLOSE on flow retirement"
statements (`README.md` §5/§10, `MQP3_REV2_SPEC.md` §3.4) describe a behavior that does not exist. For a
rev3 wire this is a decision point: keep session-scoped flow lifetime (then never define FLOW_CLOSE) or add
a real per-flow retirement/expiry that both ends honour.

### F18 — Loss of a server `SESS_CLOSE` can silently blackhole a session (no per-flow liveness). `[code + estimate]`

See F13 for the server→client direction; symmetric for client→server: the client's best-effort 3×
`SESS_CLOSE` `[code rev2.rs:600-619]` is skipped when `!rev2.is_ready()` `[code rev2.rs:606]`, so an
association that exits inside the handshake window leaves the server session to the 180 s idle sweep.
No RTT, but worth fixing in a redesign that claims bounded state.

### F19 — Doc/comment drift that would mislead the redesign. `[code]`

- `src/bin/myquic2-client/auth.rs:88-93` claims "the egress cache refuses to publish a connection until
  [CAPS]". False: `egress.rs:415-423` says the opposite and the code publishes the generation as soon as
  `set_rev2`+`publish` happen (test `egress_publishes_before_caps_for_optimistic_first_packet`,
  `tests.rs:5129-5166`).
- `src/bin/myquic2-client/rev2.rs:126-134` says "the reconnect loop **and the egress cache** read
  `is_ready()`"; the egress cache never calls it (only `send_sess_close` does, `rev2.rs:606`).
- `README.md:265` and §10 claim "`FLOW_CLOSE` on flow retirement"; no sender exists (F17).
- `README.md:266` ("ACK unlocks the 2 B steady path") is accurate, but the docs should add that an
  ACK loss costs one more RTT of extended headers, not a retry (the client keeps sending OPEN).

### F20 — Redundant / duplicated interactions (byte and send-call, not RTT). `[code]`

| Interaction | Cadence today | Redundancy |
|---|---|---|
| `CTL HELLO` | 1 at publish + every 200 ms until CAPS, ≤2 s | one HELLO is enough; the retries only matter under loss. 8 B each. |
| `CTL CAPS` | ≤1 per 100 ms per connection `[code accept.rs:820-834]` | 17 B of which `max_conn_flows`/`max_flows_sess` are compile-time constants and ignored for enforcement (`MQP3_REV2_SPEC.md:97-101`); only `max_train_items`/`max_frame_bytes` are consumed `[code rev2.rs:217-232]`. |
| Duplicate `DATA OPEN` | one per payload while `Opening` | by design carries a new payload, but repeats a 14 B / `11+L` header per payload instead of 2 B. |
| `FLOW_ACK` | one per install, **re-ACK per duplicate OPEN** `[code accept.rs:2221-2243]` | up to `p` ACKs per opening window; also redundant with the implicit downlink ACK. |
| `SESS_CLOSE` | 3× on association exit `[code rev2.rs:609]` | no ack; 21 B per exit; necessary only because CTL is unreliable. |
| `FLOW_CLOSE` | never sent | dead opcode (F17). |
| `HELLO` from server | ignored `[code dispatcher.rs:1053-1055]` | harmless. |
| Auth token | once per connection, ≤256 B + FIN | fine; could be merged into the first CTL/HELLO frame to save a packet, but not an RTT. |

### F21 — `DATA OPEN` repeats include the full `u32 session` (4 B) and the full address; the first frame is the most expensive frame per flow and it is *more* expensive than INLINE for one-shot flows. `[derived]`

`OPEN` = `2 + varint(id) + 4 + addr` vs `INLINE` = `2 + 4 + addr`; IPv4: 14 B vs 13 B, and `OPEN` also
costs a 4 B `FLOW_ACK` from the server and a server-side binding slot. Break-even vs `INLINE` for an
IPv4 uplink-only flow (`18 + 2n` vs `13n`) is `n ≥ 2` payloads `[derived]`; for domain flows
(`15+L + 2n` vs `10+L` per payload) similar. So the client's unconditional "new target ⇒ bind" policy is
byte-negative for one-shot targets (DNS-over-SOCKS qps, `udp_forward` peer churn), though it enables TRAIN
and compression later. A redesign might make binding conditional on a second payload (cost: first payload
INLINE, second OPEN — still one extra header) or keep a per-connection "default target" (lever L6) so
one-shot flows can be steady immediately.

### F22 — 0-RTT datagrams are legal on the wire but currently impossible to exploit; if the Lead wants them for the *local* drop-window, queue-until-publish is strictly simpler. `[code + web]`

RFC 9221 §3 explicitly permits DATAGRAM frames in 0-RTT packets
(<https://www.rfc-editor.org/rfc/rfc9221.txt>), and quinn-proto's remembered-transport-parameters handling
means `send_datagram` works before the handshake completes
`[code-dep quinn-proto…connection/mod.rs:2059-2094, 3352-3363, 3770-3790]`. But as derived in §1.2,
the server's auth gate nullifies the end-to-end gain. The local benefit (datagrams produced in the 0…0.5 RTT
window are not dropped) is achieved more simply and replay-safely by a bounded queue that flushes on
publish (F9). Do not build 0-RTT data-plane plumbing unless auth moves to early data.

---

## 4. RTT-reduction opportunities

RTT column = user-visible round trips removed; "compression window" = the 1-RTT window of degraded
encoding. All are wire/software levers; backward compatibility is not required (per the brief).

| # | Lever | RTT / bytes saved | Risk | Complexity |
|---|---|---|---|---|
| L1 | **0-RTT auth** (token in early data, or bind auth to the resumption ticket/PSK identity; keep single-use stateful tickets + optional replay cache) | **0.5 RTT on every resumed dial** (first UDP forward at 1d vs 2d; TCP target-dial start at 1d vs 2d); 0 on first-ever dials. Bytes: token packet moves earlier, same size | Replay of the bearer token inside the ticket window; single-use tickets narrow but do not close the race; a proxy credential replay is worse than a duplicated HTTP request. Needs an explicit security sign-off. | High (server TLS/auth integration; rustls does not expose ticket identity→auth-state hooks today) |
| L2 | **Drop `FLOW_ACK` from the compression path**: after the first `OPEN`, immediately use steady frames and `TRAIN`; repeat the OPEN context every K frames (e.g. K=16) and/or after every idle gap; drop `FLOW_ACK`/`FLOW_REJECT` to a low-rate hint | Removes the 1-RTT compression window: for `p` payloads/RTT saves `12p` B (IPv4) / `(9+L)p` B (domain) and up to `p−1` DATAGRAMs/send-calls; user-visible RTT saved: **0** (compression only) — but it removes the only MQP round trip | All-context-lost flow silently blackholes (P≈q^K, q = per-DATAGRAM loss); a steady frame for an unknown id is already dropped safely `[code accept.rs:1962-1985]`. Mitigate with periodic context re-send. Also removes the server's re-ACK traffic (4 B/flow + duplicates) | Medium (client uplink policy + stager; server already tolerates unknown-id steady frames; remove/keep FLOW_ACK) |
| L3 | **`OPEN+TRAIN` compound frame** (one frame = context + up to 64 payloads for the same flow/session) | Opening burst becomes 1 DATAGRAM instead of `p`; saves `(p−1)·(packet overhead + 12 B)` and `p−1` send calls; RTT 0 | Loses the whole burst if the DATAGRAM is lost (same as a lost TRAIN); frame is larger (fragmentation interaction) | Medium (codec + stager + server ingress) |
| L4 | **Bounded queue-until-publish for UDP** (per-association ring or one first-datagram slot, e.g. 4 datagrams / 200 ms; flush on generation publish; drop on generation change or age) | Converts a **multi-second app retry** (DNS resolver timeout) into `backoff + 1 RTT`; RTT saved: **0**, but user-visible saved for one-shot flows can be seconds. Also useful for `udp_forward` | Stale delivery after a path change; keep the deadline short and count the drops. UDP semantics leave this to policy | Medium (association state + epoch flush; there is already a stager to reuse) |
| L5 | **Faster failure detection**: active CTL probe when no rx progress for 2–3× keepalive (10–15 s), instead of the 40 s watchdog; or lower watchdog to ~3×keepalive | Saves up to **~25 s** of blackhole/drop window on every path failure (not RTT) | False positives on long handovers/loss bursts; must stay below quinn's idle timeout and above a healthy-idle stamp age (the `data_stale` derivation already proves that midpoint) | Low (reuse `HELLO`-shaped CTL + ACK, or reuse existing ACK stats; watchdog is already a tunable formula) |
| L6 | **Connection-scoped default/template target**: a CTL frame registers `(template_id → target)` once per connection; `udp_forward` peer sessions (fixed target per listener) start with a compact frame carrying `sess`+`template_id`+payload (≈5–6 B header instead of the 14 B OPEN); no per-flow OPEN/ACK needed | Removes `14 B/flow` OPEN + `4 B/flow` ACK + the 1-RTT window for every new forward peer session (DNS churn: one query = one session); forward-mode flows can be steady/TRAIN from payload 1. RTT 0 | Server must scope templates to the authenticated connection and expire them; target policy is still applied at the exit; a compromised client could name any registered template (same power as OPEN, so no new capability) | Medium (new CTL opcode + server table + client forward path) |
| L7 | **Don't tear down a live data connection for a missing CAPS**: keep sending HELLO with backoff, fail only connections that never completed the exchange *and* carried no data (or after a much longer cap) | Removes a rare but total **1 RTT + 0.2–0.4 s + 2 s** redial penalty for every flow on a connection whose CAPS was lost >2 s | A genuinely non-rev2 peer would keep a connection alive that the client can't use — but data would already be failing; bounded by the watchdog | Low |
| L8 | **Merge HELLO into the first data frame / server-unsolicited CAPS**: server sends CAPS right after auth without waiting for HELLO; client may drop HELLO entirely if ALPN/version encodes rev2 | Saves 8 B up + 17 B down per dial and one 200 ms retry loop; RTT 0 | Version gate becomes ALPN-only; still fail-fast (no old-wire fallback needed per brief) | Low |
| L9 | **Per-flow close / expiry** (actually send `FLOW_CLOSE`, or define flow TTL): not an RTT lever; frees table slots so new targets keep binding (which keeps steady/TRAIN instead of falling back to INLINE after 64 targets/session) | Bytes: avoids INLINE fallback (13 B vs 2 B per payload) after table pressure; RTT 0 | Reintroduces a frame that both ends decode; must be idempotent and rate-limited | Low |
| L10 | **Pre-auth stream credit**: raise 4 → e.g. 16, or have the client delay only 5th+ TCP stream opens until `MAX_STREAMS` arrives | Removes up to **1 RTT** `open_bi` park for the 5th+ concurrent TCP flow inside the first RTT after a dial | Doubles/quadruples pre-auth parked-stream memory (4 streams ≈ 393 KiB → 16 ≈ 1.5 MiB per conn worst case at 1024 spans×96 B); the pre-auth cap exists for exactly that DoS | Low/Medium |
| L11 | **Reduce `SESS_CLOSE` ×3 → ×1** + rely on idle sweep / piggyback on next CTL | Saves 14 B per association exit; RTT 0 | Loss window grows from p³ to p for delayed reclamation; idle sweep is 180 s | Trivial |
| L12 | **One-shot targets should use INLINE, not bind** (client policy, no wire change): if the association is unlikely to send a second payload, INLINE is 13 B vs OPEN 14 B + ACK 4 B + server slot | Saves `5 B`/one-shot IPv4 flow now; under `udp_forward`-style churn it also saves a server binding. RTT 0; disabling ACK-wait for those flows removes no wait | Heuristic; after 2 payloads binding wins on bytes, and INLINE can never TRAIN | Trivial |

**What cannot be removed:** the first frame must carry the target address (or a template/association
handle — L6 is the only real way around that); a cold dial's 0.5 RTT publish and 1 RTT to server-visible
data are TLS-1.3/QUIC-inherent; the server→target and target protocol RTTs are proxy-inherent.

---

## 5. Assumptions and uncertainties

1. **Timing model assumes no loss/reordering on the handshake flight.** With packet loss, the "1 RTT to
   server-visible data" becomes PTO-driven (the transport seeds `initial_rtt = 190 ms` by default
   `[code src/transport/build.rs:358-366]`, so the first PTO is ~435–575 ms `[estimate]`). A measured
   audit should include loss cells.
2. **The `d`/publish timing relies on rustls 0.23.46/quinn 0.11.12 internals** (server `Finished` →
   `start_traffic` → quinn `Connected`). If either crate is upgraded, re-verify §1.1. I did not run traces.
3. **I did not run any benchmark or binary** (hard rule). Every ARQ/latency figure is derived from code.
4. **Server-side queuing/lock costs are assumed non-latency-adding** except where cited (DNS hold, FLOW_ACK
   ordering). I did not audit the server's scheduler for queueing delay under saturation.
5. **The 40 s watchdog figure is the default** (`idle_timeout_secs` unset → 60 s → 2/3 = 40 s). Deployments
   that set `idle_timeout_secs` or `keep_alive_secs` move this linearly; `data_stale_ms` moves with it.
6. **0-RTT availability depends on rustls' client session cache and ticket lifetime**; the first dial of a
   process is always a full handshake. I did not verify cache sizing/eviction for the client store
   (server store is 8192, `[code src/tls/server_cfg.rs:20-24]`).
7. **`udp_fail_closed`/`udp_split`/`interactive_ports` are defaults**; operator configs can change the
   single-point-of-failure analysis in F10.
8. **The rev3 wire sketch** (`analysis/rev3/wire_model.py`: 1-byte header, no HELLO/CAPS, no per-flow
   FLOW_ACK, inline OPEN repeats) was in progress while this audit was written. This report evaluates it
   only on the RTT axis (F7/F14): it removes the only MQP round trip, but that round trip was never on the
   payload path; its measurable RTT gain is 0, its byte/send-call gain is real, and its only RTT lever is
   L1. If the sketch also changes auth to be TLS-bound/0-RTT-capable, that is where its 0.5 RTT comes from.
9. **Fragment path:** I did not re-derive per-fragment RTT (FRAG has no ACK and no reassembly feedback);
   its only RTT-relevant aspect is the same OPEN context on the first fragment (`R2FragFlow::Opening`,
   `[code rev2.rs:935-951; r2.rs:733-798]`).
10. **Full-cone/server-owned flows** (opt-in `udp_full_cone`) mirror the domain/rebind analysis
    (`OPEN|SRC` + client `FLOW_ACK`, `[code dispatcher.rs:1125-1131; src/mqp/r2_flow.rs:325-377]`);
    I did not audit the server's full-cone admission path.

---

## 6. What to measure to confirm (suggestions for the Lead)

All of these already exist; no code changes needed:

1. **`lattcp`** (`examples/hotpath_bench.rs`, per-iteration SOCKS CONNECT + first echo) — splits
   `connect µs` from `echo µs` p50/p90/p99; run under `tc netem` 70/140 ms
   (`scripts/linux-bench-matrix.sh:85-95`). Expected: CONNECT is loopback-local (no server RTT) when warm;
   the `echo` number contains the target RTT. This directly tests F15/F16 and the cold-start publish wait
   if run immediately after client start.
2. **`lat`** (serial UDP request/reply, one association) — the cleanest end-to-end RTT measurement for
   steady UDP; run warm vs immediately after a client start, and while the interactive UDP slot is
   deliberately killed (e.g. `tc netem loss 100%` on that connection's path, or kill the server's view of
   one conn) to measure F9/F10 loss-and-retry behavior.
3. **`udpdomain` / `udpdomainswitch`** — measures the DNS hold + rebind path (F4); compare cold cache vs
   warm cache to separate `DNS` from `FLOW_ACK` latency. `udpdomainswitch` is the rebind cadence test.
4. **`udpmulti` / `udpfanout` / `udpbidir`** — with an instrumented client, count `open_tx`, `via` the
   60 s reporter's `Rev2Counters` (`rev2.rs:1191-1240,1379-1469`), to measure frames-per-payload and confirm the
   `Opening`-window aggregate overhead (F3): expected ratio improves only after ~1 RTT.
5. **`frame_bench`** — byte-level check of `OPEN` vs steady header sizes and the `OPEN+TRAIN` proposal;
   combine with `analysis/rev3/wire_model.py` for the rev3 sketch.
6. **Add a "first datagram" probe** (not present): `lat`-style but sending one datagram immediately after
   UDP ASSOCIATE, repeated N times, and report the fraction that never get a reply (expected = the fraction
   of tries landing in the publish/reconnect window). This is the only direct measurement of F9/F10.
7. **Reconnect timing probe**: kill the server process (or `iptables -j DROP` one connection) and record
   time-to-first-delivered-datagram for `lat` (expected ≈ 40 s watchdog default; count the NO_EGRESS
   drops in the reporter) — confirms F11/F12 and the value of lever L4/L5.
8. **HELLO/CAPS loss stress**: on netem with 2 % loss, run hundreds of dials and count
   `handshake_fail` (`rev2.rs` counters) vs successful conns; confirms the 2 s teardown risk in F8.
9. **Auth/0-RTT trace**: `RUST_LOG=quinn=debug,rustls=debug` on a client restart, plus server logs, to
   confirm the token and first datagrams are in the same flight (F5) and that no early data is sent
   (`QUIC resumption: 0-RTT accepted=…` debug line exists at `auth.rs:379`).
10. **Stream-credit stall**: 10 parallel `lattcp` CONNECTs issued immediately after a fresh client start /
    slot restart; look for a latency tail in the first 5 (pre-auth credit = 4) vs the rest (F6).

---

## 7. Contradictions with the briefing facts / doc-vs-code drift

The briefing's facts check out, with four corrections/refinements and one stale-comment trap:

| Briefing claim | Verdict | Evidence |
|---|---|---|
| Auth = bearer token on a 1-RTT uni stream after the handshake; `send_auth_stream` ~412-446 | **Confirmed**, exact lines `auth.rs:418-447`; called at `:386-388` (0-RTT path) and `:400-402` (full path) | `[code]` |
| Server calls `authenticate()` before processing any datagram | **Confirmed**: server main loop `authenticate()` at `main.rs:853-865`, then `handle_conn` at `:880`; `handle_conn` spawns the datagram reader at `accept.rs:2841-2847` | `[code]` |
| `dial_once` uses `into_0rtt()` but awaits `ZeroRttAccepted` and publishes after the token write; no app early data | **Confirmed** (`auth.rs:372-409`), with the refinement that the publish wait is **0.5 RTT, not 1 RTT** (`Connected` fires after the server Finished; §1.1) and the 0-RTT opportunity is **0.5 RTT, not 1 RTT** (only realizable with early auth) | `[code + code-dep + derived]` |
| FLOW_ACK confirms a binding and unlocks compressed steady frames | **Confirmed**, plus: any compressed downlink frame is also an implicit ACK (`dispatcher.rs:1132-1135`), and loss of FLOW_ACK self-heals via duplicate-OPEN re-ACK (`accept.rs:2221-2243`) | `[code]` |
| HELLO/CAPS negotiate limits over CTL datagrams but data may flow before CAPS | **Confirmed on the client**: the egress cache publishes the generation before CAPS; CAPS is not a data gate (`egress.rs:415-423`, `tests.rs:5129-5166`). **Note the stale comment** in `auth.rs:88-93` claiming the opposite, and `rev2.rs:126-134` claiming the egress cache reads `is_ready()` | `[code]` |
| SOCKS5 TCP replies are optimistic | **Confirmed** (`socks.rs:246-264`), but only after `wait_conn` — so a cold/redialing slot still delays the SOCKS reply (`socks.rs:154-168`) | `[code]` |

Additional drift found (F17/F19): `FLOW_CLOSE` is a dead opcode (decode-only, never sent);
`MQP3_REV2_SPEC.md:97-101` states `CAPS.max_conn_flows`/`max_flows_sess` are reserved/not enforced — the
client stores CAPS but only uses `max_frame_bytes`/`max_train_items` (`rev2.rs:217-232`), so 12 B of the
17 B CAPS body are informational.

---

## 8. Decisive code quotes (verbatim, trimmed only with `…`)

**No MQP wait on the client uplink.** `send_uplink` chooses a standalone frame until confirmed, then stages;
there is no await:
```rust
// src/bin/myquic2-client/rev2.rs:778-790
    if payload.len() <= BATCH_SMALL_MAX {
        let kind = if binding.is_open() {
            R2StageKind::Steady { wire_id: binding.wire_id }
        } else {
            R2StageKind::Open { wire_id: binding.wire_id, sess, addr: addr.into_owned(), src: false }
        };
```
```rust
// src/bin/myquic2-client/rev2.rs:281-287 — drain_stage → drain_staged → try_send_datagram (sync)
    pub(crate) fn drain_stage(&self, conn: &quinn::Connection, limit: usize) -> R2DrainOutcome {
        drain_staged(conn, &self.stager, limit, || { … })
    }
```

**`Open` items are standalone by construction:**
```rust
// src/udp/r2_stage.rs:18-23
//! * [`R2StageKind::Open`] — the first frame of an opening flow: carries
//!   `sess + addr`, must be sent standalone (`DATA OPEN`).
//! * [`R2StageKind::Inline`] — the no-flow fail-safe: standalone `DATA INLINE`.
//!
//! `Open`/`Inline` items break a train run (they are self-describing frames,
//! not train items); ordering inside one session is preserved because each
```

**Server forwards before it installs/ACKs:**
```rust
// src/bin/myquic2-server/accept.rs:2142-2155
    // … Forward them now, in arrival order, before the install/ACK.
    udp_try_send(&sock, map_for_dual(dst), payload);
    for queued in pending.take_queued() { … udp_try_send(&sock, map_for_dual(dst), queued); }
    match r2_install(&state, &ss, sess, id, TargetAddr::Domain(host, port), usable) {
        Ok(_) => { r2_stats::bump(&r2_stats::OPENS); r2_send_ctl(&cd, &Ctl::FlowAck { … }); }
```

**Client applies FLOW_ACK asynchronously, and any compressed downlink frame also confirms:**
```rust
// src/bin/myquic2-client/dispatcher.rs:993-997
        r2::Ctl::FlowAck { id, .. } => match rev2.registry.get(id) {
            Some(binding) => { binding.mark_open(); counters::flow_ack_rx(); }
            None => counters::rx_unknown_id(),
        },
```
```rust
// src/bin/myquic2-client/dispatcher.rs:1132-1135
    // Any compressed downlink proves the server installed this id: that is the
    // implicit ACK the uplink waits for (a pure-uplink flow otherwise relies on
    // `CTL FLOW_ACK`).
    binding.mark_open();
```

**0-RTT is offered, awaited, and only then authenticated + published (no early app data):**
```rust
// src/bin/myquic2-client/auth.rs:372-388
    let conn = match connecting.into_0rtt() {
        Ok((conn, accepted_fut)) => {
            let token = auth_token.to_owned();
            let accepted = match tokio::time::timeout_at(deadline, accepted_fut).await { … };
            tracing::debug!("QUIC resumption: 0-RTT accepted={accepted}");
            if !ensure_dialed_alive(&conn).await { … }
            // 1-RTT only: the established connection's keys are fresh per
            // handshake, so a captured token can never be replayed into a new
            // connection the way captured early data could.
            if !token.is_empty() { send_auth(&conn, &token, deadline).await?; }
            conn
        }
```
```rust
// src/bin/myquic2-client/auth.rs:68-77 (publish happens only after dial_once returns)
            match dial_once(&ep, &cfg, server, &sname, &auth).await {
                Ok(conn) => { … let rev2 = ConnRev2::new(); slot.set_rev2(rev2.clone()); slot.publish(&conn); … }
```

**Server authenticates before it ever reads a datagram, and only then raises stream credit:**
```rust
// src/bin/myquic2-server/main.rs:853-880
            if let Err(e) = authenticate(&conn, &auth_token, tokio::time::Instant::now() + AUTH_TIMEOUT).await {
                … conn.close(0x01u32.into(), b"unauthorized"); return;
            }
            …
            conn.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(MAX_BIDI_STREAMS_PER_CONN));
            if let Err(e) = handle_conn(conn, allow_private, reply_filter, conn_limit_for_conn, cap).await
```
```rust
// src/bin/myquic2-server/auth.rs:30-35
        let mut uni = conn.accept_uni().await?;
        uni.read_to_end(AUTH_TOKEN_MAX_BYTES).await.map_err(anyhow::Error::from)
```

**CAPS is not a data gate on the client (and the comment in auth.rs:88-93 is stale):**
```rust
// src/bin/myquic2-client/egress.rs:415-422
                // A rev2 generation is usable for UDP as soon as its state is
                // published, **before** `CAPS`: the first payload is sent
                // optimistically instead of waiting one HELLO/CAPS RTT. The
                // server keeps the version gate authoritative by buffering
                // these frames until a valid HELLO arrives, then flushing them;
                // `CAPS` only updates the negotiated caps and the compression
                // limits. …
```

**UDP with no egress is dropped, never queued:**
```rust
// src/bin/myquic2-client/assoc.rs:487-509
                None => {
                    // No isolated egress connection right now: …
                    let n = dgram_drops::bump(&dgram_drops::NO_EGRESS);
                    dgram_drops::warn_egress_drop(dgram_drops::EgressDrop::NoConnection, n, || { … });
                    return;
                }
```
```rust
// src/config/client_conf.rs:318-323
    /// Whether UDP egress is confined to its dedicated connection. Default
    /// `true`: a datagram that has nowhere isolated to go is dropped and
    /// counted, rather than queued behind TCP traffic on a shared connection.
    pub fn udp_fail_closed(&self) -> bool { self.udp_fail_closed.unwrap_or(true) }
```

**SOCKS success is optimistic but still behind `wait_conn`:**
```rust
// src/bin/myquic2-client/socks.rs:246-252
    // Optimistic SOCKS success: the application's first bytes must not be
    // serialized behind the server-side dial. Waiting for the MQP-2 ACK here
    // costs one full client<->server RTT on every connection … a failed dial
    // tears the TCP flow down instead of returning a SOCKS error.
```

**Downlink rebind keeps re-sending `OPEN|SRC` until the peer ACKs (the downlink 1-RTT window):**
```rust
// src/mqp/r2_flow.rs:317-323
    /// A learned source is only `Exact` once the peer confirmed the binding
    /// frame (`FLOW_ACK`) or when the binding's target *is* that source …
    /// Otherwise the frame must be re-sent as
    /// `OPEN|SRC`: QUIC DATAGRAMs are unreliable and a lost binding frame
    /// would otherwise leave every later steady frame for this flow
    /// undeliverable forever.
```

**Stale-gate formula (TCP new-flow steering only):**
```rust
// src/bin/myquic2-client/pool.rs:440
    (keepalive + watchdog_secs) / 2 * 1_000
```

---

## Appendix A — frame/byte sizes used in this report

| Object | Bytes (id < 128, IPv4) | Source |
|---|---:|---|
| `DATA` steady | 2 (`1 + varint(id)`) | `[derived r2.rs:275-277,172-179]` |
| `DATA OPEN` | 14 (`2 + 1 + 4 + 7`) | `[derived r2.rs:280-283]` |
| `DATA INLINE` | 13 | `[derived r2.rs:286-288]` |
| `DATA OPEN` domain | `11 + L` (L = name length) | `[derived; AddrHeader domain = 4+L]` |
| `DATA INLINE` domain | `10 + L` | `[derived]` |
| `CTL FLOW_ACK` | 4 (`0x0C,0x10,id,status`) | `[derived r2.rs:906-912,944-948]` |
| `CTL FLOW_REJECT` | 4 | `[derived r2.rs:910-911,949-953]` |
| `CTL FLOW_CLOSE` | 3 | `[code r2.rs:911,954-957]` (never sent) |
| `CTL SESS_CLOSE` | 7 (`kind, op, u32 sess, reason`) | `[code r2.rs:912,958-962]` |
| `CTL HELLO` | 8 | `[code r2.rs:907,927-932]` |
| `CTL CAPS` | 17 | `[code r2.rs:908,933-943]` |
| Steady `DATA` after 64 flows on a conn | 3 (`varint(wire_id)` = 2 B) | `[derived r2.rs:172-179; r2_flow.rs:744-780]` |
| TCP target header | 7 IPv4 / 19 IPv6 / `4+L` domain | `[code src/mqp/addr.rs:52-74]` |
| MQP TCP dial ACK | 11 IPv4 / 23 IPv6 (`3 + atyp + addr`) | `[derived src/mqp/ack.rs:41-49; lib.rs:680-708]` |
| Auth token | ≤256 B (`AUTH_TOKEN_MAX_BYTES`) + stream FIN | `[code src/mqp/ack.rs:54]` |
| QUIC per-packet overhead (IPv4, one DATAGRAM frame) | ≈57–58 B (IP 20 + UDP 8 + short header/PN 1+8+16 + DATAGRAM 1 + len 1–2) | `[derived; cf. analysis/rev3/wire_model.py:4-22]` |

## Appendix B — derivation of the key numbers

- **Publish latency**: 1 one-way (`d`) = 0.5 RTT → `auth.rs:372-409` + rustls `ExpectFinished` timing (§1.1).
- **Server first-forward**: 2d = 1 RTT → client `Connected` at d, token+data sent at d, arrive 2d, server
  auth returns immediately (`server main.rs:853-880`; token in same flight).
- **0-RTT auth saving**: 2d → 1d = **0.5 RTT** per resumed dial (§1.2).
- **Opening compression window**: OPEN at t=0, server forwards/installs/ACKs at d, client applies at 2d =
  **1 RTT** (`accept.rs:2144-2177,2333-2352`; `dispatcher.rs:993-999`).
- **Opening-window byte overhead**: `p` payloads/RTT × (14−2) = **12p B** IPv4; `(11+L−2)=9+L` B/domain
  (`r2.rs:275-283` constants; `p = pps × RTT`).
- **Bound-flow break-even vs INLINE**: `14+4+2n ≤ 13n` ⇔ `n ≥ 2` (IPv4, uplink only).
- **Reconnect outage (UDP)**: `watchdog(40 s) + first backoff(0.2–0.4 s) + publish(0.5 RTT) + server(0.5 RTT)`;
  during it all datagrams are dropped (`assoc.rs:487-509`, fail-closed `client_conf.rs:318-323`).
- **Pre-auth credit stall**: publish 0.5, credit raised 1.0, `MAX_STREAMS` received 1.5 RTT; a 5th stream
  opened at 0.5–1.5 RTT waits 0–1 RTT (`tuning.rs:146,161`; `quinn…connection.rs:331-336`).
