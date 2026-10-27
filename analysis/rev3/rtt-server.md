# MQP-3 rev2 — server-side round-trip / latency audit

**Scope.** The *server* half of the MQP-3 rev2 data plane (`src/mqp/r2.rs`,
`src/mqp/r2_flow.rs`) and every server interaction that can delay, drop or
serialize user payload: accept → auth → HELLO gate → `DATA OPEN` → policy/SSRF →
DNS → per-session socket → forward; the reply direction (source match, rebind,
`FLOW_ACK`); session lifecycle; admission/limiters; the TCP path; and the
DNS/cache stack behind it.

**Question this answers.** Which server-side latency is *MQP-attributable* (a
protocol interaction a wire redesign can delete) and which is *network-inherent*
(DNS resolver RTT, target TCP handshake, QUIC handshake)? Backward compatibility
is not a constraint.

**Method / evidence grades.** Read-only source audit (no build, no run). Every
non-obvious claim carries `file:line`. Grades used throughout:

- **[code]** — directly visible in the cited lines.
- **[derived]** — a byte/RTT count obtained by arithmetic on the codec constants
  (`src/mqp/r2.rs`) and the per-packet overhead model in
  `analysis/rev3/wire_model.py:15-17` (≈57 B IPv4+UDP+QUIC per DATAGRAM packet);
  the arithmetic is shown.
- **[estimate]** — a CPU-time order of magnitude with no in-repo measurement;
  listed in §6 as unresolved.
- **[measured]** — none in this report. The repository's measurement machinery
  (`examples/hotpath_bench.rs`, `scripts/linux-bench-matrix.sh`) was deliberately
  not run (task constraint); §7 says exactly which cells would confirm each
  claim.

**Headline result (details in §1 and S1–S20).** On a warm pooled connection the
server **never waits for a client response before forwarding a payload**, and
the client never waits for a server response before sending one. MQP-3 rev2
therefore adds **zero mandatory round trips** to the data path. What it *does*
add is: (a) one extra DATAGRAM per flow, the `FLOW_ACK`, plus an ACK-gated
compression window of ~1 RTT of oversized headers (S3/S4/S7); (b) a mandatory
HELLO gate in front of *all* data frames, which turns a lost control datagram
into a 200 ms stall and can silently drop early payloads (S1); (c) a
domain-target OPEN path that always waits for a full resolver RTT (external) and
**loses the triggering payload** on DNS/policy/session failure (S5); and (d) a
lost `SESS_CLOSE` with no repair path (S10).

---

## 1. RTT ledger by scene (what is MQP vs network)

`ΔMQP` = round trips or waits a wire redesign could delete. `Δexternal` = DNS
resolver / target TCP / QUIC handshake, i.e. physics of the deployment.
"Warm" = an already-established pooled QUIC connection with a live session/flow.

| # | Scene | ΔMQP | Δexternal | Notes / evidence |
|---|---|---|---|---|
| A | Warm conn, existing flow, one payload each way | **0** | 1 RTT (client↔server↔client) | steady 2 B header; server `registry.get` + `target_ip` + grouped send, no await `accept.rs:1962-2006`, `accept.rs:2983-3232` |
| B | Warm conn, first payload to a **new IP target**, request/response | **0 waited**; +1 DATAGRAM (ACK) and ~+51 B net wire for the first exchange | 1 RTT | forward-then-install-then-ACK; ACK never gates the forward `accept.rs:2223-2252`, `2333-2350`; break-even arithmetic §Appendix A |
| C | Warm conn, first payload to a **new domain target**, cold DNS | 0 waited (but see S5 failure = **payload lost**); µs-scale task spawn | **+1 resolver RTT** (bounded 5 s) before the payload moves `accept.rs:2075-2144` | remote-DNS design; the only genuinely large added latency on the first payload |
| D | Warm conn, new domain target, **warm** cache (thread memo/moka) | ~**one task round trip** (spawn+await) that a sync memo check would remove (S6) | 0 | `accept.rs:2253-2325` has no sync lookup; the generic slow path does (`forward.rs:388-423`) |
| E | New flow's later payloads, before `FLOW_ACK` | **~1 RTT of oversized headers**, no TRAIN aggregation (S4) | 0 | `client rev2.rs:779-796`; stager keeps `Open` standalone `r2_stage.rs:462-495` |
| F | Domain-target downlink, first→second reply | **~1 RTT of re-sent `OPEN\|SRC` headers** (S7) | 0 | `match_source` returns `Rebind` until `reply_src_acked` `r2_flow.rs:325-366` |
| G | IP-target downlink where reply source == target; server-owned full-cone flow | **0** (compresses immediately, no ACK) | 0 | `target_names_src` short-circuit `r2_flow.rs:331-334`; `install_unsolicited` sets `target=Ip(src)` `reader.rs:229-266` |
| H | TCP `CONNECT` (warm pool) | **0** (dial-ACK is in-band, uplink not gated) | 0.5 RTT header + target TCP handshake | `tcp.rs:33-173`, `tcp.rs:191-205`, `tcp/pump.rs:47-61`; client SOCKS success is optimistic `client socks.rs:246-264` |
| I | Fresh QUIC connection + auth | 0 extra if token rides the first 1-RTT flight; **+1 RTT vs a 0-RTT design** (deliberate) | 1 RTT handshake (fresh) | `main.rs:853-880`, `auth.rs:22-47`, `client auth.rs:357-365` |
| J | HELLO lost on the wire, first flight of data | **up to 200 ms** stall (HELLO retry) and >8 pre-HELLO frames dropped | datagram loss | `accept.rs:1100-1104,1450-1470,2659-2696`; `client rev2.rs:45-50,479-519` |
| K | CAPS lost | up to 2 s then close+redial (startup only) | datagram loss | `client rev2.rs:47-50,505-517` |
| L | Session reaped by server, `SESS_CLOSE` lost | no RTT, but **unbounded one-way blackhole** for an active uplink-only association | datagram loss | `accept.rs:1533-1540,2783-2824`; `client rev2.rs:687-704`, `dispatcher.rs:1033-1052` |
| M | New session, first payload | 0 waited; session creation (~64 KiB socket, syscalls, reader spawn) runs before the send | 0 | `reader.rs:1746-1807`; refusal = payload **dropped** `reader.rs:1656-1741` |

Reproduce the "fewest possible round trips" floor: **A = 0**, and every other
row's ΔMQP is either a *bytes* cost (B/E/F), a *loss-window* cost (J/K/L), or an
*external* RTT the protocol merely serializes in front of (C/D). The redesign can
reach "0 MQP round trips" without touching transport framing; the hard part is
deleting the ACK gate and the HELLO gate without inheriting their loss windows
(§4).

---

## 2. Server step table (required format)

"Blocking?" = is the step **awaited** before the payload leaves the server toward
its target (uplink) or toward the client (downlink)? "ΔMQP RTT" = wait a wire
redesign could delete. "Δext RTT" = DNS/target/QUIC physics.

| # | Server step / event | Blocking? | ΔMQP RTT | Δext RTT | code ref | removable / overlappable? |
|---|---|---|---|---|---|---|
| 1 | Accept conn + QUIC/TLS handshake; per-IP pending slot, pre-auth slot, conn permit (all fail-fast) | yes (setup) | 0 | 1 RTT fresh, 0 on resumption | `main.rs:699-846` | inherent; transport |
| 2 | Auth token: `accept_uni` + read token, constant-time compare; `authenticate` completes before `handle_conn` spawns | **yes — gates the whole datagram reader** | 0 fresh (token in same flight); +1 RTT on resumed conns | 0 | `main.rs:853-880`, `auth.rs:22-47`; client `auth.rs:388-415` | keep; if 0-RTT app data is wanted, the token must move into TLS/ALPN or become replay-tolerant |
| 3 | Raise bidi stream credit to 8192; spawn sweeper + uni-drain + **datagram reader** | no | 0 | 0 | `main.rs:878`, `accept.rs:2783-2848` | — |
| 4 | HELLO/CAPS gate: non-HELLO rev2 frame buffered (8 frames/16 KiB) until `HELLO(wire_ver=2)` | **yes, when HELLO is lost/behind** | 0 normally; up to 200 ms on loss; overflow = drop | loss-dependent | `accept.rs:1100-1104,1450-1470,2659-2696` | **remove the gate** (frames are self-identifying); CAPS can be a pure capability update |
| 5 | First-byte dispatch (`is_r2` → DATA/TRAIN/FRAG/CTL) | no | 0 | 0 | `accept.rs:3027-3040,2713-2748` | — |
| 6 | `DATA OPEN` decode + owner/conflict checks | no | 0 | 0 | `accept.rs:2184-2219` | — |
| 7 | IP target: SSRF cache check | no | 0 | 0 | `accept.rs:2223-2229`, `pin.rs:292-336` | — |
| 8 | IP target: forward (`get_or_create_sess` + `udp_try_send`, or staged `sendmmsg`) | **yes on the session's first payload** (awaits socket create / may await shard read lock) | 0 (µs CPU; failure = drop) | 0 | `accept.rs:2230-2251`, `forward.rs:446-467`, `reader.rs:1557-1984` | session-socket multiplexing could remove the per-session syscall burst (L11) |
| 9 | Domain target: `begin_pending_open` → **spawn** bg task | returns immediately to the loop; the payload is owned by the task | ~0 (µs spawn) | 0 | `accept.rs:2253-2327` | add a synchronous memo check to avoid the spawn on warm cache (L7) |
| 10 | Domain target: DNS permit + resolve (thread memo → moka → hickory; 5 s timeout) | **yes — payload held for the whole resolver RTT** | 0 | **1 resolver RTT** | `accept.rs:2067-2082`; `dns/resolve.rs:392-432,479-508`; `dns/store.rs:56-100` | external; only overlappable via client-side resolution or a speculative address in OPEN (L8/L10) |
| 11 | Domain target: SSRF-filter resolved set (≤16), pick first | no | 0 | 0 | `accept.rs:2083-2099,2016-2028` | — |
| 12 | Domain target: session create (guarded) | yes (in bg task) | 0 | 0 | `accept.rs:2110-2138` | as #8 |
| 13 | Forward payload to target (+ queued duplicate payloads in arrival order) | yes (the await is the point of the task) | 0 | 0 | `accept.rs:2144-2154` | — |
| 14 | Install binding: registry insert + session reverse table `rcu`; mark `Open` | no (after forward) | 0 | 0 | `accept.rs:1606-1673,2155-2180,2333-2350` | — |
| 15 | Send `FLOW_ACK` (one per accepted OPEN, **including duplicate OPENs**) | no | 0 | 0 | `accept.rs:2336-2343,2165-2172`; re-ACK per duplicate `2205-2219,2333-2350` | **delete or make opt-in** (L3/L4); redundant for request/response flows (S3/S8) |
| 16 | Steady flow frame: `registry.get` → `target_ip`/`resolved_first` → fast stage / slow forward | no | 0 | 0 | `accept.rs:1962-2006` | — |
| 17 | TRAIN: batch id resolution + per-item forward | no | 0 | 0 | `accept.rs:2440-2515` | — |
| 18 | FRAG: reassemble (2 s/256 partials/256 KiB) then route | no | 0 | 0 | `accept.rs:2531-2632`; `udp/r2_reasm.rs` | — |
| 19 | Downlink: session reader `recvmmsg` burst → allowlist mirror → `match_source` | no | 0 | 0 | `reader.rs:1207-1428`, `1015-1048` | — |
| 20 | Downlink reply: `Exact` steady frame (or join TRAIN) | no | 0 | 0 | `reader.rs:1090-1132,515-618` | — |
| 21 | Downlink reply: `Rebind` → standalone `OPEN\|SRC`, learn `reply_src` only on `Sent` | no | **~1 RTT of re-sends** until the client's `FLOW_ACK` arrives (bytes, not payload delay) | 0 | `reader.rs:398-444,1113-1122`; `r2_flow.rs:96-109,325-366` | **replace with repeat-context or in-band ack** (L3/L5) |
| 22 | Server-side reap: 60 s idle sweep / reader exit / pressure sweeps → `SESS_CLOSE` ×3 (detached, chunked) | no | 0 | 0 | `accept.rs:2783-2824,1694-1741,1533-1576`; `reader.rs:1475-1483` | no RTT; but see S10 for lost-close repair |
| 23 | TCP: `accept_bi` → 5 s header read → share + stream permit → DNS (domain) → dial permit → dial (4 s, 250 ms HELLO stagger) → ACK write → relay | header read then dial are the critical path | 0 | 1 RTT proxy hop + target connect; +250 ms if the preferred-family candidate is dead | `tcp.rs:33-205,295-336` | dial timing already earliest-possible |
| 24 | Admission: conn/pending/session/dial/stream/header limiters | **no — every one is `try_acquire` (fail-fast)**; refusal drops or resets, never queues | 0 | 0 | `accept.rs:25-127,716-728,3291-3319`; `reader.rs:1713-1741`; `tcp.rs:73-80,156-164` | — |

Blocking inventory (the complete list of things the server *awaits* before a
payload moves): HELLO gate (#4), session creation (#8/#12), DNS resolution (#10),
and — for TCP — the header read and target dial (#23). Nothing else. In
particular the server never awaits a client frame, a control frame, a table
insert, an install or an ACK.

---

## 3. Findings

### S1 — The HELLO gate in front of *all* rev2 data frames is pure bookkeeping and can be deleted.

`handle_r2_ingress` treats every non-HELLO rev2 frame — data *and* control — as
un-dispatchable until a valid `HELLO` has been seen:

```rust
// accept.rs:2659-2670
if kind == R2Kind::Ctl {
    let is_hello = d.get(1).copied() == Some(r2::R2_CTL_HELLO);
    if !is_hello && !state.ctl.hello_seen() {
        if state.buffer_pre_hello(d) { return; }
```

and the data branch repeats it (`accept.rs:2690-2696`). The buffer is bounded at
**8 frames / 16 KiB per connection** (`accept.rs:1100-1104`) and overflow is
counted and dropped (`accept.rs:1460-1468`). The gate opens only for
`wire_ver == R2_WIRE_VER` (`accept.rs:1822-1837`).

Why it is removable: rev2 frames are self-identifying by first byte
(`r2::kind`, `r2.rs:128-136`; first-byte space documented at `r2.rs:17-21`), and
no non-rev2 peer can emit `0x0X` frames — both the shipped MQP-2 and v3 decoders
reject that space (`r2.rs:1082-1110`). A frame that parses as rev2 *is* rev2, so
the server does not need permission before dispatching it. Consequences of the
current gate, all avoidable:

- HELLO is a **DATAGRAM**, so it can be lost. The client retries every 200 ms
  (`client rev2.rs:45-46,479-519`), and every buffered pre-HELLO frame waits for
  that retry: **up to 200 ms of added first-payload latency**, once per
  connection per HELLO loss (J in §1).
- On a connection that starts a burst before HELLO is dispatched, frames 9..N of
  that burst are **dropped silently** (`PRE_HELLO_DROPPED`,
  `accept.rs:1465-1468`) — application-visible UDP loss attributable to a
  control-plane version check.
- It also reserves 16 KiB per connection inside the 96 KiB
  `R2_INGRESS_FIXED_BYTES` charge (`accept.rs:1104`; `config/tuning.rs:33`), for
  a gate that only matters for one flight.

Cost of removal: none to correctness (HELLO can stay as a capability
announcement to answer with CAPS); CAPS is already documented as "a capability
update, not a first-packet gate" (`README.md:137,350`).

### S2 — The first uplink payload is forwarded *before* install/ACK; the server never waits for the client on the forward path.

IP target (`accept.rs:2223-2252`): policy check → `flush_staged_sends` →
`forward_server_dgram(...).await` (which resolves/creates the session and sends
to the target) → `arm_fast` → then `r2_install` and only then `FLOW_ACK`
(`accept.rs:2333-2350`). Domain target is the same order inside the bg task:
policy → session → `udp_try_send(&sock, …)` (`accept.rs:2144`) → queued
duplicates (`2148-2154`) → `r2_install` → `FLOW_ACK` (`2155-2173`).

So `FLOW_ACK` is not awaited by anything server-side, and no client response is
awaited before forwarding. **ΔMQP RTT for the payload = 0**; the ACK is a
post-hoc notification. This is the single most important structural fact for
the redesign: the ack exists only to unlock compression, not to gate delivery.

The forward path *is* gated by session creation on a session's first payload
(`get_or_create_sess`, S11) and, for domains, by DNS (S5) — both before the send,
not after it.

### S3 — `FLOW_ACK` is emitted once per accepted `OPEN` frame, including duplicate OPENs; for one-shot flows it is a net wire loss.

The ACK is sent from both install sites, unconditionally:

```rust
// accept.rs:2333-2343 (IP path; the domain task is identical at 2155-2172)
match r2_install(state, ss, sess, id, target, resolved) {
    Ok(_) => {
        r2_stats::bump(&r2_stats::OPENS);
        r2_send_ctl(cd, &Ctl::FlowAck { id, status: r2::R2_ACK_OPEN });
```

A duplicate OPEN does not short-circuit: the only duplicate check rejects a
*different* `(session, target)` (`accept.rs:2205-2219`), so a same-target
duplicate forwards the frame's new payload, re-installs idempotently
(`FlowRegistry::insert` returns the existing binding, `r2_flow.rs:518-535`) and
**re-sends the ACK** from the same tail (`accept.rs:2333-2350`). While the client is in
`Opening`, *every* payload is sent as `OPEN` (`client rev2.rs:778-796`), so a
burst of N payloads before the first ACK reaches the client produces up to N ACK
datagrams from the server. This is documented as intended
(`README.md:344`: "duplicate OPENs are re-ACKed") but has no coalescing.

Per-flow cost, [derived] (see Appendix A for header arithmetic): `FLOW_ACK` is
`3 + varint(id)` = **4 B** for `wire_id < 128` (`r2.rs:906-914`), carried in one
QUIC DATAGRAM ⇒ **≈57 B on the wire** including IPv4/UDP/QUIC framing. For a
one-shot request/response flow the flow machinery is a **net loss of one packet
and ~+51 B** (IP target) or **+63 B** (domain target) versus sending both frames
as `INLINE`:

- uplink: `OPEN` 14 B vs `INLINE` 13 B ⇒ +1 B (`r2.rs:275-289`)
- downlink: steady 2 B vs `INLINE` 13 B ⇒ −11 B
- ACK: +≈61 B (4 B frame + 57 B packet)
- ⇒ +51 B net, +1 packet; break-even ≈ 4.4 further payloads in either direction
  (each later payload saves 11–12 B).

The redesign consequence: **do not ACK a flow nobody has asked about.** Either
carry `OPEN` context redundantly ("repeat-context", as the rev3 byte sketch in
`analysis/rev3/wire_model.py` already assumes) or make the ACK opt-in with a
flag in the OPEN frame. For a single DNS-style exchange the savings are exactly
the 2 of 4 packets: `wire_model.py:126-140` models the same 4→2 packet result
independently.

### S4 — ACK-gated compression costs ~1 RTT of oversized headers *and* disables TRAIN aggregation for the flow's early payloads.

`UplinkFlows::ensure_binding` creates the binding in state `Opening`
(`r2_flow.rs:123-133`); the client sends `R2StageKind::Open` (self-describing,
`wire_id + sess + addr`) for every payload until `binding.is_open()`
(`client rev2.rs:778-790`). Two costs follow:

1. Header: 14 B (IPv4) / 26 B (IPv6) / 11+L B (domain) instead of 2–3 B — for
   every payload in the first RTT. At 60 pps that is ~4 payloads at 70 ms RTT
   [derived: RTT/packet-interval], ~11 B × 4 = ~44 B per flow, **plus** it
   repeats to N payloads in a burst.
2. Aggregation: the stager only packs `Steady` items into a `TRAIN`; an `Open`
   head is forced to a standalone frame:

   ```rust
   // r2_stage.rs:471-480
   let head_is_standalone = self.sessions.get(&session)
       .and_then(|q| q.front())
       .is_some_and(|i| !matches!(i.kind, R2StageKind::Steady { .. }));
   if head_is_standalone { … encode_standalone … }
   ```
   So while compressing is gated on the ACK, one flow's payloads each cost one
   DATAGRAM send instead of sharing a cross-session `TRAIN`. For an 8-flow
   fan-out within the first RTT that is up to 8 extra send calls per burst; the
   `TRAIN`/stager machinery only starts paying off after the round trip.
   [derived from `r2_stage.rs:462-495` + `client rev2.rs:833-835`]

The ACK itself is not the only possible signal: any compressed downlink frame
also marks the client binding open (`client dispatcher.rs:1132-1135`), so for
request/response flows the server's explicit ACK is redundant (S8). The ACK
matters for (a) pure-uplink flows and (b) uplink bursts that want compression
before any reply comes back.

### S5 — Domain-target OPEN: the payload waits for the full resolver RTT, and on failure the payload is **lost** (no INLINE fallback).

The domain arm of `r2_ingress_open` spawns `r2_forward_domain_open_bg`
(`accept.rs:2308-2326`) and returns. In the task:

- DNS-budget refusal: `r2_reject(DNS)` and **return** — the payload dies here
  (`accept.rs:2067-2073`).
- Resolver error / timeout: `r2_reject(R2_REJECT_DNS)` and **return**
  (`accept.rs:2075-2082`).
- Policy filtered every resolved record: `r2_reject(POLICY)` and **return**
  (`accept.rs:2083-2089`).
- Session creation refused (fair-share / global pool / no-DATAGRAM): reject and
  **return** (`accept.rs:2110-2130`).

In all four cases the datagram that triggered the OPEN — and every duplicate
payload queued behind it — is dropped:

```rust
// accept.rs:1200-1210 — PendingDnsOpen::drop
for _ in self.state.take_pending_payloads(&self.entry) {
    r2_stats::bump(&r2_stats::DNS_OPEN_DROPS);
}
```

The client only learns via `FLOW_REJECT`, then falls back to `INLINE` for
*subsequent* payloads (`client rev2.rs:69-92`: `R2_REJECT_DNS` gets a 1 s
retry window). So a failed domain flow costs the client **one application-level
retransmission**, which for a DNS stub or QUIC handshake is typically 100 ms–5 s,
not an RTT. Compare the IP path, which explicitly forwards before the install
decision so that a table-full refusal can never lose the triggering payload
(`accept.rs:2205-2219`: "*A full registry is deliberately not checked here: the
payload still has to be delivered before the install is refused (P2-7)*"). The
domain path does not inherit that property. Also note: on **success** the
ordering is forward-then-install (`accept.rs:2144` before `2155`), so a later
install failure does not lose a delivered payload — only a *pre*-forward failure
does.

Two more session-level caps in the same path:

- `MAX_PENDING_DNS_OPENS = 16` **per connection** (`accept.rs:1106-1110`): the
  17th concurrent *new* domain flow is refused with `FLOW_REJECT(dns)` and its
  payload dropped (`accept.rs:1297-1307`). A page-load-style burst of
  domain-target UDP flows (QUIC/HTTP3, games, WebRTC) can hit this.
- The duplicate-payload queue behind an in-flight lookup holds 64 items /
  256 KiB per connection and **drops the overflow** (`accept.rs:1112-1121,
  1331-1354`); `PendingPayload::Full` counts `DNS_OPEN_DROPS`
  (`accept.rs:2267-2275`). At 60 pps a 5 s DNS timeout offers ~300 payloads to
  a 64-item queue, so only the first ~64 survive.

### S6 — The rev2 domain OPEN path has **no synchronous cache fast path**, unlike the generic datagram path.

`forward_server_dgram`'s domain arm consults the thread memo and the session
destination memo synchronously and spawns a resolver *only* on
`ForwardResolution::Unresolved` (`forward.rs:468-505`, `388-423`). The rev2 OPEN
arm does not: it goes straight to `begin_pending_open` + `tokio::spawn`
(`accept.rs:2253-2325`). Consequences even on a fully warm cache (moka hit, TTL
120 s, `dns/store.rs:56`):

- the payload is handed to another task and only forwarded after that task is
  polled — one spawn + await round trip [estimate: single-digit µs on x86; no
  in-repo measurement];
- the install and `FLOW_ACK` also happen in that task, so the client's
  compression starts one task round trip later than necessary;
- the `(session, id)` coalescing entry and its locks are taken
  (`accept.rs:1292-1317`) for a case where a synchronous `lookup_cached_fast`
  would have answered without any DNS work.

This is a removable µs-scale delay (not an RTT) and a straightforward
consistency fix: mirror `resolve_forward_target` before spawning.

### S7 — `reply_src_acked`: exactly one RTT of redundant `OPEN|SRC` headers per learned reply source; needed only for domain targets and source-port changes.

`SessionFlows::match_source` classifies a source whose `reply_src` was learned as
`Exact` only when the peer confirmed the binding frame — unless the binding's
target *is* that source:

```rust
// r2_flow.rs:331-341
if b.reply_src() == Some(src) {
    let target_names_src = matches!(&b.target, TargetAddr::Ip(a) if *a == src);
    if b.reply_src_acked() || target_names_src {
        return Some(SourceMatch::Exact(b.clone()));
    }
    if rebind.is_none() { rebind = Some(b); }
    continue;
}
```

`reply_src_acked` is set *only* by `CTL FLOW_ACK` (`accept.rs:1846-1852`) — there
is no in-band path server-side. And `set_reply_src` re-arms the wait on every
`OPEN|SRC` send (`r2_flow.rs:161-169`), called from `stage_open_src` on `Sent`
(`reader.rs:414-418`) and from the large-reply sender (`reader.rs:559-591`).

Therefore:

- **Domain targets**: the first reply is `OPEN|SRC` (matched via
  `resolved_contains`, `r2_flow.rs:349-357`); every further reply until the
  client's ACK returns is *another* `OPEN|SRC` (14 B IPv4 vs 2 B steady). At 70
  ms RTT and 60 pps that is ~4 extra frames × 12 B ≈ 48 B per flow — small, but
  it is a *round-trip-shaped* cost: it exists only because the sender cannot
  know the binding arrived.
- **IP targets with an unchanged reply source**: `target_names_src` is true ⇒
  `Exact` immediately; **zero** cost.
- **Client-driven rebind on port change / anycast**: same one-RTT header cost.
- The client ACKs *every* `OPEN|SRC` it decodes (`client dispatcher.rs:1125-1131`,
  `870-884`), so the mechanism self-heals across loss (the next reply re-sends
  the source, which is ACKed again). The cost is bytes, never a withheld payload.

Redesign options (L3/L5): (a) repeat `OPEN|SRC`/context for the first K frames
without waiting for any ack (K≈2–3) — zero RTT cost, no ACK datagram, loss
window = K consecutive losses; (b) an in-band "I have source version v" bit in
the client's own frames — cheaper but only works when the client has a reverse
frame to piggyback on; (c) keep the explicit ACK only for pure-downlink flows.

### S8 — The client's implicit ACK makes `FLOW_ACK` redundant for request/response flows.

The client marks a binding open on **any** downlink frame for that id:

```rust
// client dispatcher.rs:1132-1135
// Any compressed downlink proves the server installed this id: that is the
// implicit ACK the uplink waits for (a pure-uplink flow otherwise relies on
// `CTL FLOW_ACK`).
binding.mark_open();
```

For an IP-target request/response flow, the server's first reply is already a
steady frame (`match_source` → `Exact`, S7), so **even if the explicit ACK is
lost entirely** the first compressed reply confirms the install. The ACK only
changes behaviour for (a) pure-uplink flows and (b) uplink bursts that want to
compress *before* any reply comes back. This is the strongest argument for
deleting `FLOW_ACK` entirely and relying on (i) self-describing repeat frames for
the first K payloads and (ii) a repair path for the rare install failure: the
acknowledgement is already in the data plane for every flow that has a reply.

### S9 — Full-cone / server-owned flows need no ACK and are not on any normal path.

`install_unsolicited` allocates an `owner=1` id, installs the binding in both
tables, and sets `target = Ip(src)` plus `reply_src = src` (`reader.rs:229-266`).
Because `target_names_src` is then true, the *second* reply from that source is
`Exact` **without** `reply_src_acked` (S7). The first reply is `OPEN|SRC`
(`reader.rs:1066-1072`), which the client installs and ACKs
(`dispatcher.rs:1117-1135`). Costs: one id allocation (never reused,
`r2_flow.rs:740-778`), one registry insert, one reverse-table `rcu`; the client's
uplink reuse probe is a lock-free counter check (`find_server_flow`,
`r2_flow.rs:616-638`) that is skipped entirely for normal clients. No RTT, no
per-flow setup on the normal path, and it is gated on `udp_full_cone`
(`reader.rs:1066-1069`). Nothing here is on the redesign's critical path.

### S10 — Session lifecycle adds no RTT, but a lost `SESS_CLOSE` has no repair path.

Reap paths: the 60 s per-connection sweeper (`accept.rs:2783-2824`), the
fair-share/global-pool sweeps inside session creation (`reader.rs:1664-1699,
1713-1741`), and the reply reader's own exit (`reader.rs:1429-1506`). All reap
only sessions idle ≥ `SESS_IDLE_MS = 180_000` (`table.rs:469`) except the
reader-exit path. Each reap sends `CTL SESS_CLOSE` **three times**, detached and
chunked (`accept.rs:1533-1540,1557-1576`; `reader.rs:1475-1483`), because
"a lost close only delays reclamation" (`README.md:352`).

The delay is not benign in one shape. The client's only consumer of a
`SESS_CLOSE` is `UplinkFlows::sync`: on `take_session_closed(sess)` it drops the
association's bindings and re-opens (`client rev2.rs:687-704`); the only producer
is the `SESS_CLOSE` CTL arm (`dispatcher.rs:1033-1052`). If all three closes are
lost *and* the client's own 180 s idle path does not fire (the app keeps sending,
and downlink traffic/keepalives keep the connection alive), the client keeps
sending `steady` frames for ids the server has purged; the server drops them as
`UNKNOWN_ID` (`accept.rs:1973-1978`; steady frames never recreate a session) and
there is **no other signal** — no `NACK`, no reset, no flow close — until the
connection is redialed or the association idles out. The client's own comment
("a lost close is harmless (the server's own 180 s sweep is the backstop)",
`client rev2.rs:63-67`) only holds if the client also goes silent for 180 s.
Probability is low (p³ per close), but the failure mode is unbounded and
silent; a redesign that puts close/reject on a reliable stream, or that lets the
receiver repair an unknown id (rate-limited "you used a dead id"), removes it
(L9).

Other lifecycle facts, for completeness: `SESS_CLOSE` ×3 costs 3 DATAGRAMs
(7 B frame each, `r2.rs:912`) per reaped session; a 60 s sweep with thousands of
sessions is a detached chunked task, off the data path (`accept.rs:1557-1576`);
`FLOW_CLOSE` is a single 2–6 B frame and idempotent (`accept.rs:1862-1883`).
None of this adds per-flow setup or RTT on the data path.

### S11 — Per-session socket creation is on the first-payload critical path, and resource refusals there drop that payload.

First datagram of a session (`get_or_create_sess_guarded`, `reader.rs:1557-1984`):
memo probe (lock-free), then session shard **read lock that can block** ("The
read *blocks* rather than failing fast", `reader.rs:1602-1622`), then:

1. fair-share gate (`len_upper_bound >= fair_sess_cap` → `FAIR_SHARE` drop,
   `reader.rs:1656-1694`);
2. `cd.max_datagram_size()` probe (quinn state lock, `reader.rs:1710`);
3. global session permit `try_acquire` (`SESSION_FULL` drop,
   `reader.rs:1713-1741`);
4. `udp_socket_dual_small("[::]:0")`: `socket()` + `SO_*BUF` (64 KiB default,
   `lib.rs:243-254`), dual-stack, `bind()`, non-blocking, `tokio` register
   (`reader.rs:1746-1765`);
5. spawn the per-session reply reader (`reader.rs:1792-1807`) and publish under
   the shard write lock (`reader.rs:1814-1935`).

All of it is awaited before the target send; none of it is a network round trip.
[estimate] low tens of µs per new session (5 syscalls + task spawn); not
measured in-repo. Failure at steps 1/3/4 returns `None` and the caller **drops
the triggering payload** (`forward.rs:461`, `accept.rs:2247-2250`), which for the
first datagram of an association is app-visible loss (the app's retry pays the
latency, often 100 ms–1 s for DNS/game clients). The architecture lever is
one socket per *connection* with `recvmsg` source-address demux (L11): it removes
this per-session cost, the 64 KiB/session admission term (`README.md:408`), and
the per-session reader task, at the price of rewriting reply demultiplexing and
the source policy.

### S12 — Admission/dial/header/stream limiters cannot delay a first byte: every one is fail-fast.

Every admission gate uses `try_acquire_owned`/`try_acquire` and refuses
immediately rather than queueing:

- connection + pre-auth slots + per-IP pending share: `main.rs:716-769`
  (drop the incoming connection);
- dial limiter: `accept.rs:25-28` + `tcp.rs:156-164` (stream reset `0x04`);
- stream-task + per-connection share: `tcp.rs:58-80`, `accept.rs:3291-3319`
  (reset `0x05`);
- header-read credit: `tcp.rs:21-26,47-48`, `accept.rs:116-127` (reset `0x05`);
- session pool + fair share: `reader.rs:1656-1741` (datagram drop);
- DNS slow path: `dns/resolve.rs:339-349`, `forward.rs:487-493`,
  `accept.rs:2067-2073` (drop / `FLOW_REJECT(dns)`).

So there is no permit queue in front of a first byte; under pressure the answer
is a drop or a stream reset, which the client's retry/redial pays for. The only
blocking wait on the ingest path is the session-table `RwLock` read
(`reader.rs:1621`) and, on TCP, the header read/target dial.

### S13 — TCP path: the server dials as early as it possibly can; the dial ACK is an in-band marker, not a gated round trip.

Order per stream (`tcp.rs:33-205`): 5 s header read → drop header credits →
share slot → stream permit → (domain) DNS → dial permit → `dial_happy_eyeballs`
→ `tune_relay_tcp` → write the MQP dial ACK → relay. The target is only known
from the header, and the header is the client's first stream write
(`client forward.rs:291-305`, `client socks.rs:216-245`), so the dial starts at
the earliest possible instant: ~0 ms after the header read, i.e. 0.5 RTT after
the app's CONNECT reached the client. From app CONNECT to established target:
**0.5 RTT (header one-way) + 1 target TCP RTT ≈ 1.5 RTT**; a direct connection
would be 1 target RTT, so the extra half round trip is the inherent proxy hop.

The dial ACK does not add a round trip: it is the first thing written on the
server→client stream half and the pump consumes it before relaying downlink
bytes (`tcp/pump.rs:47-61`); the uplink direction is explicitly **not** gated on
it ("saves one client↔server RTT on every connection", `tcp/pump.rs:51-52`), and
the client answers SOCKS optimistically before the ACK arrives
(`client socks.rs:246-264`). Multi-candidate dials use happy-eyeballs with the
RFC 8305 **250 ms** fallback stagger (`tcp.rs:269-295`), so a dead
preferred-family address adds up to 250 ms — network policy, not MQP.

### S14 — CAPS/HELLO bookkeeping costs are startup-only; one code comment about the CAPS gate is stale.

- Client `HELLO` is sent immediately and retried every 200 ms up to a 2 s cap,
  then the connection is closed and redialed (`client rev2.rs:45-50,479-519`).
- Server answers with a 17 B `CAPS` (`r2.rs:906-914`) throttled to one per 100 ms
  (`accept.rs:820-828,1431-1446`). `CAPS` is not required for data (S1).
- Per-flow cost: **0**.

Contradiction worth fixing: `client auth.rs:88-93` claims "the egress cache
refuses to publish a connection until then [CAPS]", but the egress cache
deliberately publishes pre-CAPS so the first payload is optimistic
(`client egress.rs:413-421`; the corresponding test is
`client tests.rs:6516-6526`). The egress code is the implementation; the auth
comment is stale.

Also startup-only but worth naming: with auth enabled the token must wait for
1-RTT keys, so a **resumed** connection forfeits 0-RTT app data — one RTT of
setup versus a 0-RTT design (`client auth.rs:357-365`, server gate
`main.rs:853-880`). This is an explicit security trade-off (replay), not an
accident, and it is the largest setup-only RTT in the whole system.

### S15 — Reply pinning / allowlist misses are per-reply CPU and a compression-quality question, not an RTT.

Per reply the reader does: epoch-gated allowlist mirror (one relaxed load + 16-slot
scan, `reader.rs:1015-1030`; `pin.rs:37-54,526-543`), an MQP-3 flow-table probe
(`reader.rs:1037`), then the rev2 reverse match — a linear scan of ≤64 bindings,
each possibly scanning ≤16 resolved addresses (`r2_flow.rs:325-366`). All
lock-free. Outcomes:

- `Exact` → 2–3 B steady frame, or an item in a cross-session `TRAIN`;
- `Rebind` → one standalone `OPEN|SRC` (14 B IPv4) and a one-RTT re-send window
  (S7);
- no match, restricted filter → **drop** (counted `REFUSED`,
  `reader.rs:1050-1058`);
- no match, full-cone → install a server-owned flow (S9) or `INLINE` on a table
  bound (`reader.rs:1060-1072`).

A *miss* therefore costs header bytes (13–25 B `INLINE` instead of 2–3 B steady)
and, under the restricted filter, a legitimate reply can be dropped if its
source is neither in the flow's 16-address resolved set nor in the 16-entry
recent-destination ring nor in the flow table (e.g. a target answering from an
address outside its DNS answer, or a >16-address anycast set;
`r2_flow.rs:50` caps the retained set). No RTT anywhere.

### S16 — The stager adds no latency to an isolated payload (negative finding worth recording).

A single small payload is pushed to the connection stager and drained at the end
of the *same* drain-burst iteration, before the association task parks again:

```rust
// client assoc.rs:771-776
if let Some(b) = bind { drain_assoc_stage(&egress_shared, &pool, b); }
```

and `Open`/`Inline` items are never held back to fill a train (`r2_stage.rs:462-495`).
The only timer in the path is the 20 ms `STAGE_RETRY_MS` backstop for a *blocked*
send buffer (`reader.rs:338-353`). So the batching layer is not a hidden
latency source; the mission's "fewest round trips" work does not need to touch
it.

### S17 — Ordering/loss semantics that produce latency without a round trip.

- QUIC DATAGRAMs are unreliable and may be reordered; the pre-HELLO buffer
  preserves *arrival* order but not send order (`accept.rs:2672-2687`).
- A steady frame for an unknown/closed id is **dropped silently**
  (`accept.rs:1973-1978`): no NACK, no repair. This is correct for stale frames
  (ids are never reused, `r2.rs:25-29`) but is also the mechanism behind the
  S10 blackhole and the reason repeat-context/repair is needed in a redesign.
- The install is intentionally *after* the forward: `r2_install`'s contract is
  "the target has already accepted the payload when this runs; an install
  failure therefore only means 'no compression', never 'payload lost'"
  (`accept.rs:1591-1605`), and the IP OPEN arm relies on it ("the payload still
  has to be delivered before the install is refused (P2-7)",
  `accept.rs:2205-2219`). This invariant should be preserved by any redesign —
  except that the *domain* path breaks it for pre-forward failures (S5).

### S18 — Table/id exhaustion paths never cost a round trip (and mostly never lose payloads).

- Per-connection registry full: the forward happens first; the install fails and
  the server answers `FLOW_REJECT(table_full)` (`accept.rs:2345`), payload
  delivered. Only the *domain* path loses it (S5).
- Per-session `SessionFlows` full (64 flows, `r2_flow.rs:36,282-287`): the client
  falls back to `INLINE` (`client rev2.rs:1069-1071`), the server forwards it as
  a one-shot (`accept.rs:2396-2415`), payload delivered.
- Client id space exhausted / registry full on the send side: `INLINE` fail-safe
  (`client rev2.rs:711-717,1110-1116`).
- Server id space (`FlowIds`, `r2_flow.rs:740-778`) only matters for full-cone.

### S19 — Server→client control traffic inventory (the "bookkeeping" question).

Per connection: `CAPS` 17 B (per HELLO, throttled 100 ms) — startup only.
Per flow: `FLOW_ACK` 4 B / `FLOW_REJECT` 4 B / `FLOW_CLOSE` 2–6 B
(`r2.rs:906-914`). Per learned downlink source: `FLOW_ACK` ×1 from the client,
`OPEN|SRC` ×(1..RTT-window) from the server. Per session: `SESS_CLOSE` 7 B ×3 on
reap. Every one is a separate DATAGRAM (≈57 B wire each [derived]). None gates a
payload; all are removable or collapsible except the close.

The one *in-band* control frame — the TCP dial ACK — is already optimal (S13).

### S20 — DNS cache layering and its warm-path behaviour.

Order per lookup: thread-local `(host,port)` memo (sync, no lock, no clock,
`dns/resolve.rs:392-432`) → host-keyed moka positive cache (`try_get_with`,
single-flight; `dns/resolve.rs:479-508`; TTL 120 s `dns/store.rs:56`) → negative
cache (10 s, `dns/store.rs:58`) → hickory upstream with a 5 s timeout
(`dns/store.rs:100`, `dns/resolve.rs:140,175-180`) → `getaddrinfo` fallback under
its own permits. Process-wide slow-path budget: 1024 permits
(`dns/resolve.rs:339-349`), per-connection domain-open cap 16 (S5).

Because the moka cache is host-keyed, a new **port** for a known name is served
from cache without an upstream query (`dns/resolve.rs:19-23`). So the "cold
resolver RTT" happens at most once per name per 120 s per process; a warm
lookup costs an async cache probe (no I/O) — which is exactly why S6's missing
synchronous memo check is pure overhead on the warm path.

---

## 4. RTT-reduction opportunities

Ordered by (RTT/bytes saved on the latency-critical path) ÷ risk. "Saved" is per
flow unless stated; byte figures are MQP bytes with the ≈57 B packet overhead
noted where a DATAGRAM disappears.

| # | Lever | Saved RTT / bytes | Risk | Complexity |
|---|---|---|---|---|
| L1 | **Process rev2 data frames before/without HELLO** (keep HELLO only as the CAPS trigger). Frames are self-identifying (`r2.rs:128-136`), so the gate protects nothing. | Removes the up-to-200 ms HELLO-loss stall and the 8-frame overflow drop class; frees the pre-HELLO share of `R2_INGRESS_FIXED_BYTES` (96 KiB/conn, `config/tuning.rs:33`); −1 code path | very low (old peers already drop `0x0X`; a rev2 frame can only come from a rev2 peer) | low (delete gate + buffer; client unchanged) |
| L2 | **Delete `FLOW_ACK`; repeat self-describing context for the first K frames of a flow** (uplink: `OPEN`-form for K payloads; downlink: `OPEN\|SRC` for K replies), plus a rare repair path. | −1 DATAGRAM/flow (≈61 B); removes the ACK-gated compression wait ⇒ up to 1 RTT earlier steady headers + TRAIN participation; one-shot DNS: 4→2 packets | medium: if K contexts are lost the flow has no compression *and* no install until repair — needs an explicit repair (negative ack / periodic context) | medium |
| L3 | **Opt-in ACK flag in OPEN** (fallback if L2 is too invasive): only ask for the ACK when the flow will have no downlink or wants pre-reply compression. | −1 DATAGRAM/flow for all request/response and one-shot flows | low (pure additive bit; old server just never ACKs → client stays inline, no loss) | low |
| L4 | **In-band ack bit** in the client's steady header ("I have reply source v") instead of a CTL datagram. | −1 DATAGRAM per learned source; removes the one-RTT `OPEN\|SRC` repeat for request/response flows | low-medium (header bit; only helps flows with a reverse frame; pure-downlink flows still need context-repeat) | low-medium |
| L5 | **Carry the resolved reply source in the OPEN-ack** (or client-side prediction), so the server can compress the *first* downlink reply of a domain flow. | Removes the one-RTT `OPEN\|SRC` window for domain flows; −1 frame/first reply | medium: the client would write a *predicted* source into the SOCKS5 header if the actual source differs (anycast/port change); current design deliberately reports the actual source (`reader.rs:561-569`, `client dispatcher.rs:1117-1131`) | medium |
| L6 | **Never lose the triggering payload on a domain-path failure**: buffer it and deliver via the `INLINE` fail-safe when DNS/policy/session fails (re-validate policy on the inline path). | Removes one app-level retransmission per failed domain flow: typically 100 ms–5 s (DNS stub / QUIC handshake timeout), i.e. the largest avoidable *latency* in the audit | low (payload already bounded by the duplicate-queue budget; fails closed) | low-medium |
| L7 | **Synchronous warm-cache fast path in `r2_ingress_open`** (mirror `resolve_forward_target`): memo/moka hit ⇒ forward + install + ACK in the reader-loop poll, no task. | Removes one spawn+await (~µs) on every new domain flow, and the ACK/compression start delay behind it | very low (identical policy, already used by the generic path) | low |
| L8 | **Speculative resolved address in the domain OPEN** (client-supplied, SSRF-validated; server keeps its own resolution as the authority for later frames). | Removes the **resolver RTT** from the first payload's critical path (typically 10–70 ms on a warm resolver, up to 5 s worst case) | low-moderate: this does not expand reachable targets (the client can already send an IP-target OPEN), but it changes *which* address a name maps to for the first payload (split-horizon/poisoning), and leaks the name to the client's resolver if the client resolved it | medium |
| L9 | **Reliable control plane for close/reject** (one length-prefixed stream, per REFACTOR §5.5), and/or a rate-limited "dead id" repair frame so a receiver can ask for context. | Removes the unbounded lost-`SESS_CLOSE` blackhole (up to redial/180 s of one-way loss) and the ×3 repeats (2 DATAGRAMs saved per reap); stream also removes the CAPS-loss 2 s redial | medium (new stream, framing, backpressure, memory accounting) | medium-high |
| L10 | **Client-side resolution option for UDP/TCP domain targets** (no wire change): resolve locally, send IP targets; server DNS becomes a fallback. | Removes the resolver RTT from *all* domain flows for deployments that opt in | medium: changes the remote-DNS privacy/locality property; not a wire change | low (config) / product decision |
| L11 | **One relay UDP socket per connection** with `recvmsg` source-address demux, instead of 64 KiB socket + reader task per session. | Removes per-session socket syscalls + reader spawn from the first-payload path [estimate: low tens of µs]; removes the ~2.25 GiB session-pool fixed admission term; makes session creation O(1) | high: reply source authorization, per-session rate/fairness and the session reaper all key off the per-session socket; large refactor | high |
| L12 | **Coalesce duplicate-OPEN re-ACKs** (at most one ACK per flow per RTT) if the ACK survives L3. | For an N-payload burst in the first RTT: N−1 ACK DATAGRAMs saved | low | low |
| L13 | **Bundle CAPS with the first data frame direction** (or drop CAPS entirely; its 5 limits are all compiled-in defaults). | −1 DATAGRAM per connection (startup only) | low | low |

Cross-check with the parallel byte model: `analysis/rev3/wire_model.py:126-211`
scenarios A/B/E/F/G compute the same +1 packet per one-shot flow structure
(4→2 packets for the domain request/response, 3→2 for IP) and the same
`HELLO+CAPS` per-connection setup; this audit adds that those packets are *not*
on the RTT path, that L6 is the only lever that removes a multi-second failure
latency, and that L1/L8 (and L10 at the product level) are the only levers that
remove a *wait*.

---

## 5. Verification of the stated facts (and contradictions found)

All eleven "key established facts" from the task brief were checked against the
tree. Nine are exactly right; two need a precision fix; three documentation
contradictions were found (not code bugs).

| Stated fact | Verdict | Evidence |
|---|---|---|
| Auth token on a 1-RTT uni stream; `authenticate()` before datagram processing | **confirmed** | client writes token only after handshake (`client auth.rs:357-365,388-415`); server awaits `authenticate` before `handle_conn` (`main.rs:853-880`); token read `auth.rs:22-47` |
| Server pre-HELLO buffer 8 frames / 16 KiB | **confirmed** | `accept.rs:1100-1104,1450-1469` |
| FLOW_ACK sent per installed flow | **imprecise**: per accepted *OPEN frame*, duplicates re-ACK | `accept.rs:2333-2343`, `2155-2172`, duplicate falls through `2205-2219` |
| Server requires client FLOW_ACK before it stops re-sending `OPEN\|SRC` for a learned reply source | **confirmed**, with the `target == src` exception (IP-target flows need no ACK) | `r2_flow.rs:96-109,325-366`; `accept.rs:1846-1852` |
| DNS slow path buffers pending OPEN payloads (…/take_pending_payloads) with a 16 pending cap and 5 s timeout | **imprecise**: 16 = concurrent *lookups* per connection (`MAX_PENDING_DNS_OPENS`); payload queue = 64 items / 256 KiB per connection; 5 s = resolver budget (`DNS_LOOKUP_TIMEOUT`), not a payload timer | `accept.rs:1106-1121`; `dns/store.rs:100`; `accept.rs:1375-1386` |
| SESS_CLOSE sent 3× on reap | **confirmed** | `accept.rs:1533-1540`; callers `accept.rs:2807-2809`, `reader.rs:1481-1483` |
| Per-session 64 KiB socket + reader task | **confirmed** | `lib.rs:243-254`; `reader.rs:1746-1807` |
| 8192-session global pool | **confirmed** | `table.rs:461,470-473` |
| 4096-flow registry per connection | **confirmed** | `r2_flow.rs:40`; `accept.rs:1225-1227` |
| Domain-path failure behaviour | **confirmed as loss** (not inline fallback): triggering + queued payloads dropped | `accept.rs:2067-2089,2110-2130,1200-1210` |
| `reply_src_acked` blocks downlink compression until client FLOW_ACK | **confirmed** | `r2_flow.rs:325-366`; `accept.rs:1846-1852` |

Documentation contradictions (no code change implied, but the redesign doc must
not repeat them):

1. `README.md:293` — "Downlink compression is driven by the client's local
   binding (`reply_src`); it does not wait for an uplink ACK." For the
   **server's** downlink sender this is false for domain targets and port
   changes: `match_source` returns `Rebind` until `reply_src_acked`
   (S7). It is true only for bindings whose target *is* the reply source.
2. `README.md:291` — a reply outside the 16-address resolved cap is "inline under
   full-cone, refused by the restricted filter". The full-cone path installs a
   server-owned binding and sends `OPEN|SRC`, not `INLINE`
   (`reader.rs:1060-1072`); `INLINE` is only the table-bound fallback.
3. `client auth.rs:88-93` — "the egress cache refuses to publish a connection
   until [CAPS]"; the cache explicitly publishes pre-CAPS
   (`client egress.rs:413-421`).

Also note for the redesign: the spec's own §5.5 proposal (control plane on one
QUIC bidi stream, `FLOW_ACK` carrying the resolved address) is directionally
right for reliability (L9) but still keeps a per-flow handshake-shaped ACK; L2
(repeat-context + repair) is strictly cheaper on the data path and is what the
rev3 byte model already assumes.

---

## 6. Assumptions and uncertainties

| # | Assumption | Grade | How to settle |
|---|---|---|---|
| 1 | QUIC/IPv4/DATAGRAM framing ≈57 B per one-DATAGRAM packet (20 IP + 8 UDP + 27 QUIC short header/tag + 1 type + 1–2 length) | [derived] from `analysis/rev3/wire_model.py:15-17`; standard QUIC short-header math | measure packet bytes on the wire (tcpdump/`ConnectionStats`) |
| 2 | Header sizes: steady 2 B, `OPEN` v4 14 B, `OPEN` v6 26 B, `OPEN` domain 11+L, `INLINE` v4 13 B, `FLOW_ACK` 4 B for id<128 | [code]+[derived] | golden tests already pin several (`r2.rs:1113-1129,1266-1314`) |
| 3 | Session creation cost (5 syscalls + task spawn) is low tens of µs | [estimate] | `hotpath_bench udpdomain` vs `udp` with a cold session per packet; or perf |
| 4 | Warm DNS OPEN's task spawn costs single-digit µs | [estimate] | A/B after L7; the bench's `udpdomain` cells with a cached name |
| 5 | Typical resolver RTT is one nameserver RTT (10–70 ms) | [estimate] (network-dependent) | netem matrix cells / DNS query log |
| 6 | The client ACKs every `OPEN\|SRC`; one client ACK per binding frame | [code] `client dispatcher.rs:1125-1131` | — |
| 7 | A 32-payload burst in the first RTT yields up to 32 `FLOW_ACK`s | [derived] (one ACK per accepted OPEN, §S3) | counter `r2_stats::ACKS` vs `OPENS` with a burst bench |
| 8 | 180 s idle reaps do not normally race an active app; the blackhole needs a reader exit + 3 lost closes | [derived] from `table.rs:469`, `reader.rs:1429-1506`, `accept.rs:1533-1540` | fault-injection test: drop the 3 CTL DATAGRAMs |
| 9 | "MQP adds no mandatory RTT" assumes the client's optimistic pre-CAPS send and the 1-RTT token both land in the first post-handshake flight | [derived]; `client egress.rs:413-421`, `main.rs:853-880` | in-order/multi-worker scheduling; measure first-payload time-to-target on a warm pool |
| 10 | The cross-session `TRAIN` gain is not modelled here (that is the byte model's job) | n/a | `hotpath_bench udpfanout` / `udpps` |

Known uncertainty that could flip a conclusion: if the client's stager ever holds
a payload waiting for a burst boundary under real app pacing, the "stager adds no
latency" (S16) result would need re-checking — the code path says no
(`client assoc.rs:771-776`), but this is exactly what a p99 measurement would
confirm.

---

## 7. What to measure (do not run now; these are the confirmation cells)

The repository already has the machinery; each claim above maps to a cell.

1. **One-shot-flow packet/byte overhead (S3/S18, L2/L3).**
   `examples/hotpath_bench.rs` mode `udpdomain` (domain target, one datagram per
   flow) and `udp` (IP target) with **IP-target vs domain-target** side by side,
   at 8 B–512 B payloads; count client/server DATAGRAM sends and wire bytes from
   `ConnectionStats`. Expected current-wire signature: 4 packets per one-shot
   domain flow (OPEN, ACK, OPEN|SRC, ACK) vs 2 for a no-ack wire
   (`analysis/rev3/wire_model.py:126-140`); the server counters to read are
   `r2_stats::OPENS`, `ACKS`, `OPEN_SRC_SENT`, `STEADY_SENT`, `FLOW_ACKS_RECV`
   (declared `accept.rs:853-900`).
2. **ACK-gated compression window (S4/S7).**
   High-rate same-flow bench (`udpps` / `udppaced`, 64–200 B, one association):
   compare frames/payload in the first 50 ms vs steady state; latency histograms
   of the first N payloads. `r2_stats::STEADY_SENT`/`OPEN_SRC_SENT` ratio over
   time is the direct observable.
3. **HELLO-loss stall and pre-HELLO overflow (S1, L1).**
   `scripts/linux-bench-matrix.sh` cells at 0.5 %/2 % loss, `udp` mode, with a
   9+-datagram burst at connection start; read `PRE_HELLO_BUFFERED` /
   `PRE_HELLO_DROPPED`. Add a targeted fault-injection (drop the first HELLO) to
   measure the 200 ms stall directly.
4. **DNS critical path (S5/S6/S20, L6/L7/L8).**
   `udpdomain` with (a) cold name, (b) warm name, (c) a name that fails to
   resolve, (d) a name resolving to a filtered address. Count DNS cache
   hit/miss events, `r2_stats::DNS_OPEN_DROPS`, `r2_stats::REJECTS` and the
   end-to-end first-reply latency; the (c)/(d) cells are the payload-loss
   measurement (expect exactly one lost datagram per attempt + the 1 s reject
   window from `client rev2.rs:83-92`).
5. **Session reap blackhole (S10, L9).**
   Fault-injection test (drops the 3 `SESS_CLOSE` DATAGRAMs) with an
   uplink-only flow: confirm the association's payloads stop being forwarded
   while the connection stays alive. This is a test, not a bench.
6. **Limiters never queue (S12).**
   Saturate `max_connections` / session pool / dial limiter in the matrix and
   confirm the observable is a drop/reset (`dgram_drops::FAIR_SHARE`,
   `SESSION_FULL`, `DIAL_PERMIT_REFUSED`, `STREAM_SHARE_REFUSED`), never an
   increased first-byte latency.
7. **TCP dial timing (S13).**
   `hotpath_bench tcp` + a SYN-delaying target under netem: first-downlink-byte
   time should be `0.5 RTT header one-way + target RTT`, with no extra leg from
   the MQP dial ACK (compare against `TCP_DIAL_ACK_TIMEOUT` absence by patching a
   test client, not production).
8. **Stager latency (S16).** `udppaced` (one datagram per burst, paced): p50/p99
   should track the app's pacing + one `flush_staged` pass; any fixed ≥1 ms floor
   would expose a hidden wait.
9. **Optional but valuable instrumentation gap.** The server's `r2_stats` module
   (`accept.rs:848-1010`) has no consumer in the 60 s reporter
   (`reporter.rs:148-226` only prints `udp_stats`/`dgram_drops`); its counters
   are currently read only by unit tests. Adding one line
   (`opens/acks/rejects/steady/open_src/flow_acks/hello/caps/pre_hello_dropped/
   dns_open_drops/full_cone`) to the 60 s report would make every claim in this
   audit directly observable in the matrix runs. (Read-only observation for the
   Lead; not modified here.)

---

## Appendix A — byte reference and break-even arithmetic

Frame sizes from `src/mqp/r2.rs` (`varint(wire_id)=1` for ids < 128; IPv4 addr
= 7 B, IPv6 = 19 B, domain = 4+L B, from `src/mqp/addr.rs` via the length
functions at `r2.rs:275-289,686-700`):

| Frame | Formula | id<128, IPv4 | domain (L) |
|---|---|---:|---:|
| `DATA` steady | `1 + varint(id) + payload` (`r2.rs:275-277`) | 2 B | 2 B |
| `DATA OPEN` | `2 + varint + 4 + addr + payload` (`r2.rs:281-283`) | 14 B | 11+L B |
| `DATA INLINE` | `2 + 4 + addr + payload` (`r2.rs:287-289`) | 13 B | 10+L B |
| `FRAG` steady | `1 + varint + 4 + 1 + 1 + chunk` (`r2.rs:686-688`) | 8 B | 8 B |
| `FLOW_ACK`/`FLOW_REJECT` | `3 + varint(id)` (`r2.rs:906-914`) | 4 B | 4 B |
| `FLOW_CLOSE` | `2 + varint(id)` | 3 B | 3 B |
| `SESS_CLOSE` | 7 B | 7 B | 7 B |
| `HELLO` / `CAPS` | 8 B / 17 B | — | — |

Per-flow arithmetic (IP target, id<128, one payload each way), baseline =
inline every frame:

- uplink `OPEN` 14 vs `INLINE` 13 → **+1 B**
- downlink steady 2 vs `INLINE` 13 → **−11 B**
- `FLOW_ACK` 4 B + one packet ≈57 B → **+61 B**
- net **+51 B and +1 packet per one-shot flow**; each *additional* payload to
  the same flow saves 12 B (uplink) or 11 B (downlink) ⇒ break-even at
  ⌈51/11.5⌉ = **5 payloads** after the first exchange. Domain target: +63 B
  and break-even ≈ 5–6 payloads (uplink saves 9+L B).

A 50 B/100 B request/response therefore pays ~51 B and one extra packet; a
1000-payload flow pays the same once and then saves ~11 B × 1000.

---

## Appendix B — files read for this audit

`src/mqp/r2.rs`, `src/mqp/r2_flow.rs`, `src/bin/myquic2-server/{main,auth,accept,reader,forward,table,pin,tcp,reporter}.rs`,
`src/bin/myquic2-client/{auth,rev2,dispatcher,egress,assoc,forward,socks}.rs`,
`src/dns/{store,resolve,memo}.rs`, `src/transport/{build,limits}.rs`,
`src/tcp/pump.rs`, `src/udp/r2_stage.rs`, `README.md` (§MQP-3 rev2 wire,
§1–§17), `MQP3_REV2_SPEC.md`, `MQP3_REFACTOR_ANALYSIS.md` (§5.5–§6),
`examples/hotpath_bench.rs` (modes only), `scripts/linux-bench-matrix.sh`,
`analysis/rev3/wire_model.py`.

No file under `src/` was modified; nothing was built or run.
