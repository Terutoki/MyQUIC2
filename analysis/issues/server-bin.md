# myquic2-server binary audit — severe perf / memory / logic defects

Scope: `src/bin/myquic2-server/**` at HEAD `8f0d685` (clean tree). Commit `8f0d685` is the recent
audit-hardening batch; its server-bin diff (`main.rs`, `accept.rs`, `reader.rs`, `table.rs`, `tcp.rs`)
was read specifically for regressions, and the hardening claims were checked against the code
(README §12 and `MQP3_REV2_SPEC.md` §4/§5 treated as hypotheses, not evidence).

**Method (executed vs read).** Executed: `git status/log/show 8f0d685` (server-bin diffs),
`grep`/`sed` over the server bin and the shared modules it calls (`mqp/r2.rs`, `mqp/r2_flow.rs`,
`udp/r2_reasm.rs`, `udp/r2_stage.rs`, `udp/r2_frag.rs`, `udp/send.rs`, `mqp/v3.rs`,
`dns/policy.rs`, `config/tuning.rs`, `transport/build.rs`, `transport/limits.rs`), and inspection of
the vendored `quinn 0.11.12` / `quinn-proto 0.11.19` sources in `~/.cargo/registry` (stream-credit
raise API, receive-assembler over-allocation bound). Read in full: `main.rs`, `auth.rs`, `memo.rs`,
`reporter.rs`, `accept.rs` (2742 lines), `reader.rs` (1852), `table.rs`, `forward.rs`, `pin.rs`,
`tcp.rs`. `tests.rs` used only for intended invariants. Not executed: no build, no test suite, no
benchmark (read-only audit; the task states `cargo check --workspace --all-targets` passes). No
source/config/test file was modified.

Severity: **S0** = remote crash / data corruption / memory blowup / admission bypass; **S1** =
serious under normal production load; **S2** = material but conditional / needs a specific trigger.
No S0 defect was found; the strongest defects are availability/resource-exhaustion and
hot-path-amplification classes.

## Findings (severity-sorted)

| # | Sev | Category | Location | One-line | Conf |
|---|-----|----------|----------|----------|------|
| 1 | S1 | logic / resource lifetime | `forward.rs:499-540, 554-613`; `reader.rs:1421-1437`; `accept.rs:1366-1379` | The `SESS_CLOSE × domain-DNS` fix landed only in the rev2 `DATA OPEN` path; the *generic* DNS slow path recreates a just-closed session deterministically (socket+task+global permit leaked until the 180 s idle sweep) | high |
| 2 | S1 | performance / DoS | `accept.rs:1275-1280, 1366-1384`; `r2_flow.rs:500-508`; `r2_reasm.rs:547` | Every incoming `CTL SESS_CLOSE` costs an O(4096) connection-registry `HashMap::retain` (+ O(256) reassembler retain, shard write lock) **before** the "was there even a session?" early-out — a ~30-byte datagram buys tens of µs of pointer-chasing; no CTL rate cap | high |
| 3 | S1 | availability / admission | `main.rs:625-656`; `auth.rs:12-24` | Pre-auth admission is a 256-slot semaphore held for `PRE_AUTH_TIMEOUT`/`AUTH_TIMEOUT` (5 s each) by a peer that never authenticates; ~26–51 stalled handshakes/s refuse **all** new connections, including legitimate token holders (same shape in tokenless mode via `conn_limit` + `HANDSHAKE_TIMEOUT`=10 s) | high |
| 4 | S1 | performance / fairness | `forward.rs:487-536`; `tcp.rs:156-164`; `accept.rs:24` | One admitted connection can hold all 1024 process-wide DNS-slow-path permits (the per-connection `DnsGate` overwrites and always `Proceed`s — it does not bound concurrency) and all 4096 global dial permits, so other clients' cold-name UDP and every TCP CONNECT fail | medium-high |
| 5 | S2 | performance | `accept.rs:288-340, 2280-2347` | The connection fast-session table is 16 slots while the code itself documents that "one connection routinely carries hundreds of sessions"; beyond 16 live associations every datagram is a full slow path (2–3 shard read locks, DNS memo, 255-byte pin copy, **unbatched** send) | medium |
| 6 | S2 | memory leak / regression | `reader.rs:1379-1400` | New `no_live_entry` guard suppresses the reader-exit registry purge when a same-id session was recreated in the window, leaking the dead entry's bindings until connection close — the purge is already scoped to the dead entry's own snapshot, so the guard is unnecessary (introduced by `8f0d685`) | medium |
| 7 | S2 | performance / lifecycle | `reader.rs:1181-1202, 1314-1325`; no `stage.lock().clear()` in server bin | The connection stager is drained only at a session reader's burst boundary; after a `Blocked` drain the queued datagrams are not retried until the next reply on any session, so a quiet tail can sit until connection close and is then dropped without any counter | high |
| 8 | S2 | observability / silent drops | `reader.rs:1106-1125`; `udp/r2_frag.rs:196-250` | Rev2 large-reply `Blocked` (DATAGRAM send buffer full) and partial-fragment failures are dropped without any `dgram_drops`/`udp_stats` booking, unlike the staged small-reply path | high |
| 9 | S2 | performance / allocation | `reader.rs:1052-1094`; `Reader::handle_session_reply`; `r2_stage.rs` push/pack | Every small downlink reply pays an owned `Bytes::copy_from_slice` + stager node + a fresh encoded frame allocation (2–3 allocs/reply) because the stager is connection-shared | medium |
| 10 | S2 | performance / hot-path stall | `accept.rs:2201-2216`; `reader.rs:1558-1567, 1604-1620, 1846-1848` | Reap paths run their cleanup synchronously on the packet/shard runtime: per reaped session one registry remove **and three `CTL SESS_CLOSE` datagrams**; a 4096-session/4096-binding connection produces ~12k `try_send_datagram` + 4k registry write locks inline, milliseconds of stall on the shard that also drives QUIC | medium |

---

## Detail

### 1. S1 — Generic domain-DNS path resurrects a session after `CTL SESS_CLOSE` (incomplete fix of the P0 it claims to close)

*Trigger path (any peer that can authenticate — or every peer on the tokenless default):*
`DATA INLINE(domain)` / v2 `0x02` domain datagram / v3 `SINGLE|TRAIN` inline domain (all reach the
same slow path, and the legacy forms do not even require `HELLO`) → `forward_v3_item` /
burst-loop → `forward_server_dgram` (`forward.rs:435`) → `ForwardResolution::Unresolved` →
`tokio::spawn(...)` at `forward.rs:516` → `deliver_resolved_server_dgram` → after the DNS await,
`get_or_create_sess(...)` at `forward.rs:585` with **no cancellation token**.

`CTL SESS_CLOSE` only cancels lookups registered in `pending_dns_opens`
(`accept.rs:1366-1372`, `cancel_pending_opens_for_session`, `accept.rs:1077`), and only the rev2
`DATA OPEN` domain handler registers those (`begin_pending_open`, `accept.rs:1709`). The generic
DNS waiter is not registered at all and calls the *unguarded* creation:

```rust
// forward.rs:585  (inside deliver_resolved_server_dgram, after `resolve_all_cached(..).await`)
let sock = match get_or_create_sess(
    ss, cd, conn_id, s, Some((host, port, dst, DNS_CACHE_TTL_MS)), r2,
).await
```

`get_or_create_sess`'s own doc (`reader.rs:1421-1427`) asserts the opposite of the truth for this
caller: "every caller here is a *live* datagram path whose session cannot be cancelled behind its
back". The caller is a spawned task that outlives the datagram, and `SESS_CLOSE` can remove the
session while it waits: `take_session` sees no entry (the session is created only *after* DNS
completes), so it reaps nothing; the task then publishes a socket + reader task + global session
permit for the closed association. Note that for a *new* association the session does not even exist
at close time, so the leak is deterministic, not a 50/50 race: delay the DNS answer (attacker's own
authoritative zone), send the datagram, send `SESS_CLOSE`, then let the answer land.

The fix in `8f0d685` (`get_or_create_sess_guarded` + `cancel_pending_opens_for_session`) covers
`r2_forward_domain_open_bg` (`accept.rs:1577`) only.

*Impact at scale:* each leak pins one of the process-wide `MAX_SESSIONS_GLOBAL = 8192` session slots
(socket + 8 KiB reader buffer + reader task) and is reclaimed only by the 180 s idle sweep
(`SESS_IDLE_MS`). One connection can keep up to `fair_sess_cap()` = 4096 leaked sessions; two
connections exhaust the pool. The DNS slow path admits 1024 concurrent lookups
(`DNS_SLOW_PATH_PERMITS`, `DNS_LOOKUP_TIMEOUT` = 5 s), so with a 1–5 s attacker-controlled answer
delay a peer can generate hundreds of leaks per second — the pool is exhausted in seconds and stays
exhausted (every legitimate new UDP association gets `SESSION_FULL`) for ~180 s after the attacker
stops. It also violates the documented close contract ("Close purges … the session's stager items
… a late frame then finds no live binding", README §"Close means close").

*Residual second race (same root):* even on the *guarded* rev2 path, the "cancelled" re-check
(`accept.rs:1603`) and `r2_install` (`accept.rs:1612`) are not performed under the registry lock.
Sequence: `session_r2_flows` returns a live handle → `SESS_CLOSE` runs `take_session` +
`registry.remove_session` → `registry.insert` succeeds and the `rcu` publishes into the now-orphaned
handle → an `Open` binding with a dead `session` stays in the registry (and its steady frames later
re-create the session through the unguarded datagram path). The window is small, so this half is a
medium-confidence race; the generic-path leak above does not need it.

*Fix direction:* thread the cancellation flag (or a closed-session tombstone/epoch) through the
generic slow path and `deliver_resolved_server_dgram`, and check it inside the shard write critical
section of `get_or_create_sess` (i.e. route the generic waiter through the guarded variant);
additionally re-check the flag inside `r2_install`'s registry
critical section, or drop the binding if `session_r2_flows` no longer names a live entry *after*
the insert.

### 2. S1 — `CTL SESS_CLOSE` is an O(4096) CPU amplifier per ~30-byte datagram

```rust
// accept.rs:1275
pub(crate) fn r2_close_session(ss: &SessTable, state: &R2ConnState, sess: u32) -> bool {
    let entry = ss.take_session(sess);
    let purged = state.registry.remove_session(sess);   // <-- before the `entry == None` early-out
    ...
// r2_flow.rs:503
pub fn remove_session(&self, session: u32) -> usize {
    let mut map = self.map.write();
    let before = map.len();
    map.retain(|_, b| b.session != session);            // walks every binding + Arc deref
    before - map.len()
}
```

The `SESS_CLOSE` arm (`accept.rs:1366`) additionally runs
`cancel_pending_opens_for_session` (mutex + ≤16-entry scan), `r2_reasm.drop_session` (retain over
≤256 partials, `r2_reasm.rs:547`) and `stage.lock().drop_session`, then `r2_close_session`, whose
registry walk runs **even when `take_session` found nothing** — i.e. for the common retransmission
case (the client sends `SESS_CLOSE` ×3, spec §3.4) and for a peer sending arbitrary session ids.
There is no rate limit and no dedupe: `STALE_CLOSES` only counts, it does not short-circuit
(`accept.rs:1285-1287`). I found no CTL rate/total cap anywhere on the server, although
`MQP3_REV2_SPEC.md` §3.4 specifies "Control frames have rate/total caps".

*Attacker recipe:* one authenticated (or tokenless-default) connection: 64 sessions × 64 `DATA OPEN`
IP frames (each one forwarded syscall to a public host) fills the per-connection registry to its
4096 cap and the reverse tables to their 64 caps, then send random-id `SESS_CLOSE` CTLs. Every
7-byte CTL payload now walks 4096 `Arc<FlowBinding>` allocations (cache-miss pointer chasing;
tens of µs) while holding the connection registry **write** lock (which blocks the same connection's
steady-frame `registry.get` read locks), plus the session shard write lock for `take_session`.

*Impact:* a ~30–50-byte wire frame buys ~10–100 µs of CPU on the shard runtime that also drives that
endpoint's QUIC, i.e. a 10^4–10^5× amplification; a modest packet rate (≈20–50 kpps, a few Mbit/s)
saturates a core and degrades every other connection on the shard. The baseline cost is already
~O(256+16) iterations with an empty registry, so it does not need the fill.

*Fix direction:* purge by the removed entry's own reverse table (≤64 ids — the entry is available
from `take_session`), keep the by-session-id scan only for the entry-missing case and make that path
cheap (e.g. a per-connection `session -> ids` index, or a bloom/count gate), and add the
spec-mandated CTL rate/total caps (`STALE_CLOSES` as the dedupe counter is not enough).

### 3. S1 — Pre-auth admission slots are trivially held open by an unauthenticated peer

```rust
// main.rs:641
let pending = if st.auth_enabled {
    match st.pending_limit.clone().try_acquire_owned() {
        Ok(p) => Some(p),
        Err(_) => { /* warn_once_per_sec */ drop(incoming); continue; }
    }
} else { None };
```

The pending slot is acquired **before** the handshake and released only after `authenticate`
returns (`main.rs:744`), which is bounded by `PRE_AUTH_TIMEOUT` (5 s handshake) + `AUTH_TIMEOUT`
(5 s token read) — `auth.rs:12-24`. A peer that completes the handshake (or not) and simply never
opens the claimed uni stream holds a slot for 5 s; a client that opens no token stream at all never
needs a valid certificate. Holding all `MAX_UNAUTH_CONNECTIONS = 256` slots costs
256/5 s ≈ **51 new connections per second**, and every subsequent `Incoming` is dropped
(`drop(incoming)`) — legitimate clients included. With `auth_token` empty the same denial is even
cheaper through `conn_limit` (256 permits held for `HANDSHAKE_TIMEOUT` = 10 s ⇒ ≈26 half-open
handshakes/s). `warn_once_per_sec` only logs one line per second; nothing backs off, evicts the
oldest pending handshake, or isolates the source.

*Impact:* new-connection admission is denied process-wide while the attack runs; a network flap
that forces legitimate clients to reconnect during the attack turns into a service outage. The
existing authenticated connections are unaffected.

*Fix direction:* cap pending handshakes per source address (and/or shrink to a short
`PRE_AUTH_TIMEOUT` retry-based budget), release the pre-auth slot at handshake completion and gate
only the token exchange on it, or require a (cheap) proof-of-work/retry token before occupying a
pending slot.

### 4. S1 — No per-peer share for two process-wide pools a single connection can drain

*DNS waiters.* `forward_server_dgram` takes from the **global** 1024-permit
`dns_slow_path_limiter` (`forward.rs:487`) and then claims through `DnsGate`
(`forward.rs:499`). `DnsGate` has only 8 slots but is not a rate limiter: when all slots are live it
overwrites a slot round-robin and still returns `GateClaim::Proceed`
(`forward.rs:242-258`). So one connection has **no per-connection bound** on concurrent lookups; it
can hold all 1024 permits for up to `DNS_LOOKUP_TIMEOUT` (5 s) with unique attacker-controlled
names. During that window every other client's cold-name datagram gets `DNS_BUDGET` and every
domain `CONNECT` gets reset `0x04` (`tcp.rs:100-106`), and the attacker repeats at will.
(*Unauthenticated/tokenless peers get the same ability.*)

*Dial permits.* `dial_limiter()` is a global 4096-permit semaphore (`accept.rs:24`) taken per
`handle_tcp_stream` (`tcp.rs:156`). One connection may spawn up to
`stream_share(1) = min(16384, MAX_BIDI_STREAMS_PER_CONN) = 8192` relay tasks, so a single peer can
hold all 4096 dial permits with streams whose headers point at black-holed public IPs (each dial
waits the 4 s budget) and reset every other client's `CONNECT` `0x04`. The per-connection shares
that exist for header tasks (`HEADER_CREDIT_PER_CONN`) and stream tasks do not cover the dial pool.

*Fix direction:* per-connection (ideally per-source-IP) bounded shares in front of both pools, or
fail-fast accounting that reserves the pool per peer (e.g. `stream_share`-style divisor for dials
and a hard per-connection DNS-waiter cap that `DnsGate` enforces instead of overwriting).

### 5. S2 — 16-slot fast session table versus "hundreds of sessions per connection"

`FAST_SESS_SLOTS = 16` (`accept.rs:288`), while the table's own comment documents the workload it
must serve:

> "the client multiplexes every UDP association of an egress class onto one connection …
> so one connection routinely carries hundreds of sessions. With one slot, every datagram for any
> *second* session missed …" (`accept.rs:2300-2305`)

and then sizes the table at 16 ("covers … DNS + a game + a handful of flows", `accept.rs:2316-2319`).
With A active sessions > 16, `arm_fast` evicts the quietest entry on every miss
(`fast_arm_index`, `accept.rs:399`) and an interleaved workload over >16 associations misses on
essentially every datagram. A miss is not a cheap fallback: `resolve_fast` scratch path →
`try_stage` miss → `forward_server_dgram` slow path (`forward.rs:435`) → `remember_dst` shard read
lock, `get_or_create_sess` probe, **a per-datagram `udp_try_send` that bypasses the staged
`sendmmsg` batching** (`forward.rs:463,478`) — plus `arm_fast` (`sess_memo_lookup` +
`session_flows` shard read + 255-byte `ConnPin` copy). The file's own measurement ("70.2 µs vs
76.3 µs server CPU per delivered datagram, 20 000 datagrams, one vs two sessions", `accept.rs:
2310-2313`) shows the fast/slow delta; with >16 sessions the slow path is the steady state. Also
`try_stage`'s documented invariant "every frame kind arms the table" does not help when the table
evicts between datagrams.

*Impact:* for the multi-association shape the protocol is designed for (client supports 4032
associations; README/client comments say associations of one egress class share a connection), the
server pays several shard read locks + an unbatched syscall per datagram instead of one `sendmmsg`
per burst — CPU and p99 latency scale with the association count. No benchmark exists for >16
sessions. *Fix direction:* size the fast table from the documented association target (e.g.
`MAX_FAST_*` 256, with a per-connection memory charge) or split it per shard/epoch; at minimum add a
multi-session benchmark.

### 6. S2 — Reader-exit registry purge leaks bindings when the session id was recreated

```rust
// reader.rs:1379 (introduced by 8f0d685)
if let Some(registry) = r2_registry && let Some(r2_flows) = removed_r2 {
    let no_live_entry = { let r = ss2.shard(s).read(); !r.contains_key(&s) };
    if no_live_entry {
        for binding in r2_flows.load().iter() {
            binding.mark_closed();
            if registry.remove(binding.wire_id).is_some() { n += 1; }
        }
    }
}
```

This reader removed its own entry (it holds that entry's `r2_flows` snapshot), then re-acquires the
shard read lock to test emptiness. A datagram for the same session id arriving in that window is
served by the datagram reader, which creates a new session entry
(`get_or_create_sess` read path → write path). `no_live_entry` is then false and the **dead**
entry's bindings are never marked closed and never removed from the connection registry. The guard
is unnecessary: the loop already removes only ids from the dead entry's own snapshot, so a
recreated session's bindings cannot be touched. (`8f0d685` replaced the previous unconditional
`registry.remove_session(s)`; the replacement fixed the recreated-session purge but introduced
this leak.)

*Impact:* up to 64 registry entries per race leak until the connection ends (the registry cap is
4096); a client that reconnects/churns sessions with in-flight datagrams can fill the registry,
after which every new `DATA OPEN` is answered `FLOW_REJECT(TABLE_FULL)` and the client falls back
to `INLINE` permanently (larger frames, no compression). Old bindings also remain forwardable; the
wire ids are never reused so they cannot splice a new flow, but they keep dispatching to dead
sessions' targets.

*Fix direction:* drop the `no_live_entry` guard (the snapshot scoping is what protects a recreated
session), or check generation identity (e.g. compare `Arc::ptr_eq` of the entry's `r2_flows` handle)
instead of key presence.

### 7. S2 — Connection stager has no retry/timer: a `Blocked` drain strands queued downlink datagrams

Small replies are pushed into the shared `R2Stager` (`reader.rs:1086`) and drained only at the
session reader's burst boundary (`reader.rs:1320`). `stage_verdict` maps `Blocked` to
`StageDrain::Ok` (`reader.rs:290-298`), i.e. a full quinn DATAGRAM send buffer leaves the items
queued and the reader simply goes back to `recv_from`. Nothing drains the stager on the 60 s idle
tick (`reader.rs:1186-1202` — the tick branch only checks idle/close and refreshes the budget), and
the server bin never calls `R2Stager::clear()` on teardown (grep: only `drop_session`/`drop_flow_scoped`).
There is no `flush`/timeout wakeup.

*Trigger/impact:* a saturated downlink (the exact case where `Blocked` is the steady state) followed
by silence (a target's last burst, a DNS-style request/response, a game keepalive whose reply lands
in a full buffer) → the tail of replies (up to the stager cap, 1024 items / 256 KiB) is not sent and
not counted; it is retried only if some session later pushes another reply (drain) — possibly never
before connection close, at which point it is dropped silently with the `R2ConnState`. This is a
silent-loss + indefinite-delay hole in an otherwise carefully accounted path, and it contradicts
"a reply that cannot be staged is a single send"/UDP-drop semantics: the datagram is neither sent
nor booked as dropped.

*Fix direction:* drain on the idle tick (or arm a short retry timer when `drain_staged` returns
`Blocked`), and on connection/stager teardown account the queued items (`EGRESS_DEAD`/`BUFFER_FULL`)
instead of dropping them silently.

### 8. S2 — Rev2 large-reply drops are not booked anywhere

```rust
// reader.rs:1106
let sent = r2_send_large_reply(c2, s, &mut *frag2, r2_match.as_ref(), src, payload, *limit);
match sent {
    R2LargeReply::Sent | R2LargeReply::Blocked => {}     // <-- Blocked: no counter at all
    R2LargeReply::TooLarge => { /* only reprobe the budget */ }
    ...
```

`r2_send_large_reply` books `udp_stats::payload` on `Sent`; a `try_send_datagram` `Blocked`
(`udp/send.rs:84`, the datagram send buffer full) simply drops the payload. The fragment branch has
the same gap: `R2Fragmenter::send` books per-payload stats only when **every** frame was queued
(`udp/r2_frag.rs:250-258`) and returns `PayloadSend{failed}` for a partial/blocked payload without
booking the drop — only its own "too large" reasons bump `dgram_drops::TOO_LARGE`
(`r2_frag.rs:263-270`). Compare the staged small path, which books `BUFFER_FULL` on requeue
overflow/drop (`reader.rs:319-322, 355-356`). The 60 s reporter's last-hop line (`reporter.rs:
169-173`) only covers the UDP retry pool, not QUIC DATAGRAM drops.

*Impact:* under downlink saturation (a client that does not read, a bursty target) large replies
(> `BATCH_SMALL_MAX`) are silently lost while the operator's only signal says nothing. Any
diagnosis of "UDP works small, not big" is blind.

*Fix direction:* book `dgram_drops::BUFFER_FULL` per dropped payload for the rev2 single-frame and
fragment paths (and surface it in the 60 s line), mirroring the stager's contract.

### 9. S2 — Per-reply allocation on the staged downlink path

Every reply ≤ `BATCH_SMALL_MAX` is copied into an owned `Bytes` for the connection stager
(`reader.rs:1070-1074`, because another session's reader may drain it), then the drain re-encodes it
into a fresh frame `Bytes` (`r2_stage.rs` pack/`encode_*`). That is 2–3 heap allocations and at
least one full payload copy per reply, on the hottest server path (downlink relay), for a design
whose predecessor staged into a reused arena (`reply_stage`/`flush_reply_train`, now `#[cfg(test)]`).
The push also takes the connection-wide stager mutex once and the burst-end drain twice
(`is_empty` probe + pack).

*Impact:* at high reply rates (many associations on one connection, exactly the intended shape)
this is the dominant allocator traffic in the process; mimalloc softens it but does not remove the
copy. The batching gain (0.74 frames/payload measured) still helps, so this is a trade-off rather
than a pure waste — flagged because per-reply owned copies are explicit hot-path work in the
server's reply loop and no measurement of the cost exists in the tree.

*Fix direction:* keep a per-reader reused `BytesMut`/arena for the common "this reader also drains
the burst" case, or let a push hand the payload to a drain on the same task before copying.

### 10. S2 — Reap cleanup runs inline and emits 3 CTL datagrams per reaped session

```rust
// accept.rs:2210-2216 (60 s sweeper task), reader.rs:1558-1566 (fair-share sweep on the
// DATAGRAM READER), reader.rs:1608-1613 (session-pool sweep on the datagram reader):
let evicted = sess.sweep_all(now);
r2_cleanup_evicted(r2, &evicted);
for entry in &evicted { r2_send_sess_close(&conn, entry.sess); }   // 3 try_send_datagram each
abort_evicted(evicted);
```

`r2_cleanup_evicted` → `r2_close_entry_bindings` removes each binding from the connection registry
one write lock at a time; `r2_send_sess_close` encodes and `try_send_datagram`s **three** frames per
entry. A connection that legitimately held `fair_sess_cap()` = 4096 sessions with 4096 bindings
(e.g. an app that abandoned many associations without `SESS_CLOSE`) produces ~4096 registry write
locks + ~12 288 `try_send_datagram` calls in one synchronous loop. In the `get_or_create_sess` case
this runs **on the datagram reader task**; in the sweeper case it runs on the current-thread shard
runtime that also drives QUIC for every connection of that endpoint. Re-triggering requires the
sessions to reach `SESS_IDLE_MS` (180 s), so this is a periodic stall rather than a per-packet
amplifier, but every such burst loses/latens packets for all connections on the shard.

*Fix direction:* send the reaps' `SESS_CLOSE` from a bounded background queue (or one coalesced
control datagram for a batch of sessions), avoid per-binding registry write locks by draining the
registry once, and keep the datagram-reader path to the O(1) decision.

---

## Checked and found sound (hypotheses that did not produce findings)

- **First-byte dispatch:** `r2::kind` matches only `0x00/0x01/0x04/0x08/0x09/0x0C`; legacy
  `0x02/0x05/0x06` and v3 `0x1X–0x4X` cannot be claimed by rev2 and vice versa
  (`mqp/r2.rs:128`, `mqp/v3.rs:98`, `accept.rs:2406-2439`). No rev2/v2/v3 misdispatch.
- **Peer-input panics:** decoders validate lengths before slicing (`get_varint`/`get_u32`/addr
  decode); `d[0]` in `handle_v3_ingress` is guarded by `is_v3` (non-empty) + `v3_sess` len≥5;
  `usable[0]` follows the `is_empty` check; `read_mqp_target` indexes only after `read_exact`;
  TRAIN count is bounded to 64 by the decoder (`r2.rs:580-650`) so the `slots`/`item_slot` arrays
  and the open-address table cannot overflow; reassembler positions are checked against
  `MQP_FRAG_MAX_PAYLOAD`/frame bounds. I found no panic/index path reachable from a datagram
  (release is `panic = "abort"`, so this mattered).
- **Locks across `.await`:** none. `get_or_create_sess_guarded` (the only large "async" helper on
  the creation path) contains no await points at all; all other lock uses (`stage.lock()`,
  `registry`, shard guards) are temporary inside synchronous helpers, and `drain_staged` performs
  the QUIC sends outside the stager lock.
- **Bounded structures:** flow registry 4096/conn, `SessionFlows` 64/session, v3 `FlowTable` 64,
  `RecentAddrs` 16, pre-HELLO 8 frames/16 KiB, `pending_dns_opens` 16/conn, `DnsGate` 8,
  both reassemblers (256 partials / 256 KiB), stager (1024 items / 256 KiB). The admission
  constants were re-derived and match the runtime checks (per-connection 19,625 KiB =
  8+4 MiB windows + 2 MiB DATAGRAM + 2×256 KiB reassembly + ~1 MiB stager + 32 KiB ingress +
  4096×904 B registry + 576 KiB pre-auth assembler; session pool ≈2.25 GiB on Linux). The quinn
  receive-assembler charge (1024 spans × 96 B/stream) is **conservative**: quinn-proto 0.11.19's
  assembler bounds retained over-allocation at `max(32 KiB, 1.5 × buffered)` and defragments, so the
  real per-stream ceiling is lower than the charge (checked because the hardening commit's P0 claim
  depends on it).
- **Fast path purity:** a steady, warmed datagram is `read_datagram` → `sess_memo`/fast-table probe
  → `mirror_record` epoch compare → `staged.push` → `sendmmsg`; no allocation, no shard lock, no DNS
  lookup, no `Bytes` copy (`d.slice_ref`), and no quinn lock before the send (verified against the
  comments at `accept.rs:2278-2289`). `flush_staged_sends` groups ≤32 frames per `sendmmsg` run on
  Linux (`accept.rs:246-281`).
- **SESS_CLOSE / FLOW_CLOSE ordering on the live path:** registry binding is removed first, then the
  session-scoped stager queue and reassembler partials are purged (`accept.rs:1344-1364`); the
  reverse-table snapshot is what `r2_remove_flow`/`r2_close_entry_bindings` use, so late frames fail
  lookup instead of re-routing (spec §5.1/§5.8). The reply reader validates a source against its
  **own** session's allowlist/flow tables/rev2 reverse table, so cross-session delivery is not
  possible from a peer-controlled wire id.
- **SSRF/`allow_private`:** IP path checks `is_global_ip_cached` before forwarding; the domain path
  filters the full resolved set (`policy_resolved`) before install and before first send, stores
  only accepted addresses in the binding, and steady frames use that stored address; the
  `resolve_pin` pin-hit path is safe because the pin is armed only from filtered addresses and
  `is_global_ip` is a pure function of the address (the fast path still re-checks via
  `fast_allow_cached`). `is_global_ip` correctly recurses into IPv4-mapped/translated/compatible
  and NAT64 forms, and its non-global table includes CGNAT/loopback/link-local/documentation/
  multicast/reserved space (`dns/policy.rs`). `map_for_dual` is applied only after the check.
- **TCP path:** header read is bounded (5 s, stack buffer, domain length validated), the two-stage
  header credit / share and the stream-share `fetch_add` reservation are race-correct, and the
  dial input is SSRF-filtered inside `dial_happy_eyeballs`. The TCP header-read stage *is* bounded
  per connection (256) — but see finding 4 for the global dial pool.

## Cross-domain notes (for the Lead / other auditors)

1. **Client-side counterpart of finding 1:** the client's SESS_CLOSE handling and its own domain
   lookups should be checked for the same "late DNS answer after close" shape; the server-bin fix
   (`get_or_create_sess_guarded`) was not applied to the generic slow path, so a symmetric hole may
   exist on the client's `rev2.rs` state if any await separates an association close from a
   resolver completion.
2. **Shared-lib drop accounting:** `R2Fragmenter::send` (`src/udp/r2_frag.rs`) and
   `try_send_datagram` (`src/udp/send.rs`) drop a payload on `Blocked` without booking anything;
   the server's finding 8 is a call-site symptom, but the missing per-payload accounting is in the
   shared module and affects the client's downlink path too.
3. **quinn endpoint incoming-connection queue:** the server accept loop drains `ep.accept()`
   quickly (permit + `tokio::spawn`), but I did not verify whether quinn 0.11.12 bounds its
   `Incoming` queue under an Initial flood. If it is unbounded, the admission-first claim deserves
   a cross-check in the transport/endpoint domain (not this binary's code).
4. **README/architecture claims:** the README's "every peer-fillable structure has a hard bound"
   and "close means close" are contradicted by findings 1, 6 and 7; the "client multiplexes
   hundreds of associations per connection" statement is contradicted by the 16-slot fast table
   (finding 5). The stale `PERF_ANALYSIS.md`/`PROTOCOL_ANALYSIS.md` were not used as evidence.
5. **Legacy v2/v3 paths are reachable without `HELLO`/wire-version negotiation** (intentional for
   old clients, per README), which is what makes finding 1 reachable even without valid rev2
   framing.
