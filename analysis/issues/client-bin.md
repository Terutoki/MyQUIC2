# myquic2-client audit — severe defects (HEAD 8f0d685)

Scope: `src/bin/myquic2-client/**` (main.rs, pool.rs, dispatcher.rs, rev2.rs, egress.rs,
assoc.rs, socks.rs, hub.rs, auth.rs, reporter.rs, util.rs). tests.rs used only to learn the
intended invariants. Read-only; no source/test/config was modified.

Method: **executed** — `git show 8f0d685 -- src/bin/myquic2-client` (whole 978-line diff) and
`git show 8f0d685^:.../rev2.rs` for the pre-fix ordering; targeted greps across the client and
its shared-library call sites (`src/mqp/r2_flow.rs`, `src/mqp/r2.rs`, `src/udp/r2_stage.rs`,
`src/udp/r2_reasm.rs`, `src/udp/r2_frag.rs`, `src/udp/send.rs`, `src/udp/retry.rs`,
`src/transport/build.rs`, `src/linux.rs`, `src/time/*`) and the server paths that produce the
client's input (`accept.rs` SESS_CLOSE/`r2_close_session`, `reader.rs` reader-exit notify,
`table.rs` idle sweeps). Full suite **not** run; no `cargo check`/test executed.

Severity: S0 crash/corruption/remote memory blowup · S1 serious under normal load ·
S2 material but conditional. "Peer" below means the configured QUIC server unless stated.

## Severity-sorted findings

| # | Sev | Cat | Location | One-line | Conf |
|---|-----|-----|----------|----------|------|
| C1 | S1 | logic/perf | rev2.rs:55, 121, 270-311, 518-535, 580; dispatcher.rs:888-897 | Server-initiated `SESS_CLOSE` is recorded in an append-only set; stale ids are never evicted, and a full set silently drops all later closes → permanent silent UDP blackhole after a server reap; any resident id puts an exclusive lock + scan on every uplink datagram | high |
| C2 | S1 | perf | main.rs:87-97, 63-69; linux.rs:184-200; README:453 | Main runtime worker count = `cores - min(planned_slots, cores)` (floor 1): **1 worker** at shipped 7-slot defaults on every ≤8-core host, i.e. all SOCKS/TCP-pump/UDP-assoc work serialized on one thread; on non-Linux no slot is actually pinned (`pin_to_core` is a no-op), so the subtraction has no basis there | high |
| C3 | S2 | perf/logic | dispatcher.rs:847, 888-897; r2_flow.rs:503-508; r2_stage.rs:246, 270-311 | Peer-controlled CTL frames have no rate limit/dedupe and their handlers do unbounded work: each `SESS_CLOSE` does a full-registry write-lock `retain` + global stager lock; each `CAPS` takes the global stager mutex. Tiny frames amplify into CPU/lock work shared with the per-packet uplink path (README:581 promises a malformed frame cannot become a CPU primitive) | high mechanism, med impact |
| C4 | S2 | logic/perf | rev2.rs:432-466 | End-of-association local cleanup (`registry.remove_session` + `stager.drop_session`) and the `SESS_CLOSE` send are inside a closure gated on `rev2.is_ready()` **and** on acquiring an egress handle; on handshake-window exits or a lost single-flight refresh the association's connection-scoped bindings/staged payloads leak for the connection's life and the server session is left to its 180 s sweep (whose later reap notification feeds C1) | high |
| C5 | S2 | perf | dispatcher.rs:1033-1051; r2_flow.rs:455-470; server accept.rs:1911 | Client TRAIN downlink resolves ids one at a time (`registry.get` = read lock + `Arc` clone/drop per distinct id) although the shared `FlowRegistry::get_batch` exists exactly for this and the server uses it; TRAIN-dict is the normal Phase-2 downlink shape (up to 64 distinct ids/DATAGRAM) | high |
| C6 | S2 | perf | rev2.rs:598-627, 225-227; r2_stage.rs:382-407, 919-975; rev2.rs:880-899 | Uplink steady path: one `Bytes::copy_from_slice` heap alloc+copy per payload, then a **connection-wide** `parking_lot::Mutex<R2Stager>` push per packet (plus 1–2 more acquisitions per burst drain) — all associations on the connection serialize; a one-slot target memo also makes multi-target associations pay a 64-entry session-table scan plus a fresh binding lookup on alternating-target traffic | high mechanism, med impact |
| C7 | S2 | logic | dispatcher.rs:806-833, 939-952; rev2.rs:907-946 | Server-owned `OPEN|SRC` flows are installed **before** the session lookup and regardless of whether any association exists; a peer can pin up to 4096 bindings/conn. 8f0d685's new capacity probe runs **before** `find_server_flow`, so once the registry is full an already-installed server-owned flow can no longer be reused (pre-fix order reused first) → avoidable INLINE on the full-cone reply path (regression) | high mechanism, low-med impact |
| C8 | S2 | logic | assoc.rs:235 | SOCKS5 UDP datagrams with `FRAG != 0` (and malformed/unauthorized-source datagrams) are dropped with **no counter and no log** (`debug!` only for the source case); RFC-1928-legal, but the reporter/README claim every drop is accounted → silent loss with no observability on a path a client may legitimately fragment | high |
| C9 | S2 | logic | assoc.rs:214-219, 426 | `expected_app_ip` pins only the control-TCP peer IP after `unmap`: an app whose SOCKS control connection is v4 (127.0.0.1) but whose UDP socket is v6 (::1), or vice-versa, has every datagram silently ignored (debug only, no counter) and the association starves/reaps at 180 s | med |
| C10 | S2 | logic | dispatcher.rs:1248-1263; egress.rs:393-405 | Two generation-pairing TOCTOUs: dispatcher takes `conn` from `wait_conn` and reads `slot.rev2()` as a later statement (quinn `ReadDatagram` drains already-buffered datagrams from a *closed* connection, so a buffered old-generation frame could be dispatched against the next generation's id tables → misdelivery/loss); egress `refresh_global` similarly loads `slot.shared` and then `slot.rev2()`. Requires a >200 ms pause between adjacent instructions (redial backoff floor), so reachability is low, but the pairing is not structural and a mispairing is a cross-generation id collision | low-med |

### C1 — SESS_CLOSE set is append-only: silent blackhole + per-datagram exclusive lock (S1)

`rev2.rs:52-55`:
```rust
/// Bounded because a peer controls `SESS_CLOSE`: past the cap the
/// notification is dropped (compression just waits for the redial) instead of
/// growing an unbounded set.
const MAX_CLOSED_SESSIONS: usize = 64;
```
`note_session_closed` (`rev2.rs:272-282`) only ever *pushes*:
```rust
if closed.len() < MAX_CLOSED_SESSIONS && !closed.contains(&sess) {
    closed.push(sess);
}
```
The only remover is `take_session_closed(sess)` (`rev2.rs:285-311`), called from
`UplinkFlows::sync` (`rev2.rs:518-535`) for **this association's** session, and `sync` runs on
**every uplink payload** (`rev2.rs:580 up.sync(rev2, sess)`). There is no expiry, no eviction,
and `clear_flows`/`retire_dead_slot` do not touch it.

Trigger/impact A — stale ids are permanent, so the set becomes a per-packet write lock:
1. A server-initiated reap (60 s sweeper, fair-share/session-pool eviction, reader error;
   `src/bin/myquic2-server/reader.rs:1352-1360`, `accept.rs:2201-2214`) sends `SESS_CLOSE` ×3.
2. The client association is idle or already exiting; nobody calls `take_session_closed` for it,
   so the id stays in the vec forever. This includes the ordinary race where both sides reap at
   the same 180 s threshold (`SESS_IDLE_MS == ASSOC_IDLE_MS == 180_000`), and the duplicate
   frames (×3) that arrive after the association consumed the first one.
3. From then on `closed_len != 0`, so **every** uplink datagram of **every** association on
   that connection takes `closed_sessions.write()` and linearly scans the vec
   (`rev2.rs:292-311`) — an exclusive lock on the per-packet path, shared with the dispatcher's
   CTL thread and all relay tasks. At 10⁵–10⁶ UDP pps this is material and it serializes the
   uplink across main-runtime workers.

Trigger/impact B — cap-full drops are **not** benign, they blackhole a session:
1. After 64 stale ids (or after a peer sends 64 distinct `SESS_CLOSE` frames — 64 tiny
   DATAGRAMs), `note_session_closed` stops recording.
2. A live association is later reaped server-side; its `SESS_CLOSE` notifications are dropped.
   `UplinkFlows::sync` never resets; the association keeps its `Open` bindings
   (`rev2.rs:526-533` is the only reset path).
3. The server already purged that session's connection-registry bindings
   (`accept.rs:1275-1299 r2_close_session` → `registry.remove_session`), so every subsequent
   steady `DATA` is an unknown-id drop: **no error, no FLOW_REJECT, no re-OPEN**. The app's
   traffic is silently discarded; the association's 180 s idle reap never fires while the app is
   active, so the blackhole lasts until the QUIC connection redials. The comment's assumption
   ("compression just waits for the redial") is wrong for server-side reaps: delivery, not just
   compression, depends on this notification (also contradicts MQP3_REV2_SPEC.md §3.4's
   "correctness never depends on their arrival").

Existing test coverage only pins the *drop* (`rev2.rs:1328-1344`,
`tests.rs:4900-5000` consume one id) — nothing evicts or ages entries.

Minimal fix direction: age entries (timestamp + prune on note/take), or store only ids of
sessions the client actually knows, and — the correctness half — have the uplink fall back to
re-`OPEN`/recover when steady frames for a session stop being confirmed, or make the cap unable
to block a *live* association's close (e.g. remove the oldest entry on insert). Local cleanup in
`send_sess_close` should not depend on the notification set at all (see C4).

### C2 — main runtime collapses to one worker; non-Linux has no compensating pinning (S1)

`main.rs:87-97`:
```rust
fn main_runtime_workers(c: &ClientConf) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    if !shard_runtime_enabled() { return cores; }
    cores
        .saturating_sub(
            planned_slot_count(c.conn_count(), c.udp_split(), c.udp_egress_cnt()).min(cores),
        )
        .max(1)
}
```
At the shipped defaults (`DEFAULT_QUIC_CONNS=4`, `DEFAULT_UDP_EGRESS_CONNS=2`,
`udp_split=true`) `planned_slot_count == 7` (`pool.rs:878-887`), so on an 8-core host the main
runtime gets **1** worker; on 4-/2-core hosts also 1. The main runtime runs every SOCKS accept,
both TCP relay pump directions and every UDP-association relay loop (`main.rs:252-342`,
`main.rs:423-432`) — i.e. all app-side copying and syscalls. The seven per-slot current-thread
runtimes exist only to run the QUIC driver/dispatcher/reconnect loop, which are idle between
packets, yet their cores are subtracted as if permanently occupied.

Second, the formula's premise is Linux-only: `linux::pin_to_core` (`src/linux.rs:184-200`)
does nothing on `#[cfg(not(target_os = "linux"))]`, while the slot threads and the subtraction
still happen on macOS. README:453 states the client "pins one current-thread runtime per pool
slot and sizes the multi-threaded main runtime to the cores those pinned threads leave over" —
on non-Linux that is not what the code does: 7 unpinned slot threads + 1 worker.

Impact: aggregate client TCP throughput and UDP-association CPU are capped by one core while
the slot cores are under-utilized; on the OpenWrt/low-core target and on development macOS the
regression is unconditional. Confidence high (arithmetic + code); impact depends on offered
load (design center is small packets, but TCP relays share this runtime).

Minimal fix direction: compute the subtraction from cores *actually reserved for pinned slots*
(Linux only), and floor the main runtime at `min(cores, max(2, cores - pinned))` — or make the
main runtime's width configurable and independent of the pinning formula.

### C3 — peer-controlled CTL frames do unbounded work with no throttle (S2)

`dispatcher.rs:888-897` — one 1-byte CTL per tiny DATAGRAM, at peer-chosen rate:
```rust
r2::Ctl::SessClose { sess, .. } => {
    let _ = r2_reasm.drop_session(sess);
    let _ = rev2.stager.lock().drop_session(sess);
    let _ = rev2.registry.remove_session(sess);
    rev2.note_session_closed(sess);
```
`remove_session` is a **write-lock `retain` over up to 4096 entries**
(`r2_flow.rs:503-508`); `stager.lock()` is the connection-wide stager mutex used by every
uplink push/drain. `Caps` similarly calls `on_caps` → `ctl.set_caps` (RwLock) +
`stager.lock().set_max_train_items` (`rev2.rs:178-193`) per frame. None of HELLO/CAPS/
SESS_CLOSE is rate-limited or deduped (unlike FLOW_CLOSE/FLOW_REJECT, whose unknown-id scans
8f0d685 correctly removed). A hostile/buggy server can therefore turn bytes into O(registry)
work and stager-lock contention on the same mutex the uplink data path needs
(README:581 promises a malformed frame cannot become a CPU primitive). Impact scales with
registry size and the datagram rate; a 50 kpps CTL flood ≈ 2·10⁸ map-entry visits/s plus the
uplink lock convoy. S2 because the server is the configured peer; still remotely triggerable
and cheap to fix.

Minimal fix direction: per-connection token bucket for CTL frames, dedupe/ignore repeated
`CAPS` (only first accepted) and `SESS_CLOSE` ids, and skip `remove_session` when no binding
names the session (registry could expose a cheap `contains_session` or the session id could be
validated against a bounded known-session set first).

### C4 — end-of-association cleanup is conditional on readiness/egress (S2)

`rev2.rs:432-466`: `registry.remove_session(sess)` and `stager.lock().drop_session(sess)` live
inside the `send` closure, after
```rust
if !rev2.is_ready() { return; }         // rev2.rs:437
```
and the closure only runs if `egress.with_fresh(...)` yielded a handle or
`egress.acquire(...)` won the per-binding single-flight (`rev2.rs:456-465`). On an exit during
the 0-RTT→CAPS window (`handshake` may take up to 2 s, `rev2.rs:49`), or when another
association/thread holds the refresh gate and the memo/cached entry is stale, the association's
connection-scoped bindings and any queued stager items for it are left behind; the server is
not told either, so its session survives until the 180 s sweep and then emits a `SESS_CLOSE`
that lands as a stale entry (C1). Reachable with any fast association churn during a dial and
with any egress refresh contention at exit. Bounded per connection (4096 bindings/256 KiB
stager), so memory impact is small; the lifecycle/notification impact feeds C1.

Minimal fix direction: run local cleanup unconditionally in `send_sess_close` (before/independent
of the `is_ready()` gate and of egress acquisition), and only the datagram send stays
best-effort.

### C5 — client TRAIN ingress ignores `get_batch` (S2)

`dispatcher.rs:1033-1051`: per distinct id in a TRAIN frame,
```rust
let Some(binding) = rev2.registry.get(id) else { ... };
```
`FlowRegistry::get_batch` (`r2_flow.rs:455-470`) was written for exactly this ("the TRAIN
ingress uses this to replace one acquire per item") and the server's ingress uses it
(`accept.rs:1911`). On the client each TRAIN-dict item pays a `parking_lot` read-lock
acquire/release + `Arc` clone+drop; a 64-id dict costs 64 lock cycles + 128 refcount RMWs per
DATAGRAM, all on the dispatcher thread that also runs the QUIC driver. At a few 10 k
TRAIN-DATAGRAMs/s this is a measurable share of the slot thread; it is also avoidable with the
existing API (one stack array of 64 `(u32, Option<Arc>)` + one `get_batch`).

Minimal fix direction: collect the frame's distinct ids while iterating `last`/first occurrence,
one `get_batch`, then iterate as today.

### C6 — uplink hot path: one heap copy + one connection-wide mutex per payload (S2)

`rev2.rs:609-627`: every staged small payload is copied into a fresh `Bytes`:
```rust
payload: Bytes::copy_from_slice(payload),
```
then `push_stage` (`rev2.rs:225-227`) takes `parking_lot::Mutex<R2Stager>` (connection-scoped,
`rev2.rs:113`) — one global lock acquisition **per datagram**, contended by every association
sharing the connection; `R2Stager::push` itself does 2–3 hash-map/set operations
(`r2_stage.rs:382-407`), and a burst drain takes the same lock twice more
(`r2_stage.rs:919-975`). Separately, the one-slot target memo means an association cycling
between destinations pays `SessionFlows::find` (up to 64 `TargetAddr` compares) plus the
registry `find_server_flow` scan on every switch (`rev2.rs:880-899`). This is the price of
cross-session TRAIN packing (deliberate), but it is the remaining per-packet alloc/lock surface
on the connection's data path; at high pps the single stager mutex is a scalability ceiling and
the allocation shows in the hot-path profile. S2 (throughput/CPU headroom, no correctness
impact).

Minimal fix direction: per-worker/per-thread staging queues with a shared drain (or
`Bytes::copy_from_slice` replaced by a pooled payload buffer), and a small multi-slot target
memo (e.g. 2–4 MRU entries) for fan-out associations.

### C7 — server-owned flow install/cap interactions (regression from 8f0d685) (S2)

`dispatcher.rs:806-833, 939-952`: an unknown **server-owned** id with `OPEN`/`OPEN|SRC` is
installed before `r2_lookup` (the session may have no association at all), and there is no
`full_cone`/session validation on the client (there cannot be a full-cone config — that is
server-side). A peer can therefore pin up to `R2_MAX_FLOWS_PER_CONN` (4096) bindings per
connection with tiny frames; at cap the uplink's `has_capacity` probe falls back to `INLINE`
for every new flow (bounded memory, degraded framing).

Regression: 8f0d685 inserted the capacity probe **before** the server-owned-flow scan
(`rev2.rs:910-923`), whereas the parent commit
(`git show 8f0d685^:src/bin/myquic2-client/rev2.rs`, `ensure_binding`) ran
`find_server_flow` first. A full registry is exactly when reusing an already-installed
server-owned flow is the only way to keep the reply path compressed; now a full-cone client at
cap sends all replies `INLINE` (13–30 B header) even though the flow id exists locally. Impact:
framing/CPU only, no loss. Confidence high on the ordering change; low on how often a registry
reaches its 4096 cap in practice.

Minimal fix direction: move the capacity probe after `find_server_flow` (reuse needs no
capacity), and validate `sess` against a live-association set before installing a binding.

### C8 — SOCKS5 UDP `FRAG != 0` (and other malformed app datagrams) dropped with no counter (S2)

`assoc.rs:235-237`:
```rust
if msg.len() < 4 || msg[0] != 0 || msg[1] != 0 || msg[2] != 0x00 {
    return AppDgram::Continue;
}
```
`msg[2]` is the SOCKS5 FRAG byte, so any non-zero FRAG is dropped silently: no
`dgram_drops::bump`, no warn (only `debug!` for the source-IP mismatch a few lines later). RFC
1928 §7 permits a proxy to drop fragments it does not support, but the client advertises no
such capability and a local app that fragments would see complete UDP failure with **zero**
diagnostics, while README:391-440 claims every peer-fillable path and every drop is counted
(the same silently-dropped class applies to `decode` failures and wrong-app-source datagrams in
`AppDgramCtx::process`). S2: silent data loss without counters.

Minimal fix direction: count `FRAG != 0` (and framing rejects) in a dedicated
`dgram_drops` bucket; rate-limited warn once per window.

### C9 — app-IP pin is family-sensitive and silently blackholes dual-stack apps (S2)

`assoc.rs:214-219`:
```rust
if let Some(expected) = expected_app_ip
    && unmap(app.ip()) != expected
```
with `expected_app_ip = tcp.peer_addr().ok().map(|p| unmap(p.ip()))` (`assoc.rs:426`). If the
app opens the SOCKS control connection to `127.0.0.1` and sends UDP from `::1` (or connects to
`[::1]` and sends v4-mapped), `unmap` leaves the families distinct → every datagram is ignored
with only `debug!`, no counter; the association appears up (SOCKS reply sent) and reaps at
180 s. Med confidence of real-world occurrence (most apps are family-consistent), high
confidence of the code path/impact when it happens. Same silent-drop family as C8.

Minimal fix direction: compare IPs with v4-mapped normalization both ways, or accept a
bounded local set; count rejects.

### C10 — generation-pairing TOCTOUs between connection handle and rev2 state (S2, low reachability)

`dispatcher.rs:1248-1263`:
```rust
let conn = match slot.wait_conn(&mut gen_rx, Duration::from_secs(10)).await { ... };
...
let Some(rev2) = slot.rev2() else { ... }
```
`wait_conn` returns connection `C_n`; `slot.rev2()` is read as a *later* statement. If the slot
dies, redials and publishes `C_{n+1}`/`R_{n+1}` between the two, the dispatcher pairs `C_n`
with `R_{n+1}`. quinn's `ReadDatagram::poll` explicitly drains already-buffered datagrams from a
closed connection before reporting the error
(`quinn-0.11.12/src/connection.rs:824-830`), so those frames would be resolved against the next
generation's id tables; since client ids restart at 1 on every dial, a stale id can resolve to
an unrelated live binding → payload delivered to the wrong association, or a CTL frame applied
to the wrong generation. Same shape in `egress.rs:393-405` (`slot.shared.load()` then
`slot.rev2()`). The gap is two adjacent instructions but the redial path includes a ≥200 ms
backoff, so it needs a >200 ms preemption of the slot thread — possible under extreme
saturation, low probability. The code comment ("normally present") acknowledges only the
None case, not the wrong-generation case.

Minimal fix direction: publish `(conn, rev2)` as one `ArcSwap` atomically (or have
`wait_conn` return the paired `Arc<ConnRev2>` read under the same generation), and have
`refresh_global` read the pair once.

## Checked and found sound (selected)

- **No locks held across `.await`** in the client bin: the only locks are
  `ConnRev2.stager` (parking_lot Mutex), `closed_sessions`/`rejected` (RwLock) and all are used
  inside synchronous fns (`send_uplink`, `ensure_binding`, `handle_r2_ctl`, `drain_assoc_stage`,
  `send_sess_close`); verified each call site. Egress `with_fresh`'s `RefCell` borrow is held
  while the sync closure sends, and nothing re-enters the memo.
- **Zero-copy downlink**: per reply an untransmitted bytes slice (`d.slice_ref`) is staged and
  the flush encodes only ≤22 B headers; on Linux header+payload go as two iovecs of one
  `sendmmsg` (`retry.rs:316-413`), so no whole-payload copy on the reply path. Single-reply runs
  skip the 32-entry `refs` array. Portable fallback (non-Linux) copies header+payload via a
  reused thread-local buffer — acceptable.
- **Stager is not held across sends**: `drain_staged` packs under a short lock and calls
  `try_send_datagram` with the lock released (`r2_stage.rs:919-975`); requeue happens under a
  fresh hold; all queue accounting (`queued_items`/`queued_bytes`, drops) matched on inspection.
- **SOCKS5 framing bounds**: 255-byte domain name is safe in `read_socks_addr`
  (`buf[2..4+255]` == `buf[2..259]` of a 259-byte buffer; `AddrHeader::MAX_LEN = 259`,
  `src/mqp/addr.rs:59`); greeting methods length capped at 255; per-negotiation 10 s deadline;
  CONNECT/UDP-ASSOCIATE reply formats (VER/REP/RSV/ATYP/addr/port) are correct.
- **Auth/0-RTT**: token is only written after `ZeroRttAccepted` resolves (1-RTT keys), i.e. not
  in replayable early data (`auth.rs:376-408`); a failed write `reset`s instead of FIN-ing a
  truncated token (`auth.rs:438-447`); dial attempt deadline shared by 0-RTT auth stages;
  0-RTT replay of application bytes is impossible because no stream is opened before the
  handshake completes. Client advertises (0,0) incoming stream credit
  (`transport/build.rs:201-207, 269-271`), which is safe because the server only ever
  `accept_*`s (`server/accept.rs`) — it never opens a stream to the client.
- **`retire_dead_slot` generation race**: capture-before-clear is safe because the only
  publisher installs `set_rev2` then `publish`, and it does so only after its own clear (shared
  is `None`); a death that loses the compare cannot clear a fresh generation's rev2 (verified
  by the `clear_rev2_if` compare and the test at tests.rs:3809-3937). `clear_if_and_mark_dead`'s
  `live=false`-inside-rcu + `restore_live_if_replaced` bump correctly recovers a lost CAS race.
- **No flow-id leaks**: `FlowIds` is monotonic (`try_update`, no reuse); `insert_new`
  re-checks capacity under the same write lock before allocating; `ensure_binding` never keeps a
  half-bound flow (removes the registry entry when the session table refuses), and the
  new tests cover the full-table/rejected paths.
- **Panics on peer input**: every downlink decoder call is `Result`-checked
  (`decode_data/train/frag/ctl`), `r2::kind`/`is_r2` are first-byte-safe, TRAIN decode is
  allocation-free with fixed arrays, `flush_staged`'s socket-head `expect` is upheld by
  "every frame's first staged item is `Some(relay)`"; no peer-controlled indexing/slicing or
  unwrap found in dispatcher/rev2. `spawn_dispatcher`'s big `[DispatchSlot; 4096]` cache is
  heap-held by the spawned future, recreated per generation (bounded).
- **Memory bounds**: flow registry 4096/conn, session table 64, stager 1024 items/256 KiB/conn,
  closed/rejected sets 64, dispatch cache fixed 4096, hub 4032 associations, DNS slow-path
  tasks ≤1024 permits, TCP relay capped at 8192 connections, assoc recv buffers pooled to
  depth 8/thread and recycled on exit. No unbounded peer-fillable structure found in this
  domain (the bounded-but-dead set in C1 is the exception, and it is bounded in memory, not in
  time).
- **Hub lifecycle**: `SessReservation` releases the process-wide slot on every exit path
  (`assoc.rs:12-33, 221-230`), `AliveGuard` clears the liveness bit, `DispatchSlot` caches only
  `Weak` relay handles (the 1200-assoc fd-leak regression class is covered by tests), the
  ArcSwap clone-on-publish map is bounded by `HUB_SHARDS=256`.
- **Pool routing**: `pick_tcp_index` is lock-free (two stack arrays + relaxed atomics), the
  dead-handle check is per new flow only, class-preserving rotated failover and the L3 stale
  gate are consistent; `wait_conn` is the liveness authority and its watch generation cannot
  miss a publish (watch retains the version), and stale `gen_rx` receivers are harmless.
- **Watchdog/health**: watchdog silence `max(2·keepalive, 8 s)` is strictly below the QUIC idle
  timeout `max(3·keepalive, 15 s)` for every clamped keepalive (1..=300); the selection-time
  stale threshold is the midpoint and below the watchdog; keepalive is always enabled after the
  clamp, and received packets (including ACKs) advance `udp_rx.datagrams`, so a healthy idle
  connection cannot be declared stale/silent.
- **Shutdown**: SIGTERM closes each slot endpoint (sharded: per-slot drain ≤1 s in its own
  thread; shared: one group deadline), shard threads joined, no lock held across the blocking
  join beyond process exit.

## Cross-domain notes

- **server-bin**: the client sends `SESS_CLOSE` ×3 per association exit and the server's reader
  exit / sweeps send ×3 back; every duplicate that arrives after the client association is gone
  becomes a permanent stale id in the client's `closed_sessions` (C1), and the server-side
  handlers have the same O(registry) `remove_session`/stager cost per tiny CTL frame (C3, same
  family as the client). Server `r2_close_session` marks bindings `Closed`; the client's
  `handle_r2_ctl` SESS_CLOSE does **not** (only `remove_session`), a small asymmetry.
- **mqp-wire**: `FlowRegistry::get_batch` is only used by the server ingress; the client should
  use it (C5). MQP3_REV2_SPEC.md §3.4's "correctness never depends on control-frame arrival"
  is false for server-initiated reaps: a lost/dropped `SESS_CLOSE` leaves the client sending
  steady frames for a purged session forever (C1). `install_server_flow` accepts an unknown
  server-owned `OPEN` without the `SRC` flag set (spec §3.1 defines the address as the reply
  source only under `OPEN|SRC`) — benign with a trusted server, worth a validation.
- **udp-dataplane**: `R2Stager::push` is the per-uplink-packet global lock (C6); the
  pack/send/requeue split itself is lock-across-send-free and the queue bounds/accounting look
  correct. `R2Reassembler` bounds (256 partials / 256 KiB / 2 s / `prune_orders`) and the
  `FRAG_MAX_HELD_BYTES` charging look sound from the client's usage.
- **core-dns**: the client spawns downlink domain resolvers on the *slot* dispatcher runtime
  (`dispatcher.rs:610 tokio::spawn` inside `spawn_dispatcher`), bounded by the global 1024
  permits and moka single-flight; no serialization bug found, but those task shells/resolver
  futures share the pinned slot thread with the QUIC driver.
- **README claims to revisit**: README:453 (pinning/main-worker sizing, C2), README:581
  ("malformed frame cannot become a CPU primitive", C3), README:391-440 ("every drop counted",
  C8), README:44 "every peer-fillable structure has a hard bound" (C1's set is bounded in
  memory but unbounded in occupancy time, with correctness impact).
