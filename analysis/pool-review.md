# Client connection pool review

Scope: `src/bin/myquic2-client/pool.rs` (ConnSlot, ConnPool, ZeroRttState,
select_slot, the stale gate, layout helpers) plus the pool's immediate
collaborators: the reconnect/dial loop (`auth.rs`), the per-slot dispatcher's
generation handshake (`dispatcher.rs`), the egress binding boundary
(`egress.rs`), and the pool-derived sizing in `main.rs`.

Method: read every publication and death transition against its consumers;
cross-check the claimed invariants against the code and the tests; reason about
the relaxed/atomic orderings and the watch-channel semantics (verified against
the pinned `tokio 1.54` and `quinn 0.11.12` sources); recompute the threshold
inequalities over the full legal config domain.

No runtime benchmark was run; the performance section states the cost model
explicitly and marks everything that should not be optimized without a profile.

---

## Summary

| # | Finding | Type | Severity |
|---|---|---|---|
| L1 | `ZeroRttState` phase is slot-scoped, not dial/connection-scoped; a stale 0-RTT monitor can overwrite a later attempt's phase | logic | **medium** |
| L2 | The L2 (dead-handle) and L3 (stale-path) overlays are not composed: a re-pick by one gate is not checked by the other | logic | low |
| L3 | `bump_gen` is a non-atomic read-then-write across two watch locks | robustness | low |
| L4 | `designed_fds()` budgets `MAX_POOL_CONNS` endpoints while the pool can own `MAX_POOL_CONNS + MAX_UDP_SLOTS` | sizing/docs | low |
| L5 | `planned_slot_count` duplicates the pool-layout arithmetic it is supposed to be the single definition of | maintainability | info |
| M1 | `SharedEgress::forget_slot` checks-then-clears without a CAS; a concurrent refresh can have its fresh publish wiped | logic | low |
| P1 | `ConnPool::slot()` returns an owned `ConnSlot` (6 Arcs + the watch pair cloned) on every TCP flow / UDP association | performance | low |
| P2 | Two quinn state-mutex probes per TCP flow (`holds_dead_handle` + `wait_conn`) — already PERF_ANALYSIS P3-7 | performance | low (known) |
| P3 | Single-cell `rr` atomic bumped on every flow, including pinned flows that rarely read it | performance | info (measure) |
| P4 | On a generation bump every waiting flow wakes and takes quinn's state lock at once | performance | info |
| T1 | Test gaps: threshold invariant only proven for the default idle; no 0-RTT attempt-race test; no gate-composition test; no `forget_slot` race test | test gap | info |
| D1 | Docs drift: README says 7 default connections (8); PERF_ANALYSIS P3-9 claims interactive UDP is single-connection (it is sharded) | docs | info |

Nothing found rises to "wrong routing in steady state", "lost datagram", or
"lost TCP flow" in the normal case. L1 and M1 are rare-race defects with
user-visible symptoms (a failed flow; a held/dropped datagram) but no steady
state damage; the pool's routing, publication/death protocol and egress-boundary
math all held up (see *Verified correct* below).

---

## L1 (medium) — `ZeroRttState` is shared per slot, but the phase belongs to a dial attempt

### What the code claims

`pool.rs:45-49`:

> It is per-generation state published with the connection (reset at the start
> of every dial) […] the only consumer — the TCP open path's 0-RTT retry —
> re-validates through the connection it was handed.

`pool.rs:132-138` says `wait_settled`'s caller is "the TCP open retry". That is
no longer the only consumer: `spawn_ctl_stream` also waits on the same state
(`dispatcher.rs:1244-1280`, added with the P6 fix) and a wrong phase there means
opening the control stream into 0-RTT — exactly the condition P6 removed.

### What the code does

`ZeroRttState` (`pool.rs:50-148`) is one `Arc` per **slot**, holding only
`phase` and `token_early`. The phase transitions are:

* `dial_once` calls `mark_none()` at the start of **each candidate dial**
  (`auth.rs:584`), then `mark_pending()` (`auth.rs:596`) /
  `set_token_early()` (`auth.rs:614`) if `into_0rtt()` succeeds;
* `spawn_zero_rtt_monitor` (`auth.rs:683`) is spawned **per 0-RTT attempt** and
  later unconditionally calls `mark_settled(accepted)` (`auth.rs:693`).

There is no attempt id, generation or connection identity on the state and none
on the monitor. `mark_settled` therefore cannot tell whether the phase it is
about to overwrite still belongs to its own handshake.

### The interleaving

A 0-RTT attempt can spawn its monitor and then fail before publication:
after `spawn_zero_rtt_monitor`, `dial_once` still checks
`ensure_dialed_alive` and may `bail!` (`auth.rs:625-627`). `dial_candidates`
then immediately tries the next address (`auth.rs:445-474`) — the common
dual-stack case the code itself names ("an AAAA record on a network without a
v6 route is the common case").

```
dial A (0-RTT candidate)                   dial B (next candidate)
---------------------------------------    --------------------------------------
mark_none()
mark_pending()
send_early_auth(...).await
spawn monitor(A)
ensure_dialed_alive() == false -> bail --+  mark_none()
                                         |  connect_with -> into_0rtt()
                                         |  mark_pending()
                                         |  send_early_auth(...).await  <- first await
                                         |    monitor(A) polled at that await:
                                         |    accepted == false -> mark_settled(false)
                                         +->  phase = REJECTED
                                              (B is still handshaking / PENDING)
```

`monitor(A)`'s `accepted_fut` resolves `false` because A's connection died
(`dial_once` only bails after observing `close_reason`). The monitor also
re-sends the token on A's dead connection and bumps
`ZERO_RTT_REJECTED`/`ZERO_RTT_RESEND_FAILURES` (`auth.rs:683-740`) — harmless
except for metric noise. On the shared-runtime topology the monitor runs on a
different worker, so the window is concurrent rather than merely scheduling
order; on a current-thread slot the interleaving above is the natural order
(the next await point polls the pending monitor).

### Consequences for connection B (a 0-RTT generation)

1. **Spurious header retry / duplicate target dial.** A TCP flow whose stream is
   0-RTT (`recv.is_0rtt() == true`) and whose `write_all(hdr)` succeeds sees
   `zero_rtt.is_rejected() == true` (`auth.rs:783-793`), resets the stream and
   re-opens + re-writes the header on a second stream. If the peer had accepted
   and delivered the first header, that is a second `CONNECT` for the same
   target: the server dials the target again, and the first (reset) stream tears
   its dial down.
2. **Self-sustaining retry loop.** `wait_settled` returns immediately (phase is
   not `PENDING`), so the retry re-opens *another 0-RTT stream* while the
   handshake is still in flight. Each iteration repeats the same check; after
   `MAX_0RTT_OPEN_ATTEMPTS = 8` the flow is failed with
   `"0-RTT rejected; stream open retries exhausted"` (`auth.rs:791-793`,
   `auth.rs:806-808`) even though the connection is healthy. The SOCKS client
   gets `REP=0x04`.
3. **Premature control stream.** `spawn_ctl_stream`'s `wait_settled`
   (`dispatcher.rs:1277`) returns immediately, so the rev3 control stream opens
   into 0-RTT. If the peer rejects the early data (stale ticket, restarted
   server), the stream resets; the dispatcher's closed-queue arm then retires
   the generation (P6 layer 2) and the client redials — churn the P6 fix was
   meant to avoid.
4. **The reverse direction.** If the phase was corrupted to `ACCEPTED` from a
   previous attempt while B's early data is later rejected, the flow takes the
   documented residual window instead of retrying, i.e. it fails closed.

The window is bounded by B's own monitor settling (one round trip after
`mark_pending`), so this is rare — but it is not a theoretical race: it needs
"a 0-RTT candidate fails before publication" and "the next candidate is also a
0-RTT dial", both routine on a dual-stack host with a stale ticket.

### Fix

Minimal: give the state an attempt identity that every publisher must present.

```rust
pub(crate) struct ZeroRttState {
    attempt: AtomicU64,            // identity of the current dial
    phase: AtomicU8,
    token_early: AtomicBool,
}

impl ZeroRttState {
    /// Start a dial; every later write for this dial must carry the id.
    pub(crate) fn begin_attempt(&self) -> u64 {
        let id = self.attempt.fetch_add(1, Ordering::Relaxed) + 1;
        self.phase.store(Self::NONE, Ordering::Relaxed);
        self.token_early.store(false, Ordering::Relaxed);
        id
    }

    pub(crate) fn mark_pending(&self, attempt: u64) {
        if self.attempt.load(Ordering::Relaxed) == attempt {
            self.phase.store(Self::PENDING, Ordering::Relaxed);
        }
    }

    /// The monitor's verdict; dropped when the dial it belongs to is gone.
    pub(crate) fn mark_settled(&self, attempt: u64, accepted: bool) {
        if self.attempt.load(Ordering::Relaxed) == attempt {
            self.phase.store(if accepted { Self::ACCEPTED } else { Self::REJECTED },
                             Ordering::Relaxed);
        }
    }
}
```

`dial_once` captures the id, threads it into `spawn_zero_rtt_monitor`, and
`set_token_early`/`mark_settled` take it. A late monitor then becomes a no-op
(the token re-send may still run against its dead connection; that is already
bounded and counted).

Thorough alternative: publish the phase **with the connection**, the way
`rev2` is published (`ConnSlot::set_rev2`/`rev2_for`, `pool.rs:247-290`), and
have consumers resolve `(conn, phase)` coherently. That fixes the whole class
of "slot-scoped hint read by a connection-scoped consumer", not just the
monitor race: today `socks.rs:155`/`forward.rs:284` capture the slot state
before `wait_conn` and then read whichever generation is current, so the
re-validation claimed in the doc comment is not actually performed.

Regression test (deterministic, no sockets): with the proposed API,
`begin_attempt/mark_pending` twice and a late `mark_settled(first, false)` must
leave the phase `PENDING`. With the current API, the equivalent sequence
`mark_pending(); mark_none(); mark_pending(); mark_settled(false)` already
produces `REJECTED` while a dial is pending, which is the defect.

---

## L2 (low) — the two failover overlays are each single-shot and do not compose

`pick_tcp_index_inner` (`pool.rs:1025-1078`) applies at most one overlay:

1. **L2** (`pool.rs:1057-1065`): if the preference is live but
   `holds_dead_handle`, mark it dead and `return select_slot(pinned, rr, &live)`;
2. **L3** (`pool.rs:1074-1076`): if the preference is live but its stamp is
   stale, return `select_slot(pinned, rr, &fresh)`.

Each is documented as "a single re-pick", but the two gates are not applied to
each other's result:

* after an L2 re-pick, the returned slot is **not** checked against `fresh`
  (the stamp array is already computed — this is free);
* after an L3 re-pick, the returned slot is **not** checked for a dead handle.

Concrete case (`n = 4`, bulk flow, `rr = 0`, preference slot 1):

| slot | live | handle | stamp | `fresh` |
|---|---|---|---|---|
| 0 | yes | ok | now | yes |
| 1 | yes (stale-true) | **dead** | now | yes |
| 2 | yes | ok | 30 s old | no |
| 3 | yes | ok | 30 s old | no |

L2 fires, sets `live[1] = false`, and `select_slot` continues the rotation to
slot 2 — the blackholed path the L3 gate exists to avoid, while slot 0 is live
and fresh. The flow then sits in `wait_conn` on slot 2 for up to
`reconnect_timeout_secs` (10 s) and fails; applying L3 to the L2 result would
have selected slot 0 through the documented "bulk falls back to the interactive
slot when no bulk slot is usable" rule. The mirror case: L3 re-picks a sibling
that holds a dead handle (its stamp was recent because it died after the last
progress sample), and the flow waits on a dead slot for the same 10 s.

Impact is narrow — the L2 window is the sub-second interval between QUIC death
and the conn loop's `retire_dead_slot`, and the mirror needs a death inside the
same second — but it is exactly the "isolation precisely when a connection is
degraded" property the L3 gate was added for, so it is worth closing.

### Fix

Apply the overlays to the **candidate that will be returned**, not to the
initial preference, and clear the rejected candidate from whichever mask is
used for the re-pick:

```rust
let mut pick = select_slot(pinned, rr, &live[..n]);
if live[pick] && self.slots.get(pick).is_some_and(ConnSlot::holds_dead_handle) {
    live[pick] = false;
    fresh[pick] = false;   // dead, however fresh the last progress stamp is
    pick = select_slot(pinned, rr, &live[..n]);
}
if live[pick] && !fresh[pick] && fresh[..n].iter().any(|&f| f) {
    fresh[pick] = false;   // never re-pick the candidate just rejected
    pick = select_slot(pinned, rr, &fresh[..n]);
}
pick
```

(One extra `fresh` check on the L2 path, zero extra quinn locks. The mirror
case would need one more `holds_dead_handle` probe on the L3 result; that is
one mutex on an already-rare path, and is optional if the cost is unwelcome.)
The existing routing tests encode the single-re-pick behaviour and would need
the two-gate composition added.

---

## M1 (low) — `forget_slot` is check-then-clear, so it can wipe a fresh publish

Not in `pool.rs`, but on the pool's death path: `retire_dead_slot` calls
`egress.forget_slot(idx)` after the clear commits (`auth.rs:352`), and
`forget_slot` (`egress.rs:516-528`) does:

```rust
if self.cached[i].load().as_ref().is_some_and(|e| e.slot == slot) {
    self.cached[i].store(None);              // no CAS on the value just checked
    self.generation[i].fetch_add(1, Release);
}
```

A concurrent `refresh_global` for the same binding can have decided the cached
handle was dead/expired, scanned the pool, and published a handle from a
*different, live* pool slot between the `load` and the `store`. The
unconditional `store(None)` then throws that fresh publish away (and bumps the
generation again, invalidating every thread-local memo). The next datagram
re-acquires through the single-flight gate; if it loses, the payload is held or
dropped under `udp_fail_closed`.

The comment on `forget_slot` says "The clear is scoped by `EgressCache::slot`,
so a healthy slot's cache is untouched" — true for the value that was *read*,
not for a value published in between. Impact is one wasted refresh window plus a
possible held/dropped datagram, in the rare death-vs-refresh race; correctness
is restored on the next datagram. Fix with a compare-and-clear:

```rust
// Same last-run-wins pattern as ConnSlot::clear_if_and_mark_dead.
let mut cleared = false;
self.cached[i].rcu(|cur| {
    let hit = cur.as_ref().is_some_and(|e| e.slot == slot);
    cleared = hit;
    if hit { None } else { cur.clone() }
});
if cleared {
    self.generation[i].fetch_add(1, Ordering::Release);
}
```

`invalidate` (unconditional clear) is fine: it runs for the caller's own binding
and any cached handle is suspect there.

---

## L3 (low) — `bump_gen` is a non-atomic read-then-write

`pool.rs:21-24`:

```rust
let next = tx.borrow().wrapping_add(1);
tx.send_replace(next);
```

The split is a real deadlock fix (`tx.send_replace(tx.borrow() + 1)` holds the
watch read guard across the write lock), but the increment is still two separate
lock acquisitions and two writers can interleave:

```
A: borrow() -> g            B: borrow() -> g
A: send_replace(g + 1)      B: send_replace(g + 1)   // one increment lost
```

No missed wakeup today: `send_replace` always notifies (it forwards to
`send_modify`, which sends unconditionally), and `rev2_for` additionally
validates the connection identity (`pool.rs:276-290`), so a collapsed adjacent
pair is invisible. It is still a violation of the documented "bump the counter"
contract that a future generation-keyed cache or a `rev2_for`-style check could
trip over, and it is a trivial fix:

```rust
pub(crate) fn bump_gen(tx: &watch::Sender<u64>) {
    tx.send_modify(|g| *g = g.wrapping_add(1)); // one lock, atomic, still notifies
}
```

---

## L4 (low) — the fd budget counts TCP slots, not pool slots

`main.rs:59-67` derives the startup `RLIMIT_NOFILE` raise from

```
MAX_SOCKS_CONNS + MAX_UDP_ASSOCS + MAX_POOL_CONNS + FD_GUARD
```

with the comment "one QUIC endpoint per pool slot (`MAX_POOL_CONNS`)". Since the
UDP egress range was added, one pool slot is one endpoint (each shard builds
its own endpoint on its own thread, `main.rs:483-506` and `main.rs:874-960`)
and the pool owns
`tcp_slots + interactive_shards + bulk_shards` = up to
`MAX_POOL_CONNS + MAX_UDP_SLOTS` = 32 with the default split
(`pool.rs:1145-1168`, `config/tuning.rs:99,133,141`). The derivation therefore
understates the endpoint term by up to 16 fds.

No practical failure: `FD_GUARD = 256` absorbs it, and the derived value
(12,496 at the caps) is dominated by the relay/association pools. But the
comment, the number and its test (`tests.rs:8168`, which asserts the sum
literally) encode the old one-connection-per-endpoint era, so a future guard
reduction or a pool-width change would silently under-provision. Use the same
layout function the pool uses:

```rust
fn designed_fds(c: &ClientConf) -> u64 {
    (MAX_SOCKS_CONNS + MAX_UDP_ASSOCS
        + planned_slot_count(c.conn_count(), c.udp_split(),
                             c.udp_interactive_cnt(), c.udp_egress_cnt())
        + FD_GUARD) as u64
}
```

(`report_fd_budget()` is already called after `load_toml`, `main.rs:177`.)

---

## L5 (info) — `planned_slot_count` duplicates the layout it "mirrors"

`planned_slot_count` (`pool.rs:1145-1168`) repeats the clamps of
`ConnPool::new_with_bulk_ports` (`pool.rs:816-833`) line for line. Its doc says
keeping the arithmetic in one function stops the two from drifting, but it is
two functions; the only protection is a six-case equality test
(`pool.rs:1170-1219`). Extract a single `SlotLayout::for_config(...)` (returning
`tcp`, `interactive`, `bulk`, `udp_slots`, `total`) and have the constructor,
`planned_slot_count`, `designed_fds` and the worker sizing all read it. That
also makes L4 a one-line consumer change.

---

## P1 (low, per-flow) — `ConnPool::slot()` clones the whole slot

`pool.rs:966-971`:

```rust
pub(crate) fn slot(&self, i: usize) -> ConnSlot {
    self.slots.get(i).cloned().expect("...")
}
```

`ConnSlot` (`pool.rs:157-212`) contains six `Arc`s (`shared`, `zero_rtt`,
`live`, `rev2`, `last_rx_ms`, `runtime`) plus the `watch::Sender`/`Receiver`
pair (a shared inner `Arc`), so a call is ~9 refcount RMWs and ~9 drops. It is
on:

* every SOCKS CONNECT (`socks.rs:152`) and forwarded TCP flow
  (`forward.rs:283`, `forward.rs:246`),
* every UDP association spawn (`assoc.rs:1091`),
* every pool slot at startup (fine).

`pick_tcp_index` itself allocates nothing and its only lock is the single
quinn state probe the L2 gate documents (`pool.rs:1057-1062`); the `slot()`
call immediately after it is a separate, avoidable cost. Add a borrow accessor
for the synchronous paths and keep the owned clone only where a `'static`
value is required (`tokio::spawn`, tests that store/mutate through the shared
Arcs):

```rust
pub(crate) fn slot_ref(&self, i: usize) -> &ConnSlot {
    self.slots.get(i).expect("pool slots are installed at startup and never removed")
}
```

Estimated saving is tens of nanoseconds per flow — irrelevant against a TCP
accept + SOCKS negotiation + QUIC stream open (<1% of flow setup). It is listed
because the accessor is misleadingly cheap-looking and the fix is mechanical,
not because it should move a benchmark.

---

## P2 (low, known) — two quinn state-lock probes per TCP flow

`pick_tcp_index`'s L2 probe (`pool.rs:1057-1062`, `holds_dead_handle` →
`close_reason()`) and `wait_conn`'s confirmation (`pool.rs:500-505`) both take
quinn's connection-state mutex, on the same connection, for the same flow. This
is already logged as PERF_ANALYSIS P3-7. Two ways out, in increasing order of
work:

1. Let `wait_conn` accept the `quinn::Connection` the L2 probe just verified
   (e.g. `wait_conn_confirmed(&self, conn, …)`) so the flow does not re-probe.
   Careful: the probe result is only valid for that handle; the call must not
   silently fall back to a newer generation.
2. Publish an atomic "dead" bit from a `conn.closed()` watcher task spawned at
   publish, and drop the L2 probe entirely (the watcher becomes a second
   `retire_dead_slot` writer, a case that function is already written for). The routing path then costs zero quinn locks; the remaining
   `close_reason` is `wait_conn`'s authority.

Option 2 also shortens the stale-true window that L2 exists to paper over, at
the cost of one more cheap task per generation. Under a reconnect stampede the
current design additionally makes every blocked flow take the state lock at
once when the generation bumps; option 2 does not change that (wait_conn still
confirms), but it halves the per-flow probe count.

---

## P3 (info) — `rr` is one shared cache line

`pool.rs:1047` bumps `self.rr` on **every** TCP flow, including pinned flows
that (while slot 0 is live) never read it. The advance is required: pinned
fallbacks rotate on the same cursor, and only advancing for bulk flows would
restart every pinned fallback at the same slot (documented at
`pool.rs:1041-1046`). Keep it. At 10k CONNECT/s this is 10k RMW/s on one line —
below the noise of the accept path. Only if a profile ever shows the line as a
contention point should a per-thread cursor seeded from the global be
considered.

The same "don't optimize" verdict applies to the two `[bool; MAX_POOL_CONNS]`
arrays and the two atomic loads per slot in `pick_tcp_index_inner`: ~1.5 KB of
cache footprint at the 16-slot maximum, once per flow.

## P4 (info) — every waiter takes quinn's state lock on a bump

`bump_gen` wakes every `wait_conn` waiter (all TCP flows queued on the slot, and
its dispatcher at most once). Each waiter then re-loads `shared`, checks
`is_live` and calls `close_reason()` — one acquisition of the connection-state
mutex that the driver holds while processing every inbound packet. At the
accepted-flow cap that is up to `MAX_SOCKS_CONNS` serialized acquisitions plus
scheduler wakeups in one burst.

Measured order of magnitude: a `close_reason` acquisition is a short critical
section, so the burst is 8192 × ~100 ns ≈ 1 ms of mutex serialization, spread
over the workers; the accept loop is not blocked (each flow is its own task).
Not worth changing on its own, but the P2 option 2 (atomic dead bit) does not
remove it: `wait_conn` must still confirm the handle it returns. A cheaper
confirmation would be to return the handle the *bump* was published with, i.e.
skip `close_reason` when the receiver just observed a new version and the
handle it loads was installed by the publisher — but that reopens the dead
handle race `wait_conn` exists to close, so it should stay as is.

---

## T1 (info) — test coverage gaps

1. **Threshold invariant.** `data_stale_threshold_sits_between_healthy_idle_and_watchdog`
   (`tests.rs:993-1026`) loops `resolve_idle_timeout_secs(keepalive, None)`,
   i.e. only the *default* idle timeout. Production also accepts an explicit
   `idle_timeout_secs` clamped down to `max(3 × keepalive, 15 s)`
   (`transport/build.rs:93-153`). I recomputed the two inequalities over that
   full domain (keepalive 1..=300, idle `max(3k,15)`..=900): the invariant
   holds — the tightest cases are keepalive 4/5 at idle 15 s, giving a 7 s
   threshold against a 5/6 s healthy-age bound — so this is a gap in the proof,
   not a bug. Add an inner loop over `Some(idle)` in
   `[floor, 900]` to make the doc claim true.
2. **0-RTT attempt race.** No test reuses one `ZeroRttState` across two dials:
   every test constructs a fresh state per dial, including the retry loop in
   `dial_until_resumed` (`tests_0rtt.rs:155`), so L1 is invisible to the suite.
   The deterministic sequence in L1's regression note covers the state
   machine; an integration variant could defer a monitor's settle across a
   second `dial_once` with a test-only hook.
3. **Gate composition.** The L2 and L3 tests each set up a single degraded
   condition. The four-slot table in L2 (dead preference + stale successor +
   fresh slot 0) would pin the intended composition once fixed.
4. **`forget_slot` race.** `retire_dead_slot_clears_egress_rev2_and_stage_once`
   stores the only cached entry before the call; nothing exercises a publish
   winning between `forget_slot`'s load and store.

---

## D1 (info) — documentation drift about the pool

Two statements that no longer match the code, both about the pool's shape:

* `README.md:1469` says "**Seven** QUIC connections by default" two lines above
  a diagram titled "ConnPool · **8** connections by default". The shipped
  default is `DEFAULT_QUIC_CONNS` 4 + `DEFAULT_UDP_INTERACTIVE_CONNS` 2 +
  `DEFAULT_UDP_EGRESS_CONNS` 2 = 8 (`config/tuning.rs:82,114,127`), i.e. the
  diagram is right and the caption was not updated when the interactive class
  was sharded.
* `PERF_ANALYSIS.md:438` (P3-9) says "The interactive UDP class is hard-bound to
  a single connection" and cites `client/pool.rs:592-598`. The class has been
  sharded (`interactive_shards`, `udp_irr`, `MAX_UDP_INTERACTIVE_CONNS`; the
  same document's A2 entry at line 573 records the fix), and that line range
  now holds `data_stale_threshold_ms`. The P3-7 row's
  `pool.rs:763-771,252-257` references are stale for the same reason. Anyone
  working from the P3 list would re-fix fixed work or cite the wrong lines.

---

## Verified correct (checked, not issues)

Worth recording so these are not re-litigated:

* **Publication order and coherent pairing.** `set_rev2 → publish →
  note_rx_progress → live=true → bump_gen` (`auth.rs:112-126`) means a
  dispatcher/egress reader can only pair `(conn, rev2)` when the slot still
  publishes that `conn`; `rev2_for`'s connection-identity re-check
  (`pool.rs:276-290`) makes the generation double-read redundant but harmless.
  The reader-side `rev2`-before-`shared` order is safe because `set_rev2` only
  runs while `shared` is empty (retire commits first, and the SOCKS
  `open_bi` second writer is compare-and-clear).
* **The death commit.** `clear_if_and_mark_dead` (`pool.rs:424-449`) folds the
  clear, `live=false` and the stamp reset into one `rcu` decision; the
  `marked && !cleared` restore (`pool.rs:445-448`) is exactly the lost-race
  tail, and `restore_live_if_replaced` bumps the generation so a waiter cannot
  keep observing the transient `false` (`pool.rs:465-474`). The
  retried-closure side effect (stamp reset) is re-seeded by the publisher, and
  an intervening `0` stamp is treated as "unknown, not stale" — fail-safe in
  the right direction.
* **Routing table.** `select_slot` (`pool.rs:545-572`): pinned pin, bulk
  rotation over slots `1..n`, rotated class-preserving failover, bulk→slot-0
  only when no bulk slot is live, preference kept for the bounded `wait_conn`
  stall, `n == 1` short-circuit. The `rr`-advanced-on-every-flow choice is what
  makes pinned fallbacks spread; the tests pin the row-by-row table.
* **Threshold derivation.** 22 s at the shipped 5 s/40 s pair; strictly above
  the healthy-idle age and strictly below the watchdog for every legal
  keepalive with the default idle, and (recomputed here) also for every legal
  explicit idle. `is_data_stale`'s boundary is inclusive and a backwards clock
  cannot manufacture staleness (`saturating_sub`).
* **UDP binding and class boundary.** `udp_bind`/`udp_bind_shard`
  (`pool.rs:903-928`) reduce modulo a count clamped to `>= 1` at construction,
  so no divide-by-zero; `udp_class_slots` (`pool.rs:880-886`) keeps each class
  inside its own shard range; `slot_uses_bulk_preset` and
  `slot_is_latency_sensitive` (`pool.rs:1105-1132`) are correct for both split
  modes (bulk preset only for bulk UDP shards, priority only for slot 0 and
  interactive UDP shards).
* **Egress boundary.** `egress_order`'s fixed array
  (`MAX_POOL_CONNS + MAX_UDP_SLOTS` = 32) is exactly large enough: the visible
  order is a deduplicated walk over at most `tcp_slots + udp_slot_count` = 32
  distinct slots, so `k` never exceeds the array length.
  `forget_slot` compares `EgressCache::slot`, which stores **global** pool
  slot indices, against the global index the conn loop passes — correct for
  TCP holders and for fail-open UDP-on-TCP holders alike.
* **Relaxed liveness reads.** `live` and `last_rx_ms` are hints only;
  `close_reason`/`wait_conn` remain the authority, and a stale `false` can at
  worst cause one extra `changed()` iteration. The stored `gen_rx` is never
  marked seen, so clones carry version 0; `changed()` then returns once
  immediately and marks seen (verified against the pinned tokio source), which
  is a bounded extra re-check, not a spin.
* **`wait_conn` bounds.** The deadline is re-checked each iteration, the
  `select!` covers both the bump and the deadline, and a `live`-stale-true
  handle is rejected by `close_reason` before it is handed out.
* **Slot layout clamping.** `new_with_bulk_ports` and `planned_slot_count`
  agree on every clamp (tested), and `slots_total` never exceeds the 16/8/8
  caps the scratch arrays assume.

---

## Suggested fix order

1. **L1** (medium, user-visible flow failures and generation churn). Attempt
   id in `ZeroRttState` + thread it through `dial_once`'s monitor; unit test the
   late-settle sequence. Consider the per-generation publication as the
   follow-up that also fixes the slot-scoped/connection-scoped mismatch.
2. **L2** (low, routing correctness during degradation). Compose the overlays;
   update the two routing tests.
3. **L3, L4, L5, M1, D1** (small, mechanical). `send_modify`; fd budget from
   the shared layout; the `SlotLayout` extraction; the `forget_slot`
   compare-and-clear; the README/PERF_ANALYSIS corrections.
4. **P1, P2, P4** (perf, only if a profile asks for it; P1 is mechanical, P2 is
   a design choice, P4 is a measurement note).
5. **T1** (test hardening alongside the fixes above).

Validation for the L1 fix: `cargo test -p myquic2 --bin myquic2-client` (the
0-RTT suite in `tests_0rtt.rs` plus the new state-machine case), then the
existing dual-stack/restart E2E if one exercises a failed first candidate.
