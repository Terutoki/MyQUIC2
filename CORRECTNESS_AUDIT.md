# Correctness and memory-leak audit

Audit of the association/session/flow lifecycles, the bounded queues and the
teardown paths, followed by the fixes for what it found. Companion to
[PERF_ANALYSIS.md](PERF_ANALYSIS.md): that document covers throughput, this one
covers correctness.

Method:

* read every lifecycle transition (SOCKS accept → associate → flow binding →
  session table → stager → reader teardown → reconnect) against its bounds;
* targeted runtime soak: 3,000-association churn, file-descriptor and RSS
  sampling during and after the burst, server-side counter reconciliation;
* `cargo clippy --release --all-targets` with the drop/lock lints enabled.

## Findings

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| P1 | a killed client can pin server sessions for up to 180 s | medium | *already handled*; see below |
| P2 | a large simultaneous connect burst overflows the listener backlog | medium | **fixed** |
| P3 | stage-full payload drops are counted but anonymous | low | **fixed** |
| P4 | an invariant `expect` can panic the shared datagram loop | low | **fixed** |
| P5 | lock guards held across a `match` scrutinee | low | **fixed** |

### P1 — torn-down resources (verified, no change needed)

The paths that own state all release it on teardown:

* `sess_reader_task` (`src/bin/myquic2-server/reader.rs:1505`) removes the
  session entry under the shard write guard, purges every flow binding of the
  session from the registry (`remove_session`, `src/mqp/r2_flow.rs:804`), sends
  `SESS_CLOSE` and marks the bindings closed before it returns.
* `conn.closed()` (`src/bin/myquic2-server/accept.rs:3824`) calls
  `SessTable::drain_all`, so a QUIC connection close (graceful *or* idle
  timeout) reaps every session of that connection immediately.
* the client's TCP pump already watches the control channel: the association
  select loop (`src/bin/myquic2-client/assoc.rs`) has a `tcp.readable()` arm
  that breaks the association on EOF, so a SOCKS client that closes its socket
  no longer leaves the relay running (this was an early bug, fixed before this
  audit).
* graceful shutdown closes every endpoint (`src/bin/myquic2-server/main.rs`),
  which sends `CONNECTION_CLOSE` and triggers the `drain_all` above.

The only residual window is a peer that disappears *without* a close: quinn's
idle timeout (60 s, keepalive 5 s) closes the connection, and the 180 s
`SESS_IDLE_MS` sweep covers sessions orphaned by a live peer. Both are bounded
and the admission budget accounts for them, so no code change was made.

### P2 — listener backlog (fixed)

`tcp_listener_dual` called `listen(1024)`. A 3,000-association burst issues
3,000 `connect(2)` calls at once; with 1,024 slots the accept queue overflows
before the accept loop drains it, and ~9 % of the SOCKS handshakes fail
(`failed_assocs=272`, then `948`, then `2,647` across overlapping bursts).

Fix: `LISTEN_BACKLOG = 4096` (`src/lib.rs:652`, used at `src/lib.rs:637`).
Linux honours it (`net.core.somaxconn` defaults to 4096); macOS clamps it to
`kern.ipc.somaxconn` (128 by default — `sysctl -w kern.ipc.somaxconn=4096`
raises it), so on macOS the fix is a no-op unless the sysctl is raised. The
backlog is a queue depth only; the accept loop and the admission semaphores
still bound how many connections are served.

The Linux side is reasoned from `listen(2)` semantics, not re-measured: the
3,000-association burst that produced the 272/948/2,647 failures above was run
on macOS. A Linux run is worth doing before quoting a recovery percentage.

### P3 — anonymous stage-full drops (fixed)

A payload dropped because the connection stager stayed full after a drain was
counted (`dgram_drops::BUFFER_FULL`, the `stage=…full` reporter field) but the
warning named neither the association nor the flow, so an operator could not
tell which app socket was losing datagrams.

Fix: the warning now carries both ids (`src/bin/myquic2-client/rev2.rs:1567`,
`:1609`). Both full-queue paths report them: the push path through
`R2StageItem::ids`, and the requeue-overflow path through `requeue_unsent`,
which now returns the identity of the first item it could not take back.
INLINE items print `inline` rather than a fabricated `flow 0`. The drop verdict
and counters are unchanged, so throughput is not affected; the id extraction
runs only on the drop path, not on every staged payload.

### P4 — panic on the datagram path (fixed)

`encode_train_run` used
`.expect("every run flow was deduped into the flow list")`
(`src/udp/r2_stage.rs:754`). The invariant holds today (`take_steady_head`
builds the flow list from the run itself), but a future edit breaking it would
panic the task that drains **every** association of the connection.

Fix: the lookup returns `None` on a miss (the caller already books that case as
too-large and drops the frame) and reports the broken invariant once through
`tracing::error!`, so a future logic bug degrades to a counted drop and a single
log line instead of a panic. Regression test:
`encode_train_run_drops_a_run_whose_flow_is_not_in_the_list`.

### P5 — guards held across a match (fixed)

Clippy's `significant_drop_in_scrutinee` fired at two sites:

* `src/bin/myquic2-server/reader.rs:655` — `match stage.lock().push(item)`
  held the stager mutex until the end of the match;
* `src/mqp/r2_flow.rs:805` — `match self.by_session.write().remove(&session)`
  held the per-session index lock until the end of the match. The map write
  lock was taken *after* the match, so the two guards never actually overlapped;
  an arm that later learned to take it would have inverted the order
  (`insert`/`clear` take map first).

Both now bind the result before the `match`, so the guard is released at the
end of the statement. No behaviour change; the lints are clean.

## Verification

* `cargo test --release`: **721** tests pass (360 lib, 201, 145, 7, 8).
* `cargo clippy --release --all-targets` clean; the
  `significant_drop_in_scrutinee` / `await_holding_lock` runs no longer warn.
* 3,000-association churn soak: server fds return to the 18-fd baseline after
  the idle sweep, client fds stay at 54 for every cycle, RSS plateaus
  (19.1 MB → 67.5 MB retained allocator, no per-cycle growth).
* 2,000-association burst with the fixed binaries: the listener starts cleanly
  (no `EADDRINUSE`), warm runs report `failed_assocs=0`.

## Not addressed here

* macOS `kern.ipc.somaxconn=128` clamps the backlog regardless of the code
  constant.
* Datagram loss inside a short burst is application-level: the association
  bench sends without retransmission inside a 5 s window, and UDP has no
  recovery — it is not a proxy leak or a queue that grows without bound.
