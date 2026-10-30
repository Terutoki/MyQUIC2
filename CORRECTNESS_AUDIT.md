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
| P6 | a hard server restart left the client spinning a core per connection | high | **fixed** |

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

Fix: the warning now carries both ids (`stage_or_count` and `warn_stage_full`
in `src/bin/myquic2-client/rev2.rs`). Both full-queue paths report them: the
push path through
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

* `stage_open_src` (`src/bin/myquic2-server/reader.rs`) — `match
  stage.lock().push(item)` held the stager mutex until the end of the match;
* `FlowRegistry::remove_session` (`src/mqp/r2_flow.rs`) — `match
  self.by_session.write().remove(&session)` held the per-session index lock
  until the end of the match. The map write
  lock was taken *after* the match, so the two guards never actually overlapped;
  an arm that later learned to take it would have inverted the order
  (`insert`/`clear` take map first).

Both now bind the result before the `match`, so the guard is released at the
end of the statement. No behaviour change; the lints are clean.

### P6 — post-restart busy loop on a closed control queue (fixed)

Reported symptom: the server restarts, the client reconnects, and a minute later
one or two client cores sit at 100%. Reproduced end-to-end by
`rev3_hard_server_restart_reconnect_does_not_burn_cores`
(`tests/rev3_e2e.rs:1137`): UDP traffic through a running server, 1.5 s for the
client to store tickets, the server `SIGSTOP`ped past the client's 10 s silence
watchdog, the paused process `SIGKILL`ed, and a fresh process started from the
same config (same certificate, new ticket keys). The first redial offers the
stale ticket, the new process cannot decrypt the early data and rejects 0-RTT
(`0-RTT rejected` in quinn, `Not resuming` in rustls) while the 1-RTT connection
itself is healthy.

The rev3 control stream was the only client stream opened while the handshake
was still in flight, so the rejection reset it (`ZeroRttRejected`).
`spawn_ctl_stream` (`src/bin/myquic2-client/dispatcher.rs:1240`) then returned
and dropped the dispatcher's inbound queue. The dispatcher's select arm

```rust
msg = dispatch_ctl_rx.recv() => { if let Some(msg) = msg { ... } }
```

had no `None` arm, and a closed, empty tokio `mpsc::Receiver` is ready
immediately on every poll: the arm became a permanently ready branch, so the
slot's `current_thread` runtime — one OS thread pinned to a core — spun at 100%
for the rest of the generation's life. That is one core per affected connection,
measured at 6.29 cores on a 10-core macOS box (the report's one or two cores is
the same bug on a smaller client).

Fixed in two layers:

* **Never open the control stream into 0-RTT.** `spawn_ctl_stream` now waits for
  the handshake phase to settle (`ZeroRttState::wait_settled`, bounded by
  `DIAL_ATTEMPT_TIMEOUT` and aborted early by `conn.closed()`) before opening
  the stream. The wait costs at most one round trip and loses nothing: outbound
  control messages queue in the bounded `CTL_QUEUE` until the stream is up, and
  no data-path work awaits the control plane. A full-handshake dial settles
  immediately (`NONE`), so non-resumed connections are unaffected.
* **Retire a generation whose control stream dies anyway.** The dispatcher's
  `None` arm now closes the connection (when it is still up) and breaks, so the
  reconnect loop publishes a fresh generation within its 200 ms–5 s backoff. A
  rev3 generation without its reliable control plane cannot repair context
  (`NEED_CONTEXT`), refuse flows (`REJECT`) or deliver closes, so retiring it is
  the only correct outcome. The retirement is counted as `ctl_stream_closed`
  (`src/bin/myquic2-client/rev2.rs:2137`).

The E2E test covers both layers: with only the settle wait reverted it fails on
eight post-restart control-stream teardowns (`connection already closing:
false`, one per slot); with the original code (both layers absent) it fails on
CPU — 6.29 cores for the restart sequence that burns 0.01 cores now.

## Verification

* `cargo test --all-targets`: **725** tests pass (360 lib, 201 client, 148
  server, 7 forwarding E2E, 9 wire-revision E2E, including the restart
  regression test).
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
