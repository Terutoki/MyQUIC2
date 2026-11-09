# TCP / UDP ECHO path review — performance and logic

Scope: the whole data plane an echo workload exercises, on the current tree
(`b6c1757`, 2026-11-09):

- **UDP**: SOCKS5 `UDP ASSOCIATE` (`assoc.rs`), `[[udp_forward]]`
  (`forward_udp.rs`), the client connection-scoped stager (`rev2.rs`,
  `udp/r2_stage.rs`), the client dispatcher (`dispatcher.rs`), the server
  datagram reader / fast table / session readers (`accept.rs`, `reader.rs`,
  `table.rs`, `memo.rs`, `pin.rs`), and the shared wire codecs.
- **TCP**: SOCKS5 `CONNECT` (`socks.rs`), `[[tcp_forward]]` (`forward.rs`),
  the relay pump (`tcp/pump.rs`), the server header/dial path (`tcp.rs`) and
  the server stream-task admission (`accept.rs`).

Out of scope: DNS internals (covered by `analysis/dns-review.md`), the pool's
reconnect state machine (covered by `analysis/pool-review.md`), and the
transport's congestion-control tuning.

Method:

1. Read every hop of the two echo directions, including the error/teardown
   paths, and cross-check the claimed invariants against the code.
2. Verify the runtime-topology claims against the pinned dependency sources
   (`quinn 0.11.12`, `tokio 1.54`): in particular, `quinn::TokioRuntime` is a
   unit struct whose `spawn`/`wrap_udp_socket` use the **ambient** runtime
   (`quinn-0.11.12/src/runtime/tokio.rs:19-40`), so an endpoint created inside
   the shard's `block_on` really does keep its driver, connection drivers,
   stream tasks and session readers on the shard thread.
3. Run the full test suite (see *Verification*). No new performance benchmark
   was run; every performance claim below is a code-level cost model, and the
   ones that need a profile are marked **measure**.

This review is a follow-up to `analysis/echo-path-lock-audit.md`
(2026-11-04). That audit's central result still holds: on the default sharded
topology there is no steady-state **lock contention** on this path; the cost is
single-thread per-packet work (syscalls, QUIC crypto, copies). The items below
are the next layer: unconditional copies/allocations, a few cross-runtime
ordering problems, protocol-state races, and drop-accounting classes.

---

## Summary

| # | Finding | Type | Severity | Status |
|---|---|---|---|---|
| L1 | Reply-source updates are unversioned: a stale `FLOW_ACK` (or a reordered `OPEN\|SRC`) can confirm a source the peer never learned; the client then keeps writing an old source into the SOCKS5 header while the server compresses | logic | **P2** | fixed (source-carrying ACK; short reorder window remains) |
| L2 | `PumpAbort` cancels the TCP pump without running the RST / `reset` / `stop` disposition; quinn's `SendStream::drop` calls `finish()`, so an aborted relay can look like a clean EOF | logic | **P2** | fixed |
| L3 | `[[udp_forward]]` burst flush can perform a blocking connection-wide drain on the main runtime (`flush_stage` opportunistic drain at ≥64 items), contradicting the E1 placement | performance | **P2** | fixed |
| L4 | The server copies every small reply into an owned `R2StageItem` before the lone-reply direct path, which then copies again into the DATAGRAM; the steady echo reply pays two payload copies and two allocations, where the client downlink pays zero | performance | **P2** | partial (burst-end fast path only; per-reply borrowed direct reverted to keep train packing) |
| L5 | The client has no analogue of the server's `try_send_direct`: a one-datagram request burst always pays the item copy + stager push + drain (gate + claim + encode copy): ~4-5 stager lock acquisitions (one a try_lock) and 2 payload copies per request | performance | **P2** | partial (stager round trip removed; item copy remains) |
| L6 | A large standalone payload drains the entire connection-wide stager (up to 1024 items from all sessions) before it is sent, head-of-line blocking other associations on the same connection | performance | **P3** | fixed |
| L7 | `SpaceCache` is not a lower bound on quinn's DATAGRAM buffer space: it subtracts payload bytes only, while quinn charges the encoded frame (headers/TRAIN overhead) and control DATAGRAMs are not counted at all. The "admission decisions are identical" claim is false | claims / policy | **P3** | fixed |
| L8 | `SharedEgress::invalidate` is an unconditional store; a stale `ConnectionLost` verdict can wipe a concurrent refresh's fresh publish | race | **P3** | fixed |
| L9 | `SharedEgress::forget_slot` clears the shared cache but not per-thread egress memos; a thread that stops sending on a binding pins a dead `quinn::Connection` (and its buffers) until it next uses that binding or exits | memory | **P3** | fixed (memo holds a Weak<EgressCache>) |
| L10 | Warm-cache and cold-cache domain `DATA OPEN` install different reply-source sets (`vec![dst]` vs all policy addresses), and a domain flow is pinned to `resolved_first()` with no record failover; a dead first record blackholes the flow, and a reply from another record is refused on the warm path | logic | **P3** | partial (warm/cold set consistent; record failover not implemented) |
| L11 | Terminal-verdict drops of a pre-stager batch are booked as `BUFFER_FULL` instead of `EGRESS_DEAD` on both ends, hiding connection death inside buffer pressure | accounting | **P3** | fixed |
| L12 | `R2Stager::rotate_steady_past` is O(steady sessions) for the first session of every frame; on a high-fan-out connection a drain is O(frames × sessions) pointer moves | performance | **P3** | partial (scan bounded to 32; linked-list cursor not adopted) |
| L13 | TRAIN ingress decodes every frame twice (id pass, then payload pass) and initializes ~3 KB of stack arrays per frame on both client and server | performance | **P3** | fixed |
| L14 | The session memo (L2) is per worker thread and shared by every connection on the shard; the documented "2× headroom over the fast table" is a per-connection ratio but the effective per-connection L2 shrinks as connections per shard grow | sizing / docs | **info** | docs updated (no code change) |
| L15 | A `[[udp_forward]]` listener admits from the main runtime while the slot runtime drains/sends: `admit_uplink` takes the connection stager mutex **per payload**, and may take quinn's state lock on an estimate miss; the "every per-connection structure on one thread" premise does not hold for the forward shape | performance / claims | **P2** | fixed (staged bytes published atomically) |
| K1 | A queued `OPEN\|SRC` never learns `reply_src`/`note_ctx_sent`; the flow stays `Rebind` until a later direct send succeeds | logic | P3 | fixed (source learned before the context is queued) |
| K2 | The first fragmented payload after the DATAGRAM buffer becomes full can still send a prefix and drop the tail; the all-or-nothing gate is only armed after a previous `Blocked` | logic | P3 | known residual of F9 |
| K3 | macOS portable receive pays one `try_recv_from` EAGAIN per burst; Linux uses `recvmmsg` | performance | P3 | known (E4) |
| K4 | The drain gate covers encode+send and one `drain_staged` call can process up to `R2_STAGE_MAX_ITEMS` = 1024 items | performance | P3 | known (E5); becomes P1 under `MYQUIC2_SHARD_RUNTIME=0` |
| K5 | Server fast table is ~568 slots/connection against a documented ~2000-session working set; the rest takes the slow path | performance | P2 (shape) | known (E3) |

Severity is relative to this path: **P2** = measurable on a common echo shape
or a persistent state/data-integrity error; **P3** = edge shape, accounting, or
a claim that needs a profile/benchmark; **info** = sizing/documentation.
**measure** means the impact is a code-level cost estimate, not a measured
regression.

No P1 was found on the shipped topology. The two highest-impact logic items are
L1 (a persistent wrong SOCKS5 source) and L2 (silent FIN on a cancelled TCP
relay); both are narrow-window but real. The largest performance items are
L15/L3 (the forward listener's cross-thread admission and opportunistic drain),
L4/L5 (the two missing lone-payload direct paths), all of which need a profile
of the deployed shape before they displace the known residuals.

---

## 1. Topology and per-hop cost

### 1.1 Topology (verified)

- **Server**: one current-thread runtime per ingress endpoint
  (`myquic2-server/main.rs:605-660`); the endpoint is built inside
  `rt_thread.block_on`, and `quinn::TokioRuntime` uses ambient `tokio::spawn`
  and ambient `tokio::net::UdpSocket::from_std`, so the endpoint driver, every
  `ConnectionDriver`, every connection's datagram reader, every session reader
  and every TCP stream task run on that one shard thread.
- **Client**: one current-thread runtime per pool slot
  (`myquic2-client/main.rs:887-930`); the TCP pump is spawned on the slot
  runtime (`run_tcp_pump`, `main.rs:146-172`), and a UDP association's steady
  state is moved to the slot runtime that owns its egress binding
  (`assoc.rs:1091-1138`).
- **Consequence**: the stager mutexes, the drain gate, the flow registry, the
  fast table and the session memos are single-threaded for a pure SOCKS
  association in steady state. The existing audit's "no contention" result is
  structural for that shape. It has two exceptions (L15): a `[[udp_forward]]`
  listener runs on the main runtime and touches the same connection's stager,
  and each association's first burst runs on the caller's runtime before the
  steady state moves. The costs below are mostly unconditional work, not
  waits, but "one thread per connection" is not a universal invariant.

### 1.2 UDP ECHO, hop by hop (steady small payload)

| Hop | Unconditional work per payload | Notes |
|---|---|---|
| app → relay (`assoc.rs`) | 1 `recv_from` (or one `recvmmsg` refill per burst), SOCKS5 header validation, `coarse_millis` once per burst | burst path handles up to 31 extras in place (`with_burst_msg`) |
| egress resolve (`egress.rs`) | one generation load, one thread-local memo check, no Arc clone on a hit | refresh winner once per 1 s per binding; quinn `close_reason`/`max_datagram_size` only there |
| uplink admission (`rev2.rs`) | `mono_millis` + `queue_window_cap` (stats once/250 ms) + **stager mutex `queued_bytes`**; `SpaceCache` CAS if it fits | L7 / K6 |
| uplink encode (`rev2.rs`) | `Bytes::copy_from_slice(payload)` (alloc+copy), item push | L5 |
| burst end (`rev2.rs` + `r2_stage.rs`) | `push_stage_batch` (1 stager lock), `drain_stage` (gate lock, empty probe, claim lock, post-drain try_lock), `claim_batch`, `encode_claimed` (alloc+copy), `try_send_datagram` (quinn state lock) | for a one-payload burst this is the whole stager round trip; ~4-5 stager acquisitions |
| server ingress (`accept.rs`) | `read_datagram`, `wire::kind`, decode (zero-copy slice), fast-table probe (~71 tags), `mirror_record` (epoch check), staging push | fast path; slow path adds session memo/shard read |
| server → target (`accept.rs`) | burst-end `sendmmsg` (≤32) / `try_send_to` per frame | zero-copy slice from the received DATAGRAM |
| target → server (`reader.rs`) | `recvmsg`/`recvmmsg`, reply-source validation (memo/ring/flow), `Bytes::copy_from_slice` into item, `StageBatch::flush` | L4 |
| server reply (`reader.rs`/`r2_stage.rs`) | `try_send_direct` (stager lock + gate try-lock) or staged drain; `encode_standalone_item_for` (alloc+copy); `try_send_datagram` (quinn lock) | L4 |
| client dispatcher (`dispatcher.rs`) | `read_datagram`, `wire::kind`, registry lookup, `Weak` upgrade/`is_alive`, stage as a `Bytes` slice, grouped `sendmmsg` with header+payload iovecs | **zero payload copy** on the downlink |
| client app (`assoc.rs`) | `sendmmsg`/`try_send_to`, `entry.mark_replied` store | reply path takes no clock |

The two asymmetries worth naming: the **client uplink** pays a staging round
trip the **server downlink** avoids, and the **server reply** pays a payload
copy the **client downlink** avoids.

### 1.3 TCP ECHO

| Hop | Work | Notes |
|---|---|---|
| SOCKS CONNECT (`socks.rs`) | negotiate, `pick_tcp_index` (coarse clock + live/dead probes), `wait_conn`, `open_bi`, header write, optimistic reply | one quinn state-lock probe in `pick_tcp_index` + one in `wait_conn`; known P2/P3 pool notes |
| client pump (`tcp/pump.rs`) | c2s `read_buf` 16 KiB (double buffer, pooled), `write_chunk` ≥8 KiB zero-copy / `write_all` below; s2c `read_chunks(8)` + `write_vectored` | one quinn state lock per 16 KiB chunk / per batch; on the slot runtime |
| server stream (`tcp.rs`) | 5 s header read (header-credit bounded), per-connection share, global stream permit, dial permit, happy-eyeballs, `TCP_NODELAY`/`TCP_NOTSENT_LOWAT`, ACK write, pump | dial budget 4 s; ACK budget 5 s |
| target | — | — |
| teardown | clean → `tcp.shutdown()`; abnormal → `abort_tcp` RST + `send.reset`/`recv.stop` | **not reached on task cancellation** (L2) |

---

## 2. Findings

### L1 — A stale `FLOW_ACK` (or a reordered `OPEN|SRC`) can confirm a reply source the peer never learned

**Severity: P2 (logic / data integrity).** Persistent wrong SOCKS5 source
address; possible app-level mis-association. **Status: fixed for the persistent
case** by the source-carrying rev2 `FLOW_ACK_SRC` / rev3 `SRC_ACK`; a reordered
older context can still move the client backwards for a few frames, but the
server's mismatch ACK now clears the confirmation and re-sends the current
context, so it converges. A wire source epoch is the remaining full fix.

**Where**

- Server binding state: `set_reply_src` sets the address and **clears**
  `reply_src_acked`; `mark_reply_src_acked` sets only a boolean and carries no
  address (`src/mqp/r2_flow.rs:269-289`).
- Server `FLOW_ACK` handler: `Ctl::FlowAck { id, .. } => { registry.get(id) →
  mark_open() + mark_reply_src_acked() }` (`accept.rs:2784-2790`). It cannot
  tell which `OPEN|SRC` the ACK belongs to.
- Server classification: `match_source` returns `Exact` when
  `reply_src == src && (reply_src_acked || target_names_src)`
  (`r2_flow.rs:433-474`); the reply path is `reader.rs:1578-1621`.
- Client receive: `dispatch_r2_data` sets `binding.set_reply_src(src)` for every
  `OPEN|SRC` and ACKs it (`dispatcher.rs:1395-1403`); a **steady** frame is
  delivered with `r2_reply_dst(binding)` — the latest source the client
  happened to apply (`dispatcher.rs:1404-1419`, `r2_reply_dst` at `:827-844`).
- Server send: `OPEN|SRC` is emitted by `stage_open_src`
  (`reader.rs:867-918`) and, for large replies, by `r2_send_large_reply`
  (`reader.rs:1083-1117`).

**Mechanism (rev2)**

1. Target replies from `s1`. The server classifies `Rebind`, sends
   `OPEN|SRC(s1)` directly and does `set_reply_src(s1)`; `acked = false`.
2. The client decodes it, sets its `reply_src = s1`, and sends `FLOW_ACK{id}`.
3. Before that ACK arrives, the target starts replying from `s2` (anycast,
   multi-homed service, port change). The server sends `OPEN|SRC(s2)` and
   `set_reply_src(s2)`; `acked = false` again.
4. The stale `FLOW_ACK` for step 2 arrives. `FlowAck` has only the id, so the
   handler marks the **current** source `s2` acked.
5. A later reply from `s2` now classifies `Exact`; the server sends a steady
   (address-less) frame. If the client's `OPEN|SRC(s2)` was lost or reordered
   behind this steady frame — both are UDP DATAGRAMs — the client's
   `reply_src` is still `s1`. It writes `s1` into the SOCKS5 reply header for a
   payload that actually came from `s2`.
6. Because the server now considers the source acked, it never repeats
   `OPEN|SRC(s2)`; the wrong source persists for the flow's life.

The symmetric trigger needs no stale ACK at all: if `OPEN|SRC(s2)` is
reordered behind an older `OPEN|SRC(s1)`, the client applies s1 last and
sends the ACK for the id; the server, whose current source is s2, marks s2
acked (or, on rev2, is still waiting for an ACK and accepts this one). Nothing
in the frame identifies which source the ACK is for, and nothing in the client
rejects an older source. Both are the same missing generation.

The same class exists in rev3 without an ACK: `note_ctx_sent` confirms the
source after K=2 successful context frames (`reader.rs:467-488`). If both
context frames are lost or reordered behind the first steady frame, the client
has no way to ask for the source again: `NEED_CONTEXT` repairs an **unknown
flow id**, not a stale source (`dispatcher.rs:1111-1136`, `accept.rs:2913-2926`).
For a domain flow `r2_reply_dst` is `None` in that state and the steady frame is
dropped (loss, not mislabel); for an IP flow whose source port changed, the
fallback is the target address, i.e. a wrong source port.

**Why the existing guards do not cover it**

- `ReplySourceMemo` validates `observed_reply_src` and `observed_acked`
  (`reader.rs:294-327`). A stale ACK changes `acked`, which invalidates the
  memo — but the **new** scan still returns `Exact`, so the memo is not the
  problem; the state transition is.
- The "re-send until ACK" rule is sound only if an ACK identifies the
  context it confirms. It does not.

**Fix direction**

- Version the reply source: add a source generation/epoch to `OPEN|SRC` and
  echo it in `FLOW_ACK` (the existing `status` byte is a natural place for a
  small generation, or add a `src_epoch` field to the rev2/rev3 binding form).
  `mark_reply_src_acked` would take the generation and confirm only if it
  matches the current one.
- Alternatively, treat a source change as requiring a **new** confirmation
  window that a stale ACK cannot close: e.g. record `src_epoch` and only accept
  an ACK whose generation is ≥ the latest; on a changed source, suppress
  compression until an ACK generated *after* that change arrives (this needs
  the epoch in the ACK to be robust).
- Cheapest partial mitigation for rev3: carry the context (source) on the first
  N steady frames after any source change, and make `NEED_CONTEXT` re-arm the
  source as well as the id.
- Regression test: two source changes within one RTT, deliver the old ACK after
  the second `set_reply_src`, assert the next reply is **not** steady until the
  client has decoded the second `OPEN|SRC`.

**Note:** K1 (a queued `OPEN|SRC` never learned the source) was fixed with the
same change: the source is recorded **before** the context is queued, and the
source-carrying ACK confirms it (see *Fix landing*).

### L2 — Cancelling the TCP pump skips the RST / `reset` / `stop` disposition

**Severity: P2 (logic / teardown integrity).** A truncated TCP flow can be
presented to the peer and the application as a clean transfer.

**Where**

- `PumpAbort` aborts the spawned pump when the caller future is dropped;
  the comment claims "the pump's own drops then close the socket and
  reset/stop the stream" (`main.rs:110-122`, used at `:156-159`).
- The pump deliberately owns the final disposition in
  `copy_tcp_quic_inner`: clean EOF → `tcp.shutdown()` FIN; **any** `Err` →
  `abort_tcp` (SO_LINGER=0 RST) + `send.reset(0x04)` / `recv.stop(0x04)`,
  gated on the per-direction completion flags (`tcp/pump.rs:592-630`).
- Quinn's `SendStream::drop` calls `finish()` — a graceful FIN
  (`quinn-0.11.12/src/send_stream.rs:344-354`); `RecvStream::drop` stops the
  receive side (`recv_stream.rs:523+`); the owned `TcpStream` drop is a FIN.

**Mechanism**

When the pump task is aborted (caller future dropped on runtime shutdown, a
fatal slot-runtime error, or any external cancellation), the pump future is
dropped at an await point. The `match outcome` block never runs. The owned
`tcp`, `send` and `recv` are dropped by the future's destructor: the TCP socket
FINs and the QUIC send half FINs. The `copy_tcp_quic_inner` contract — "any
abnormal end aborts with RST and resets/stops the peer" — is bypassed exactly
in the case it was written for: an abandoned, incomplete transfer.

**Trigger rating:** rare in normal operation (the SOCKS/forward tasks are not
individually aborted), but a slot-runtime failure or process shutdown while a
large upload/download is in flight is exactly when silent truncation is worst.
The E2 commit's claim that abort is equivalent to the old inline drop is
therefore not correct: the inline drop also skipped the disposition, but the
comment now sells the abort as restoring it.

**Fix direction**

- Make `PumpAbort` hold the owned `TcpStream`/stream halves, or add a drop
  guard created by `run_tcp_pump` that, on abort, sets `SO_LINGER=0` and calls
  `send.reset`/`recv.stop` before the future's fields drop. The guard must not
  run on normal completion.
- A simpler shape: pass the halves into a small `PumpGuard` owned by
  `run_tcp_pump` (not by the pump future) and let the pump borrow them; the
  guard's `Drop` decides RST vs FIN from a shared completion flag.
- Test: abort a pump mid-upload and assert the peer's `read_chunks` returns
  `ReadError::Reset`, not `Ok(None)`.

### L3 — `[[udp_forward]]` can still drain the connection stager on the main runtime

**Severity: P2 (performance/placement; shape-dependent).**

**Where**

- `UdpForwarder::flush_peer` calls `flush_assoc_stage`
  (`forward_udp.rs:766-788`), which is documented as "push ... **without**
  draining here" (`rev2.rs:2569-2583`).
- But `UplinkFlows::flush_stage` has an opportunistic drain: after a successful
  `push_stage_batch`, if `queued >= R2_MAX_TRAIN_ITEMS` (64) it calls
  `drain_conn_stage` (`rev2.rs:1490-1500`), which calls the **blocking**
  `drain_stage` (`rev2.rs:2117-2120`, `udp/r2_stage.rs:1361-1372`).
- `R2Stager::claim_batch` can process 4 frames/64 items per batch and
  `drain_staged_inner` loops up to `R2_STAGE_MAX_ITEMS` (1024), so this is an
  encode+send loop, not a cheap nudge.

**Mechanism / impact**

The listener's `touched` list can hold up to `LAST_HOP_DRAIN` peers. For each
peer it pushes that peer's batch; the returned `queued` is the **total** queue
length, so any time the connection stager already holds ≥64 items (many peers,
or a previous drain that returned `Blocked`), the listener thread performs a
full drain: stager lock, drain gate, claim, encode, `try_send_datagram` and
quinn's connection-state mutex. Under a saturated send buffer each such drain
also probes `datagram_send_buffer_space()` (one quinn state lock) before
bailing. This is exactly the cross-core work E1 moved to the slot runtime; the
listener is on the main multi-thread runtime while the driver is on the slot
thread.

The single-flight `egress.refreshing` gate is not involved here; the drain is
serialized by the stager's own drain gate.

**Fix direction**

- Add a `flush_stage_no_drain` (or a `push_only: bool`) used by
  `flush_assoc_stage`; the retry task is already notified by
  `request_drain`, and `flush_assoc_stage` calls it unconditionally.
- Or move the opportunistic-drain trigger to "only when the caller is the
  connection's own slot runtime" (e.g. pass a `may_drain` flag from the
  SOCKS association vs. the forward listener).
- Regression test: a forward listener with >64 queued items on a shared
  connection must not call `drain_staged` from the listener thread (a test
  seam can assert the drain count).

### L4 — Small-reply downlink pays a redundant item copy before the direct-send fast path

**Severity: P2 (performance; steady echo reply).** **Status: partial.** The
per-reply borrowed direct path was implemented and reverted: it sent the first
reply of every multi-reply burst standalone and broke the cross-session TRAIN
packing (`rev2_downlink_steady_train_and_port_rebind`,
`rev2_stage_cross_session_dict_train`). The existing burst-end
`StageBatch::flush_single` fast path still avoids the queue round trip; the item
copy remains until a burst-count/borrowed-item design lands.

**Where**

- `handle_session_reply` creates the item with
  `payload: Bytes::copy_from_slice(payload)` for every small reply
  (`reader.rs:1657-1661`; the `Blocked` large-reply path does the same at
  `:934-961`).
- The lone-reply fast path (`StageBatch::flush` → `flush_single` →
  `try_send_direct`) then calls `encode_standalone_item_for`, which allocates a
  body and copies `item.payload` again (`reader.rs:743-747`, `:781-815`;
  `udp/r2_stage.rs:1465-1497`, `:1288-1311`).

**Mechanism / impact**

For a single small steady reply (DNS/STUN/game request-response, the `lat` and
one-shot echo shape), the server pays:

- one heap allocation + payload copy to build the `R2StageItem`;
- one heap allocation + payload copy to encode the DATAGRAM body;
- a stager lock and a drain-gate try-lock in `try_send_direct`.

The client downlink delivers the same payload with **zero** copies (a `Bytes`
slice plus a two-iovec `sendmmsg`). The server's direct path was introduced to
avoid the **queue** round trip, but it does not avoid the item copy; the
`PERF_ANALYSIS` §22.3 counts the queue round trip as "two allocations, two
copies"; in the current code the direct path still pays the item copy and the
encode copy, so only the queue bookkeeping (not the copies) was removed.

**Quantify (measure):** at 128 B and 40k replies/s the copy is ~10 MB/s plus
40k allocations/s; at 512 B it is ~40 MB/s. The allocator traffic and the
extra cache footprint are the cost, not the bytes.

**Fix direction**

- Before building the item, if this is a lone small `Exact` reply (the burst
  batch is empty and the connection stager is empty / gate free), encode
  directly from the borrowed `payload` with the same wire encoder and send it.
  Only fall through to the owned item + queue when the direct send returns
  `NotNow`. This is a `try_send_direct_borrowed` sibling of the existing
  helper; it preserves ordering because the stager empty/gate-free conditions
  are the same.
- Alternatively, change `StageBatch` to hold a borrowed/`Bytes`-slice item for
  the duration of one burst and only materialize owned items when pushing to
  the stager.

### L5 — The client uplink has no lone-payload direct path

**Severity: P2 (performance; one-datagram request/response shape).**
**Measure.** **Status: partial.** `flush_lone_direct` now sends a lone staged
payload through `try_send_direct` (no push/drain); the item copy in
`send_uplink` remains because removing it needs a borrowed stage item whose
lifetime spans the burst.

**Where**

- Small payloads are always copied into an `R2StageItem`
  (`rev2.rs:2018-2023`, `:1989-1997` for INLINE) and pushed into the
  association batch.
- At the burst boundary `relay_burst` calls `drain_assoc_stage`
  (`assoc.rs:673-685`), which pushes the batch (`rev2.rs:1461-1535`) and drains
  the connection stager (`rev2.rs:2521-2551`).
- The server has the equivalent fast path (`try_send_direct`); the client has
  no `try_send_direct` call site (grep: only `src/udp/r2_stage.rs` and
  `server/reader.rs`).

**Mechanism / impact**

For a burst of one datagram (the serial echo/latency shape), the client pays:

- `Bytes::copy_from_slice` (alloc+copy) into the item;
- `push_stage_batch`: stager lock, HashMap entry, VecDeque push;
- `drain_stage` → `drain_staged_inner`: one stager lock to clone the gate, one
  for the emptiness probe, one for the claim, plus the gate; then a post-drain
  `try_lock` in `ConnRev2::drain_stage`, `claim_batch`, `encode_claimed`
  (alloc+copy), `try_send_datagram` (quinn state lock).

The cross-session TRAIN that justifies the stager has nothing to pack for a
single payload. The server's `flush_single` proves the pattern is safe when the
queue is empty and the gate is free. On the sharded topology the locks are
uncontended, but the allocations/copies and the extra bookkeeping are paid
per request; the existing `lat` p50 (111 µs) includes them.

**Fix direction**

- Mirror the server: a `try_send_direct`-based path for the association's
  lone staged item at burst end (`try_send_direct` takes the item by value and
  returns `NotNow` when the queue/gate is busy, so the normal drain can
  follow). This removes the second stager acquisition and the queue
  bookkeeping, but not the item copy.
- To remove the item copy as well, defer materializing the owned `R2StageItem`
  until the burst is known to have more than one payload; keep the received
  payload in the association-owned recv buffer (or a small borrowed arena) for
  the burst, encode directly at the boundary, and only copy into items when
  pushing to the shared stager. This is the shape the server could use too
  (L4), so design it once.
- Regression: a one-datagram burst must produce one DATAGRAM with the same
  bytes and one stager acquisition (test seam) rather than push+drain.

### L6 — A large payload drains the whole connection stager

**Severity: P3 (performance / head-of-line; mixed sizes).**

**Where:** `send_uplink`, large-payload branch: `up.flush_stage` then
`drain_conn_stage` before `send_standalone`
(`rev2.rs:2025-2045`; `drain_conn_stage` at `:2117-2120`).

**Mechanism / impact**

The stager is connection-scoped and holds every association's queued small
payloads. The stated reason is per-session FIFO: this session's earlier small
payloads must be on the wire before the large one. But the call drains **all**
sessions, up to the 1024-item call budget. On a connection multiplexing many
associations, one 60 KiB datagram can synchronously encode and send a large
backlog belonging to unrelated sessions, delaying itself and consuming the
slot thread. A per-session drain (`drain_staged_for_session`) would preserve
the required order without the cross-session head-of-line block; the stager
already has per-session queues and a steady cursor over them.

**Fix direction:** add a session-scoped drain (claim only this session's items,
plus the TRAIN packing restrictions) or cap the pre-large drain to the
session's own queued items. Keep the connection-wide drain at burst ends.

### L7 — `SpaceCache` over-admits: it counts payload bytes, not DATAGRAM bytes

**Severity: P3 (claims / queue-window accuracy).**

**Where**

- `SpaceCache` and `note_admitted(len)` (`rev2.rs:129-215`); `admit_uplink` and
  `admit_standalone` call it with `item.payload.len()` / `len`
  (`rev2.rs:557-583`, `:601-625`).
- The encoded frame includes `DATA`/`OPEN`/`INLINE`/TRAIN headers
  (`mqp/r2.rs`, `mqp/r3.rs`); quinn's `datagram_send_buffer_space()` charges
  the **encoded body**, not the raw payload. The steady `DATA` header is 2-3 B
  on rev2 and 2 B on rev3; the `OPEN`/`OPEN|SRC`/`INLINE` forms carry an
  address and are larger; each TRAIN item adds a length field plus the train
  header.
- Control DATAGRAMs (`HELLO`, `FLOW_ACK`, `SESS_CLOSE`) go through
  `try_send_datagram` directly (`rev2.rs:1224-1305`, `dispatcher.rs:873-887`)
  and never call `note_admitted`; each one reduces quinn's space without
  updating `since`.

**Mechanism / impact**

The type's key claim — "admitted bytes are >= bytes actually handed to quinn,
so `space()` is a lower bound" (`rev2.rs:93-123`) — is false by the frame
header length (2-3 B for a steady rev2 DATA, 2 B for rev3, more for the
OPEN/INLINE/TRAIN forms) and by every uncounted control frame. A cached "fits" can therefore be false; the 10 ms queue window can be
exceeded by the accumulated overhead since the last exact probe. The admitted
set is *close* to the unconditional-probe rule, not identical:
- at 128 B payloads and ~2 B headers, the over-admit is ~1.5 % of the window;
- at 20 B payloads, ~10 %;
- a burst of `SESS_CLOSE`/`FLOW_ACK` adds its own bytes.
These are policy/queueing errors, not corruption; the send may later return
`Blocked` and drop the newest payload, which is the policy the window exists to
avoid.

**Fix direction:** either charge the encoded body size (the encoder knows the
header length; `frame_limit`/`encode_*` can return it) or add a fixed
per-payload overhead and count control sends. At minimum, correct the comments
and the commit/test claim; the `SpaceCache` tests
(`rev2.rs:3087-3153`) only pin the arithmetic, not the payload-vs-wire
identity.

### L8 — `invalidate` can wipe a fresh publish

**Severity: P3 (race; extra refresh/hold).**

**Where:** `SharedEgress::invalidate` does an unconditional
`cached[bind.index].store(None)` plus a generation bump (`egress.rs:497-501`);
called from `recover_send_outcome` for `ConnectionLost` /
`Unsupported` (`assoc.rs:1205-1232`).

**Mechanism**

A `ConnectionLost` verdict belongs to the handle the send used. That handle may
be an old memo entry while another thread has already refreshed the binding and
published a fresh connection. `invalidate` then drops the fresh publish. The
generation bump makes every thread's memo miss, so the next datagram re-acquires
(correctness is preserved), but the refresh may hit the single-flight gate held
by another thread and fall into the W3 hold; under a reconnect storm this
amplifies refresh churn. `forget_slot` already uses the compare-and-clear
pattern (`egress.rs:516-534`); `invalidate` should do the same, keyed by the
same `stable_id`/slot identity, and bump the generation only when it actually
cleared.

**Fix direction:** `rcu`-clear only if the cached handle is the one the verdict
was recorded against (pass the `stable_id` or the `Arc`), and do not bump on a
lost compare.

### L9 — `forget_slot` leaves thread-local egress memos pinning the dead connection

**Severity: P3 (bounded memory retention).**

**Where:** `EGRESS_MEMO` is a thread-local array of strong
`quinn::Connection` clones + `Arc<ConnRev2>` (`egress.rs:19-40`, `:194-245`);
`forget_slot` clears only the process-wide `cached` slots
(`egress.rs:516-534`). `with_fresh` releases a memo entry only when that
thread next uses the binding and sees the generation mismatch
(`egress.rs:200-219`); `sess_memo_forget`/`memo_clear` are per-binding and not
called from `forget_slot`.

**Mechanism / impact**

A dead generation's `quinn::Connection` clone is held by every thread-local
memo that used the binding, until that thread sends on the binding again or
exits. The doc at `egress.rs:503-515` says the per-binding `cached` slots are
"the only place outside the pool that hold a strong `quinn::Connection`"; that
is not true. The retention is bounded (one entry per thread per binding, at
most the thread count × `MAX_UDP_SLOTS`), but a `quinn::Connection` keeps the
whole connection state and its DATAGRAM buffers; a handful of dead generations
can pin tens of MiB. The existing `forget_slot` test
(`tests.rs:5598-5635`) checks the shared cache only, so this is not covered.

**Fix direction:** either accept and document the per-thread retention, or
publish a process-wide generation and have each memo entry store a `Weak` (or a
small `Arc` with a `forget` broadcast). A cheap alternative: on `ConnSlot`
death, mark the binding's generation and have a per-slot maintenance tick clear
the **current thread's** memo; cross-thread clearing would need a per-thread
registration. Given the bound, documenting is reasonable, but the current
comment overclaims.

### L10 — Domain reply-source sets differ between warm and cold OPEN; no record failover

**Severity: P3 (logic; multi-record names).**

**Where**

- Warm-cache domain `DATA OPEN` installs `Some(vec![dst])` — the one address
  the synchronous probe sent to (`accept.rs:3367-3406`, especially `:3400-3406`).
- Cold-cache `DATA OPEN` **now installs the same one-address set**
  (`vec![dst]`, install at `accept.rs:3229`); it used to install the full
  policy-accepted set, making the warm and cold paths disagree.
- Steady forwarding always uses `binding.target_ip().or_else(||
  binding.resolved_first())` (`accept.rs:3016-3019`); `resolved_first` is the
  first record.
- Reply classification for a domain binding uses `resolved_contains(src.ip())`
  (`r2_flow.rs:457-465`), and the session's `RecentAddrs` ring contains only
  the address(es) actually sent to (`pin.rs:463-530`).

**Mechanism / impact**

- Both paths now authorize exactly the address the flow sent to, which removes
  the warm/cold inconsistency: a reply from a different record is refused
  consistently. (A record the flow never sent to should not be implicitly
  trusted.)
- Neither path ever tries another record: a dead first record still blackholes
  the flow for its lifetime. This remains the open part of L10. The server has a `mark_unreachable` mechanism, but it
  is used only by the **non-flow** domain forwarding path
  (`forward.rs:750-792`); `r2_forward_flow_resolved` has no such check and no
  alternate address. The client keeps sending steady frames to the id; the
  server keeps sending to `resolved_first()`.
- For UDP there is no handshake to detect a dead record; a `sendto` routing
  error (`ENETUNREACH`/`EHOSTUNREACH`) is the only signal, and the flow path
  uses `udp_try_send` (which swallows the result) rather than
  `udp_try_send_or_return`.

**Fix direction:** make the warm path install the same authorized set it can
prove (at least the sent address plus the thread-cache record set if the cache
exposes it), and on a hard routing error in the flow send path either rotate to
the next `resolved` address (updating the binding atomically) or send a
`FLOW_REJECT`/`SESS_CLOSE` so the client re-opens the flow and may resolve a
different record. A per-flow `resolved` cursor is needed either way.

### L11 — A terminal connection verdict books pre-stager batches as `BUFFER_FULL`

**Severity: P3 (accounting; loss diagnosis).**

**Where**

- Client `UplinkFlows::flush_stage`: after a failed push and a
  `drain_conn_stage`, a still-full/terminal push drops the batch with
  `BUFFER_FULL` (`rev2.rs:1514-1534`), even if `drained.failed` is
  `ConnectionLost`/`Unsupported`.
- Server `StageBatch::drop_pending` books `BUFFER_FULL` for every item
  (`reader.rs:833-839`), including the `verdict == Terminal` arm at
  `:753-758`.

**Mechanism / impact**

The items never reached the connection stager (or were in the pre-stager
batch), so nothing else accounts them. When the connection is dead, the loss
class is `EGRESS_DEAD`, not buffer pressure. The 60 s report then shows
`buffer full` for a connection death and under-reports `egress dead`, which is
the counter an operator uses to tell "slow path" from "dead tunnel". The
per-payload `BUFFER_FULL` also contradicts the "one event per verdict" rule the
same paths use for `EGRESS_DEAD` on the send verdict.

**Fix direction:** pass the drain verdict into the drop helper; if
`ConnectionLost`/`Unsupported`, bump `EGRESS_DEAD` once per payload (or once per
batch with a separate counter), otherwise `BUFFER_FULL`.

### L12 — `rotate_steady_past` is O(steady sessions) for the first frame of a run

**Severity: P3 (performance; high fan-out).** **Measure.** **Status: partial.**
The scan is now bounded to 32 entries; a session deeper in the ring is left in
place and served when the cursor reaches it (fairness approximation). A
linked-list cursor would be the exact O(1) fix.

**Where:** `claim_one_frame` picks a session from the general cursor and calls
`take_steady_head` (`r2_stage.rs:711-775`); `take_steady_head` calls
`rotate_steady_past` (`:789-833`), which does
`steady_order.iter().position(...)` + `VecDeque::rotate_left(pos + 1)`
(`:957-965`).

**Mechanism / impact**

`next_steady_session` leaves the session it just served at the back, so the
common case is O(1). The **first** session of each frame comes from
`next_session` and may sit in the middle; the scan plus rotate is O(steady
sessions). A drain of 4 frames at 2000 steady sessions is ~8k pointer moves;
more frames or more sessions scale linearly. The existing comment acknowledges
"only a run's first item ... may need the scan" but does not bound the cost.

**Fix direction:** keep a `HashMap<u32, usize>` index for `steady_order`
(updated on push/rotate) or maintain a generation/epoch cursor and avoid
`rotate_left` (e.g. a `VecDeque` of indices with swap-remove on service). If
profiling shows this is noise, document the bound instead.

### L13 — TRAIN ingress double-decodes and re-initializes ~3 KB of stack per frame

**Severity: P3 (performance; train-heavy traffic).** **Measure.**

**Where**

- Client `dispatch_r2_train`: pass 1 over `t.items()` to collect ids
  (`dispatcher.rs:1467-1493`), pass 2 over `t.items()` to stage
  (`:1518-1574`).
- Server `r2_ingress_train`: same two passes (`accept.rs:3627-3652`,
  `:3654-3672`).
- Both allocate zero-initialized stack arrays per frame: `slots`
  (64 × ~16 B), `slot_of` (128 × 2 B), `item_slot` (64 × 2 B), and on the
  client `resolved` (64 × ~24-32 B) — roughly 2.5-3.5 KB of stores plus the
  double varint/address parse.

**Mechanism / impact**

TRAIN is the packing win for small-payload bursts; a 64-item train is parsed
twice, and the stack zeroing is per frame. At high train rates this is real
work, though the echo path's one-DATA-per-payload shape does not pay it. A
single pass that records each item's payload offset/flow id in a small
`[(u32, u32)]` arena would remove the second decode; `MaybeUninit`/a reusable
thread-local scratch would remove the zeroing. The dedupe hash is already
open-addressing and allocation-free.

**Fix direction:** make `decode_train` yield offsets in one pass into a
caller-provided scratch (the codec already bounds the items at 64), or cache
the `(id, payload_off, payload_len)` triples from pass 1 and reuse them in pass
2. Keep the stack arrays but initialize them with `MaybeUninit` only for the
entries used.

### L14 — The session memo's "2× headroom" is per connection, but the memo is per thread

**Severity: info (sizing / docs).**

**Where:** `SESS_MEMO_SLOTS = 2048` is a thread-local array shared by every
connection whose datagram reader runs on that worker
(`memo.rs:52-89`, `:166-196`); the fast table it backs is per connection
(`accept.rs:417-448`, `FAST_SESS_SLOTS`). The commit `7816371` sized the memo
as "the fast table's second level" with 2048 slots and a compile-time
`SESS_MEMO_SLOTS >= 2 * FAST_SESS_SLOTS` (`accept.rs:360-365`).

**Mechanism / impact**

The ratio holds for a shard with one busy connection. With C connections per
shard (the server's normal deployment: one endpoint accepts many peers), the
per-connection share of the shared 2048 slots is ~2048/C. A fast-table miss
for a connection with a >568-session working set is then unlikely to find its
session in the memo, and it falls through to the shard read in
`get_or_create_sess`. The fast table is still the primary; the memo simply does
not deliver the claimed second-level hit rate at high connection fan-out.

**Fix direction:** either size the memo from the admitted-connection count (or
make it a small per-connection array in the connection state, which the fast
table already is), or document that the 2× headroom is a per-connection upper
bound and that a busy shard's effective L2 is shared.

### L15 — A forward listener takes the connection stager lock per payload from the main runtime

**Severity: P2 (performance, `[[udp_forward]]` shape; contradicts the E1/E6
"one thread per connection" premise).** **Measure.** **Status: admission path
fixed** — the stager occupancy is now an atomic `staged_bytes` mirror; the
per-burst push still takes the stager mutex, and the optional quinn probe on an
estimate miss remains.

**Where**

- `spawn_udp_forward` spawns the listener with `tokio::spawn` on the caller's
  runtime, which is the main multi-thread runtime (`forward_udp.rs:43-75`).
  `handle_datagram` → `send_peer_payload` → `send_payload_uplink`
  (`forward_udp.rs:746`, `:891-915`; `assoc.rs:461-566`) runs there.
- `send_payload_uplink` calls `rev2.admit_uplink` for **every payload**. The
  finding was that this took `self.stager.lock().queued_bytes()`
  (`rev2.rs:569`); it now reads the `staged_bytes` atomic published after every
  push/drain. On an estimate miss
  the exact `conn.datagram_send_buffer_space()` (`rev2.rs:575`) — the latter
  is quinn's connection-state mutex, the very lock E1 removed the *drain*
  from. `queue_window_cap` also calls `conn.stats()` once per 250 ms
  (`rev2.rs:647-662`). `flush_peer` → `flush_stage` takes the same stager
  mutex (`forward_udp.rs:766-788`, `rev2.rs:1490`).
- The slot runtime's association, drain and retry task take that stager mutex
  and the quinn connection-state lock. Both runtimes therefore touch
  per-connection state concurrently, on different OS threads.
- The same is true, for one burst, for a SOCKS association's
  pre-migration phase: its first datagram is handled on the main runtime
  before `udp_associate_inner` moves the steady state to the slot
  (`assoc.rs:1037-1113`).

**Mechanism / impact**

A bulk-preset connection (`queue_window_ms == 0`) short-circuits before the
stager lock (`rev2.rs:563-565`), so the finding is specific to the tuned /
interactive class — which is exactly the class small echo datagrams use.

The stager's push/claim/drain gate remain correct under the lock, so this is
not a race. The cost is:

- a cross-core `Mutex<R2Stager>` acquisition **per payload** in admission
  (plus one per peer per burst in `flush_peer`), while the slot runtime's
  drain/retry task takes the same mutex to claim; the cache line ping-pongs
  between the main worker and the slot thread;
- a possible **quinn connection-state mutex** acquisition per payload from the
  listener whenever `SpaceCache` refuses (near the window or under a backlog)
  and on the 250 ms `stats()` sample — the exact cross-core park the E1
  commit attributes to the old shape;
- a `SpaceCache` CAS that can lose its observed-word race (L7).

The doc at `rev2.rs:117-123` says the multi-thread caveat applies only when
`MYQUIC2_SHARD_RUNTIME=0`; the forward feature produces the same shape on the
default topology. The existing audit's lock inventory (`Mutex<R2Stager>` "same
shard thread") is true for a pure SOCKS echo, not for a mixed
forward+SOCKS deployment. E6's "two locks per payload" counts the stager and
the quinn-state probe; here the stager lock itself is cross-thread on every
payload, and the quinn lock is the cross-core park when `SpaceCache` misses.

**Fix direction:** make admission read the stager occupancy from an atomic
(the stager already maintains `queued_bytes`; publish it on every push/claim)
so the per-payload path takes no mutex, and either keep the forward listener's
batch in a per-peer arena until the slot's retry task pushes it, or accept the
per-burst push. Do not add a new lock to the listener path. A cheap
mitigation is to have the forward listener use a connection-level
`AtomicUsize` for `queued_bytes` and only take the stager lock to push.

---

## 3. Known residuals (already documented; re-checked, not re-opened)

| # | Residual | Reference |
|---|---|---|
| K2 | The first fragmented payload after the DATAGRAM buffer fills can send a prefix and drop the tail; the aggregate gate is armed only after a previous `Blocked`. | F9 fix; `udp/r2_frag.rs:291-307`, `:344-370` |
| K3 | macOS (no `recvmmsg`) pays one `EAGAIN` per burst on the portable `try_recv_from` arm. | E4; `udp/retry.rs` / `batch.rs:528-546` |
| K4 | The drain gate covers encode+send; one drain can process 1024 items. On the shard thread it cannot contend; under `MYQUIC2_SHARD_RUNTIME=0` it becomes a cross-thread critical section. | E5; `udp/r2_stage.rs:1501-1600` |
| K5 | ~568 fast-table slots per connection against a documented ~2000-session working set; the rest pays the slow path (memo + shard read). | E3; `accept.rs:356-388`, `:4274-4310` |
| K6 | `admit_uplink` still takes the stager mutex and `mono_millis` per payload; commit `355a5c8` removed only the quinn state-lock probe. | `rev2.rs:557-583`, `:647-662`; PERF §26 |

---

## 4. Verified non-issues / deliberate trade-offs

- **No per-packet task/channel spawn** on either echo direction. The only
  data-plane channel is the `WouldBlock` retry shard (`udp/retry.rs`), and it
  is not used in steady state.
- **Client downlink is zero-payload-copy**: `StagedReply.payload` is a
  `Bytes` slice of the received DATAGRAM, the SOCKS5 header is encoded into a
  reused `hdrs` buffer, and the two are sent as two iovecs of one `sendmmsg`
  (`dispatcher.rs:736-817`).
- **Server target send is zero-payload-copy** (slice of the received
  DATAGRAM; `flush_staged_sends`).
- **Burst batching is real** on both receive paths (`LAST_HOP_DRAIN = 32`),
  and the singleton cases (one-frame group, one-reply batch) are already
  special-cased; the remaining issue is the client **uplink** singleton (L5),
  not the downlink.
- **No unbounded per-association queue**: the W3 hold is
  items/bytes/TTL-bounded (`rev2.rs:1654-1683`), the stager is bounded
  (1024 items / 256 KiB), the reassembler is bounded (256 partials / 256 KiB /
  2 s), and the dispatch cache is a fixed 4096-slot array.
- **Stream/reassembly cleanup**: one `R2Reassembler` per connection, partials
  expire on a 500 ms tick guarded by `held_bytes() > 0`; a fragment flood
  cannot pin memory past the bounds.
- **TCP pump buffers are pooled and bounded** (`COPY_BUF_POOL_DEPTH = 4`,
  ≤2× `COPY_CHUNK`), and the c2s zero-copy `write_chunk` path is used only at
  ≥8 KiB.
- **Optimistic SOCKS success is a deliberate one-RTT trade**: the reply is sent
  before the server dial ACK; a failed dial is signalled by RST from the pump,
  not by a SOCKS error. The pump's ACK gate and `abort_tcp` make the failure
  explicit; L2 is the cancellation hole in that disposition.
- **TCP idle watchdog cadence**: `idle_step = min(5 s, idle)`; a 300 s idle
  flow pays 60 timer wakes over its idle life. At 10k live flows that is
  ~2k wakes/s across the slot runtimes (each wake is two atomic loads and a
  re-arm). It is the price of the per-direction AND gate; not free, but
  bounded and only on live flows.
- **The E1/E2 placement fixes are in place**: the forward listener pushes
  batches and notifies the retry task; the TCP pump runs on the slot runtime.
  L3 is the residual drain in the push path; L15 is the per-payload admission
  lock the listener still takes; L2 is the abort disposition.

---

## 5. Recommended order

1. **L1** (protocol correctness). Version the reply source; add the two-source
   race test. This is a small wire/API change with a clear observable failure.
2. **L2** (teardown integrity). Add the abort disposition guard and the
   peer-sees-reset test.
3. **L3 + L15** (forward-shape placement). Split `flush_stage` into push-only
   and push+drain, and take the per-payload stager occupancy from an atomic;
   the forward listener then touches no connection mutex on the payload path.
   This restores the E1 contract.
4. **L4 + L5** together (one borrowed-direct design for both directions):
   measure the `lat`/one-shot echo shape before/after; the two asymmetries are
   the same underlying missing fast path.
5. **L6, L12, L13** only if a profile of the deployed shape (many
   associations/connection, train-heavy bursts) shows them; otherwise document.
6. **L7-L11** are correctness-of-documentation/accounting; fix the comments and
   the drop class, and add tests that assert the encoded size is what the
   admission cache charges.

Suggested measurements (not run here):

- A/B the `hotpath_bench lat` and `udpbidir` shapes with a lone-payload direct
  path (L5) and a borrowed reply path (L4): p50/p99, client/server CPU,
  `stage_drains`/`stage_push` counters.
- A forward-listener shape with enough peers to fill the stager (L3/L15):
  main worker `__psynch_mutexwait`/parking samples, listener latency, and the
  `stage_push`/`stage_drains` counters.
- A high-fan-out connection (2000 sessions, 4 frames/drain) for L12/L13:
  drain CPU per item; `fast_table` hits/misses for L14.

---

## 6. Verification

- `cargo test --all-targets --quiet`: **391 lib + 228 client + 165 server
  (+1 ignored) + 7 forward_e2e + 9 rev3_e2e = 800 passed, 0 failed**
  (the ignored test is the server's microbenchmark).
- The fixes are in the current tree; `cargo fmt --all --check` and
  `cargo clippy --all-targets -- -D warnings` are clean.
- Dependency facts checked against the vendored registry sources:
  `quinn 0.11.12` `src/runtime/tokio.rs:19-40` (ambient runtime),
  `src/send_stream.rs:344-354` (`SendStream::drop` → `finish()`),
  `src/recv_stream.rs:523+` (`RecvStream::drop` → stop).

---

## 6.1 Fix landing (2026-11-09)

The implemented fixes landed in this tree; L4/L5/L10/L12 are partial as noted
in the table below. `cargo fmt --all --check` and
`cargo clippy --all-targets -- -D warnings` are clean, and
`cargo test --all-targets --quiet` passes **800 tests** (391 lib + 228 client
+ 165 server + 1 ignored + 7 forward_e2e + 9 rev3_e2e), 0 failed.

| # | What changed | Test that pins it |
|---|---|---|
| L1 | Rev2 `CTL FLOW_ACK_SRC` carries the reply source; rev3 `SRC_ACK` rides the reliable control stream. `FlowBinding::confirm_reply_src` confirms only the current source (a mismatch clears the ack); the source is learned **before** the context is queued; the legacy source-less `FLOW_ACK` no longer confirms a source. | `flow_ack_confirms_a_learned_reply_source`, `dispatch_rev2_open_src_sends_flow_ack_idempotently`, `rev3_downlink_src_context_until_source_ack`, `rev3_downlink_server_owned_open_src_then_steady`, full-cone tests |
| L2 | `PumpGuard` owns the TCP socket and QUIC halves; its `Drop` runs the RST/`reset`/`stop` disposition when the pump future is cancelled, while the normal path sets `finished` first. | `aborting_a_tcp_pump_resets_the_peer_stream` |
| L3 | `UplinkFlows::flush_stage_no_drain` is used by `flush_assoc_stage`; the forward listener only pushes and notifies. A full queue leaves the batch for the deferred retry instead of draining. | `forward_flush_is_push_only_even_above_the_train_threshold` |
| L4 | Per-reply borrowed direct was implemented and **reverted**: it sent the first reply of a multi-reply burst standalone and broke cross-session TRAIN packing. The existing burst-end `flush_single` fast path (one reply, empty queue, free gate) remains; the item copy is the deferred part. | `rev2_downlink_steady_train_and_port_rebind`, `rev2_stage_cross_session_dict_train` |
| L5 | `flush_lone_direct` sends a lone staged payload through `try_send_direct`, skipping the push/drain. (The item copy remains: a borrowed stage item is a larger redesign.) | `lone_staged_payload_is_sent_directly` |
| L6 | `drain_session_staged` drains only the large payload's session; a terminal verdict books `EGRESS_DEAD` instead of requeueing for teardown. | `session_drain_leaves_other_sessions_queued`, `rev2_stage_drain_propagates_connection_lost` |
| L7 | Admission charges `item_wire_len`/`uplink_wire_len` (the exact encoded body), and `note_control_sent` charges `HELLO`/`FLOW_ACK_SRC`/`SESS_CLOSE` on successful DATAGRAM sends. | `admission_charges_the_encoded_frame_not_just_the_payload` |
| L8 | `invalidate` compare-and-clears only a cached handle whose connection is closed; a fresh live publish survives a stale verdict. | `invalidate_only_clears_a_closed_cached_handle` |
| L9 | The thread-local memo holds `Weak<EgressCache>` instead of a strong `Connection`; `forget_slot`/`invalidate` release the only strong owner. | `stale_egress_memo_releases_the_connection`, memo tests |
| L10 | Both warm and cold domain `DATA OPEN` install `vec![dst]` (the address actually sent to), removing the warm/cold authorization inconsistency. Record failover remains a documented design gap. | `rev2_domain_open_and_downlink_rebind` |
| L11 | Terminal-verdict pre-stager drops book `EGRESS_DEAD` on both ends; live-full drops keep `BUFFER_FULL`. | terminal drain tests |
| L12 | `rotate_steady_past` scans at most 32 entries; a deeper session stays in the ring and is served when the cursor reaches it. | stager drain/order tests |
| L13 | Both TRAIN readers record payload offsets in pass 1; pass 2 slices `d` instead of decoding the frame twice. | all TRAIN tests |
| L14 | `memo.rs` now states the per-thread/per-connection sharing and that 2x is an upper bound. | docs |
| L15 | `ConnRev2` publishes `staged_bytes` after push/drain; admission reads it without the stager mutex. | `stager` tests + the forward test above |

Known residuals after the fixes:

- **L1 reorder window**: rev2/rev3 have no source epoch in the context frame.
  A reordered older `OPEN|SRC` can still move the client backwards for a few
  frames; the source-carrying ACK mismatch now clears the server's ack and
  forces a fresh context, so it converges. A wire epoch is the remaining
  full fix.
- **L4/L5 item copy**: the lone payload is still copied into an owned
  `R2StageItem`; removing it needs a borrowed burst item (the recv arena is
  valid until the burst boundary, but the item must survive a push to the
  shared stager).
- **L10 record failover**: a dead first DNS record still blackholes a domain
  flow; the flow path's staged `sendmmsg` does not report a per-destination
  routing error to the binding.
- **L12 linked-list cursor**: the bounded scan removes the unbounded scan but
  a session deeper than 32 is not moved to the tail; this is a fairness
  approximation, not an exact round-robin.
- **K2-K6** remain as listed in section 3.

## 7. Line index

| Topic | Location |
|---|---|
| Server shard = one current-thread runtime per endpoint | `myquic2-server/main.rs:449-467`, `:591-660` |
| Quinn `TokioRuntime` = ambient spawn/socket registration | `quinn-0.11.12/src/runtime/tokio.rs:19-40` |
| Server datagram reader / fast table / burst drain | `accept.rs:417-695`, `:4200-4685` |
| Server reply reader / `handle_session_reply` | `reader.rs:1452-1749`, `:1808-2116` |
| Server `StageBatch` / `try_send_direct` | `reader.rs:681-839`, `udp/r2_stage.rs:1465-1497` |
| Server small-reply item copy | `reader.rs:1657-1661` (large `Blocked`: `:934-961`) |
| Server `FLOW_ACK` handler | `accept.rs:2784-2790` |
| `FlowBinding::set_reply_src` / `mark_reply_src_acked` | `mqp/r2_flow.rs:269-289` |
| Server `match_source` / `ReplySourceMemo` | `mqp/r2_flow.rs:433-474`; `reader.rs:232-328` |
| Client dispatcher `OPEN\|SRC` apply + ACK | `dispatcher.rs:1395-1419`, `:873-887` |
| Client downlink grouped flush (zero copy) | `dispatcher.rs:736-817` |
| Client association burst end / stager drain | `assoc.rs:673-708`, `:1091-1138` |
| Client uplink item copy / staging | `rev2.rs:1989-2023`, `:2089-2114` |
| Client `flush_stage` / opportunistic drain | `rev2.rs:1461-1535` |
| Client `flush_assoc_stage` | `rev2.rs:2584-2611` |
| Client `SpaceCache` / `admit_uplink` | `rev2.rs:129-215`, `:557-625` |
| Client `try_send_datagram` / control frames | `udp/send.rs:84-95`, `rev2.rs:1193-1305` |
| Egress memo / `with_fresh` / `forget_slot` / `invalidate` | `egress.rs:19-40`, `:194-245`, `:497-534` |
| Forward listener `flush_peer` | `forward_udp.rs:766-788` |
| Fragmenter aggregate gate | `udp/r2_frag.rs:291-307`, `:344-370` |
| Stager steady cursor / drain gate | `udp/r2_stage.rs:741-833`, `:952-965`, `:1501-1600` |
| TRAIN two-pass | `dispatcher.rs:1467-1518`; `accept.rs:3627-3672` |
| Server warm/cold domain OPEN sets | `accept.rs:3016-3019`, `:3146-3240`, `:3400-3406` |
| Server non-flow unreachable handling | `forward.rs:750-792` |
| TCP pump disposition | `tcp/pump.rs:592-630` |
| `PumpAbort` / `run_tcp_pump` | `main.rs:110-122`, `:146-172` |
| Quinn stream drop semantics | `quinn-0.11.12/src/send_stream.rs:344-354`, `src/recv_stream.rs:523+` |
| Session memo sizing | `memo.rs:52-89`; `accept.rs:356-388` |
