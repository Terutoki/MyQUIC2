# UDP data-plane audit — `src/udp/**`, `src/transport/**`, `src/linux.rs`, `src/sync.rs`, `src/time/**`

**Scope.** `src/udp/{send,retry,batch,r2_frag,r2_reasm,r2_stage,fragmenter,reassembler}.rs`,
`src/udp.rs`, `src/transport/{build,limits}.rs`, `src/transport.rs`, `src/linux.rs`, `src/sync.rs`,
`src/time/{mono,coarse}.rs`. Key callers were grepped/read to prove each path is live from the
current binaries: client `bin/myquic2-client/{assoc,dispatcher,rev2,egress,pool}.rs` and
server `bin/myquic2-server/{accept,reader,forward,main,table}.rs`. Commit `8f0d685`'s diff for
this domain (`src/udp/r2_reasm.rs`, `src/udp/r2_stage.rs`, `src/transport/build.rs`) was reviewed
for regressions; `PERF_ANALYSIS.md` §0.6/T5/T6 and `MQP3_REV2_SPEC.md` were read as prior context
but not trusted. **Method: static reading only.** I executed no tests and ran no cargo command
(the tree is read-only for this task); the only commands run were `git show`/`git status`,
`grep`/`sed`/`wc` and reads. Two findings rest on dependency-source verification, so I read the
locked crate sources directly: `quinn-0.11.12/src/endpoint.rs` (per-`recvmsg` receive-batch
allocation), `quinn-proto-0.11.19/src/{frame.rs,connection/datagrams.rs}` (DATAGRAM payload is a
`Bytes` split of that batch), `quinn-udp-0.5.16/src/unix.rs` (`UDP_GRO`, `gro_segments() == 64`)
and `nix-0.31.3/src/sys/socket/mod.rs` (`recvmmsg` zips the iovec slice against the preallocated
headers, so the `n`-sized hand-off in `udp/batch.rs` is sound). Severities: S0 crash/corruption/
remote memory blowup; S1 serious under normal load; S2 material but conditional; S3 minor.
Overlapping findings already filed by a sibling teammate are cross-referenced instead of
double-counted.

---

## 1. Findings table (severity-sorted)

| # | Severity | Category | Location | One-line issue | Confidence |
|---|----------|----------|----------|----------------|------------|
| UDP-01 | **S1** (S0-shaped under fast ingress; see impact) | memory | `src/udp/r2_reasm.rs:79-92, 386-398, 486-492` | `PendingChunk` stores a refcount **view** of the received frame `Bytes`; one view pins quinn's whole per-`recvmsg` GRO batch (up to ~92 KiB) while charging only `len+48` against the 256 KiB budget — per-connection retention is 100-1900× the documented/admission-charged bound | high (mechanism) / medium (magnitude) |
| UDP-02 | S2 | perf / task+wake amplification | `src/udp/retry.rs:125-155, 423-440` | One tokio `JoinSet` task **and** one `tokio::time::timeout` timer **and** one payload copy per `WouldBlock` datagram, under last-hop egress backpressure — contradicting the documented "no task is spawned per packet" | high |
| UDP-03 | S2 | logic / accounting | `src/udp/r2_frag.rs:194-205, 232-249`, `src/udp/r2_stage.rs:848-857` | Rev2 FRAG (and >512 B direct) payloads dropped on `Blocked`/`TooLarge` book **no** `dgram_drops` counter (the MQP-2 path books every one); the stager additionally books a *size* verdict as `EGRESS_DEAD`. Partially overlaps server-bin #8; this adds the FRAG/caller halves | high |
| UDP-04 | S2 | logic / silent drop | `src/udp/r2_reasm.rs` (file has zero `dgram_drops`/`udp_stats` calls) vs `src/udp/reassembler.rs:451,600,711` | Rev2 reassembler refusals (budget full, geometry, replay, duplicate) and partial expiry/eviction are entirely uncounted, unlike the legacy reassembler it replaces; a peer that fills the 256 KiB budget makes all later fragmented traffic vanish from every counter | high |
| UDP-05 | S3 | perf / alloc on hot path | `src/udp/r2_stage.rs:620-647, 705-714, 918-975` | Per-DATAGRAM packing adds a fresh `Vec` in `encode_train_run` (+ O(flows×items) `position`), a fresh `PackedFrames` (2 `Vec`s) per drain, and an O(sessions) `rotate_steady_past` on the first item of every train frame — all inside the connection-wide stager lock | high (cost small) |
| UDP-06 | S3 | perf / copy | `src/udp/r2_reasm.rs:169-181, 205-212` | In-order fragment placement does `buf.resize(end, 0)` (zero-fill) followed by `copy_from_slice`, writing every chunk twice | high |

Minor (brief): client dispatcher polls the 500 ms reassembly-expiry tick **unguarded**
(`client/dispatcher.rs:1369-1373`) while the server guards the same branch on
`held_bytes() > 0` (`server/accept.rs:2355`); client connection count is small (`MAX_POOL_CONNS` +
`MAX_UDP_SLOTS`), so this is ~2 wake/s/connection at most.

---

## 2. Finding detail

### UDP-01 — S1 (S0-shaped) — Rev2 pending-fragment views pin whole quinn GRO receive batches

**Evidence (my file).** `src/udp/r2_reasm.rs:69-78` states the design premise:

```
/// The chunk is held as a *view* of the frame it arrived on (an owned
/// refcount clone of the [`Bytes`] plus offset/len), so it is copied exactly
/// once — into the assembly buffer when a later fragment unlocks it. The
/// clone is one atomic increment against the incoming frame; ...
```

The cost model charges that view as if it were the only thing pinned
(`src/udp/r2_reasm.rs:88-92`):

```
/// Cost of one [`PendingChunk`] in the retained-bytes budget: the view
/// (idx + offset + len + the `Bytes` header) and its share of the frame it
/// pins. 48 B is the same per-datagram bookkeeping charge the fragmenter uses.
const PENDING_CHUNK_COST: usize = 48;
```

and the only retention point is a plain `Bytes` clone (`src/udp/r2_reasm.rs:486-492`):

```
None => partial.pending.push(PendingChunk {
    idx,
    d: d.clone(),
    chunk_off: f.chunk_off,
    len: n,
}),
```

Admission for that path charges `n + 48` (`src/udp/r2_reasm.rs:389-398,404`); the budget is
`FRAG_MAX_HELD_BYTES = 256 KiB` (`src/mqp/fragment.rs:165`), i.e. one view costs as little as
**49 charged bytes**.

**Why the pin is much larger than the charge.** The `d: Bytes` handed to `r2_reasm::push` is the
QUIC DATAGRAM payload taken straight from `Connection::read_datagram` — the server's own ingress
code says so: *"`d` is already owned (from `read_datagram`), so payload slices borrow it directly:
one refcount bump per slice, no extra clone per packet"* (`server/accept.rs:2403-2405`, cf.
`r2_reasm.push(&d, &frag, coarse_millis())` at `server/accept.rs:1963`). In the locked quinn
version, each datagram payload is a `Bytes` split of the packet payload
(`quinn-proto-0.11.19/src/frame.rs:567-573`), which is itself a slice of **one `BytesMut` allocated
per `recvmsg` batch** (`quinn-0.11.12/src/endpoint.rs:790-800`:
`let mut data: BytesMut = buf[0..meta.len].into(); while !data.is_empty() { let buf =
data.split_to(meta.stride...) }`). On Linux quinn-udp sets `UDP_GRO` and `gro_segments() == 64`
(`quinn-udp-0.5.16/src/unix.rs:1001-1029`), so `meta.len` — and therefore the allocation a retained
view pins — can be `max_udp_payload_size × 64 ≈ 92 KiB`, exactly as the **legacy** MQP-2
reassembler documents at `src/udp/reassembler.rs:283-295`:

```
/// There used to be a zero-copy variant that stored `parent.slice(..)` of
/// the datagram the frame was decoded from. That is unsound as a *memory
/// bound*: ... up to 64 x 1472 B = ~92 KiB on Linux, where quinn-udp enables
/// `UDP_GRO` ... a 20 B fragment could hold ~92 KiB of RSS against a budget
/// that read as 20 B
```

The rev2 reassembler reintroduces exactly the structure the legacy one removed (the legacy module
now owns/copies every chunk). `PERF_ANALYSIS.md:453` records the same ~92 KiB measurement for the
legacy component.

**Trigger path (live).** Server, after token auth (`server/main.rs:729-749` authenticate →
`handle_conn`): a rev2 `FRAG` DATAGRAM → `handle_r2_ingress` → `r2_ingress_frag`
(`server/accept.rs:1946-1967`) → `R2Reassembler::push`. A fragment is stored as a *pending view*
whenever its position is not derivable yet — e.g. `total=64`, `idx=1..63` delivered before the
`idx=0` determinator (`Partial::pos_of` returns `None` for `idx>0` without `first_len`,
`r2_reasm.rs:155-163`). Each arriving frame in that shape becomes one retained view. The symmetric
client path is `client/dispatcher.rs:1096` (`r2_reasm.push(d, &f, coarse_millis())` on downlink
FRAG). Because the chunk must end at `d.len()` (`r2_reasm.rs:309-311`) while the QUIC packet can be
padded with `PADDING` before/after the DATAGRAM frame, a padded full-size packet can carry a
1-byte chunk: charge 49 B, pinned batch up to ~92 KiB.

**Impact at scale (estimate, not measured).**
- Charged bound: 256 KiB / 49 B ⇒ **~5,350 pending views** per connection. Each view in a distinct
  full GRO batch pins up to ~92 KiB ⇒ worst-case retention **≈ 480 MiB per connection**, vs the
  256 KiB the module documents and the admission model charges
  (`config/tuning.rs:351` adds `2 × FRAG_MAX_HELD_BYTES` per admitted connection; the comment
  there explicitly says the reassembler "pins each until the partials expire").
- A view lives at most `FRAG_TIMEOUT_MS` (2 s) + one 500 ms sweep (`mqp/fragment.rs:101-116`), so
  sustained pinned bytes ≈ min(480 MiB, 2.5 s × per-connection ingress rate). 10 MB/s ⇒ ~25 MiB
  (100× the charge); 100 MB/s ⇒ ~250 MiB (1000×). Reaching the multi-hundred-MB figure requires a
  fat pipe and a token-holding peer, which is why I rate S1 rather than S0; the *bound violation*
  itself is unconditional and the per-connection figure has no bearing on how many connections the
  admission budget will admit. On a server sized by `max_peer_memory_mb` this exceeds the operator's
  budget by orders of magnitude on the reassembly term, so a handful of peers can OOM the process.
- The same mechanism, transiently, applies to the `total == 1` fast path
  (`payload: d.slice(f.chunk_off..)`, `r2_reasm.rs:349`) and therefore to `R2Assembled.payload`
  whenever a peer sends one-fragment `FRAG` frames or answers with a single fragment: the delivered
  payload keeps the batch alive until the caller drops it (client `StagedReply`, server
  `forward_*`), bounded by one drain burst.

**Minimal fix direction (do not implement here).** Make the pending representation own its bytes —
copy the chunk into a `Box<[u8]>`/small `Bytes` of exactly `len` when it becomes pending (the
legacy reassembler's fix; one extra alloc + memcpy per out-of-order fragment, in exchange for the
accounted bound being real), and keep the zero-copy view only for the `total == 1` delivery that
does not outlive the current burst. Alternatively charge the batch (impossible through `Bytes`'s
API) or expose/disable GRO on the QUIC endpoint socket.

---

### UDP-02 — S2 — One task + one timer + one copy per `WouldBlock` datagram in the retry pool

**Evidence.** `src/udp/retry.rs:125-155`: the shard worker is a `select!` over a `JoinSet`; the
`recv()` arm does

```
while inflight.len() >= UDP_RETRY_INFLIGHT {          // 16
    inflight.join_next().await;
}
inflight.spawn(async move {                           // ← one task per retried datagram
    if let Err(reason) = retry_one(&req).await { ... }
});
```

`retry_one` wraps each send in `under_retry_deadline` → `tokio::time::timeout(UDP_RETRY_TIMEOUT, …)`
(`retry.rs:99-113`), i.e. a timer-wheel registration + cancellation per retry, and the slice entry
point copies the payload before it is queued (`retry.rs:247-259`:
`payload: Bytes::copy_from_slice(payload)` only on `WouldBlock`, plus an `Arc<UdpSocket>` clone).
The public contract in the same file claims the opposite (`retry.rs:203-209`):

```
/// ... queued to a sharded global retry pool (one worker per shard, selected by
/// destination ip+port) so the caller never stalls, no task is spawned per packet,
```

**Trigger path (live).** `udp_try_send_grouped` / `udp_try_send` / `udp_try_send_slice` are the
last-hop send path for both binaries: server `forward_server_dgram` → `udp_try_send`
(`server/forward.rs:463`), server uplink staging `flush_staged_sends` →
`udp_try_send_grouped` (`server/accept.rs:260,275`), client downlink replies
`udp_try_send_grouped` (`client/dispatcher.rs:732,740`). Whenever the destination socket's send
buffer is full (`try_send_to` → `WouldBlock`; on Linux the `sendmmsg` group can also return 0 and
fall into the per-frame path, `retry.rs:388-397`), every frame takes this path. That is exactly the
saturated regime the batching exists for: a slow local app (client downlink) or a slow/congested
target (server uplink) with e.g. 50–200 k small datagrams/s.

**Impact.** Per backpressured datagram: payload copy + `JoinSet::spawn` task alloc + timer insert +
timer cancel + send syscall, vs ~one `try_send_to` on the healthy path. Rough estimate 0.5-1.5 µs
extra per packet (task + timer dominate); at 100 k pps backpressured that is 5-15 % of one core plus
allocator/join-set churn, and the pool's bounded in-flight (16/shard) means the worker is either
spawning or reaping continuously. This is a throughput/latency amplifier precisely on the
congestion path; it does not lose data (the queue is bounded and drops are counted).

**Fix direction.** Keep one task per shard: a bounded `VecDeque<UdpRetry>` drained in place after
`writable().await` (or a single reused `Sleep`/`timeout` for the head), so a retry is a queue entry,
not a task; or drop the per-retry deadline and bound the queue depth only. Note the docs should be
corrected either way.

---

### UDP-03 — S2 — Rev2 fragmented/large send drops are invisible to `dgram_drops`

**Evidence.** MQP-2 `DgramFragmenter` books every exit: the aggregate gate calls
`note_send_buffer_full()` (`src/udp/fragmenter.rs:296-310`), the per-fragment loop sends through
`send_encoded`, which books `BUFFER_FULL`/`TOO_LARGE` (`src/udp/send.rs:198-212`), and size refusals
book `TOO_LARGE` (`fragmenter.rs:267-283`). The rev2 twin has the same aggregate gate but **no
counter** (`src/udp/r2_frag.rs:194-205`):

```
if self.last_blocked {
    if conn.datagram_send_buffer_space() < plan.footprint(payload.len()) {
        return PayloadSend { frames: 0, failed: Some(DatagramSend::Blocked) };
    }
    ...
```

and its send loop calls raw `try_send_datagram` on every frame (`r2_frag.rs:240-249`):

```
match try_send_datagram(conn, body) {
    DatagramSend::Sent => frames += 1,
    other => { self.last_blocked = other == DatagramSend::Blocked;
               return PayloadSend { frames, failed: Some(other) }; }
```

So a multi-frame payload dropped on a full DATAGRAM buffer — or refused `TooLarge` when the path
budget shrank under the cached `limit` — books only `udp_stats::fragmented` on the *all-frames-queued*
path (`r2_frag.rs:252-260`); nothing on the drop path. Callers explicitly assume otherwise:
`client/assoc.rs:358-361` — *"`Blocked`/`TooLarge` are already counted where they are decided"* —
although `recover_send_outcome`'s `Blocked` arm only logs at debug level
(`client/assoc.rs:737-739`), and the same holds for the client's `send_standalone`/`try_single_data`
returns (`client/rev2.rs:748-787`) and the server's `r2_send_large_reply` single-frame returns
(`server/reader.rs:1106-1109`: `R2LargeReply::Sent | R2LargeReply::Blocked => {}`). Sibling report
`server-bin.md` #8 covers the server large-reply half; the FRAG/aggregate-gate half and the client
half are uniquely here.

Second half: the stager maps every non-`Blocked` failure verdict to `EGRESS_DEAD`
(`src/udp/r2_stage.rs:848-857`):

```
let counter = if other == DatagramSend::Blocked {
    &dgram_drops::BUFFER_FULL
} else {
    &dgram_drops::EGRESS_DEAD
};
```

A `TooLarge` verdict from quinn (path MTU shrank under the cached `limit`) therefore books each
payload of that frame as "connection dead" although the connection is alive and the caller merely
re-probes the budget. Operators see `egress_dead` spikes with no connection loss; the size class is
untracked.

**Impact.** Trigger: DATAGRAM send buffer full (saturation) for a fragmented payload or a >512 B
payload (the stager only handles `n <= BATCH_SMALL_MAX = 512`, so large replies/payloads always take
this path), or PMTU shrink mid-fragment. At saturation every such payload is dropped and invisible
in `dgram_drops`; counters that are supposed to separate "buffer full" from "connection dead" from
"too large" under-report one class and misclassify another.

**Fix direction.** In `R2Fragmenter::send`, mirror the MQP-2 accounting: `note_send_buffer_full()`
on the gate drop and on a `Blocked` frame verdict, `TOO_LARGE` bump on `TooLarge` verdicts/encoder
disagreement; in `send_packed_frames`, split `TooLarge` into the `TOO_LARGE` counter and leave
`EGRESS_DEAD` for `Unsupported`/`ConnectionLost`.

---

### UDP-04 — S2 — The rev2 reassembler has no drop/expiry/eviction accounting

**Evidence.** `grep -c 'dgram_drops\|udp_stats' src/udp/r2_reasm.rs` → **0**. Every refusal path
returns `None` silently: duplicate (`r2_reasm.rs:365-369`), total mismatch/context splice
(`:357-364`), non-derivable middle width (`:370-377`), payload-bytes cap (`:378-380`), budget
refusal (`:404-406`), hostile geometry (`:449-461`), partial cap (`:420-425`), plus `expire`
(`:590-617`) and `evict_oldest` (`:647-669`). The live callers just return:
server (`accept.rs:1963-1967`) *"Partial, duplicate, expired or refused fragment: the module already
bounds and validates everything; UDP semantics say drop."*; client (`dispatcher.rs:1096-1099`).

The legacy reassembler it runs beside *does* account: `udp_stats::reassembly_expired()` on expiry
(`src/udp/reassembler.rs:600`) and `reassembly_evicted()` on count/byte-cap or restart eviction
(`:451,:711`).

**Trigger path (live).** The rev2 path is the production datapath in both directions: server uplink
`r2_ingress_frag` (`accept.rs:1946`) and client downlink `dispatch_r2_frag`
(`dispatcher.rs:1084`). The concrete loss window: a peer (or a burst-loss episode) fills the 256 KiB
reassembly budget / 256-partial cap with incomplete multi-fragment payloads; from then on
`r2_reasm.rs:404-406` refuses every fragment of every *new* payload silently — no counter moves, no
warning, and the 2 s expiry of the occupying partials is not counted either, so the observable
`FRAG_FRAMES` (accepted) − `FRAG_COMPLETE` gap is the only hint.

**Impact.** At the budget ceiling (reachable with 256 × 64-fragment partials, or simply by an
attacker alternating a few hundred 2-of-N partials), all rev2 fragmented traffic is dropped with no
`dgram_drops`/`udp_stats` trace; operators cannot distinguish "no fragments arrived" from
"reassembler refused everything". No correctness impact on delivered payloads.

**Fix direction.** Add refusal/expiry/eviction counters (bulk-batched if hot) in `push()`/`expire()`,
matching the legacy module's `reassembly_*` set, and a rate-limited warning on the budget-refusal
class.

---

### UDP-05 — S3 — Per-DATAGRAM allocations and O(n) work inside the stager lock

**Evidence.** `encode_train_run` builds the codec item list as a fresh `Vec` per frame
(`src/udp/r2_stage.rs:630-646`):

```
let items: Vec<(u8, &[u8])> = run.iter().map(|item| {
    ...
    let idx = self.flows_scratch.iter()
        .position(|f| *f == wire_id)          // O(flows) per item
        .expect(...);
    (idx as u8, item.payload.as_ref())
}).collect();
```

on top of the already-`O(items × flows)` dedupe in `take_steady_head`
(`new_flow = !unique.contains(&wire_id)`, `:586`). `drain_staged` allocates a fresh
`PackedFrames` (two empty `Vec`s) per call (`:926`), and the first item of each train frame pays
`rotate_steady_past`'s `steady_order.iter().position(...)` + `VecDeque::rotate_left`
(`:700-714`) — O(sessions) each time the general cursor selects a session that is not already at the
back of the steady cursor. `pack_batch` emits at most 4 frames / 64 items per lock hold
(`R2_PACK_BATCH_FRAMES=4`, `R2_PACK_BATCH_ITEMS=64`, `:68-69`).

**Impact.** At the aggregation target (64-item TRAIN frames) this is one extra heap alloc +
~64×32 u32 compares per frame, plus one O(sessions) rotate per frame, all under the connection-wide
stager lock that every other association's push must acquire — i.e. it lengthens the critical
section that UDP-02/[client-bin C6] already identifies as a contention point. Per-item cost is
small (tens of ns); the finding is only about the locked-region cost, not about a measured cliff.
Not quantified here.

**Fix direction.** Reuse a stager-owned `Vec<(u8,&[u8])>` scratch (borrows are local to the encode
call, so a field is possible with a small lifecycle split), precompute the flow index per unique
flow once per frame (map from the `unique` scan instead of `.position`), and park the general cursor
in step with the steady cursor (rotate on pop like the steady cursor does) so the O(sessions) scan
happens only on cursor divergence. Keep a `PackedFrames` scratch on the drainer side.

---

### UDP-06 — S3 — In-order fragment placement zero-fills then overwrites the chunk

**Evidence.** `Partial::buf_write` grows the assembly buffer with `resize(end, 0)` and then copies
the chunk over the freshly zeroed tail (`src/udp/r2_reasm.rs:176-179`); `drain_pending` repeats the
pattern (`:209-212`). For the common in-order case `buf.len() == pos` on every arrival, so the
`resize` zero-fills exactly the bytes the `copy_from_slice` writes next: two passes over every
fragment's payload for every multi-fragment datagram.

**Impact.** ≤ 8 KiB of redundant zero stores per completed fragmented payload (~0.3-0.5 µs at
memcpy speed); irrelevant at normal rates, noticeable only under a fragment-flood microbenchmark.
**Fix direction.** Extend without zeroing (`Vec::spare_capacity_mut`/`set_len` over the written
range) when `pos == buf.len()`; keep `resize` only for the out-of-order gap case.

---

## 3. Checked and found sound

Items below were read and checked against caller contracts; no severe defect found.

- **`src/udp/send.rs`** — `try_send_datagram`'s `now_or_never` cancellation semantics verified
  against quinn-0.11.12's `SendDatagram::poll` (on `Pending` the data is back in the future and the
  `Notified` drop unregisters; no byte-counter drift/waiter leak). `DatagramSend` mapping covers
  every quinn variant; `send_encoded` books exactly-once size/buffer drops. `send_udp_datagram`,
  `send_udp_batch` and `note_send_buffer_full` are **production-dead** (only the legacy MQP-2
  fragmenter and tests call them); they are not a live risk.
- **`src/udp/retry.rs`** — shard selection/hash, `ArcSwap` re-arm race (`compare_and_swap` loser's
  temporary sender/worker exits immediately), depth/in-flight bounds, and exactly-once accounting
  on the submit path (`retried` only after the queue accepted, `dropped_no_permit` otherwise) are
  sound. The `UDP_RETRY_INFLIGHT`/`UDP_RETRY_TIMEOUT` HOL fix works as documented; only UDP-02
  remains.
- **`src/udp/batch.rs`** — verified against nix-0.31.3 `recvmmsg`: it zips `iovs` against the
  preallocated `MultiHeaders`, so the `n < 32` hand-off never exposes uninitialized headers
  (`nix-0.31.3/src/sys/socket/mod.rs:1917-1962`). `MaybeUninit` initialisation/casting in
  `sendmmsg_frames` (two iovecs per `mmsghdr`, `0..n` only) and `BurstRecv::recv`'s slice split are
  in-bounds; `with_burst_msg`/`burst_msg_copy` reproduce `recvfrom` truncation exactly; the drain
  bound (32/poll), thread-local scratch (~270 KiB/thread, bounded by thread count), and the
  syscall/group histogram accounting are consistent (incl. failed-`sendmmsg` and >32 remainder
  paths). Sendmmsg/recvmmsg probes are once-per-process and fail closed to the portable path.
- **`src/udp/r2_frag.rs`** — `FragPlan` header arithmetic (headers are index-independent; `total`
  matches the chunking loop), `total ≤ 64`, `payload ≤ 8 KiB`, per-context monotonic u32 `frag_id`
  (wrap requires >1.4 M fragmented payloads/s inside the 2 s window, per sending context — client
  association / server session, verified constructors), all-or-nothing gate only after a `Blocked`,
  `last_blocked` reset paths, and no peer-triggerable panic (no indexing/overflow). Only UDP-03.
- **`src/udp/r2_reasm.rs`** — bounds and state machine are sound apart from UDP-01/UDP-04/UDP-06:
  shape checks precede mutation; `pos_of`/`buf_write`/geometry checks prevent resize explosions from
  a hostile wide `unit`; completion mask spells out total=64 (`checked_shl(64) → u64::MAX`); a
  refused fragment leaves a live partial untouched (except `ctx` adoption, which a hostiler
  fragment can only use to poison its own partial); eviction/prune ordering (`first_ms` primary,
  `FragKey` tie-break) preserves the sweep contract; `order_bytes`/`held` bookkeeping is exact on
  every removal path; no peer-triggerable panic found (`expect`/`unreachable` are internal
  invariants under one `&mut self`). `drop_session`/`drop_flow` cannot remove ctx-less partials,
  but the payload completion then has no route (registry/session gone) and it expires — verified
  with the caller paths, no misroute.
- **`src/udp/r2_stage.rs`** — the `steady_order`/`steady_mark` cursor introduced by `8f0d685` was
  re-derived for every head transition: insert on push-into-empty, on `pop_one` revealing a new
  head, and in `drop_flow_scoped`; lazy removal in `next_steady_session`; eager `forget_steady` in
  `drop_session`; `drop_flow`'s rebuild is internally consistent; stale-mark self-healing after a
  queue empties/reopens is correct (a session whose mark survives a re-push is still in
  `steady_order` and gets re-validated). Queue caps/accounting (`queued_items`/`queued_bytes`
  saturating), `requeue_unsent` indexing (`outcome.frames` = failed frame index), the
  `R2_STAGE_MAX_ITEMS` progress bound, and the train-size estimate in `take_steady_head`
  (exactly equals `r2::train_dict_len`: 4-byte header + idx/varint/payload per item + varint per
  new flow) are sound — the encoder cannot refuse a run the packer accepted. `Drop`/`clear`
  accounting cannot double-book. Only UDP-03's `EGRESS_DEAD` misclassification and UDP-05 remain.
- **`src/udp/fragmenter.rs`** — **dead production send path**: every constructor live in a non-test
  context was searched (`grep DgramFragmenter`); the only non-test call sites are `#[cfg(test)]`
  helpers (`client/assoc.rs:773-830`, `server/reader.rs:576-660,765-830`) and both binaries' comments
  state the legacy fragmenter is retired on the reply paths (`server/reader.rs:1105-1106`,
  `client/rev2.rs:562`). Logic was nevertheless checked for the case it is resurrected (id-reuse
  window, aggregate footprint, exactly-once accounting) — sound.
- **`src/udp/reassembler.rs` (MQP-2)** — **live only as an untrusted-input parser**: both binaries
  still decode peer-chosen MQP-2 type bytes (`0x05` FRAG) into this reassembler
  (`client/dispatcher.rs:541-542`, `server/accept.rs:2439-2440`) while a conforming rev2 peer never
  sends them; the send-side counterpart is dead (above). Audited as hostile input: chunks are owned
  copies of exactly their length (no GRO pin), slot tables/`retained` are charged with the first
  stored chunk, partial count/byte caps are enforced with insertion-ordered O(1)-amortised
  eviction, expiry is tick-driven from both readers, tombstone fingerprints are bounded and
  payload-free, and no peer-triggerable panic/index bug was found.
- **`src/transport/build.rs`, `limits.rs`** — window/ACK/RTT/MTU/keepalive/idle derivation verified
  (`watchdog_silence_secs < idle_timeout_secs` over the whole clamp range; idle = 3×, watchdog =
  2× with floors 15 s/8 s), DATAGRAM buffers match the `MQP_DGRAM_MAX`/`DGRAM_MAX_WIRE` compile
  asserts, client `(0,0)` incoming stream credit and the server pre-auth 4/2 credit match the
  documented memory lever, and the bulk/interactive presets are applied only on the client side
  (server builds non-bulk, so the `2 × DATAGRAM_BUFFER` admission term is correct for the server).
- **`src/linux.rs`** — `setsockopt` plumbing (`value` pointer/len, `c_int` casts), clamps
  (`BUSY_POLL_MAX_US`, `NOTSET_LOWAT_MIN..MAX`, `0` = kernel default) and first-failure logging are
  sound; every helper is best-effort and never fails a connection.
- **`src/sync.rs`** — intentionally empty (doc shim); no code.
- **`src/time/{mono,coarse}.rs`** — one `START` epoch shared by both readers, `coarse_millis` is a
  lagging (≤1 s) quanta upkeep sample of the same clock, `ensure_upkeep` is a `OnceLock` load on the
  hot path, fallback is the live clock, saturating arithmetic cannot move the epoch backwards.
  Callers in this domain compare timestamps only against each other from the same reader
  (`r2_reasm::push`/`expire` both use the coarse clock; `FRAG_TIMEOUT_MS = 2 s` dwarfs the 1 s lag),
  and the "0 = never" sentinels are handled with `.max(1)` where the precise clock is used.
- **Cross-checked liveness** (so no finding is dead code): `try_send_datagram` ←
  `r2_stage::send_packed_frames`, server `r2_send_large_reply`, client `try_single_data`;
  `r2_stage` ← client `drain_assoc_stage`/`send_uplink`/`stage_or_count` and server
  `stage_push`/`drain_stage`/`stage_open_src`; `r2_reasm` ← both datagram readers; `recv_burst`/
  `with_burst_msg` ← both end's drain loops; `udp_try_send_grouped` ← server
  `flush_staged_sends`, client `flush_staged`; retry pool ← all three last-hop send entry points.

---

## 4. Cross-domain notes (outside this domain, spotted while proving caller paths)

1. **Server: stager has no retry/timer after a `Blocked` drain.** `drain_staged` requeues the frames
   after the failed one (`r2_stage.rs:918-975`), but the only drain on the server is a session
   reader's burst boundary (`server/reader.rs:1320`); the 60 s idle tick branch
   (`server/reader.rs:1186-1201`) only refreshes `limit` and `continue`s. A tail requeued after a
   transient full DATAGRAM buffer can therefore sit until another reply on *any* session or
   connection close (then counted `EGRESS_DEAD` in the stager `Drop`), with no size/buffer counter.
   The client equivalent is bounded by the association loop's post-`select` drain every iteration
   (`client/assoc.rs:655-675`, idle tick 30 s). This is **already reported as server-bin #7**;
   cross-referenced so the Lead merges rather than double-counts.
2. **Server/client: MQP-2 receive handlers are still live for peer-chosen type bytes** (`0x05`
   FRAG and the legacy `0x02` DATAGRAM/BATCH decoders: `client/dispatcher.rs:541,562`,
   `server/accept.rs:2439,2579`). They are not reachable from the conforming rev2 peer, so they are
   not a compatibility requirement in the current protocol; they remain a hostile-input parser
   surface (audited sound above). The matching *send* side is dead code — `udp/fragmenter.rs`,
   `send_udp_datagram*`, `send_udp_batch` can be deleted with the legacy decoders when the MQP-2
   compatibility window closes; until then they are only exercised by tests.
3. **`server-bin #1` (generic DNS path resurrects a just-closed session)** is the terminal path this
   domain feeds (`r2_reasm` completion → `r2_ingress_open` → `forward_server_dgram` →
   `get_or_create_sess`); the reassembler side of that race is bounded (a late completion for a
   closed session is routed only through the registry/session path, which drops it) — no separate
   udp-domain defect found there. Note the **ctx-less partial** case I specifically checked:
   `drop_session` cannot purge a partial whose fragments have no OPEN context yet
   (`r2_reasm.rs:547-566`), so such a partial can complete after `SESS_CLOSE`; the completion then
   carries `(wire_id, None, None)` or an OPEN context and is dropped by the now-empty registry
   unless `forward_server_dgram` recreates the session — i.e. it funnels into server-bin #1 rather
   than adding a new consumer of the bug.
4. **`config/tuning.rs:351` admission term vs client bulk preset** — the per-connection charge adds
   `2 × DATAGRAM_BUFFER` (1 MB each) which matches the server's `build_transport_tuned` (non-bulk);
   the client-only bulk preset uses `DATAGRAM_BUFFER_BULK` (2 MB × 2) but clients are not
   admission-limited, so the mismatch is not a server accounting bug. Flagged only so the next
   reader does not "fix" it by adding the bulk term to the server charge.
5. **`r2_stage.rs:819-826` doc/code disagree**: the `send_packed_frames` doc says "a `Blocked`
   frame is retried on the next drain", but the code books the failed frame's items as
   `BUFFER_FULL` and only requeues the frames *after* it (`:848-857`, `requeue_unsent`
   `:755-774`). Behaviour is a defensible drop-newest UDP policy and is what the reachable callers
   expect; only the comment is wrong (not filed as a defect).
