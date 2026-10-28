# MyQUIC2 Data Plane Performance Analysis Report (Code-Logic Level)

> Analysis date: 2026-10-19 · Baseline commit: `d73809f` · Read-only analysis, no source code modified.
> Scope constraint: **analyze code logic only**, do not analyze configuration parameter values (window/MTU/buffer size/timeout/core count, etc.),
> all fix recommendations are changes at the level of code logic, data structures, batching, or scheduling structure.

---

## 0. Analysis Scope and Method

- Four parallel deep reads + Lead line-by-line review:
  - `src/udp/**` + `src/mqp/**` (~4.7k lines)
  - `src/bin/myquic2-server/**` (~3.6k lines)
  - `src/bin/myquic2-client/**` (~3.2k lines)
  - `src/lib.rs` production sections, `src/dns/**`, `src/stats/**`, `src/transport/**`, `src/linux.rs`
- Key conclusions all carry code line-number evidence; quantitative numbers come from each analyst's `/tmp` microbenchmarks (Apple M4/macOS, **used only for orders of magnitude**),
  plus existing measurement records in code/README (e.g. `accept.rs`'s +8.8% CPU, `frame_bench`'s pooling-rejection data).
  End-to-end gains still need re-measurement on a Linux target machine with `examples/hotpath_bench.rs`.

### Overall judgment

The main data path (UDP encode → quinn DATAGRAM → sendmmsg / recvmmsg; TCP double-buffer pump) **is already highly optimized**:
steady state per datagram = 1 exact-capacity allocation + 1 payload copy + 1 state lock inside quinn,
with no per-packet Mutex / channel / task / formatted logging, statistics already thread-local batched, BATCH decoding zero-allocation.
Therefore this report has no P0; the remaining issues concentrate in **4 P1 (2 of which are logic-defect amplification) + 9 P2 + several P3**.

| ID | Priority | Location | One-line issue |
|---|---|---|---|
| F1 | **P1** | `server/forward.rs:55-143` | When a domain target is filtered by SSRF, **one resolver task is spawned per packet**, and the connection fast table is never armed |
| F2 | **P1** | `server/accept.rs:258-438` | The 16-slot direct-mapped fast table conflicts with the client's **sparse monotonic session ids**; conflicting sessions fall back to the slow path on every packet |
| F3 | **P1 (system-level)** | `client/main.rs:49,210-244,473-543` | Fragment slot runtimes stack on top of the main runtime's default worker count; the Linux default path has **deterministic core oversubscription** |
| F4 | **P1** | `udp/reassembler.rs:336-361,603-632` | Fragment reassembler eviction uses an **O(256) `min_by_key` full-table scan**; above a completion rate of ~128/s, it is paid once per completed payload |
| F5 | P2 | `server/reader.rs:138-248` + `client/dispatcher.rs:549-563,retry.rs:328-332,391-408` | The downlink "single reply" path pays one extra full-payload copy (GROUP_SCRATCH) and is wrapped in BATCH-of-1 |
| F6 | P2 | `udp/batch.rs:553-572` + `assoc.rs:245,255` / `server/reader.rs:345,362` | After the Linux `recvmmsg` drain, each datagram is **memcpy'd once more** into the caller's buf |
| F7 | P2 | `server/pin.rs:467-492` + `reader.rs:453-466` | `remember_dst` **unconditionally** bumps the allowlist epoch, defeating the reply reader's epoch gating |
| F8 | P2 | `client/assoc.rs:195-208,373-449` | Uplink small packets only do **2-pack**; the same burst to the same destination could fit 8~13 per frame (the server side already has an N-pack reference) |
| F9 | P2 (conditional) | `udp/fragmenter.rs:237-264` | When the quinn send buffer has "room for 1 fragment but not N", fragment send **sends the prefix and drops the tail**, producing orphan fragments that waste tunnel bandwidth |
| F10 | P2 (structural) | `client/main.rs:379-388` + `assoc.rs:5-10` + `main.rs:508-543` | The relay task runs on the main runtime while the egress driver is pinned to a slot runtime; every outbound DATAGRAM crosses cores for a state lock + driver wake |
| F11 | P2 | `lib.rs:318-394` + `server/reader.rs:769` + `table.rs:148-158` | Each UDP session socket does 4~5 extra diagnostic `getsockopt` calls (on clamp, +2 BUFFFORCE calls doomed to EPERM); each insert/remove scans 8 shard read locks |
| F12 | P2 | `stats/udp_stats.rs:92-115` | `fragmented()`/`unsolicited()` don't do the same 256 batching; in the fragmented state, one **global atomic RMW** per payload |
| F13 | P2/P3 | `udp/reassembler.rs:288,384,446-448,497,319-329` | 3 repeated hash probes per fragment, 5~6 at completion; at completion, a second traversal of the payload + two extra allocations |
| F14 | P3 | `stats/drops.rs:239`, `accept.rs:530`, `pin.rs:389`, `fragmenter.rs:213`, `dns/resolve.rs:386-450`, `socks.rs:133-259`, `assoc.rs:45-46` | A series of per-packet/per-flow small overheads that can be eliminated (see §4) |

### 0.5 Fix Landing Status (implemented 2026-10-19)

The file:line references in §1/§2/§3 of this report are the **baseline at analysis time** (`d73809f`); post-fix code is
as per `git diff`. Implementation results:

| ID | Status | Landing points |
|---|---|---|
| F1 | ✅ Fixed | `server/forward.rs` adds a per-connection `DnsGate` (in-flight coalescing + Unusable 5s negative cache) + `resolve_forward_target` (when the thread memo is filtered by SSRF, fall back to the session DestMemo; on hit, inline and return `Some` so `arm_fast` takes effect); fully filtered no longer spawns per packet |
| F2 | ✅ Fixed | `server/accept.rs` 16 slots changed to bounded linear probing (`fast_probe` / `fast_arm_index`), shared by resolve/try_stage/arm; only when >16 live sessions does it evict the least active by `last` |
| F3 | ✅ Fixed (2026-10-28, third batch §8 A1) | `client/main.rs` `main_runtime_workers_for` no longer subtracts every pinned slot from the app runtime: pinned slots may claim at most half the cores, so the app side always keeps `>= ceil(cores/2)` workers (the old rule collapsed an 8-core Linux box to **1** worker). `priority_pin_cores` now takes the app worker count and never pins a slot onto a core the app runtime occupies |
| F4 | ✅ Fixed | `udp/reassembler.rs` each of the two maps gets an insertion-order `VecDeque` + lazy invalidation + prune/over-limit rebuild on `expire`; eviction amortized O(1), `held` accounting unchanged |
| F5 | ✅ Fixed | `udp/retry.rs` Linux n==1+header changed to a two-iovec `sendmmsg` (zero copy); `server/reader.rs` single staged reply sends a single 0x02 frame, no longer BATCH-of-1 |
| F6 | ✅ Fixed | `src/udp/batch.rs` adds `with_burst_msg` (borrowed); the recvmmsg drain paths in client `assoc.rs` and server `reader.rs` process in place; non-Linux keeps the `burst_msg_copy` fallback |
| F7 | ✅ Fixed | `server/pin.rs` `remember_dst` bumps the epoch only when rcu actually publishes (Cell flag); steady state zero epoch RMW |
| F8 | ⏸ deferred | Quantified gain ~0.25~1% single core, conflicting with the packet-loss/accounting/latency invariants pinned by 4 regression tests; design archived (client report) |
| F9 | ✅ Fixed | `udp/fragmenter.rs` records `last_blocked`; under backpressure, fragment send first does an aggregate pre-check with `datagram_send_buffer_space()`, and drops the whole packet if it doesn't fit (no more orphan prefix frames) |
| F10 | ⏸ Pending measurement | Cross-runtime relay migration needs `MYQUIC2_SHARD_RUNTIME=0` A/B measurement before deciding |
| F11 | ✅ Fixed | `src/lib.rs` process-level socket buffer probe cache (subsequent sockets skip 4~6 getsockopt / failed BUFFFORCE) + `udp_socket_dual_small_addr`; `server/table.rs` table-level `live` count makes `note_empty_state` O(1) |
| F12 | ✅ Fixed | `stats/udp_stats.rs` `fragmented()`/`unsolicited()` merged into thread-local 256 batching |
| F13 | ⏸ deferred | Requires rewriting the `push_with_chunk` borrow/accounting structure, gain ~4ns/fragment + 30~45ns at completion, risk not worth it; left for a separate change |
| F14 | ◐ Partial | Fixed: P3-2 reassembly tick guard, P3-3 pin hit skips SSRF re-check, P3-4 fragmenter clock lazification, P3-5 DNS warm-hit positive-then-negative + single allocation, P3-6 SocketAddr direct pass; Not done: P3-1 drop counting padded shard, P3-7 CONNECT timer merging, P3-8 dispatcher slice_ref, P3-9 interactive single-connection fragmentation (all low gain/cold path/design tradeoff) |

> Constraint compliance: no configuration parameters/defaults changed (`src/config/**`, `Cargo.toml` zero changes), no dependencies added;
> all are code logic, data structure, batching, and scheduling structure changes. Behavioral changes see §7.

### 0.6 Second Batch Fix Landing Status (rev2/R2 path, implemented 2026-10-21)

The second batch (T0–T9: rev2/R2 tabularization, reassembly, stager and statistics paths) was implemented in the order
`T3→T4→T9→T1→T7→T5+T0→T2→T8→T6`; constraints same as 0.5 (zero config/zero dependency changes,
arc-swap reuses the existing dependency), tests pinned for existing behavior updated in sync to preserve assertion intent. Landing
points per `git diff`:

| ID | Status | Landing points |
|---|---|---|
| T3 | ✅ Fixed | `server/accept.rs` r2_stats adds an independent `TRAIN_ITEMS` counter + `bump_train_item()`: per **item** (one TRAIN frame holds at most 64 items) thread-local 256-batch writeback, the only r2_stats line that lands on the packet path; the remaining r2_stats keep one RMW per frame (read directly by tests) |
| T4/T4b | ✅ Fixed | `client/rev2.rs` counters split into `rev2_counter_fns_tls` (thread-local `Cell` accumulation, `FLUSH_EVERY` periodic writeback to the shared value) and direct fn two kinds; `Rev2Snapshot::now()` calls `flush_locals()` for the current thread before reading, so snapshot/test reads and batching see each other. Observable counter semantics unchanged |
| T9 | ✅ Fixed | `client/rev2.rs` `UplinkFlows` single-slot memo (`last: Option<(TargetAddr, Arc<FlowBinding>)>`) serves steady targets: a hit saves the `SessionFlows::find` linear scan and the binding's Arc clone/drop; memo slot and `mark_closed` mutual-exclusion semantics are pinned by a regression test (after close it must reopen with a new id, never reuse a dead binding) |
| T1 | ✅ Fixed | `server/accept.rs` TRAIN two-pass parsing: pass1 builds `item_slot: Vec<u16>` + ≤64 dedup slots (linear dedup bounded by the encoder maximum), and the new `FlowRegistry::get_batch` fills all slots under **a single read lock**; pass2 walks items through the newly extracted `r2_forward_flow_resolved(state, binding, payload)` (a binding already `Closed` is not forwarded); the original per-item entry `r2_forward_flow_item` becomes a thin wrapper |
| T7 | ✅ Fixed | `client/dispatcher.rs` `dispatch_r2_train` three-layer hoist: per-distinct-id memo (skips registry.get + reply-dst derivation), per-session-run memo (skips `r2_lookup`'s Weak upgrade + is_alive + app read), `stage_reply_follow` makes run-following items with `sock: None` inherit the flush's relay Arc (one clone per run). On any miss it falls back to the per-item path; observable surfaces such as counts/rejections/staging order are preserved per item |
| T5+T0 | ✅ Fixed | `udp/r2_stage.rs` drain two-phase: `pack(limit, &mut PackedFrames)` encodes frames only inside the lock, `send_packed_frames` (free function) sends QUIC **outside the lock**, `requeue_unsent` re-inserts the items after the failed frames to restore per-session FIFO (overflow is accounted by the caller per the full-queue policy: client `BUFFER_FULL`, server additionally `STAGE_FULL_DROPS`); `push` returns the queue length avoiding a second lock; hot-path reader/drainer all use the three-part combination. **The old whole `drain()` is retained but only one caller `stage_open_src` remains** (its invariant "the queue drained this time is exactly this OPEN SRC and it is online" requires push→send to hold the lock throughout), and its internals were also changed to pack+send+requeue with an assertion of zero overflow on re-insert. **No push_batch**: downlink replies come from different sessions with no shared batchable entity, and lock-across-send has already been eliminated by the two-phase design itself |
| T2 | ✅ Fixed | `FlowBinding.resolved` RwLock→`ArcSwap<Vec<SocketAddr>>`: DNS install/rebind `store` atomically swaps the whole set, readers' `load()` snapshot never blocks writers (REP `SourceMatch` does one snapshot read per candidate) |
| T8 | ✅ Fixed | `server/forward.rs` DnsGate adds a single-slot fast hint (hot_key/hot_state/hot_deadline three AtomicU64; publish order deadline→state→key, Release store of key): the same-key hot path returns InFlight/Unusable directly without locks; finish invalidates per verdict — delivered clears entry+hint, only evicted with the authoritative table lacking this key clears the hint, a stale finish does not disturb a newer claim's hint, expiry passes through by deadline. Behavior test `dns_gate_fast_hint_is_invalidated_by_a_delivered_finish_and_expires` |
| T6 | ✅ Fixed | `udp/r2_reasm.rs` reassembly changed to a **single assembly buf**: total==1 returns `d.slice(chunk_off..)` zero-copy (payload shares the allocation with the frame, test asserts pointer equality); for multiple fragments, copies **once** into the final position per `pos(i)=len(0)+(i-1)*unit` (sender split contract: middle segments equal width, last segment short or equal width), fragments whose position cannot be determined hold a "frame view" (Bytes refcount clone + chunk_off/len) waiting for the determinator, and are placed exactly once on unlock; on completion `Bytes::from(mem::take(buf))` with zero second copy (each chunk end is monotonic ≤ last segment end, no truncate needed); a middle width not matching the locked `unit` **rejects the whole fragment** (returns before any mutation); a write end > 8 KiB is always rejected (prevents resize explosion from a maliciously widened unit). retained accounting changed to a capacity basis: `buf.capacity() + pending Σ(len+48)` (`PENDING_CHUNK_COST`), recomputed after each mutation with saturating add/sub on `held`; the first write reserves a cap of 8 KiB. `mqp/r2.rs` `FragRef` adds an informational `chunk_off` field (filled at decode, wire unchanged) |

> **Behavior changes (only two)**: (1) when a middle fragment's width does not match the payload's locked unit, that fragment is rejected
> (the old implementation tolerated mid-segment differing widths and concatenated in arrival order — the sender contract is equal-width middle segments); (2) `FragRef` adds
> a `chunk_off` field (purely informational, wire/encoding unchanged). held accounting changed from "slot table + chunk length" to
> "assembly buf capacity + pending views", with the 256 KiB/connection cap and full-queue/eviction semantics unchanged.
>
> **Verification (macOS local)**: `cargo fmt --all --check` ✅ clean |
> `cargo clippy --all-targets -- -D warnings` ✅ clean |
> `cargo test --all-targets` ✅ **433 passed / 0 failed**
> (lib 206 / client 125 / server 102; including 5 new T6, 1 T8 fast-hint,
> 1 T9 regression, 2 T5 requeue tests). Review fix: the `total == 64` completion mask changed to
> `checked_shl` (the original `1u64 << 64` panics in debug and yields a zero mask in release and never completes),
> pinned by `a_full_width_64_fragment_payload_completes`.

---

## 1. P1 Issues (Expected Largest Impact)

### F1 [P1] When a domain target's resolution result is filtered by SSRF, one resolver task is spawned per UDP packet, and the fast table is never armed

**Location**
- `src/bin/myquic2-server/forward.rs:55-70` (resolution source selection), `:71-87` (spawn branch), `:89-107` (resolution/filtering inside the task), `:108-137` (send inside the task), `:138-143` (returns `None`)
- `src/dns/resolve.rs:431-450` (the thread DNS memo stores only the "first address after sorting")
- `src/bin/myquic2-server/accept.rs:681-692,723-737,752-770,814-816` (`arm_fast` only when `forward_server_dgram` returns `Some`)

**Mechanism (verified line by line)**

```rust
// forward.rs:55-70 —— only the Unknown branch consults the session DestMemo
let resolved = match lookup_cached_fast_with_ttl(h, p) {
    (CachedLookup::Negative, _) => { bump(REFUSED); return None; }
    (CachedLookup::Addr(dst), life) => Some((dst, life)),          // ← filtered addresses also take this path
    (CachedLookup::Unknown, _) => sess_dest_lookup_ttl(ss, coarse_millis(), s, h, p),
};
if let Some((dst, life)) = resolved
    && (allow_private || is_global_ip_cached(dst.ip())) {
    ... send ...; return Some((dst, life));                        // only this path can arm_fast
}
// forward.rs:77-87 —— filter failure / not cached → per-packet permit + clone + spawn
let permit = dns_slow_path_limiter().clone().try_acquire_owned()?;
let host = h.to_owned();
tokio::spawn(async move { ... resolve_all_cached(&host, p).await ... });
// forward.rs:143 —— returns None ⇒ accept.rs never arm_fast
```

Three persistent shapes:
1. **The first resolution result is filtered** (`CachedLookup::Addr(filtered)`): the thread memo is written by `resolve.rs:431-448`
   on a shared cache hit with the "first address after sorting", so the next synchronous query **always** returns the same filtered address;
   this branch no longer consults the session `DestMemo` and falls straight to spawn.
2. **The entire record set is filtered**: when the spawn task's `find(...)` has no usable address, it only `bump(REFUSED)` and returns
   (`forward.rs:98-101`), **writing no negative cache** ⇒ the next packet starts over entirely.
3. **The spawn branch can only return `None`** ⇒ the connection-level fast table is never armed; every subsequent packet re-runs
   `resolve_fast` miss → full slow path → spawn again.

`allow_private` defaults to `false` (`config/server_conf.rs:35-37`), so this is the behavior under the default configuration.

**Trigger conditions**: the target domain resolves to a private/loopback address (localtest.me, nip.io, self-controlled domains, split-horizon,
NAT internal services), or the first entry of a mixed record set is private (with public addresses after it). **Peer-drivable**:
with the default empty `auth_token`, any peer that can connect to the server can drive this path with domain-target datagrams;
the 1024-permit `dns_slow_path_limiter` is also shared with server TCP dialing (`server/tcp.rs:91`), so once it is exhausted, legitimate domain targets' first resolution is dropped/reset per `DNS_BUDGET`.

**Cost**: per packet ≈ `tokio::spawn` + `host.to_owned()` + 2×Arc clone + permit `try_acquire_owned`
+ two moka await probes inside the task + two allocations on a successful arm + `get_or_create_sess` + `remember_dst`
+ one `sendto` ≈ **1~3µs/packet**; versus tens~hundreds of ns on the normal fast path, an amplification of **10~30×**.

**Fix direction** (logic fix, no parameter changes)
1. The `CachedLookup::Addr(filtered)` branch first consults the session `DestMemo` (merging the two sources); on a usable hit do
   `send + return Some((dst, life))` so `arm_fast` takes effect;
2. Add a short-term negative cache for "the entire record set is unusable" (can reuse `DNS_NEG_TTL` or the filtered variant of `DestMemo`),
   so subsequent packets count `REFUSED` inline and no longer spawn;
3. Add in-flight dedup per `(conn, sess, host, port)`: while a resolution is in flight, subsequent packets are dropped directly per UDP semantics
   (or share the same waiter), eliminating "one task per packet".

**Validation**: use `dns_cache_seed_set` to construct "first filtered, second global" and "all filtered" targets,
and assert that over N consecutive packets the spawn count is 1/0 (add a test-only counter).

---

### F2 [P1] The 16-slot direct-mapped fast table conflicts with sparse monotonic session ids; conflicting sessions stay on the slow path permanently

**Location**
- `src/bin/myquic2-server/accept.rs:258` (`FAST_SESS_SLOTS = 16`)
- `:318-320` (`fast_slot(s) = (s as usize) & 15`)
- `:364-409` (`try_stage` requires the slot's `sess == s`, otherwise returns `Err`)
- `:411-438` (`arm_fast` unconditionally overwrites that slot)
- `:574-575` (comment assertion: "Session ids come from the client's monotonic counter, so N <= 16 live ids land on N distinct slots")
- Client fact: `src/bin/myquic2-client/hub.rs:295-322` (process-level monotonic `fetch_add`, no rollback, no reuse)

**Mechanism**: the comment's premise does not hold. Client ids are a **process-level monotonic, never-reused** counter;
the active session set is a **sparse subset** of `[1, next)` (session release leaves holes; ids of the two egress classes interactive/bulk
interleave on the same counter). Therefore the `s & 15` collision probability, estimated by the birthday problem (active count A):
A=5 about **50%**, A=8 about **88%**, A=10 about **97%**. The comment's "only conflicts at 17" holds only when ids are contiguous.

A conflicting pair overwrites each other's slots, so both sessions miss on **every packet**:
`resolve_fast` (`accept.rs:333-362`) → `try_stage` returns `Err` → slow path
`forward_server_dgram` → `udp_try_send` (**one `sendto` per packet, bypassing burst's sendmmsg once per 32 packets**)
+ `remember_dst`'s shard read lock + epoch bump + two memo probes + 4×Arc clone → `arm_fast` overwrites back again.

**Impact**: the client multiplexing all UDP associations of one egress class onto one QUIC connection is the documented main form
(interactive class fixed at index 0, `pool.rs:592-598`); the common 5~20 concurrent UDP flows will most likely hit a conflict.
The code itself measured this same slow path at +8.8% CPU (`accept.rs:564-568`), and `sendto` amplifies more on Linux.
Stacked with F7, the reply direction also pays an extra ArcSwap load.

**Fix direction**: change the 16-slot direct-map to **bounded linear probing** (probe at most 16 slots starting from `s & 15`, stopping on
`sess == s` hit / empty slot; arm takes the first empty slot, evicting when the table is full), or 4-way set-associative.
Probing can only miss, never mis-route. Do not just increase the slot count (each slot ~420B, 4096 connections already ~27MiB).

**Validation**: extend the existing fast-table cases in `tests.rs`, use congruent sparse ids (e.g. 1001/1009/1025) and assert that both hit.

---

### F3 [P1, system-level] Fragment slot runtimes + main runtime default worker count ⇒ Linux default path core oversubscription

**Location**
- `src/bin/myquic2-client/main.rs:49` (`#[tokio::main]` = default multi-thread runtime, worker count = `available_parallelism()`)
- `:210-244` (sharded topology: **one OS thread per pool slot**)
- `:473-490` (`priority_pin_cores`: the first `cores` slots are pinned)
- `:508-543` (each slot thread builds a `new_current_thread` runtime hosting that connection's quinn driver + dispatcher + reconnect)
- `src/bin/myquic2-client/pool.rs:575-598` (default pool = 4 TCP + 3 UDP = **7 slots**)
- `src/linux.rs` (`pin_to_core` takes effect on Linux only)

**Mechanism**: under the default configuration, 7 slot threads (the first `min(cores,7)` pinned) + the main runtime's `cores`
preemptive workers. On 4-core Linux/OpenWrt = 4 pinned + 3 floating slot threads + 4 main workers,
**11 runnable threads contending for 4 cores**; the main runtime carries all SOCKS/TCP pump and UDP association relay tasks,
while pinned slot threads carry the receive/reply hot path ⇒ every pinned core has two resident competitors.
On macOS `pin_to_core` is a no-op, so existing macOS soak cannot see this problem; but Linux is the release target.

**Impact**: when CPU saturates, the pinned shard's driver/dispatcher available CPU drops roughly by the CFS equal share,
and receive/send latency and the pps ceiling drop; the fewer the cores, the worse. Needs Linux 2~4 core measurement to confirm the magnitude.

**Fix direction** (scheduling logic):
- Explicitly build the main runtime: `worker_threads((cores - pinned_slot_count).max(1))`, and use
  `on_thread_start` + an atomic cursor to pin workers to cores not occupied by shards; or
- When `slots_total >= cores`, limit the pin count (leave at least 1 core for ingress) / shrink the default pool width.
  Principle: `pinned shard count + preemptive worker count` should not exceed the core count.

---

### F4 [P1] Reassembler eviction uses an O(n) `min_by_key` full-table scan; above a fragment completion rate of ~128/s it is paid once per payload

**Location**
- `src/udp/reassembler.rs:336-361` (`remember`: inserts a tombstone for every **completed** fragment payload, then
  `while recent.len() > FRAG_MAX_PARTIALS && evict_oldest_tombstone()`,
  `while held > FRAG_MAX_HELD_BYTES && evict_oldest_tombstone()`)
- `:603-616` (`evict_oldest_tombstone`: `recent.iter().min_by_key(at_ms)`, at most 256 entries)
- `:618-632` (`evict_oldest`: likewise `min_by_key` over `parts`)
- `:496-517` (the completion branch calls `remember`)
- `:527-534` (when packet loss/reordering keeps the byte-cap over the limit, **each stored fragment** first evicts tombstones one by one, then scans parts)

**Mechanism**: every completed fragment payload records a tombstone (live for `FRAG_TIMEOUT_MS = 2s`, cap 256).
As long as a single reassembler (one per QUIC connection) has a fragment payload completion rate >~128/s, `recent` stays saturated,
and **after that every completed fragment payload does a 256-entry `min_by_key` full-table scan** (measured ~181ns for 256 entries).
The default `initial_mtu = 1200` (`config/tuning.rs:192`) ⇒ QUIC DATAGRAM budget 1162B ⇒ UDP payloads over ~1150B get fragmented,
so any bulk UDP / VPN traffic enters this path; it is not a cold path.
Under packet loss, the byte-cap path additionally scans `parts` once per fragment.

**Impact**: 20k completed payloads/s ≈ 3.6~4.2ms/s (~0.4% core); 100k/s ≈ 2%;
stacked with F13's completion-path hash/assemble, this is about half of the reassembler's per-payload user-space cost.

**Fix direction** (change the data structure, not the cap parameters): eviction order matches insertion order (`at_ms`/`first_ms` are monotonic),
so an insertion-order `VecDeque<key>` can be maintained beside each of the two maps: pop from the head on eviction, and if the key is not in the map or the
timestamp doesn't match, skip lazily — amortized O(1); or use a monotonic seq + `BTreeMap<seq,key>` (O(log n)).
Overwriting an existing key only needs to lazily invalidate the old queue entry.

---

## 2. P2 Issues

### F5 [P2] The downlink "single reply" path pays an extra full-payload copy and is wrapped in BATCH-of-1

**Location**
- `src/bin/myquic2-client/dispatcher.rs:549-563` (when run length is 1, uses `[SendFrame;1]`)
- `src/udp/retry.rs:328-332` (n==1 goes per-frame directly) → `:391-408`
  (`GROUP_SCRATCH` concatenates header + **whole payload**)
- `src/bin/myquic2-server/reader.rs:184-248` (`flush_reply_batch` calls `encode_batch` even when n==1)
- The comments at `src/bin/myquic2-client/hub.rs:28-31` / `dispatcher.rs:500-508` both claim the downlink does "zero payload copy"

**Mechanism**: the server BATches replies ≤512B (even n==1 is wrapped as a 0x06 frame); >512B and reassembled replies go single-frame.
The client groups by `(sock,app)` on flush; **run length 1 is a common shape** (one reply per drain burst).
With n==1, `udp_try_send_grouped` takes the per-frame path: header non-empty ⇒ concatenates header+payload into
`GROUP_SCRATCH` then `try_send_to`. That is, **every single-frame reply pays one whole-packet memcpy**, contradicting the doc's "zero-copy"
(the `retry.rs:387-390` comment "Linux won't reach the header branch" is also wrong — that branch hits on Linux too).
On the server side, n==1 also pays an extra arena staging copy + BATCH header/count + client batch decode.

**Impact**: 1.4KB reply ~17.5ns each (measured), 20k~100k replies/s ⇒ 0.04~0.4% core + contention with the quinn driver for L1/L2;
the amount is small, but it is a gratuitous full-payload copy on the hot path, and the fix is about 10 lines.

**Fix direction**
- In `retry.rs`, when n==1 and the header is non-empty, use the already n==1-capable `sendmmsg_frames(fd,&dst,&frames[..1])`
  (2 iovecs, zero copy; n==1 skips `record_send_group` to preserve histogram semantics);
- Server `flush_reply_batch` when `staged.len() == 1` directly uses `DgramFragmenter::send` to send a 0x02
  single frame (the prefix cache is already in `frag`), no longer wrapping a BATCH.

---

### F6 [P2] After the `recvmmsg` drain, each datagram is memcpy'd once more into the caller's buffer

**Location**
- `src/udp/batch.rs:553-572` (`burst_msg_copy`: `dst[..n].copy_from_slice(&b.data[off..off+n])`)
- `src/udp/batch.rs:425-455` (per-thread 32×`BURST_SLOT` ≈270KiB recvmmsg scratch)
- Call sites: `client/assoc.rs:245,255` (app→QUIC uplink), `server/reader.rs:345,362` (target→client downlink)

**Mechanism**: the awaited head uses `recv_from(&mut buf)` (kernel→buf once); the remaining drain uses `recv_burst`
to write into the thread-local BURST arena with one `recvmmsg` (kernel→arena), then `burst_msg_copy` copies arena→buf again,
and only then decode/encode. The drain loop body has **no await**, the BURST arena stays valid until the next refill, and the
payload is consumed within the same synchronous section ⇒ this arena→buf copy can be removed.

**Impact**: on Linux, one fewer full-payload memcpy per drained datagram; 40~100k pps × ~1KB ≈ 0.5~1% of one core;
linear amplification for 8KB payloads.

**Fix direction**: add a borrowed accessor in `udp::batch` (`burst_msg(i) -> Option<(&[u8], SocketAddr)>`
or a closure-scoped API), and let callers parse/encode in place; if the server accept slow path needs `.await`, copy that one entry then.

---

### F7 [P2] `remember_dst` unconditionally bumps the allowlist epoch, defeating the reply reader's epoch gating

**Location**: `src/bin/myquic2-server/pin.rs:467-492` (`fetch_add` at `:489-490`, rcu at `:476-488`),
`src/bin/myquic2-server/reader.rs:453-466` (epoch change ⇒ `recent.load_full()` once per reply)

**Mechanism**: the purpose of the epoch is to let the reply reader pay only one relaxed load in steady state (comment at `table.rs:41-50`),
but `remember_dst` still unconditionally does `fetch_add` when the ring has not changed (steady state, same target). Sessions on the slow path
(F2 conflicting sessions, multi-target sessions, the phase when a domain target has not been armed) call `remember_dst` per packet ⇒ their reply reader
executes `ArcSwap::load_full()` **for every reply** (hazard pointer + Arc refcount RMW),
and contends with the sending side's epoch RMW for the same cache line.

**Fix direction**: bump only when the ring actually changes (move into the `!contains` branch; inside the rcu closure use a local flag to record
whether a push actually happened; an extra bump on rcu retry is harmless — the epoch only needs to be monotonic, more is fine).

---

### F8 [P2] The client uplink only does 2-pack for small packets; N-pack capability gap

**Location**: `src/bin/myquic2-client/assoc.rs:195-208` (`pending_buf`/`pending_pack` state and comments),
`:373-449` (pairing logic, only joins two adjacent entries into `[&[u8];2]`), `:511-521` (flush at the end of a burst);
reference implementation `src/bin/myquic2-server/reader.rs:138-248` (budget-aware arena + `reply_stage`/`flush_reply_batch`, up to 16 per frame)

**Mechanism**: `send_udp_batch` supports up to `MAX_BATCH_ITEMS = 16`, but assoc sends immediately after only 2 are paired.
A 32-packet burst to the same destination ⇒ 16 quinn sends, each = connection-state mutex + driver wake +
one exact frame allocation + quinn packet copy. 100~200B payloads fit ~8~13 per frame by path budget.
The whole interactive class's associations share the same egress connection, so reducing send count also reduces that mutex's cross-core contention.

**Impact**: sends/payload from 0.5 → ~1/8~1/13; at 40k pps and 200~300ns per send, ≈ 0.3~0.6% core,
and directly relevant to the README's 100k pps N=1 small-packet goal. **Does not add latency** (still flushed at the end of the burst).

**Fix direction**: expand `pending_buf` into an arena + `Vec<(off,len)>`, copying the server's
`reply_stage`/`flush_reply_batch` pattern; on encode failure fall back to per-entry `frag.send`, preserving the existing
TooLarge/Blocked semantics and accounting.

---

### F9 [P2, conditional] Under a saturated send-buffer window, fragment send "sends the prefix and drops the tail", producing orphan fragments that cannot be reassembled

**Location**: `src/udp/fragmenter.rs:237-264` (per-fragment `send_encoded`, returns immediately on the first non-`Sent`),
`src/udp/send.rs:243-252` (`PayloadSend` doc: partial sends are not rolled back),
`src/udp/send.rs:84-95` (quinn `send_datagram_wait` checks space for **a single** datagram)

**Mechanism**: quinn 0.11.12's `send_datagram_wait` only checks whether "this one datagram" can be enqueued
(`quinn-proto-0.11.19/src/connection/datagrams.rs:49`). When the send buffer is in the "enough for 1 fragment, not N"
state (under saturation the driver drains only one packet ≈ one fragment per iteration, a normal window), a 2-fragment payload successfully enqueues fragment 1
and fragment 2 returns `Blocked` — fragment 1 still goes on the wire, the peer never receives fragment 2, and the partial is discarded after 2s,
**wasting (F−1) fragments' worth of tunnel bandwidth** (up to 50% of that payload's bytes when F=2).

**Fix direction**: have `DgramFragmenter` record "whether the previous fragment send was Blocked"; when fragmentation is needed (F>1) and the previous send was Blocked,
first call quinn 0.11.12's public `Connection::datagram_send_buffer_space()`
(`quinn-0.11.12/src/connection.rs:508`) as a pre-check, and if the space is less than the total frame length + bookkeeping margin, drop the whole thing
(count `Blocked`, equivalent to fragment 1 being Blocked), otherwise send fragment by fragment as usual. The healthy path only adds one bool check.

---

### F10 [P2, structural] Client relay task and egress driver on different runtimes ⇒ every outbound DATAGRAM crosses cores for a state lock + driver wake

**Location**: `src/bin/myquic2-client/socks.rs:139` → `assoc.rs:5-10` (the relay loop lives in the SOCKS task,
spawned by `main.rs:379-388` on the `#[tokio::main]` main runtime);
the egress driver/dispatcher lives in the slot runtime at `main.rs:508-543`.

**Mechanism**: `try_send_datagram` → quinn `SendDatagram::poll` takes the `ConnectionInner.state` mutex and
calls `state.wake()` every time (quinn-0.11.12 `connection.rs:856-876`); the lock's partner is the
driver, which holds it on every received packet, and the driver is on a pinned slot thread while the relay task is on a main worker ⇒ every UDP send is one cross-core
cache-line handoff + one cross-runtime driver wake (TCP amortizes it every 16KiB, UDP pays it per packet).

**Impact**: every outbound UDP datagram; each cross-core handoff+wake is about 0.1~0.3µs (estimate) ⇒ 40k pps ≈ 0.5~1.3% core +
latency jitter. **The fix's benefit is uncertain and the refactor cost is high, so it must be A/B measured first** (`MYQUIC2_SHARD_RUNTIME=0` against
`hotpath_bench udpmulti/lat`). Direction: after the first packet determines the `UdpBind`, move the relay loop to the corresponding slot runtime;
a cross-runtime channel is not recommended (it would introduce a hop of the same magnitude).

---

### F11 [P2] Each UDP session socket creation does 4~5 extra diagnostic `getsockopt`; each insert/remove scans 8 shard read locks

**Location**
- `src/lib.rs:318-394` (`udp_socket_dual_impl`): the Linux branch `:367-373` first does getsockopt to determine force,
  `:374-387` reads back 2 more times for the warning; `warn_buf_clamped` does 2 atomic swaps each time; `:414-425` does not cache force failure
- Call sites: `server/reader.rs:769` (once per new UDP session), `client/assoc.rs:45-46,50` (per association)
- `src/bin/myquic2-server/table.rs:148-158` (`note_empty_state`: `shards.iter().any(|sh| !sh.read().is_empty())`,
  called on every insert/remove: `reader.rs:894` and `:607`)

**Mechanism**: the SO_SNDBUF/SO_RCVBUF clamp verdict is a netns/process-level constant, but it is read back on
**every socket** for the "whether clamped" warning; when clamped without CAP_NET_ADMIN, each socket also issues 2 `SO_*BUFFFORCE` calls doomed to EPERM.
Measured (macOS A/B): 4 readbacks add +1.5~1.7µs/socket; on Linux at 0.3~0.5µs/syscall, ~1.2~3µs/new flow. `note_empty_state` takes 8 shard read locks per insert/remove (~hundreds of ns).

**Fix direction**: a `static PROBE: OnceLock<ClampVerdict>` process-level cached verdict (probe the first socket + attempt
force once and record the capability), then skip readback/force afterwards; change `note_empty_state` to a table-level `AtomicUsize live_count`
(insert +1, remove -1, update global holders on the 0↔1 transition), removing the 8-lock scan each time.

---

### F12 [P2] `udp_stats::fragmented()` / `unsolicited()` are not batched; in the fragmented state one global atomic RMW per payload

**Location**: `src/stats/udp_stats.rs:92-99` (fragmented), `:111-115` (unsolicited);
compare `:60-89`'s `payload()` TLS batching; call sites `udp/fragmenter.rs:273` (after each fragment payload is sent successfully),
`server/reader.rs:471` (full-cone, every non-whitelisted inbound packet)

**Mechanism**: `FRAGMENTED.fetch_add(1, Relaxed)` hits the global cache line directly, and all shards/threads contend for the same line.
The default `initial_mtu=1200` makes >1150B payloads routinely fragmented, so this is a **normal path**, not an exceptional path.
Measured shared `fetch_add` 22.6/24.6ns/op vs batched 0.21ns; ~5~25ns more per fragment payload, and it is a cross-shard serialization point.

**Fix direction**: add a `fragmented` counter to the existing TLS structure (same Cell as datagrams/bytes), or add
`payload_fragmented(len, frames)` to combine into one TLS access, flushed with the 256 threshold; `unsolicited` likewise.

---

### F13 [P2/P3] The reassembler repeats hash probes per fragment; at completion a second traversal + two extra allocations

**Location**: `src/udp/reassembler.rs:288`→`:297-311` (`recent.get`), `:384` (`parts.get`),
`:446-448` (`parts.entry`, second probe of the same key), `:497` (completion's `parts.remove`, third time),
`:319-329` (`prints_of` hashes each chunk and allocates `Box<[Option<ChunkFp>]>`),
`:85-91` (`assemble` allocates BytesMut then copies all chunks)

**Mechanism**: an ordinary fragment does 3 hash map probes; a completing fragment does 5~6. At completion it first computes a fingerprint over the full payload
(measured 2800B ~45ns) and then does a full assemble copy (~60ns); the same data is traversed independently twice with two allocations
(plus one String allocation for `p.address.clone()` on Domain targets).

**Fix direction**: a single `parts.entry(key)` serves the four decisions "exists/over-limit/restart/complete"; more thoroughly, merge the tombstone
into the same map (`enum Slot { Partial, Tombstone }`), with 1 probe per fragment and in-place conversion at completion; compute the fingerprint
during the same cache-hot access that stores the chunk in `push`, and move it directly at completion, saving the second traversal and the `Box` allocation.

---

## 3. P3 List (small overheads, zero/low-risk fixes)

| # | Location | Issue |
|---|---|---|
| P3-1 | `stats/drops.rs:239`, direct counting in `stats/udp_write.rs`, `stats/warn.rs:26-38` | One global `fetch_add` + `coarse_millis` per drop; happens per packet during saturation/REFUSED floods. Can change to a padded per-thread shard array (snapshot sum remains exact), keeping the warning gate |
| P3-2 | `server/accept.rs:530,607` + `client/dispatcher.rs:602-604,692` | The per-connection 500ms reassembly tick wakes unconditionally (even with an empty reassembler, and for TCP-only connections); 4096 connections ≈ 8k wakeup/s. Add the guard `if reasm.held_bytes() > 0` to the select branch |
| P3-3 | `server/pin.rs:389` | A pin hit repeats `is_global_ip_cached` once per domain-target packet (pure function, already filtered at arm); the arm verdict can be trusted and returned directly, saving ~10ns/packet |
| P3-4 | `udp/fragmenter.rs:213` | One precise `mono_millis()` read per fragment payload, but it is only used after 2^32 id wraps; move the clock evaluation into the `last_wrap_ms != 0` branch |
| P3-5 | `dns/resolve.rs:386-450` | warm-hit does negative then positive, two moka probes each time; the Ok branch does `Vec<SocketAddr>` + `Arc::from`, two allocations. Query positive first, with the port attached by the caller |
| P3-6 | `client/assoc.rs:45-46` + `lib.rs:319` | Each association formats a `SocketAddr` into a String and parses it back; add a constructor entry in lib that takes `SocketAddr` |
| P3-7 | `client/socks.rs:133,150,166,218,246-252,377` + `pool.rs:763-771,252-257` | ~7 independent timeout timers per TCP CONNECT; `holds_dead_handle` and `wait_conn` probe liveness twice on the same quinn state lock; non-interactive flows pay an extra `set_priority(0)` (quinn-proto 0.11 only stores the i32 and sends no frame) |
| P3-8 | `client/dispatcher.rs:220-243` | BATCH does one `d.slice_ref` per payload + one `entry.relay.clone()` per frame; can change to `StagedReply{frame,off,len}` holding just 1 frame + 1 socket Arc per frame |
| P3-9 | `client/pool.rs:592-598`, `egress.rs:259-290` | The interactive UDP class is hard-bound to a single connection (one driver + one state lock carries all small-packet associations); bulk already has shard rotation, which could be generalized (design cap, not a defect) |

---

## 4. Points Confirmed Optimized and **Not Recommended to Touch**

The following, after line-by-line verification + existing in-code measurements, fall into "changing them again is negative gain or duplicated work":

- **Per-datagram encode**: `Vec::with_capacity` exact capacity + `Bytes::from` goes through in-place `into_boxed_slice`
  (`mqp/datagram.rs:97-135`), 1 allocation + 1 copy; frame pooling has already been rejected by measurement in `examples/frame_bench.rs`
  (+39~52% / +128~324%).
- **`DgramPrefixCache`**: steady state, same (sess,dst) → zero validation, zero re-encode (`mqp/datagram.rs:168-217`).
- **BATCH encode/decode**: `decode_batch` zero allocation, validates the whole frame first then iterates lazily (`mqp/batch.rs:141-181`).
- **quinn per-frame state lock**: internal to `send_datagram_wait`, intrinsic to the API, cannot be bypassed by this repository.
- **Reassembler chunk copy**: `Bytes::copy_from_slice` exists to make `FRAG_MAX_HELD_BYTES` accounting exact
  (otherwise a 20B fragment would pin a ~92KiB GRO batch, see `udp/reassembler.rs:266-279` and the corresponding tests).
- **TCP pump**: `read_chunks(8)` + `write_vectored`, ≥8KiB `write_chunk` zero copy, double-buffer pool,
  fixed 5s idle tick (`tcp/pump.rs:229-535`); no per-chunk allocation.
- **thread-local statistics**: `udp_stats::payload`, `udp_write::sent`, `record_drain_batch` all do 256 batching
  (F12 only fills in the two missed fields).
- **egress memo / hub / dispatcher**: `with_fresh` 1×TLS + 1×Acquire load, no Arc RMW, no quinn lock
  (`egress.rs:139-165`); hub's 256-shard `ArcSwap<HashMap>` read path is lock-free (`hub.rs:210-233`);
  dispatcher drains ≤32 packets per wake, no per-packet spawn/channel (`dispatcher.rs:615-693`).
- **Normal send path pays no retry cost**: on success `udp_try_send_*` only does `try_send_to` + TLS counting.
- **Regex/logging/format**: all hot-path warns are rate-limited and detail closures only run when due; no per-packet formatting.
- **coarse/mono clocks**: coarse 1.44ns, mono 3.26ns (measured); the per-packet path already uses coarse; do not change again.
- **transport/TLS/DNS memo**: built once at startup; DNS memo hit is zero allocation, zero lock; `is_global_ip` only on cache miss.
- **sendmmsg/recvmmsg batching**: the last hop already groups by (sock,dst) run, Linux up to 32 frames at a time;
  `sendmmsg_frames` already uses `MaybeUninit` to eliminate the 2.7KB dead store; F5 is only the n==1+header residue.

---

## 5. Recommended Fix Order and Validation Approach

**First batch (small changes, large gains, includes security amplification)**
1. **F1**: slow path merge session memo + filtered negative cache + in-flight dedup (+ seeded DNS unit tests).
2. **F2**: fast table bounded linear probing (+ sparse id unit tests).
3. **F5**: client n==1 uses `sendmmsg_frames`; server n==1 sends a single frame directly (+ batch case assertions).
4. **F6**: `udp::batch` borrowed burst accessor, processed in place at both client/server.
5. **F7**: epoch bumps only on real writes (+ unit test).
6. **F12**: fragmented/unsolicited merged into the TLS batch.

**Second batch (measure first)**
7. **F3**: Linux 2~4 core `hotpath_bench udpmulti/lat/lattcp` to re-check oversubscription; then limit the main runtime worker count/pinning.
8. **F4**: reassembler insertion-order queue + lazy eviction; compare `udpps` + fragmented traffic load tests.
9. **F8**: client uplink N-pack (following the server `reply_stage` pattern).
10. **F9**: fragmenter blocked state + `datagram_send_buffer_space()` pre-check; saturated-state bandwidth comparison.
11. **F10**: first `MYQUIC2_SHARD_RUNTIME=0` A/B, then decide whether to migrate the relay task.

**Third batch**: F11, F13, P3 list (low-risk cleanup).

**Common validation means**
- Unit tests: seeded DNS, sparse session ids, epoch counting, n==1 single frame, burst borrowed accessor.
- End-to-end: `examples/hotpath_bench.rs`'s `udpps`/`udppaced`/`udpmulti`/`udpdomain`/`bulk`/`lat`,
  comparing CPU/pps/latency before and after on a Linux target machine (including 2~4 core small machines).
- System observation: `perf stat` (context-switch, cycles/instruction), `strace -c` (syscall count on session creation),
  `perf record` (confirm hotspot migration).

---

## 6. Limitations

- No end-to-end benchmark was executed; all percentages/µs here are estimates from "per-event cost × frequency assumption" or existing in-code measurements,
  intended for orders of magnitude and relative ranking; final gains need re-measurement on a Linux target machine.
- Microbenchmarks ran on Apple M4/macOS; Linux syscall unit prices are usually lower and quanta precision differs, but
  the mechanics — syscall counts, atomic contention, copied bytes — are the same, so the problem direction is unchanged.
- The trigger frequency of F3/F9/F10 depends on deployment shape (core count, saturation level, cross-core topology); conditions were noted where they were listed as P1/P2.

---

## 7. Implementation Record and Verification (2026-10-19)

### 7.1 Change Scope

17 source files (+3298/−874), no changes to `src/config/**`, `Cargo.toml`/`Cargo.lock`:

| File group | Fixes |
|---|---|
| `src/bin/myquic2-server/{accept,forward,pin,reader,table,tests}.rs` | F1/F2/F5-server/F6-server/F7/F11b/P3-2/P3-3 |
| `src/bin/myquic2-client/assoc.rs` | F6-client, P3-6 |
| `src/udp/{batch,retry,fragmenter,reassembler,send}.rs`, `src/udp.rs` | F4/F5/F6-API/F9/P3-4 + `note_send_buffer_full` accounting entry |
| `src/lib.rs`, `src/stats/udp_stats.rs`, `src/dns/resolve.rs` | F11a/F12/P3-5 + `udp_socket_dual_small_addr` |
| `src/mqp/fragment.rs` | eviction policy comment sync (the only documentation change) |

### 7.2 Verification Results (macOS aarch64 local + Podman Linux container, rustc 1.99.0)

| Command | Result |
|---|---|
| `cargo fmt --all --check` | ✅ clean (fmt unified at integration time) |
| `cargo clippy --all-targets -- -D warnings` | ✅ clean |
| `cargo test --all-targets` (macOS local) | ✅ **279 passed / 0 failed** (lib 134 / client 76 / server 69; baseline about 240, 39 new regression tests) |
| **`cargo test --all-targets` (Podman / Debian 12 aarch64 Linux container)** | ✅ **283 passed / 0 failed** (lib 138 / client 76 / server 69; the extra 4 are `#[cfg(target_os = "linux")]` tests) |
| **`cargo fmt --all --check` + `cargo clippy --all-targets -- -D warnings` (same Linux container)** | ✅ clean (CI parity) |
| `cargo zigbuild --target x86_64-unknown-linux-gnu --all-targets` | ✅ exit 0 (including Linux-only cfg branches: F5 sendmmsg, F6 with_burst_msg, F9 gate, F11a probe) |
| `cargo zigbuild --target x86_64-unknown-linux-musl --bins` | ✅ exit 0 (CI static musl target) |
| `git diff --check` | ✅ clean |

> Linux container run notes: the image is based on `localhost/myquic2-ci:1.99` (Rust 1.99.0) with `cmake`/`ninja` added,
> with the workspace and host cargo registry mounted, and `CARGO_TARGET_DIR` pointing at a Podman volume. This way
> `recvmmsg`/`sendmmsg`, the `with_burst_msg` in-place branch, the F9 backpressure gate, F11a Linux probing and other
> runtime paths are genuinely executed and pass. The only remaining unverified item is the **throughput/latency gain** itself: it is recommended to use
> `examples/hotpath_bench.rs` (`udpps`/`udppaced`/`udpdomain`/`udpmulti`) on a Linux target machine for a before/after comparison.

### 7.3 Behavior Changes (require review attention)

1. **F1**: while a resolution is in flight, subsequent datagrams for the same `(session, name, port)` are now dropped directly (UDP semantics,
   counted `REFUSED`), instead of each spawning a resolver; all-filtered/failure verdicts are cached for 5s, rejected inline during that time.
   The existing `l2_dns_singleflight_burst_delivers_server` was renamed accordingly to
   `l2_dns_burst_coalesces_to_one_waiter_per_session` (asserts spawn==1).
2. **F5-server**: a single staged reply now sends a single `0x02` DATAGRAM, no longer wrapping a 1-item BATCH frame
   (the client accepts both; 3 fewer wrapping bytes per reply on the wire).
3. **F6**: on Linux, datagrams drained by recvmmsg are no longer copied into the caller's buf (non-Linux/no recvmmsg keeps the original path).
4. **F11a**: the socket buffer clamp verdict changed to a process-level cache (after the first socket probe, runtime
   `net.core.*mem_max` changes are no longer observed, effective on restart; consistent with `MYQUIC2_SESS_SOCKET_BUF`'s process-level model).
5. **P3-3**: a pin hit no longer redoes the SSRF verdict per packet (already filtered before arm, the pin address is immutable over its lifetime, the predicate is pure);
   security semantics unchanged.
6. **P3-5**: DNS warm-hit changed to positive first then negative (the positive/negative store mutual-exclusion invariant is pinned by a test),
   the negative cache hit path pays one extra positive probe, the warm path one fewer.

### 7.4 Follow-up (deferred, per §0.5)

F3 (thread topology), F8 (client N-pack), F10 (cross-runtime), F13 (reassembler probe fusion),
P3-1/P3-7/P3-8/P3-9 — all need a Linux benchmark or have a gain/risk ratio unsuitable for this batch; design proposals were retained in the report.

## 8. Third Batch: Independent Audit of v0.2.3 (2026-10-28)

Scope: a fresh audit of the shipped tree (`HEAD 8ac314e`, v0.2.3) for the largest remaining performance limits and memory
leaks, this time reading the code rather than re-measuring the 2026-10-19/21 batches. Result: **no unbounded growth
remains** — every peer-fillable structure is bounded (buffer pools, stager, reassemblers, flow registry, DNS cache, retry
pool, dispatch cache, forward hubs), and no task/owner cycle survived review. The severe findings were instead scheduling
and architecture limits plus one lifecycle leak in the v3 ingress fast table. All but A4 are fixed in this batch.

| ID | Severity | Status | Landing points |
|---|---|---|---|
| A1 | P1 | ✅ Fixed | `client/main.rs`: `main_runtime_workers_for` clamps the *pinned* share to half the machine (`cores.saturating_sub(slots.min(cores / 2)).max(1)`) instead of subtracting every pinned slot; `priority_pin_cores(pool, app_workers)` takes the worker count and installs at most `cores - app_workers` pins, so a pin can never displace the app runtime on its own core. On an 8-core Linux host the default 7-slot pool used to leave the app runtime (every SOCKS accept, TCP relay pump and UDP association task) **one** worker; it now gets 4, and slot threads get the other 4. |
| A2 | P1 (QoS) | ✅ Fixed | `config/tuning.rs` adds `DEFAULT_UDP_INTERACTIVE_CONNS = 2` / `MAX_UDP_INTERACTIVE_CONNS = 8`; `config/client_conf.rs` adds `udp_interactive_conns` (`udp_interactive_cnt()`); `client/pool.rs` gives the interactive class its own shard range `0..interactive_shards` (bulk is `interactive_shards..`), a second round-robin cursor (`udp_irr`) so bulk bursts cannot move an interactive association, `MAX_UDP_SLOTS` = interactive + bulk (16), and `planned_slot_count` takes both counts. `client/main.rs` logs both ranges and prioritizes every interactive shard in the pin order. Default pool: 4 TCP + 2 interactive UDP + 2 bulk UDP = 8 connections. |
| A3 | P1 (ops) | ✅ Fixed | `src/fdlimit.rs` (`nofile_limit`, `raise_nofile_limit`, `NoFileLimit::{shortfall, describe}`) raises the soft limit to `min(hard, wanted)` best-effort and reports the `ulimit -n` / `LimitNOFILE=` / `--ulimit nofile=` remedy; both binaries call `report_fd_budget()` at startup against their designed capacity (server 24,840 = 8,192 sessions + 16,384 relay slots + 8 endpoints + 256 guard, client 12,496 = 8,192 + 4,032 + 16 + 256). `nix` gains the `resource` feature. Previously **nothing** in the tree touched `RLIMIT_NOFILE`, so a stock `nofile=1024` silenced the 8,192-session design at ~1,000 sessions with a rate-limited `EMFILE` warn. |
| A5 | P2 (leak) | ✅ Fixed | `server/accept.rs`: `FastSess.flows` is now `Weak<ArcSwap<FlowTable>>` instead of `Arc<...>`; `arm_fast` stores `Arc::downgrade(&flows)`; `fast_flows` upgrades and falls back to `session_flows` when the session is gone; `fast_arm_index` recycles dead slots (`slot_is_dead` = `abort.is_finished() \|\| sock.strong_count() == 0`) before growing the probe chain. A strong handle made the per-connection slot array a second owner of a dead session's flow table; session ids are monotonic, so nothing ever replaced the entry and up to 64 x 22 KiB per connection stayed pinned until the connection ended, outside the admission charge. `R2_INGRESS_FIXED_BYTES`'s doc was updated to the weak-handle wording. |
| A6 | P3 | ✅ Fixed | `mqp/v3.rs` `decode_fragment_v3` now rejects `total > MQP_FRAG_MAX_TOTAL` (64) and `chunk > MQP_FRAG_MAX_PAYLOAD` (8,192) as `Malformed`, matching the v2 decoder's contract. Latent only (the v3 stage uses the encoder, the tests used the decoder), but a hostile or buggy peer would have been able to index beyond the reassembler's 64-fragment bound if the decoder ever became a receive path. |
| A7 | P3 | ✅ Fixed | `server/accept.rs`: the rev3 control-plane handoff `ctl_in` is now `mpsc::channel(CTL_IN_QUEUE = 64)` instead of unbounded, and `r3_control_stream_task` awaits `send`, so a peer that outruns the datagram loop applies QUIC flow control to its own reliable stream. Messages are never dropped (`OPEN`/`CLOSE` are not idempotent), and the datagram loop only touches this queue through `queue_ctl`'s `try_send`, so the wait cannot deadlock. The token bucket (4,096 msg/s) had already bounded the growth rate to ~100 KB/s, so this is defence in depth, not an observed incident. |
| A4 | P2 (structural) | ⏸ Won't fix — rationale below | The server keeps one DATAGRAM reader task per connection (`server/accept.rs` `handle_conn_inner`), so one client connection is one core at most. |

### A4: why the per-connection server pipeline is not fanned out

The obvious fix — spawn N reader tasks per connection — is wrong for two reasons, both verified in the tree:

1. **Quinn serializes a connection by design.** One connection owns one UDP socket, one crypto/ACK state and one DATAGRAM
   queue; every outbound datagram takes the connection lock (`udp/send.rs` notes that `send_datagram_wait` takes one mutex
   per poll). Concurrent readers cannot exceed that ceiling, they only add contention.
2. **The stager's contract is per-session FIFO.** `udp/r2_stage.rs` pins "each session's steady items keep their FIFO
   order" (`mixed_heads_deliver_every_payload_exactly_once`), and `wire_id`s are client-assigned and monotonic. Two tasks
   pushing for the same session race on both the sequence and the frame order, so a fan-out would trade a throughput
   ceiling for a correctness regression.

The supported way to raise per-client parallelism is therefore **more connections**, which A2 already does (3 -> 4 UDP
connections by default, 2 of them interactive rather than 1), and which is bounded by `MAX_POOL_CONNS`,
`MAX_UDP_INTERACTIVE_CONNS` and `MAX_UDP_EGRESS_CONNS`. The remaining serialization is a protocol property, not a bug:
the client chooses its connection count, the server mirrors it.

### 8.1 Verification

- `cargo test` — **718 passed, 0 failed** (lib 358, client 200, server 145, E2E 15: 7 forwarding + 8 wire-revision).
- New regression tests: `arm_recycles_a_dead_slot_instead_of_growing_the_chain`,
  `reaped_session_releases_its_flow_table_from_the_fast_slot`, `fd_budget_covers_the_session_and_relay_pools`,
  `fd_budget_covers_the_relay_and_association_pools`, `decode_fragment_v3_rejects_impossible_totals_and_oversized_chunks`,
  `interactive_associations_rotate_over_their_own_shards`, plus the widened
  `main_runtime_worker_count_only_subtracts_real_pinning`, `slot_pinning_prioritizes_the_interactive_pair`,
  `udp_bulk_ports_force_bulk_regardless_of_first_payload` and the config matrix for `udp_interactive_cnt`.
- Behavior changes to review: (1) the app runtime now keeps half the cores on a pinned topology — on an 8-core Linux box
  the client runs 4 app workers + 4 pinned slot threads instead of 1 + 7; (2) the default client pool is 8 connections
  instead of 7, so a server sees one extra QUIC connection per client; (3) `nofile` is raised best-effort at startup and a
  short hard limit prints a warning instead of failing; (4) the rev3 control plane applies backpressure to a fast peer.
  No wire change, no on-disk format change.
