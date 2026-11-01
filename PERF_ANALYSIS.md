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

## 9. Fourth Batch: Second Audit Round (2026-10-28, post-3ab72b9)

An independent sweep of the same datapath after the first batch of fixes, this time looking for defects *introduced or
left* by it as well as for what the first pass skipped. Four items were found; one was withdrawn after verification.

| # | Item | Severity | Status |
|---|------|----------|--------|
| B1 | Fast session table (64 slots) vs `LOCAL_SESS_MAX` = 4096, i.e. up to ~2000 live sessions per QUIC connection after the client pools its associations | High | ✅ Fixed: 128 slots, inline pins kept, memo raised to 256 |
| B2 | Per-connection reply stager shared by every session (1,024 items / 256 KiB) | Medium-high | ⏸ Documented, structural |
| B3 | rev3 uplink has no context-lost recovery | — | ❌ Withdrawn: MQP-3 codec is test-only (see below) |
| B4 | Two doc comments drifted after batch 3 | Low | ✅ Fixed |

### 9.1 B1 — fast table working set

> **Follow-up (2026-10-31):** the inline pin and then the per-slot SSRF
> verdict moved out of the hot slot, so `FAST_SESS_SLOTS` is computed from the
> same array budget at 88 B `FastSess` (~568 slots); the thread-local
> `is_global_ip_cached` memo supplies the verdict, and a bounded 48-entry
> domain-pin side cache restores the INLINE/legacy lock-free hit. The 128-slot
> numbers below are the historical record of B1, not the current table.

`FAST_SESS_SLOTS` was 64 while `LOCAL_SESS_MAX` is 4096, and the shipped client concentrates up to ~2000 live sessions on
one connection (2 interactive + 2 bulk UDP shards for up to 4,032 associations). Past 64 live sessions *every* arm evicts:
`fast_arm_index` falls through to the least-recently-active slot, so the table becomes a churn buffer and each datagram
pays a full probe plus the slow path — `remember_dst`'s shard read lock, an unbatched `sendto` that bypasses
`flush_staged_sends`' `sendmmsg`, and two memo probes.

The fix doubles the table to 128 slots instead of sizing it to `LOCAL_SESS_MAX`, which would cost ~1.7 MiB per connection
at ~420 B per slot (the inline `ConnPin` dominates). **Memory account:** 128 × ~420 B = 52.5 KiB per connection, up from
26.25 KiB; with the 16 KiB pre-HELLO buffer that is ~68.5 KiB, still inside the 96 KiB `R2_INGRESS_FIXED_BYTES` charge
(4,096 connections: 210 MiB worst case, in the same order as the documented quinn reassembler and TCP pump ceilings).

`SESS_MEMO_SLOTS` had to grow with it: the memo index mixes the session id with the odd multiplier `0x9e3779b9`, so two
ids exactly one fast-table step apart collide in a memo of the *same* size — precisely the pair a probed table exists to
keep. A memo miss clears the session's fast slot, so 128/128 would have made the two tables fight. 256 restores the 2×
headroom and costs ~5 KiB per worker thread.

**Not fixed (structural):** a fixed-size table cannot cover 4096 sessions per connection. The remaining fix is to make a
miss cheap — stage the slow path's target send into the same `flush_staged_sends` batch instead of one `sendto` per
datagram — and to keep spreading the client's associations over more egress connections.

**Measurement follow-up (2026-10-30):** the current code uses ~405 slots plus a
bounded 48-entry domain-pin side cache. `hotpath_bench udpmulti` at the shipped
8 associations (≈2 sessions per connection) does not exceed the old 128-slot
working set, so it cannot show the overflow win. A meaningful A/B needs a
512+ association client or a synthetic 1000-session ingress test; record pps,
CPU, syscalls/payload and fast-table hit rate, with a 10–100 session control run
to measure the longer probe's low-fan-in cost. Until then, treat the table-size
change as a structural improvement, not a measured throughput claim.

### 9.2 B2 — shared reply stager

`R2ConnState.stage` is one `R2Stager` per connection (1,024 items / 256 KiB) and the client packs ~2000 sessions onto a
connection, i.e. ~0.5 frame / 128 B of headroom per session when the stager is full. Under overload `stage_push` drops
with `BUFFER_FULL`; it does not queue.

Sharing is the design: a per-session quota would multiply the per-connection bound by the session count and make the
admission charge meaningless. The queueing discipline that matters here is upstream — the connection's DATAGRAM send
buffer and the target socket's send buffer — and both are drop-newest already. Fairness is a scheduling problem (which
session drains first), not a capacity one; the current drain is FIFO over one stager, which at least keeps a single
session's frames in order.

### 9.3 B3 — withdrawn: MQP-3 is not on the wire

The finding assumed `handle_v3_ingress` (`accept.rs`) served live traffic. It does not: `encode_single` / `encode_train`
callers are tests plus `flush_reply_single` / `flush_reply_batch` in `reader.rs`, and both of those functions are
`#[cfg(test)]`. The rev3 wire is `src/mqp/r3.rs` (`wire::kind(Wire::Rev3, ..)` → `r3::kind`), and `is_v3` therefore never
matches a frame from a shipped peer. Context-lost asymmetry between the v3 encoder and its ingress is real but
unreachable; `src/mqp/v3.rs` (3.2k lines) and its ingress paths are exercised by tests only, with no config switch to
enable them. Recorded here so the next audit does not report it again without checking reachability.

## 10. Fifth Batch: Third Audit Round (2026-10-28, post-62fe2b3)

A third pass over the datapath after the second batch, focused on handoff queues and on whether the first batch's
server-side fix had a client-side counterpart. One item was found.

| # | Item | Severity | Status |
|---|------|----------|--------|
| B5 | Client rev3 **outbound** control queue is unbounded while its producer is the peer's frame rate | Medium | ✅ Fixed: `CTL_QUEUE` = 64, `try_send` + `ctl_queue_full`, inbound side bounded and awaited |

### 10.1 B5 — client rev3 control queue

Batch 3 bounded the server's inbound control handoff (`CTL_IN_QUEUE` = 64, `try_send`, drop + count). The client's
outbound side had no bound at all: `ConnRev2::send_ctl` pushed into a `tokio::sync::mpsc::unbounded_channel` installed by
`dispatcher::spawn_ctl_stream`, and the consumer writes the messages in order onto the reliable control stream, where
progress is gated by the peer's flow control.

Only one of the three producers was rate-limited (`send_need_context`, via `CtlRate`). The other peer-driven one is
`send_flow_reject`: `install_server_flow` refuses a binding frame for four reasons (`wire_id_server_owned` violation, a
missing session or address, an unencodable address, and a full/conflicting registry) and queues one `REJECT` per refused
frame. A peer that keeps sending frames this side refuses *and* stops reading the control stream therefore queued them at
its own packet rate for the connection's lifetime — ~72 B per queued message, i.e. megabytes per second at a few tens of
thousands of packets per second, with no cap.

The fix mirrors the server: both directions are now `channel(CTL_QUEUE)` with `CTL_QUEUE = 64`. `send_ctl` uses
`try_send` and counts `ctl_queue_full` on `Full` (the counter is in the 60 s report line as `qfull=`); the stream task
awaits its handoff to the dispatcher, so a peer that floods the inbound direction stalls its own stream through QUIC flow
control instead of growing the queue. Dropping is safe for the messages that can actually fill the queue — `REJECT` and
`NEED_CONTEXT` are re-derivable from the frames that follow — while a dropped `ASSOC_CLOSE` degrades to the server's 180 s
idle reap. Regression coverage: `rev3_control_queue_drops_instead_of_growing` (capacity-1 and `CTL_QUEUE` cases, exact
drop count, and that draining one slot restores admission).

**Not changed:** `send_flow_ack` on the rev2 plane, which is a DATAGRAM send and already drops on `Blocked`.

## 11. Sixth Batch: Fourth Audit Round (2026-10-29, post-09f609a)

A fourth pass, this time looking for *per-datagram fixed cost* rather than missing bounds: cache footprint,
lock count, atomic read-modify-write, syscalls. One severe item was found, and it was self-inflicted by the
previous batch's table growth.

| # | Item | Severity | Status |
|---|------|----------|--------|
| B6 | `fast_arm_index` turned every fast-table miss into a scan of 128 scattered ~440 B entries (~1.3 µs) | High | ✅ Fixed: split-array table, tag-only probe, in-place re-arm |
| B7 | Chained probing + "recycle the first dead slot" left entries unreachable and allowed a duplicate for the same session | Medium | ✅ Fixed: probe scans tags, no chaining, no holes |
| B8 | Re-arming a live session rewrote the whole 440 B entry and both `Weak`s | Low | ✅ Fixed: only the pin and the liveness stamp are touched |
| B9 | `arm_fast` took a third shard read lock per miss to cache a v3 flow table no shipped peer reads | Medium | ✅ Fixed: field removed, one lock per v3 train instead |
| B10 | `arm_fast` cleared the slot on every session-memo miss, so the 256-entry memo's evictions discarded live slots | High | ✅ Fixed: only a `Stale` memo clears |

### 11.1 B6 — the miss path paid for the table's size

The steady shape of a server datagram is: `resolve_fast` (hit → `try_stage` → the frame joins the burst, flushed
as `sendmmsg` runs of ~32) or, on a miss, memo probe → shard read lock (`get_or_create_sess`) → a second shard read
lock (`remember_dst`) → one `udp_try_send` → `arm_fast`.

`arm_fast` picked its slot with `fast_arm_index`, which scanned the whole table — and each step of that scan
dereferenced a 440-byte `FastSess` to call `slot_is_dead` (two cross-object atomic loads: `abort.is_finished()`
and `sock.strong_count()`) plus `last.load(Relaxed)`. The payload array was 128 × 440 B = 52.5 KiB, i.e. far past
L1, so one arm touched ~384 scattered cache lines: ~5.4k cycles, **~1.3 µs**, before even writing the entry back
(440 B memcpy plus two `Arc::downgrade` refcount round-trips).

The trigger is the shipped shape: the client pools ~4032 associations onto 4 UDP connections, so a server
connection fronts ~1000 live sessions against 128 slots. At ~12 % hit rate, **88 % of datagrams take the slow path
and arm**, i.e. ~1.3 µs of pure cache traffic each — around 17 % of one core at 150 kpps, on top of the ~2-3 µs
the slow path already cost against ~0.2-0.3 µs for a hit. The previous batch raised the table from 64 to 128 to
lift the hit rate from ~6 % to ~12 % and doubled the cost of every miss doing it: the eviction *churn* was priced
in, the probe *scan* was not.

### 11.2 The fix — split arrays, tag-only probe, in-place re-arm

`FastTable` is now three parallel arrays over `FAST_SESS_SLOTS`:

```rust
pub(crate) struct FastTable {
    tags:  [u32; FAST_SESS_SLOTS],              // 0 = free (session 0 is refused)
    ages:  [u64; FAST_SESS_SLOTS],              // liveness stamp for eviction
    slots: [Option<FastSess>; FAST_SESS_SLOTS], // the entry itself
}
```

- `probe` reads `tags` only: 128 × 4 B = 512 B, eight cache lines, no dereference, no atomics. The chain and the
  `None`-stops-the-probe rule are gone with it, so an entry can never hide behind a hole (B7), and `arm_index`
  prefers the session's own slot before the first free tag before the minimum `ages` entry — the last one being
  the only case that reads `ages` (1 KiB).
- `insert` copies the entry once and stamps `ages` from it; `clear` removes tag, age and payload together, which
  is also what releases a reaped session's flow-table `Weak`.
- `touch(idx, stamp)` writes `ages` only when the stamp actually advanced (it advances about once per second), so
  the steady hit path does not dirty the array every datagram.
- Re-arming a session that already holds its slot now only refreshes `pin` (the one field that can change: a new
  DNS generation) and the stamp. B8.
- `size_of::<FastSess>() <= 448` is a compile-time assert next to the type: `R2_INGRESS_FIXED_BYTES` is derived
  from that number, so a field may not grow it silently.

Cost after the change: a miss scans 1.5 KiB instead of 52.5 KiB of scattered payloads, ~50 ns against ~1.3 µs.

### 11.3 Not changed — staging the slow path's target sends (B-suggestion 2)

Staging the slow path's `udp_try_send` into the burst was the other candidate. It buys nothing on the wire:
`flush_staged_sends` merges only *consecutive* frames that share `(sock, dst)`, and a slow-path datagram is a run
of length one by construction — the burst spans many sessions, so the neighbours differ. `udp_try_send_grouped`
routes a single header-less frame to the per-frame path anyway, so the syscall count is identical and the send is
merely deferred to the end of the burst. Recorded here so it is not re-proposed without measuring the run shape.

### 11.4 B9 — the arm path's third shard lock (found while sizing B6's follow-up)

`arm_fast` opened with `session_flows(ss, s)`, a shard read lock plus an `Arc`
clone, purely to fill `FastSess::flows` — a field only `handle_v3_ingress` reads.
That function serves MQP-3 rev3 TRAIN frames, which no shipped peer sends (§9.3), so the
lock was paid by **every rev2 miss** to serve dead code: a third shard
acquisition on a path that already takes two (`get_or_create_sess`,
`remember_dst`). At the miss rates that matter (tens of thousands per second)
that is ~0.2-0.3 us per datagram, and it is precisely the cost a bigger table
would otherwise be spent to avoid.

The field, the `fast_flows` accessor and the per-arm probe are gone;
`handle_v3_ingress` takes `session_flows` once per train and keeps the handle
for every item in it (a train carries up to `MQP3_MAX_TRAIN_ITEMS`), so the v3
path pays one lock per train instead of one per frame. `FastSess` drops 8 B to
432 B, which the compile-time assert now pins exactly.

`reaped_session_releases_its_flow_table_from_the_fast_slot` was deleted with
the field: the leak it guarded (a reaped session's 22 KiB flow table pinned by
a slot the sweeper cannot reach) is now impossible by construction rather than
by discipline. Everything else in the table is either a `Weak` (the socket), an
`AbortHandle` (no ownership) or a shared 8 B stamp.

### 11.5 B10 — the memo miss that threw away live slots (found in the post-hoc review)

Reviewing the batch turned up a worse defect than any of the numbers above:
`arm_fast` handled `SessHit::Stale` and `SessHit::Miss` in one arm,
`fast.clear(s)`. Clearing on a *miss* is a leftover from the single-slot design,
where a miss meant "this register now describes someone else". The table is
keyed by session id, so it no longer holds that meaning: a miss says only that
this thread's memo dropped `(conn_id, s)`.

That mattered because the memo is a **256-entry direct-mapped cache** and the
index mixes the id with an odd multiplier, i.e. it is a bijection mod 2^8: ids a
multiple of `SESS_MEMO_SLOTS` apart always collide. The shipped client pools
~4032 associations onto 4 UDP connections, so a server connection fronts ~1000
live sessions — roughly four per memo row, which means most re-arms see a miss.
Each of those misses cleared a slot that was still perfectly valid, so the
effective hit rate was gated by the *memo*, not by the table: a session armed on
a fresh hit lost its slot the next time a hash neighbour was armed.

The fix is to clear only on `Stale` (the row still names this session and its
reader is finished, so the slot can only describe a dead session). A `Miss`
leaves the slot alone, and the slot checks its own liveness anyway
(`is_live_for` + `sock.upgrade` before anything is staged). Leaving a dead entry
behind is safe by construction: recreating a reaped id re-puts the memo inside
`get_or_create_sess`, immediately before the arm, so the new session always arms
through the `Fresh` path and replaces the dead entry; if that never happens the
frozen age makes the entry the next eviction victim.

`SESS_MEMO_SLOTS` itself is not the lever. With the clear gone, a miss costs one
slow path and no state; the table still admits ~`FAST_SESS_SLOTS` arms no matter
how large the memo is.

### 11.6 Verification

`cargo test --bin myquic2-server` — 145 passed. The fast-table tests were rewritten for the new type:
both sessions hit (`two_sessions_on_one_connection_both_hit_the_fast_table`), a full table evicts the quietest
session (`a_full_table_evicts_the_quietest_session`), and sparse ids hit while a full table never grows
(`sparse_session_ids_both_hit_and_a_full_table_never_grows`, which also pins that re-arming returns the same slot
and leaves `len()` unchanged). B10 is pinned by `a_memo_eviction_keeps_the_fast_slot_serving`, which arms a
session, evicts its memo row with an id exactly `SESS_MEMO_SLOTS` away, and asserts the slot still serves; run
against the old `Stale | Miss` arm it fails with "a memo miss must not drop the slot".

## 12. Seventh Batch: the batched uplink that never decoded (2026-10-29, post-57c9d13)

Everything above came from reading the code. This batch came from running it: the
repository's own benchmark (`examples/hotpath_bench`, the shape README §12 quotes)
reported **13–17 % loss** on loopback at every rate, including 80 pps aggregate,
where no queue in the system can be full.

### 12.1 What the counters said

Instrumenting both ends split the loss exactly:

| Point | Value | Meaning |
| --- | --- | --- |
| bench `sent` | 1600 | payloads the app offered |
| client `app` | 1600/1600 | read and handed to the uplink — no ingest loss |
| client `stage` | 1600p / 1489f / 1600i / 0 drops | 1600 payloads packed into 1489 DATAGRAMs, none dropped |
| server `diag_rx` | 1489 | **every packed DATAGRAM arrived** (quinn is not the loss) |
| server decoded payloads | 1380 | **220 payloads vanished inside the frames** |
| bench `recv` | 1380 | what came back |

1488 datagrams, 1380 decoded as single-payload `DATA`, and **108 as `TRAIN`
— every one of which the decoder rejected**. 108 trains carrying the remaining
~220 payloads is exactly the 13.75 % loss.

### 12.2 Root cause

`src/mqp/r3.rs` wrote the train item-length field through a helper with side
effects, invoked from inside a `debug_assert!`:

```rust
for (idx, p) in items {
    v.push(*idx);
    debug_assert!(put_item_len(&mut v, p.len()));   // never runs in release
    v.extend_from_slice(p);
}
```

`debug_assert!` compiles its **whole expression** away when
`debug_assertions` is off, so `put_item_len` never appended the length byte in
any release build. Every multi-item `TRAIN` therefore went out as
`[flags][nfl][count][fids][idx][payload]...` instead of
`[flags][nfl][count][fids][idx][len][payload]...`, and the peer rejected the
frame (`Malformed("bad r3 train item fid")`) and dropped **all** of its
payloads. Single-payload frames use `encode_data_steady`, which has no such
field, so they were unaffected — which is why the loss only appeared once the
stager had two items to batch, i.e. at higher association counts.

The same pattern existed in `encode_train_same` and `encode_train_same_equal`.
All three are fixed; the tests could never catch it because `cargo test` runs
with debug assertions on, where the call *does* run.

### 12.3 The fix

1. The three writers are unconditional (`let wrote = put_item_len(..)`, with a
   `debug_assert!` on the returned flag, which is already bounded by the
   matching `train_*_len` helpers).
2. Each encoder now refuses a frame whose produced length disagrees with its
   budgeted length (`if v.len() != total { return None; }`). A future header
   regression degrades to a counted too-large drop instead of a silent,
   peer-rejected frame.
3. `train_encoders_emit_every_length_field` pins the byte layout of all three
   forms — the tests that existed only round-tripped, and round-tripping is
   exactly what a debug build still does. CI gained a
   `cargo test --release --lib mqp::` job so this class of bug is exercised in
   the profile the binaries ship in.

### 12.4 Verification

Same machine, same command, after the fix:

| Shape | Before | After |
| --- | --- | --- |
| 8 × 1000 pps × 128 B × 20 s | 13.7 % loss | **0.000 %** (160000/160000) |
| 8 × 10 pps × 128 B × 20 s | 17.6 % loss | **0.000 %** (1600/1600) |

`per_assoc_recv_min == per_assoc_recv_max` in both runs: delivery is now exact
per association, not merely right in aggregate.

## 13. Small-datagram ceiling: platform-dependent, silent drops past it

> Measured 2026-10-29 on macOS 27 (arm64, 10 cores — §13.1–13.3) and on Linux
> 6.18 in a podman VM (Fedora 43, 5 vCPU, 3.8 GiB — §13.4), release build, loopback,
> 128-byte payloads, 8 associations over the shipped 4-connection pool, with
> `hotpath_bench echo` as the target. Absolute numbers are host-specific.

### 13.1 macOS: the knee is ~35–40k pps

`hotpath_bench udpmultipaced` offers a fixed aggregate rate and counts what
returns. One client, one server, 15 s:

| Offered (8 assocs) | Delivered | Loss |
| --- | --- | --- |
| 20,000 pps (8 × 2,500) | 299,983 / 299,983 | 0.000 % |
| 40,000 pps (8 × 5,000) | 554,340 / 599,971 | 7.6 % |
| 80,000 pps (8 × 10,000) | 414,751 / 1,199,939 | 65.4 % |
| 80,000 pps, 45 s | 1,056,605 / 3,599,935 | 70.6 % |

An earlier 8 × 5,000 run lost nothing at all, so 40k is the knee itself — small
changes in machine state move it either side. Past the knee the curve is not
merely lossy but *inverted*: at twice the offered rate the proxy delivers
**fewer** datagrams (21–26k) than it does at 40k (35k). A control runs the same
echo target with no proxy:

`hotpath_bench udpraw 127.0.0.1:19000 1 100000 32` → 74,408 pps, 0.000 % loss.

So host and harness sustain ~74k pps one-way duplicating; the proxy contributes
four hops and fails at half that.

CPU during the runs (`top -l 2`, ≈25 s windows):

| Offered | client | server | bench | echo |
| --- | --- | --- | --- | --- |
| 40k | 214 % | **95.5 %** | 146 % | 67 % |
| 80k | 220–288 % | 72–91 % | 235 % | 61–77 % |

The server is at ~1.0 core at 40k and cannot go higher at 80k: the ingress
thread runs `handle_conn_inner` (`accept.rs:3749`), `sess_reader_task`
(`reader.rs:1495`) and `spawn_dispatcher` (`dispatcher.rs`) on one shard worker,
and on macOS that is the whole server — `SO_REUSEPORT` delivers the group to a
single member, so `ep_count` is 1 (`main.rs:198-213`,
`reuse_port_ingress_supported`).

### 13.2 Where the datagrams actually go

Aligned 60 s windows at 80k pps, one server, one client:

| Point | Count | Share |
| --- | --- | --- |
| offered by the app | 3,599,935 | 100 % |
| pushed into the client stage | 3,596,902 | |
| packed into DATAGRAM frames | 3,341,385 items / 2,284,335 frames | |
| client stage drops (`x` 255,423 + `full` 1,381) | 256,804 | 7.1 % |
| server forwarded (`udp write … sent`) | 1,082,217 | |
| returned to the app | 1,056,605 | 29.4 % of offered |

Only 7.1 % is dropped by our own policy on the client (`rev2.rs:1515`,
`stage_or_count`). The rest disappears between the client's `send_datagram`
(which succeeds) and the server's `recv_datagram` (which returns less). Two
receive-side queues are involved, and both drop silently:

- the server socket's receive queue — `netstat -s -p udp` "dropped due to full
  socket buffers" grew by **209,921** during a 10 s 80k run that lost 571,813
  datagrams, i.e. 37 % of the loss;
- quinn's per-connection incoming DATAGRAM buffer, `DATAGRAM_BUFFER = 1 MiB`
  (`limits.rs:84`) — the rest. quinn-proto documents the behaviour
  (`quinn-proto-0.11.19/src/connection/datagrams.rs:22`): when the receive
  buffer is full the datagram is *silently* dropped. The peer is not told and
  the local app only sees a gap.

That is the operational problem: `udp write` falls from ~35k to ~21k pps with
**no drop counter anywhere on the server** — `stage_full` is 0, because the
stager queue never fills; the drops happen below it. The only visible number is
the throughput that did not happen.

### 13.3 Why macOS sits at ~35k pps

Per datagram the ingress thread does two syscalls (`recvfrom` in
`sess_reader_task`, `sendto` in `flush_staged_sends`), a QUIC receive/decrypt, a
session lookup, one `R2Stager` push and a `send_datagram` that encodes and
enqueues. A `sample` profile of the saturated server puts ~55 % of the thread's
non-idle samples in `__sendto` and ~27 % in `__recvfrom`; crypto does not appear
at these rates. At 35k pps × 2 syscalls/s ≈ 70k syscalls/s the thread is at its
syscall budget — the raw echo thread sustains 74k pps with the same two calls
and nothing else.

Two syscalls per datagram *can* be batched on Linux: `flush_staged_sends`
(`accept.rs:254`) coalesces consecutive `(socket, destination)` runs into one
`sendmmsg`, and the client dispatcher does the same for replies
(`dispatcher.rs:78`, `:718`). But a connection multiplexes every association of
its egress class and the stager rotates across sessions (`r2_stage::pack_batch`
→ `pack_one_frame`), so consecutive frames of one drain almost never share a
destination: the run length is 1 and the fast path is the per-frame one. macOS
has no `sendmmsg` at all. The reply path on the client has the same shape — in
a slot thread at 84 % busy, 67 % of samples are `__sendto` under
`spawn_dispatcher`.

Beyond raw cost there is no feedback: DATAGRAM has no flow control, the client
keeps `send_datagram`-ing at 80k pps into a 35k pps pipe, and the excess is
dropped by the kernel/quinn receive buffers. Those buffers are FIFO, so the
datagrams delivered at 80k are also the oldest: queueing delay grows without
bound while goodput falls *below* capacity. That is congestion collapse, not
congestion control.

### 13.4 Linux (podman VM, 5 vCPU): ≥140k pps with the same code

The same binaries and the same shape in a 5-vCPU podman VM (Linux 6.18, Fedora
43). The server logged
`endpoints=5` and `udp batch backend: sendmmsg+recvmmsg (sendmmsg=true,
recvmmsg=true); GSO/GRO auto-probed`, so every batching path macOS lacks was
taken. 15 s per row:

| Offered (8 assocs) | Delivered | Loss |
| --- | --- | --- |
| 120,000 pps (8 × 15,000) | 1,799,441 / 1,799,928 | 0.027 % |
| 140,000 pps (8 × 17,500) | 2,098,120 / 2,099,932 | 0.086 % |
| 160,000 pps (8 × 20,000) | 2,104,622 / 2,399,243 | 12.3 % (10–19 % over repeats) |
| 160,000 pps (1 assoc) | 491,866 / 499,931 | 1.6 % |

CPU at 120k: server **0.42 core**, client 1.03, echo 0.25. That is ~3.5 µs of
server CPU per 128 B round trip, against ~24 µs on macOS (0.96 core at 40k
pps) — 6–7× cheaper, because `recvmmsg`/`sendmmsg` and GSO/GRO collapse a burst
into one receive and one send syscall instead of one pair per datagram. At 120k
the server is not the constraint.

The 160k row is where the *chain* saturates, not the QUIC layer. Nearly every
lost datagram is a kernel receive-queue overflow: `RcvbufErrors`
(`/proc/net/snmp`) grew by 275,056 in the 15 s cell against 294,621 lost (93 %),
by 487 against 487 at 120k, and by 1,812 against 1,812 at 140k. The QUIC sockets
themselves never dropped: `*:8443` carries 8 MiB receive buffers and `d=0` on
every sample. The overflow is spread across whichever queue is momentarily
smallest — the echo target's sockets (`127.0.0.1:19000`) mostly, the proxy's
per-association app sockets (`[::ffff:127.0.0.1]:*`, 128 KiB each, seen with
`r=48000…130560` queued and a few thousand drops), and the server's
per-session sockets. The proxy's own share is visible: in a 65 s 160k run the
client stage dropped 2.3 % of pushes (43,981 of 1,938,808) and `stage_full` rose
by 775 — the two slot threads that both send and receive at 160k pps are at
their limit, and at 140k they are not. Raising the target's buffers was not
possible: the container's `/proc/sys` is read-only.

So the per-datagram cost is what separates the two platforms, not the design:
unbatched 2-syscall-per-datagram on one `SO_REUSEPORT` member on macOS versus
batched syscalls with GSO/GRO across five on Linux. The earlier "~35k pps
anywhere" reading of this section was a macOS property; the same code held
0.09 % loss at 140k pps on a 5-vCPU Linux guest.

### 13.5 What the shape says to change

1. **Bound the sender, not the receivers.** A per-association credit (the
   `flow_ack`/ctl channel already carries out-of-band control) or a token
   bucket paced by ACKed datagrams would keep offered load near the measured
   pipe rate. For a UDP relay, loss is often the right signal to the app; today
   the app gets loss with no way to pace, and the proxy's buffers add delay on
   top of it.
2. **Make receive drops visible.** quinn-proto drops incoming DATAGRAMs
   silently; a wrapper counter (or a patched quinn) would let the 60 s line
   report `quinn_rx_drop=N` next to `stage_full`. The stage already counts its
   own drops (`send_packed_frames`, `BUFFER_FULL`); the layer below it is the
   blind spot.
3. **One thread per connection is the unit of scaling.** Shards exist on Linux
   (`ep_count = cores`), but a connection still lives on one shard. On the
   5-vCPU guest the 120k pps run used 0.42 core in total, so the per-connection
   bound was not reached; on macOS it is ~35k pps because the shard's syscall
   budget is reached there. Spreading a connection's receive loop, QUIC driver
   and senders across workers would need the shared runtime — measured worse on
   macOS: `MYQUIC2_SHARD_RUNTIME=0` gave 23.6 % loss at 40k against 12.3 %
   sharded, because locality beats parallelism at this size. The honest
   conclusion is a documented per-platform budget, not a fix.
4. **Batch per session.** `pack_one_frame` rotating sessions is fair but makes
   server-side `sendmmsg` runs length-1. A per-session pending queue (send up to
   N frames of one session per call) trades a little fairness for fewer sends —
   worth measuring on Linux, impossible on macOS.
5. **Re-check the pieces before blaming them.** Raising
   `R2_STAGE_MAX_ITEMS`/`_BYTES` 8×/4× moved the loss from 63 % to 70 %
   (reverted); splitting the client across 8 connections instead of 4 changed
   it by 0.005 %. Neither the stager caps nor per-connection headroom are the
   constraint.

### 13.6 What this does not establish

Loopback runs a 4-hop chain on one host and the harness itself burns 2.4 cores,
so the absolute pps numbers are not a capacity spec. What is portable is the
structure: a QUIC pass and at least one syscall per datagram on a single thread,
a receive-side buffer that drops silently, and no sender feedback. It is also
why the README's 8 × 1,000 pps × 128 B acceptance test passes at 0.000 % loss
while, on macOS, anything above ~35k pps degrades — the published test sits 5×
below that host's knee. On the Linux guest the same code held <0.1 % loss to
140k pps, which is the better evidence that the shape is sound and the ceiling
is the host's socket path.

Reproduce:

```sh
cargo build --release
./target/release/myquic2-server &
./target/release/examples/hotpath_bench echo 19000 &
# macOS: 8 x 10,000 -> 65-71 % loss; 8 x 5,000 is the ~40k knee.
# Linux: 8 x 15,000 -> 0.03 %; 8 x 20,000 -> 12 %, drops on the echo socket and
# on the proxy's app-facing sockets; the QUIC sockets (:8443, 8 MiB) show d=0.
./target/release/examples/hotpath_bench \
  udpmultipaced 127.0.0.1:1080 127.0.0.1:19000 8 10 128 10000
# macOS:
netstat -s -p udp | grep 'dropped due to full socket buffers'
# Linux (netstat may be absent): RcvbufErrors is the 6th field of the Udp: line
awk '/^Udp:/ {print $2, $6}' /proc/net/snmp
```

---

## 14. Eighth Batch: the DNS probe's hash, and a verdict that was not one (2026-11-01, post-bd791be)

Scope: `src/dns/**` only, plus one clock read on the server's slow path. No configuration values and no dependencies
changed. The two findings are independent: a hot-path cost that was ~2x too high for what it did, and a cache entry
that claimed more than the lookup behind it knew.

### 14.1 What the synchronous probe actually costs

`lookup_cached_fast` (`src/dns/resolve.rs:392-432` before this batch) is the datagram path's DNS answer: it builds the
per-`(host, port)` key on the stack, probes this thread's two-way memo, and returns the memoized address plus its
remaining life. It runs whenever the connection fast table's pin misses (`resolve_fast` → `resolve_pin`,
`src/bin/myquic2-server/accept.rs:707-725`, and `resolve_forward_target`, `src/bin/myquic2-server/forward.rs:413-452`);
a steady flow with a warm pin pays only `fast.probe_cached` + `is_global_ip_cached` and never reaches it. So the probe
is not the dominant per-packet cost — but it is the cost a *new* flow or a pin refresh pays, and it was paying for a
hash it did not need to pay that much for.

Everything in the probe is length-independent except the hash: `DnsMemoSlot::matches` compares the full key only on a
hash+length match, `dns_key` lowercases in place, `from_utf8` validates a stack prefix. The measurement (a
`examples/dns_probe_bench.rs` harness, 20M `black_box`ed calls, ns/op) separated the two:

| probe case | before | meaning |
|---|---|---|
| `coarse_millis()` alone | 0.97 | clock is not the problem |
| warm hit, 4-byte host | 15.24 | ~12 ns fixed overhead + ~3 ns hash |
| warm hit, mixed names (4–50 B) | 29.6 | |
| warm hit, 50-byte host | 40.81 | ~12 ns fixed + ~29 ns hash |
| cold miss (no clock read) | 21.78 | the hash is paid on a miss too |

The old hash (`src/dns/memo.rs:176-185`, `h = h*0x9e3779b97f4a7c15 + b` per byte, then two multiplies) is a serial
dependency chain: 4 cycles/byte, i.e. ~30 ns on a 50-byte name and nothing at all on a 4-byte one. It is the only term
that scales with the name.

### 14.2 The replacement: length-mixed, eight bytes at a time

`dns_memo_hash` (`src/dns/memo.rs:188-206`) now seeds with the length, folds eight-byte little-endian words with one
multiply each, packs the tail into one more word (a zero-padded tail needs its length mixed in, hence the seed), and
finishes with splitmix64:

```rust
let mut h = (bytes.len() as u64).wrapping_mul(K);
let (chunks, rem) = bytes.as_chunks::<8>();
for c in chunks { h = (h ^ u64::from_le_bytes(*c)).wrapping_mul(K); }
if !rem.is_empty() { /* zero-padded tail, one more fold */ }
h ^= h >> 30; h = h.wrapping_mul(0xbf58476d1ce4e5b9);
h ^= h >> 27; h = h.wrapping_mul(0x94d049bb133111eb); h ^ (h >> 31)
```

Replacing it is safe by construction: the hash is only a *filter* — `DnsMemoSlot::matches` still compares the full key,
so a collision costs a miss, never a wrong address — and every test that exercises the memo finds its same-set keys
dynamically through `dns_memo_set(dns_memo_hash(&k))`, so none of them asserts a concrete hash value. The two
properties the old function's doc called out were checked before landing:

- **set spread** — 200k names `host-{i}.example.com`: coefficient of variation of the 64 set loads 0.0182 → 0.0200
  (perfect is 0.0179), i.e. still even.
- **suffix correlation** — the reason the old finalizer existed (names sharing `….example.com` share their tail bytes):
  20k-name sets scored CV 0.0667 → 0.0485 for `.example.com` and 0.0569 → 0.0569 for `.cdn.net`. No regression.

`dns_memo_hash_spreads_sets_over_suffix_shared_names` (`src/lib.rs:1027`) pins the spread bound and that every byte of
the first 24 reaches the hash, which covers the tail-packing branch a name under eight bytes would otherwise skip.

### 14.3 Measured, interleaved

Both variants were prebuilt and the runs alternated (`old new new old old new`), because a single-machine run drifts by
~1.7x between sessions: the `coarse_millis()` control line read 0.97 ns/op in the first session and 1.66–1.86 ns/op in
this one, with unchanged code. Medians of three runs each, ns/op:

| probe case | old | new | delta |
|---|---|---|---|
| warm hit, mixed names | 51.14 | 30.71 | **−40 %** |
| warm hit, 50-byte host | 69.53 | 33.59 | **−52 %** |
| warm hit, 4-byte host | 27.07 | 22.70 | −16 % |
| cold miss (no clock read) | 39.33 | 24.10 | −39 % |
| negative hit | 44.29 | 33.55 | −24 % |
| `coarse_millis()` control | 1.84 | 1.66 | unchanged (noise) |

The control line is the point: the machine state was the same on both sides, so the delta belongs to the hash. The
short-name case gains least, as expected — a 4-byte key's hash was already two multiplies — and the cold miss gains
because the probe hashes the key whether the set lookup hits or misses.

Reproduce:

```sh
cargo run --release --example dns_probe_bench
# Interleaved A/B: build, copy the binary, stash src/, rebuild, copy, pop, then alternate the two binaries.
```

### 14.4 The logic defect: one TTL for two different claims

`resolve_all_cached` negatively caches a failed lookup so the datagram path can refuse a dead name without spawning a
resolver per packet — the comment there is explicit that the per-thread memo, not the slow-path semaphore, is what
bounds the *rate* of spawned lookups. The defect was that it treated every failure as the same claim. Before this batch
`record_negative` (`src/dns/resolve.rs:746-757`) wrote a 10 s host-keyed entry for **all** of them, including:

- the outer `DNS_LOOKUP_TIMEOUT` expiring — we stopped waiting; the resolver may still be fine and the name certainly is;
- `dns getaddrinfo fallback saturated (…)` — our own permit set was full, which says nothing about any name;
- a name server that is down or unreachable (a Wi-Fi roam, a VPN coming up, a paused laptop).

A name that resolves perfectly well could therefore be refused on every port for 10 s because one lookup hit a blip —
the cache was answering a question it had not asked. The obvious "just don't cache those" is wrong for the reason the
existing comment gives: with no entry at all, the per-datagram path re-spawns a resolver task per datagram during an
outage, and the semaphore only bounds how many run at once.

The fix splits the claim by what the lookup learned (`src/dns/resolve.rs:177-224`):

| failure | class | cached for |
|---|---|---|
| resolver answered `NoRecordsFound` (NXDOMAIN/NODATA) | `LookupFailure::Verdict` | `DNS_NEG_TTL` = 10 s |
| libc `getaddrinfo` failed on the fallback path | `Inconclusive` (see below) | `DNS_INCONCLUSIVE_TTL` = 1 s |
| outer timeout, fallback saturation, blocking-task panic | `Inconclusive` | `DNS_INCONCLUSIVE_TTL` = 1 s |
| hickory transport/protocol/timeout/`Busy` error | `Inconclusive` | `DNS_INCONCLUSIVE_TTL` = 1 s |

Classification is per-answer, not per-message: hickory 0.26's `NetError::is_no_records_found()` is the only predicate
that says "the resolver answered about this name" (`hickory_resolver::net::NetError`, re-exported, so no dependency was
added). The `getaddrinfo` fallback claims no verdict at all — libc gives no portable way to tell `EAI_NONAME` from
`EAI_AGAIN`, and that path only runs when hickory could not be built, which is the worst moment to guess.

Three mechanical consequences had to be handled together:

1. **The negative entry stores its deadline, not its insertion instant** (`src/dns/store.rs:127-136`). The cached
   remaining life is what another port of the same name memoizes, so a per-entry TTL is only expressible if the entry
   carries it; the cache's own 10 s moka TTL is now just an eviction bound above the per-entry deadline. The single
   reader (`src/dns/resolve.rs:612-628`) subtracts the entry's deadline from the clock instead of from a compile-time
   constant.
2. **An entry whose deadline has passed must not refuse anything.** It can still be resident (moka evicts lazily), so
   the probe checks the remaining life rather than the entry's presence and falls through to a fresh lookup. It is not
   removed on the way past: another thread may have just written a fresher refusal for the same name, and
   `try_get_with` single-flights the re-lookup anyway.
3. **The error text a caller sees is unchanged** except for the timeout, which now reads
   `dns lookup timed out after 5s` instead of `dns lookup timed out: deadline has elapsed` (nothing asserted on either).
   `LookupFailure` renders the same `{e:#}` chain the plain `anyhow::Error` did.

The asymmetry with the server's own gate is intentional and worth stating: `DNS_GATE_UNUSABLE_TTL_MS`
(`src/bin/myquic2-server/forward.rs:26-36`) is 5 s and therefore *longer* than the 1 s backoff. The gate is per target
and the negative entry is per name, so during a blip the target-level gate is what holds most datagrams off while the
host-wide entry stops refusing as soon as the resolver might be healthy again. Neither one can outlive the shared
entry's deadline for a *different* target, which is what the `resolve_all_cached` memoization preserves.

New tests, all deterministic (no network): `only_a_resolver_answer_is_cached_as_a_verdict`,
`an_inconclusive_failure_backs_off_briefly` (also pins that a second port inherits the entry's *remaining* life, not
the verdict TTL) and `an_expired_refusal_falls_through_to_a_fresh_lookup` (uses an IP literal, so the re-lookup runs
the real init path without an upstream query).

### 14.5 Examined and deliberately not changed

- **`resolve_forward_target`'s up-front clock read** (`src/bin/myquic2-server/forward.rs:413-452`): it called
  `coarse_millis()` before the memo probe, then the probe read the clock again on a hit. The probe already returns the
  remaining life, so only the session-memo fallbacks need "now"; they now read it inline. One fewer clock read on every
  slow-path datagram, and the probe's own read is unchanged.
- **`is_global_ip` at `accept.rs:2971` (`policy_resolved`), `forward.rs:629` (`deliver_resolved_server_dgram`) and
  `tcp.rs:321` (`dial_happy_eyeballs`)** stays uncached, unlike the packet path's `is_global_ip_cached`. Each of these
  runs once per resolution or per dial, and the fallback addresses are one-shot: filling the 64-slot direct-mapped
  packet-path cache with them would evict the hot entries it exists to serve. §4's rule ("`is_global_ip` only on a
  cache miss") is the right one, and these three sites are not misses on that path.
- **`upstream_resolver`'s process-lifetime `OnceLock`** (`src/dns/resolve.rs:364-390`) is a real limitation, not a bug
  this batch could fix: the resolver is built once from the platform's DNS configuration, so a nameserver change (VPN
  up/down, Wi-Fi roam, DHCP renewal) is never picked up, and every lookup keeps timing out against a dead server. The
  1 s backoff makes that state recover quickly *once the config changes*, but nothing re-reads the config. Fixing it
  needs a watcher (inotify on `/etc/resolv.conf`, `SystemConfiguration` dynamic-store notifications on macOS) and a
  swap of the resolver behind the same `OnceLock`, which is a separate design change; it is recorded here so the
  limitation is documented rather than implied.

### 14.6 Verification

`cargo fmt --all --check` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test --all-targets` **732 passed / 0 failed / 1 ignored** (lib 368, client 199, server 149,
`forward_e2e` 7, `rev3_e2e` 9).

### 14.7 What this does not establish

The probe numbers are a one-machine loopback microbenchmark of a pure function; they do not become a pps or p99 claim.
The end-to-end effect is bounded by how often the memo probe is on the hot path at all — a steady flow with a warm
fast-table pin never reaches it, so the gain shows up on new flows, pin refreshes and cache turns, not on a steady
`udpdomain` run. The §13 caveat applies unchanged: `hotpath_bench` is the instrument for end-to-end claims, and this
batch did not run it.

## 15. Ninth Batch: DNS latency — a retry budget that could not retry, a TTL cliff, and a dial that waited on its own stagger (2026-11-01, post-18d8ace)

The eighth batch made the DNS path cheap per packet. This one is about the per-*flow* latency that remains once the
probe is cheap: where a lookup has to happen at all, how long its worst case is, and how its answer is used. Three
findings, in the order of how much client-visible time they cost.

The starting point is that the obvious levers were already in place: A and AAAA are queried in parallel
(`LookupIpStrategy` defaults to `Ipv6AndIpv4`), nameservers are hedged (`num_concurrent_reqs` defaults to 2), and the
sync probe is ~30 ns. The remaining latency was not in the resolver; it was in three places around it.

### 15.1 B1 — the configured retries could never run

`hickory`'s `ResolverOpts` defaults are `timeout = 5 s` with `attempts = 2`, and `DNS_LOOKUP_TIMEOUT` is also 5 s. The
two budgets were the same number, so the first attempt was allowed to consume the whole wall and the retries the
resolver had been configured to make were dead code: one lost UDP datagram cost the client the full 5 s, and a name
server that would have answered on the second try never got a second try.

`attempts` is hickory's count of *additional* tries (`RetryDnsHandle`, `hickory-net-0.26.1/src/xfer/retry_dns_handle.rs`:
`NoRecordsFound`/`NoConnections` are not retried, `Busy` is retried without decrementing, everything else decrements
and re-sends). The budget is now derived from the wall instead of set beside it:

| constant | value | role |
| --- | --- | --- |
| `DNS_QUERY_TIMEOUT` (`src/dns/store.rs:178-179`) | 1.5 s | one attempt, retransmissions included |
| `DNS_LOOKUP_ATTEMPTS` (`src/dns/store.rs:180`) | 2 | extra attempts |
| `DNS_LOOKUP_TIMEOUT` (`src/dns/store.rs:161-162`) | 5 s | wall around the whole lookup, unchanged |

A `const _: () = assert!(...)` (`src/dns/store.rs:184-187`) now refuses to compile the pair if
`DNS_QUERY_TIMEOUT × (1 + DNS_LOOKUP_ATTEMPTS)` does not fit inside the wall, and
`hickory_response_cache_is_disabled_and_ttls_stay_bounded` pins both values plus that arithmetic. Worst case is
unchanged at 4.5 s of attempts inside a 5 s wall; the case that changed is a *dropped* query, which now recovers at
~1.5 s instead of failing at 5 s.

### 15.2 A1/A2 — serve-stale and refresh, so a TTL expiry is a repair instead of a stall

A positive entry lived exactly 120 s. One millisecond later the next datagram for that name had no answer to serve,
and `forward_server_dgram`'s domain arm *holds* the datagram while a resolution runs: one upstream RTT behind the
resolver's own upstream RTT, 10–50 ms on a good path and 100–300 ms over LTE/VPN — for an answer this process already
had a moment earlier. Nothing about the old answer was wrong, either: it is the address the previous datagram was sent
to.

The store now separates **freshness** from **residency** (`src/dns/store.rs:63-96`):

- `DNS_CACHE_TTL` (120 s) is the freshness deadline, unchanged, and is still what every layer above clamps against.
- `DNS_STALE_WINDOW` (1 h) is how long past it an entry may still answer — RFC 8767's model. The moka TTL is
  `TTL + window`, so the cache only evicts answers that cannot be served stale any more.
- `DNS_STALE_MEMO_TTL` (1 s) is what a *stale* hit is memoized for in the per-thread memo. Short on purpose: the memo
  is what lets the sync probe skip the async path, but the async path is the only place that can schedule a refresh,
  so the packet path must come back within a second rather than for the entry's whole remaining window.

`resolve_all_cached` serves the stale entry immediately and claims a refresh (`src/dns/resolve.rs:646-650`,
`request_refresh`/`refresh_positive` at `src/dns/resolve.rs:834-900`):

- one refresh per name at a time, process-wide (`RefreshClaim`, an `Arc<str>` in a `parking_lot::Mutex<HashSet>`,
  released by `Drop` so a cancelled task cannot wedge the name);
- background refreshes draw from **their own** permit pool (`DNS_REFRESH_PERMITS = 256`,
  `src/dns/resolve.rs:451-456`), never from `dns_slow_path_limiter`: a burst of expired entries must not consume the
  admission budget of the datagrams that have no answer at all. (The first draft reused the slow-path pool; the
  existing `slow_path_limiter_has_the_charged_permit_count` test caught it as a 1023-vs-1024 flake, which is the same
  signal admission accounting would have seen.)
- a failed refresh writes **no** negative entry: the name demonstrably resolves — we are serving its own previous
  answer — and a refusal would both flip the sync path's memo to `Negative` for a working name and break the
  positive/negative disjointness the caches are built on. The stale entry keeps serving and the next stale hit retries.
- a successful refresh replaces the entry with a fresh one, removes any negative entry and bumps the epoch, exactly
  like a foreground success. If a foreground resolution refreshed the entry while the background lookup was in flight,
  the background write is skipped so the insertion instant stays monotone.

The refresh path cannot use the positive cache's `try_get_with` single flight: a present (stale) entry is a *hit*, so
that call would hand back the stale value instead of running the init. That is why the claim set exists rather than a
second cache or a sentinel — one cache, one entry, one refresh.

### 15.3 C1 — the dial no longer waits on its own stagger

`dial_happy_eyeballs` (`src/bin/myquic2-server/tcp.rs:319-401`) used to delegate the race to `happy-eyeballs 0.2.1`,
which cost more than it saved:

- Its `tokio::connect` re-partitioned the address list v6-first and re-interleaved it, so a
  `dns_ip_preference = "ipv4"` deployment resolved v4-first and then raced v6-first — the preference stopped meaning
  anything on the wire.
- It held `CONNECTION_ATTEMPT_DELAY = 250 ms` as a hard-coded stagger and, after an attempt *failed*, kept waiting for
  the delay task (`Ok(Err(_)) => error.get_or_insert(e)` then continues). A refused or unroutable first candidate —
  which answers in microseconds — therefore cost every new TCP flow the full 250 ms before the second candidate was
  even tried. On a network that advertises AAAA but cannot route v6, that is more than the DNS lookup itself.

`race_dial` (`src/bin/myquic2-server/tcp.rs:372-401`) keeps the caller's order (which is the
`dns_ip_preference`-sorted, family-alternating list `handle_tcp_stream` builds) and starts the next candidate
**immediately when one fails**, keeping the 250 ms stagger only for candidates that have not been reached yet. The
single-candidate arm (every IP-literal flow) is unchanged: one direct connect under the same 4 s budget. The
dependency is gone (`Cargo.toml:182-186` records why), so the crate's re-interleaving cannot come back.

New tests (`src/bin/myquic2-server/tcp.rs:404-484`): `a_failed_attempt_advances_without_waiting_the_stagger` (refused
port first, live listener second: must connect and must not spend the stagger — the old code failed this by
construction), `the_first_candidate_to_accept_wins` (order is the caller's), `a_single_candidate_is_one_direct_connect`
(and a refused single candidate fails without the budget), `a_private_candidate_is_not_dialled_without_permission`
(the SSRF filter runs before any attempt, on both arms).

### 15.4 New tests for the stale path

All deterministic, no network (the seeded host is an IP literal, so the background re-resolve runs hickory's literal
path): `positive_life_splits_fresh_from_stale_at_the_ttl` (the boundary is the deadline, not the residency),
`a_stale_entry_is_served_and_refreshed` (served from the entry; the memo life is the stale life, not the TTL; the
entry's insertion instant moves only once the refresh lands), `a_fresh_entry_does_not_schedule_a_refresh` (eight fresh
hits leave the entry byte-identical).

### 15.5 Examined and deliberately not changed

- **A3, per-record TTLs** instead of the flat 120 s: the right long-term shape (a 300 s CDN record is re-resolved 2–5×
  more than needed, a 30 s record is over-cached), but it changes the value type of both caches and every clamp above
  them. Serve-stale removes the *latency* of a re-resolution, which is the part this batch was for; the query-rate part
  is a separate change.
- **A4, building the resolver at startup**: `upstream_resolver` is a `OnceLock`, so `builder_tokio()` runs inside the
  first lookup, synchronously on a tokio worker (the macOS SystemConfiguration read is ms-scale). Warming it from
  `spawn_blocking` at startup is a few lines, but it needs a startup hook the server binary does not currently have for
  DNS, and it does not touch steady-state latency.
- **B2, search-list RTTs**: hickory's `ndots` default and the resolv.conf search list make a single-label name walk the
  suffixes sequentially. A `ndots = 0`/FQDN mode for strict SOCKS semantics is a behaviour change (LAN short names stop
  resolving), not a pure win.
- **C2, no happy-eyeballs for UDP**: `forward_server_dgram` takes the first address that passes the filter and pins it
  for 30 s. A dead first address costs the application's retransmit timer, and `FlowBinding::resolved` already holds
  the whole list — but racing datagrams means duplicating sends, and per-datagram duplication is exactly the cost this
  design removed.
- **C3, parking concurrent datagrams on an in-flight resolution** instead of refusing them (DnsGate `InFlight`): the
  right fix, but it changes the gate's ownership model and needs a per-target broadcast, not a counter.
- **D1, resolving in parallel with the first QUIC packet** (client-side hint): a wire change (rev4), and it trades
  split-horizon/VPN correctness for one RTT.

### 15.6 Verification

`cargo fmt --all --check` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test --all-targets` **739 passed / 0 failed / 1 ignored** (lib 371, client 199, server 153, `forward_e2e` 7,
`rev3_e2e` 9).

### 15.7 What this does not establish

The stale-path and retry changes are verified by behaviour, not by a latency microbenchmark: the stale hit's cost is a
moka hit, a mutex-guarded claim and one task spawn, and the path it replaces is bounded below by one upstream query
RTT, so the direction is unambiguous but the milliseconds are field numbers. Serve-stale also does not make a *wrong*
answer diagnosable from the outside: a stale answer is indistinguishable from a fresh one at the API. The instrument
for end-to-end p50/p99 remains `hotpath_bench udpdomain` (the only mode that exercises the relay DNS path), which this
batch did not run; `examples/dns_probe_bench.rs` measures the probe function only and is unaffected by this batch.

## 16. Tenth Batch: the reconnect that re-resolved, the resolver that never noticed, and a TTL nobody read (2026-11-01, post-192dede)

§15 removed the retry-budget dead end, the TTL cliff and the dial stagger. This batch is the second pass over the same
axis — *does the lookup have to happen at all, how long is its worst case, and how is the answer used* — and it starts
with the two places where the answer was "the lookup happens again, for no reason".

### 16.1 The client re-resolved its own server endpoint on every reconnect (item 1)

`spawn_conn_loop` called `resolve_server_addr` on every iteration of its reconnect loop, and that function was the
*uncached* path: `resolve_all_timeout` (`src/dns/resolve.rs`), i.e. a fresh upstream query — or a full
`DNS_LOOKUP_TIMEOUT` — in front of every redial, on a path that by design retries for as long as the server is away.
It then returned `v.into_iter().next()`, one address, and `dial_once` used only that one with a 5 s attempt budget.

Two failures follow from that shape:

- A network where the AAAA record is present but IPv6 is unroutable (a v4-only uplink, a VPN that captures v6) makes
  the preferred address a permanent dead end: every reconnect re-races the same address, and the address that would
  work is never tried at all.
- The reconnect latency floor becomes one DNS RTT *plus* the backoff, even though the answer had not changed.

The fix is `resolve_server_addrs(s, max)` (`src/dns/resolve.rs:1299`): the shared positive cache's path
(single-flight, serve-stale, negative verdicts), the caller's port attached, preference order preserved, capped at
`DIAL_ADDR_CANDIDATES = 3` (`src/bin/myquic2-client/auth.rs:65`). `resolve_server_addr` is now that function with
`max = 1`, so the two cannot drift.

The dial side (`src/bin/myquic2-client/auth.rs:349` and `:370`) remembers the address that carried the previous
connection (`prefer_last_good`, promoted to the front, rest of the order untouched) and tries the candidates in order,
falling through on failure (`dial_candidates`, each failure logged at debug, the last error returned so the
iteration's `warn!` still names the reason). One dead first address now costs one attempt, not the whole iteration.

What it does not do: parallel racing of the candidates (the TCP path's `race_dial` does that, but a QUIC handshake
race needs one endpoint per attempt and the client's endpoint is shared), and the address hint of item 7, which needs
a wire revision.

### 16.2 The resolver was built once and never looked at the network again (item 2)

`upstream_resolver()` was a process-lifetime `OnceLock` built lazily inside the first lookup, from the platform's DNS
configuration *as it was then*. A laptop that joins a VPN, changes Wi-Fi, or gets a new DHCP lease keeps pointing at
the previous network's nameservers for the life of the process. Every cold name then burns the whole attempt budget
(`DNS_QUERY_TIMEOUT x 3`) against a server it cannot reach, and serve-stale only hides that for the hour its window
lasts — after which resolution for *new* names simply stops working until the process restarts.

The resolver is now a swappable generation (`src/dns/resolve.rs:426`-`:600`):

- `build_resolver_gen()` reads `hickory_resolver::system_conf::read_system_conf()` itself, builds
  `TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())`, applies
  [`configure_resolver_options`] and records a **fingerprint** of the configuration (nameserver IPs, domain, search
  list, lowercased) alongside it. `Err` remains the "use `getaddrinfo`" signal for the fallback.
- `resolver_gen()` holds the current generation in an `ArcSwap`, and `upstream_resolver()` hands out an `Arc` clone:
  a lookup in flight across a swap keeps its old resolver alive to completion, and the swap itself is a single atomic.
- `spawn_resolver_watch()` is called at startup by both binaries (`src/bin/myquic2-server/main.rs:103`,
  `src/bin/myquic2-client/main.rs:179`). It warms the generation in `spawn_blocking` — the first lookup no longer
  reads SystemConfiguration/resolv.conf on a runtime worker — and then polls the platform configuration every
  `RESOLVER_CONFIG_POLL = 30 s` (`src/dns/resolve.rs:426`), rebuilding only when the fingerprint moved. Both the read
  and the rebuild run off-runtime.

30 s is the compromise: a VPN coming up is picked up before the stale window it would otherwise hide behind, and the
steady-state cost is one small file read (Linux/OpenWrt) or one dynamic-store query (macOS) per half minute.

The `gen` identifier is a reserved keyword in edition 2024; the first build of this failed with
`error: expected identifier, found reserved keyword 'gen'`. Worth remembering when naming anything
generation-shaped in this crate.

### 16.3 The stale path was pacing itself at request rate (item 4, correcting §15.2)

§15's serve-stale memoized a stale answer for `DNS_STALE_MEMO_TTL = 1 s`, which "lets the packet path keep answering
it while still returning to `resolve_all_cached` once a second". That is the *repair* latency, and it was fine. What
was not fine: the same one-second expiry also paced the **retries**, because a failed refresh released its in-flight
claim immediately — so with upstream DNS down, every stale flow asked for a refresh once a second, each of those
became a fresh attempt against the failing server, and each attempt also cost a waiter task, a
`dns_slow_path_limiter` permit and a moka probe. The admission budget that exists to bound flows with no answer was
being spent on flows that already had one.

Two changes (`src/dns/resolve.rs:1030`-`:1070`, `src/dns/store.rs:120`):

- `DNS_REFRESH_COOLDOWN = 5 s`, tracked per name in a `HashMap<Arc<str>, Instant>` ("do not start a refresh before
  this instant"). The claim reserves its own slot for `DNS_LOOKUP_TIMEOUT + cooldown` while the task runs, and its
  `Drop` rewrites that to `now + cooldown`, so a cancelled or panicked task cannot wedge a name and a failing one is
  retried on a fixed schedule rather than at request rate. The map is pruned on insertion and refuses to exceed
  `DNS_CACHE_MAX` entries — it is keyed by name, so it is the one structure here that could otherwise grow forever.
- `DNS_STALE_MEMO_TTL` becomes 5 s, and `materialize_cached` clamps it to the entry's own remaining residency
  (`deadline + DNS_STALE_WINDOW`), so the memo can never outlive the store.

Net effect per active stale flow: one async re-entry per 5 s instead of per second, and one upstream attempt per name
per 5 s instead of per second *per flow*.

### 16.4 The freshness window was a constant, not the answer's TTL (item 5)

The positive cache stored `inserted_at` and treated `inserted_at + DNS_CACHE_TTL` (120 s) as freshness. Both
directions were wrong, and one of them was a correctness issue:

- A name whose TTL is 30 s was served as *fresh* for 120 s — four times longer than its owner allowed, with no refresh
  scheduled because the entry still looked current.
- A name whose TTL is 300 s was re-resolved every 120 s — 2.5x the upstream traffic its owner asked for, each
  re-resolution a chance to wait on a cold lookup.

The store now holds `(freshness deadline, address set)` (`src/dns/store.rs:56`), and the deadline is the answer's own
TTL (`Lookup::valid_until`, the minimum over the returned records), clamped by `record_ttl`
(`src/dns/resolve.rs:790`) to `DNS_RECORD_TTL_MIN = 10 s` .. `DNS_RECORD_TTL_MAX = 300 s`
(`src/dns/store.rs:79`, `:87`). The floor keeps a zero-TTL record from turning every datagram into a lookup; the
ceiling is the conventional one and bounds how long a moved CDN endpoint can be served from a 24 h record.

Two consequences worth naming:

- `configure_resolver_options` had to raise hickory's `positive_max_ttl` from `DNS_CACHE_TTL` (120 s) to
  `DNS_RECORD_TTL_MAX`. hickory clamps **every** answer's TTL to that window even with its cache disabled
  (`ResponseCache::clamp_positive_ttls` rewrites the TTLs before the `Lookup` is built), so the old value would have
  silently capped the whole feature at 120 s.
- `DNS_CACHE_TTL` did not disappear: it is now the *default* for answers that carry no TTL at all (the `getaddrinfo`
  fallback, which reports none). The seeds in the tests describe entries the production path would have written with
  that default, so `dns_cache_seed_aged(host, port, addr, age)` derives the deadline as `now + DNS_CACHE_TTL - age`.

The freshness/staleness split itself is unchanged: past the deadline an entry is served and refreshed (RFC 8767),
inside the window it is served and nothing else happens.

### 16.5 A dotted target is a fully qualified name (item 6)

hickory applies the resolv.conf search list after a failed bare-name query, one serial round trip per suffix. For a
SOCKS target that is never what was meant: `no-such-host.example.com` should not be retried as
`no-such-host.example.com.corp.example`, and on a slow or lossy link those extra round trips are exactly what the
negative verdict is supposed to make rare.

`query_name` (`src/dns/resolve.rs:253`) returns the target with a trailing dot when it already contains a dot, and
leaves single-label targets alone — `intranet` still walks the search list, which is the only way a short LAN name
resolves at all. IP literals are excluded explicitly: `lookup_ip` short-circuits them before parsing, and a trailing
dot would make the literal unparseable. The hosts file still matches: `Hosts::lookup_static_host` compares against
fully-qualified keys.

The trade-off, stated plainly: a dotted LAN name that used to resolve *through* a search suffix
(`printer.office` + `corp.example`) now resolves only as the literal `printer.office.`. That is the behaviour a
strict SOCKS target implies, but it is a behaviour change, and a user who relied on search-suffix completion for a
dotted short name would need the full name.

### 16.6 Examined and deliberately not changed

- **Parking datagrams on an in-flight resolution (item 3).** The gate still answers `GateClaim::InFlight` by dropping
  the datagram, so the second and third datagram of a cold name wait for the app's own retransmit. Parking them would
  remove that wait, but it needs somewhere to keep the payloads: a bounded per-entry queue, a memory term in the
  `dns_inflight_memory_bytes` accounting that admission charges, and a flush/cancel lifecycle tied to the waiter. That
  is a memory-bound redesign of the relay's most contended path, not a latency tweak, and it changes the drop
  semantics the refusal counters describe. Deferred deliberately; it is the largest remaining item.
- **Client address hint on the wire (item 7).** Still the biggest structural win (the DNS lookup overlaps the QUIC
  handshake instead of preceding it) and still a wire revision: it needs a hint field in the Hello, a server-side
  policy for trusting it, and a split-horizon/VPN answer for when the client's view and the server's view disagree.
- **UDP happy eyeballs (item 8).** With no failure signal from the app, the relay would be racing addresses blind and
  spending packets on the losing ones. Documented, not implemented.
- **Throughput-only leftovers**: the 261-byte key-buffer memset and the 64-slot `is_global_ip_cached` are irrelevant to
  latency and were left alone.

### 16.7 Verification

`cargo fmt --all --check` clean; `cargo clippy --all-targets -- -D warnings` clean; `cargo test --all-targets`
**743 passed, 0 failed, 1 ignored** (lib 374, client 200, server 153, `tests/forward_e2e.rs` 7, `tests/rev3_e2e.rs` 9).

New tests, all behavioural rather than mock-based:

- `src/dns/resolve.rs`: `the_resolver_fingerprint_tracks_nameservers_and_search` (a changed nameserver or search list
  is a new generation, an unchanged config is not), `a_failed_refresh_is_cooled_down_per_name` (in-flight blocks a
  second attempt, the cooldown outlives the attempt, the name becomes claimable again only after it),
  `the_freshness_window_is_the_answers_own_ttl_clamped` (floor, cap, pass-through, zero), plus the renamed
  `positive_life_splits_fresh_from_stale_at_the_deadline`.
- `src/bin/myquic2-client/tests.rs`: `dial_candidates_prefer_the_last_good_address` (no hint keeps order, hint first is
  a no-op, hint promoted with the rest stable, stale hint ignored).

### 16.8 What this does not establish

There is still no latency microbenchmark for any of this. The numbers here are structural — the reconnect path lost one
uncached lookup and gained a candidate list, the resolver gained a 30 s re-read, the stale path lost four of five
async re-entries per second, and the TTL now follows the record — and the only honest end-to-end instrument remains
`hotpath_bench udpdomain`, which this batch did not run. Serve-stale and the new refresh cooldown also make the
*diagnosis* of a slow lookup harder from the outside: a stale answer is indistinguishable from a fresh one at the API,
and a refresh that is being cooled down looks exactly like one that is running.

### 16.9 Review of this batch: the attempt budget I split and then re-multiplied

A read-only review of `fad78a8` against every invariant the batch claims found one
real defect and five stale comments. The defect is mine, from item 1.

`dial_candidates` (`src/bin/myquic2-client/auth.rs:401`) walks up to
`DIAL_ADDR_CANDIDATES` = 3 addresses in sequence, and each `dial_once` enforced
`t0 + DIAL_ATTEMPT_TIMEOUT`. One reconnect iteration could therefore hold the
loop — and the pool's dead generation — for 3 × 5 s. That is the exact
arithmetic `DIAL_ATTEMPT_TIMEOUT`'s own doc rejects: it exists because "without an
explicit bound a dead path costs ~15 s per attempt". Item 1 fixed the case where
a dead first address never gave way; it reintroduced the 15 s worst case for the
case where all candidates hang.

The fix keeps the iteration's wall bounded by sharing it:

```rust
fn attempt_budget(candidates: usize) -> Duration {
    (DIAL_ATTEMPT_TIMEOUT / candidates.max(1) as u32).max(DIAL_MIN_ATTEMPT)
}
```

so one address (the common case) still gets the whole 5 s, two get 2.5 s each,
and three stop at `DIAL_MIN_ATTEMPT` = 2 s — a 6 s worst case instead of 15 s,
with every slice still long enough for a full handshake on a high-RTT link.
`dial_once` now takes the budget explicitly instead of reading the constant, and
`attempt_budget_is_shared_by_the_candidates` pins the split (1 → 5 s, 2 → 2.5 s,
3 → 2 s, wall ≤ 6 s).

The comment corrections, all consequences of item 5 replacing the flat TTL with
a per-record deadline:

- `PosCache`'s doc still described the value as an insertion instant
  (`src/dns/store.rs:217`); it is the freshness deadline, and the cache's own TTL
  is `DNS_RECORD_TTL_MAX + DNS_STALE_WINDOW`.
- `materialize_cached`'s "comes back within a second"
  (`src/dns/resolve.rs:1003`) predates `DNS_STALE_MEMO_TTL` being retuned to 5 s.
- `CachedLookup`'s variants still said "a fresh address"/"a fresh negative
  entry"; a stale answer is memoized too, with the short stale life, and the
  negative life is the refusal's backoff, not a fixed window.
- `upstream_resolver`'s doc argued that clamping hickory's TTLs had been
  abandoned because the two layers were independent stores. That is still why
  hickory's *cache* is disabled, but the clamp itself is now back on purpose at
  `DNS_RECORD_TTL_MAX`: hickory rewrites every returned answer's TTL even with
  `cache_size = 0`, so the clamp has to be the store's own ceiling or the store
  can never see a TTL above it. The paragraph now states the current
  arrangement instead of the rejected one.

Checked and left alone: `materialize_cached`'s `saturating_duration_since` before
the `.min(DNS_STALE_MEMO_TTL)` (no panic if the clock passes eviction),
`seed_positive`'s `checked_sub`, `refresh_positive` writing neither a negative
entry nor an overwrite of an already-fresh entry, `RefreshClaim::Drop`'s cooldown
after cancellation, `claim_refresh`'s bound, and the store's moka TTL being
always ≥ any entry's `deadline + DNS_STALE_WINDOW`.

One dependency behaviour was verified rather than assumed, because item 6's FQDN
rewrite could have broken `/etc/hosts`: `Hosts::insert` sets `set_fqdn(true)` on
every stored name (`hickory-resolver-0.26.3/src/hosts.rs:114-117`),
`lookup_static_host` sets it on the query name too (`hosts.rs:60-66`), and
`impl Hash for Name` includes `is_fqdn`
(`hickory-proto-0.26.3/src/rr/domain/name.rs:1127-1136`) — so `host` and `host.`
hit the same hosts entry and the trailing dot cannot defeat an override.

Verification after the fixes: `cargo fmt --all --check` clean,
`cargo clippy --all-targets -- -D warnings` clean, `cargo test --all-targets`
744 passed / 0 failed / 1 ignored (the extra test is the attempt-budget one).

### 16.10 Review round two: the disjointness the refresh could break

Round two reviewed the whole series (`bd791be..c67e9ed`: `18d8ace`, `192dede`,
`fad78a8`, `c67e9ed` — 18 files, +2304/−257) rather than one batch, because the
batches interact. One real defect, one missing test and two cosmetic items came
out of it.

**The defect.** §16.4's positive/negative split rests on a single-flight
argument: a foreground resolution only runs when the positive entry is *absent*,
so its refusal can never coexist with a live answer. `refresh_positive`
(`src/dns/resolve.rs:1126`) deliberately bypasses `try_get_with` — it must, or
the present stale entry would be handed back instead of re-resolved — and writes
with a plain `insert`. So it is not single-flighted against a foreground init.
The window is narrow (the entry has to be evicted by moka capacity pressure, i.e.
absent at the same instant a refresh is in flight) but the outcome is exactly
the state the split forbids: both stores hold a live entry for the name. The warm
arm keeps serving the answer, so nothing looks wrong until that answer ages out —
then the negative probe refuses a name that resolves, on every port, and this
thread's memo was tagged `Negative`.

The repair cannot live in `record_refusal`: that runs inside the init future, and
moka holds the key's single-flight for the init's whole duration, so a
`positives().get(..)` from inside it waits for itself. It is therefore a
post-init step, `withdraw_refusal_if_answered`
(`src/dns/resolve.rs:1316`), called from `resolve_all_cached`'s `Err` arm once
the single-flight has been released: a *fresh* positive means the refusal is
stale by construction, so it is removed (bumping `NEG_EPOCH` when it was there, so
other threads' negative memos stop trusting it) and this thread's memo is
rewritten with the live answer so the packet path agrees with the store. Covered
by `a_refusal_is_withdrawn_when_a_refresh_answered_first`, which seeds the exact
coexisting state, calls the helper, and asserts both the store and the memo flip
back.

**The missing test.** `query_name` (`src/dns/resolve.rs:250`) — item 6's FQDN
rewrite — had no test at all. `query_name_makes_dotted_targets_fully_qualified`
now pins the four cases that matter: a dotted name gains the dot, an FQDN is left
alone, a single label keeps the search list, and IP literals (`192.0.2.7`, `::1`,
`[::1]`) are untouched.

**Cosmetics.** `refresh_positive`'s comment claimed it would "prefer the newer
answer and keep the insertion instant monotone"; the freshness check and the
insert are not atomic, so a foreground write landing between them can be replaced
by this older answer. Both are valid answers and the deadline only moves earlier,
so it is now documented as best effort instead of asserted as a property. And a
dead `let _written = memo_put_with_epoch(..)` binding in the negative branch
became `let _ =`.

**Verified rather than changed.** `LookupFailure::from_resolver`'s predicate is
correct: `is_no_records_found()` is `matches!(self, Self::Dns(DnsError::NoRecordsFound { .. }))`
(`hickory-net-0.26.3/src/error.rs:177-184`), which covers NXDOMAIN (the
`NoRecordsFound` carrying `ResponseCode::NXDomain` that `is_nx_domain` singles
out) and NODATA, while `Timeout`/`Io`/`Proto`/`Busy`/`NoConnections` stay
inconclusive — so only an answer is cached as a verdict. `race_dial`
(`src/bin/myquic2-server/tcp.rs:372`) is sound: the `biased;` select polls
completions first, a failed attempt falls straight through to spawning the next
candidate, the `else` arm is only reachable once every candidate was spawned and
every attempt finished, and returning drops the `JoinSet`, cancelling survivors.
`spawn_resolver_watch` (`src/dns/resolve.rs:536`) `continue`s on a transient
`read_system_conf` failure instead of swapping in an error generation; its
fingerprint covers nameservers, domain and search, not `ResolverOpts` (a `ndots`
change alone would not rebuild — acceptable, and now stated). The stale memo life
is always `≤ (deadline + DNS_STALE_WINDOW)`, and moka's positive TTL is
`DNS_RECORD_TTL_MAX + DNS_STALE_WINDOW` (3900 s), so the stale window can never
outlive the store. `DNS_GATE_UNUSABLE_TTL_MS` (5 s) deliberately exceeds
`DNS_INCONCLUSIVE_TTL` (1 s): the gate is per target, so it can afford to wait out
a blip where the store must not refuse every port for that long. README's cache
row and both Mermaid nodes, the `Cargo.toml` comment left in place of the
`happy-eyeballs` dependency, and `examples/dns_probe_bench.rs` all match the code.

Verification after the fixes: `cargo fmt --all --check` clean,
`cargo clippy --all-targets -- -D warnings` clean, `cargo test --all-targets`
746 passed / 0 failed / 1 ignored (two tests added by this round).

## 17. Eleventh Batch: measuring the DNS path, and the small cliffs around it (2026-11-01, post-ef4922b)

Every DNS optimization so far was justified by a mechanism — a warm hit never
touches the network, a stale hit answers while a refresh runs, a refusal answers
from the negative cache — and none of it was *visible*: the 60 s lines counted
datagrams and drops, not how a name was resolved, and there was no p50/p99 of
resolution latency anywhere. That makes the next decision (park datagrams behind
an in-flight resolution, or add an address hint to the wire) a guess about which
cost dominates. So this batch adds the instrument first, then the three small
items that needed no decision.

### 17.1 The instrument: resolution classes and two histograms

`src/dns/stats.rs` is a small module of process-global relaxed atomics. It counts
what the async path did — `fresh`, `stale`, `refused`, `cold`, plus failures
split into `verdict` and `inconclusive`, and background refreshes as
`started`/`ok`/`failed` — and times two things a user actually waits on:

| Histogram | Start | End | What it answers |
|---|---|---|---|
| `lookup` | `resolve_ips` entry (`src/dns/resolve.rs:312`) | answer, both arms, fallback included | how long one upstream resolution took |
| `waiter` | just before the gated `tokio::spawn` (`src/bin/myquic2-server/forward.rs:594`) | socket hand-off (`src/bin/myquic2-server/forward.rs:610`) | how long a *datagram* waited for a cold name |

Both are 16 log-scale buckets from 250 µs to 4 s plus a catch-all
(`src/dns/stats.rs:28`), because the interesting distinction is
"sub-millisecond cache work" versus "one to four seconds of upstream failure",
not 3 ms versus 4 ms. A percentile reports the *upper bound* of its bucket, so
the line reads "p99 is at most this" — which is what a timeout budget needs.

The counters are bumped where the class is decided, one relaxed `fetch_add` on a
path that already pays a resolution: the warm arm distinguishes fresh from stale
before it requests a refresh (`src/dns/resolve.rs:954`), the negative arm counts
before it bails (`:996`), the `try_get_with` init future counts a resolution it
actually started (`:1012`, which is why "cold" counts resolutions rather than
callers), and the failure arm splits verdict from backoff (`:1053`). Background
work counts what it *started* — after the refresh permit, not at the claim
(`:1254`) — so the line cannot report refreshes that never ran.

The reporter prints one line for the interval, and only when something moved
(`src/bin/myquic2-server/reporter.rs:239`):

```
dns (60s): 412 fresh, 6 stale, 2 refused, 3 cold (1 verdict, 2 inconclusive),
           6 refresh (4 ok, 2 failed); lookup n=3 p50<=8.0ms p99<=128.0ms max=141.2ms;
           waiter n=3 p50<=8.0ms p99<=128.0ms max=141.9ms
```

The `waiter` histogram is the number to decide the next two items with: if its
p99 sits near `lookup`'s p99, parking datagrams behind the in-flight resolution
buys real time; if it sits near p50 of a warm hit, the datagram is mostly waiting
for the app's own retransmit, which is a different fix. `examples/dns_probe_bench.rs`
still measures only the sync probe and says nothing about either.

### 17.2 The gate learned the failure's class

`DNS_GATE_UNUSABLE_TTL_MS` was one flat 5 s window for every refusal, while the
store behind it refuses for 10 s (a verdict) or 1 s (an inconclusive backoff).
So an application retransmitting 1.2 s after a transient timeout was dropped by
the gate for a name the shared cache would already have re-resolved, and — in
the other direction — a verdict's 10 s was cut to 5 s, spawning a wasted lookup
halfway through.

`resolve_all_cached` now returns `DnsFailure` (message + `retry_ttl`,
`src/dns/resolve.rs:250`) instead of a bare `anyhow::Error`: the refusal's own
class travels with the error, `deliver_resolved_server_dgram` returns
`Option<Duration>` (`src/bin/myquic2-server/forward.rs:641`) and `DnsGate::finish`
takes that option (`:307`), so the gate mirrors exactly what the store decided.
The flat window survives only for the one refusal the DNS layer never sees: the
resolver answered and every record was filtered by the egress policy
(`gate_ttl_ms`, `src/bin/myquic2-server/forward.rs:48`). A cancelled waiter still
reports `None` — "not a DNS verdict" — so a close never caches anything.

### 17.3 The resolver follows the network in 5 s, not 30

`RESOLVER_CONFIG_POLL` was 30 s. The read it paces is a `stat` plus a parse
(`resolv.conf`) or one System Configuration query (macOS), so 30 s bought nothing
but a window in which a VPN coming up left cold names pointed at dead
nameservers — serve-stale only hides that for names already answered. It is now
5 s (`src/dns/resolve.rs:483`), which bounds the exposure to the first retry an
application would make anyway. Platform change notifications would be tighter
still and need a dependency per platform for a window this small; that is stated
in the constant's doc rather than left implicit.

### 17.4 The client resolves its own endpoint before it needs it

The client re-resolves `server_addr` on every reconnect (cached, three
candidates, `last_good` first), but the *first* connect still found an empty
cache unless the operator's timing was lucky. `client_main` now spawns one
`resolve_server_addrs(.., DIAL_ADDR_CANDIDATES)` right after
`spawn_resolver_watch()` (`src/bin/myquic2-client/main.rs:188`), detached and
only for a non-literal endpoint, so the first reconnect pays a cache hit instead
of a lookup. `DIAL_ADDR_CANDIDATES` moved from a task-local constant to a module
one (`src/bin/myquic2-client/auth.rs:50`) so both paths ask for the same list.

### 17.5 The hosts file the poll could not see

The generation fingerprint covered nameservers, domain and search list — not
`/etc/hosts`, whose table is built *with* the generation. A local override (the
usual way to pin an internal name) therefore never took effect until restart,
and the 30 s→5 s poll would not have changed that. The fingerprint now appends
the hosts file's mtime and length (`hosts_fingerprint`,
`src/dns/resolve.rs:541`; `generation_fingerprint`, `:565`), so an edit rebuilds
the generation on the next tick. Metadata rather than a content hash: the file
is re-read only when it actually changed, and a same-length rewrite moves the
mtime. Non-Unix platforms return an empty entry — hickory reads the platform's
own database there, which has no single path to stat.

### 17.6 Verification

`cargo fmt --all --check` clean, `cargo clippy --all-targets -- -D warnings`
clean, `cargo test --all-targets` **754 passed / 0 failed / 1 ignored**
(lib 382, client 201, server 155 + 1 ignored, `forward_e2e` 7, `rev3_e2e` 9).
New tests: four for the histogram/line itself (bucket bounds, the catch-all
bucket, interval subtraction, the line naming every class and skipping empty
histograms), `dns_gate_refusal_window_follows_the_failure_class`
(`src/bin/myquic2-server/tests.rs:3689`) pinning the 1 s/10 s/5 s split,
`the_generation_fingerprint_covers_the_hosts_file`
(`src/dns/resolve.rs:1834`), and an assertion in the existing
negative-cache test that the returned `DnsFailure` carries the verdict's
remaining life.

### 17.7 What this does not establish

The histograms are observational, not a benchmark: no before/after, no load
sweep, and the buckets are coarse by design. Nothing here shows that parking
datagrams (§16.6's deferred item 3) would help — that is exactly what the
`waiter` line is now for, and the decision is waiting on numbers from
`hotpath_bench udpdomain` rather than on another mechanism argument. The
resolver poll still cannot see a change that leaves nameservers, search list and
hosts file identical but changes resolver *options*; that is documented at the
fingerprint rather than fixed.

## 18. Twelfth Batch: a routing verdict, parked followers, and four reasons a cached answer outlives its truth (2026-11-01, post-44f5081)

The eleventh batch built the instrument; this one acts on what it measures and on
the review of that batch. Five of the six items are behavioural — each removes a
case where the DNS layer knows something that the datagram path then throws away:
the kernel saying "no route", the answer naming several addresses, a filtered
verdict that cannot change while its answer is cached, a client retrying an
address list built before the network moved, a truncated answer served as if it
were complete. The sixth is the instrument itself: the line printed a lifetime
maximum where it promised an interval one.

### 18.1 A `sendto` routing error is a verdict, not packet loss

`deliver_resolved_server_dgram` used to take the first policy-allowed record and
send once. On a network that advertises AAAA without a working IPv6 route — the
common shape of a broken dual-stack network — that first address is unroutable,
`sendto` fails immediately with `ENETUNREACH`, and the failure is booked as
`udp_write failed` exactly like a full socket. Nothing noticed that the same
answer held an address that worked, and the session memo kept the dead one for
its whole life.

`udp_try_send_or_return` (`src/udp/retry.rs:250`) is the new primitive: it books
the failure as before and hands the payload back with the error kind, so a caller
that owns a *record set* can try the next address. `udp_try_send` is now a thin
wrapper (`let _ = udp_try_send_or_return(..)`), so every existing caller keeps
its behaviour and its accounting.

The delivery path walks the allowed addresses in preference order
(`src/bin/myquic2-server/forward.rs:918`) and stops at the first the kernel
accepted; a routing error (`NetworkUnreachable | HostUnreachable |
AddrNotAvailable`) condemns that address in a thread-local, direct-mapped hint
(`mark_unreachable`, `:561`, 16 slots, 10 s) and the loop continues. When a later
address wins, it is written to the session destination memo and the reply
allowlist (`sess_dest_store` + `remember_dst`), so the *next* datagram is answered
inline by `resolve_forward_target` and the pin armed from it carries the address
that works. `resolve_forward_target` now treats a recently unroutable address as
a miss (`:527`), which is what routes that next datagram through the waiter
instead of repeating the failure forever.

Three deliberate limits. The first candidate is always tried, because the hint is
a ten-second memory and not a fact; only later candidates are skipped. The staged
burst path cannot retry per datagram (it groups frames for one `sendmmsg` pass),
so it only records the verdict and lets the next datagram repair — documented at
the call site. And the hint is advisory in one direction only: it can make the
gate deliver to a second address from the same answer, never to an address the
egress policy filtered, and "no allowed address" still fails closed.

### 18.2 Followers wait instead of being dropped

The gate's whole purpose is one waiter per `(session, name, port)`, and the
datagrams that arrived during the flight were dropped — ordinary UDP loss, but a
loss the application pays for with its own retransmit timer (200 ms on a QUIC
PTO, ~1 s on a TCP-style RTO) for a name that was already being resolved. That is
the case the `waiter` histogram was added for.

`DnsGate::park` (`src/bin/myquic2-server/forward.rs:389`) stores a follower in
the live in-flight entry, bounded by `DNS_GATE_PARK_ITEMS` (4 datagrams) and
`DNS_GATE_PARK_BYTES` (8 KiB) per claim. When the answer lands, the waiter takes
them in arrival order (`take_parked`, `:424`) and sends each through
`deliver_resolved_server_dgram` — the session, memo and allowlist are already
warm, so each is one DATAGRAM send — bumping `dns::stats::parked_delivered()`.
Anything still parked when the claim completes without an answer (a verdict, a
cancelled waiter, an evicted slot) is counted as `dgram_drops::REFUSED` per
datagram in `finish` (`:462`), so a parked datagram is never silently discarded.

The memory is charged, not hand-waved: a parked set only exists while its claim's
waiter holds a slow-path permit, so `dns_inflight_memory_bytes`
(`src/config/tuning.rs:663`) counts one `DNS_WAITER_PARK_BYTES` (8 KiB) per
permit — at most 8 MiB process-wide at the 1,024-permit cap. Overflow and the
`Unusable` arm keep the old refuse-and-count behaviour, and the line now reports
`{parked} parked ({parked_delivered} delivered)`.

### 18.3 A filtered verdict lasts as long as its answer

`DNS_GATE_UNUSABLE_TTL_MS` was a flat 5 s window for the one refusal the DNS
layer never sees: the resolver answered, but every record was filtered by the
egress policy. That verdict is a property of the *answer* — the same records,
filtered by the same policy — so it cannot change while the answer is cached, and
5 s re-spawned the same doomed resolution up to twenty-four times over one
300 s-cached answer.

`filtered_ttl_ms` (`src/bin/myquic2-server/forward.rs:82`) returns the entry's
remaining life, capped by `DNS_GATE_FILTERED_TTL_MS` (60 s) so one name cannot
hold a gate slot indefinitely; a memo miss falls back to the fresh-answer bound.
A fresh resolution re-decides either way, which is what keeps the window honest.

### 18.4 The client's second failure

The reconnect loop reads `resolve_server_addrs` every iteration, which is right
while the cache holds a live answer. But a positive entry is served for up to
`DNS_STALE_WINDOW` (1 h) past its freshness deadline, so a machine that moved
networks keeps retrying the addresses of the network it left — and
`prefer_last_good` puts the last one it *did* reach first, which after a change
is the wrong hint.

Two consecutive failed iterations say the answer is wrong rather than the
attempt. `should_force_refresh` (failures >= 2, a pure predicate) then calls
`resolve_server_addrs_fresh` (`src/dns/resolve.rs:1298`), which removes the
positive and negative entries and resolves again, and clears `last_good` for the
next attempt. The next iteration reads the now-fresh cache; the counter saturates
rather than wrapping, and the ordinary path re-populates the cache for the
iterations that follow.

### 18.5 A truncated answer over TCP

`opts.try_tcp_on_error = true` in `configure_resolver_options`
(`src/dns/resolve.rs:459`). hickory's alternative on TC=1 is to serve the partial
UDP record set — silently dropping addresses — and because hickory's own cache is
deliberately disabled, every cold lookup would pay that again. The retry is
bounded by the same 1.5 s × 2 budget as any other attempt.

### 18.6 The refresh histogram, and two accounting bugs

`refresh_positive` now times its own lookup into `stats::refresh_lookup_took`
(`src/dns/resolve.rs:1152`), separate from the foreground `lookup` histogram:
"slow DNS" has two meanings, and the datagram path's p99 is the one users feel
while a refresh's p99 only delays how long a stale answer keeps being served.

Both review findings of the eleventh batch are fixed here. `HistSnapshot::since`
printed the process-lifetime `max_us` as the interval's maximum, so a histogram
that recorded one 4 s outlier once printed `max=4.0s` in every subsequent
minute; an interval's ceiling is now `percentile_us(100)`, a bucket bound
(`max<=`), and `max_us` is documented as the lifetime maximum it is. And
`send_packed_frames`'s missing-body arm had lost its `book_too_large` /
`items_dropped` accounting while `requeue_unsent` starts at the frame *after* the
failed one, so the payloads left the queue unbooked.

The line now reads, for an interval:

```
dns (60s): 412 fresh, 6 stale, 2 refused, 3 cold (1 verdict, 2 inconclusive),
           6 refresh (4 ok, 2 failed), 9 parked (9 delivered);
           lookup n=3 p50<=8.0ms p99<=128.0ms max<=256.0ms;
           refresh n=6 p50<=16.0ms p99<=256.0ms max<=256.0ms;
           waiter n=3 p50<=4.0ms p99<=64.0ms max<=64.0ms
```

### 18.7 Verification

`cargo fmt --all --check` clean, `cargo clippy --all-targets -- -D warnings`
clean, `cargo test --all-targets` **760 passed / 0 failed / 1 ignored**
(lib 383, client 202, server 159 + 1 ignored, `forward_e2e` 7, `rev3_e2e` 9).
New tests: `a_routing_failure_condemns_only_that_address` (exact-address match,
port in the key, the three routable kinds and one that must not condemn),
`a_filtered_verdict_is_bounded_by_the_answers_life` (fresh bound on a miss,
remaining life for a seeded answer, capped),
`dns_gate_parks_followers_until_the_answer` (arrival order, both bounds, a
finished claim parks nothing), `dns_gate_park_bounds_and_generation_ownership`
(only the owning generation takes its followers, a verdict parks nothing),
`a_second_failed_iteration_forces_an_uncached_lookups` (the threshold and the
saturating counter) and `a_printed_maximum_belongs_to_its_interval`.

### 18.8 What this does not establish

No measurement backs the parking item: the `waiter` line's p99 against the `app
RTO` is the number that decides whether 8 KiB per claim is worth it, and that
still needs a `hotpath_bench udpdomain` run under a cold-name burst. The routing
hint is remembered per thread (a hash slot, ten seconds), so two workers can
disagree about one address for that window — it only costs a datagram. The
deferred structural items are unchanged: the rev4 client address hint on the wire
(split-horizon needs a fallback design) and UDP happy-eyeballs without feedback,
which §18.1's feedback partially supersedes.
