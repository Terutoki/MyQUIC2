# SOCKS5 hot-path audit — commit `41031b4` (client TCP/UDP forward listeners) vs parent `1135076`

**Question (task-3).** Commit `41031b4` added client-side config-driven TCP/UDP forward
listeners. Does that commit degrade the existing **SOCKS5 TCP/UDP ECHO** hot paths
(throughput / latency / allocations / lock contention) **when no forward listener is
configured**, and what is the residual per-packet delta? If forward listeners *are*
configured, which shared budgets can let forward traffic starve SOCKS?

**Commit/HEAD under audit.** `41031b4` = `feat(client): add config-driven TCP/UDP forward
listeners`; parent `1135076`. HEAD `7232088` (= v0.2.2) differs from `41031b4` only by
`README.md` (docs) and `Cargo.toml`/`Cargo.lock` (version bump) — verified with
`git diff --stat 41031b4 7232088`; therefore every HEAD line number below is also the
`41031b4` line number. The tree was clean at audit start (the only untracked path is the
`analysis/forwarding-audit/` report directory itself; no source/config was modified).

**Scope.** Only the delta in code the SOCKS paths actually execute:
`src/bin/myquic2-client/{assoc,dispatcher,hub,main,socks,pool,egress,rev2}.rs`,
`src/lib.rs`, `src/config/client_conf.rs`, `src/stats/udp_stats.rs`. Feature-correction
defects in the new `forward.rs` / `forward_udp.rs` belong to the sibling audits (task-1 /
task-2) and are **not** duplicated here.

**Method.** Static reading of HEAD source + `git diff -U0`/`git diff` of every hunk in the
commit, plus call-graph tracing forward from the SOCKS accept loops. I did **not** run
`cargo build`, `cargo test` or a release build: the benchmark teammate owns the build and
this audit is code-level. Cheap, non-repo checks used: `git show`/`diff`/`grep`/`sed`, and
one standalone `rustc 1.99.0` probe in `/tmp` for struct layout (no repo files touched, no
crates compiled). Struct-size and branch-count numbers are **computed/inferred** (exact
inputs stated); everything about code content and call paths is **verified** line-by-line.
Confidence tags: **verified** (read the exact lines), **inferred** (reasoned from verified
inputs), **unprovable statically** (needs measurement).

**Verdicts (explicit, as requested):**

- **SOCKS5 TCP ECHO: no measurable impact expected.** Every file on the `CONNECT` data path
  (`socks.rs`, `pool.rs`, `src/tcp/pump.rs`, `linux::tune_relay_tcp`, `rev2.rs`, `util.rs`)
  is **byte-identical** across the commit; with no forward listener configured the new
  startup code executes zero iterations, makes zero syscalls and spawns zero tasks. Per-flow
  delta = 0.
- **SOCKS5 UDP ECHO: no measurable impact expected.** Per **reply** the delta is ~2–3
  well-predicted branches + 2 byte loads + 2 byte stores ≈ **2–3 cycles ≈ 0.6–0.9 ns**
  (@3.5 GHz); per **app datagram** the delta is a call boundary that release LTO almost
  certainly inlines (bound if not inlined: ~1–3 ns). No new allocation, lock, atomic or
  syscall enters any per-datagram / per-reply path. `AssocEntry` stays **48 B**;
  `StagedReply` grows **104 → 112 B**. Wire bytes and log text are unchanged.
- **No SOCKS behavior change** in the shared delta (audited suspicion-by-suspicion in §5);
  `reply_v6`/`raw_reply` are provably constant `true`/`false` for every SOCKS relay socket.
- **Residual risk is codegen-layout noise** (statistically invisible, unprovable statically)
  **and, only when forward listeners are configured**, real cross-feature contention on
  shared budgets: TCP relay semaphore 8192, shared `UdpHub`/`MAX_UDP_ASSOCS` 4032, the
  single interactive UDP egress connection, and the shared TCP pool slots/driver threads
  (§6). That contention is a capacity/conflict property of the feature, not a regression of
  the SOCKS code paths when the feature is unused.

---

## 1. What the commit actually changed

`git diff --stat 1135076 41031b4`:

| area | files | +/- | runtime? |
|---|---|---|---|
| client bin — shared code | `assoc.rs` 215, `dispatcher.rs` 70, `hub.rs` 36, `main.rs` 51 | +289/−83 | yes (audited below) |
| client bin — new feature | `forward.rs` +242, `forward_udp.rs` +445 | +687 | only reachable when forward config is non-empty |
| client bin — tests | `tests.rs` +598 | +598 | **test-only** (`#[cfg(test)] mod tests;`, `main.rs:37-38`) |
| config | `client_conf.rs` +472 | +472 | additive; parsed once at startup |
| lib | `src/lib.rs` 1/1 | +1/−1 | re-export only, no runtime |
| stats tests | `src/stats/udp_stats.rs` 14/4 | +14/−4 | **test-only** (both hunks inside `mod tests`, starts line 340) |
| integration test | `tests/forward_e2e.rs` +648 | +648 | **test-only** (separate test target) |
| non-code | `README.md`, `config-client.toml`, `dist/…sample`, plan doc, `Cargo.*` | — | documentation / dev-dependency `tempfile` only |

Crucially, `git diff --stat 1135076 41031b4 -- src/tcp/ src/udp/ src/dns/ src/transport/
src/mqp/ src/bin/myquic2-server/ src/sync.rs src/linux.rs src/time/` is **empty**: the
server, the MQP wire/rev2 engine, the UDP send/retry/batch engine, DNS and the TCP copy pump
are untouched. The rest of the client binary is unchanged by inspection of
`src/bin/myquic2-client/{socks,pool,egress,rev2,util,auth,reporter}.rs` — **zero hunks** in
all of them. So for the SOCKS TCP path this commit is a pure startup/binary-composition
delta; for the SOCKS UDP path it is the `assoc.rs`/`dispatcher.rs`/`hub.rs` delta audited here.

**Excluded as test-only / non-runtime** (mentioned, not counted in the per-packet delta):
`tests.rs` (+598, `cfg(test)`; contains the new forward/UDP-mode unit tests), the two
`udp_stats.rs` hunks (test assertions inside `mod tests`, lines 373/377 → HEAD 373/387, a
flaky-test fix that also depends on `L_DATAGRAMS` — runtime `udp_stats` code untouched),
`tests/forward_e2e.rs` (+648 integration test), `dispatcher::dispatch_one` hunks (that
function is `#[cfg(test)]` in **both** baseline and HEAD — baseline `1135076:dispatcher.rs:655`,
HEAD `dispatcher.rs:681`), README/config samples/plan doc and the `tempfile`
**dev-dependency** (`Cargo.toml:230-234`; dev-deps are not in the release binary).

---

## 2. Hunk-by-hunk table (`git diff -U0 1135076 41031b4`)

Frequency legend: **D** = once per app datagram (up), **R** = once per reply (down),
**A** = once per association, **S** = startup-only, **C** = compile/link only, **T** = test-only.
"X" marks the hunk whose cost actually lands on the ECHO hot path.

### 2.1 `src/bin/myquic2-client/assoc.rs` (+144/−71; 7 hunks)

The `-U0` diff splits the extraction into hunks `@@ -387,27 +387,114 @@`,
`@@ -415,30 +502,2 @@`, `@@ -447,7 +505,0 @@`, `@@ -455,6 +507,8 @@`, `@@ -461,0 +516,5 @@`
(all one semantic move) plus two `send_reply_addr` hunks.

| hunk | HEAD lines | change | path / frequency | real? |
|---|---|---|---|---|
| a1 | 388-402 | inline egress-selection+send block replaced by `send_payload_uplink(..., SessionKind::Socks); AppDgram::Continue` | SOCKS UDP uplink — **D, X** | real |
| a2 | 407-425 | new `SessionKind {Socks, Forward}` + `label()` (`&'static str`) | only read inside the two pre-existing `tracing::debug!` branches (first-payload and fragmented) — **A/rare, no hot cost** | real |
| a3 | 427-521 | extracted `send_payload_uplink()` (covers the `-415/-447/-455/-461` hunks: same statements, moved) | SOCKS uplink — **D, X**; forward uplink (feature) | real |
| a4 | 1109-1122 | `send_reply_addr`: `peer = if entry.reply_v6 { map_for_dual(app) } else { app }`; early `if entry.raw_reply { send bare payload; return }` | SOCKS **slow** reply path only (domain-form reply source → spawned DNS resolver task; conforming server always sends IP-form) — **R but cold, X(no-op)** | real |
| a5 | 1125 | final `udp_try_send_slice(&entry.relay, map_for_dual(app), …)` → `…, peer, …` | same slow path — **R cold** | real |

### 2.2 `src/bin/myquic2-client/dispatcher.rs` (+61/−9; 18 hunks)

| hunk | HEAD lines | change | path / frequency | real? |
|---|---|---|---|---|
| d1 | 91-98 | `StagedReply` += `raw: bool`, `reply_v6: bool` (+docs) | every staged reply (layout) — **R, X(memory)** | real |
| d2 | 101 | `fn stage_reply` → `pub(crate) fn stage_reply` | visibility only, same crate — **C** | real, no codegen effect |
| d3 | 113-114 | `stage_reply` copies `entry.raw_reply`/`entry.reply_v6` into the staged reply | **hot downlink staging for all production frame paths**: rev2 `DATA` `dispatcher.rs:1085,1140`, rev2 `TRAIN` `1266,1275`, rev2 `FRAG` `1388` — **R, X** | real |
| d4 | 134-135 | `stage_reply_follow` does the same for TRAIN followers | rev2 TRAIN — **R, X** | real |
| d5 | 224-225 | `stage_v3_reply` gains `raw, reply_v6` params | legacy MQP-3 v3 downlink only (`diagnostics/rollback`; rev2 peer never emits) — cold | real |
| d6 | 237-238 | `stage_v3_reply` Ip-arm push sets the two fields | legacy v3 — cold | real |
| d7 | 250-251 | `stage_v3_reply` Domain-arm push | legacy v3 — cold | real |
| d8 | 325-326 | `dispatch_stage_multi` MQP-3 SINGLE passes `entry.raw_reply, entry.reply_v6` | legacy MQP-3 — cold | real |
| d9 | 368-369 | MQP-3 TRAIN passes the same | legacy MQP-3 — cold | real |
| d10 | 434-435 | MQP-2 BATCH Ip-arm staging sets the fields | legacy MQP-2 — cold | real |
| d11 | 451-452 | MQP-2 BATCH Domain-arm staging sets the fields | legacy MQP-2 — cold | real |
| d12 | (old 667-668 → HEAD 692-693 deleted) | `dispatch_one`: removed unconditional `pkt.truncate(0); encode_reply(...)` | **`#[cfg(test)]` fn — T** | test-only |
| d13 | 697-710 | `dispatch_one`: `dst` from `reply_v6`, early raw send | **`#[cfg(test)]` fn — T** | test-only |
| d14 | 749-754 | `flush_staged`: read `run_v6`, compute `run_dst` **once per run** (baseline called `map_for_dual(run_app)` per send-group) | all production downlink replies — **R, X** | real |
| d15 | 758 | run-boundary predicate adds `staged[j].reply_v6 == run_v6` | flush run scan — **per scanned item of multi-reply runs, X** | real |
| d16 | 776-786 | header staging: `if s.raw { offs.push((hdrs.len(),0)) } else { encode_reply_header }` | flush, per reply — **R, X** | real |
| d17 | 794 | `n == 1` send uses `run_dst` instead of `map_for_dual(run_app)` | flush, per single-reply run (common shape) — **R, X** | real |
| d18 | 802 | grouped send uses `run_dst` | flush, per send-group — **R, X** | real |

### 2.3 `src/bin/myquic2-client/hub.rs` (+36; 4 hunks)

| hunk | HEAD lines | change | path / frequency | real? |
|---|---|---|---|---|
| h1 | 103-122 | `AssocEntry` += `raw_reply` (113), `reply_v6` (122) + docs | struct layout for every association; read per reply by `stage_reply`/`send_reply_addr` | real |
| h2 | 145-171 | `new()` → `with_reply_mode(relay,false)`; new `new_raw()`; `with_reply_mode()` now calls `relay.local_addr()` (**one getsockname syscall**) | SOCKS: `assoc.rs:572` (once per UDP ASSOCIATE); forward: `forward_udp.rs:190` | real, **A, cold** |
| h3 | 162 | init `reply_v6` | same | real |
| h4 | 169 | init `raw_reply` | same | real |

### 2.4 `src/bin/myquic2-client/main.rs` (+48/−3; 5 hunks)

| hunk | HEAD lines | change | path / frequency | real? |
|---|---|---|---|---|
| m1 | 30-31 | `mod forward; mod forward_udp;` | binary composition (new code linked, only called from empty loops when unconfigured) — **C** | non-behavioral |
| m2 | 42-43 | glob `use` list gains `forward::*` | compile-time — **C** | non-behavioral |
| m3 | 131-136 | `let tcp_forwards = c.tcp_forwards()?; let udp_forwards = c.udp_forwards()?;` before TLS/QUIC setup | **S**; empty config = one `SocketAddr::parse` + two `Vec::with_capacity(0)` (no heap) + zero loop iterations | real, cold |
| m4 | 370-407 | bind+spawn forward listeners **before** the SOCKS accept loop; per entry a `format!` log + bind + `tokio::spawn` | **S**; zero iterations / zero syscalls / zero tasks when tables empty | real; no-op when empty |
| m5 | 414 (old 369) | old `let timeout = Duration::from_secs(c.reconnect_timeout_secs.max(1));` removed here, now at HEAD 373 | **S**; same value, same single computation, still passed to `handle_socks` (`main.rs:488`) | real, no-op |

### 2.5 `src/lib.rs`, `src/config/client_conf.rs`, `src/stats/udp_stats.rs`

| file / hunk | HEAD lines | change | classification |
|---|---|---|---|
| `lib.rs` 1 hunk | 41 | re-export `ForwardEntry, TcpForwardSpec, UdpForwardEntry, UdpForwardSpec` | public-API surface only; the bin already reaches these via `myquic2::*`; **no runtime effect** |
| `client_conf.rs` `@@ -0,0 +1,3` / `+12` | 1-3, 12 | new imports (`SocketAddr`, `anyhow`, `TargetAddr`) | compile-time |
| `client_conf.rs` `@@ -137,0 +142,56` | 142-197 | `ClientConf` += `tcp_forward: Vec<ForwardEntry>` (147), `udp_forward: Vec<UdpForwardEntry>` (152), **both `#[serde(default)]`**; new `ForwardEntry`(164)/`UdpForwardEntry`(175)/`TcpForwardSpec`(186)/`UdpForwardSpec`(193) | additive config shape; parsed **once at startup**; old configs parse identically |
| `client_conf.rs` `@@ -202,0 +263,412` | 263-674 | `tcp_forwards()` (269) / `udp_forwards()` (304) validation + `unmap_listen_ip`/`listen_overlaps`/`parse_forward_listen`/`parse_forward_target` (336-419) + `#[cfg(test)] mod tests` | startup-only when called from `main.rs:135-136`; with empty tables the loops are empty (and the two functions do **not** allocate — `Vec::with_capacity(0)`); test block = test-only |
| `udp_stats.rs` 2 hunks | 373-384, 387-388 | assertion changes inside `mod tests` | **test-only, excluded** |

**Count.** 41 hunks total in the shared scope: **32 real runtime hunks** (assoc 7,
dispatcher 16, hub 4, main 3 executing, client_conf 2 executable: the field block and the
validation-method block), **4 compile/link-only** (`main.rs` mod/use + 2 `client_conf`
import hunks), **1 public-API-only** (`lib.rs`), **4 test-only** (2 dispatcher `dispatch_one`
hunks + 2 `udp_stats` test hunks); plus the non-runtime files listed in §1. Of the 32, the
hunks reachable with an empty forward config are: assoc a1/a3 (per datagram), dispatcher
d1/d3/d4/d14–d18 (per reply), hub h1 (layout) and h2 (one syscall per association), main
m3/m4/m5 (startup, no-op when empty), and the two `client_conf` hunks (config parse, no-op
cost).

---

## 3. SOCKS5 UDP ECHO delta

### 3.1 Call graph, both directions (all production paths)

Uplink (app → QUIC), per datagram:

```
main.rs:421-495  accept loop → socks_conn_limiter() (main.rs:470) → handle_socks (socks.rs:126)
  → UDP ASSOCIATE branch → handle_udp_associate (assoc.rs:6) → hub.alloc_sess (assoc.rs:12)
  → bind_relay (assoc.rs:45) → AssocEntry::new (assoc.rs:572)  [HEAD: +1 getsockname]
  → hub.publish (assoc.rs:573) → write_socks_reply (assoc.rs:575)
  → 'assoc loop (assoc.rs:683) → relay.recv_from → AppDgramCtx (assoc.rs:678-689)
  → ctx.process (assoc.rs:272): size check 298, app-IP pin 312, coarse clock 325,
    SOCKS5 framing 337, source lock 350, liveness 362
  → send_payload_uplink (assoc.rs:391, fn 439-521): memo hit with_fresh (463) → send_uplink (464)
    → [miss only] generation load 471 → acquire 473 → memo_store 475 → send_uplink 477
    → [no-egress only] NO_EGRESS bump 491 + rate-limited warn 492
  → recover_send_outcome (520)
```

Downlink (QUIC → app), per reply (server unchanged: `src/bin/myquic2-server/reader.rs:535`
sends rev2 steady `DATA`):

```
spawn_dispatcher (dispatcher.rs:1454) → read_datagram (1524) → bounded drain (1538-1571)
  → dispatch_inbound (1539) → dispatch_r2 (1399) → dispatch_r2_data (1055)
     [or dispatch_r2_train 1178 / dispatch_r2_frag 1288]
  → r2_lookup (839) → stage_reply (101; push at 1085/1140) [TRAIN: stage_reply_follow 122]
  → flush_staged (1573 → fn 733): run head 744-754, run scan 755-769,
    header staging 775-787, single-frame send 788-797 / grouped send 798-803
  → udp_try_send_grouped (src/udp/retry.rs:340)  [1 syscall per run on Linux]
```

The SOCKS UDP ECHO reply is the `DATA` path (`dispatch_r2_data` → `stage_reply` →
`flush_staged`). The `TRAIN` follower path (`stage_reply_follow`) and the `FRAG` path
(`dispatcher.rs:1388`) also use `stage_reply*`, so the same two-field copy covers them.

### 3.2 `send_payload_uplink` extraction — equivalence proof (verified)

I extracted the baseline inline block (`git show 1135076:…/assoc.rs`, old lines 387-459)
and the HEAD function body (`assoc.rs:451-521`), stripped comments/whitespace, normalized the
renamed identifiers (`&addr` vs `target`, `SessionKind::label()`), and diffed
token-by-token with `difflib`. The **only** differences are:

1. the two `tracing::debug!` argument lists gain `kind.label(),` (`assoc.rs:454-456`,
   `509-511`) — rendered text is byte-identical for SOCKS because `SessionKind::Socks.label()
   == "assoc"` (`assoc.rs:418-425`), so `"udp assoc {sess}: …"` is produced exactly as before;
2. the `warn_egress_drop(...)` call is re-formatted across lines (`assoc.rs:492-503`) —
   same callee, same arguments, same closure body;
3. the no-egress arm ends with `return;` instead of `return AppDgram::Continue;`
   (`assoc.rs:503`) — the caller (`process`) then falls through to `AppDgram::Continue` at
   `assoc.rs:403`, and there is no statement after the call, so the control flow is identical.

Every other statement is token-identical, **in the same order**: bind memoization →
`with_fresh` → generation-load-before-acquire on miss → `memo_store` → `send_uplink` →
fragmented debug → `recover_send_outcome`. No statement was added, dropped, reordered or
re-conditioned on a new flag. **Verdict: behaviorally equivalent.**

### 3.3 Per-datagram delta (uplink)

| resource | added by the commit | comment |
|---|---|---|
| branches | 0 | `SessionKind::Socks` is a constant at the call site; `kind.label()` is only evaluated inside the *pre-existing* debug branches (first payload / fragmented only). The debug-level check itself already existed. |
| loads/stores | 0 | the 10-argument call uses values already in registers/locals; if inlined, zero |
| allocations | 0 | — |
| locks / atomics | 0 new | the only atomics in the moved block (generation `Acquire` load, `memo_store`, `NO_EGRESS` bump, `refreshing` `Relaxed` load) are moved code — identical count/ordering |
| syscalls | 0 | — |
| function call | 1 direct call (possibly inlined) | **inferred**: release profile is `lto = true`, `codegen-units = 1` (`Cargo.toml:236-240`), and the function has two in-crate callers, so LLVM sees the body and can inline it into `AppDgramCtx::process`; if it does not, the bound is one predicted `call`+`ret` plus a few argument moves ≈ **1–3 ns/datagram** |

### 3.4 Per-reply delta (downlink, SOCKS = `raw_reply=false`, `reply_v6=true`)

| resource | delta | evidence |
|---|---|---|
| `stage_reply` (`dispatcher.rs:101-116`, also follow variant 122-137) | **+2 byte loads** (`entry.raw_reply`, `entry.reply_v6`) + **one 2-byte store pair** into the staged struct | loads land in the `AssocEntry` bytes this function already touches (`entry.mark_replied()` store, `entry.relay.clone()`), so no new cache line in the steady case |
| `flush_staged` run head (`749-754`) | +1 byte load + 1 predictable branch (`if run_v6`) to choose `run_dst`; **for multi-item runs this hoists `map_for_dual` out of the send-group loop** (baseline re-evaluated it per group), i.e. neutral-to-positive | `map_for_dual` itself (`src/dns/policy.rs:140-145`) is the same call as before |
| run-boundary scan (`758`) | +1 byte load + 1 compare per scanned item of a **multi-reply** run (`staged[j].reply_v6 == run_v6`) | single-reply runs never execute the loop body |
| header staging loop (`776-786`) | +1 byte load + 1 highly-predictable branch per reply (`if s.raw`); the `else` arm is byte-identical to baseline | branch never taken for SOCKS |
| sends (`794`, `802`) | use precomputed `run_dst`; the value is `map_for_dual(run_app)` for SOCKS, identical to baseline | — |
| allocations / locks / atomics / syscalls | **0** | scanned every added line of the shared diff for `alloc/Mutex/RwLock/Atomic/spawn/format!/Vec::/local_addr`: the only new ones are `local_addr` in hub cold path and startup spawns in `main.rs` loops (§3.6, §2.4) |

Totals for the common one-reply-per-drain shape: **≈2 extra loads + 2 extra stores + 2–3
well-predicted branches ≈ 2–3 cycles ≈ 0.6–0.9 ns** per reply at 3.5 GHz, assuming the
staging buffer is L1/L2-resident (it is: 32 × 112 B = 3.5 KiB, allocated once per dispatcher
connection and never freed, `dispatcher.rs:1519`). Comparison: a single-reply run still pays
one `sendmmsg` syscall (≥ ~300–500 ns class) plus quinn DATAGRAM encode/send; a batched run
amortizes ~32 replies/syscall. The added ~1 ns is therefore **<0.1–0.2 %** of the per-reply
path, and ≈0.1 % of one core even at 1 M replies/s (1 ns × 1e6 = 1 ms/s). That is below
run-to-run noise of any real ECHO measurement.

### 3.5 Struct size / cache-line effects (computed; layout inputs verified)

Field sizes verified: `bytes::Bytes` = 4 machine words = 32 B (`bytes-1.12.1/src/bytes.rs:101-107`,
locked by `Cargo.lock`), `SocketAddr` = 32 B (standalone `rustc 1.99.0` probe on this host),
`Option<Arc<T>>` = 8 B (pointer niche), `ArcSwapOption<T>` = 8 B (one `AtomicPtr`,
`arc-swap-1.9.x/src/lib.rs:326-334` and `:738`), `AtomicU64` = 8 B, `&'static`/Arc = 8 B.

- **`AssocEntry`** (fields `hub.rs:41-123`): relay 8 + flows 8 + confirmed 8 + app 8 +
  alive 1 + replied 1 + last 8 = **42 B → 48 B with padding**. With `raw_reply` + `reply_v6`
  it is 8+8+8+8+1+1+8+1+1 = **44 B → 48 B**. **Size is unchanged (48 B)**; the two bools fit
  in bytes that were already padding, so there is no new allocation size, no extra cache-line
  footprint and no change to how many lines a reply touches. (Rust is free to reorder
  `repr(Rust)` fields, but the total payload 44 B rounds to 48 either way.)
- **`StagedReply`** (fields `dispatcher.rs:86-99`): sock 8 + app 32 + dst 32 + payload 32 =
  **104 B baseline** (align 8) → with two bools 106 B → **112 B HEAD (+8 B, +7.7 %)**.
  Consequences: the dispatcher's `Vec::with_capacity(LAST_HOP_DRAIN = 32)`
  (`dispatcher.rs:1519`, `src/udp/batch.rs:46`) allocates 3 584 B instead of 3 328 B **once
  per connection generation**, `staged.clear()` keeps that capacity, so **no per-packet
  allocation change**. Per staged reply the vector write is 8 B larger; both 104 B and 112 B
  structs straddle cache lines, so the number of lines touched per element is unchanged in
  practice (and every such write is amortized against the payload copy/syscall). The 32-entry
  capacity is identical, so the `refs` stack array `[SendFrame; 32]` (512 B) and the
  `hdrs`/`offs` capacities are untouched.

### 3.6 Once-per-association additions (not per packet)

- `AssocEntry::with_reply_mode` adds **one `getsockname` syscall** (`hub.rs:159`) per
  association/SOCKS `UDP ASSOCIATE` (`assoc.rs:572`) and per forward peer session
  (`forward_udp.rs:190`). That is worth ~0.2–0.5 µs once per association, against a setup
  path that already opens a relay socket, sets buffer options, binds, publishes into the hub
  and writes the SOCKS reply (tens of µs). It cannot appear on the ECHO per-datagram path.
  For forward listeners it lands on the single listener task at session creation (forward
  capacity, not SOCKS).
- `c.tcp_forwards()` / `c.udp_forwards()` at startup (`main.rs:135-136`): with empty tables
  one `socks_listen` `SocketAddr` parse + two zero-capacity `Vec`s, **no heap allocation**
  (`Vec::with_capacity(0)` does not allocate), zero iterations of the spawn loops. Startup
  delta ≈ sub-µs against a startup that builds TLS configs, a QUIC pool (7 endpoints at
  defaults) and awaits shard readiness — unobservable.

### 3.7 Codegen / monomorphization concerns

- No generic is introduced: `SessionKind` is a 1-byte non-generic enum; `send_payload_uplink`
  is a single non-generic `pub(crate)` fn with two callers. No monomorphization growth, no
  `#[inline]`/`repr`/`unsafe` was added anywhere in the shared diff (scanned).
- The extracted body is a net code-size *reduction* versus inlining it at two sites
  (SOCKS + forward), and with `lto = true` + `codegen-units = 1` the compiler sees it.
  Whether it inlines into `AppDgramCtx::process` is a compiler decision that cannot be read
  off the source; the bound if it does not is given in §3.3.
- The ~+687 lines of new forward modules and ~+472 lines of config code are linked into the
  client binary unconditionally (the calls exist in `client_main`; only the loops are empty
  at runtime), so I-cache/function-placement and inlining-budget effects are possible. That
  is the only plausible residual source of a *measurable* SOCKS delta, it is
  **statistically unprovable from source**, and it can cut either way. See §7 R1.

---

## 4. SOCKS5 TCP ECHO (`CONNECT` + copy pump)

**Files on this path are unchanged by the commit.** Verified empty diff for
`src/bin/myquic2-client/socks.rs`, `pool.rs`, `egress.rs`, `rev2.rs`, `util.rs`, `auth.rs`,
`reporter.rs`, `src/tcp/pump.rs`, `src/tcp.rs`, `src/linux.rs`, `src/transport/`,
`src/mqp/`, `src/bin/myquic2-server/`. Trace (all pre-existing code):

```
main.rs:421-495 accept → socks_conn_limiter().try_acquire_owned (main.rs:470; MAX_SOCKS_CONNS
  = 8192, socks.rs:11/24) → handle_socks (socks.rs:126) → read greeting/request →
  pool.pick_tcp_index(&target) (socks.rs:147; pool.rs:794) → slot.wait_conn →
  conn.open_bi() 5 s timeout (socks.rs:166) → AddrHeader write → copy_tcp_quic_acked
  (socks.rs:261 → src/tcp/pump.rs:53) → linux::tune_relay_tcp (main.rs:469)
```

With no forward listener configured, the commit inserts **nothing** into this path:

- `main.rs` m3 validation: empty tables → no allocation, no iteration;
- `main.rs` m4 spawn loops: empty vectors → no bind, no task, no log;
- `main.rs` m5: `timeout` is computed at HEAD 373 instead of old 369 with the same value and
  is still passed to `handle_socks` at `main.rs:488`; the SOCKS listener is created in the
  same order with the same arguments (`main.rs:408-409`, `info!` 410, `spawn_udp_reporter`
  414 — identical to baseline order);
- hub/dispatcher/assoc changes are UDP-only and are not on the TCP path.

**Per-connection delta: 0.** **Verdict: SOCKS5 TCP ECHO: no measurable impact expected.**
If forward listeners *are* configured, forward flows acquire from the same
`socks_conn_limiter()` (`forward.rs:51,79`) — that is a runtime capacity coupling, discussed
in §6 R2a, not a change to the SOCKS per-flow code.

---

## 5. "No SOCKS behavior change" — suspicious-diff hunts

Legend: **verified** = the exact lines were read; **inferred** = reasoned from verified lines.

| # | Suspicion | Finding | Status |
|---|---|---|---|
| 5.1 | `reply_v6` conditional changes the `map_for_dual` decision for SOCKS relays | SOCKS relay sockets are **always AF_INET6/dual-stack**: `bind_relay` binds `map_for_dual(SocketAddr::new(relay_ip, 0))` (`assoc.rs:49`), `map_for_dual` always returns an IPv6 address (`policy.rs:140-145`, v4→v4-mapped v6), `udp_socket_dual_small_addr` (`lib.rs:333`) → `udp_socket_dual_impl_addr` selects `Domain::IPV6` when `addr.is_ipv6()` and sets `only_v6(false)` (`lib.rs:347-359`); the error fallback binds `[::]:0` (`assoc.rs:54-59`). So `local_addr()` is V6 ⇒ `reply_v6 = true` ⇒ `map_for_dual` is applied on every reply exactly as in baseline (mandatory on macOS/BSD). Even a failed `local_addr()` (not realistic on a bound socket) falls back to `unwrap_or(true)` = old behavior (`hub.rs:159`). | **verified**, high confidence |
| 5.2 | `raw` flag alters SOCKS reply framing | `AssocEntry::new` passes `raw_reply=false` (`hub.rs:145-147,156`); dispatcher's raw branch (`dispatcher.rs:776-781`) and `send_reply_addr` early return (`assoc.rs:1116-1122`) are never taken for SOCKS. | **verified** |
| 5.3 | `map_for_dual` call sites lost/added | Baseline `flush_staged` called it inside both sends; HEAD computes `run_dst` once per run and uses it in both sends (`dispatcher.rs:750-754,794,802`) — same mapped value for SOCKS. `dispatch_one` (test) same. `send_reply_addr` same via `peer`. **No call removed from a live SOCKS path, none added.** | **verified** |
| 5.4 | group-flush run boundary now includes `reply_v6`, could split runs / reorder bytes | For SOCKS `reply_v6` is constant `true`, so the predicate `app == run_app && reply_v6 == run_v6 && same socket` reduces exactly to baseline's `app == run_app && same socket`. Even a hypothetical split would only change syscall grouping, never bytes, destination or order (runs flush in encounter order). | **verified** |
| 5.5 | slow-path early return in `send_reply_addr` skips encoding | Only when `entry.raw_reply` (false for SOCKS). SOCKS still does `pkt.truncate(0); encode_reply(...); udp_try_send_slice(...)` in the same order. | **verified** |
| 5.6 | log text changed | For SOCKS, `label()` = `"assoc"`, so both lines render byte-identically: `"udp assoc {sess}: egress class … shard … (first payload … B)"` and `"udp assoc {sess}: … B sent as … fragments"` (`assoc.rs:454-456, 509-511` vs baseline). Normalized diff shows only the added argument. | **verified** |
| 5.7 | error paths changed | The no-egress arm keeps `dgram_drops::bump(&NO_EGRESS)`, the same `warn_egress_drop(EgressDrop::NoConnection, n,` + closure `format!(…)` arguments/format, then returns without touching `recover_send_outcome` — same as baseline's `return AppDgram::Continue`. The caller then returns `Continue` (`assoc.rs:403`). | **verified** |
| 5.8 | `dispatch_one` byte changes affect production | `#[cfg(test)]` in **both** baseline (`1135076:dispatcher.rs:655`) and HEAD (`dispatcher.rs:681`) — not compiled into the release binary. | **verified** |
| 5.9 | extraction drift (semantics reordered/conditioned) | Normalized token diff in §3.2: only the 3 listed differences; all statements/order identical. | **verified** |
| 5.10 | `AssocEntry::new` side effect changes behavior | Adds only `local_addr()` + stores two constants; error paths unchanged; no mapping mutation after construction. | **verified** |
| 5.11 | `stage_reply` visibility change | `fn` → `pub(crate) fn`, same crate/module — linkage/visibility only; no runtime behavior or codegen difference (no `#[inline]`). | **verified** |
| 5.12 | `ClientConf` new fields break/alter old config parsing | Both fields are `#[serde(default)]` (`client_conf.rs:145-152`) and `deny_unknown_fields` still accepts the old key set; an empty-table config produces the same parsed values as before plus two empty `Vec`s. The commit's own `forward_tables_are_optional` test asserts empty defaults (`client_conf.rs` tests). | **verified** |
| 5.13 | startup order re-orders SOCKS socket creation | With empty tables the inserted block is a no-op; the SOCKS listener (`main.rs:408-409`), info line, reporter spawn and accept loop are byte-identical and in the same order. Only the `timeout` binding moved earlier (same value). | **verified** |
| 5.14 | `AssocEntry` layout change could alias/overflow | Size unchanged 48 B (§3.5); only new bool fields, no field type/size change, no `unsafe`/`repr` involved. | **verified** (size computed) |

**One intended, forward-only behaviour difference (not a SOCKS change):** a SOCKS relay that
were ever *not* IPv6 would now send replies with the identity address instead of the
v4-mapped form. Not reachable with today's `bind_relay`; it is exactly the forward-listener
fix (plain IPv4 forward listeners need no mapping). **One forward-only observation** (owned by
task-2): `raw` is not part of the flush run-boundary predicate, but run identity (same
`Arc<UdpSocket>`) already implies same mode in practice, and mixed items are still framed
per item — no SOCKS implication.

**Verdict: "no SOCKS behavior change" holds** — wire bytes, destinations, send order, error
accounting, logs and lifetimes are all unchanged for SOCKS. **Verified, high confidence.**

---

## 6. Cross-feature contention when forward listeners ARE configured

This is real (it is the price of sharing tuned machinery), but it only exists when the
operator adds `[[tcp_forward]]`/`[[udp_forward]]` tables. Defaults used below:
`MAX_SOCKS_CONNS = 8192` (`socks.rs:11`), `MAX_BIDI_STREAMS_PER_CONN = 8192`
(`src/config/tuning.rs:145`), `MAX_UDP_ASSOCS = 4032` (`tuning.rs:187`),
`DEFAULT_QUIC_CONNS = 4` (`tuning.rs:79`), `DEFAULT_UDP_EGRESS_CONNS = 2` (`tuning.rs:110`)
⇒ pool = 4 TCP slots + 1 interactive UDP slot + 2 bulk UDP shards = 7 slots
(`main.rs:226-249`), `interactive_ports` default `[53, 123, 3478, 3479, 3480, 3481]`
(`client_conf.rs:231-235`), `udp_split` default true (`client_conf.rs:256-258`),
`UDP_INTERACTIVE_MAX = 512` (`pool.rs:501`), one `UdpHub` and one `SharedEgress` shared by
both features (`main.rs:258-260`).

| # | shared resource | SOCKS user | forward user | starvation condition | effect / magnitude |
|---|---|---|---|---|---|
| R2a | `socks_conn_limiter()` semaphore, **8192** permits process-wide (`socks.rs:24`; SOCKS at `main.rs:470`, forward at `forward.rs:51,79`) | every SOCKS TCP relay; permit held for flow lifetime (idle 300 s) | every forward TCP stream, same permit source, **no per-listener cap** | ≈8192 concurrent forward TCP flows | New SOCKS accepts fail closed: socket dropped with a rate-limited warn (`main.rs:477-480`). Hard outage, fail-fast (try_acquire, no blocking), recovers as forward flows close. One externally reachable forward port can hold the whole budget. |
| R2b | `UdpHub` sessions, **4032** process-wide (`main.rs:257-259`; SOCKS `assoc.rs:12-19`, forward `forward_udp.rs:177`) | every SOCKS `UDP ASSOCIATE` owns one relay socket + hub slot (~8.5 KiB userspace recv buffer each, `assoc.rs:64-75`) | one hub slot **per peer source address**; each listener's `max_sessions` defaults to `udp_assoc_count()` = 4032, i.e. a single listener may take the whole budget (`client_conf.rs:304-330`) | ≥4032 live forward peers | New SOCKS `UDP ASSOCIATE` refused with SOCKS `REP=0x01` (`assoc.rs:14-18`); forward peers dropped with `SESSION_FULL`. A non-loopback UDP forward listener creates one session per unique source, so a burst of ~4 k **spoofed 5-tuples** can pin the budget; idle reaping is 180 s (`ASSOC_IDLE_MS`, `hub.rs:135`; forward sweep `forward_udp.rs:223-246`), so the denial window outlives the burst by up to 180 s. Forward peer client memory is smaller than a SOCKS association (relay = the shared listener), but each peer also creates a **server-side** session (unchanged server code, ~8 KiB/session class), so the operational limit is also server-side. |
| R2c | **interactive UDP egress class = exactly one QUIC connection** (`pool.rs:657-717,724-746`; slot `tcp_slots+0`) | SOCKS UDP ECHO with first payload ≤512 B (the normal ECHO shape) → interactive | any UDP forward whose target port is in `interactive_ports` (DNS `:53` is the obvious one) or whose first payload ≤512 B → same single connection | any forward UDP traffic in the interactive class | Shared congestion window, shared quinn DATAGRAM send queue/backpressure, **shared per-slot dispatcher task** (`dispatcher.rs:1454-1624`; drain budget `LAST_HOP_DRAIN = 32`, `batch.rs:46`) and shared server-side session reader. Under load this is latency/pps coupling proportional to forward traffic; no hard cap on the class beyond quinn queue limits (backpressure verdicts are counted where they happen). Class isolation exists **between** interactive and bulk, not between applications inside a class. |
| R2d | bulk UDP egress shards (2 default) + the per-class round-robin cursor (`pool.rs:695-704`) | SOCKS UDP flows >512 B (or bulk-port targets) | UDP forward bulk-class peers | shared shard bandwidth/driver time | Same cwnd/dispatcher coupling as R2c but spread over 2 connections; the rr cursor is advanced by forward first-sessions too, which can change which shard a later SOCKS association lands on (distribution only, no correctness impact). |
| R2e | `UdpHub` shard RCU maps + `len`/`next` atomics (`hub.rs:274-439`) | association create/destroy, dispatcher cache misses | forward peer create/destroy | high forward peer churn (spoofed sources) | `publish`/`unpublish` clone a whole shard map (`hub.rs:393-405`) and `alloc_sess` CASes the process-wide `len` (`hub.rs:359-391`; `release` decrements at `hub.rs:406-409`). This is **once per session open/close, not per datagram**; established ECHO replies hit the dispatcher's 4096-slot cache (`dispatcher.rs:26,161-218`) and do not touch the hub. Effect: extra cache-line traffic on the shard/`len` line → higher SOCKS association-setup latency under churn; steady-state ECHO unaffected. |
| R2f | TCP pool slots (4 default) + their per-slot current-thread runtimes/drivers (`main.rs:278-368,615-689`) | SOCKS TCP flows, assigned by `pick_tcp_index` (`pool.rs:794-880`) | forward TCP flows, same pool/slots/QUIC connections; interactive-port targets pin to slot 0, bulk targets round-robin | heavy forward TCP traffic on a slot shared with SOCKS flows | Shared congestion window and single-threaded per-slot driver/current-thread runtime: forward bulk load raises SOCKS latency on the same slot and can split throughput. Not a hard admission failure unless stream credit caps (below); flows on *other* slots are isolated. |
| R2g | QUIC bidi stream credit per connection, **8192** (`tuning.rs:145`) | SOCKS flows on that connection | forward flows on that connection | all 8192 streams of one connection used while more flows are pinned/routed there (interactive port targets pin slot 0) | `open_bi()` stalls until a stream closes; SOCKS CONNECT fails at the 5 s open timeout (`socks.rs:166`) and forward at its 5 s (`forward.rs:161-169`). Reachable only with extreme concurrency on one slot (the global TCP semaphore is also 8192). |
| R2h | per-connection rev2 reassembler budget, 256 KiB (`src/mqp/fragment.rs:165`; instance per dispatcher connection `dispatcher.rs:1500`) | fragmented SOCKS UDP replies | fragmented forward UDP replies | forward traffic with inconsistent/large fragmented payloads fills the shared budget | Later fragments on that connection are refused until expiry/eviction; pre-existing shared-budget shape (already documented as UDP-01 in `analysis/issues/udp-dataplane.md`) that forward sessions can now share. Conditional on fragmented forward traffic. |
| R2i | startup coupling | SOCKS listener comes up only if client startup succeeds | forward validation runs earlier and any forward bind/validation failure aborts startup (`main.rs:131-136,374-406`) | malformed `[[tcp_forward]]`/`[[udp_forward]]` or an occupied forward bind port | SOCKS is unavailable — intentional "fail loudly" design, but it is a new way for a forward config typo to take the SOCKS proxy down. No runtime effect once started. |
| R2j | shared counters / reporter | `udp_stats::session()` sessions, drop counters | forward peers bump the same counters (`forward_udp.rs:188`, and drop classes) | — | Diagnostic only: the 60 s "udp associations"/budget lines now include forward peers, so SOCKS-only rates are not separable from the totals. |

**What remains isolated when forwards are configured:** UDP class isolation
(interactive vs bulk) still prevents a *bulk* forward flow from sharing a congestion window
with a *small-payload* SOCKS ECHO flow; TCP pool slots are separate QUIC connections
(4 cwnds) so an aggressive forward flow cannot consume all TCP capacity unless it pins slot 0
or spreads round-robin; per-connection DATAGRAM dispatchers are separate per pool slot; and
the SOCKS association's own recv buffer/task is private. **But same-class traffic shares the
single connection of that class**, which is the intended design for throughput and the main
reason R2c matters operationally.

**Practical mitigations if forwarding is exposed:** keep forward listeners loopback-only
(the code warns otherwise, `forward.rs:44-50`, `forward_udp.rs:36-42`), set per-listener
`max_sessions` well below `max_udp_assocs` (`client_conf.rs:304-330`), raise
`udp_egress_conns` for bulk and avoid putting latency-sensitive UDP forward targets in the
interactive class, and raise `quic_conns`/keep `udp_split=true` for class separation on TCP.

---

## 7. Residual risks and what only a benchmark can settle

| id | sev | risk | status / falsification |
|---|---|---|---|
| R1 | **S3** | Codegen/layout perturbation: +~700 linked feature lines and the extracted function can shift inlining, I-cache and branch layout; the extraction could be outlined instead of inlined. No source-level way to bound the sign or size. | **unprovable statically.** Falsifiable by the bench teammate's interleaved A/B (parent client vs HEAD client, **no** forward config): a delta larger than the A/B noise floor would be codegen, not semantics. Expected: within noise (<0.5–1 %). |
| R2a/R2b/R2f/R2g | **S2** (conditional on forward config) | Hard capacity starvation of SOCKS by forward traffic on shared budgets (TCP semaphore, UDP hub sessions, shared slots/stream credit). | **verified mechanism**, magnitude config-dependent; see §6. Not triggered with empty forward tables. |
| R2c/R2d/R2h | **S2–S3** (conditional) | Shared-class congestion/dispatcher/reassembly coupling when forward UDP traffic is active. | **verified mechanism**; magnitude needs the "with listeners configured + active forward traffic" benchmark, not the idle-listener case. |
| R2i | **S3** | A bad forward config prevents SOCKS startup. | **verified**; intended fail-loud trade-off, worth documenting for operators. |
| R3 | S3 | Long-run drift from the +8 B `StagedReply` / per-reply branches. | **inferred** ≤1 ns/packet; at 1 Mpps ≈ 1 ms CPU/s (0.1 % of one core). Below measurement noise; no mechanism for a non-linear effect (no allocation/atomic/lock changed). |

**Expected benchmark signatures** (cross-check for `analysis/forwarding-audit/bench.md`):
SOCKS5 UDP ECHO (`udp`, `udppaced`, `lat`, `udpmulti`) and TCP ECHO (`tcpecho`, `bulk`)
parent-vs-HEAD with no forward config should be identical within run-to-run noise; a
reproducible >1 % pps or >2 % latency-p50 regression would contradict this audit and should
be attributed to R1 (codegen) and investigated. With **idle** forward listeners configured,
only startup cost differs; with **active** forward traffic, expect the §6 coupling
(latency/pps degradation proportional to forward load in the same class), not a per-packet
SOCKS slowdown.

---

## 8. Evidence ledger

Commands used (read-only, no repo build): `git status`, `git log`, `git show
1135076:<file>`, `git rev-parse`, `git diff --stat/-U0/-numstat 1135076 41031b4`,
`git diff --stat 41031b4 7232088`, `grep`/`sed`/`wc` across `src/`; one standalone
`rustc 1.99.0 -O` layout probe under `/tmp/fwd-audit/` (no repo files touched, no crates
built) for `SocketAddr`/`Option<Arc<T>>`/`Bytes`-shaped field sizes; `bytes`/`arc-swap` field
layouts read from the locked registry sources. No `cargo` command was run — the release build
belongs to the bench teammate (`task-4`), and avoiding it also avoids target-dir lock
contention with them.

| claim | evidence type | confidence |
|---|---|---|
| Only client bin + client config + tests/docs/deps changed; server/wire/engine/TCP-pump untouched | `git diff --stat` incl. path-filtered empty results | verified |
| Every shared-diff hunk classified; 2 dispatcher + 2 udp_stats hunks test-only; tests.rs / integration test excluded | `-U0` diff read hunk-by-hunk + `#[cfg(test)]` checks | verified |
| `send_payload_uplink` is a line-equivalent move (only label arg, closure formatting, `return` vs `return Continue`) | normalized token diff of baseline block vs HEAD function | verified |
| SOCKS relays are always dual-stack IPv6 ⇒ `reply_v6=true` ⇒ same `map_for_dual` behavior | `assoc.rs:45-62`, `policy.rs:140-145`, `lib.rs:333,347-359` | verified |
| No new allocation/lock/atomic/syscall enters a per-datagram or per-reply path | every added line of shared diff scanned; call graphs traced | verified |
| `AssocEntry` 48→48 B; `StagedReply` 104→112 B; staged buffer +256 B once per connection | layout probe + locked crate sources; `dispatcher.rs:1519` | computed (high) |
| Per-reply delta ≈2–3 cycles (0.6–0.9 ns @3.5 GHz); uplink delta 0 inlined / ≤1–3 ns outlined | branch/load counting + release profile (`lto`, `codegen-units=1`) | inferred |
| Shared-budget starvation mechanisms (R2a–R2j) | constants + call sites read (§6 table) | verified mechanism; magnitude config-dependent |
| Magnitude of any codegen perturbation | — | **unprovable statically** (bench task-4) |

**Bottom line.** For the user's question — *does adding the forward listeners degrade SOCKS5
TCP/UDP ECHO when forwarding is not configured?* — the code-level answer is **no**:
`SOCKS5 TCP ECHO: zero delta` (files byte-identical, no new code executes), `SOCKS5 UDP ECHO:
≤~1 ns per reply of always-predicted branches with no new allocation/lock/atomic/syscall, and
no behavior change`. The residual risk is compiler layout noise (needs the A/B benchmark to
rule out), and the genuine contention risk is confined to deployments that actually configure
forward listeners, where forward traffic competes for the same 8192 TCP permits, 4032 UDP
session slots, interactive/bulk UDP egress connections and TCP pool slots as SOCKS.
