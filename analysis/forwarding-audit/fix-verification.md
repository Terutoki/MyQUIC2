# Fix-round verification — forwarding audit fixes (task-8)

**Verdict: GO.** Formatting, workspace check, clippy (`-D warnings`) and every test target are
green on the fix-round tree; the admission/eviction/config changes match what the review file asked
for and no permit leak, double release or SOCKS-path regression was found. One non-code item left:
the README's "555 tests" badge/line is stale (new total **566**) and must be refreshed by the Lead
(not edited here, per instructions). The fix round is still uncommitted on top of HEAD `7232088`
(no source files were modified during this verification; only this report was written).

**Tree under test.** HEAD `7232088` + uncommitted fix-round diff:
`14 files changed, 1408 insertions(+), 154 deletions(-)`; `git diff` fingerprint
`7e666a08e5b8f612d90e96ca69a20247a8387eeb450247817e2b32fcac1c3e3c`. All commands below ran on
that same tree in this order; no file changed between runs (no `cargo fmt` changes were needed).

---

## 1. Command results

| # | Command | Result |
|---|---|---|
| 1 | `cargo fmt --all -- --check` | **pass**, zero output / no files reformatted (exit 0) |
| 2 | `cargo check --workspace --all-targets` | **pass**, `Finished dev profile`, 0 errors / 0 warnings (exit 0) |
| 3 | `cargo clippy --workspace --all-targets -- -D warnings` | **pass**, `Finished dev profile`, 0 warnings (exit 0) |
| 4 | `cargo test --workspace` | **pass**, exit 0, 0 failures, 0 build warnings; 5 targets: lib, client bin, server bin, `forward_e2e`, doc-tests |
| 5 | `cargo test --lib` | **273 passed**, 0 failed |
| 6 | `cargo test --bin myquic2-client` | **168 passed**, 0 failed |
| 7 | `cargo test --bin myquic2-server` | **119 passed**, 0 failed |
| 8 | `cargo test --test forward_e2e` | **6 passed**, 0 failed |
| 9 | `cargo test --lib client_conf` | **11 passed**, 0 failed (7 pre-existing + 4 new) |
| 10 | `cargo test --bin myquic2-client forward_udp` | **4 passed**, 0 failed (the new UDP inline tests) |
| 11 | `cargo test --bin myquic2-client admission` | **3 passed**, 0 failed (the new TCP admission tests) |

`cargo test --workspace` targets as reported: `unittests src/lib.rs`, `unittests
src/bin/myquic2-client/main.rs`, `unittests src/bin/myquic2-server/main.rs`, `tests/forward_e2e.rs`,
`Doc-tests myquic2` (0 doc-tests). **Total: 273 + 168 + 119 + 6 = 566 tests, all green.**

Baseline comparison (HEAD `7232088`): 555 = lib 269 + client 161 + server 119 + E2E 6.
New: **+4 lib** (`forward_budgets_reserve_a_socks_share_by_default`,
`tcp_forward_max_conns_parses_clamps_and_defaults`, `cross_family_listen_overlap_is_asymmetric`,
`forward_listener_count_is_capped`) and **+7 client bin** (3 `forward::tests::admission_*`, 4
`forward_udp::tests::*`). Server and E2E counts unchanged. **README action for Lead:** line 9 badge
`Tests-555_passing` → `Tests-566_passing`, line 1062 `**555 tests** ... (lib 269 + client 161 +
server 119 + 6 ...)` → `(lib 273 + client 168 + server 119 + 6 ...)`.

E2E test names (all pass): `invalid_forward_config_fails_client_startup`,
`private_target_fails_fast_without_allow_private`,
`tcp_forward_e2e_roundtrip_half_close_and_parallel`,
`udp_forward_e2e_roundtrips_an_8k_payload`, `udp_forward_e2e_two_peers_get_their_own_replies`,
`udp_forward_listener_survives_peer_churn`.

New tests (all pass, names quoted for the README/PR): `config::client_conf::tests::forward_budgets_
reserve_a_socks_share_by_default`, `...::tcp_forward_max_conns_parses_clamps_and_defaults`,
`...::cross_family_listen_overlap_is_asymmetric`, `...::forward_listener_count_is_capped`,
`forward::tests::admission_holds_one_permit_from_each_level_until_released`,
`forward::tests::admission_refusals_release_every_earlier_level`,
`forward::tests::admission_refuses_at_the_outermost_exhausted_level`,
`forward_udp::tests::forward_budget_refuses_extra_peers_and_releases_on_drop`,
`forward_udp::tests::listener_cap_evicts_only_a_peer_idle_past_the_floor`,
`forward_udp::tests::eviction_scan_is_throttled_against_a_refusal_flood`,
`forward_udp::tests::recv_error_classification_covers_resource_errors_but_not_broken_sockets`.

---

## 2. Review of the new hunks (vs `review-shared-fixes.md`)

### R-01 (three-level TCP admission lifecycle) — ADDRESSED, mechanism verified

`forward.rs:131-171` adds `TcpAdmission { listener, forward_budget, relay }`, `TcpPermits` and
`TcpRefusal`; `try_admit()` (`:162-177`) acquires per-listener → forward budget → shared relay with
`?` after each `try_acquire_owned`, so the earlier `OwnedSemaphorePermit` locals are dropped on any
Err return; success returns all three. `spawn_tcp_forward` now takes `forward_budget` **and**
`relay_limiter` as parameters (`:46-47`) — `main.rs:387` passes `socks_conn_limiter().clone()`
explicitly, so the "relay permit" level is the exact same process semaphore SOCKS uses (no second
global), and the seam is testable with small semaphores (as the new tests do). In the accept loop the
returned tuple is moved into the relay task as the named binding `_permits` (`forward.rs:116`), so
all three permits live exactly as long as the relay and are dropped exactly once on task end
(normal end, error, panic in dev tests, runtime task drop). `tune_relay_tcp` now runs **after** a
successful admission (`:110` vs `:95`), so refused connections no longer pay `setsockopt`s (R-08
addressed). New tests assert permit counts before/after release and after refusals at each level —
`admission_refusals_release_every_earlier_level` is exactly the leak/double-release guard I asked
for. **No contradiction with the review file.**

### R-02 (budget reserve edge) — ADDRESSED

`client_conf.rs:425-427`: `default_forward_share(cap) = cap.saturating_sub((cap/4).max(1)).max(1)`,
so caps 2..=8 now keep a nonzero SOCKS reserve (cap 2 → 1, cap 3 → 2, cap≥8 → at least one slot;
only the degenerate cap=1 gives forwarding the whole budget, unavoidable and documented). Test loops
`cap in 1usize..=8` and asserts `forward <= cap` plus `forward < cap` for `cap >= 2`
(`client_conf.rs:843-853`); it passes. Field docs require only "3/4 at the shipped 4032" which
remains exact (3024). **No contradiction.**

### R-04 (startup observability) — ADDRESSED

`main.rs:397-403` now emits
`tcp_forward <listen> -> <target> via QUIC (max_conns=…, forward_conn_budget=…, shared_relay_limit=8192, bound)`
(the UDP line already carried `forward_session_budget=…`). Both budgets are the same numbers the
process actually built its semaphores from (`main.rs:382-383`). **No contradiction.**

### R-03 / R-05 / R-06 / R-07 (informational items from the review) — not changed

As expected for non-defects: top-level budget knobs still silently clamp `0` → 1 while per-entry
caps error on `0`; `TcpForwardSpec` still has the new public field; mapped-unspecified is still
rejected only at config layer; per-listener `max_conns` still defaults to the process budget. None of
these is a regression or correctness bug; no action needed for this round (README documents the
defaults/reserve behaviour). **No contradiction.**

### UDP budget / eviction (task-6) — reviewed, no defect found

- **Budget permit is a lifetime permit**: acquired in `try_admit_peer` (`forward_udp.rs:266`),
  moved into `PeerSession._fwd_permit` on success (`:305`), released by `Drop` when the entry is
  removed (idle sweep, eviction, `shutdown_all`, task drop). On a hub-full refusal the code
  `drop(fwd_permit)` before returning `Err` (`:285`), so the failed-retry path cannot leak it;
  the listener-cap / budget refusal paths never acquire a shared hub slot. Verified by
  `forward_budget_refuses_extra_peers_and_releases_on_drop` (permit count returns to 1 on peer drop;
  a refusal installs no session) — passes.
- **Eviction cannot take a live peer**: `evict_one_idle` (`:339-392`) skips any peer whose
  `AssocEntry::replied` is set (reply activity not yet folded by the 30 s tick), and only considers
  peers with `idle_ms(now) >= EVICT_MIN_IDLE_MS` (5 s, `:693`); a victim is the *oldest* such peer.
  Verified by `listener_cap_evicts_only_a_peer_idle_past_the_floor`: a fresh peer is refused without
  eviction, a peer with a set `replied` flag is kept past the floor, and only after the flag is
  folded is it evicted to admit the new source (hub + budget slots both returned).
- **Eviction scan cannot become its own DoS**: `EVICT_SCAN_INTERVAL_MS = 100` (`:711`) is checked
  *before* any per-peer work (`:339-347`), so a spoofed-source refusal flood walks the table at most
  once per interval; `eviction_scan_is_throttled_against_a_refusal_flood` asserts a throttled refusal
  does no scan/eviction and moves no stamp, then that the next scan after the interval evicts and
  admits. Passes.
- **No 20 ms ICMP stall**: the transient-recv-error arm now `continue`s immediately, yielding only
  every 32 consecutive errors (`forward_udp.rs` run loop), and `recv_error_is_transient` adds
  `ENOBUFS`/`ENOMEM` raw codes + `ErrorKind::OutOfMemory` so a resource error is retried rather than
  declared fatal. `recv_error_classification_covers_resource_errors_but_not_broken_sockets` passes.
- Single-probe steady path: `handle_datagram` does one `get_mut` fast path and re-probes only on a
  miss/write; `send_peer_payload` takes disjoint refs. No duplicate `contains_key`.

### SOCKS hot path — nothing new (re-confirmed)

`src/tcp/pump.rs`, `pool.rs`, `auth.rs`, `linux.rs`, `rev2.rs`, `hub.rs` are untouched in the diff.
Shared-file changes: `socks.rs` constant relocation only (same semaphore size/assert), `assoc.rs`
`#[inline]` on the extracted `send_payload_uplink`, `dispatcher.rs` one `raw` bool compare added to
the flush run key (SOCKS entries are always `raw=false`, so grouping is unchanged — see
`review-shared-fixes.md` §7), `main.rs` startup-only budgets/logging. SOCKS5 TCP ECHO path is
code-identical to baseline. No new per-connection locks/allocations.

---

## 3. Residual observations (non-blocking)

1. **README test count is stale** — 555 → **566** (lib 273 + client 168 + server 119 + E2E 6). The
   Lead should also refresh the badge at README line 9 and the verification line at line 1062. (I did
   not edit README, per task instructions.)
2. **Fix round is uncommitted** (14 modified files on top of `7232088`); the final commit/release
   step is the Lead's.
3. New tests live inline in `forward.rs` / `forward_udp.rs` rather than `tests.rs` (only spawn
   call-site args changed there). That is a deliberate, testable-seam choice; no conflict with the
   existing test layout, but the README verification section lists counts only, so no doc drift
   beyond item 1.
4. The `default_forward_share` doc now says "everything but a quarter" while the implementation
   floors the reserve at one slot (caps 5..=7 reserve < 25% but > 0). The doc's next sentence covers
   the floor; no change requested.

**Final: GO for merge/release after the README count refresh and commit.**

---

## Addendum — final tree re-verification (post-B4 eviction fold, task-12)

**What changed since §§1-4.** HEAD still `7232088`, fix round still uncommitted; new `git diff`
fingerprint `53df4e0824085b55611815fcb01d2a3ee1934b4a2d6591c02319a9f294abeabe` (was
`7e666a08…`), `14 files changed, 1406 insertions(+), 156 deletions(-)` (was 1408/154). Per-file
stat comparison against the verified tree shows exactly two files changed — `README.md` (+4 lines:
the 555→566 test-count refresh requested in §3 item 1) and `src/bin/myquic2-client/forward_udp.rs`
(the B4 eviction `replied`-fold + its updated inline test); every other file's diff stat is
byte-for-byte the same as in the verified round, so no other source change landed.

**Final-tree gates (all re-run on the fingerprint above, same tree, no edits between runs):**

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | **PASS**, 0 output / nothing reformatted |
| `cargo check --workspace --all-targets` | **PASS**, 0 errors / 0 warnings |
| `cargo clippy --workspace --all-targets -- -D warnings` | **PASS**, 0 warnings |
| `cargo test --workspace` | **PASS** exit 0: 273 + 168 + 119 + 6 (+0 doc-tests) = **566 green, 0 failed** |
| `cargo test --lib` / `--bin myquic2-client` / `--bin myquic2-server` / `--test forward_e2e` | **273 / 168 / 119 / 6 passed**, 0 failed each |
| `cargo test --bin myquic2-client listener_cap_evicts_only_a_peer_idle_past_the_floor` (updated test) | **1 passed** |
| `cargo test --bin myquic2-client forward_udp` (all inline UDP tests) | **4 passed** |

Counts are unchanged from §1 (test updated, not added; no new tests): total remains 566.

**Review of the final eviction fold (`forward_udp.rs:343-394`).** The per-peer body is now

```rust
if !peer.entry.idle_since_tick(now, EVICT_MIN_IDLE_MS) {
    continue;
}
let idle = peer.entry.idle_ms(now);
if victim.is_none_or(|(_, oldest)| idle > oldest) { victim = Some((*src, idle)); }
```

`AssocEntry::idle_since_tick` (`hub.rs:201-212`) is the idle sweep's own fold: `replied.swap(false)`
and, iff the flag was set, `last.store(now)`, then `idle_ms(now) >= limit`. Checked against the
three required properties:

1. **A peer with `replied` set is not evicted in that scan.** The fold stamps `last = now`, so
   `idle_ms == 0 < EVICT_MIN_IDLE_MS` → the function returns false → `continue`; it can never become
   the victim in that call. Verified by the updated test: at `later` the flag is set, the scan folds
   it, the peer is kept and the new source is still refused (`forward_udp.rs:884-940`).
2. **It becomes evictable after `EVICT_MIN_IDLE_MS` with no further activity.** The fold's `last`
   stamp is the new baseline; the next scan ≥5 s later (production `now` is coarse = 1 s granularity,
   so worst case ≈6 s; the 100 ms scan throttle can only *delay* a scan, never permit an earlier
   eviction) sees `replied == false` (already consumed) and `idle >= 5000` → candidate. The updated
   test proves exactly this: after another 5001 ms it evicts the peer, admits the new source, and
   asserts the hub slot and forward-budget permit were returned
   (`fwd.hub.len == 1`, `available_permits == MAX_UDP_ASSOCS - 1`) — so the B4 34.5 s ⇒
   ~5-6 s improvement follows from the code and is pinned by the test.
3. **A receive-only flow is not evicted while replies keep arriving.** Each dispatcher reply sets
   `replied` again; every scan that observes it folds and re-stamps `last = now`, so `idle` never
   reaches the floor while replies arrive more often than `EVICT_MIN_IDLE_MS`. The fold is
   race-safe in the safe direction: `swap(false)` then `store(now)` — a reply landing after the swap
   sets the flag again for the next scan; a reply landing before it is folded into this stamp; no
   activity is lost and no peer is evicted on activity a later scan will see. Fold activity can only
   *delay* eviction, never advance it. Interaction with the 30 s idle sweep is unchanged (the sweep
   uses the same fold for `ASSOC_IDLE_MS`; a scan that folds first merely refreshes `last`, so the
   180 s reap is not brought forward either). Intended nuance, not a defect: a "receive-only" peer
   whose replies are sparser than the 5 s floor is treated as idle at the floor like any other
   bidirectional-silence peer (that is `EVICT_MIN_IDLE_MS`'s documented contract, and the updated
   test covers the ≥5 s case).

No defect found in the changed hunk or the updated test.

**Do the earlier fix-verification results still hold?** Yes. Only `forward_udp.rs` (this fold + test)
and README counts differ from the verified tree; the `forward.rs` admission seam, `main.rs` budgets/
relay-limiter passing, `client_conf.rs` budget/overlap/target logic, dispatcher `raw` key and the
untouched SOCKS TCP path (§§1-4 of this report and §4 of the earlier sections) are unchanged, and
all gates re-ran green on the final tree. §1 counts stand at 566.

Minor, non-blocking, pre-existing (not introduced by this round): README line 504 (§17 Verification
snapshot) still says "The current tree has **530 tests** (lib 262 + client 149 + server 119)"; that
line is unchanged since HEAD and now conflicts with the refreshed badge/verification line (566). An
optional docs cleanup for the Lead; it does not affect the gates.

**Addendum verdict: GO — the final tree (with the B4 eviction fold) passes fmt/check/clippy and
566/566 tests, the fold is correct, and the earlier verification conclusions are unaffected. The
fix round is ready to commit/close once the Lead is satisfied with the pre-existing README:504
snapshot line (optional).**
