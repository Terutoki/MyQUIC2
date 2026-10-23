# Review — Lead shared-layer fixes for the forwarding audit (task-10)

**Scope & method.** Read-only review of the Lead's shared-layer changes in the working tree
(no commits yet; base HEAD `7232088`). Files reviewed: `src/config/tuning.rs` (MAX_SOCKS_CONNS move,
DEFAULT_FORWARD_CONNS), `src/lib.rs` re-export, `src/config/client_conf.rs`
(`max_forward_sessions`/`max_forward_conns`, `ForwardEntry.max_conns`, `TcpForwardSpec.max_conns`,
`forward_session_budget`/`forward_conn_budget`, `MAX_FORWARD_LISTENERS`, asymmetric
`listen_overlaps`, mapped-unspecified target rejection, tests), `src/bin/myquic2-client/main.rs`
(parse-before-bind, two shared budgets, spawn arguments, log lines), `forward.rs` (three-level TCP
admission), `util.rs` (`listen_is_loopback`), `dispatcher.rs` (`raw` in the flush run key),
`assoc.rs` (`#[inline]`), `socks.rs` (constant relocation), `tests.rs` (spawn call sites).
`forward_udp.rs` and README/config samples were read for interface consistency only — they are
being changed in parallel by another teammate (the UDP file gained its own budget/permit work
between two snapshots during this review, so its details are explicitly out of scope and should be
re-read by the verifier after task-6).
Static review only: no `cargo` command was run (tree state is mid-change; the verifier owns
`cargo check`/`fmt`/`clippy`/tests in task-8). Two bind-semantics claims were checked
experimentally on the macOS dev host with Python sockets (`0.0.0.0:P` + `[::1]:P` coexist and stay
family-separated; `[::]:P` with `V6ONLY=0` receives a v4 `127.0.0.1` client as mapped peer);
Linux behaviour is inferred from the same bind semantics and is marked as such.

**Verdict: no S0/S1/S2 defect found in the Lead's shared-layer changes.** The three-level
admission acquires in the documented order and releases every permit exactly once on every branch;
the budget math is correct for all realistic caps; the asymmetric overlap rule matches what
`tcp_listener_dual`/`udp_socket_dual` actually bind; the mapped-unspecified fix works; the
`main.rs` reordering has no side effects; the dispatcher key change cannot alter SOCKS grouping;
the SOCKS hot path gained nothing new beyond a single bool compare on the UDP downlink. Findings
below are S3 (tests/clamps/nits) plus informational notes.

---

## 1. Findings

| # | Severity | Location | Issue | Confidence |
|---|---|---|---|---|
| R-01 | S3 (test gap) | `src/bin/myquic2-client/forward.rs:94-152`, `tests.rs` | The central T-01 fix — three-level admission permit lifecycle (leak/double-release on each Err branch) — has **no test**. Only config-level budget tests were added; `tests.rs` changed only the spawn call sites. The parallel UDP work already has the analogous lifecycle test (`forward_udp.rs` inline tests: `forward_budget_refuses_extra_peers_and_releases_on_drop`), which is a good template. | high |
| R-02 | S3 (edge math vs doc) | `src/config/client_conf.rs:260-275,418-425` | `default_forward_share` uses integer floor: for `max_udp_assocs` ∈ {2,3} it reserves **nothing** (2→2, 3→3) and for 5..7 the reserve is <¼, contradicting "at least 1/4 ... always stays available" (field doc `:138-148`, README). | high |
| R-03 | S3 (clamp inconsistency) | `client_conf.rs:281-285` vs `:357-361`; `:270-275` | An explicit top-level `max_forward_conns = 0` / `max_forward_sessions = 0` silently clamps to 1, while a per-entry `max_conns = 0` / `max_sessions = 0` is a startup error. Also explicit `max_forward_sessions` clamps to `MAX_UDP_ASSOCS`, not to the effective `udp_assoc_count()`, so it can exceed the hub (harmless — hub is authority) and remove the SOCKS reserve (documented in README — "the defaults are the only values that guarantee it" — but not warned at startup). | high |
| R-04 | S3 (observability nit) | `src/bin/myquic2-client/main.rs:390-426` | The TCP startup line carries only per-listener `max_conns` (which defaults to the *aggregate* budget, so `max_conns=6144` reads like a per-listener cap) and no process-wide `max_forward_conns`; the UDP line carries both per-listener and process budget. One start-up line per process (or an extra field) would make the SOCKS reserve visible for TCP too. | high |
| R-05 | S3 (public API) | `src/config/client_conf.rs:213-218,183-195`; `src/lib.rs:41-52` | `TcpForwardSpec` gained a required public `max_conns` field and `ForwardEntry` a public one; both are re-exported from the lib, so downstream struct-literal construction breaks. Crate is bin-oriented, so low impact; `#[non_exhaustive]`/constructors if the lib API is meant to be stable. | high |
| R-06 | Info (residual, not introduced here) | `src/mqp/addr.rs:165-178,205-227` vs `client_conf.rs:510` | Mapped-unspecified rejection is config-layer only. The shared wire codec still accepts `::ffff:0.0.0.0` from a SOCKS-sourced target, and with `allow_private=true` the server may dial its own loopback (audit T-02's defence-in-depth suggestion, deliberately not taken in this round). No regression; `allow_private=false` still filters via `is_global_ip` recursion. | high |
| R-07 | Info (design residual) | `client_conf.rs:357-360`, `forward.rs:66-69` | Per-listener `max_conns` defaults to the *process* forward budget, so admission level 1 is a no-op in the default config and one forward listener can still consume the whole 6144 budget, starving *other forward listeners* — only SOCKS is protected (T-01's headline impact is fixed; cross-listener isolation needs an explicit smaller `max_conns`). Documented as "no extra per-listener constraint". | high |
| R-08 | Info (nit) | `forward.rs:93` before `:101` | `linux::tune_relay_tcp` still runs before admission, so a refused connection pays 2-3 `setsockopt`s it never uses. Move the acquire chain before tuning. Negligible; unchanged from the audited commit. | high |

No item above is a correctness defect in the changed logic; the sections below record what was
verified.

---

## 2. Three-level TCP admission — permit lifecycle (verified correct)

`forward.rs:94-152`: level 1 `listener_limiter` (`:101`) → level 2 `forward_budget` (`:117`) →
level 3 shared `socks_conn_limiter()` (`:130`), then one task holding `(permit, forward_permit,
listener_permit)` (`:148`). Checked every branch:

- level-1 Err: only the `Arc` clone for `try_acquire_owned` is consumed; `continue` drops the
  socket (RST via `abort_tcp`) and **no permit is held** — no leak.
- level-2 Err: `listener_permit` is live; `continue` unwinds the loop body and drops it — **released
  back to the listener semaphore** (not leaked, not dropped twice).
- level-3 Err: `listener_permit` + `forward_permit` are live; `continue` drops both — released,
  never spawn-held.
- Success: all three are **moved** into the async block as the named binding `_permits`; a named
  binding (not `let _ = …`) lives to the end of the task body, so all three are held for the relay's
  lifetime and dropped exactly once at task end (normal end, `Err`, panic/unwind in dev tests, or
  task drop at runtime shutdown). No manual `add_permits`/`forget` exists in the file, so a double
  release is structurally impossible (`OwnedSemaphorePermit` has exactly one owner on every path).
- Refusal ordering is right: a level-1/2 refusal spends no shared permit; level 3 can only refuse
  when SOCKS (+ other forward flows) already holds the rest.
- `Semaphore::new(max_conns)` is safe: config guarantees `1..=MAX_SOCKS_CONNS` (`:357-361`) and the
  process budget is clamped ≥1 (`:281-285`); a hypothetical 0 would refuse all connections, not
  panic. Semaphores are process-wide (one per protocol, created in `main.rs:382-384`) and cloned
  into listeners — the aggregate cap is not multiplied per listener. No blocking acquire → no
  ordering deadlock. Ready to be `cargo check`ed by the verifier.
- **Gap (R-01):** none of this is pinned by a test. Suggested minimum: extract the three acquires
  into a `fn try_admit(&listener, &budget, &shared) -> Result<[OwnedSemaphorePermit; 3], Refusal>`
  (or a test seam taking the three `Semaphore`s) and assert, for each refusal level, that
  `available_permits()` is unchanged for that level and every earlier level after the refusal, and
  that a success holds one permit from each; then one test for release on relay completion. The
  UDP half's `forward_budget_refuses_extra_peers_and_releases_on_drop` (`forward_udp.rs`, inline
  test module) is the same property for the UDP budget and can serve as the pattern.

## 3. Budget defaults / clamps (verified, R-02 edge)

- `MAX_SOCKS_CONNS = 8192` moved to `tuning.rs:198` and re-exported (`lib.rs`); socks.rs's cap,
  `socks_conn_limiter()` and the `MAX_BIDI_STREAMS_PER_CONN` compile assert now share one definition
  across lib+bin — no drift path left.
- `DEFAULT_FORWARD_CONNS = MAX_SOCKS_CONNS - MAX_SOCKS_CONNS / 4 = 6144` exactly 3/4, leaves 2048
  (¼) shared permits for SOCKS; `forward_conn_budget` clamps `1..=8192`; explicit values honored
  (tests `forward_budgets_reserve_a_socks_share_by_default`, `tcp_forward_max_conns_parses_clamps_and_defaults`).
- `forward_session_budget` default = `default_forward_share(udp_assoc_count())` = 3024 at the
  shipped 4032, and it **follows a lowered `max_udp_assocs`** (100→75, 1→1 in tests) — good.
- **R-02**: `(cap - cap/4).max(1)` floors the quarter. For `max_udp_assocs=2|3` the share equals the
  whole cap (no reserve at all), for 5..7 the reserve is 1 (<¼); the doc/README "always keeps a
  reserve" is only true for caps divisible by 4 (and ≥4). Fix:
  `cap.saturating_sub((cap / 4).max(1)).max(1)`; add a loop test for caps 1..=8. Real-world caps
  (≥100) are unaffected.
- **R-03**: top-level knobs use silent `clamp(1, …)` on `0` while per-entry knobs bail on `0` —
  either error for top-level 0 too (consistent with the "a typo must not silently change
  behaviour" principle used for `max_sessions`) or document the clamp. Explicit
  `max_forward_sessions` > effective `udp_assoc_count` is harmless (hub binds first) but leaves the
  reserve off silently; README already says only defaults guarantee the reserve.
- Per-listener `max_conns` default = `forward_conn_budget()` (`:357-360`) and the process budget is
  the same number → level 1 is a no-op by default (R-07); intentional per the field doc, worth
  keeping in mind when judging "one listener can monopolize".

## 4. Asymmetric `listen_overlaps` vs real bind semantics (verified correct)

Code: `client_conf.rs:439-469`. Bind reality: `tcp_listener_dual` uses AF_INET for v4 and
AF_INET6 + `set_only_v6(false)` for **every** v6 bind (`lib.rs:614-636`); `udp_socket_dual_impl_addr`
does the same for UDP (`lib.rs:344-361`). Consequence (verified on the dev host, Linux inferred):
a **concrete** v6 address (e.g. `[::1]`) matches only v6 traffic for that exact address even with
V6ONLY=0; only the **wildcard `[::]`** accepts v4-mapped traffic. So the rule
`(V4,V4) | (V6,V6) => equal or either unspecified`, `(V6 wildcard, V4) => overlap`, else false is
exactly the "can accept the same traffic" relation. Spot checks against the bind experiment:
`0.0.0.0:P` + `[::1]:P` coexist and stay family-separated → allowed (new test
`cross_family_listen_overlap_is_asymmetric`); `[::]:P` + `127.0.0.1:P` genuinely conflicts (verified:
`[::]` received the v4 client as `::ffff:127.0.0.1`) → rejected; `[::]:P` vs `[::1]:P` rejected;
mapped forms unmap to v4 first, so `[::ffff:127.0.0.1]` vs `127.0.0.1` and
`[::ffff:0.0.0.0]` vs `0.0.0.0`/`[::]` are rejected; `[::ffff:0.0.0.0]` vs concrete v6 is allowed
(mapped-any is v4 wildcard on Linux, does not capture v6). Platform note: on hosts where a mapped
listen form binds as a plain v6 address (macOS observation earlier), treating it as v4 can
over-reject a pair, never under-reject — fail-closed, acceptable.
- The anti-capture case from the original audit (shipped `socks_listen = "[::]:1080"` vs a
  `127.0.0.1:1080` forward) still rejects; the old wildcard tests still pass under the new rule.
- `udp_socket_dual` sets no `SO_REUSEADDR` (by design), but the overlap relation is about the
  address/port traffic set, not REUSEADDR, so the same rule holds for UDP.

## 5. Mapped-unspecified target fix (verified)

`client_conf.rs:505-512`: `unmap_listen_ip(addr.ip()).is_unspecified()` rejects
`[::ffff:0.0.0.0]:P`, `[::]:P`, `0.0.0.0:P`; `[::ffff:127.0.0.1]:P` still accepted (private target,
server policy decides). New test cases cover mapped-ANY and `[::]`; verified earlier with a scratch
program that `Ipv6Addr::from(::ffff:0.0.0.0).is_unspecified() == false`, which is why the unmap is
needed. Residual wire-layer acceptance is R-06 (pre-existing, not a regression). Tests in
`client_conf.rs` parse/lower/overlap/clamp/cap suites look consistent with the new rules; the
prebuilt lib test binary is stale now, so they must be run in task-8.

## 6. `main.rs` parse-before-bind reordering (verified no side effects)

Only the pure `c.socks_listen.parse()` moved earlier (`main.rs:373`, before the budgets and the
forward bind loops; previously just before the SOCKS bind). Effects: (a) an invalid `socks_listen`
now fails **before** any forward listener is bound, closing the "forward ports bound, then startup
rejects the config" window — an improvement; (b) the parsed `listen` is used only in the SOCKS log
line after the loops, and the UDP loop's `let listen = spec.listen` shadow is scoped to the loop —
no capture of the wrong value; (c) no moved code had side effects (parse is pure); (d) the QUIC
pool is still started before binds, so the earlier T-06 ordering observation (bind failure detected
after the tunnel starts dialing) is unchanged, not worsened. The two `Arc<Semaphore::new(…)>`
creations are startup-only and ≥1 permit; they are shared (cloned) into listeners, so the aggregate
cap is not multiplied.

## 7. Dispatcher `raw` run key / SOCKS grouping (verified no change)

`dispatcher.rs:750,760`: `raw` joins `(app, reply_v6, sock)` in the run key. A run is "consecutive
staged items that may share one `sendmmsg`"; the only run-key change is a stricter equality, so it
can only **split** a run, never merge two different destinations. `StagedReply.raw` is copied from
`AssocEntry.raw_reply` at staging time (`dispatcher.rs:113,134,434,451`), and `raw_reply` is set only
at construction (`hub.rs:145-169`): SOCKS associations always use `AssocEntry::new` (raw=false,
`assoc.rs:578`), forward listeners use `new_raw` (raw=true). Therefore for SOCKS every item has
`raw == false`, the new predicate is always true, and grouping/order/syscall count are unchanged;
same for a forward listener's peers (all raw=true). The batch invariant (head carries the socket,
trailing `None` items inherit the same entry) is unchanged, so the `.expect("flush run head always
carries the relay socket")` cannot be reached by the new key. Cost for SOCKS: one extra `bool`
compare per consecutive staged item — not measurable.

## 8. SOCKS hot path — anything new?

No. In the working tree, `src/tcp/pump.rs`, `pool.rs`, `auth.rs`, `linux.rs`, `rev2.rs` are
untouched; `socks.rs` changes are the constant move only (runtime-identical: same semaphore size,
same assert); `main.rs` changes are startup-only; `assoc.rs` adds `#[inline]` to the extracted
`send_payload_uplink` (restores the pre-extraction inlining for both call sites — neutral/positive);
`dispatcher.rs` adds one bool compare on the UDP **downlink** path only. TCP SOCKS5 ECHO therefore
sees no change at all; SOCKS UDP sees an unmeasurable instruction-count delta.
Server code, wire format and runtime deps remain untouched.

## 9. Interface consistency with the parallel `forward_udp.rs` work (read-only check)

At review snapshot, `spawn_udp_forward` already accepts the 6th `Arc<Semaphore>` argument in the
same position as `main.rs:413-420` passes it; it uses `listen_is_loopback`; its peer admission is
ordered listener cap → forward budget → `UdpHub::alloc_sess`, drops the budget permit before
returning `HubFull`, stores the permit in `PeerSession._fwd_permit` so `Drop` releases it with the
hub slot, and counts `REFUSED` vs `SESSION_FULL` with separate log windows. This matches the Lead's
TCP contract. Because that file is still being edited by the UDP teammate (it changed during this
review), final review of its details belongs to the UDP auditor / verifier; `tests.rs` only gained
the spawn-call-site arguments, and the UDP tests appear to be inline in `forward_udp.rs`, so no
`tests.rs` write conflict is visible now.

## 10. For task-8 (verification hand-off)

1. `cargo fmt --check` / `clippy -D warnings` on the final tree (new code adds several
   near-duplicate rate-limit static fns in `forward.rs`; clippy usually tolerates them, but this is
   the first full build).
2. Run the new config tests plus the client suite; then the E2E `forward_e2e` tests (config strings
   are unchanged/backward-compatible: new knobs are optional and old E2E configs still parse).
3. Ask for/adjust the R-01 admission test before calling T-01 "fixed": the permit-lifecycle
   property is the whole point of the change and is currently only provable by inspection.
4. Add a small-caps test for R-02 (caps 1..=8) and decide the R-03 `0`-clamp policy.
