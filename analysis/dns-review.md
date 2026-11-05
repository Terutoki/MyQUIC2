# DNS subsystem review — correctness and performance

Scope: `src/dns/**` (`key`, `memo`, `store`, `resolve`, `policy`, `stats`) and every
DNS consumer on the data path — server `forward.rs` / `tcp.rs` / `pin.rs` /
`accept.rs`, client `dispatcher.rs` / `auth.rs`. Baseline `8f52978` (v0.2.3),
clean tree.

Method:

* read every path through `resolve_all_cached`, the sync probe
  (`lookup_cached_fast*`), the negative-verdict/epoch protocol and the
  `DnsGate` coalescer;
* checked the assumptions the module rests on against the actual dependency
  sources (`moka 0.12.16`, `hickory-resolver 0.26.3`);
* `cargo check --all-targets` — clean; `cargo test --lib dns` — 47/47 pass;
* ran `examples/dns_probe_bench` for the per-datagram probe cost.

## Findings

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| D1 | `DNS_CACHE_MAX_ADDRS` truncation is family-blind: a large answer can lose the *whole* non-preferred family, defeating the dual-stack fallback the rest of the code is built around | medium | **fixed** |
| D2 | `resolve_server_addrs_fresh` removes a negative entry without bumping `NEG_EPOCH`, breaking the module's own invalidation invariant | low | **fixed** |
| D3 | `parked_delivered` counts resource refusals and cancelled waiters as deliveries | low (stats) | **fixed** |
| D4 | `refresh_registry` never shrinks below `DNS_CACHE_MAX` and prunes O(n) under the process-global lock | low (perf/mem) | **fixed** |
| D5 | `upstream_resolver()` clones the failure reason `String` on every lookup of the `getaddrinfo` fallback state | nit | **fixed** |

Fixes landed in this tree: `src/dns/resolve.rs`, `src/dns/store.rs`,
`src/bin/myquic2-server/forward.rs`, `src/bin/myquic2-server/tests.rs`. See
[Fixes landed](#fixes-landed) at the end for what changed and which tests pin
it.

### D1 — the retained-set cap can drop an entire address family

`prepare_cache_ips` sorts preferred-family-first and then keeps a flat prefix of
32 (`src/dns/resolve.rs:1099-1104`):

```rust
ips.sort_by_key(|ip| pref.sort_key_ip(*ip));
ips.truncate(DNS_CACHE_MAX_ADDRS);   // 32
```

With the default `IpPreference::Ipv6`, an answer carrying **32 or more AAAA
records drops every A record**; with `dns_ip_preference = "ipv4"` the mirror
happens. The cap itself is deliberate and pinned by a test
(`resolve.rs:2351`, which asserts the 40-v6 + 40-v4 answer comes back *all
IPv6*), but two consumers explicitly depend on the other family surviving the
answer:

* **client dial** — `resolve_server_addrs(&server_str, DIAL_ADDR_CANDIDATES)`
  with `DIAL_ADDR_CANDIDATES = 3` (`bin/myquic2-client/auth.rs:50,80`). The
  three candidates come from the capped set, so on a host whose endpoint
  publishes ≥32 AAAA records the client's *control connection* has no IPv4
  candidate at all. On a network with an advertised-but-unrouted IPv6 path
  (`ENETUNREACH`, exactly the case `mark_unreachable` and the stale-list refresh
  exist for) the reconnect loop can never fall back, and
  `resolve_server_addrs_fresh` re-resolves into the same truncated set.
* **server TCP** — `tcp.rs:117-147` interleaves families specifically so that
  "a flat prefix cut would [not] starve the non-preferred family whenever
  upstream returns more than 8 preferred-family records". That reasoning is
  correct but no longer reachable: the starvation already happened in
  `prepare_cache_ips`, before `tcp.rs` ever sees the list.

The `store.rs:173-178` note ("32 is far more than any consumer uses … the
dropped tail only bounds memory, never a lookup's ability to find *a* usable
address for a real service") holds for *finding an address*, not for *keeping a
path to the other family*.

Fix — one pass, cap per family, which also removes the second problem below:

```rust
fn prepare_cache_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let pref = ip_preference();
    let (mut head, mut tail): (Vec<_>, Vec<_>) = ips
        .into_iter()
        .partition(|ip| pref.sort_key_ip(*ip) == 0);
    let half = DNS_CACHE_MAX_ADDRS / 2;
    tail.truncate(half);                       // keep room for the other family
    head.truncate(DNS_CACHE_MAX_ADDRS - tail.len());
    head.extend(tail);                         // stable order inside each family
    head
}
```

Note the second, independent benefit: today the *whole* answer is materialized
and sorted before being cut (`lookup.iter().collect()` at `resolve.rs:348`, then
`sort_by_key` over an attacker-sized `Vec` — a 64 KiB TCP-retried answer is
~4 000 records). The partition form is one linear pass and never allocates the
tail it discards.

The test at `resolve.rs:2351` encodes the current behaviour and would need
updating; `seeded_name_retains_at_most_the_cap` (single family) keeps passing.

### D2 — one negative-cache removal site skips `bump_neg_epoch`

The epoch protocol is documented as "bumped whenever a name's negative entry is
removed because it resolved again" (`src/dns/memo.rs:90-96`), and three of the
four removal sites honour it:

* `resolve_all_cached` init success — `resolve.rs:1043-1045`
* `refresh_positive` — `resolve.rs:1297-1299`
* `withdraw_refusal_if_answered` — `resolve.rs:1457-1459`

The fourth does not (`resolve.rs:1525-1527`):

```rust
let host_key = dns_host_key_owned(host);
let _ = positives().remove(host_key.as_str()).await;
let _ = negatives().remove(host_key.as_str()).await;   // no bump_neg_epoch()
```

Consequence: every other worker thread whose per-`(host, port)` memo holds a
`Negative` slot for that name keeps answering `CachedLookup::Negative` for the
rest of the verdict's life (up to `DNS_NEG_TTL` = 10 s) — the exact failure the
epoch exists to prevent (`memo.rs:64-74`). In practice the affected name is the
client's own `server_addr`, which nothing reads through the sync probe, so the
user-visible impact is small; but the invariant is load-bearing and this is the
one site that violates it. One-line fix:

```rust
if negatives().remove(host_key.as_str()).await.is_some() {
    bump_neg_epoch();
}
```

### D3 — `parked_delivered` over-counts

`forward.rs:894-900` treats *every* `None` from
`deliver_resolved_server_dgram` as "the datagram left". But `None` is also
returned for

* a cancelled waiter before the send (`forward.rs:990-992`) and after session
  creation (`forward.rs:1021-1023`), and
* a session-creation refusal (`forward.rs:1013-1018`), which is a *resource*
  refusal that the doc for that function explicitly says is "not a DNS verdict".

So the 60 s line's `parked (N delivered)` can claim deliveries that never
happened — precisely the number an operator would use to judge whether parking
is worth its memory. A three-state return (`Delivered` / `Unusable(Duration)` /
`NotDelivered`) removes the ambiguity; the call sites already branch on the
`Option`.

### D4 — `refresh_registry` growth and lock scope

`claim_refresh` (`resolve.rs:1202-1222`) prunes the map only when it is already
at `DNS_CACHE_MAX` (10 240 entries):

```rust
if registry.len() >= DNS_CACHE_MAX {
    registry.retain(|_, until| *until > now);
}
```

So a long-lived relay that has once seen 10 240 distinct stale names keeps the
map at that size forever, holding one `Arc<str>` (the full name) plus an
`Instant` per entry — a few hundred KiB to a couple of MiB that is never
reclaimed, and an O(10 240) `retain` executed while the *process-global* mutex
is held. The mutex itself is only taken on stale hits (at most one per flow per
`DNS_STALE_MEMO_TTL` = 5 s), so contention is low; the cost is memory and a
periodic latency spike on the stale path.

Cheap fix: prune on a size *and* liveness condition, e.g. `if registry.len() >
256 && registry.len() > live * 2`, or replace the map with a
`moka::future::Cache<Arc<str>, Instant>` with a 10 s TTL — the crate already
depends on moka and this is exactly a TTL map.

### D5 — allocation on the degraded path

`upstream_resolver()` returns `Err(reason.clone())` (`resolve.rs:707-713`), so
every lookup of a process running on the `getaddrinfo` fallback allocates the
reason string before it even logs. Store the reason as an `Arc<str>` in
`ResolverGen` (or return `&str` with the guard's lifetime) — it is the one path
where a per-lookup allocation is least welcome.

## Verified sound (no action)

These were the places most likely to hide a bug; each was checked against the
dependency source or the call sites, and holds:

* **moka does not cache `try_get_with` errors** (`moka-0.12.16/src/future/cache.rs:1321`,
  and its own test at :4050 — "Nothing will be inserted to the cache"). The
  negative cache really is the only refusal authority, and the
  positive/negative split is not silently violated by the single flight.
* **hickory bounds one attempt end-to-end**, not per nameserver
  (`hickory-resolver-0.26.3/src/name_server_pool.rs:313`,
  `let deadline = Instant::now() + self.cx.options.timeout`). The
  `DNS_QUERY_TIMEOUT × (1 + DNS_LOOKUP_ATTEMPTS) < DNS_LOOKUP_TIMEOUT` invariant
  at `store.rs:210` therefore holds with any number of configured nameservers —
  stronger than the comment claims, not weaker.
* **A failed `build()` cannot be produced in this feature set**: with `__tls`
  and `__dnssec` off, `ResolverBuilder::build` has no reachable `?`
  (`resolver.rs:495-580`), so `ResolverGen::error` is only reached from an
  unreadable system config — and that generation carries an *empty* fingerprint,
  which makes `spawn_resolver_watch` rebuild as soon as the config becomes
  readable. No sticky-fallback hole.
* **An empty `resolv.conf` does not produce a resolver with zero nameservers**:
  `into_resolver_config` returns `Err("no nameservers found in config")`
  (`system_conf/unix.rs:65`), which lands in the `getaddrinfo` fallback.
* **SSRF before pinning**: both production `pin_cache` sites
  (`accept.rs:887`, `accept.rs:3392`) take the address from
  `forward_server_dgram`'s return value, which is only produced after
  `is_global_ip_cached` passed; `resolve_pin`'s two arm sites filter before
  `pin_arm`. The "no recheck on a pin hit" argument (`pin.rs:372-381`) is sound.
* **The `getaddrinfo` permit cannot be over-admitted by a timeout**: it is
  acquired *inside* the blocking closure (`resolve.rs:420`), so a dropped future
  does not release it early.
* **The negative-memo epoch re-check is inside the thread-local borrow**
  (`memo.rs:313-319`), which closes the probe→write window; a bump costs each
  `(host, port, thread)` exactly one async-path probe to re-memoize, so the
  process-global epoch is bounded, not a herd.

## Measured cost of the per-datagram probe

`examples/dns_probe_bench`, release build, this machine (20 M iterations each):

```
warm hit (per-datagram)        19.66 ns/op
cold miss (no clock read)      15.29 ns/op
coarse_millis() alone           1.01 ns/op
warm hit,  4-byte host         14.19 ns/op
warm hit, 50-byte host         19.47 ns/op
negative hit (per-datagram)    19.18 ns/op
```

Two conclusions worth recording:

* The probe is **not** a hot-path problem: ~20 ns for a 50-byte name is ~2 % of
  one core at 1 Mpps, and it is dominated by the per-byte work (lowercase copy
  into the stack buffer, then the hash over the same bytes — two passes), not by
  the clock (`coarse_millis` is 1 ns). Any further gain would come from folding
  the lowercasing into `dns_memo_hash`'s chunk loop, which is not worth the
  readability cost at this number.
* A **miss is cheaper than a hit** (15.3 vs 19.7 ns): the miss skips the clock
  read and fails the compare on the hash. The comment in `resolve.rs:6-11` that
  "a memo hit costs two atomic loads and a byte compare" is therefore
  optimistic — the hit also pays `coarse_millis()` — but at 1 ns the wording is
  immaterial. (`memo.rs:228-232`'s "without any clock read" means *without a
  precise* clock read; worth a word if that comment is next touched.)

## Suggested order

1. D2 and D3 — one-line/one-enum fixes, no behavioural risk.
2. D1 — decide the policy (per-family cap vs. current flat prefix), then land it
   with the test at `resolve.rs:2351` updated.
3. D4/D5 — opportunistic.

---

## Fixes landed

Verification for the whole change set: `cargo fmt --check` clean,
`cargo clippy --all-targets` clean, `cargo test --lib` 387 passed,
`cargo test --bin myquic2-server` 165 passed (1 ignored),
`cargo test --bin myquic2-client` 213 passed, `cargo test --test forward_e2e`
7 passed, `cargo test --test rev3_e2e` 8 passed + 1 environmental failure
(`rev3_hard_server_restart_reconnect_does_not_burn_cores` shells out to `ps`,
which this sandbox denies: `ps: operation not permitted`).

### D1 — `prepare_cache_ips` caps per family (`src/dns/resolve.rs`)

Replaced the sort-then-flat-truncate with a single `partition` on the preference
key plus a per-family budget: `other` gets what `preferred` leaves after taking
at most half, then `preferred` takes whatever `other` did not need. A
single-family answer still retains the full 32; a mixed one retains 16 + 16.

Two secondary effects, both wanted: the O(n log n) sort over an
attacker-sized answer is gone (one linear pass), and `store.rs`'s
`DNS_CACHE_MAX_ADDRS` docs now describe the per-family contract instead of
claiming the dropped tail "still gets enough of them for dual-stack".

The client's dial list needed a second half. `resolve_server_addrs` took a flat
`take(max)`, so with `DIAL_ADDR_CANDIDATES = 3` a v6-rich answer still produced
three IPv6 candidates and no IPv4 one — the cache no longer *lost* the A
records, but the dial loop never saw them. New `dial_candidates` (mirroring the
server's `tcp.rs` alternation) interleaves the families inside `max`, so three
candidates are `[v6, v4, v6]`. `resolve_server_addrs_fresh` uses it too, so the
"the answer is the suspect" path produces the same shape.

Tests: `cache_prefix_caps_each_family_and_keeps_the_other_one_reachable`
(replaces the old prefix test), `dial_candidates_interleave_families_within_the_cap`.
`seeded_name_retains_at_most_the_cap` still passes unchanged.

### D2 — epoch bump on the forced-refresh path (`src/dns/resolve.rs`)

`resolve_server_addrs_fresh` now bumps `NEG_EPOCH` when it actually removed a
negative entry, matching the other three removal sites.

Test: `a_forced_refresh_invalidates_the_negative_memo` — seeds a verdict, forces
a refresh, asserts the epoch moved and the store is clear; the memo assertion
runs when `localhost` resolves (it is the only offline-resolvable,
non-literal name).

### D3 — `DeliveryOutcome` (`src/bin/myquic2-server/forward.rs`)

`deliver_resolved_server_dgram` returns `Delivered` / `Unusable(Duration)` /
`NotDelivered` instead of `Option<Duration>`. `parked_delivered` is now bumped
only for `Delivered`, so a session-creation refusal, a cancelled waiter, or a
send that every candidate rejected is no longer reported as a delivery. The
`DnsGate` still sees exactly the same verdict (`outcome.unusable()`), and the
"every candidate failed" case — previously `None`, i.e. indistinguishable from
a delivery — is now explicitly `NotDelivered`. Flattened the `if let Some(sock)`
nesting while there.

Tests updated: `cancelled_generic_dns_waiter_does_not_create_a_session` asserts
`NotDelivered`, `generic_dns_slow_path_clamps_the_session_memo_to_the_entry_life`
asserts `Delivered`.

### D4 — self-bounding refresh registry (`src/dns/resolve.rs`)

`RefreshRegistry { entries, sweep_at }`: the sweep runs at `sweep_at`, which is
`2 × live` after each sweep with a 256-entry floor and a `DNS_CACHE_MAX` ceiling
(a `const` assert keeps the floor below the cap, so the sweep can never be
scheduled past the hard cap). Amortized O(1) per claim, and the resident size is
bounded by roughly twice the live set instead of pinning 10 240 names forever.

Test: `the_refresh_registry_sweeps_once_its_entries_have_cooled` — 1 024 claims
with a monotonically advancing clock leave at most one floor's worth of entries.
Both refresh tests now hold `DNS_CACHE_TEST_LOCK` (the registry is
process-global and one test sweeps it).

### D5 — `Arc<str>` reason (`src/dns/resolve.rs`)

`ResolverGen::resolver`'s error arm and `upstream_resolver`'s return type carry
`Arc<str>`, so the fallback path clones a refcount instead of allocating the
reason on every lookup.

### Left as-is (reported, not changed)

While fixing D3 I noticed that the parked-datagram loop calls
`deliver_resolved_server_dgram` with `waiter: None`, so a parked payload can
still be delivered into a session created *after* the association closed — the
window `DnsWaiter` exists to close for the first delivery. Passing
`waiter.as_ref()` there (or the claim's cancel flag) would close it, but that is
a behaviour change outside D3's scope, so it is left for a separate change.

