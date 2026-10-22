# Core / DNS / config / stats / TLS audit — MyQUIC2 @ 8f0d685

**Domain:** `src/lib.rs` production section (lines 1–707; everything after is `#[cfg(test)]`),
`src/dns/**`, `src/config/**`, `src/stats/**`, `src/tls/**`, plus the caller paths in
`src/bin/**` that determine hot-vs-cold reachability.
**Audit commit:** 8f0d685 (clean worktree). **Method:** static read of every production line in
the domain (all five dns files, all four stats files, all three config files, all three tls files,
lib.rs production) plus targeted greps of every call site in `src/bin/**`; `git show 8f0d685`
for the in-domain deltas; dependency sources inspected where a claim depended on them
(quinn-proto 0.11.19 `assembler.rs`, hickory-resolver 0.26.3 `cache.rs`/`name_server_pool.rs`,
foldhash 0.2.0 `seed.rs`). **No test suite was run** (per instructions). One filesystem check was
executed (`umask` → `0022`, `ls -l server-key.pem` → `-rw-r--r--`). Read-only: no source, test or
config file was modified.

Severity scale used: S0 remote crash/memory blowup/security bypass; S1 serious under normal load;
S2 material but conditional (or material only for operators / under specific configs).

## Findings

| # | Sev | Category | Location | One-line | Conf |
|---|-----|----------|----------|----------|------|
| 1 | S1 | memory / admission | `src/dns/store.rs:67-68,83-92` + `src/dns/resolve.rs:459-479` | Positive DNS cache is entry-bounded (10,240) but each entry's address set is attacker-sized (a hostile authoritative server can return thousands of A/AAAA records over TCP), so the cache can retain hundreds of MiB–~1 GiB against a 9.17 MiB DNS admission term. | high (code) / med (magnitude) |
| 2 | S1 | memory / admission math | `src/config/tuning.rs:496-505`, `src/bin/myquic2-server/main.rs:222,235-241` | `stream_pump_memory_bytes` prices only the 2×16 KiB userspace pump buffers per TCP relay flow and omits the relay **TCP socket kernel buffers**; the process-wide `MAX_STREAM_TASKS`=16,384 flows (8,192 reachable from one shipped client) can pin ≈1.2–2.3 GiB at Linux initial defaults, more with autotuning, i.e. ~2.5–20× the 512 MiB fixed term the startup log claims as "worst case". | high (omission) / med (magnitude) |
| 3 | S2 | logic / TTL clamp | `src/bin/myquic2-server/forward.rs:590`, `src/bin/myquic2-server/accept.rs:1582` | The slow-path resolver arms the session destination memo and connection pin with the full `DNS_CACHE_TTL_MS` instead of the positive-cache entry's remaining life, so a nearly-expired cached answer can be used for up to `DEST_PIN_TTL_MS` (30 s) past the documented 120 s window — the exact bug `pin_life_ms` was added to prevent. | high |
| 4 | S2 | logic / cache epoch | `src/dns/resolve.rs:454-458` + `src/dns/memo.rs:101-109,123-138` (+ `resolve.rs:476-478`) | Negative-memo epoch is read *after* the negative-cache probe, so a `memo_put` racing another thread's success can tag its stale negative entry with the **post-bump** epoch and refuse a name that now resolves for up to 10 s (`DNS_NEG_TTL`). | med (race) / high (code) |
| 5 | S2 | stats | `src/stats/udp_stats.rs:46-55,88-118,202-222`, `src/stats/udp_write.rs:39-56,73-86` | Thread-local counters flush only by count (256 events), never by time, and `snapshot()` can only flush the reporter's own thread, so per-worker relay/sent counters read 0 for arbitrarily long at low rates and are lost when a worker thread exits — contradicting the in-code claims ("cannot dwell at zero for a low-rate session"). | high |
| 6 | S2 | TLS / security | `src/tls/cert.rs:8-17` | `gen_self_signed_files` writes the server private key with `std::fs::write` (mode 0644 under a normal umask), so any local user can read the key of the certificate every client pins and impersonate the server to those clients. | high (mode) / S1 in multi-user deployments |
| 7 | S2 | perf / resource | `src/dns/resolve.rs:168-198` (185-191), `238-259` | When the hickory resolver cannot be built the fallback `tokio::net::lookup_host` (getaddrinfo) is not cancellable: the 5 s `timeout` drops the future and releases the DNS permit while the blocking-pool thread keeps resolving for the libc timeout, so permits no longer bound live resolver work (up to 512 blocking threads per process). | med |
| 8 | S2 | memory / admission math | `src/config/tuning.rs:26-32,350-364` + `src/mqp/r2_flow.rs:84-104,177-179` | `R2_FLOW_HEAP_SLACK_BYTES`=832 under-counts per-flow heap: misses the `reply_src` `Arc` (~48 B), allocator rounding for the 255-byte name (~16–32 B) and the previous COW snapshot retentions (2×~600 B transient), i.e. the 4,096-flow registry charge is ~1.5–15 % low per connection depending on snapshot overlap. | med |
| 9 | S2 | config / docs | `config-server.toml:34-47` | Shipped server config comments were not updated by 8f0d685: they still claim a "4 KiB MQP-3 flow table", "~1.09/2.09 GiB" session pool, "14.5 MiB" per connection and ~512 MiB TCP pump fixed term, while the code now charges 22 KiB, 2.25 GiB, 19.625 MiB, and adds 384 MiB assembler + 34 MiB retry + 8.75 MiB DNS + worker scratch (~3.1 GiB fixed). Operators sizing `max_peer_memory_mb` from the sample under-budget the process. | high |

Nothing found in this domain meets S0 (remote crash / unbounded memory / security bypass);
findings 1 and 2 are quota-bounded memory blowups that outgrow the configured budget rather than
unbounded growth.

---

## 1 — DNS positive cache: entry-bounded capacity, peer-sized values (S1)

**Location / evidence**
- `src/dns/store.rs:67-68` — capacity is a *count* of entries:
  ```rust
  pub(crate) const DNS_CACHE_MAX: usize = 10_240;
  pub(crate) const DNS_NEG_MAX: usize = 4096;
  ```
- `src/dns/store.rs:86-91` — no `weigher`, no per-entry byte bound:
  ```rust
  Cache::builder()
      .name("dns-pos")
      .max_capacity(DNS_CACHE_MAX as u64)
      .time_to_live(DNS_CACHE_TTL)
  ```
- `src/dns/resolve.rs:459-472` — the value is the complete A+AAAA answer set, unfiltered,
  truncated nowhere:
  ```rust
  match resolve_ips(host, port, DNS_LOOKUP_TIMEOUT).await {
      Ok(mut ips) => {
          ...
          let ips: Arc<[IpAddr]> = Arc::from(ips);   // resolve.rs:471
          Ok((now, ips))
  ```
  `resolve_ips` (resolve.rs:168-198) returns `lookup.iter().collect()` from `hickory`
  `lookup_ip` — A and AAAA records, no count cap.
- `src/config/tuning.rs:549-553` — the only DNS admission term prices **waiters**, not retained
  entries:
  ```rust
  pub fn dns_inflight_memory_bytes() -> u64 {
      (DNS_SLOW_PATH_PERMITS as u64).saturating_mul(
          crate::UDP_RECV_MAX as u64 + DNS_WAITER_HOST_BYTES + DNS_WAITER_STRUCT_BYTES)  // 9.17 MiB
  }
  ```
- The flow-level cap (`R2_MAX_RESOLVED_ADDRS`=16) is applied only after the cache hit, per flow
  (`src/bin/myquic2-server/accept.rs:1494-1505 policy_resolved`), and the TCP dial path keeps at
  most 8 candidates (`tcp.rs:110-140`) — neither reduces the **cache's** retained value.

**Trigger path (hot/normal, not an exotic path):** any domain target reaching the server. Each
unique name resolved once fills one positive-cache slot for 120 s:
`server UDP domain datagram → forward_server_dgram → resolve_all_cached`
(`forward.rs:566`), `server TCP DATA OPEN → resolve_all_cached` (`accept.rs:1552`),
`server TCP CONNECT domain → resolve_all_cached` (`tcp.rs:107`). A client app can name arbitrary
domains (the auth token does not restrict *which* names are resolved, and tokenless servers are a
supported mode). A hostile authoritative server answers with a large answer set; hickory retries
truncated UDP responses over TCP (`hickory-resolver-0.26.3/src/name_server_pool.rs:385-389`), and
TCP DNS messages are u16-length-prefixed, so up to ~64 KiB of A/AAAA records ≈ several thousand
`IpAddr`s are accepted, clamped only by `positive_max_ttl`/`negative_max_ttl`, not by count.

**Impact:** with 10,240 entries × ~5–90 KiB retained per entry the cache alone can grow to
~50–900 MiB, versus the 9.17 MiB charged and the per-connection/session terms that dominate an
operator's `max_peer_memory_mb`. On a 256–512 MiB router image this is an OOM class. Even a modest
200-record answer per name × 10k names ≈ 35 MiB; a determined attacker reaches hundreds of MiB.
The cache's own docs (`store.rs:59-66`) describe capacity only in entries and claim "a failing-
domain flood cannot evict positives", which remains true, but the byte claim is absent.

**Fix direction (do not implement here):** cap the retained set per name before insert
(e.g. truncate `ips` to a small constant such as 16–32 addresses after sorting, keeping the
preferred family first), and/or give the moka caches a `weigher` that prices
`key.len + 17 * ips.len()` so `max_capacity` is bytes rather than entries. Either restores the
documented "the caches above are the only TTL and memory authority" story. Confidence high that
the code does what is quoted; medium on the exact worst-case bytes (kernel/allocator dependent).

## 2 — TCP relay socket kernel buffers are outside the admission fixed term (S1)

**Location / evidence**
- `src/config/tuning.rs:496-505` — the function documents itself as the *worst case* for the
  process-wide flow pool, but only prices userspace buffers:
  ```rust
  /// Worst-case buffers held by `max_streams` concurrent TCP <-> QUIC pump
  /// flows: two [`COPY_CHUNK`] buffers per flow ...
  pub fn stream_pump_memory_bytes(max_streams: usize) -> u64 {
      (max_streams as u64).saturating_mul(2 * crate::tcp::pump::COPY_CHUNK as u64)
  }
  ```
- `src/bin/myquic2-server/main.rs:222,235-241` — charged once as `pump_bytes` (16,384 × 32 KiB =
  512 MiB) in `fixed_bytes`, which the startup line calls the process worst case.
- `src/bin/myquic2-server/accept.rs:45` — flow bound is `MAX_STREAM_TASKS: usize = 16_384`
  (per connection, `MAX_BIDI_STREAMS_PER_CONN` = 8,192).
- The relay TCP sockets are created by plain `TcpStream::connect` (`tcp.rs:165`) and
  `TcpStream` from the SOCKS side; the only socket options applied are `TCP_NODELAY` and
  `TCP_NOTSENT_LOWAT` (`linux.rs:161-177`). **No `SO_SNDBUF`/`SO_RCVBUF` is set** on relay TCP
  sockets (grep: only the UDP path in `lib.rs:390-396` sets them), so the kernel's default
  autotuned buffers apply (`net.ipv4.tcp_rmem` default 131,072 B receive cap growing to 6 MiB,
  `tcp_wmem` 16 KiB to 4 MiB).
- Contrast the project's own standard: UDP session sockets (`per_session_memory_bytes`,
  tuning.rs:412-443) and QUIC endpoint sockets (`endpoint_memory_bytes`, tuning.rs:477-494) both
  charge the kernel `SO_*BUF` caps. The TCP relay socket is the one socket class never charged.

**Trigger path:** `SOCKS CONNECT → server accept loop → handle_tcp_stream → dial_happy_eyeballs →
TcpStream::connect(target) → copy_tcp_quic_*` (server `tcp.rs:165-210`). A peer (authenticated;
tokenless mode is also supported) opens up to 8,192 CONNECTs and points them at targets that
accept but do not read (or its own servers, which push data while the app stops reading the SOCKS
socket). The pump then blocks on QUIC flow control, the target keeps filling the relay socket's
receive buffer, and the pump's writes fill the send buffer — both up to the kernel caps, per flow.

**Impact:** at Linux *initial* defaults (128 KiB rcv + 16 KiB snd) the 16,384-flow pool can pin
≈2.3 GiB beyond the 512 MiB charged; autotuning can grow each flow to multi-MiB, so the claimed
bound can be exceeded by one to two orders of magnitude. This is exactly the class of under-count
the audit commit fixed for UDP session/endpoint/retry pools: an operator who sets
`max_peer_memory_mb` to, say, 1 GiB can still see multi-GiB RSS from a single admitted peer.
Confidence high that the term is missing; medium on the exact bytes (sysctl- and target-dependent).

**Fix direction:** either charge a documented per-flow kernel term
(`MAX_STREAM_TASKS × (relay_sndbuf_cap + relay_rcvbuf_cap)`) in `stream_pump_memory_bytes`, or
bound it for real by setting small explicit `SO_SNDBUF`/`SO_RCVBUF` on relay TCP sockets
(`socket2` after connect/bind) and charging that value; then update the startup "worst case"
line/test that pins these constants.

## 3 — Slow-path resolver arms pins/memos with the full DNS TTL, not the entry's remaining life (S2)

**Location / evidence**
- The clamp contract is stated explicitly (`src/bin/myquic2-server/pin.rs:433-453`):
  > "Every arming site therefore clamps to the source's remaining life; a fresh resolution (the
  > spawned resolver task) passes `DNS_CACHE_TTL_MS`, where the 30 s pin wins and behaviour is
  > unchanged."
  ```rust
  pub(crate) fn pin_life_ms(remaining_ms: u64) -> u64 { DEST_PIN_TTL_MS.min(remaining_ms) }
  ```
- But the spawned resolver task does **not** necessarily produce a fresh resolution: its
  `resolve_all_cached` first probes the host-keyed positive cache
  (`src/dns/resolve.rs:437-439`), so it can return an answer of any remaining life (down to
  milliseconds) and the caller still passes the full TTL:
  - `src/bin/myquic2-server/forward.rs:590`
    ```rust
    let sock = match get_or_create_sess(ss, cd, conn_id, s,
        Some((host, port, dst, DNS_CACHE_TTL_MS)), r2).await
    ```
  - `src/bin/myquic2-server/accept.rs:1582` (rev2 DATA OPEN slow path) — same call shape.
  `get_or_create_sess`/`get_or_create_sess_guarded` then store
  `expires: coarse_millis() + pin_life_ms(life)` (`reader.rs:1775`), i.e. 30 s.
- The infra needed for the correct clamp already exists and is used on the fast paths:
  `lookup_cached_fast_with_ttl` (`resolve.rs:323-363`) feeds `resolve_forward_target`
  (`forward.rs:388-421`) and `resolve_pin` (`pin.rs:408-427`); only the two spawned-resolver
  sites pass the constant.

**Trigger path:** domain target; the requesting worker's per-(host,port) DNS memo is cold
(new worker-thread, new port of a known name, or a memo-conflict eviction) but the shared
host-keyed cache entry is still live and close to expiry. The slow-path lookup then returns a
nearly-expired answer and the session destination memo / connection pin (and therefore every
subsequent datagram that hits them without a DNS read) is armed for 30 s.

**Impact:** up to `DEST_PIN_TTL_MS` (30 s, `pin.rs:176`) of traffic to an address that the DNS
cache has already aged out — the documented end-to-end staleness bound is `DNS_CACHE_TTL`
(120 s, `store.rs:56`), so the real bound becomes ~150 s for that flow, and `pin_life_ms`'s own
convergence claim ("clamped to the source's remaining life") is false for this path. No security
impact (the address was SSRF-filtered when armed), but it is the exact staleness bug the clamp was
introduced to close.

**Fix direction:** after `resolve_all_cached` returns in the two `_bg` task sites, read the
remaining life from the same authority — `lookup_cached_fast_with_ttl(host, port).1` (the
materialize path has just memoized the entry, so this is one thread-local probe) — and pass that
instead of `DNS_CACHE_TTL_MS`; alternatively have `resolve_all_cached` return the entry's
`inserted`/remaining life. Confidence high.

## 4 — Negative-memo epoch is sampled after the negative cache probe (S2)

**Location / evidence**
- `src/dns/resolve.rs:454-458` (negative-hit branch of `resolve_all_cached`):
  ```rust
  if let Some(inserted_at) = negatives().get(host_key).await {
      let remaining = DNS_NEG_TTL.saturating_sub(inserted_at.elapsed());
      memo_put(memo_key, None, Instant::now() + remaining);
      anyhow::bail!("dns negative cached");
  }
  ```
- `src/dns/memo.rs:123-138` — `memo_put` → `DnsMemoSlot::new`, which samples the epoch *inside*
  the write:
  ```rust
  s.neg_epoch = if addr.is_none() { neg_epoch() } else { 0 };   // memo.rs:136
  ```
- The success path publishes the invalidation in the opposite order
  (`src/dns/resolve.rs:476-478`):
  ```rust
  if negatives().remove(host_key).await.is_some() {
      bump_neg_epoch();
  }
  ```
- Fast-path consumer: `src/dns/resolve.rs:348-359` accepts a negative memo only while
  `now < m.expires_ms && m.neg_epoch == neg_epoch()`.

**Race:** thread A observes the negative entry (Some) at T0; concurrently thread B resolves the
name, removes the negative entry and bumps `NEG_EPOCH` at T1 > T0; A then calls `memo_put` and
loads the **already-bumped** epoch at T2 > T1, storing a negative memo whose tag equals the
current epoch. Because the tag looks current, the fast path serves `CachedLookup::Negative` for
the memo's remaining life (up to ~10 s) even though the positive cache now holds a valid address.
The window requires the bump to land between A's `negatives().get()` return and A's epoch load
(no `await` between, but the OS can preempt the thread); a name that flaps (fails → resolves under
load) and multiple worker threads retrying it make it reachable.

**Impact:** up to `DNS_NEG_TTL` (10 s) of incorrect refusals on the thread that lost the race:
server UDP datagrams are dropped as `REFUSED` (`forward.rs:470-473`), server TCP CONNECT/dials
fail fast (`tcp.rs:107-145`), and client UDP replies are refused (`dispatcher.rs:574-580`). It is
self-healing after the memo deadline, and only one thread's memo is poisoned at a time.

**Fix direction:** sample the epoch *before* probing the negative cache and pass it into a
`memo_put_with_epoch` (or reject the write if the epoch changed between probe and write); the
same "read the authority, then write the memo, then re-validate" shape the positive path already
uses. Confidence high on the ordering; medium on real-world hit rate.

## 5 — Batched stats have no time-based flush; a 60 s reporter cannot flush workers (S2)

**Location / evidence**
- `src/stats/udp_stats.rs:54-55` — the only flush triggers are counts:
  ```rust
  const FLUSH_DATAGRAMS: u64 = 256;
  const FLUSH_BYTES: u64 = 256 * 1024;
  ```
  `payload()` (`udp_stats.rs:88-118`), `fragmented()` (126-140) and `unsolicited()` (157-168)
  add to thread-locals and flush only when their own threshold is crossed.
- `udp_stats.rs:202-222` — `snapshot()` calls `flush_locals()`, which flushes only the *calling*
  thread's cells, then loads the globals; the docs admit "a thread that exits with a pending
  count drops it" but justify the threshold with "256 datagrams bounds the worst-case undercount
  to ~15 s at 17 pps".
- `src/stats/udp_write.rs:39-48` makes the stronger (false) claim:
  > "one shared atomic RMW per 256 sends, so the 60 s `udp write` line cannot dwell at zero for a
  > low-rate session."
  A thread doing fewer than 256 sends between reports *does* dwell at zero: 1 pps → up to 256 s
  between flushes, well past the 60 s interval; 0.1 pps → ~42 min. `udp_write.rs:73-86`'s
  `snapshot()` has the same caller-thread-only flush.
- `udp_stats::payload` is on the per-packet path (`server/accept.rs:681,732`,
  `server/reader.rs:391,502,529,562,602,677,831`, `client/dispatcher.rs:211,222,400,415,...`),
  and `udp_write::sent()` on every last-hop write (`udp/retry.rs:211,249`).

**Impact:** operational blindness, not data-path loss. At low rates (DNS-style request/response,
keepalive games, one packed train every few seconds) a worker's relay/sent counters are invisible
for arbitrarily long: for a thread that never again reaches 256 events the pending count is never
published at all, and `snapshot()` on the reporter's (different) thread cannot flush it. The only
recovery is that same thread later crossing a threshold; a thread that exits with a pending count
drops it (documented at `udp_stats.rs:206-211`; the shipped binaries' worker threads persist for
process lifetime, so this part is mostly a test/embedder and rearmed-runtime case). This is
exactly the "keepalives/DNS trickle" case the 256 threshold was lowered to serve, and the doc's
"~15 s" bound only holds at ≥17 pps. Long-idle UDP flows can therefore be logged as "no UDP
traffic" while datagrams are being relayed.

**Fix direction:** add a time gate (e.g. flush in `snapshot` on every N-th report, or a coarse
clock check in `payload()` once per second) and/or have the reporter read/flush via a shared
per-thread registry; correct the two doc claims. Confidence high (the code is unambiguous).

## 6 — Generated server private key is world-readable (S2; S1 in multi-user deployments)

**Location / evidence**
- `src/tls/cert.rs:8-17`:
  ```rust
  pub fn gen_self_signed_files(san: &str, cert_path: &str, key_path: &str) -> Result<()> {
      ...
      std::fs::write(cert_path, cert.pem()).context("write cert")?;
      std::fs::write(key_path, key_pair.serialize_pem()).context("write key")?;
  ```
  `std::fs::write` creates a new file with mode `0o666 & !umask`; this host's umask is `0022`
  (executed check), giving `0644`. The repository's own `server-key.pem` is `-rw-r--r--`, i.e.
  the generator's output mode. There is no `set_permissions`/`OpenOptionsExt::mode` anywhere in
  the tree (grep).
- Trigger: first server start with both cert/key absent (`server/main.rs:100-116`).

**Impact:** on a multi-user host (or anywhere the working directory is readable), the pinned
server identity is stealable: clients use `client_tls_config` with this certificate as the **only
root** (`tls/client_cfg.rs:10-15`), and hostname verification compares `server_name`, so an
attacker with cert+key can answer `connect_with` for those clients and terminate the tunnel
(decrypting all proxied TCP/UDP) until the operator rotates both files. Past sessions are
protected by TLS 1.3 forward secrecy, future ones are not. Requires local read access, hence S2 by
the stated scale; it is a complete bypass of the pinning design for that deployment.

**Fix direction:** write the key with `OpenOptions::new().write(true).create_new(true).mode(0o600)`
(unix) and `chmod 0600` after generation; the cert may stay 0644. Confidence high.

## 7 — getaddrinfo fallback defeats the DNS timeout and permit bound (S2)

**Location / evidence**
- `src/dns/resolve.rs:168-198`:
  ```rust
  let ips = tokio::time::timeout(timeout, async {
      match upstream_resolver() {
          Ok(r) => { ... r.lookup_ip(host).await ... }
          Err(why) => {
              tracing::debug!("hickory resolver unavailable ({why}); using getaddrinfo");
              tokio::net::lookup_host((host, port)).await?   // resolve.rs:187
  ```
- `src/dns/resolve.rs:238-259` — the fallback triggers whenever `builder_tokio()`/`build()` fails
  (unreadable/invalid platform DNS config, e.g. a container without resolv.conf).
- The comment above the resolver (resolve.rs:217-222) claims the timeout "actually stops the work
  instead of leaving a blocking thread to finish it" — true for hickory, false for this fallback:
  `lookup_host` is `spawn_blocking`, so dropping the future at the 5 s timeout leaves the blocking
  thread in libc `getaddrinfo` (resolv.conf `timeout×attempts`, commonly 10–40 s) while the caller
  returns, drops its `dns_slow_path_limiter` permit, and lets another waiter start.

**Impact:** in the fallback mode the 1,024-permit limiter no longer bounds live resolver work; the
real bound becomes Tokio's `max_blocking_threads` (512) and the blocking pool is kept saturated by
a unique-name flood, delaying every other `spawn_blocking` user in the process (the binaries use
the blocking pool for little else, so the practical impact is memory/thread churn and resolver
calls taking up to the libc timeout; permits are recycled while up to 512 resolver threads keep
running). Conditional on hickory init failing; medium severity. The one-time
`builder_tokio()` construction is also synchronous file/SystemConfiguration I/O executed on a
Tokio worker on first lookup (resolve.rs:243-246), which can stall a shard runtime briefly, but is
cold and one-shot.

**Fix direction:** acquire the permit around the *blocking* completion too (e.g. spawn the
getaddrinfo lookup on a dedicated bounded pool and keep the permit until its JoinHandle is
dropped), or pre-build the resolver at startup and fail fast if the platform resolver is
unavailable rather than silently degrading under load. Confidence medium (mode-specific).

## 8 — `R2_FLOW_HEAP_SLACK_BYTES` under-counts per-flow heap (S2)

**Location / evidence**
- `src/config/tuning.rs:26-32` — the slack's own derivation:
  > "the `Arc` header (16 B), the target's domain name up to the 255-byte wire limit, and the
  > bounded resolved set (`R2_MAX_RESOLVED_ADDRS` × 32-byte `SocketAddr` plus the `Arc`/`Vec`
  > headers). That is 823 B; 832 keeps the arithmetic round."
- `src/mqp/r2_flow.rs:84-104` — a `FlowBinding` also owns:
  - `reply_src: ArcSwapOption<SocketAddr>` — when set on a rebind this allocates an
    `Arc<SocketAddr>` (Arc header 16 + 32 B payload ≈ 48 B) that the 823 B derivation does not
    include;
  - `target: TargetAddr` whose domain `String` heap allocation for a 255-byte name costs
    `malloc(255) + header` ≈ 16–32 B beyond the 255 B counted;
  - both `ArcSwap` fields can hold the **previous** snapshot while readers' hazard pointers are
    live (`resolved` = `Arc<Vec<SocketAddr>>` ≈ 16+24+16×32 = 552 B; `reply_src` ≈ 48 B) — the
    same two-snapshot effect that `R2_SESSION_TABLES_BYTES` explicitly prices
    (tuning.rs:379-405), but not applied here.
- Registry charge is `R2_MAX_FLOWS_PER_CONN (4096) × (size_of::<FlowBinding>() + 832)` inside
  `per_connection_memory_bytes` (tuning.rs:353-363).

**Impact:** per domain flow the charge is short by ~70 B steady-state and up to ~70+600 B while a
`set_resolved`/rebind snapshot is being retired; across 4,096 flows one connection can hold
~0.3–2.7 MB more than charged (≈1.5–14 % of the 19.625 MiB per-connection term), and across a
full 4,096-connection admission the aggregate under-count is ~1–10 GiB in the worst case. Only
matters when `max_peer_memory_mb` is set (the term is otherwise informational), hence S2 and the
weakest of the memory findings; also note `RECENT_ADDRS_BYTES` (tuning.rs:371-377) hard-codes
"16-slot" without referencing the binary-private `RECENT_DST_CAP` (`server/pin.rs:35`), so a future
change there silently desynchronizes admission (unlike `SERVER_SESS_BUF_POOL_DEPTH`, whose mirror
carries a "must update" warning).

**Fix direction:** add `reply_src`/allocator rounding/one-retained-snapshot terms to the
derivation (or raise the constant to the derived value ~1,500 B for the worst case) and add the
missing cross-crate invariant warning for `RECENT_ADDRS_BYTES`. Confidence medium.

## 9 — Shipped server config's admission comments are stale against the code (S2)

**Location / evidence** — `config-server.toml:34-47` (not touched by 8f0d685, whose "files
changed" list is README/MQP3 spec + `src/…` only):
> "the UDP session pool: MAX_SESSIONS_GLOBAL (8192) × (2 x MYQUIC2_SESS_SOCKET_BUF + its reader
> buffer + **4 KiB MQP-3 flow table**) = ~1.09 GiB … ~2.09 GiB on Linux … and the TCP pump
> buffers: 2 x 16 KiB per active stream x MAX_STREAM_TASKS = ~512 MiB — and what is left is
> divided by receive window + send budget + both DATAGRAM buffers + the reassembly budget =
> **14.5 MiB** with the default 4/8/4 MB windows."

Current code: `MQP3_FLOW_TABLE_MAX_BYTES = 22 * 1024` (`src/mqp/v3.rs:65`), session pool
`per_session_memory_bytes()` = 294,913 B → 2,304 MiB (tuning.rs:434-457, pinned by lib tests),
per-connection `per_connection_memory_bytes()` = 19.625 MiB (`lib.rs` tests
`per_connection_memory_tracks_the_windows`), and `fixed_bytes` now also includes
`stream_assembler_memory_bytes(4096)` = 384 MiB, `retry_pool_memory_bytes()` = 34 MiB,
`dns_inflight_memory_bytes()` = 8.75 MiB and `worker_scratch_bytes(ep_count)` (server/main.rs:220-241)
— roughly 3.1 GiB fixed at defaults, not the ~1.5–2.6 GiB the sample implies.

**Impact:** an operator following the shipped sample (`max_peer_memory_mb = 512` is the commented
example) sizes the host from numbers that are ~2× off for the fixed term and ~35 % off per
connection; the code does warn at startup ("budget at or below the fixed term → one connection"),
so this is misleading documentation rather than a silent failure, hence S2/low impact. Included
because the config file is operator-facing and the same commit updated README but not it.
**Fix:** regenerate the two parenthetical figures (and mention the new fixed terms) from the same
constants the startup log prints.

---

## Checked and found sound (no finding)

- **SSRF / private-IP policy** (`src/dns/policy.rs`): full CIDR-table enumeration was compared
  against RFC 6890/IANA (v4 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24,
  192.0.2/24, 192.88.99/24, 192.168/16, 192.175.48/24, 192.31.196/24, 192.52.193/24, 198.18/15,
  198.51.100/24, 203.0.113/24, 224/4, 240/4; v6 everything below 2000::/3 plus 2001::/23,
  2002::/16, 3fff::/20, 5f00::/16, 64:ff9b::/32, fc00::/7, fe00::/9, ff00::/8). Embedded-v4 forms
  recurse before the tables: IPv4-mapped (`to_ipv4_mapped`), RFC 2765 translated
  (`::ffff:0:a.b.c.d`), NAT64 well-known and deprecated IPv4-compatible; **no bypass found**
  (`::ffff:127.0.0.1`, `::ffff:0:10.0.0.1`, `64:ff9b::7f00:1`, `::a00:1`, Teredo/6to4, metadata
  `169.254.169.254`/`100.100.100.200` all denied). Scope IDs cannot reach the predicate: the wire
  encoder rejects `scope_id != 0` (`lib.rs` test `dgram_encoder_matches_the_reference_encoding`)
  and SOCKS5 ATYP carries no zone. Server egress re-checks on every fast-path arm
  (`fast_allow_cached`, `dial_happy_eyeballs` filter) and every pin/memo store is fed a filtered
  address (audited all `pin_arm`/`sess_dest_store` call sites).
- **DNS cache keys** (`src/dns/key.rs`): normalization (ASCII case-fold + trailing-dot strip) is
  consistent between the borrowed and owned forms; the per-port key is injective (port separated
  at the final NUL, which decimal digits and the host cannot introduce ambiguity even for hosts
  containing NUL); buffer bounds are exact (255-byte host + NUL + 5 digits = 261 = `DNS_KEY_BUF`,
  `dns_host_key` = 255); no allocation on the memo hit path.
- **Memo (`src/dns/memo.rs`)**: 2-way × 64-set table with full-key compare (hash is only a
  filter, so no cross-name mis-serve), positive/negative kept disjoint, `neg_epoch` invalidation
  on other-thread success works (unit test `a_resolution_invalidates_another_threads_negative_memo`);
  footprint 320 B/slot × 128 = 40 KiB/thread — material only on threads that resolve names and
  small against the process terms (not charged; noted, not a finding).
- **Cache bounding / eviction**: moka `max_capacity` + TTL, no O(n) eviction scans on any path;
  negative store is host-keyed and value `Instant` (bounded); single-flight via
  `try_get_with_by_ref` coalesces concurrent lookups and has no manual in-flight map to leak;
  failed init caches nothing in the positive store (errors are shared, not cached); hickory's own
  response cache is correctly disabled (`ResponseCache::new(0,...)` → moka `max_capacity(0)`;
  verified against hickory-resolver 0.26.3 `cache.rs:39-47`), so it is not a second TTL authority.
- **Slow-path limiter**: exactly `DNS_SLOW_PATH_PERMITS`=1024 permits, `try_acquire_owned`
  everywhere (grep: client `dispatcher.rs:588`, server `forward.rs:487`, `tcp.rs:100`,
  `accept.rs:1544`), all permits moved into the spawned task or explicitly dropped on every exit;
  no `await` while holding a *session* permit that could invert with the DNS permit; no permit
  leak on rejection/cancel paths (RAII guards verified).
- **Admission arithmetic**: `per_session_memory_bytes` (both flow tables, Linux SO_*BUF doubling),
  `session_pool_memory_bytes` (8,192 × 288 KiB = 2,304 MiB), `endpoint_memory_bytes` (userspace
  GRO buffer 3,014,656 B + doubled 16 MiB kernel caps), `retry_pool_memory_bytes`
  (16 × 272 × 8,192 = 35.65 MB, matches `udp/retry.rs:50-51` channel depth/in-flight),
  `dns_inflight_memory_bytes`, `worker_scratch_bytes` (matches `server/reader.rs:35`
  `SESS_BUF_POOL_DEPTH=8` + `BURST_SLOT` derivation) — all match the actual structures; all use
  saturating arithmetic and `max_peer_memory_mb` is clamped `≤1<<20` MiB → no overflow;
  `admission_cap` subtracts saturating and floors at 1 connection.
  `stream_assembler_memory_bytes` (1024 spans × 96 B) was checked against quinn-proto 0.11.19
  `assembler.rs`: the 96 B figure is conservative — a stream's retained over-allocation is bounded
  by `max(32 KiB, 1.5 × buffered)` and `data.len() ≤ MAX_CHUNKS(=1024)`, so ≤~90 KiB/stream
  even in the sparse-gapped-frame regime; the 4096-task header credit charge (384 MiB) holds.
  Client adds (0,0) incoming stream credit so it cannot be made to park assemblers.
- **Config parse/validate**: both configs `deny_unknown_fields`; windows/ack-delay/initial-RTT/MTU
  clamps (1..64 MB, 1..25 ms, 1..3000 ms, 1200..1472 B) applied in `tuning.rs`; endpoint count
  clamped 1..=8; `max_connections`/`max_udp_assocs`/`udp_egress_conns` clamped where consumed;
  auth token length rejected on **both** sides against the same 256 B wire cap
  (`client/main.rs:100-106`, `server/auth.rs:24` + `server/main.rs:71`, lib
  `AUTH_TOKEN_MAX_BYTES`); token comparison constant-time (`subtle::ConstantTimeEq`).
- **TLS verification** (`src/tls/**`): client pins the configured cert as the sole root and keeps
  rustls' default hostname verification against `server_name` (`client/main.rs:125`,
  `dial_once` → `connect_with`); TLS 1.3 only both sides; server uses `with_no_client_auth`
  (token auth instead), stateful resumption store sized for the connection cap, and the
  `max_early_data_size = u32::MAX` 0-RTT acceptance is documented with the replay bound; the auth
  token is deliberately 1-RTT only. No verification mistake found beyond the file-mode issue (#6).
- **`stats` drop counters** (`src/stats/drops.rs`): `bump()` is a direct `fetch_add` returning the
  new total; every counter has a `DropSnapshot` field and a pinned test
  (`every_drop_counter_has_its_own_snapshot_field`); the `L_*` thread-locals/`flush_locals` there
  are vestigial (never written; `batched()` is `#[allow(dead_code)]`) — exact counters, no defect.
  `warn.rs` claim windows use `NEVER_WARNED = u64::MAX` so the first window is due; slots are
  enumerated (no substring matching); warning detail strings are built only by the window winner.
- **lib.rs socket helpers**: `probe_udp_socket_buffers` caches the clamp verdict per buffer size
  (OneLock) so the 4–5 `getsockopt`/`setsockopt` diagnostics run once per size, not per socket;
  `buf_probe_slot` resolves sizes through the same `sess_socket_buf()` used by callers; no panics
  on config/peer input anywhere in lib.rs production (no `unwrap`/`expect`/`panic!`); the
  dual-stack `[::]`+V6ONLY=0 and REUSEPORT paths match their docs; session sockets use the small
  buffer.
- **Legacy MQP-2 helpers in lib.rs are *not* hot**: `read_mqp_ack` is still live, but only on the
  per-TCP-connection relay-open path (`tcp/pump.rs:381` via `copy_tcp_quic_acked` from
  `client/socks.rs:261`), not per packet; `resolve_server_side`, `lookup_cached_sync`,
  `resolve_all` are re-exported/test-only in the binaries (grep). The legacy v3/MQP-2 UDP frame
  decoders in the bins are cold (refused/counted) and outside this domain.
- **hickory single-flight / negative-cache publish order**: negative verdict is written inside
  the init future before the error is published to waiters, and success removes the negative
  before the positive entry is visible; no "serves a sentinel as a resolution" path.

## Cross-domain notes (for the Lead; not repeated as findings here)

- **Server bin `r2_stats`** (`src/bin/myquic2-server/accept.rs:830-878`, per-frame sites `src/bin/myquic2-server/reader.rs:503,516,530,550`): `bump()` is a direct
  process-wide `fetch_add` and `STEADY_SENT`/`OPEN_SRC_SENT` are bumped per downlink reply frame —
  the same shared-cache-line cost the lib stats code removed for `udp_stats::payload`. Only
  `TRAIN_ITEMS` is thread-locally batched. Belongs to the server-bin audit (hot path on replies).
- **Server reporter first-second suppression** (`src/bin/myquic2-server/reporter.rs:6-35`):
  `warn_stream_share_refused`, `warn_once_per_sec` and `warn_sess_create_failed` initialise their
  slots with `0` instead of the lib's `NEVER_WARNED = u64::MAX`, so (per `warn.rs:6-18`) a
  handshake/fd storm in the first second is swallowed — the exact bug `claim_server_log` fixed for
  its own classes (`reporter.rs:37-47`).
- **`PendingOpen::Full` is counted as `DNS_BUDGET`** (`accept.rs:1717`): that arm is the
  per-connection 16-slot pending cap, not the global resolver budget; the 60 s line will report a
  resolver-budget outage for one busy client. (The neighbouring in-flight arm is correctly
  `REFUSED`.)
- **`udp_stats::payload` is counted before the forward/send outcome** (e.g.
  `server/accept.rs:681,732` before `forward_v3_item`; `reader.rs` before send): payloads that are
  then refused/dropped still count as relayed datagrams. Semantics of "relayed" vs "accepted";
  worth one sentence wherever the reporter docs are next edited.
- **Client `lookup_entry` dead-entry arm** (`client/dispatcher.rs:179-185`): a hub entry that
  exists but `!is_alive()` returns `NoEntry` without bumping `UNKNOWN_SESS`, although the enum doc
  says the drop is counted where it is decided; the hub probe only counts the absent case.
- **`AUTH_MAX_BYTES` duplication** (`server/auth.rs:24` vs lib `mqp/ack.rs:54`): equal today, but
  the server bin re-declares the 256 B cap instead of importing `AUTH_TOKEN_MAX_BYTES`; if the lib
  constant changes, server/client caps drift silently (the two length checks would disagree).
- **`config-client.toml` / README** were updated in 8f0d685 but `config-server.toml` was not
  (finding #9); the client sample also still describes the per-connection figure from the old
  formula where relevant.
