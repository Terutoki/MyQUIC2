# TCP forwarding audit — `forward.rs`, forward config validation, startup wiring (commit `41031b4`)

**Scope.** Repo `/Users/eric/WorkSpace/MyQUIC2`, current HEAD `7232088` (v0.2.2); feature commit
`41031b4` ("feat(client): add config-driven TCP/UDP forward listeners"), baseline `1135076`.
TCP half only: `src/bin/myquic2-client/forward.rs` (new, 242 lines), the TCP parts of
`src/config/client_conf.rs` (`ForwardEntry` / `TcpForwardSpec` / `tcp_forwards` /
`parse_forward_listen` / `parse_forward_target` / `listen_overlaps`, 472 added lines shared with
UDP), `src/bin/myquic2-client/main.rs` startup wiring, `src/lib.rs` exports.
Compared line-by-line against the existing SOCKS5 `CONNECT` path (`socks.rs`), the shared pump
(`src/tcp/pump.rs`), the shared pool (`pool.rs`: `pick_tcp_index`, `wait_conn`), the shared
admission semaphore (`socks.rs:11,24-27` + `main.rs:470-482` + `forward.rs:51,79-94`), the shared
death commit (`auth.rs:284-306` `retire_dead_slot`) and Linux relay tuning
(`linux.rs:241` `tune_relay_tcp`). Plan
`docs/superpowers/plans/2026-10-23-client-tcp-udp-forwarding.md` §1/§4.3/§4.4/§5/§9/§11 was read
as the intended contract and every claim re-checked against HEAD code.
The feature files are unchanged between `41031b4` and HEAD (`git diff 41031b4 HEAD -- forward.rs
client_conf.rs main.rs` is empty; only README/release commits followed), so HEAD code *is* the
code under audit.

**Method.** Static reading against HEAD, plus cheap verifications only: ran the already-built
current lib test binary (`target/debug/deps/myquic2-42f32f8785bf98af client_conf::tests`) → 7/7
pass; verified `std::net::SocketAddr` parse / `is_unspecified` / `is_loopback` edge cases with a
scratch `rustc` program in `/tmp` (not in the repo); verified same-port cross-family bind
coexistence with Python sockets on the macOS dev host. No source/config change, no release build,
no benchmark, no full test suite (a teammate owns benchmarks). No E2E process test was run, so
runtime claims are marked **Inferred** where they depend on kernel/OS behaviour.
Severities: **S0** crash/corruption/security; **S1** serious under normal load; **S2** material
but conditional; **S3** minor.

**Bottom line.** The TCP relay itself is a faithful, line-equivalent copy of the SOCKS `CONNECT`
half: no S0/S1 defect was found in admission, permit lifetime, half-close/RST disposition, header
write, ACK timeout, dead-slot self-heal, priority or shutdown. One **S2** availability/fairness
gap (no per-listener TCP admission cap on top of the shared 8192-permit pool) and several **S3**
issues (two config-validation holes, one over-broad overlap rule, one logging-window interaction,
startup ordering, listener-count scalability, mapped-loopback warning, test gaps) are reported
below. The SOCKS5 TCP ECHO hot path is **code-identical** to the baseline (explicit verdict in §4).

---

## 1. Findings table (severity-sorted)

| # | Severity | Category | Location | One-line issue | Confidence |
|---|----------|----------|----------|----------------|------------|
| T-01 | **S2** | limits / fairness / availability | `forward.rs:51,79-94,98-103`; `socks.rs:11,24-27`; `main.rs:470-482`; contrast `client_conf.rs:180-181`, `forward_udp.rs:164-172` | A single TCP forward listener can consume all 8192 process-wide relay permits (shared with SOCKS and every other listener) and deny the SOCKS5 endpoint; TCP forwarding has no per-listener cap while UDP forwarding does | high (mechanism) / medium (impact: conditional on reachability) |
| T-02 | **S3** | config validation | `client_conf.rs:394-401`; `src/mqp/addr.rs:165-178,205-227` | IPv4-mapped unspecified target `[::ffff:0.0.0.0]:p` passes both config validation and the shared wire encoder's "refuse unspecified" check, contradicting plan §4.3; with server `allow_private=true` it silently dials the server's own loopback | high |
| T-03 | **S3** | config validation | `client_conf.rs:336-363` | Overlap rule over-rejects legal cross-family pairs (v4 wildcard vs any same-port v6 address); a config that binds successfully is refused at startup with a false "overlaps" error | high (macOS bind verified; Linux inferred) |
| T-04 | **S3** | observability / logging | `forward.rs:137-140,236-242`; `stats/warn.rs:159-172`; `socks.rs:299-308`; plan §5.4 | Forward aborts spend the *shared* `tcp_abort_log_due()` window on a `debug!` line (invisible at default `info`), which can suppress the SOCKS abort `warn!` that carries path stats; forward failure lines carry no conn stats although plan §5.4 requires them | high |
| T-05 | **S3** | startup scalability | `client_conf.rs:271-299,305-318`; `lib.rs:633` | Overlap validation is O(n²) in listener count and there is no cap on the number of forward entries; a generated config with thousands of listeners stalls startup and pins 1024-backlog kernel queues per listener | high |
| T-06 | **S3** | startup ordering | `main.rs:135-136` vs `278-368,373-390` | Config is validated before TLS/QUIC (correct), but listeners are bound only *after* the QUIC shard threads/endpoints are spawned and dialing/authentication has begun; a busy port aborts startup after the tunnel was already dialed | high (verified); impact small |
| T-07 | **S3** | config / diagnostics | `forward.rs:44`; `client_conf.rs:336-344`; `lib.rs:633` | Mapped-loopback listen `[::ffff:127.0.0.1]:p` is accepted and warns "not loopback" (`is_loopback()` is false on the mapped form) although it is loopback-only; link-local listen literals pass validation only to fail at bind | high |
| T-08 | **S3** | test coverage | `tests.rs:7339-7357`; `tests/forward_e2e.rs:377-436,560-591` | The pre-pump "RST, not FIN" guarantee is not asserted (the test accepts a clean EOF); forward's dead-slot self-heal branch, multi-listener startup, and SOCKS/forward admission interaction are untested | high |

No S0 and no S1 finding. The intended plan §5/§11 guarantees are otherwise delivered; §3 records
the guarantee-by-guarantee check, §5 the areas checked and found sound.

---

## 2. Finding detail

### T-01 — S2 — No per-listener TCP admission cap: one forward listener can exhaust the shared 8192-permit pool

**Evidence (verified).** The forward listener acquires the *same process-wide* semaphore that the
SOCKS accept loop uses, and holds the permit for the entire relay:

```rust
// forward.rs:51
let limiter = socks_conn_limiter().clone();
...
// forward.rs:79-94
let permit = match limiter.clone().try_acquire_owned() {
    Ok(p) => p,
    Err(_) => {
        ...
        // A forward listener has no SOCKS reply channel to carry the
        // failure: close with RST ...
        abort_tcp(&sock);
        continue;
    }
};
...
// forward.rs:98-103 — held until the relay task ends
tokio::spawn(async move {
    let _permit = permit;
    if let Err(e) = relay_tcp_forward(sock, target, pool, egress, timeout).await {
```

The SOCKS side is the same semaphore (`main.rs:470-482`), and its definition is unchanged
(`socks.rs:11` `MAX_SOCKS_CONNS = 8192`, `socks.rs:24-27` `socks_conn_limiter()`). The permit is
held for the whole flow lifetime, which is bounded by the pump's idle watchdog at
`FORWARD_TCP_IDLE = 300 s` (`forward.rs:17`, `pump.rs:489-556`). A peer that connects and sends
nothing therefore holds one permit for up to 5 minutes: the forward path has no negotiation to
complete — accept → `wait_conn` → `open_bi` → header write → pump, all with zero application bytes.
When the pool is down, the permit is held for `reconnect_timeout_secs` (default 5 s,
`main.rs:373`) per connection instead.

The UDP half of the same feature *does* have a per-listener limit — `max_sessions`
(`client_conf.rs:180-181`, enforced at `forward_udp.rs:164-172`, counted as
`dgram_drops::REFUSED`) — while the TCP half has no equivalent knob. The asymmetry is not
accidental in the plan (§5.2 line 301 justifies the *sharing*: "避免 SOCKS 8192 + 每转发监听器各自
8192 把进程 fd/task 上限乘出多份"), but the plan never addresses who may consume the shared pool.

**Mechanism / impact (consequence verified by code; exploitation is inferred).** With N exposed
TCP forward listeners there are N+1 independent admission points into one 8192-permit pool and no
per-point share. A peer able to reach a forward listener (the code only *warns* for a non-loopback
bind, `forward.rs:44-50`; it does not restrict) can open ~8192 idle connections and hold them for
up to 300 s; during that window:
- SOCKS5 `CONNECT` is denied — `main.rs:470-481` fails admission and drops the accepted socket;
- every other forward listener RSTs its connections (`forward.rs:79-94`);
- the server sees up to ~8192 concurrent streams (subject to its per-connection stream share,
  `server/accept.rs:87-88`), each dialing the fixed target, which can exhaust the *target's* accept
  limit (e.g. an appliance admin port, a database).
A loopback-only deployment is not a new threat (any local process already has unauthenticated
SOCKS on loopback), so the finding is conditional on an exposed listener — exactly the deployment
the README/plan warns about for this feature (`listen` on `0.0.0.0` / an interface IP for LAN
appliances). The feature therefore adds an unauthenticated ingress point that can deny the
pre-existing ingress, with no per-listener ceiling and a cheap 300 s hold.

**Fix direction.** Add an optional per-entry cap mirroring UDP's `max_sessions`, e.g.
`[[tcp_forward]] max_conns = 1024` (`Option<usize>`, clamp `1..=MAX_SOCKS_CONNS`, default = the
global cap) enforced with a nested `Arc<Semaphore>` created in `spawn_tcp_forward` and acquired
with the global permit (`try_acquire_owned` on both; a refusal is dropped/RST and rate-limited as
today). Keep the global shared permit so the fd/task ceiling is not multiplied. Optionally reserve
a SOCKS floor (e.g. a second counter that forward listeners may not consume past `MAX - SOCKS_FLOOR`)
or at minimum document in README/route-map that an exposed forward listener can starve SOCKS.
Minor, same area: `linux::tune_relay_tcp(&sock)` runs *before* the admission check
(`forward.rs:75` before `:79`), so refused connections pay 2-3 needless `setsockopt`s; move the
admission check first.

---

### T-02 — S3 — IPv4-mapped unspecified target passes config validation and the wire encoder

**Evidence (verified).** `parse_forward_target` rejects an IP literal only through
`SocketAddr::ip().is_unspecified()`:

```rust
// client_conf.rs:394-401
if let Ok(addr) = raw.parse::<SocketAddr>() {
    if addr.port() == 0 { bail!(...); }
    if addr.ip().is_unspecified() {
        bail!("{kind}[{idx}].target {raw:?}: unspecified address is not a valid target");
    }
    return Ok(TargetAddr::Ip(addr));
}
```

`[::ffff:0.0.0.0]:80` parses as `SocketAddr::V6`, and `Ipv6Addr::from(::ffff:0.0.0.0)` is *not*
`is_unspecified()` (only `::` is) — **verified with a scratch `rustc` program**: the address
parses `Ok`, `is_unspecified == false`. The shared wire encoder has the same blind spot:
`AddrHeader::header`/`TargetAddrRef::encode` only check `a.ip().is_unspecified()` for the v6 arm
(`src/mqp/addr.rs:165-178`, `122-141`), and the server-side decoder repeats it
(`src/mqp/addr.rs:205-227`). So the mapped form is accepted at every layer, contradicting plan
§4.3 ("target IP 不得为 unspecified（0.0.0.0 / ::，wire 编码本身会拒绝）") and the commit
message's "unspecified IPs ... are rejected".

**Impact.** With the server's `allow_private = true` (the setting the README requires for private
targets) the server dials `::ffff:0.0.0.0:port`; Linux routes a v4-mapped unspecified destination
like `0.0.0.0`, i.e. to the server host's own loopback (inferred, standard Linux behaviour) —
a config typo becomes a silently different target instead of a startup error. With
`allow_private = false` the shared `is_global_ip` policy recurses on the embedded v4 and filters
it (`src/dns/policy.rs:99-135`), so this is **not** an SSRF bypass — it is a validation/instruction
mismatch, hence S3. The same helper is shared by `udp_forwards`, so the UDP half inherits it.

**Fix direction.** Normalise before every unspecified test: in `parse_forward_target` map
`SocketAddrV6` through `to_ipv4_mapped()` (the file already has `unmap_listen_ip`,
`client_conf.rs:336-344`) and reject the mapped-unspecified form (or normalise it to
`TargetAddr::Ip(v4)` so the wire form matches the operator's intent). Defence in depth: add the
same check to `TargetAddrRef::header`/`decode` (which also guards the SOCKS-source paths), and
update the plan/README wording.

---

### T-03 — S3 — Overlap validation rejects legal cross-family listener pairs

**Evidence (verified).** The overlap predicate treats *any* unspecified address as covering every
other address of the same port, in either direction:

```rust
// client_conf.rs:356-363
fn listen_overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() != b.port() { return false; }
    let a_ip = unmap_listen_ip(a.ip());
    let b_ip = unmap_listen_ip(b.ip());
    a_ip == b_ip || a_ip.is_unspecified() || b_ip.is_unspecified()
}
```

`tcp_listener_dual` only creates a dual-stack socket for an IPv6 bind (`lib.rs:613-635`:
`s.set_only_v6(false)` only when `addr.is_ipv6()`), so an **IPv4 wildcard does not cover IPv6
addresses**, while the IPv6 wildcard `[::]` (dual-stack) does cover IPv4. The symmetric rule
therefore rejects pairs that bind successfully, e.g.:

- `socks_listen = "0.0.0.0:1080"` + `[[tcp_forward]] listen = "[::1]:1080"`;
- two forwards, `0.0.0.0:8080` (IPv4-only target) + `[::1]:8080` (IPv6-only target).

**Verified** on the macOS dev host with Python sockets: `0.0.0.0:P` bound and `::1:P`
(`IPV6_V6ONLY=0`) bind coexist; both listeners work. Linux's `inet_csk_bind_conflict` likewise
compares the socket addresses, and a concrete `::1` bind does not collide with a v4 wildcard —
inferred, not executed here. Impact: startup failure with an error that claims an overlap that
does not exist (`client_conf.rs:279-291`), blocking a legitimate family-split deployment; it fails
closed (no silent misroute), so S3.

**Fix direction.** Make the rule family-aware: with `a4 = unmap(a)`, `b4 = unmap(b)`:
`overlap = a4 == b4` **or** (`a4` unspecified and its family covers `b4`: v4 wildcard covers v4
only, v6 wildcard `[::]` covers v4-mapped and v6), mirrored for `b4`. i.e. `0.0.0.0:p` conflicts
only with v4/mapped addresses on `p`, `[::]:p` conflicts with everything on `p`. Keep the
`[::ffff:x]` normalisation. Add unit tests for the two pairs above (`forward_listener_overlap_…`
currently pins only the genuine-conflict cases, `client_conf.rs:611-674`).

---

### T-04 — S3 — Forward abort logging shares (and can steal) SOCKS's one-per-window abort line

**Evidence (verified).** The forward relay gates an abnormal-end line on the *process-global*
`tcp_abort_log_due()` claim but emits it at `debug!`:

```rust
// forward.rs:134-141
Err(e) => {
    // Sampled like the SOCKS abort line: `tcp_abort_log_due` gates the
    // formatting and the tracing write, not just the emission.
    if tcp_abort_log_due() {
        tracing::debug!("tcp_forward {target:?} aborted: {e:#}");
    }
    Err(e)
}
```

`tcp_abort_log_due` is one static window shared by the whole process (`stats/warn.rs:159-172`),
and the SOCKS path uses the same claim for a `warn!` line that reads `conn.stats()`
(rtt/cwnd/lost — `socks.rs:299-308`). Plan §5.4 requires for forward "异常 warn!（RST 原因 + 连接
stats，节流）" (line 332); the forward wrapper instead logs a rate-limited `warn!` with only the
error chain and no stats (`forward.rs:236-242` `warn_forward_end`).

**Mechanism / impact.** In a mixed deployment, a forward abort storm consumes the shared window to
emit lines that are filtered out at the default `info` level, *and* the suppression counter folded
into the next SOCKS warn belongs to forward aborts — so the SOCKS diagnostic that carries the path
snapshot (the one needed to diagnose a loss-driven kill) can be silently suppressed by traffic on
an unrelated listener. Conversely, when the window is won by SOCKS the forward abort detail is
lost. This is logging-only (no data-path effect), and the separate `warn_forward_end` window keeps
a forwarded-flow failure visible, so S3.

**Fix direction.** Give the forward abort its own `claim_log_window_counted` slot (as the accept and
admission lines already do), and either log it at `debug` without claiming the shared window, or
(per plan §5.4) log at `warn` and include `conn.stats()` — which requires moving the stats read
into the relay task (`conn` is available there) and dropping the redundant duplicate line. Either
way do not share SOCKS's window for a line visible at a different level.

---

### T-05 — S3 — Quadratic overlap validation and no listener-count cap

**Evidence (verified).** Per entry the validator linearly scans the previously seen listeners:

```rust
// client_conf.rs:284-292
if let Some((j, other)) = seen
    .iter()
    .find(|(_, other)| listen_overlaps(listen, *other))
{ ... }
```

so `tcp_forwards()` is O(n²) in `[[tcp_forward]]` entries (`udp_forwards()` repeats it at
`:309-317`). There is no cap on the number of entries anywhere in `client_conf.rs`; each accepted
entry becomes a listener task with a 1024-deep backlog (`lib.rs:633` `s.listen(1024)`), one fd and
kernel accept-queue memory, and (once connections are accepted) per-connection socket buffers.

**Impact.** Config is operator-owned, so this is self-DoS at worst: ~10k entries ⇒ ~50 M
`listen_overlaps` calls (startup stall of seconds to minutes) plus 10k fds/listener tasks and
kernel accept queues before the process decides anything. Normal configs (a handful of entries) are
unaffected; S3.

**Fix direction.** Cap the entry count (e.g. 256 per family) with an indexed error, and/or replace
the scan with a canonicalised sort (`Vec<(u16 port, IpAddr)>` sorted, then adjacent comparison +
wildcard bookkeeping) for O(n log n). Document the listener limit.

---

### T-06 — S3 — Listener bind happens after the QUIC pool is already dialing

**Evidence (verified).** Forward validation runs before TLS/QUIC work — good, exactly as the E2E
test asserts (`main.rs:131-136` before `:151` `load_cert_der`; `tests/forward_e2e.rs:557-591`):

```rust
// main.rs:135-136
let tcp_forwards = c.tcp_forwards()?;
let udp_forwards = c.udp_forwards()?;
```

but the actual binds happen only after `client_main` has built the pool, spawned the slot
shard threads/endpoints and let the reconnect loops start (`main.rs:278-368`), at
`main.rs:373-390`. Plan §4.4 orders the phases as "解析配置 → 绑定所有监听 → spawn 任务 → 打日志"
and the commit message says a busy port "aborts startup" — both still true (bind failure → `?` →
non-zero exit; `tests.rs:7617-7661` pins the error text), but the failure is detected *after* the
client has dialed and authenticated to the server. Additionally, entries earlier in the list have
already bound and printed `tcp_forward … (bound)` when a later entry fails.

**Impact.** Cosmetic/cleanup only: no listener is silently skipped, so the guarantee holds; the
server sees a short connect/auth/disconnect churn on a config with a busy port, and the log shows
some "(bound)" lines before the fatal error. S3.

**Fix direction.** Bind all forward listeners (both families) into a
`Vec<(TcpForwardSpec, std::net::TcpListener)>` *before* the TLS/QUIC setup, then convert/spawn
after it. This also removes the (small) window in which another local process could take the port
between validation and bind — the bind error is the authority today, binding earlier just makes
fail-fast cleaner.

---

### T-07 — S3 — Mapped-loopback listeners warn "not loopback"; link-local listens are accepted then fail at bind

**Evidence (verified).** The non-loopback warning uses the raw `IpAddr`:

```rust
// forward.rs:44-50
if !listen.ip().is_loopback() {
    warn!("tcp_forward listen {listen} is not loopback: any host that can reach it can use ...");
}
```

For a configured `[::ffff:127.0.0.1]:8080` this is **verified false** — `SocketAddr` parses it, and
`Ipv6Addr::is_loopback()` is true only for `::1`, so the mapped loopback form triggers the
"any host that can reach it can use the tunnel" warning even though the socket is loopback-only
(the overlap path already normalises this form via `unmap_listen_ip`, `client_conf.rs:336-344`;
the warning does not). The mapped listen forms are accepted but not documented in the README
listener table ("IPv4 literal / IPv6 literal / dual-stack wildcard").

Separately, a link-local listen literal such as `[fe80::1]:8080` parses and passes validation
(`client_conf.rs:370-381`) but bind fails (EADDRNOTAVAIL without a scope id — verified on the
macOS dev host with Python; Linux inferred), so startup fails at `forward.rs:40-41` with a bind
error instead of the indexed validation message. (MQP cannot carry scope ids, so this form can
never be a useful *target* either; the README mentions targets only.)

**Impact.** Misleading security warning (noise/desensitisation), and one more class of config that
fails later and with a less actionable message. Both still fail safe; S3.

**Fix direction.** Normalise before the warning: `unmap_listen_ip(listen.ip()).is_loopback()`
(move the helper into a shared spot or reuse `unmap` from `dns::policy`); reject link-local listen
addresses in `parse_forward_listen` with the entry index, or document that a scope id cannot be
configured; add the mapped literals to the README listener table if they are meant to be supported.

---

### T-08 — S3 — The pre-pump RST guarantee and the self-heal branch are not pinned by tests

**Evidence (verified).** The README and plan §5.3 promise "RST, not FIN" for every failure before
the pump takes ownership, but the unit test accepts either outcome:

```rust
// tests.rs:7352-7357
let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut probe)).await;
match read {
    Ok(Ok(0)) | Ok(Err(_)) => {}
    other => panic!("app socket must close (FIN or RST) fast, got {other:?}"),
}
```

so a regression from `abort_tcp`/`SO_LINGER(0)` to a plain drop (clean FIN — exactly the failure
mode the comment at `forward.rs:88-91` says must not happen) would still pass. Other gaps:
- the forward dead-slot self-heal branch (`forward.rs:160-170`) has no caller-level test; only
  `retire_dead_slot` itself is unit-tested (`tests.rs:3821-3926`) and the SOCKS analogue's failure
  path is exercised elsewhere. A stub connection that closes between `wait_conn` and `open_bi` and
  an assertion on `gen`/`live`/`retire_dead_slot` return would pin it;
- the E2E TCP test (`tests/forward_e2e.rs:377-436`) covers echo, half-close, 64 KiB and 32
  parallel streams but not: a second listener, a wildcard listener (`[::]` with an IPv4 client),
  a domain target, or a concurrent SOCKS CONNECT on the same client (admission sharing);
- the startup tests cover validation and one bind conflict; no test asserts the multi-listener
  case where entry 2 fails after entry 1 bound (T-06);
- `tests.rs:7617-7661` is the only shutdown-adjacent test; no test drives `shutdown_tx.send(true)`
  through a *spawned* listener and asserts it stops accepting.

**Impact.** The safety properties that a future refactor could most plausibly break (RST
disposition, self-heal) are unprotected by tests; S3.

**Fix direction.** Tighten the fail-fast test to require `Err(ConnectionReset)` (or a read error
with that kind) and to assert it on the pre-pump path, add the self-heal caller test, and extend
the E2E harness with a two-listener config exercising `[::]` + IPv4 client + a SOCKS CONNECT
alongside forward traffic.

---

## 3. Plan §5/§11 guarantees vs current HEAD code

| Plan guarantee | Code | Verdict |
|---|---|---|
| §5.1 bind before spawn; bind failure aborts startup | `forward.rs:40-43` (bind) then `:52` (spawn); error context names the listener (`:40-43`) | **Delivered.** Bind happens in the caller before spawn; test `tests.rs:7617-7661`. |
| §5.2 accept loop: transient error → rate-limited warn, 50 ms pause, continue | `forward.rs:54-70`; own `claim_forward_accept_failed_log` slot (`:216-220`) | **Delivered** (identical shape to the SOCKS loop, `main.rs:423-437`). |
| §5.2 tune relay TCP + shared process admission cap | `forward.rs:75` `tune_relay_tcp`; `:79-94` `socks_conn_limiter()` | **Delivered** (cap not multiplied); fairness gap reported as T-01. |
| §5.3 relay = SOCKS CONNECT minus negotiation/replies | `forward.rs:115-143` + `open_forward_stream` `:151-189` vs `socks.rs:126-312` | **Delivered**; the only differences are the SOCKS reply writes and the `conn.stats()` log. |
| §5.3 open_bi 5 s + dead-slot self-heal via `retire_dead_slot` | `forward.rs:161-170`; same `close_reason()` guard and argument order as `socks.rs:172-211`; `auth.rs:284-306` | **Delivered** (no divergence). |
| §5.3 header write as its own flush, 5 s budget, reset/stop on failure | `forward.rs:177-187` | **Delivered**; stack buffer, `AddrHeader::MAX_LEN`, `send.reset(0x04)`/`recv.stop(0x04)`. |
| §5.3 failure before the pump closes the app socket with **RST** | `forward.rs:122-128` + `:197-204` (`SO_LINGER(0)` on a borrowed `SockRef`, then drop) | **Delivered in code**; not pinned by the test (T-08). |
| §5.3 idle = SOCKS's 300 s, ACK = 25 s via `copy_tcp_quic_acked` | `forward.rs:17,129`; `socks.rs:7,261-267`; `pump.rs:53-61,379-392` | **Delivered, identical constants** (open/write 5 s, ACK 25 s, idle 300 s). |
| §5.4 shared 8192 cap / server stream share unchanged, no new metrics | shared semaphore (above); server untouched; no new metric structs | **Delivered**; consequence documented as T-01. |
| §5.4 abnormal end logged as throttled `warn!` with RST reason **+ conn stats** | `forward.rs:236-242` (warn, no stats) + `:137-140` (debug, shared window) | **Partially delivered** — no conn stats, and the window is shared with SOCKS at a different level (T-04). |
| §5.5 header flushed before app bytes; app bytes not gated on the dial ACK | `forward.rs:177-187` writes the header before any read; `pump.rs` starts the c2s arm immediately and only the s2c arm consumes the ACK (`pump.rs:379-392`) | **Delivered.** |
| §11 "same pump and pool path, no new copies; forwarding only removes SOCKS negotiation/replies" | `copy_tcp_quic_acked` unchanged (`git diff 1135076 HEAD -- src/tcp/pump.rs` empty); forward does no data copy; per-flow metadata cost ≤ SOCKS (see §4) | **Delivered** (the only added per-flow metadata is a `TargetAddr` clone, which SOCKS's domain decode also allocates). |
| §4.4 startup order parse → bind → spawn → log, before the SOCKS accept loop | validation `main.rs:135-136`; forward spawn `:373-390`; SOCKS bind `:408-409` | Ordering delivered at coarse level; binds occur after the QUIC pool starts (T-06). |
| §4.3 validation rules (non-zero port, bracketed v6, unspecified target, domain limits, unknown fields, max_sessions clamp) | `client_conf.rs:365-426, 319-323`; `#[serde(deny_unknown_fields)]` on `ClientConf` (`:15`) and both entries (`:163,174`) | **Delivered**, except the mapped-unspecified hole (T-02) and the over-broad overlap rule (T-03). |
| §9 resource bounds / TCP relies on existing semaphore + stream share | same | **Delivered**; no per-listener TCP cap (T-01). |

---

## 4. SOCKS5 TCP ECHO impact — explicit verdict

**Verdict: the feature cannot affect the SOCKS5 TCP ECHO code path.** Everything the ECHO
benchmark traverses is byte-identical to the baseline:

| Path | Change since `1135076` | Evidence |
|---|---|---|
| `src/bin/myquic2-client/socks.rs` (negotiate + CONNECT) | **none** | `git diff 1135076 HEAD -- src/bin/myquic2-client/socks.rs` → empty |
| `src/tcp/pump.rs` (`copy_tcp_quic_acked` + copy buffer pool) | **none** | `git diff … -- src/tcp/pump.rs` → empty |
| `src/bin/myquic2-client/pool.rs` (`pick_tcp_index`, `wait_conn`, slot selection) | **none** | `git diff … -- pool.rs` → empty |
| `src/bin/myquic2-client/auth.rs` (`retire_dead_slot`, dial loops) | **none** | `git diff … -- auth.rs` → empty |
| `src/linux.rs` (`tune_relay_tcp`) | **none** | `git diff … -- src/linux.rs` → empty |
| SOCKS5 accept loop body in `main.rs` | unchanged; the diff only adds `mod`s, the validation calls, the forward spawn loops, and moves one `let timeout` line earlier | `git diff 1135076 41031b4 -- src/bin/myquic2-client/main.rs` |
| Server TCP path (`src/bin/myquic2-server/tcp.rs`) | **none** | `git diff … -- tcp.rs` → empty |
| Runtime dependencies / allocator / profiles | no runtime dep added (`Cargo.toml` diff = version bump + dev-only `tempfile`) | `git diff 1135076 HEAD -- Cargo.toml` |

With no `[[tcp_forward]]` entries (the only configuration the ECHO benchmark needs), the new code
executes once at startup: two `ClientConf::tcp_forwards()/udp_forwards()` calls that return empty
`Vec`s, and two `for` loops over them (`main.rs:135-136,374-406`). No task, socket, timer, extra
semaphore acquire, extra lock or extra allocation is added to the per-connection SOCKS path. The
`assoc.rs`/`dispatcher.rs`/`hub.rs` changes in the same commit are the UDP raw-reply extraction
(`send_payload_uplink`) and cannot be reached by a TCP ECHO flow.

The **only** mechanisms by which this feature can alter a *concurrently running* SOCKS5 ECHO
measurement are shared-resource contention, and they are generic (identical in kind to running N
extra SOCKS CONNECTs at the same time):
1. the process-wide 8192 admission semaphore (T-01) — an active forward workload consumes permits,
   so a SOCKS accept can be refused at the instant the pool is full;
2. the shared `ConnPool` slots/cwnd and `rr` cursor — forwarded flows rotate through the same bulk
   slots and pin slot 0 for interactive ports, exactly like SOCKS flows;
3. main-runtime CPU — each forward listener parks on `accept()` (no wakeups when idle); active
   forwarded flows run the same pump on the same runtime as SOCKS;
4. server-side `MAX_STREAM_TASKS`/`stream_share` and outbound dials (server code unchanged).

So: **a SOCKS5 TCP ECHO benchmark with the shipped/forward-free config is a valid baseline and
must not show a difference attributable to this feature.** If the benchmark is run with forward
tables *configured but idle*, only listener tasks exist (parked `accept()` futures + watch
receivers: no CPU, no locks) — still no effect on ECHO, other than static fd/memory use. Only
driving traffic through a forward listener during the ECHO run introduces contention, and that
should be measured as a separate "forwarding vs SOCKS coexistence" scenario and attributed to the
shared budgets above, not to a changed ECHO path. (If the ECHO benchmark is UDP-based, note the
`assoc.rs` extraction is a separate UDP-domain audit item; it is claimed verbatim and does not
touch TCP.)

---

## 5. Checked and found sound

- **Admission permit lifetime — no leak.** The permit is acquired after accept and moved into the
  relay task as `_permit` (`forward.rs:79-99`); it is dropped on every exit path (pre-pump error,
  pump clean/abnormal end, task panic/unwind, runtime shutdown dropping the task). The cap is not
  multiplied: exactly two acquisition points exist (`main.rs:470`, `forward.rs:79`) and both use
  the same `socks_conn_limiter()` (`socks.rs:24-27`); the `MAX_SOCKS_CONNS <=
  MAX_BIDI_STREAMS_PER_CONN` compile assert (`socks.rs:14-17`) still covers both.
- **RST vs FIN / half-close.** Pre-pump failures call `abort_tcp` (`SO_LINGER=0` via a borrowed
  `SockRef`, then drop → RST), and the pump keeps its single-disposition rule: clean EOF ⇒
  `tcp.shutdown()` (FIN), any abnormal end ⇒ RST + `send.reset`/`recv.stop` gated on the
  direction's completion flag (`pump.rs:563-600`). Half-close propagation is the unchanged pump
  (`pump.rs:457-469`); the E2E test exercises app FIN → target FIN in both directions.
- **Header-write / ACK timeouts.** Same values and the same code shape as SOCKS: 5 s `open_bi`
  (`forward.rs:162` vs `socks.rs:166`), 5 s header write (`forward.rs:179` vs `socks.rs:226`),
  25 s MQP dial ACK (`TCP_DIAL_ACK_TIMEOUT`, `socks.rs:7`, consumed by the pump), 300 s idle
  (`forward.rs:17` vs `socks.rs:265`). The c2s direction is not gated on the ACK, so app bytes flow
  immediately; the header is a separate flushed write before any read, so a banner/login protocol
  sees the header without the app sending first.
- **Dead-slot self-heal — no divergence from SOCKS.** `open_forward_stream` retires the slot iff
  `conn.close_reason().is_some()` after an `open_bi` failure, passing `(&slot, slot_idx, egress,
  &conn)` — identical condition, argument order and cleanup (`retire_dead_slot` clears
  `shared`/`live`/rx stamp atomically, forgets the egress cache, retires rev2 state, bumps the
  generation; `auth.rs:244-306`). No extra writer is introduced by the forward path.
- **Priority / slot selection.** `pick_tcp_index` + `is_interactive` + `set_priority(10/0)`
  (`forward.rs:157,171-172`) are the SOCKS calls (`socks.rs:147,168-169`); an interactive target
  port pins all of a listener's flows to slot 0 with priority 10, exactly as documented in plan
  §5.3/README. No new starvation is introduced beyond the pre-existing shared-cwnd semantics.
- **No panic path in production code.** `forward.rs` has no `unwrap`/`expect`/indexing;
  `client_conf.rs` production paths use `bail!`/`?` only (the grep hits are all in `mod tests`).
  The header encode is infallible for every target the validator admits (`AddrHeader::MAX_LEN`
  259 B stack buffer covers the 255-byte-domain maximum; `header()`/`encode_into` agree by
  construction) and if it did fail, the error propagates to the RST path.
- **Accept loop does not self-starve.** Between `accept()` and `spawn` there is no `.await` (tune,
  permit, clone, spawn are synchronous), so one listener cannot back up behind slow relay work;
  the only await is the 50 ms pause on a transient accept error, matching the SOCKS loop. The
  `shutdown` watch is in the same `select!`, so SIGTERM interrupts a parked accept.
- **Shutdown / task lifecycle.** The listener is bound in the caller and spawned with the process
  shutdown watch (`main.rs:382-388`); on the signal it breaks, drops the listener socket, and its
  in-flight relay tasks end when the slot endpoints are closed (the pump reports the lost
  connection and RSTs the app). Nothing joins the listener handle, but the runtime is dropped
  immediately after `client_main` returns, so no task outlives the process; no permit or listener
  fd is retained. (`JoinHandle`s are intentionally ignored, as for the SOCKS loop.)
- **Config backward compatibility.** Both tables are `#[serde(default)]` (`client_conf.rs:146-152`)
  and unknown fields are hard errors on `ClientConf` and both entry types; a config without the
  tables parses to empty vecs and starts zero listeners (`forward_tables_are_optional`,
  `client_conf.rs:517-523`, run green on HEAD). TCP and UDP may share a port number by design;
  the SOCKS-vs-forward wildcard anti-capture case from plan §4.3 is closed by `listen_overlaps`
  (the over-rejection direction is T-03).
- **No client-side DNS.** `parse_forward_target` never resolves: IP literals are passed through,
  domain targets are only syntax-checked and sent on the wire (`client_conf.rs:383-426`), so exit
  DNS, SSRF filtering and `allow_private` remain the server's authority — the security invariant
  the plan calls out (§2.5/§9) is preserved. `is_global_ip`'s embedded-v4 recursion
  (`dns/policy.rs:99-135`) also covers mapped/translated/NAT64 forms, so no policy bypass was
  found via client config (T-02 is a validation-semantics issue, not an SSRF bypass).
- **Performance shape.** The forward per-connection path is *cheaper* than SOCKS: same pool
  lookup/`wait_conn`/`open_bi`/pump, minus SOCKS negotiation reads/writes, minus `bnd_for`'s
  `local_addr` syscall, minus two SOCKS replies. The only added per-connection metadata is
  `target.clone()` (one `String` alloc for domain targets — SOCKS's `TargetAddr::decode` allocates
  the same `String` during negotiation) plus three `Arc` bumps; no per-byte copy is added (the
  pump is untouched, and the header is a 259-byte stack write). No superlinear runtime behaviour
  in listener count or connection rate was found (the only quadratic cost is startup validation,
  T-05); idle listeners are parked `accept()` futures.

---

## 6. Cross-domain notes (outside this domain, flagged for merge)

1. `listen_overlaps` / `parse_forward_target` / `parse_forward_listen` are **shared** with
   `udp_forwards()` (`client_conf.rs:304-331`); T-02 and T-03 therefore also affect
   `[[udp_forward]]` entries. A config-domain auditor should merge rather than double-count.
2. The feature's **UDP half** changed shared code (`assoc.rs` `send_payload_uplink` extraction,
   `dispatcher.rs` raw reply mode, `hub.rs` `AssocEntry::new_raw`, `udp_stats.rs`) — out of scope
   here; the TCP report's SOCKS-ECHO verdict only covers the TCP path. Anything UDP ECHO-related
   belongs to the UDP auditor.
3. `tcp_abort_log_due()` (`stats/warn.rs:159-172`) is shared between SOCKS and all forward
   listeners (T-04). If a documentation/observability audit looks at the rate-limited logs, this
   cross-family interaction should be noted there too.
4. Server code and caps are unchanged by the commit (`git diff 1135076 HEAD -- src/bin/myquic2-server/
   → empty`), including `MAX_STREAM_TASKS`/`stream_share` (`server/accept.rs:38-93`). The client's
   shared 8192 cap remains the binding client-side constraint, consistent with plan §5.4; no
   server-side defect is attributable to this feature.
