# UDP forward-listener audit — `[[udp_forward]]` (commit `41031b4`, HEAD `7232088`)

**Question (task-2).** Adversarially audit the new client-side raw UDP forward listener
(`forward_udp.rs` + the shared `hub.rs` / `assoc.rs` / `dispatcher.rs` deltas) for logic and
performance defects: lifecycle/leaks, session starvation (`MAX_UDP_ASSOCS` 4032 shared with
SOCKS UDP `ASSOCIATE`), peer-table growth/spoofing, raw framing, dual-stack mapping, recv-error
handling, burst accounting, idle/shutdown, per-datagram vs per-peer cost, single-task CPU
ceiling, domain targets, server `socket`-per-peer cost, observability. And state explicitly
whether it can affect **SOCKS5 UDP ECHO** performance — code-level and via shared runtime
budgets.

**Commit/HEAD identity.** `git diff --stat 41031b4 7232088` = only `Cargo.lock`, `Cargo.toml`
(version bump), `README.md`. Every source line number below is HEAD **and** `41031b4`.
Baseline for the shared-code delta is `1135076`. The working tree was clean except the
`analysis/forwarding-audit/` report directory; **no source or config was modified** by this
audit.

**Scope.** `src/bin/myquic2-client/{forward_udp,hub,assoc,dispatcher,main,pool,egress,rev2}.rs`,
`src/config/{client_conf,tuning}.rs`, `src/lib.rs`, `src/udp/{batch,retry,r2_stage}.rs`,
`src/mqp/{addr,r2_flow}.rs`, and the unchanged server machinery the per-peer sessions exercise:
`src/bin/myquic2-server/{reader,forward,table,accept}.rs`. Plan
`docs/superpowers/plans/2026-10-23-client-tcp-udp-forwarding.md` §6/§9/§11/§15 and README
"UDP forwarding" sections read as **intended guarantees** to be tested against the code, not
trusted. The sibling report `analysis/forwarding-audit/socks.md` (task-3) already audits the
SOCKS-side per-packet delta; this report cross-references it instead of double-counting.

**Method.** Static reading of HEAD source, `git diff 1135076 41031b4` hunk-by-hunk, and
call-graph tracing from the new listener through the shared uplink/dispatcher paths and from
the server datagram reader to the per-session socket. **No cargo build/test was run** (bench
teammate owns the build; the client test binary is not warm in `target/debug`). This host is
macOS/arm64 (`uname`), so the Linux `udp(7)` ICMP-error behaviours below are documented-code
claims, not locally reproduced. One cheap non-repo probe: `rustc` in `/tmp` for
`SocketAddr` `FromStr` scope-id behaviour (result: scope ids are rejected at parse, so a
scoped-IPv6 target cannot be configured — see UDPF-09c). Confidence tags: **verified**
(read the exact lines), **inferred** (reasoned from verified inputs), **unprovable
statically** (needs measurement/Linux repro). Severities: S0 crash/corruption/remote memory
blow-up; S1 serious under normal load; S2 material but conditional; S3 minor.

---

## 0. Verdicts (explicit, up front)

- **Forward listener data plane CAN degrade SOCKS5 UDP ECHO**, but only when
  `[[udp_forward]]` is configured and its peers are active. The coupling is **runtime
  resource sharing, not per-packet code**: (a) one shared process-wide `UdpHub` budget of
  **4032** sessions with **no reserved SOCKS share** — a full hub refuses new SOCKS
  `UDP ASSOCIATE` with `REP=0x01` (`assoc.rs:12-19`); (b) the shared **interactive UDP egress
  connection** when both features use it (same class → shared cwnd, quinn DATAGRAM queue,
  connection stager mutex, per-slot dispatcher drain budget); (c) the shared **server session
  pool** (8192 global / fair-share `clamp(8192/holders,1024,4096)`); (d) shared **main-runtime
  CPU** with SOCKS tasks. Quantified in §5/§6.
- **With no `[[udp_forward]]` configured the feature is inert per packet**: startup only
  validates empty vectors (`main.rs:135-136`), no task/socket is created, and the only
  reachable shared-code delta is the sub-ns `StagedReply`/`reply_v6` branch overhead audited
  in `socks.md` (~0.6-0.9 ns/reply, 2-3 branches; no allocation/lock/syscall added). **No
  measurable SOCKS5 UDP ECHO regression expected** from this commit when unused.
- **No data-corruption/mis-routing defect found.** Raw reply framing is byte-correct in every
  live path (grouped flush, single flush, legacy slow path); dual-stack reply mapping is
  correct for both IPv4 and dual-stack IPv6 listeners; session id publication/teardown pairs
  exactly once and stale replies cannot cross into a re-created peer session (§3).
- **One S1 capacity defect**: by default a **single** forward listener may take the entire
  process-wide 4032-session budget (`max_sessions` default = global cap), and reaping is
  idle-timeout-only (180 s, swept on a 30 s tick). Any workload whose peers change source
  port per exchange (glibc-resolver style DNS via `resolv.conf`, TFTP, one-shot clients) at
  >~19-22 new peers/s keeps the hub permanently full: new forward peers are dropped
  (`SESSION_FULL`) **and** new SOCKS UDP associations are refused — the denial outlives the
  churn by up to ~180 s. UDPF-01.

---

## 1. Findings table (severity-sorted)

| # | Sev | Category | Location | One-line issue | Confidence |
|---|-----|----------|----------|----------------|------------|
| UDPF-01 | **S1** | capacity / shared budget | `forward_udp.rs:163-187, 223-246`; `client_conf.rs:319-323, 225-229`; `hub.rs:359-386`; `assoc.rs:12-19`; server `table.rs:461-470, 503-508`, `reader.rs:1645-1694, 1711-1741` | No SOCKS reserve and no cap-eviction: default per-listener cap equals the whole hub budget, and a full hub only frees on 180 s idle. Peer churn/spoofed sources >~19-22 new peers/s permanently deny new forward peers **and** new SOCKS `UDP ASSOCIATE` (`REP=0x01`); mixed with server fair-share, one client's forward peers can also take a large share of the server's 8192-session pool | high (mechanism) / medium (trigger prevalence) |
| UDPF-02 | **S2** | server resource amplification | server `reader.rs:1742-1807, 1711-1741`; `table.rs:461-470,503-508`; `config/tuning.rs:448-465`; `forward.rs:461-479` | Each forward peer is a full **server** session: one dual-stack UDP socket (64 KiB caps per direction; Linux kernel doubles → ~256 KiB), one reply-reader task, ~288 KiB admission charge — up to the per-connection fair cap (≤4096), i.e. up to half the server's 8192 pool from one client hop; creation (socket/setsockopt/bind/spawn) runs **inline on the shared connection datagram reader**, delaying SOCKS datagrams on that connection during peer churn | high (mechanism) / medium (magnitude) |
| UDPF-03 | **S2** | correctness / dual-stack | `forward_udp.rs:33-35`; `assoc.rs:1097-1126`; `dispatcher.rs:713-808`; no `IP_PKTINFO`/`IPV6_PKTINFO` anywhere (`grep` empty) | Replies go out the **wildcard-bound listener socket** via plain `send_to`, so the reply source address is route-chosen, not the local address the peer sent to. A connected/strict peer (glibc resolver, QUIC/DTLS endpoints) drops such replies. SOCKS deliberately avoids this by binding the relay to the advertised address (`assoc.rs:36-62`); the forward design cannot do that with one wildcard socket | verified (code) / inferred (impact) |
| UDPF-04 | **S2** | recv/send error handling | `forward_udp.rs:291-303, 419-429`; `retry.rs:271-299`; `batch.rs:491-500` | All peers share one socket, and Linux delivers a pending async ICMP error to whichever syscall next touches it (`udp(7)`): a reply to a dead peer can make the **next `send_to` for a different peer** fail (`udp_try_send_slice` drops, no retry) or make the listener's `recv_from` return `ECONNREFUSED`, where the code sleeps **20 ms, stalling every peer**. No `MSG_ERRQUEUE`/`IP_RECVERR` draining | verified (mechanism/documented) / inferred (frequency) |
| UDPF-05 | **S3** | perf / scaling | `forward_udp.rs:268-372, 285`; `main.rs:95-117, 391-406`; plan §11 `547-553` | One listener = one task with no cooperative yield inside a burst: all peers of a listener are serialized on at most one main-runtime worker, while SOCKS associations are independent tasks that can use all `main_workers`. On Linux sharded topology `main_workers = cores - slots` (often 1) so the practical delta is small, but on many-core hosts one forward listener cannot scale past one core (plan acknowledges; no `SO_REUSEPORT` sharding implemented) | verified (structure) / inferred (magnitude) |
| UDPF-06 | **S3** | perf / hot path | `forward_udp.rs:138, 142, 145, 400-404`; plan §11 `547-553` | Forward steady-state per datagram pays **two** `HashMap<SocketAddr>` lookups (`contains_key` then `get_mut`) plus a per-datagram `touched.contains(&bind)` linear scan (≤`MAX_UDP_SLOTS`=9) and a relaxed `last` load, where plan §11 claims "one foldhash HashMap lookup". SOCKS saves nothing comparable? it skips these entirely (one task per association). Estimated +10-30 ns/datagram (inferred) | verified (code) / inferred (cost) |
| UDPF-07 | **S3** | observability / supervision | `forward_udp.rs:309-316, 435-445`; `reporter.rs:44-95`; `main.rs:395-401, 458-461`; `hub.rs:290` | No current-session gauge (hub `len` is never reported; `udp_stats::session()` is cumulative), forward peers and SOCKS associations are indistinguishable in the 60 s line, session open/reap is `debug!` (default filter `info`), the fatal "listener stopped" warn shares one 1 s log window with transient recv warns (a fatal error within 1 s, or another listener's warn, **suppresses it entirely**), no counter for listener death, task is detached (JoinHandle discarded) and never restarted; shutdown `SESS_CLOSE` stays best-effort because main joins shard threads and exits without awaiting listener tasks | verified |
| UDPF-08 | **S3** | recv error taxonomy | `forward_udp.rs:305-316, 419-429`; `batch.rs:491-500` | Only six `ErrorKind`s are transient; any other kind (notably `ErrorKind::Other`/`ENOBUFS` under memory pressure) permanently stops the listener, whose socket then closes and whose refusal is silent (see UDPF-07). `recv_burst` maps any `recvmmsg` error to `Some(0)` and ends the burst with no counter. Transient arm sleeps 20 ms even for `Interrupted` (EINTR) | verified |
| UDPF-09 | **S3** | config / docs mismatches | `forward_udp.rs:36-42` vs `client_conf.rs:334-344`; `pool.rs:695-716, 724-746`; README `626, 709, 937` | (a) v4-mapped loopback `listen` (e.g. `[::ffff:127.0.0.1]:5353`) triggers the "not loopback" warning because `is_loopback()` is called without `unmap` (safe direction, spurious noise). (b) A listener's peers are **not** one egress class: class is fixed per peer from its own first payload (`pool.udp_class`), so peers of one listener may straddle up to `MAX_UDP_SLOTS`=9 egress bindings/connections — plan §11/README say "the session's UdpBind", but operators read it as per-listener. (c) README claims heavy-churn listeners should set `max_sessions`; capping protects SOCKS but does **not** fix the feature's own churn failure (UDPF-01) | verified |
| UDPF-10 | **S3** | latent invariant / test gaps | `dispatcher.rs:755-769, 776-786`; `tests.rs:7204-7235, 7382-7480`; `tests/forward_e2e.rs:441-479, 617-647` | `flush_staged` groups runs by `(app, reply_v6, sock)` but **not** by `raw`; the invariant "one relay socket ⇒ one reply mode" is real today but unasserted, so a future second entry per socket would emit a SOCKS header as forwarded payload. No test covers the grouped (`n>1`) raw flush, raw through BATCH/TRAIN multi-item staging, dual-stack-wildcard or IPv6/domain-target e2e, oversize (≥8455 B) forward datagrams, or the hub-full/churn scenario | verified (gaps) |
| UDPF-11 | **S3** | fairness | `forward_udp.rs:132-159, 268-372`; `egress.rs:164-190`; `batch.rs:46` | No per-peer or per-listener rate/fairness control: one flooding peer occupies the single listener task (its 32-datagram burst each wake) and the shared class connection's stager/cwnd; other peers of the same listener and SOCKS flows in the same class are FIFO behind it. UDP semantics make loss acceptable, but there is no isolation knob | verified |

No S0 finding. (The S1 is a capacity/availability defect, not corruption.)

---

## 2. Finding detail

### UDPF-01 — S1 — The hub budget has no SOCKS reserve, and cap pressure only frees by idle timeout

**Evidence (all verified).**
- Both features allocate from one `UdpHub`: SOCKS `handle_udp_associate` (`assoc.rs:12-20`)
  and forward `create_peer` (`forward_udp.rs:177-187`) call the **same** `hub.alloc_sess()`
  (`hub.rs:359-386`), and one `Arc<UdpHub>` is shared at startup (`main.rs:257-260`). SOCKS
  refuses with SOCKS5 `REP=0x01` when it returns `None` (`assoc.rs:14-18`); forward counts
  `dgram_drops::SESSION_FULL` and drops (`forward_udp.rs:179-186`).
- The per-listener cap is **not** isolation: unset `max_sessions` becomes
  `self.udp_assoc_count()` = the *global* cap (`client_conf.rs:319-323`; `225-229`;
  `UdpHub::with_capacity` clamps `1..=4032`, `hub.rs:319-329`). So a single listener defaults
  to being allowed to consume the whole budget (the plan §6.3 "double constraint" is a single
  constraint at defaults; §17 decision 3 kept this).
- Reaping is time-only: `sweep_idle` (`forward_udp.rs:223-246`) reaps peers whose
  `idle_since_tick(now, ASSOC_IDLE_MS)` is true — `ASSOC_IDLE_MS = 180_000` on a
  `ASSOC_IDLE_TICK_SECS = 30` tick (`hub.rs:134-135`) — i.e. a peer occupies its slot
  **180-210 s** after its last packet in either direction. There is `no evict-oldest / LRU /
  refuse-replace` path: when `len == max`, new sources are refused until the sweep frees a
  slot (`forward_udp.rs:164-187`, `hub.rs:363-374`).
- Server side: the same peer creates a server session which consumes the process-wide
  `MAX_SESSIONS_GLOBAL = 8192` semaphore and a per-connection fair share
  `clamp(8192/holders, 1024, 4096)` (`table.rs:461-470, 503-511`;
  `reader.rs:1711-1741`), so client-side optimism (up to 4032) is also throttled/refused
  server-side with no back-channel (`FAIR_SHARE`/`SESSION_FULL` counted on the server only).

**Mechanism / impact.** Forward session lifetime is tied to *source address*: each distinct
`IP:port` is a new session (`forward_udp.rs:132-159, 190-209`). Steady-state live-session
count is `new_peer_rate × [180,210] s`. With `MAX_UDP_ASSOCS = 4032`, sustained
**≥ 4032/210 ≈ 19.2/s** new sources keeps the hub full; at 100 new sources/s, live demand
(≈ 18,000) is 4.5× the budget, so all slots stay younger than the idle window and the 30 s
sweep frees nothing — the listener enters **permanent refusal**: every datagram from a new
source is dropped, while SOCKS `UDP ASSOCIATE` on the same process is denied `REP=0x01` and
forward-on-SOCKS/forward-on-server losses appear as drops. This is reachable **without an
attacker** by any DNS deployment where the peer (a local resolver/stub) creates a socket per
query (glibc `resolv.conf`-style), or by TFTP/one-shot clients; it is trivially reachable with
source spoofing on a non-loopback listener. Plan §9.3 (UDP reflection/spoofing) and README
`937` ("plan session capacity") acknowledge the risk, but the shipped **default** (`max_sessions` = 4032) allows exactly
the whole-budget takeover, and `max_sessions` only protects SOCKS — with e.g. 1024 the same
workload still fills the listener cap at ~5 new sources/s and drops new peers.
Confidence: mechanism **verified**; prevalence of per-query source ports is workload-
dependent (**inferred**, not measured here).

**Fix.** (1) Reserve capacity: give SOCKS a minimum share (e.g. cap `sum(max_sessions)` at a
fraction of `max_udp_assocs`, or reserve `max_udp_assocs - forward_budget` for
`UDP ASSOCIATE`). (2) Make cap pressure improve instead of dead-end: on `alloc_sess == None`,
reap the oldest currently-idle forward peer of the *same listener* (needs an LRU/queue over
peers; the sweep already holds `&mut self`) and retry once before refusing. (3) Consider a
shorter default idle window for forward peers (e.g. 30 s) or per-listener `idle_secs`, since
peer identity is an ephemeral source address, not a negotiated association. (4) Document the
`new_peers/s ≈ budget/idle` capacity rule and default `max_sessions` to a *fraction* of the
global budget (e.g. 1024) rather than the whole thing.

### UDPF-02 — S2 — One hop = one full server session; creation blocks the shared connection reader

**Evidence (verified).**
- Server session creation per client session: `get_or_create_sess` acquires a global semaphore
  permit (`reader.rs:1713-1741`), creates a **dual-stack UDP socket** with
  `udp_socket_dual_small("[::]:0")` (`reader.rs:1746`; value `sess_socket_buf()`, `src/lib.rs:251,272-281`; Linux
  kernel-doubling charge `config/tuning.rs:448-455`), spawns one reply-reader task
  (`reader.rs:1792-1807`), then publishes under the session shard write lock
  (`reader.rs:1814-1935`).
- The creation is **awaited inline** by `forward_server_dgram` for both IP targets
  (`server/forward.rs:461-466`) and warm-cache domain targets (`forward.rs:475-478`), i.e. on
  the per-connection datagram-reader task that also handles SOCKS session datagrams for the
  same QUIC connection.
- Per-session memory charge: `per_session_memory_bytes()` (`config/tuning.rs:456-465`) =
  `4 × sess_socket_buf() + UDP_RECV_MAX + UDP_RECV_SLACK + MQP3_FLOW_TABLE_MAX_BYTES +
  R2_SESSION_TABLES_BYTES` on Linux = `262,144 + 8,192 + 1 + 22,528 + 2,048 ≈ 294,913 B
  ≈ 288 KiB`; the pool term for `MAX_SESSIONS_GLOBAL` is ~2.25 GiB (`session_pool_memory_bytes`,
  `config/tuning.rs:477-479`; server `main.rs:221-222`).
- The server has **no per-client/per-listener quota**: one connection's cap is
  `clamp(8192/holders, 1024, 4096)` (`table.rs:503-508`), so one client's forward listener can
  hold up to 4096 server sessions (≈ half the global pool, ≈ 1.13 GiB of admission charge,
  4096 sockets and 4096 tasks) while other clients are refused at the global semaphore or
  squeezed by the shrinking fair share.

**Impact (inferred magnitude, verified mechanism).** A forward *flood* is a server resource
amplifier with no client-side back-channel: refused sessions are invisible to the client
(beyond `FAIR_SHARE`/`SESSION_FULL` in the server's 60 s line), so the client keeps creating
local sessions and sending. Inline creation cost (socket/setsockopt/bind/spawn + shard write)
on the shared reader is a head-of-line delay for all other datagrams of that connection —
including SOCKS UDP datagrams — whenever forward peer churn is high. Steady-state cost for an
established peer equals one SOCKS association's (that is inherent to the per-peer-session
design: one upstream socket per peer is required for demux, plan §2.4/§6.1).

**Fix.** (a) Document/charge the per-peer server cost in the client config guidance (the
README table says "one server session out of the server's global pool" but gives no number).
(b) Add a per-client forward-peer budget server-side if this ships for router deployments, or
reduce `MAX_SESSIONS_GLOBAL` exposure by defaulting client `max_sessions` lower (UDPF-01 fix
overlaps). (c) Move session creation off the reader task for the forward churn case
(e.g. create the socket in a spawned task and deliver the first datagram after creation) if
HOL shows up in benchmarks; not justified without measurement.

### UDPF-03 — S2 — Reply source address is route-chosen on wildcard listeners

**Evidence (verified).** The listener is created with `udp_socket_dual(&listen.to_string())`
(`forward_udp.rs:33`), which binds exactly the configured literal (`src/lib.rs:343-395`);
`0.0.0.0`/`[::]` are wildcard. Replies are written with plain `try_send_to`/`sendmmsg` on the
**listener** socket to the peer address: raw branch of `send_reply_addr`
(`assoc.rs:1116-1121`), `dispatch_one` (`dispatcher.rs:697-707`), and `flush_staged`
(`dispatcher.rs:746-802`). No `IP_PKTINFO`/`IPV6_PKTINFO` is used anywhere in the tree
(`grep` returns nothing), and `recv_from` does not even expose the local destination address.
Contrast: the SOCKS relay deliberately binds the *advertised* local address
("`bind_relay`… so every reply is sent from the address the app was told to expect",
`assoc.rs:36-62`) precisely because a wildcard bind chooses the source by route.

**Mechanism / impact (impact inferred).** On a host with several addresses on one interface
(or several interfaces), the kernel may pick a source IP for the reply that differs from the
address the peer sent its datagram to. A peer using a **connected** socket (glibc resolver
`resolv.conf` path, QUIC/DTLS handshakes that validate the 4-tuple, many VoIP stacks) filters
replies whose source does not match the connected server address and silently drops them.
A single-address host and the primary loopback (`127.0.0.1`/`[::1]`) are unaffected, but a
wildcard listener on a host with a secondary interface IP **or a secondary loopback alias**
(`127.0.0.2`, systemd-resolved's `127.0.0.53`-style setups) will reply from the primary address
of the route and be filtered — strict source matching is the common case for the documented
"DNS/QUIC/SIP/OpenVPN" use cases. This is a
behavioural difference from a real local port-forward, which README `709` explicitly
promises ("an ordinary UDP application sees the same bytes it would see from a local port
forward").

**Fix.** Either bind a concrete address (recommended in docs; the client already warns for
non-loopback wildcards, `forward_udp.rs:36-42`), or receive with `IP_PKTINFO`/`IPV6_PKTINFO`
and echo the ingress local address with `sendmsg` ancillary data (needs socket2/rustix
ancillary support; not present today). At minimum document the caveat for wildcard listeners.

### UDPF-04 — S2 — One shared socket: an async ICMP error can drop another peer's reply or stall all peers for 20 ms

**Evidence.** `udp(7)` (Linux): "All fatal errors will be passed to the user as an error
return even when the socket is not connected. This includes asynchronous errors received from
the network. **You may get an error for an earlier packet that was sent on the same socket.**"
The forward listener is one unconnected socket serving all peers (recv loop
`forward_udp.rs:287-317`; reply sends from the same socket). The code handles only the
receive-side appearance: transient kinds are retried after a **fixed 20 ms sleep**
(`forward_udp.rs:291-303`, `419-429`). The send-side appearance is not handled:
`udp_try_send_slice` counts any non-`WouldBlock` error as `failed` and drops the datagram
(`retry.rs:271-298`); `udp_try_send_grouped` has the same policy (`retry.rs:340-380`);
`recv_burst` maps any `recvmmsg` error to `Some(0)`, i.e. "drain ended", with no counter
(`batch.rs:491-500`). README `709` and the e2e churn test
(`tests/forward_e2e.rs:608-647`) only describe the receive-side story.

**Mechanism / impact (frequency inferred).** A reply to a peer that closed its socket (the
normal end of a one-shot exchange) elicits ICMP port-unreachable; the kernel queues the error
on the client's listener socket, and the *next* socket syscall — possibly a `send_to` for a
completely different peer, from any dispatcher task — consumes it and fails, losing that
unrelated reply; if the next syscall is the listener's `recv_from`, every peer is stalled for
20 ms while the loop sleeps (the error was already consumed, so the sleep is pure added
latency). Absolute frequency is bounded by kernel ICMP rate limits and unmeasured here
(macOS does not report async errors on unconnected sockets, so the e2e test cannot pin it;
on Linux the churn test exercises the receive path only). **Not S1**: kernel rate-limits make
it a loss/latency tail, not a data-integrity or permanent-outage defect.

**Fix.** Drain the error queue deliberately (`MSG_ERRQUEUE` with `IP_RECVERR`, or clear
`SO_ERROR`) so stale ICMP cannot poison unrelated sends; on a transient recv error,
`continue` without the unconditional 20 ms sleep (or sleep only for a repeated same-kind
streak); count send-side async errors separately.

### UDPF-05 — S3 — Single-task listener: one-core ceiling, no intra-burst yield

**Evidence.** `spawn_udp_forward` creates exactly one task per listener
(`forward_udp.rs:52`, `main.rs:391-406`); the run loop processes up to
`LAST_HOP_DRAIN = 32` datagrams synchronously (`forward_udp.rs:327-356`; `batch.rs:46`) with
no `yield_now` (contrast the dispatcher's saturation yield, `dispatcher.rs:1574-1588`). The
task runs on the multi-threaded main runtime, whose worker count is
`cores - slots` (min 1) on pinned Linux (`main.rs:111-117`) and `cores` on other platforms;
SOCKS per-association tasks also run there (`main.rs:486-495`) and can use all workers.

**Impact (inferred).** Per-listener aggregate throughput is capped by one core no matter how
many peers; a listener flooding its burst can also starve co-located SOCKS tasks of a worker
during that burst. On the shipped Linux/router topology `main_workers` is often 1, so the
practical difference from SOCKS is small; the asymmetry matters on many-core hosts. Plan §11
states the ceiling and defers `SO_REUSEPORT` sharding — accurate, but worth restating as an
operational limit (a single hot listener is one core; configure multiple listeners to scale).

### UDPF-06 — S3 — Per-datagram overhead vs SOCKS (and vs the plan's claim)

**Evidence.** Steady-state forward datagram: `peers.contains_key(&src)` (`forward_udp.rs:138`)
**then** `peers.get_mut(&src)?` (`:142`) — two `foldhash` `HashMap<SocketAddr>` lookups —
plus `entry.touch(now)` (one relaxed load, store ≤1/s, `hub.rs:214-221`) and
`touched.contains(&b)` (`forward_udp.rs:400-404`, up to `MAX_UDP_SLOTS = 1+MAX_UDP_EGRESS_CONNS
= 9` comparisons, `pool.rs:6`, `tuning.rs:118`). Plan §11 says "每数据报成本 = 一次 foldhash
HashMap 查找"; the code does two on the steady path (a `HashMap::entry`-style single-probe
would fix it). SOCKS skips these entirely: its binding is a stack local and the stager is
drained from the local `bind` (`assoc.rs:767-769`); forward trades its (skipped) framing decode
for the two map probes.

**Impact (inferred).** ~5-10 ns per lookup for a 17-28 B key (foldhash + one cache probe) +
a few ns scan → **+10-30 ns/datagram**, i.e. ~1-3 % of a ~1 µs/datagram relay path at
100 kpps and ~10-30 % at 1 Mpps (rough estimate; not measured). Below the noise floor for the
shipped small-packet use cases; the double lookup is still a gratuitous deviation from the
design's own claim. Fix: `match self.peers.entry(src)` (`Vacant` → create + insert, `Occupied`
→ send) — one probe, and it also removes the `get_mut(...)?` re-probe.

### UDPF-07 — S3 — Observability and supervision gaps (acceptance §15.6 only partially met)

**Evidence.** (a) No concurrent-session metric: `udp_stats::session()` is a process-wide
cumulative `fetch_add` (`src/stats/udp_stats.rs:227-230`) and the reporter prints it as
"session(s) in interval" (`reporter.rs:44-95`); `UdpHub::len` is never reported, and no
per-listener peer count exists (`peer_count` is `#[cfg(test)]`, `forward_udp.rs:115-118`).
(b) Forward peers and SOCKS associations share the same counters/classes: `REFUSED` is used
both for the per-listener cap and SOCKS framing refusals; `SESSION_FULL` is used both for hub
exhaustion and engine refusals (`forward_udp.rs:167, 179, 386`; `assoc.rs:180` onward), so the
60 s line cannot answer "is forwarding eating the budget?". (c) Session open/reap lines are
`tracing::debug!` (`forward_udp.rs:210-213, 239-243, 259-264`) while the client default filter
is `info` (`main.rs:54-59`) — "why was it reaped" is not answerable in production. (d) The
fatal-stop warn and the transient-retry warn share one static 1 s window
(`claim_forward_udp_recv_failed_log`, `forward_udp.rs:441-445`), and that static is
**process-wide**, not per listener: a transient warn (or another listener's warn) within the
last second suppresses "listener stopped" entirely; there is no counter for listener death.
(e) The `JoinHandle` is discarded (`main.rs:395-401`); shutdown only joins the shard threads
(`main.rs:458-461`) and the process exits, so listener tasks are not awaited and their
best-effort `SESS_CLOSE` may never be attempted (`forward_udp.rs:250-265, 367-370`).

**Fix.** Add `forward_peers` gauge (atomic per listener + `hub.len`) to the 60 s reporter;
distinguish forward drops from SOCKS drops (new `dgram_drops` classes or a per-listener prefix
in the log/metric); log listener start/stop at `info`; give the fatal path its own window/counter;
track the JoinHandle and await/observe it (or at least log task exit).

### UDPF-08 — S3 — Fatal-error taxonomy can permanently stop a listener

**Evidence.** `forward_recv_error_is_transient` (`forward_udp.rs:419-429`) treats only
`WouldBlock|Interrupted|ConnectionRefused|ConnectionReset|ConnectionAborted|TimedOut` as
recoverable; every other `ErrorKind` is "socket unusable" → `break` (`:305-316`), socket
dropped, task ends (`:370-372`). `ENOBUFS` under memory pressure maps to `ErrorKind::Other`
on std, so a transient resource condition is treated as fatal. `recv_burst` errors are
swallowed as an empty drain (`batch.rs:491-500`). The unit test only pins the six transient
and four clearly-fatal kinds (`tests.rs:7584-7611`), not resource-shaped kinds.

**Impact (inferred).** On a RAM-stressed router a single recv socket error can silently kill
a UDP forward listener until process restart (UDPF-07d means it may not even log). Low
probability; asymmetric consequence (whole listener gone) and cheap to harden. Fix: classify
by errno (`EAGAIN/EINTR/ECONN*/ETIMEDOUT/ENOBUFS/ENOMEM`) or retry any error a bounded number
of times with backoff before giving up; log + count the stop at `info`/metric.

### UDPF-09 — S3 — Config/docs mismatches

- (a) **Spurious non-loopback warning**: `if !listen.ip().is_loopback()` (`forward_udp.rs:36`)
  does not `unmap` first, while the config layer has exactly such a helper
  (`unmap_listen_ip`, `client_conf.rs:334-344`) and uses it for overlap checks. A
  `[::ffff:127.0.0.1]` listen is loopback but warns. Safe direction; annoying only.
- (b) **Egress class is per-peer, not per-listener**: `send_payload_uplink` fixes `UdpBind`
  from the *first* datagram of *each peer* via `pool.udp_class(target, payload.len())`
  (`pool.rs:724-746`; `assoc.rs:451-462`), so peers of one listener whose first payloads
  straddle `UDP_INTERACTIVE_MAX=512` (or an unlisted target port) land on different egress
  classes/connections: up to `MAX_UDP_SLOTS=9` distinct `UdpBind`s in one listener, several
  `drain_assoc_stage` calls per burst, and less TRAIN aggregation. Correct per the shared
  policy, but plan §11/README read as if the listener had one class.
- (c) **Scoped IPv6 target**: cannot be configured (std `SocketAddr` `FromStr` rejects
  `%zone`; verified with a `/tmp` `rustc` probe). So the `addr.header()` refusal for
  `scope_id != 0` (`src/mqp/addr.rs:173-181`) is unreachable from config, and README `709`'s
  "link-local literals carrying a scope id are rejected" is true by parser accident, not
  validation. No defect; the startup-fail-loud property is preserved by the parser error text.
- (d) **Churn guidance incomplete**: README `937` says set `max_sessions` for heavy peer
  churn; as shown in UDPF-01 that protects SOCKS only — the forward listener itself still
  fails at its own cap. The docs do not state the `new_sources/s ≈ budget/idle` rule.

### UDPF-10 — S3 — Latent run-key invariant and test gaps

**Latent invariant.** `flush_staged` groups consecutive staged replies by
`(app, reply_v6, same-or-inherited relay socket)` (`dispatcher.rs:746-769`) and then frames
each by `s.raw` (`:770-802`). `raw` is absent from the grouping key. Today a relay socket
belongs to exactly one `AssocEntry` and therefore to one mode (SOCKS relay sockets are
per-association, forward relay is the listener shared by one `AssocEntry` per peer), so a
mixed run is unreachable — the e2e/unit tests confirm both modes byte-exactly
(`tests.rs:7204-7267`) — but the invariant is implicit, not asserted. Fix: include `s.raw` in
the run-continuation predicate (one extra bool compare per item, zero cost) and/or
`debug_assert!` run homogeneity.

**Test gaps (verified by reading the test bodies).** Covered: raw single flush, SOCKS framing
unchanged, two-peer demux, 8 KiB payload, per-listener cap, hub exhaustion, idle-sweep
release + `SESS_CLOSE`, shutdown/drop release, recv-error classification, bind conflicts, raw
slow path, peer churn e2e. **Not covered**: grouped (`n>1`) raw flush (the `n==1` fast path
is the tested one; the multi-item `refs` path is only exercised by SOCKS framing), raw through
multi-item BATCH/TRAIN frame staging, dual-stack wildcard listener e2e (v4 peers on `[::]`),
domain-target e2e, oversize (≥ `ASSOC_RECV_BUF_LEN` = 8455 B) forward datagram, and a
hub-full/churn/pressure test (only the small-cap refusal is tested). Given UDPF-01 is the
headline defect, a test that fills a tiny hub then shows SOCKS `REP=0x01` would pin the
intended-or-not semantics.

---

## 3. Verified-correct baseline (so the audit is not read as only-negative)

These were traced line-by-line and are **correct as written**; they are the parts a future
change is most likely to break.

1. **Lifecycle: one `alloc_sess` ⇒ exactly one `release` on every exit path.**
   `create_peer` has no fallible operation between `alloc_sess` (`forward_udp.rs:177`) and
   `self.peers.insert` (`:199`); `PeerSession::drop` (`:71-78`) clears `entry.alive` and calls
   `hub.release`, which unpublishes + decrements even if `publish` never ran
   (`hub.rs:406-409, 416-425`). Removal paths are map removal (`sweep_idle` `:231`,
   `shutdown_all` `:251`) or whole-`UdpForwarder` drop; `shutdown_all` removes before sending
   `SESS_CLOSE` so fields are still live. Tests pin shutdown, drop, sweep-release and no
   double-release (`tests.rs:7536-7578, 7667-7709`). A panicking/aborted listener task leaks
   nothing (task drop ⇒ `UdpForwarder` drop ⇒ every `PeerSession` drop).
2. **No mis-routing of stale replies / re-created sessions.** Session ids are monotonic and
   never reused while live (`hub.rs:359-386`), the entry is `publish`ed before the first
   datagram (`forward_udp.rs:194-198`) so the dispatcher can never resolve a session that has
   no app address, and the dispatcher validates `sess` **and** `Weak::upgrade` **and**
   `is_alive()` on every hit, re-probing the hub on failure (`dispatcher.rs:161-218`). A late
   reply for a reaped session hits `hub.entry == None` → `UNKNOWN_SESS` counted, never
   delivered to the peer that re-created a session (new id). The previous owner's `Arc` is
   released by `unpublish` (`hub.rs:406-425`); the dispatch cache holds only `Weak`.
3. **Raw framing is byte-correct in both flush shapes and the slow path.** Grouped flush:
   `offs.push((hdrs.len(), 0))` → empty header iovec + payload (`dispatcher.rs:776-786`);
   `n==1` uses the same `offs` entry (`:788-796`); `n>1` fills `refs` from `offs`
   (`:798-802`); portable fallback with an empty header calls `udp_try_send_slice` on the
   payload directly (`retry.rs:433-441`). `dispatch_one` raw branch and the legacy
   domain-source slow path are equivalent (`dispatcher.rs:697-707`,
   `assoc.rs:1116-1121`). Raw mode writes no SOCKS5 header and the SOCKS path still does
   (unit tests `tests.rs:7204-7267`; 8 KiB e2e `tests/forward_e2e.rs:467-483`).
4. **Dual-stack mapping is correct.** `reply_v6` is fixed at construction from
   `relay.local_addr().is_ipv6()` (`hub.rs:156-171`); replies map only when the send socket is
   IPv6 (`assoc.rs:1108-1125`, `dispatcher.rs:697-701, 748-754`). Every SOCKS relay is
   dual-stack IPv6 by construction (`bind_relay` maps the v4 relay IP to v4-mapped,
   `assoc.rs:45-62`; `src/lib.rs:347-359` sets `IPV6_V6ONLY=false`), so `reply_v6` is
   **always true** for SOCKS — the new conditional cannot change SOCKS bytes (sibling
   `socks.md` §5 reaches the same conclusion). Forward: v4 listener ⇒ `reply_v6=false` ⇒ plain
   v4 send; v6 dual listener + v4 peer ⇒ peer `SocketAddr` is v4-mapped, `map_for_dual` is a
   no-op, dual-stack send works (unit test `tests.rs:7204-7235` exercises exactly this).
5. **Recv burst accounting is consistent with SOCKS.** Head awaits `recv_from(&mut buf)`, then
   at most `LAST_HOP_DRAIN - drained` more from one `recvmmsg` refill or portable
   `try_recv_from` (`forward_udp.rs:327-356`); `recv_burst(max = remaining)` cannot overshoot
   the 32-datagram budget (`batch.rs:469, 528-546`); every consumed datagram increments
   `drained`, including oversize/dropped ones, and `record_drain_batch` is called once
   (`:362`) exactly like SOCKS (`assoc.rs:770`). The truncation predicate
   (`payload.len() >= ASSOC_RECV_BUF_LEN`) is the same length for head, burst and copy paths
   by const assert (`assoc.rs:67-81`). Buffer pooling (`assoc_recv_buf`/`assoc_recycle_buf`,
   `assoc.rs:89-117`) is per-thread and bounded; the listener holds one buffer.
6. **Server-initiated `SESS_CLOSE` recovers a forward session.** The dispatcher records the
   close only for a live hub entry (`dispatcher.rs:1027-1046`) and bounds the set; the next
   forward datagram's `up.sync(rev2, sess)` consumes it, marks the old binding closed and
   re-opens (`rev2.rs:656-673`). So server fair-share/global eviction cannot black-hole a peer
   permanently — it costs one RTT of loss, consistent with UDP semantics.
7. **Domain targets stay server-side.** The client only encodes `TargetAddr::Domain`
   (`assoc.rs:439-462` → `rev2.rs:702-739`); it never resolves (plan §1.2 invariant holds,
   verified: no `resolve` call in the client). The server resolves the name once per **new
   session's first datagram** via the global positive cache first (`forward.rs:388-423`), so a
   warm domain target does not spawn a resolver task per peer; only a negative/all-filtered
   name or a very cold cache reaches the gated slow path (`forward.rs:468-558`), and that
   verdict is then negative-cached. Minor residual (inferred): a name whose first cached
   record is SSRF-filtered re-enters the gated slow path once per **new peer session** because
   the per-session destination memo starts empty — one short-lived waiter per new peer in that
   corner.
8. **No new per-datagram allocation/lock in the send path.** `send_payload_uplink` is a
   line-equivalent extraction of the previous SOCKS block (`assoc.rs:439-521` vs baseline
   diff; sibling `socks.md` confirms normalized-token equivalence); forward adds only the
   `SessionKind` label used on the cold bind/fragment `debug!` lines. Raw replies skip header
   encoding; the stager/TRAIN/drain shapes are the pre-existing ones. The one genuinely new
   per-datagram cost is UDPF-06.

---

## 4. Explicit answers to the task's questions

| # | Question | Answer | Evidence / confidence |
|---|----------|--------|-----------------------|
| 1 | Session lifecycle: `alloc_sess`/`publish`/`release` pairing, Drop on panic, idle sweep, shutdown, re-created sessions, stale replies | **Sound.** Exactly-once release via `PeerSession::Drop`; no window between alloc and insert; publish-before-send; monotonic ids; dispatcher validates sess+alive; stale replies counted `UNKNOWN_SESS`, never misdelivered | `forward_udp.rs:71-78,177-209,223-265`; `hub.rs:359-431`; `dispatcher.rs:161-218`; tests `tests.rs:7536-7578,7667-7709`. verified |
| 2 | Caps/starvation: per-listener `max_sessions` vs shared `MAX_UDP_ASSOCS` 4032; can forward starve SOCKS; spoofed-source churn | **YES, both directions.** Default `max_sessions` = global cap; forward and SOCKS share one hub and one server pool. Sustained ≥~19-22 new sources/s (trivial with spoofing; plausible with per-query source ports) fills the hub permanently: new forward peers `SESSION_FULL`, new SOCKS `UDP ASSOCIATE` `REP=0x01`. Server side: fair share `clamp(8192/holders,1024,4096)` + global 8192. No trust check on source (inherent to UDP) → spoofed sources create sessions and can reflect replies (fixed target, so abuse surface = the configured target) | `forward_udp.rs:163-187,223-246`; `client_conf.rs:319-323`; `hub.rs:359-386`; `assoc.rs:12-19`; server `table.rs:461-470,503-508`, `reader.rs:1711-1741`. mechanism verified / trigger prevalence inferred (UDPF-01) |
| 3 | Peer-table growth / spoofing | Bounded by `min(max_sessions, hub cap)` keys; one `HashMap<SocketAddr, PeerSession>` per listener, no shrink after churn peaks (bounded at cap); spoofed sources each cost a client session + a server session (UDPF-02). Reap is idle-only | `forward_udp.rs:88,163-187,223-246`. verified |
| 4 | Raw framing correctness (grouped `sendmmsg` and slow path) | **Byte-correct** in all live paths; both modes are unit/e2e tested; the only latent gap is the missing `raw` in the run-group key (unreachable today) | §3.3, UDPF-10; tests `tests.rs:7204-7267`, `tests/forward_e2e.rs:467-483`. verified |
| 5 | Dual-stack address mapping | **Correct.** `reply_v6` per entry; v4 listener sends v4; v6 dual listener sends v4-mapped; SOCKS unchanged (always v6 true). Caveat: reply **source address** is route-chosen on wildcard binds (UDPF-03) | `hub.rs:114-171`; `assoc.rs:1108-1125`; `dispatcher.rs:697-701,746-802`; `lib.rs:347-359`. verified (mapping) / inferred (source-address impact) |
| 6 | Recv error handling | Mostly resilient: ICMP-/transient-shaped kinds keep the listener alive (the pre-implementation concern that an ICMP error must not kill the listener). Residual: 20 ms sleep on all transients; send-side async errors can drop unrelated replies (UDPF-04); exotic kinds/ENOBUFS kill it (UDPF-08); fatal warn can be wholly suppressed (UDPF-07) | `forward_udp.rs:291-316,419-429`; `retry.rs:271-298`; `udp(7)`. verified mechanism |
| 7 | Recv burst accounting | **Consistent with SOCKS.** Bounded 32 per wake, `max=remaining`, all consumed datagrams counted, oversize predicate identical across arms, buffers pooled; `recvmmsg` errors read as empty drain (no counter, pre-existing shape) | §3.5; `batch.rs:46,469,528-546`. verified |
| 8 | Idle sweep / shutdown | Sweep: 30 s tick, 180 s bidirectional idle (reply activity folded via `replied` → `last`), `SESS_CLOSE` best-effort then slot release; O(peers) per tick; a **mass** idle reap (e.g. after an egress outage) runs up to 4032 × (`SESS_CLOSE` ×3 + registry/stager lock + per-slot scan) synchronously on the listener task → tens-of-ms stall + lock pressure on SOCKS for that burst (inferred). No cap-pressure eviction (UDPF-01). Shutdown: flag → `shutdown_all`; main exits without awaiting the task, so the close is best-effort | `forward_udp.rs:223-265,364-370`; `rev2.rs:526-604`; `main.rs:439-462`. verified / magnitude inferred |
| 9 | DNS/domain target handling | Client never resolves (invariant holds). Server resolves per **peer-session first datagram**, global-cache first; warm names cost no task per peer; negative names are cached/refused without sessions. Corner: first-cached-record-filtered domain can spawn one short waiter per new peer. No client-side cache interaction | §3.7; `server/forward.rs:388-423,435-558`. verified / corner inferred |
| 10 | Server upstream socket per peer | **One socket + one reader task + ~288 KiB admission charge per forward peer on Linux** (64 KiB caps/direction ×2 kernel doubling + 8 KiB userspace + ~24 KiB tables + 2 KiB r2 tables); up to fair cap 4096 ⇒ ≈1.13 GiB charge + 4096 fds/tasks; creation inline on the shared connection reader (HOL for SOCKS on that connection) | server `reader.rs:1746,1792-1807`; `table.rs:461-470,503-508`; `config/tuning.rs:448-465`. verified (formula/facts) / inferred (HOL magnitude) — UDPF-02 |
| 11 | Observability gaps | See UDPF-07: no concurrent gauge, shared drop counters, debug-only lifecycle, suppressible fatal log, no supervision, no metric for listener death; acceptance §15.6 ("session count/why reaped") is only partially satisfied | verified |

---

## 5. "SOCKS5 UDP ECHO impact" — explicit verdict

**Code-level (per packet when `[[udp_forward]]` is absent): no measurable impact.**
The SOCKS UDP hot path executes:
- one extra `send_payload_uplink` call boundary per app datagram (`assoc.rs:391-402`), whose
  body is the previous block moved verbatim (only `kind.label()` on cold debug lines);
- two `bool` fields loaded/copied per staged reply (`raw`, `reply_v6`, `dispatcher.rs:101-137`)
  and a `reply_v6` compare in the run-extension predicate + one `if s.raw` per frame
  (`dispatcher.rs:755-786`), and one `reply_v6` branch/bool load in the slow path
  (`assoc.rs:1108-1125`) and `dispatch_one` (test-only, `dispatcher.rs:697-707`);
- one extra `getsockname` per **association creation** (`AssocEntry::with_reply_mode`,
  `hub.rs:156-159`) — cold path, once per `UDP ASSOCIATE`.

No allocation, lock, atomic, syscall or wire-byte change enters the per-datagram or per-reply
path; `reply_v6` is provably `true` and `raw_reply` `false` for SOCKS relays, so behaviour is
identical. Sibling `socks.md` measures the delta at ~2-3 well-predicted branches ≈0.6-0.9 ns
per reply and confirms `AssocEntry` stays 48 B (only `StagedReply` grows 104→112 B). This is
below benchmark noise; **the commit is not a SOCKS ECHO regression when the feature is
unused.**

**Runtime shared-budget: YES — conditional on configuring/using forward listeners.**
The forward listener is a second consumer of mechanisms sized for SOCKS only:
1. **`UdpHub` 4032** — a full hub denies new SOCKS `UDP ASSOCIATE` (`REP=0x01`, `assoc.rs:14-18`);
   forward peers hold slots for 180-210 s after their last packet (UDPF-01).
2. **Interactive egress connection (class isolation is between classes, not applications)** —
   a SOCKS ECHO with first payload ≤512 B rides the single interactive connection
   (`pool.rs:724-746`; one slot, `pool.rs:674-680`), and so does any forward target on an
   `interactive_ports` port (53/123/3478-3481) or any forward peer whose first payload ≤512 B.
   They then share that connection's congestion window, quinn DATAGRAM buffer/backpressure,
   the connection-level `R2Stager` mutex, and its single dispatcher task — whose per-wake
   budget is `LAST_HOP_DRAIN=32` datagrams / 64 staged replies
   (`dispatcher.rs:1519-1592`). Under forward load, ECHO pps/latency degrade proportionally.
3. **Per-connection rev2 flow registry 4096** (`src/mqp/r2_flow.rs:40`) — every established
   forward peer occupies ≥1 flow binding on the same connection; SOCKS ECHO stays steady (no
   per-datagram registry use) but near the cap SOCKS associations fall back to `INLINE`
   datagrams (more bytes; server re-resolves domain targets through the cache per datagram),
   and new forward flows get `FLOW_REJECT(table_full)`.
4. **Dispatcher direct-mapped cache 4096** (`dispatcher.rs:8-26`) — 4032 live forward ids plus
   the ECHO session(s) means collisions are expected; the code's own note says round-robin
   hit rate goes from 100 % (fresh consecutive window) to ~37 % under churn, and a miss is a
   hub probe + `Weak` upgrade. Per-reply cost rises by tens of ns — a CPU effect only.
5. **Main-runtime CPU** — forward listener task(s) share the main runtime workers with all
   SOCKS tasks (`main.rs:95-117, 486-495`); a listener's 32-datagram synchronous burst can
   delay a co-scheduled ECHO task on a small `main_workers` count.
6. **Server side** — forward peers consume the server's 8192 global sessions / fair share
   (`table.rs:461,503-511`) and their first datagrams pay inline session creation on the same
   connection reader (`forward.rs:461-479`); SOCKS datagram drops (`FAIR_SHARE`,
   `SESSION_FULL`) are invisible to the client.

**Benchmark implication.** The parent-vs-HEAD ECHO A/B with **no forward config** should be
within noise; any repeatable >1 % regression should be attributed to codegen (see `socks.md`
R1), not this feature. If `analysis/forwarding-audit/bench.md` runs with an active forward
listener, expect the §5.2-5.6 coupling (proportional to forward load in the same class), not
a per-packet SOCKS slowdown; the benchmark report should state whether a forward listener was
configured.

---

## 6. Resource-budget interaction table (SOCKS vs forward, UDP focus)

| # | Resource | Bound (source) | SOCKS UDP ECHO user | Forward user | Can forward starve SOCKS? | Evidence / confidence |
|---|----------|----------------|---------------------|--------------|---------------------------|-----------------------|
| U1 | Client UDP-association slots (`UdpHub`) | 4032 process-wide, `max_udp_assocs` configurable 1..=4032 (`tuning.rs:187`; `hub.rs:319-329,359-386`); default per-listener cap = same number (`client_conf.rs:319-323`) | 1 per `UDP ASSOCIATE`, held until close/idle | 1 per **peer source address**, 180-210 s idle lifetime | **YES** — full hub ⇒ new SOCKS assoc refused `REP=0x01`; measured threshold ≈19-22 new peers/s sustained | verified (UDPF-01) |
| U2 | Client relay sockets/fds | 1 per SOCKS association (`assoc.rs:45-62`) | 1 fd + 64 KiB caps/direction | **0 extra** — all peers share the listener socket (one fd per listener) | No fd coupling; forward is cheaper client-side | verified (`forward_udp.rs:35,190`) |
| U3 | Listener socket kernel buffers | `udp_socket_dual` = `ENDPOINT_SOCKET_BUF` 4 MiB per direction (`lib.rs:151-158,343-395`) | SOCKS relay uses `sess_socket_buf` 64 KiB/direction (`lib.rs:251,333`) | up to ~16 MiB caps per listener on Linux (kernel doubling) | Indirect (memory pressure only); not per-datagram | verified formula |
| U4 | Interactive egress QUIC connection (class) | 1 connection (`pool.rs:6,674-680`) | ECHO with ≤512 B first payload → interactive slot | forward target in `interactive_ports` or first payload ≤512 B → same connection | **YES (load-proportional)** — shared cwnd, quinn DATAGRAM queue, stager mutex, dispatcher 32/64 drain budget (`dispatcher.rs:1519-1592`) | verified mechanism / magnitude needs bench |
| U5 | Per-connection rev2 flow registry | 4096 bindings (`src/mqp/r2_flow.rs:40`) | 1 per association (targets) | 1 per peer session (target) | **YES at scale** — near cap SOCKS falls back to `INLINE` per datagram (bytes+server CPU); new binds rejected `table_full` | verified (`rev2.rs:1015-1050`, `dispatcher.rs:954-1050`) |
| U6 | Connection stager | bounded items/bytes (`src/udp/r2_stage.rs`); shared per egress connection | staged small payloads share TRAIN | same, cross-peer/cross-session TRAIN | Transient `BUFFER_FULL` drops under simultaneous saturation; drained at each burst end | verified shape / magnitude inferred |
| U7 | Dispatcher per-wake budget + dispatch cache | 32 datagram / 64 staged replies; 4096-slot direct-mapped cache (`dispatcher.rs:26,1519-1592`) | 1 reply per ECHO datagram | 1 reply per peer reply; more live ids ⇒ cache collisions | **YES (CPU/latency)** — e.g. hit-rate 100 %→~37 % at 4032 live ids (code's own estimate), plus shared drain budget | verified mechanism |
| U8 | Main-runtime workers / CPU | `cores - slots` (min 1) pinned Linux, else `cores` (`main.rs:95-117`); one task per listener (`forward_udp.rs:52`) | one task per association | one **task per listener** (all peers serialized) | **YES** — forward burst CPU can delay co-scheduled SOCKS tasks; forward itself capped at 1 core per listener | verified structure / inferred magnitude |
| U9 | Server UDP sessions | global 8192; per-connection `clamp(8192/holders,1024,4096)` (`table.rs:461-470,503-511`) | 1 per association | 1 per peer source | **YES** — up to 4096/session-half of server pool + new SOCKS sessions refused `FAIR_SHARE`/`SESSION_FULL` server-side (invisible to client) | verified |
| U10 | Server per-session memory/fd/task | `per_session_memory_bytes()` ≈288 KiB Linux charge; socket 64 KiB caps/direction + 8 KiB buf + reply task (`config/tuning.rs:456-465`; `reader.rs:1746,1792-1807`) | same cost per association | same cost per peer (churn = repeated full create/destroy) | Indirect (server pool pressure); churn adds reader HOL | verified (formula) |
| U11 | Startup | forward validation/bind runs **before** the SOCKS listener (`main.rs:131-136,370-406`) | — | a bad forward config aborts client start | **YES** — config typo takes SOCKS down (fail-loud by design; also noted `socks.md` R2i) | verified |
| U12 | Counters/reporter | `udp_stats::session()` cumulative; `dgram_drops` classes (`reporter.rs:44-95`) | same counters | same counters | Diagnostic ambiguity only (UDPF-07) | verified |

TCP-side rows (shared `socks_conn_limiter` 8192, pool slots, bidi stream credit) are unchanged
by the UDP half of the feature and are tabulated in `socks.md` §6 (R2a/R2f/R2g); not repeated.

---

## 7. Per-datagram vs per-peer/per-session cost accounting (concrete)

**Per steady-state datagram (forward listener hot path, no session creation):**
| step | code | cost class |
|---|---|---|
| recv (amortized) | `recv_from` head / `recvmmsg` refill up to 32 (`forward_udp.rs:287-356`) | 1 syscall / N datagrams |
| coarse clock | `coarse_millis()` once per burst (`:318`; `src/time/coarse.rs`) | 1 relaxed load / burst |
| peer lookup #1 | `peers.contains_key(&src)` (`:138`) | hash+probe per datagram |
| peer lookup #2 | `peers.get_mut(&src)?` (`:142`) | hash+probe per datagram |
| liveness | `entry.touch(now)` (`:145`; `hub.rs:214-221`) | 1 relaxed load/datagram, 1 store/s |
| send shared path | `send_payload_uplink` → memo hit → `send_uplink` (`assoc.rs:439-521`; `rev2.rs:702-739`) — identical to SOCKS: `up.sync` epoch + `take_session_closed` relaxed load, `frame_limit` load, `addr.header()` validate (domain targets compare the name string per datagram), `ensure_binding` one-slot memo compare, push into connection stager (mutex) | same as SOCKS; +1-2 relaxed loads |
| binding dedupe | `touched.contains(&b)` (`:400-404`) | ≤9 compares/datagram |
| burst drain | one `drain_assoc_stage` per distinct `UdpBind` (`:359-362`) | per burst per bind (not per datagram) |
| stats | `record_drain_batch` (`:362`) | 1 / burst |

**Versus SOCKS:** forward skips SOCKS5 framing decode (`socks_udp_frame`, `assoc.rs:197-236`)
and the app-IP/source-lock checks (`:307-361`), so the net per-datagram delta is roughly the
extra hash probe (+6-15 ns) and the `touched` scan (+2-5 ns) — inferred, small; the plan's
"one lookup" claim is nonetheless inaccurate (§UDPF-06).

**Per new peer / session (client):** `hub.alloc_sess` (global `len` CAS + shard `contains_key`,
`hub.rs:359-386`) → `AssocEntry::new_raw` (one `getsockname` via `local_addr`, plus allocations:
`Arc<AssocEntry>`, `ArcSwap<FlowTable>`, `Arc<SocketAddr>`, relay `Arc` clone) → `hub.publish`
(RCU clone of a shard map, ~16 entries at full house, `hub.rs:393-399`) → `peers.insert`
(HashMap growth) → first `send_payload_uplink` (class derivation `pool.udp_class` — port-set
lookups + size check, `pool.rs:724-746`; egress `acquire` if memo cold; `DATA OPEN` frame,
possible server-side session creation) → `udp_stats::session()` global RMW. Roughly
microseconds + ~4-6 allocations (inferred); **no fd and no task on the client**, unlike a
SOCKS association which also allocates a relay socket + task.

**Per new peer (server):** semaphore permit + `socket()` + 3-4 `setsockopt` + `bind` +
non-blocking + tokio registration + `tokio::spawn` of a reply-reader + shard write-lock insert
+ admission charge ≈288 KiB (Linux) — i.e. **equal to a SOCKS association's server cost**,
paid at raw-source churn rate (UDPF-02).

**Per listener:** one bound socket (`udp_socket_dual`, up to ~16 MiB kernel caps on Linux),
one task, one ~8.3 KiB reader buffer (`assoc_recv_buf`, `ASSOC_RECV_BUF_LEN` = 8455 B), one `HashMap` that never shrinks
below its high-water mark, one 30 s timer (first deadline jittered 0-199 ms, `forward_udp.rs:276-281`).
**Per idle tick (30 s):** O(peers) scan with one atomic load + `Vec` push per idle peer
(`forward_udp.rs:223-246`); negligible at 4032 peers (~µs), but a mass reap then executes
`SESS_CLOSE` (up to 3 DATAGRAMs each, `rev2.rs:569-587`), `registry.remove_session` +
`stager.drop_session` (locks) and a `pool.slots_total()` scan **per reaped peer** on the
listener task (`rev2.rs:543-567`) — a burst of tens of ms at 4032 reaps (inferred), during
which the listener does not receive.

**Per reply (forward vs SOCKS, dispatcher path):** identical machinery — session resolve
(cache hit/miss), `stage_reply` (`mark_replied` relaxed store, relay `Arc` clone), grouped
flush; forward skips the ≤22 B SOCKS5 header encode and for `n==1` takes the empty-header
`try_send_to` fast path (`retry.rs:354-380,433-441`). Forward peers add *different-app runs*,
so N peers' replies in one burst cost N `send` calls (same as N SOCKS associations), while
same-peer runs share `sendmmsg`.

---

## 8. Recommended fixes (priority order)

1. **UDPF-01:** cap the aggregate forward budget below `max_udp_assocs` (reserve a SOCKS
   share), default `max_sessions` to a fraction (e.g. 1024), make cap pressure evict the
   oldest idle peer of the listener and retry, and document the `new_sources/s ≈
   budget/idle` rule. Optionally lower the forward idle window.
2. **UDPF-02:** decide whether a forward peer is allowed to be a full server session at raw
   churn rates; if yes, document the per-peer server cost (~288 KiB charge, fd+task) in the
   config guide; if no, add a server-side per-connection forward-peer quota or a client-side
   session-rate limiter.
3. **UDPF-03:** document the wildcard-listener reply-source caveat (or implement
   `IP_PKTINFO` echo). Keep loopback binding the default recommendation.
4. **UDPF-04/08:** drain the socket error queue (`IP_RECVERR`/`MSG_ERRQUEUE`) or at least
   remove the unconditional 20 ms sleep, count send-side async errors, and widen/errno-base the
   transient taxonomy (ENOBUFS/ENOMEM retried with backoff).
5. **UDPF-07:** add a forward-peer gauge and separate forward drop accounting; log listener
   start/stop and reap at `info` (or counters); supervise the task.
6. **UDPF-06/10:** `peers.entry()` single-probe; include `raw` in the flush run key and add
   the missing grouped/batch/dual-stack/oversize/churn tests.

---

## 9. Evidence ledger

| claim group | evidence type | confidence |
|---|---|---|
| HEAD source == `41031b4`; only Cargo/README differ | `git diff --stat 41031b4 7232088`; `git log --oneline` | verified |
| Forward and SOCKS share the one hub budget; default per-listener cap = global cap | `main.rs:257-260`; `assoc.rs:12-20`; `forward_udp.rs:177`; `client_conf.rs:319-323,225-229`; `hub.rs:319-329,359-386` | verified |
| 180 s idle / 30 s tick / idle-only reap / no eviction at cap | `hub.rs:134-135`; `forward_udp.rs:223-246,164-187` | verified |
| Churn threshold math | arithmetic on `MAX_UDP_ASSOCS` 4032 (`tuning.rs:187`) and lifetime [180,210] s | inferred |
| Server session cost and caps | `server/reader.rs:1713-1807`; `server/table.rs:461-470,503-511`; `config/tuning.rs:448-465,477-479`; `server/main.rs:221-222` | verified (formula), inferred (RSS/HOL) |
| Raw framing byte-correct in all paths | `dispatcher.rs:682-711,733-808`; `assoc.rs:1084-1121`; `retry.rs:271-299,340-459`; `tests.rs:7204-7267` | verified |
| Dual-stack mapping correct for both listener families; SOCKS unchanged | `hub.rs:156-171`; `assoc.rs:45-62,1108-1125`; `dispatcher.rs:697-701,746-754`; `lib.rs:347-359`; `socks.md` §5 | verified |
| Lifecycle exactly-once release; no stale-reply mis-route | `forward_udp.rs:71-78,177-209,223-265,370-372`; `hub.rs:359-431`; `dispatcher.rs:161-218`; `tests.rs:7536-7578,7667-7709` | verified |
| Shared-socket async ICMP cross-peer effect | `udp(7)` Linux-man; `forward_udp.rs:291-303,419-429`; `retry.rs:271-298`; `batch.rs:491-500`; `tests/forward_e2e.rs:608-647` | mechanism verified (man page + code); frequency inferred, not reproduced (macOS host) |
| Per-datagram double lookup / touched scan / estimate | `forward_udp.rs:138,142,400-404`; `pool.rs:6`; `tuning.rs:118`; cost estimate | code verified / bound inferred |
| Server SESS_CLOSE recovery path | `dispatcher.rs:1027-1046`; `rev2.rs:656-673`; `server/table.rs` sweep notification paths | verified mechanism |
| SOCKS per-packet delta ~2-3 branches, no alloc/lock | sibling `socks.md` §1/§5 (cross-reference) | verified there; not re-measured |

**Commands actually run** (read-only): `pwd`, `git log/status/diff --stat/-U0`, `git rev-parse`,
`grep`/`sed`/`wc`/`ls` across `src/` and the plan/README; one `rustc -O` probe in `/tmp` for
`SocketAddr` scope-id parsing. No cargo command, no source/config edit, no benchmark.
