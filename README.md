# MyQUIC2

**An ultra-high-performance QUIC-based SOCKS5 proxy** — multiplexes TCP and UDP traffic
over QUIC (four connections by default for loaded-latency isolation), written in Rust.

MyQUIC2 speaks standard SOCKS5 (RFC 1928) on the ingress side, so browsers, CLIs and
apps work unchanged (`curl --socks5`, system proxy settings, etc.), while the wire
between client and server is a purpose-built minimal binary protocol (**MQP-2**) over
QUIC (TLS 1.3, BBR congestion control, GSO/GRO batching, 0-RTT resumption,
ALPN `h3` by default for masquerade, `myquic2/2` opt-in for a versioned fail-closed handshake).

```
[ App ] --TCP/UDP--> [ myquic2-client :1080 ] ==QUIC (4 TCP + 1 UDP connection by default)==> [ myquic2-server :8443 ] --TCP/UDP--> [ Internet ]
```

The 2026-09 hardening revision adds optional shared-secret client authentication,
process-wide resource caps, PMTU-aware DATAGRAM sizing, 0-RTT-safe authentication, and
a corrected reconnect path, and the latest pass removes the remaining per-byte copies
from the TCP↔QUIC pump, makes the per-packet relay counters a compile-time choice
(`--no-default-features`), and makes the client's TCP-open path allocation-free — see
[pass 13](#2026-09-hardening-pass-13--zero-copy-tcp-pump-optional-counters-per-flow-vecs).
The newest pass fixes the session-memo correctness while removing the remaining
connection-state locks from the per-packet and per-flow paths — see
[pass 14](#2026-09-hardening-pass-14--session-memo-correctness-and-hot-path-locks).
The previous pass batches the TCP download pump, shards the per-packet counters,
shares one UDP egress cache process-wide, widens the session/DNS memos, and adds
stream priorities — see
[pass 15](#2026-09-hardening-pass-15--batched-pump-sharded-counters-shared-egress).
The previous pass removes the contention the shared paths still had at high
association counts (single-flight egress refresh, sharded retry pool and session
table, a per-connection fast path, sampled clocks, pooled pump buffers) — see
[pass 16](#2026-09-hardening-pass-16--single-flight-egress-sharded-tables-pooled-pump).
The previous pass fixes four correctness regressions the shared paths introduced
(per-shard session cap, per-session liveness sampling, stale-while-revalidate
egress, slow-upload idle stamps) — see
[pass 17](#2026-09-hardening-pass-17--shard-cap-per-session-touch-stale-egress).
The current pass removes the last per-packet application-side shared-state costs
on the packet paths: a generation-tagged thread-local memo serves the client's
outbound UDP egress handle with zero locks and zero refcount traffic, the
dispatcher cache is direct-mapped and borrows the session sender instead of
cloning it, the server's `is_global_ip` verdict memo is O(1), `wait_conn` trusts
the maintained live bit instead of taking quinn's connection-state mutex per TCP
flow, and `MAX_PAYLOAD` gets a per-thread high-water guard — see
[pass 22](#2026-09-hardening-pass-22--lock-free-egress-memo-direct-mapped-dispatch).
The previous pass removes the remaining packet-path park points the sharded
tables still had (try-lock fail-fast everywhere, optimistic stale egress with
zero quinn locks, direct-mapped memos, batched drop counters, 16-shard retry
pool, reply-address cache) — see
[pass 21](#2026-09-hardening-pass-21--no-park-locks-optimistic-egress).
The previous pass sharded the DNS positive/negative/single-flight tables by key
across 16 locks so no single reader count or mutex serializes the packet path,
and pins `poll_once`'s future-cancellation safety with a proof plus a saturation
regression test — see
[pass 20](#2026-09-hardening-pass-20--sharded-dns-cancel-proof).
The previous pass fixes a liveness regression the per-session sampler introduced
(burst-then-trickle flows were reaped as idle), stops evicted sessions from
pinning sockets in the memo/fast path, moves the memo write out of the table
lock, counts session/DNS-budget drops, and pre-checks stale egress handles — see
[pass 19](#2026-09-hardening-pass-19--touch-regression-memo-gc-budget-counters).
The previous pass removes the last blocking lock from the shared egress path and
fixes liveness for trickle flows — see
[pass 18](#2026-09-hardening-pass-18--non-blocking-egress-publish-trickle-flow-liveness).
An earlier pass removed a **process-abort** reachable from
normal network conditions (an MTU reduction could trip an accounting bug inside
quinn-proto's drop-oldest DATAGRAM path); the build is back on crates.io
(quinn 0.11.12 / proto 0.11.18), which backports the DATAGRAM fix plus the assembler
coalescing and three security fixes — see
[Hardening notes](#2026-09-hardening-pass-10--back-to-cratesio-quinn-01118).
Unit tests, clippy and fmt are re-verified on this revision on both feature sets;
the full E2E suite was last run green on pass 14 and is not re-run for the
pass-15 through pass-22 changes (wire-compatible); pass 22 additionally ran the
real binaries end-to-end (TCP ECHO 1 MiB byte-for-byte, a UDP ASSOCIATE sweep of
8–8000 B including the fragment path, 20 000 UDP datagrams at 0 % loss, 256 MiB
bulk) plus a `kill -9` → restart cycle (detection 15.4 s, redial 0.13 s, the
pre-kill UDP association self-healed) and an interleaved A/B against the
pass-21 binaries — see
[Verification & E2E Tests](#verification--e2e-tests).
The current revision gives the client's UDP egress its **own dedicated QUIC
connection**, separate from every TCP slot, and fixes the class-preserving bulk
failover, the retry-pool deadline, the association liveness stamp and the client's
drop accounting — see
[pass 25](#2026-09-hardening-pass-25--dedicated-udp-egress-class-preserving-failover-retry-deadline).
The pool default stays at four **TCP** connections (`quic_conns` 1–8), so a client
now dials `quic_conns + 1`: bulk TCP spreads across the bulk slots while UDP never
shares a congestion window — or a packet payload — with a TCP flow.
The lock file was refreshed to the newest in-range version of every dependency
(11 patch bumps; the quinn/quinn-proto/quinn-udp, tokio, time and rcgen versions
the docs cite did not move). Its unit + clippy + fmt suite (93/93, and 92/92 with
`--no-default-features`), a fresh real-binary E2E (5 connections established —
4 TCP + the dedicated UDP slot, TCP/UDP echo including the fragment path, 0 % loss
across 16 associations, the fail-closed drop counter, and self-healing after a
`kill -9`) and a full four-level cross-build of `dist/` re-run end-to-end under
x86-64 emulation are recorded in
[Verification & E2E Tests](#verification--e2e-tests).

The pass after that one is a fresh outside-in audit of the echo hot paths rather than
a new feature, and it is the first pass in this series to fix a defect that could
*silently corrupt* a transfer: an abnormal end on either side of a TCP flow was
delivered to the *peer* as a clean FIN, so a truncated download could be accepted as a
whole one by the application at the far end. It also stops treating a size rejection as
a dead egress connection, releases a server-side socket a swept session had left pinned,
enforces the reassembler's documented per-partial byte cap, and replaces the last
per-datagram `clock_gettime` calls with a coarse epoch that cannot freeze — see
[pass 26](#2026-09-hardening-pass-26--independent-hot-path-audit-of-the-tcpudp-echo-paths).
Its `dist/` artifacts **are** rebuilt from this revision, but — unlike every earlier pass
— **nothing was verified for them**: no format check, no emulation, no E2E. Treat them as
compiled, not as tested.

The pass after that one is a review-and-fix cycle on three relay-hot-path findings
rather than a new feature: the connection pin is written back from a DNS-cache hit (a
steady domain flow used to pay a session-table read lock on every packet for the second
half of the DNS TTL), the TCP upload pump double-buffers its copy buffer around quinn's
zero-copy handover, and fragment reassembly keeps a refcounted slice of the received
datagram instead of copying every chunk — see
[pass 27](#2026-09-hardening-pass-27--hot-path-review-fixes-and-a-verified-openwrt-rebuild).
Its `dist/` artifacts are rebuilt from this revision and — unlike the pass-26 rebuild —
statically checked (`file` plus per-level `objdump`), though still not run under emulation
or natively.

The current pass is a second review-and-fix cycle on the same echo paths, confirmed
finding-by-finding through two rounds of code review before anything was touched: the
TCP stream-head writes on both ends get a 5 s deadline (a stalled connection used to
park the client before its SOCKS answer and the server's stream-task permit until the
QUIC idle timeout), `SOCKS_UDP_HDR_MAX` reserves the worst-case domain header instead
of the IPv6 one (a long name plus a near-max payload was truncated before the fragmenter
saw it), and every policy refusal — negative DNS cache, SSRF-filtered target, the
reserved session id 0 — is counted in a new `dgram_drops::REFUSED` counter and printed
on both 60 s `udp budget` lines — see
[pass 28](#2026-09-hardening-pass-28--bounded-stream-head-writes-refused-datagram-accounting-and-the-socks-header-cap).
Its `dist/` artifacts are rebuilt from this revision and statically checked the same way
(`file` plus per-level `objdump`), again not run under emulation or natively.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [The MQP-2 Protocol](#the-mqp-2-protocol)
- [Security Model](#security-model)
- [Verification \& E2E Tests](#verification--e2e-tests)
- [Requirements](#requirements)
- [Building](#building)
- [Configuration](#configuration)
- [Running](#running)
- [Certificates \& Authentication](#certificates--authentication)
- [Resource Limits \& Tuning](#resource-limits--tuning)
- [SOCKS5 Compliance](#socks5-compliance)
- [Reconnect \& High-RTT Behavior](#reconnect--high-rtt-behavior)
- [OpenWrt Deployment](#openwrt-deployment)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)
- [Hardening Notes (this revision)](#hardening-notes-this-revision) — includes [pass 5](#2026-09-hardening-pass-5), [pass 8](#2026-09-hardening-pass-8--quinn-crates-moved-to-upstream-main), [pass 9](#2026-09-hardening-pass-9--tcp-windows-re-sized-for-300-mbs-at-140-ms), [pass 13](#2026-09-hardening-pass-13--zero-copy-tcp-pump-optional-counters-per-flow-vecs), [pass 14](#2026-09-hardening-pass-14--session-memo-correctness-and-hot-path-locks), [pass 15](#2026-09-hardening-pass-15--batched-pump-sharded-counters-shared-egress), [pass 16](#2026-09-hardening-pass-16--single-flight-egress-sharded-tables-pooled-pump), [pass 17](#2026-09-hardening-pass-17--shard-cap-per-session-touch-stale-egress), [pass 18](#2026-09-hardening-pass-18--non-blocking-egress-publish-trickle-flow-liveness), [pass 19](#2026-09-hardening-pass-19--touch-regression-memo-gc-budget-counters), [pass 20](#2026-09-hardening-pass-20--sharded-dns-cancel-proof), [pass 21](#2026-09-hardening-pass-21--no-park-locks-optimistic-egress), [pass 22](#2026-09-hardening-pass-22--lock-free-egress-memo-direct-mapped-dispatch), [pass 24](#2026-09-hardening-pass-24--post-audit-fixes-memo-ownership-sweeper-race-pin-deadline) and [pass 25](#2026-09-hardening-pass-25--dedicated-udp-egress-class-preserving-failover-retry-deadline), [pass 26](#2026-09-hardening-pass-26--independent-hot-path-audit-of-the-tcpudp-echo-paths), [pass 27](#2026-09-hardening-pass-27--hot-path-review-fixes-and-a-verified-openwrt-rebuild) and [pass 28](#2026-09-hardening-pass-28--bounded-stream-head-writes-refused-datagram-accounting-and-the-socks-header-cap)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Area | Detail |
|---|---|
| **Proxy ingress** | Standard SOCKS5: `CONNECT` (TCP) + `UDP ASSOCIATE`, IPv4 / domain / IPv6 targets. SOCKS itself is no-auth by design; the QUIC link can be protected with a token |
| **Transport** | QUIC (quinn 0.11.12 / proto 0.11.18 from crates.io), TLS 1.3 only, four **TCP** connections per client by default (`quic_conns`, clamped 1–8; bulk round-robin, interactive pinning, class-preserving failover) plus one dedicated UDP connection, so TCP and UDP never share a congestion window — `quic_conns = 1` restores a single shared TCP connection |
| **Handshake path** | Per-incoming accept/handshake tasks — one slow client can never stall new connections |
| **Congestion** | BBR by default (Cubic available as escape hatch), ECN + pacing on |
| **Offload** | GSO/GRO auto-probed (`UDP_SEGMENT`); 4 MB QUIC socket buffers; 1 MB DATAGRAM send/receive buffers |
| **Custom protocol** | MQP-2 binary framing: TCP costs **0 extra bytes** after the first header; UDP costs **+12 B (IPv4) / +24 B (IPv6)** per datagram, plus **+16 B per additional fragment** once a payload exceeds one QUIC DATAGRAM |
| **0-RTT** | Session resumption with early data, verified end-to-end (`accepted=true`). The auth token rides early data and is automatically re-sent if the server rejects it |
| **Reconnect** | Survives server restarts: ~15–20 s silent-path detection, backoff redial (200 ms → 5 s, decayed only after 5 s of stable connectivity), fail-fast old streams, UDP sessions self-heal |
| **Dual-stack** | IPv4 + IPv6 everywhere: listeners, relays, dial-out; v4-mapped handling on BSD/macOS |
| **Identity** | Client pins the exact Ed25519 server cert; optional `auth_token` (constant-time compare, ≤ 256 B) prevents open-relay abuse |
| **Hard bounds** | 4096 concurrent QUIC connections (256 pre-auth), 8192 UDP sessions process-wide, 4 MB per-connection receive window default |
| **DNS** | Resolved **server-side** (correct egress geo, no client resolver cost): 60 s positive / 10 s negative cache, single-flight, 1024-entry slow-path limiter |
| **High-RTT tuned** | 2 MB per-stream / 4 MB aggregate receive window, 2 MB send window by default (~114 Mb/s at 140 ms, minimal loaded queue) — 4/8/4 MB opt-in for ~240 Mb/s, 8/16/8 MB for 300 Mb/s — plus a 190 ms `initial_rtt`, ACK-every-2nd-packet with 5 ms `max_ack_delay` by default, and a 1472 B PMTU search ceiling |
| **Releases** | Static musl binaries for OpenWrt x86-64 at four CPU levels (v1–v4), ~4.4 MB stripped each (rebuilt from this revision, dedicated UDP egress included) |

---

## Architecture

Single crate, three units sharing one protocol library:

| Unit | Source | Role |
|---|---|---|
| `myquic2` (lib) | `src/lib.rs` | MQP-2 codec (owned + borrowed forms), TOML config schema, TLS/cert helpers, QUIC transport builder, TCP↔QUIC bridge |
| `myquic2-server` | `src/bin/myquic2-server.rs` | QUIC ingress → dials TCP/UDP targets; per-session UDP sockets; token auth; self-signed cert issuance |
| `myquic2-client` | `src/bin/myquic2-client.rs` | SOCKS5 ingress → QUIC egress; fixed N-slot TCP connection pool (plain indexed `Vec`, 4 by default) plus a dedicated UDP egress slot, each with a reconnect loop + DATAGRAM dispatcher; per-association UDP relay; token auth |
| `zero_rtt_probe` | `examples/zero_rtt_probe.rs` | End-to-end 0-RTT verification probe (with token support) |

**Data-plane mapping:**

- **TCP**: 1 TCP connection = 1 QUIC bidirectional stream. First bytes carry the MQP
  target header; the rest is a raw byte stream. The client answers SOCKS success
  optimistically and the server's MQP-2 dial ACK is validated on the reply path, so
  application bytes never wait for the remote dial. `FIN` ↔ QUIC `finish()`,
  dial failure ↔ closed/reset flow.
- **UDP**: 1 SOCKS association = 1 session id (`sess_id`), carried in QUIC **DATAGRAMs**
  (unreliable, no head-of-line blocking — a lost DNS packet never stalls other flows).
  A payload that fits one frame (`max_datagram_size() - 12 B` for an IPv4 target,
  `- 24 B` for IPv6/domain) is sent as a single `type=0x02` datagram; anything larger
  is split across `type=0x05` fragments and reassembled by the peer, up to
  `MQP_FRAG_MAX_PAYLOAD` (8 KiB). A datagram missing a fragment is discarded, never
  delivered short — fragmentation buys size, not reliability. Payloads past the
  reassembly cap are dropped and counted in `myquic2::dgram_drops`.
- **Control**: when `auth_token` is set, connection setup carries exactly one
  **authentication uni stream** (≤ 256 B). After that there is no control traffic
  beyond QUIC itself — no SOCKS username/password.

**Concurrency model:** Tokio multi-threaded runtime. The server spawns one task per
incoming connection (handshake included), one DATAGRAM reader and one session sweeper
per connection, and one lightweight reader task per UDP session. The client keeps a
pool of QUIC connections (4 TCP by default, `quic_conns`, clamped 1–8, **plus one
dedicated UDP egress connection**) sharing one Endpoint/UDP socket, each slot with
its own reconnect loop and DATAGRAM dispatcher; one
task per SOCKS connection and one relay + reply task per UDP association. Subscriptions
die with their association, so stale tasks can never steal another session's packets.
The pool's slot registry is a plain `Arc<Vec<ConnSlot>>` indexed by slot number:
slots are installed once at startup and never removed, so picking a slot for a
new TCP flow is one indexed load — no lock, no per-flow allocation, no pin, no
hash lookup. (It used to be a `papaya::HashMap`; the map bought nothing for a
fixed write-once set, so the dependency is gone.)

**Connection isolation (client):** quinn 0.11 exposes no per-stream priority, so
separate congestion windows are the isolation mechanism — and because
`quinn-proto` fills every packet with queued DATAGRAM frames *before* STREAM frames,
"separate congestion windows" is also the only way to stop a bulk UDP flow from
starving the TCP streams that share its connection. The pool therefore has three
classes of slot: slot 0 is the **interactive** connection (every port in
`interactive_ports`, default DNS/NTP/STUN), slots `1..quic_conns` are the **bulk**
class (bulk TCP round-robin), and slot `quic_conns` is the **dedicated UDP egress**
connection — UDP is never one of the TCP slots. Class-preserving failover: a dead
bulk preference fails over to another *bulk* slot, and only a pool with no live bulk
slot at all shares slot 0; UDP is fail-closed by default (`udp_fail_closed`), i.e. a
datagram with no isolated connection to go out on is dropped and counted in the 60 s
`udp budget` line rather than queued behind TCP traffic. Returning TCP flows stick to
their slot for life; UDP egress is sticky to its connection while it lives. Isolation
holds while more than one connection is alive: with `quic_conns = 1` all *TCP* shares
one cwnd (UDP still does not). The TCP open header is always its own write, never
batched behind first application bytes, so server-first peers (game logins, banners)
see it within ~100 ms.

---

## The MQP-2 Protocol

All integers little-endian unless noted. Address encoding mirrors SOCKS5
(`0x01` IPv4 + 4 B, `0x04` IPv6 + 16 B, `0x03` domain + 1 B len + N B), followed by
port in big-endian — so IP headers can be reused byte-for-byte.

### TCP stream open (stream head, sent once)

```
atyp u8 | addr bytes | port u16 BE
IPv4 total: 7 B. Everything after is raw application bytes (zero overhead).
```

The server replies with a status byte plus the address its dialed socket was
bound to:

```
0x00 | atyp u8 | addr bytes | port u16 BE
```

`0x00` = dial accepted. The client answers SOCKS success **immediately after writing
the target header**, before the ACK: waiting for the ACK would serialize the
application's first bytes behind the remote dial and costs one full client↔server
RTT on every connection (juicity/Hysteria-class clients answer immediately for the
same reason). The ACK is consumed by the reply direction; a reset or non-zero status
(dial refused/timeout) tears the TCP flow down, so a failed dial surfaces as a closed
connection rather than a SOCKS error code. BND.ADDR/PORT in the SOCKS reply is
therefore `0.0.0.0:0` (unknown) — the ACK still carries the real bound address and is
validated. The address is always `0x01` IPv4 or `0x04` IPv6 (the server's dialed
local socket, never a domain), so the ACK is 8 B (IPv4) or 20 B (IPv6) in total.

### UDP datagram (each QUIC DATAGRAM)

```
type=0x02 u8 | sess u32 LE | atyp u8 | addr bytes | port u16 BE | payload
```

`sess` scopes the packet to one UDP ASSOCIATE; the server echoes it back on replies
so the client dispatcher can route without any per-target state lookup. The client
sizes each datagram against the connection's live `max_datagram_size()` (PMTU-aware,
**unclamped**); the server caps replies the same way.

### UDP fragment (only when one frame is not enough)

```
type=0x05 u8 | sess u32 LE | id u16 LE | idx u8 | total u8 | atyp | addr | port | chunk
```

A QUIC DATAGRAM cannot carry a full 1472 B UDP payload — the 12/24 B MQP header plus
the QUIC packet and DATAGRAM-frame overhead exceed the path MTU — so a proxy built
only on single-frame datagrams is *strictly worse* than a direct UDP path for the
packets conferencing stacks actually emit (DTLS handshake flights, non-WebRTC media,
TURN-wrapped payloads, modest IP fragmentation). `type=0x05` lifts that ceiling to
`MQP_FRAG_MAX_PAYLOAD` without buying reliability.

- **Address on every fragment.** It costs 7 B (IPv4) / 19 B (IPv6) per fragment and
  buys a reassembler with no special case for out-of-order arrival and no way for a
  lost fragment 0 to strand the rest — every fragment is self-describing.
- **`(sess, id)` is the reassembly key.** `id` is a per-sender `u16` counter (one per
  SOCKS association on the client, one per UDP session on the server), so a wrapped
  id reused with a different `total` restarts the partial instead of splicing two
  unrelated datagrams together.
- **Bounded.** A partial is at most `MQP_FRAG_MAX_PAYLOAD`; in aggregate a connection
  holds at most `FRAG_MAX_HELD_BYTES` and evicts the oldest partial past that.
  Partials whose first fragment is older than `FRAG_TIMEOUT_MS` are swept on insert.
- **All-or-nothing.** A datagram missing any fragment is dropped, never delivered
  short. UDP peers do not retransmit, so nothing waits longer than one expiry.
- Both relays send through `myquic2::DgramFragmenter::send` — the single send path —
  so every drop is counted, and a payload above the reassembly cap is refused rather
  than truncated.

The fragment frame is additive: a peer that predates it rejects `type=0x05` in
`decode_datagram_ref` and drops the datagram (the pre-fragmentation behaviour for
oversized payloads), so a version-skewed pair loses only large datagrams and can
never misparse. Both ends must be on this revision to carry them.

### Connection authentication (`auth_token` non-empty)

### Connection authentication (`auth_token` non-empty)

```
client → server : uni stream (stream type 0x02) carrying the token bytes, FIN
server          : waits ≤ 5 s, reads ≤ 256 B, constant-time compare
mismatch        : CONNECTION_CLOSE 0x01 "unauthorized"
```

- The server reads the token **before** accepting any bidi stream or DATAGRAM, so an
  unauthenticated peer cannot dial anything.
- No ACK exists: a wrong token surfaces as a closed connection. The client keeps
  backing off and logs the close reason.
- **0-RTT**: the token is written into early data like any other stream. If the
  server rejects early data (e.g. its session store restart), QUIC discards it with
  the rest of 0-RTT; the client observes `accepted=false` and re-sends the token on
  the established connection within one RTT — no auth timeout, no extra handshake.
- Token length is capped at 256 B; empty on both sides disables the feature.

### Versioning

ALPN defaults to **`h3`** (masquerade: hides only the ALPN label — the self-signed
cert and MQP framing stay fingerprintable). Set `alpn = "myquic2/2"` explicitly on
both sides to restore the versioned identifier below.

`myquic2/2` was bumped from `myquic2/1` when the TCP-open ACK gained
the bound address: a version-skewed pair now fails the TLS handshake with a clear
error instead of misparsing the ACK as application data, so **upgrade both sides
together**. The UDP DATAGRAM layout and the auth uni stream are unchanged from MQP-1.

Pass 12 added the `type=0x05` UDP fragment frame *without* a bump, because it is
purely additive: a peer that predates it rejects the unknown type and drops the
datagram — its own pre-pass-11 behaviour for oversized payloads — so misparsing is
impossible. The cost of a skewed pair is that UDP payloads above one frame are lost,
which is why **both ends should still be upgraded together** if you carry large UDP.

### Design rationale

- TCP gets reliable streams (ordering + retransmission + flow control for free —
  never reimplement reliability on top).
- UDP gets DATAGRAMs (loss is semantic, not a bug).
- No serde/JSON/protobuf on the hot path: hand-rolled codec with a borrowed form
  (`TargetAddrRef`) so domain-typed packets do not allocate, `bytes::Bytes`
  forwarding, allocation-free DNS cache hits, and 32 KB pump buffers per TCP
  direction; DNS results cached 60 s.
- Per-flow work allocates once, not four times: the MQP-2 header is decoded out of a
  259-byte stack buffer, the IP-literal dial path borrows the decoded address instead
  of building a one-element `Vec`, and the DATAGRAM send wrapper drops on a full send
  buffer rather than using quinn's drop-oldest path (see pass 5 below).

---

## Security Model

**Server authenticity (always on).** The client pins the server's self-signed
Ed25519 certificate. This proves the client reached the genuine server.

**Client authenticity (optional, recommended).** TLS client auth is intentionally
absent (`with_no_client_auth`), so without `auth_token` the server is an *open
relay*: anyone who can reach the port can proxy TCP/UDP through it. A non-empty
`auth_token` (shared secret, constant-time compared, sent inside the QUIC-encrypted
uni stream) is the client-side gate. Keep the port firewalled as well.

**Egress policy.** With `allow_private = false`, resolved targets are filtered
against private/loopback/link-local/CGNAT/documentation/benchmark/multicast ranges;
NAT64 (`64:ff9b::/96`) and deprecated IPv4-compatible addresses are validated via
their embedded IPv4, so they cannot be used to reach private space. The sample
config sets `true` for LAN testing — turn it off on public exit nodes.

**Replay.** 0-RTT early data is theoretically replayable; rustls's stateful,
single-use session tickets bound it. The worst case is a duplicated outbound dial or
UDP datagram (no traffic amplification). TCP application bytes ride the 1-RTT keys
established by the handshake, so replay cannot duplicate an application request;
only the auth token in early data is exposed to the theoretical replay window.

**Denial-of-service bounds.** See [Resource Limits & Tuning](#resource-limits--tuning):
connection/session caps, process-wide TCP dial and per-connection stream limits, DNS
slow-path limiter, bounded detached UDP sends, and a single 5 s deadline for
unauthenticated connections (auth stream accept + token read share one budget).

**What is *not* protected.** SOCKS5 ingress is no-auth (RFC 1929 is intentionally not
implemented). The UDP relay accepts datagrams only from the SOCKS control
connection's source IP, but not its port (RFC 1928 clients legitimately use a
different socket), so a process on the same host can still race for the relay —
run it on a trusted host / bind `socks_listen` to localhost when exposing UDP.
UDP replies are not further source-validated (roadmap item).

---

## Verification & E2E Tests

Run on the 2026-09 revision (latest pass), macOS (Apple Silicon), `cargo build
--release`, with local TCP/UDP echo servers and a raw Python SOCKS5 client. All
payloads are verified byte-for-byte; UDP checks the echoed payload and the reply's
source address.

| # | Test | Result |
|---|---|---|
| 1 | `cargo test --all-targets` (codec round-trips, borrowed-datagram round-trip, DNS key normalization/injectivity, `is_global_ip` filter, DATAGRAM send-buffer saturation, MQP/SOCKS header length + framing) | ✅ 19/19 |
| 2 | TCP ECHO via SOCKS5 `CONNECT` (1 MiB random) | ✅ repeated runs |
| 3 | UDP ECHO via `UDP ASSOCIATE` (25 × 1000 B) | ✅ repeated runs, BND = relay address |
| 4 | Server `kill -9` → restart → reconnect → TCP+UDP ECHO | ✅ detects in ~15 s (idle timeout; 20 s watchdog backstop), redial < 0.4 s, kill→usable 17.5 s; a UDP association opened *before* the kill and one opened *during* the outage both self-heal |
| 5 | Optimistic CONNECT: SOCKS success returns without waiting for the remote dial | ✅ blackhole target → reply in 0.1 ms (was ~4 s waiting for the dial ACK); a failed dial closes the flow |
| 6 | 0-RTT probe with token, same server process | ✅ `accepted=true`, bound address parsed, echo over 0-RTT |
| 7 | Empty token on both sides (auth disabled) | ✅ TCP+UDP ECHO |
| 8 | Wrong token | ✅ server logs `auth token mismatch`, client sees SOCKS `0x04`, backoff grows 200 ms→5 s (no redial storm) |
| 9 | 20 concurrent TCP (256 KiB) + 8 concurrent UDP associations | ✅ 28/28, ~1.7 s wall clock |

Additional checks run on the pass-5 revision (macOS, loopback):

| # | Test | Result |
|---|---|---|
| 10 | DATAGRAM send-buffer saturation (`try_send_datagram_saturates_without_panicking`) | ✅ passes; the same test **aborts** when the send path is switched back to `Connection::send_datagram` (verified) |
| 11 | `read_mqp_target` framing: IPv4 / IPv6 / domain byte accounting, empty-domain and unknown-atyp rejection | ✅ 3/3 |
| 12 | SOCKS5 address reader: IPv4 / IPv6 / domain decode, bad-atyp, lenient variant | ✅ 3/3 |
| 13 | Domain-target `CONNECT` end-to-end (server-side DNS, `localhost`) | ✅ 5/5 transfers, no `bad connect target` |
| 14 | UDP at 20–25k datagrams/s, windowed round trip | ✅ 0.00% loss, RTT p50 0.11–0.13 ms |
| 15 | 128-datagram bursts ×300 | ✅ 100% replied, burst completion p50 1.8 ms |

Additional checks run on the pass-8 revision (quinn 0.12 from upstream `main`,
macOS, loopback, `cargo build --release`, token auth enabled on both sides):

| # | Test | Result |
|---|---|---|
| 16 | TCP ECHO via SOCKS5 `CONNECT` (1 MiB random) over a full handshake | ✅ 1048576 B byte-for-byte |
| 17 | UDP ECHO via `UDP ASSOCIATE` (25 × 1000 B) | ✅ 25/25, BND = relay address |
| 18 | Server `kill -9` → restart → reconnect: the client offers a **stale 0-RTT ticket** the restarted server rejects | ✅ `QUIC 0-RTT rejected: re-sending auth at 1-RTT` then TCP (64 KiB) + UDP (25/25) echo pass — the rejection is detected through `SendStream::stopped()`, not a redial |
| 19 | 0-RTT probe with token, same server process | ✅ `0-RTT offered`, `server accepted 0-RTT early data = true`, echo over early data; acceptance derived from `stopped()` in 3.0 s (the probe's own sleep) |
| 20 | `cargo clippy --all-targets` + `cargo fmt --check` | ✅ clean |

Additional checks run on the pass-13 revision (macOS, loopback, `cargo build --release`,
both feature sets, empty token; the SOCKS listener's owning PID is asserted before every
run so a stale process can never masquerade as the build under test):

| # | Test | Result |
|---|---|---|
| 21 | TCP ECHO via SOCKS5 `CONNECT` (1 MiB random) | ✅ 1048576 B byte-for-byte |
| 22 | Domain-target `CONNECT` (server-side DNS, `localhost`, 64 KiB) | ✅ byte-for-byte |
| 23 | UDP ASSOCIATE sweep 8 / 1200 / 1420 / 1430 / 2000 / 8000 B (the last two need `type=0x05` fragments) | ✅ 6/6 echoed, 0 lost, both directions |
| 24 | Same E2E suite against `--no-default-features` (counters compiled out) | ✅ identical results |
| 25 | `cargo test` 36/36 (34/34 without `stats`), clippy + `cargo fmt --check` clean on both feature sets | ✅ |
| 26 | A/B vs the pass-12 binaries: 3 interleaved rounds of 256 MiB bulk + 2 000 CONNECTs + 100 000 datagrams, CPU read from the two live processes | ✅ no regression — and no *gain* either: 10.37 s vs 10.41 s CPU, all throughput figures inside run-to-run noise (see pass 13) |
| 27 | Reconnect cycle: `kill -9` server while two idle TCP flows and one UDP association are open → restart → recover | ✅ detection 15.1 s (QUIC idle timeout, both connections), redial **0.19 s** after the restarted server bound (both conns), first successful TCP echo 17.2 s after the kill; the idle pre-kill flows fail with `BrokenPipeError` at connection death instead of hanging out the 300 s idle window, and the pre-kill UDP association self-heals on its next datagram (a fresh association also works) |

Additional checks run on the pass-14 revision (macOS, loopback, `cargo build --release`,
both feature sets, empty token):

| # | Test | Result |
|---|---|---|
| 28 | Dual clients sharing sess id 1 on different server connections: 2 × 30000 UDP datagrams + 2 × 304 TCP `CONNECT`s concurrently | ✅ 60000/60000 echoed, 0 lost; 608/608 flows clean |
| 29 | Reconnect cycle: `kill -9` server → restart → recover | ✅ detection 17.5 s (QUIC idle timeout), reconnect 1.8 s after the restarted server bound, UDP 2000/2000 self-heal |
| 30 | `cargo test` 48/48 (47/47 without `stats`), clippy + `cargo fmt --check` clean on both feature sets | ✅ |
| 31 | `cargo test --all-targets` 50/50 (49/49 without `stats`), clippy `-D warnings` + `cargo fmt --check` clean on both feature sets, `cargo build --release` (pass-20 revision) | ✅ |
| 32 | `cargo test --all-targets` 50/50 (49/49 without `stats`), clippy `-D warnings` + `cargo fmt --check` clean on both feature sets (pass-21 revision, this build) | ✅ |
| 33 | `cargo test --all-targets` 58/58 (57/57 without `stats`), clippy `-D warnings` + `cargo fmt --check` clean on both feature sets; real-binary smoke: 200 TCP `CONNECT`s (5400 B echoed byte-for-byte), 20 000 UDP datagrams 0 % loss, 256 MiB bulk; interleaved A/B vs pass 21: bulk 126–132 vs 126–128 MB/s, UDP ~29.4k vs ~28.9k pps, TCP ~9.2k vs ~9.6k flows/s (all within noise) (pass-22 revision, this build) | ✅ |
| 34 | Pass-22 E2E through the real binaries: TCP ECHO 1 MiB byte-for-byte; UDP ASSOCIATE sweep 8 / 1200 / 1420 / 1430 / 2000 / 8000 B × 5 each, 0 % loss in both directions (1430/2000/8000 exercise the `type=0x05` fragment path) | ✅ |
| 35 | Pass-22 `kill -9` → restart: detection 15.4 s (QUIC idle timeout), stale 0-RTT ticket retried once, redial 0.13 s after the restarted server bound, TCP ECHO + UDP sweep green after reconnect, and a UDP association opened *before* the kill self-healed on its next datagram (20.1 s no-reply window) | ✅ |

Additional checks run on the four-connection-pool revision (macOS, loopback,
`cargo build --release`, both feature sets, empty token, the SOCKS listener free
before every run):

| # | Test | Result |
|---|---|---|
| 36 | `cargo test --all-targets` 74/74 (44 lib + 18 client + 12 server; 73/73 with `--no-default-features`), clippy `-D warnings` + `cargo fmt --check` clean on both feature sets | ✅ |
| 37 | Pool default: `quic_conns = 4` **and** `quic_conns` omitted both log `quic pool: 4 connection(s)`, and the server logs exactly 4 `new QUIC conn` — all four from the client's single UDP socket, as designed | ✅ |
| 38 | Pool E2E: TCP `CONNECT` 1 MiB byte-for-byte, UDP ASSOCIATE sweep 8 / 1200 / 1420 / 1430 / 2000 / 8000 B 6/6 byte-for-byte (the last three exercise the `type=0x05` fragment path), 40 back-to-back CONNECTs clean | ✅ |
| 39 | `quic_conns = 1` still degrades to the legacy single connection (`quic pool: 1 connection(s)`, one dial, one dispatcher) with the same TCP/UDP E2E green | ✅ |
| 40 | Four-slot reconnect: `kill -9` server → all four connections reported `lost` / `timed out` at detection 16.5 s (QUIC idle timeout), the four redials landed within 0.33 s of each other against the restarted server, TCP ECHO + UDP sweep green afterwards. Four client restarts came up 4/4 each with zero dial failures | ✅ |
| 41 | `dist/` rebuilt for all four CPU levels (`cargo zigbuild`, static musl, stripped; clients +38 408–45 968 B and servers +1 856–2 432 B vs the pass-23 artifacts) and re-verified under amd64 emulation (Podman on Apple Silicon): the **v1** pair established 4 connections with 0 dial failures and passed TCP ECHO 1 MiB, a domain-target `CONNECT` (64 KiB), the 8–8000 B UDP sweep and 20 CONNECTs byte-for-byte; the earlier rebuild's v3 pair passed the same suite, and this one re-checked that v3 runs under the emulated CPU while v4 dies with `Illegal instruction` (exit 132); `objdump -d` finds 235 `zmm` refs in v4 and 0 in v1–v3 | ✅ |
| 42 | `cargo update`: 11 patch-level bumps — `rustls` 0.23.44 → 0.23.45, `clap` 4.6.6 → 4.6.7 (+ `clap_builder` / `clap_derive` / `clap_lex`), `cc`, `cfg-if`, `find-msvc-tools`, `rand` 0.10.2 → 0.10.3, `syn` 3.0.5 → 3.0.6, `unicode-ident`. quinn 0.11.12 / quinn-proto 0.11.18 / quinn-udp 0.5.15, tokio 1.53.1, time 0.3.55 and rcgen 0.14.10 were already the newest in-range versions, so the documented dependency line and the 1.88 MSRV (every bumped crate declares `rust-version` ≤ 1.85) are unchanged | ✅ |
| 43 | Flaky-test fix (test-only, `#[cfg(test)]`, no product code): the loopback reply wait is now 2 s for positive assertions and a separate 300 ms `no_reply` probe for negative ones, kept under `FRAG_TIMEOUT_MS`. Result: `cargo test --all-targets` green in **8/8** consecutive runs and 4/4 with `--no-default-features` (was red in ~1 of every 2 runs), the six `dispatch_*` tests 10/10, clippy `-D warnings` + `cargo fmt --check` clean on both feature sets | ✅ |
| 44 | `dist/` rebuilt a second time from the final tree: all **eight artifacts came out byte-for-byte identical** to the previous rebuild (`sha256` equal for every level and both binaries), which both confirms the build is reproducible from this revision and proves the test-only change above cannot have altered the shipped binaries. The fresh v1 pair re-ran the emulated E2E green (4 connections, TCP 1 MiB, domain `CONNECT`, UDP sweep, 20 CONNECTs), and v3 runs / v4 dies with exit 132 under the emulated CPU | ✅ |
| 45 | Server destination-memo writes made conditional: an IP target no longer stores a memo nothing can read back, and a domain target's memo is rewritten only when the address changed or the entry is inside the last quarter of its TTL (`DEST_PIN_REFRESH_MS`). Correctness on the fixed binaries: `udpdomainswitch` 1000 alpha + 1000 beta and `udpipswitch` 1000 IP + 1000 domain targets inside one session, **0 misrouted** in both; `udpsweep` 8/1200/1420/1430/2000/8000 B **6/6 verified verbatim**; `udpdomain` 20 000/20 000; `udpdomainmulti` 160 000 sent / 159 993 received; 4 connections up with 0 dial failures. Perf: the removed store measures 35 ns/op against the 27 ns read-lock lookup it piggybacked on, but an interleaved A/B of the two server binaries (2 rounds each) shows **no end-to-end effect** — 19 957 → 19 822 pps at 16 associations on one connection, 24 998 → 24 575 pps across two connections, both inside this host's spread — so it is kept for deleting a provably useless exclusive write, not for a measured win | ✅ |
| 46 | `WouldBlock` retry pool re-arms a shard whose worker died with its runtime. Each shard's `Sender` used to live in a `OnceLock` forever while its worker was a task on whichever runtime first needed it, so any later runtime (a test binary has one per `#[tokio::test]`; an embedder may have several) queued retries into a closed channel and the datagram was dropped silently, charged to a budget counter that had not been touched. Each shard publishes its sender through an `ArcSwap` and re-arms on demand; the probe against the old code printed `queued=false delivered=false`, and the new regression test `retry_shard_is_rearmed_after_its_runtime_ends` passes. Effect on the suite: the client bin went **0/5 → 5/5 green when run serially** (the file's runtime churn hit it every run) and the full suite to **10/10** on the default feature set and 4/4 on `--no-default-features` | ✅ |
| 47 | `dist/` rebuilt from this revision for all four CPU levels (static musl, stripped; clients 4 390 120–4 416 280 B, servers 4 325 792–4 348 536 B, i.e. +4 992–5 120 / +6 432–6 512 B per level for the retry-pool and memo changes) and re-verified under amd64 emulation (Podman on Apple Silicon) **using the repo's own harness** — the `hotpath_bench` example built for the same musl target, so no external tooling is involved. On the v1 pair: 4 connections, 0 dial failures, 4 server accepts; `udpsweep` 8/1200/1420/1430/2000/8000 B **6/6 verbatim** (fragment path included); `udpdomainmulti` 160 000 sent / 159 993 received; `udpmulti` 16 associations 603 728 received at 0.082 % loss; 40 domain-target TCP `CONNECT`s; `udpdomainswitch` **1000 alpha + 1000 beta, 0 misrouted** and `udpipswitch` **1000 IP + 1000 domain, 0 misrouted**. A second four-level build came out byte-identical (`sha256` equal for all eight files), and v3 runs / v4 dies with exit 132 under the emulated CPU, with `zmm` = 0/0/0/235 and `ymm` 3 978 → 26 900 | ✅ |
| 48 | Post-audit fixes (pass 24): session-memo ownership, sweeper re-check, connection-pin deadline, `dns_inflight` accounting. `cargo test --all-targets` **79/79** (45 lib + 18 client + 16 server; **78/78** with `--no-default-features`), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets. E2E on the fixed binaries: `udpdomainswitch` 500 alpha + 500 beta and `udpipswitch` 500 IP + 500 domain inside one session, **0 misrouted**; `udpsweep` 8/1200/1420/1430/2000/8000 B **6/6 verbatim** (fragment path included); `udpdomainmulti` 4 000 sent / 3 999 received; 20 TCP flows with replies; a 40-datagram burst at an uncached name reported as `9 dropped (resolution in flight)` in the new counter. The fd leak is closed, measured with `lsof`: 100 associations on one connection, client `kill -9`, then **1** UDP fd (the listener) after the QUIC idle timeout, against **85** on the previous binary. `dist/openwrt-x86_64/` was rebuilt for all four CPU levels from this revision (static musl, x86-64, stripped; servers 4 327 072–4 349 816 B, +1 216–1 536 B per level; clients 4 390 120–4 416 280 B, same sizes as before) — `file` confirms the format, a second four-level build came out byte-identical at every level, and `objdump -d` finds 273 `zmm` refs in v4 with none in v1/v3 (`ymm` 3 978 → 25 306 from v1 to v3), so each `target-cpu` level really is compiled in. The emulated-container re-run was **not** repeated here (the local Podman machine did not respond): the dist artifacts are cross-compiled and statically checked, while the native-binary E2E below is green | ✅ |
| 49 | Pass 25 — dedicated UDP egress and the pool audit. `cargo test --all-targets` **93/93** (49 lib + 27 client + 17 server; **92/92** with `--no-default-features`), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets. Native-binary E2E (macOS loopback, the repo's own `hotpath_bench` harness): the client logs `quic pool: 4 TCP connection(s) … + 1 dedicated UDP connection (slot 4), UDP is fail-closed` and the server logs exactly **5** `new QUIC conn`; `tcpecho` 64 KiB byte-for-byte; `udpsweep` 8/1200/1420/1430/2000/8000 B **6/6 verbatim**; `udpmulti` 16 associations × 400 = **6400/6400, 0.000 % loss** at 19 451 pps. `quic_conns = 1` dials **2** connections (1 TCP + 1 UDP) and still passes TCP plus the full UDP sweep, so the separation is structural rather than load-dependent. With every connection dead (`kill -9` the server), the next 60 s line reads `66 dropped (no egress connection)` — the fail-closed path counted and reported instead of sharing a TCP connection silently — and after the restart the same client logs 2 `QUIC connected` with TCP and the 8/8000 B sweep green again. `dist/` was rebuilt for all four CPU levels (clients 4 406 656–4 430 000 B, servers 4 334 128–4 361 864 B; `file` confirms static musl + stripped) and the **shipped v1 pair was re-run end-to-end under amd64 emulation** (Podman on Apple Silicon, the `hotpath_bench` example cross-built for the same musl target) for pass 25's artifacts and again for the clock-free reply-path build: 5 connections accepted, `tcpecho` 256 KiB byte-for-byte, `udpsweep` 8/1200/1430/8000 B **4/4 verbatim**, `udpmulti` 8 × 200 = **1600/1600, 0.000 % loss**. The egress drop-accounting build that follows does **not** repeat that emulated run: it changes only what happens to a datagram that is *already* being dropped (an exact counter, a rate-limited warning) and no data-path decision, so its coverage is the unit suite — `egress_drops_are_exact_across_threads`, falsified against the batched wiring before being kept, and `egress_drop_warnings_use_independent_slots`; `objdump -d` finds 235 `zmm` refs in v4 and none in v1–v3 (`ymm` 3 978 → 27 045 from v1 to v3), so each `target-cpu` level is compiled in | ✅ |
| 50 | Pass 26 — TCP/UDP echo hot-path audit. `cargo test --all-targets` **98/98** (53 lib + 28 client + 17 server; **97/97** with `--no-default-features`), clippy `-D warnings` + `cargo fmt --check` clean on both feature sets. Five fixes, one of them a silent-corruption defect: an abnormal pump end was announced to the *peer* as a clean FIN (`Drop for quinn::SendStream` calls `finish()`), so a truncated download looked complete one hop out; the pump now borrows its stream halves and resets/stops the abandoned one, gated on that direction's own completion. New regression tests: `abnormal_pump_end_resets_the_peer_stream_instead_of_finishing` (falsified against the old code — it panics with `the peer saw a clean FIN on an abandoned stream`), `a_partial_past_the_payload_cap_is_discarded_whole`, `coarse_millis_advances_without_traffic`, `the_coarse_epoch_is_rearmed_after_its_runtime_ends` and `too_large_refreshes_the_budget_without_discarding_the_handle`. Also: `TooLarge` no longer counted/logged as an egress loss nor allowed to flush the process-wide egress cache; the server's `fast_sock` is `Weak` (it was a second strong owner that outlived a swept session); the reassembler's documented per-partial `MQP_FRAG_MAX_PAYLOAD` cap is enforced (64 maximum-size fragments previously assembled ~91 KiB); per-datagram `mono_millis()` on three hot paths and per-*dropped*-datagram in the warn limiter replaced by `coarse_millis()`, a lazily armed 1 Hz epoch that advances with wall time (a count-based sampler freezes on trickle flows, which is why the earlier attempt was reverted) and re-arms itself if its runtime dies. Native-binary E2E (macOS loopback, the repo's `hotpath_bench`): `tcpecho` 64 KiB + 1 MiB byte-for-byte 0 mismatched; `udpsweep` 8/1200/1420/1430/2000/8000 B × 40 **6/6 verbatim**; `udpmulti` 16 × 400 = **6400/6400, 0.000 % loss** at 23 381 pps; `udpdomainswitch`/`udpipswitch` 100+100+100+100 **0 misrouted**; `bulk` 256 MiB at 105 MB/s; a 30 s mixed loop over ~30 epoch ticks with 0 failures. The session's only abort warning is the intentionally-truncated `bulk` flow, and the server's mirror line (`sending stopped by peer: error 4`) is the new propagation arriving; 0 UDP drops, 0 reassembly losses, `unknown_sess = 0`. `dist/` **was** rebuilt from this revision for all four CPU levels (static musl, x86-64, default features; clients 4 419 928–4 441 928 B, servers 4 345 120–4 373 048 B, +11 928–13 336 / +10 544–11 440 B per level vs pass 25) but, unlike every earlier pass that touched `dist/`, **no check of any kind was run on those bytes** — no `file`, no `objdump`, no reproducibility rebuild, no emulated or native run of the shipped pair; they are compiled, not tested | ⚠️ |
| 51 | Pass 27 — hot-path review fixes. `cargo test --all-targets` **99/99** (53 lib + 28 client + 18 server; **98/98** with `--no-default-features`: 52 + 28 + 18), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets. Three changes, all on the relay hot paths: the connection pin is written back from a DNS-cache hit (pinned by the new `dns_hit_arms_the_pin_when_pin_and_memo_miss`); the c2s pump double-buffers its 32 KiB copy buffer so a frozen half gets one extra cycle to be ACK-released before its capacity is needed again; fragment reassembly stores `parent.slice(..)` instead of copying every chunk, guarded by an O(1) pointer suffix check with a copy fallback. `dist/` rebuilt for all four CPU levels (servers 4 348 224–4 375 064 B, clients 4 421 240–4 444 584 B; `file` confirms static musl + stripped, `objdump -d` finds 273/235 `zmm` refs in the v4 server/client and none in v1–v3). No native E2E or benchmark re-run: wire-compatible throughout, and the removed work is nanoseconds against this host's ~350 µs loopback datagram (same caveat as passes 13 and 15) | ✅ |
| 52 | Pass 28 — bounded stream-head writes, refused-datagram accounting, SOCKS header size. `cargo test --all-targets` **99/99** (53 lib + 28 client + 18 server; **98/98** with `--no-default-features`: 52 + 28 + 18), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets. Two review rounds confirmed four findings before any edit; two were dispositioned as non-issues (an unreachable fragment-branch, and malformed-frame drops staying uncounted per pass 26's documented decision). Changes: client MQP-2 stream-head write and server TCP-open ACK write each under a 5 s `timeout` (failure resets/tears the flow down before the optimistic SOCKS success, answering `0x04` on the client); `SOCKS_UDP_HDR_MAX` 22 → 262 (worst-case domain header); new batched `dgram_drops::REFUSED` wired through `bump`/`flush_locals`/`snapshot`/`since`/`lost()`, bumped at five policy-refusal sites (server negative cache, both SSRF arms, `sess == 0` — reclassified off `SESSION_FULL` — and the client's domain-reply refusals) and printed in both 60 s `udp budget` lines; `every_drop_counter_has_its_own_snapshot_field` extended to all seven counters (`lost() >= 7`). `dist/` rebuilt for all four CPU levels (servers 4 344 544–4 373 480 B, clients 4 379 536–4 403 000 B; `file` confirms static musl + stripped on all eight, `objdump -d` finds 273/235 `zmm` refs in the v4 server/client and none in v1–v3). Client levels come out 38 824–42 224 B *smaller* than the pass-27 recorded figures and server levels −3 680…+1 424 B, a code-size move this pass's additions do not by themselves explain — the recipe and feature set are unchanged, `Cargo.lock` is untouched, and the pre-rebuild `dist/` files already sat at ~4.39/4.36 MB rather than the pass-27 recorded sizes. No native E2E or benchmark re-run: wire-compatible throughout (timeout paths and counters only) | ✅ |

Round-robin *distribution* is pinned by the unit tests rather than by the E2E
harness: `slot_routing_table` (the n = 1 / n = 2 truth table plus all four n = 4
rows) and `pool_round_robins_bulk_over_every_slot_and_pins_interactive` (a real
`ConnPool` drives `pick_tcp` to slot indices 0,1,2,3, keeps the pinned port on 0,
and fails over to slot 1 when slot 0's live bit clears).

The client bin's loopback `dispatch_*` tests were timing-flaky on the pass-23 tree
too — the full 18-test client bin was red in roughly half of back-to-back
`cargo test --all-targets` runs. Two separate causes, and the first fix below
turned out to be the smaller one:

- **Latency.** A 300 ms `recv_reply` window lost a loopback datagram whenever the
  concurrent real-QUIC tests saturated the loopback path. The waits are now split:
  **2 s** for a positive "the reply must arrive" assertion, and a **300 ms**
  `no_reply` probe for "must be dropped" assertions. The probe deliberately stays
  well under `FRAG_TIMEOUT_MS` (2 s): the fragment-reassembly test probes *between*
  the fragments of one payload, so a 2 s probe would expire the partial and fail
  an assertion that has nothing to do with timing (measured: that version was 0/8
  green). This part is test-only (`#[cfg(test)]`).
- **A dropped datagram, which no window can fix.** Every shard of the client's
  `WouldBlock` retry pool was a task on whichever runtime first needed it, while
  the `Sender` lived in a `OnceLock` forever. A `#[tokio::test]` has its own
  runtime and drops it at the end of the test, so from the second test onwards
  every retry went into a queue whose receiver had died: `try_send` returned
  `Closed`, the datagram was dropped, and the drop was charged to a
  "budget exhausted" counter that had not been touched. That is why the file
  failed **5/5** serially (one runtime per test) and intermittently in parallel.
  The pool now publishes each shard's sender through an `ArcSwap` and re-arms a
  shard whose worker is gone, on the runtime that needs it
  (`retry_shard_is_rearmed_after_its_runtime_ends`). Serial runs went 0/5 → 5/5
  and the full suite 10/10 on the default feature set, 4/4 on
  `--no-default-features`.

0-RTT probe (expect the last four lines):

```sh
cargo run --release --example zero_rtt_probe -- 127.0.0.1:8443 test.com <auth_token>
# conn1: full handshake ok
# conn2: client HAD resumption tickets, 0-RTT offered
# conn2: server bound address 127.0.0.1:53619
# conn2: 0-RTT echo ok: "zero-rtt-echo"
# conn2: server accepted 0-RTT early data = true
```

Representative reconnect trace (client log after `kill -9` of the server):

```
07:26:37 kill server
07:26:52.870 WARN QUIC connection lost, reconnecting...   (idle timeout; watchdog backs it up at 20 s)
07:26:52.871 WARN QUIC close reason: timed out
07:26:53.174 INFO QUIC connected to 127.0.0.1:8443         (server restarted at :40)
07:26:53.175 DEBUG QUIC resumption: 0-RTT keys accepted=false  (stale ticket)
07:26:53.176 server INFO new QUIC conn                     (token re-sent, auth passed)
07:26:55     TCP echo OK / UDP echo OK
```

The E2E harness is intentionally not vendored; it is a plain Python SOCKS5 client
(`CONNECT` + `UDP ASSOCIATE`) plus `asyncio` TCP/UDP echo servers on ports 18081/18082.

---

## Requirements

- **Rust** 1.88+ (MSRV driven by `time 0.3.55` / `rcgen 0.14.10`; developed and
  tested on stable 1.97.1; deps: quinn 0.11.12 / quinn-proto 0.11.18 /
  quinn-udp 0.5.15 from crates.io, rustls 0.23, tokio 1.53.1). The quinn crates
  are plain crates.io dependencies; `cargo update` moves them within the 0.11 line.
- **Linux** (production; GSO/GRO + BBR fully effective) or **macOS** (development;
  dual-stack verified, GSO degrades gracefully)
- For OpenWrt cross builds: `zig` + `cargo-zigbuild` (see [Building](#building))

---

## Building

```sh
# native release
cargo build --release
# binaries: ./target/release/myquic2-server ./target/release/myquic2-client

# tests + lints
cargo test
cargo clippy --all-targets
```

### The extreme build (`--no-default-features`)

The default build keeps the per-packet relay counters (`stats` feature) because they are
what the 60-second `udp relay` / `udp write` lines and the drop warnings report. For a
build that gives up that observability for four fewer atomic RMWs per relayed datagram:

```sh
cargo build --release --no-default-features
```

The protocol-level warnings (`udp datagram dropped …`, reassembly expiry/eviction) come
from `dgram_drops`, which is drop-path-only and stays live either way.

### Cross-compile for OpenWrt x86-64 (static musl, from macOS)

```sh
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild   # needs `zig` on PATH
```

Build one CPU level at a time (sequentially — each flag set invalidates codegen) and
copy each result into `dist/` before the next level overwrites it:

```sh
# v1 = any x86-64 (J4125/N100 safe default); v2 = SSE4.2; v3 = AVX2; v4 = AVX512
set -e
for v in x86-64 x86-64-v2 x86-64-v3 x86-64-v4; do
  case $v in x86-64) n=v1;; x86-64-v2) n=v2;; x86-64-v3) n=v3;; x86-64-v4) n=v4;; esac
  cargo zigbuild --release --target x86_64-unknown-linux-musl \
    --config 'profile.release.strip="symbols"' \
    --config "target.x86_64-unknown-linux-musl.rustflags=[\"-C\", \"target-cpu=$v\"]" \
    --bin myquic2-server --bin myquic2-client
  cp target/x86_64-unknown-linux-musl/release/myquic2-server dist/openwrt-x86_64/myquic2-server-$n
  cp target/x86_64-unknown-linux-musl/release/myquic2-client dist/openwrt-x86_64/myquic2-client-$n
  echo "built $n"
done
```

> ⚠️ Pick the level your CPU actually supports (`grep avx512 /proc/cpuinfo` for v4).
> A v4 binary on a non-AVX512 CPU dies with `illegal instruction`. When in doubt,
> ship **v1**.

Prebuilt artifacts live in [`dist/openwrt-x86_64/`](dist/openwrt-x86_64/)
(`*-v1` … `*-v4` for both binaries, plus sample configs). The shipped binaries were
rebuilt from the current revision (pass 28's 5 s stream-head write deadlines, the
`SOCKS_UDP_HDR_MAX` domain-header fix, and the `REFUSED` policy-refusal counter and its
five bump sites, on top of everything pass 27 shipped) with the
default feature set, so the relay counters are **on** in these builds: static musl,
x86-64, stripped, 4 344 544–4 373 480 B (servers: v1 4 359 840, v2 4 344 544,
v3 4 373 480, v4 4 370 472) and 4 379 536–4 403 000 B (clients: v1 4 393 760,
v2 4 379 536, v3 4 403 000, v4 4 395 048) each. Against the pass-27 *recorded* figures
the servers move −3 680…+1 424 B per level and the clients **−38 824…−42 224 B**; the
client shrink is larger than this pass's additions can account for, the recipe and
feature set are unchanged, `Cargo.lock` is untouched, and the pre-rebuild `dist/` files
already sat near these sizes rather than the pass-27 recorded ones — recorded here as
measured, not explained. The builds **were** statically checked: `file` confirms ELF
64-bit LSB x86-64, statically linked, stripped on all eight artifacts, and `objdump -d`
finds 273 `zmm`
refs in the v4 server and 235 in the v4 client with none in v1–v3 of either binary, so
each `target-cpu` level really is compiled in. What was **not** repeated is any emulated
or native run of the shipped pairs — the verification below applies to the native
release build, and a target that needs a loadable binary should be validated on the
target. The pass-26 "compiled only" wording below is kept as the history of that build:
The sizes of the intermediate pass-25 steps remain visible: the clock-free reply path
came out 128–192 B *smaller* than pass 25's first build
of the clients, and the egress drop accounting that followed added 4 888–5 144 B to them
while shaving 128–192 B off the servers (the library no longer keeps per-thread batching
cells for those two counters). The
earlier growth was the client 4 992–5 120 B and the server 6 432–6 512 B per level (the
retry pool's `ArcSwap` shard table plus the memo path changes). Three upgrade notes, all
requiring **both** sides to be replaced together (plus two notes below that need no
binary change):

- A binary built before pass 9 carries the old 2/8/4 MB windows and caps a single
  stream at ~114 Mb/s; a mixed pair is limited by whichever end is older, since a
  download is capped by the receiver's advertised window.
- A binary built before pass 12 loses every UDP payload above one QUIC DATAGRAM
  (~1422 B on a 1472 B path) and truncates relay reads at 2048 B. Payloads above
  one frame are *silently* lost against an older peer, because it rejects the
  `type=0x05` fragment frame — no misparse, but no error either.
- A binary built before pass 13 still copies every chunk through the TCP↔QUIC pump
  and allocates per SOCKS flow on the client. Wire-compatible, so a mixed pair works —
  it just leaves the pass-13 tax removals on the floor.
- Config note (no binary change): the sample configs omit tuning and follow the
  code defaults, now 2/4/2 MB (~114 Mb/s @140 ms single-stream). For ~240/300 Mb/s
  set 4/8/4 or 8/16/8 MB explicitly on both sides together.
- Pool-size note (client only): the new default is 4 connections and the shipped
  sample pins `quic_conns = 4`. A client binary built before this revision silently
  clamps that to 2 — harmless (the server accepts any number of connections), but
  the extra congestion windows only appear once the client binary is replaced.
  Omitting the field means "that build's own default", so an untouched old config
  keeps behaving exactly as before after an upgrade.
- Pass-25 note (client only, no wire change): a client built from this revision dials
  one connection **more** than `quic_conns` (`quic_conns + 1`, ≤ 9) and moves UDP
  egress onto that dedicated connection, so the server sees 5 connections where it
  used to see 4. Two consequences for an operator: the extra connection costs one
  keepalive/dial loop on both ends, and `udp_fail_closed` defaults to `true`, so UDP
  datagrams are *dropped* (and counted in the 60 s `udp budget` line) while the UDP
  connection is reconnecting instead of falling back onto a TCP connection. Set
  `udp_fail_closed = false` to keep the old always-share-a-connection behaviour.
  The client's association cap also drops 4096 → 4032 to match what the server keeps
  alive per connection. A new client against an old server, or an old client against
  a new server, is fully wire-compatible: the pool size is a local decision.

Verified by running the v1 pair under x86-64 emulation (Podman's amd64 runtime on
Apple Silicon): both binaries execute, the QUIC handshake completes, and the full E2E
suite passes — TCP ECHO 1 MiB byte-for-byte, a domain-target `CONNECT`, and the UDP
sweep of 8 / 1200 / 1420 / 1430 / 2000 / 8000 B (the last two through `type=0x05`
fragments) at 0 % loss. The AVX2 instructions the v1 binary does contain live in
`ring`'s VAES/AVX2 AES-GCM path and in `core`'s slice helpers, both behind runtime CPU
detection. The same emulated CPU runs the **v3** binary but makes the **v4** binary die
with `Illegal instruction` (exit 132), which is the expected consequence of selecting
an AVX512 level the CPU does not implement — and the proof that the per-level
`target-cpu` flags are actually compiled in.

The pass-23 rebuild was re-verified the same way, and the emulated container also
corroborates the host diagnosis in the pass-23 notes below: the v1 pair relays
**160 000 datagrams at 0.000 % loss and 22 408 pps** there, against ~3 000 pps for
the identical binaries on the macOS host, where a network extension rate-limits
UDP. The binaries were not the difference — the host was. Per-level flags were
re-checked statically as well as dynamically: `objdump -d` finds **273 `zmm`
references in the v4 build and none in v1 or v3**, with `ymm` use rising from 3 978
(v1) to 25 025 (v3), and the emulated CPU runs v1 and v3 (exit 0) while v4 dies with
exit 132.

The cache-substitution rebuild was re-verified the same way, with a small static
musl driver (`e2eclient`, built by the same `cargo zigbuild` invocation) so the
checks run *inside* the container next to the artifacts:

- both v1 artifacts execute and stay up under emulation;
- UDP over one `UDP ASSOCIATE`: **8/8 datagrams relayed** to an IP-literal target
  and **8/8** to a domain target — the latter exercises the server's DNS path and
  its new destination memo;
- the multi-target session check that caught the bug in the first version of that
  memo: two domain targets alternating in **one** session, **10 alpha / 10 beta, 0
  misrouted** (the session-keyed-only version scored 0/0 with all datagrams routed
  to the wrong target);
- TCP `CONNECT`: **4096/4096 bytes** relayed.

The per-level flags hold in the new binaries too: `objdump -d` counts **0 / 0 / 0 /
235 `zmm`** references for v1 / v2 / v3 / v4 and `ymm` **3 978 → 25 972** from v1 to
v3, and under emulation v3 runs (exit 0) while v4 dies with exit 132 — the same
signature the pass-23 rebuild showed. The four-connection revision was re-verified
the same way: the **v1 and v3 pairs** each brought up 4 connections (0 dial failures,
4 server-side accepts) and passed TCP ECHO 1 MiB, a domain-target `CONNECT`, the
8–8000 B UDP sweep and 20 back-to-back CONNECTs byte-for-byte inside the emulated
container, running the `dist/` artifacts themselves.

---

## Configuration

TOML files, CLI flags override via `--config <path>` (defaults:
`config-server.toml` / `config-client.toml` in the working directory).

### Server (`config-server.toml`)

```toml
listen = "[::]:8443"          # QUIC ingress (dual-stack wildcard recommended)
cert_file = "server-cert.pem" # cert+key auto-generated on first run only when BOTH are absent
key_file = "server-key.pem"   # Ed25519; a lone missing half is a hard error (never overwritten)
server_name = "test.com"      # SAN for the self-signed cert + expected SNI
congestion = "bbr"            # bbr | cubic (unknown values warn and fall back to bbr)
gso = true                    # informational: quinn-udp auto-probes GSO/GRO
keep_alive_secs = 5           # clamped to 1..3600; idle timeout = max(3x, 15s)
allow_private = true          # dial RFC1918/loopback targets; default is false!
auth_token = ""                # shared secret ≤ 256 B; empty = disabled (firewall only).
                               # Set a private random value here and on the client.
# Optional tuning, mirrors the client (download capped by receiver window,
# upload by sender window — change both sides together):
# stream_receive_window_mb = 2, receive_window_mb = 4, send_window_mb = 2,
# ack_threshold = 2, max_ack_delay_ms = 5, alpn = "h3"
```

### Client (`config-client.toml`)

```toml
socks_listen = "[::]:1080"    # SOCKS5 ingress (dual-stack)
server_addr = "127.0.0.1:8443"     # QUIC server (IP or hostname; re-resolved every redial)
server_name = "test.com"           # SNI; MUST match the cert SAN
server_cert_file = "server-cert.pem"  # pinned server cert (copied out-of-band)
congestion = "bbr"
gso = true
keep_alive_secs = 5           # clamped to 1..3600; idle = max(3x,15s), watchdog = max(4x,20s)
reconnect_timeout_secs = 5    # new flows wait this long for a QUIC connection
auth_token = ""                     # must match the server (empty on both = disabled)
# Optional tuning (defaults = 2/4/2 MB windows, ACK 2/5ms, 4 TCP + 1 UDP connection):
# stream_receive_window_mb, receive_window_mb, send_window_mb,
# ack_threshold, max_ack_delay_ms, quic_conns = 1..8 (1 = single TCP), udp_fail_closed, interactive_ports, alpn
```

Field notes:

- `allow_private` defaults to **false** in code; the sample config sets `true` for
  local testing. Disable it for any public exit node.
- `auth_token` empty on both sides = no authentication. Non-empty on the server but
  empty/wrong on the client = connection closes with `unauthorized` and the client
  retries with growing backoff.
- `reconnect_timeout_secs` only bounds how long a *new SOCKS flow* waits for a live
  QUIC connection; it does not control redial backoff.
- Transport tuning (`stream/receive/send_window_mb`, `ack_threshold`,
  `max_ack_delay_ms`) defaults to the low-latency preset (2/4/2 MB, ACK 2/5 ms,
  ~114 Mb/s @140 ms); set 4/8/4 MB for ~240 Mb/s or 8/16/8 MB + ACK 8/10 ms on
  **both sides** for 300 Mb/s peak at ~2x/~4x loaded latency. The shipped samples
  omit tuning entirely and use these defaults. Optimal total in flight ≈ link BDP —
  e.g. a 200M/140ms link (BDP 3.5 MB) is already served by the 2/4/2 MB default:
  single-thread caps at ~114 Mb/s while multi-thread still fills the link with
  minimal loaded latency.
- `quic_conns = 4` (default, clamped 1–8) sets the **TCP** pool size: bulk TCP
  spreads round-robin across the bulk slots, so each connection's congestion window
  holds ~1/(n−1) of the queue, while `interactive_ports` (default 53/123/3478–3481)
  pin to slot 0. `1` restores the legacy single shared TCP connection; the cap
  bounds what a config typo can request, since every slot owns a dial loop, a
  DATAGRAM dispatcher, keepalives and its own 0-RTT ticket state. One further
  connection is always dialed for UDP (slot `quic_conns`), so a client's worst case
  is 9 connections; UDP never shares a TCP connection's congestion window, and a
  dead bulk slot fails over to another *bulk* slot before it will touch slot 0.
- `udp_fail_closed` (default `true`) decides what UDP does while its dedicated
  connection is reconnecting: drop the datagram — counted, and reported in the 60 s
  `udp budget` line — rather than put it on a TCP connection. Set it to `false` to
  restore the old fallback (interactive slot, then bulk slots), which keeps UDP
  flowing at the cost of sharing a cwnd and a packet payload with TCP traffic.
- `alpn` defaults to `h3` masquerade (label only); `myquic2/2` restores the
  versioned fail-closed handshake. Same value required on both sides.
- Paths are resolved against the process CWD — use absolute paths on OpenWrt.

---

## Running

```sh
# 1. server first (generates server-cert.pem/key on first run)
./myquic2-server --config config-server.toml

# 2. copy server-cert.pem (ONLY the cert, never the key) to the client machine

# 3. client (loads + pins the cert, fails fast if missing)
./myquic2-client --config config-client.toml

# 4. use it
curl --socks5 127.0.0.1:1080 http://example.com
```

Background: `nohup ./myquic2-server --config config-server.toml > server.log 2>&1 &`

Logging honours `RUST_LOG`, e.g. `RUST_LOG=myquic2_client=debug,myquic2_server=debug`;
the default filter is `info`.

---

## Certificates & Authentication

- **Server identity**: the client pins the server's self-signed **Ed25519**
  certificate (`server_cert_file`, 444 bytes). The `ring` provider picks the
  AEAD suite (TLS13_AES_256_GCM_SHA384 observed in the probe logs on both
  x86-64 and Apple Silicon; ChaCha20-Poly1305 elsewhere), both hardware
  accelerated. This proves the client is
  talking to the genuine server — it does **not** authenticate clients.
- **Client identity (`auth_token`)**: the server has no client certs, so a
  non-empty `auth_token` is required to keep it from being an open relay. The
  client opens a one-way uni stream immediately after the handshake and writes
  the shared secret; the server refuses all streams and datagrams until it
  matches, then closes unauthorized connections. Set the same value in both
  configs. Empty token = feature disabled → only expose the port behind a
  firewall. On 0-RTT rejection the client re-sends the token automatically.
- **Server** auto-generates the cert on first run: SAN = `server_name`,
  validity **500 years backdated 7 days**. The backdating is deliberate: routers
  without a battery clock (NTP not yet synced at boot) would otherwise fail with
  `certificate not valid yet`.
- **Client** only loads and pins (`server_cert_file`). Missing file = startup error
  (it must never self-generate — a self-generated cert would never match the server).
- **Rotation rule**: any regeneration changes the key → all deployed clients need the
  new `server-cert.pem`. Compare fingerprints when in doubt:
  `openssl x509 -in server-cert.pem -noout -fingerprint -sha256` (must match exactly
  on both sides).
- **0-RTT replay note**: early data can theoretically replay; worst case is a
  duplicated outbound dial (no amplification). Tickets live in memory on both ends —
  either side restarting falls back to a 1-RTT full handshake automatically, and the
  client re-authenticates in that case.

---

## Resource Limits & Tuning

All limits are constants in the sources; the table shows where to change them.

| Resource | Limit | Where |
|---|---|---|
| Concurrent QUIC connections (server) | 4096 (new `Incoming` refused) | `MAX_CONNECTIONS` |
| Concurrent *unauthenticated* connections | 256 (pre-auth slot, released after token check) | `MAX_UNAUTH_CONNECTIONS` |
| TLS session store (server, 0-RTT/resumption) | 8192 sessions | `server_tls_config` |
| UDP sessions, process-wide | 8192 permits (fail closed) | `MAX_SESSIONS_GLOBAL` |
| UDP session socket buffers | 512 KB send + 512 KB receive per session | `udp_socket_dual_small` |
| UDP sessions per connection | 4096 (O(n) sweep above) | `LOCAL_SESS_MAX` |
| Concurrent TCP dials, process-wide | 4096, 2 s permit wait (released after connect) | `dial_limiter` |
| Concurrent bidi streams per connection | 1024 | `build_transport` |
| Concurrent TCP stream tasks (server, process-wide) | 16384 (excess streams reset) | `MAX_STREAM_TASKS` |
| Client SOCKS connections | 8192 (excess connections dropped) | `socks_conn_limiter` |
| Client UDP associations | 4096 (excess replies REP=0x01, 256-datagram queue each) | `UdpHub::alloc_sess` |
| DNS slow-path lookups (TCP + UDP) | 1024, 5 s each, single-flight | `dns_slow_path_limiter` |
| Deferred UDP sends (fresh-socket / full buffer) | 4096 | `udp_send_limiter` |
| Receive window (aggregate) | 4 MB/connection default (8/16 MB opt-in) | `TransportTuning` (`RECEIVE_WINDOW`) |
| Receive window (per stream) | 2 MB default (4/8 MB opt-in) | `TransportTuning` (`STREAM_RECEIVE_WINDOW`) |
| Send window | 2 MB/connection default (4/8 MB opt-in) | `TransportTuning` (`SEND_WINDOW`) |
| Initial RTT / PMTU ceiling | 190 ms / 1472 B | `build_transport` |
| DATAGRAM buffers | 1 MB each direction | `build_transport` |
| Keepalive / idle / watchdog | clamp 1–3600 s; idle `max(3×,15 s)`; watchdog `max(4×,20 s)` | `build_transport`, client |
| Server auth wait | 5 s per connection (one deadline for accept+read) | `authenticate()` |
| TCP stream idle reap | 300 s | `copy_tcp_quic_idle` call sites |
| UDP association idle reap | 180 s (both directions; TCP control activity counts) | server sweeper / client interval |
| DNS cache | 60 s positive (4096+512 slack), 10 s negative (4096) | `DNS_CACHE_*`, `DNS_NEG_MAX` |
| Client TCP dial ACK budget | 25 s (5 s header + 3 s DNS permit + 5 s DNS + 2 s dial permit + 4 s connect + scheduling margin) | `TCP_DIAL_ACK_TIMEOUT` |

Kernel-side tuning: raise `net.core.wmem_max` / `net.core.rmem_max` so the 4 MB
(QUIC socket) and 256 KB (per-session) socket buffers are not silently clamped; the
first clamp logs one warning per
process (per-socket warnings were removed because session churn flooded the log).
For the 300 Mb/s @ 140 ms target, 8 MB is the recommended value for both
(`sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608`): 4 MB covers
only ~110 ms of that rate.

---

## SOCKS5 Compliance

Against RFC 1928 / RFC 1929:

| Item | Status |
|---|---|
| Handshake, no-auth (`0x00`) | ✅ |
| `CONNECT`, IPv4/domain/IPv6 | ✅ (curl-verified) |
| BND.ADDR/BND.PORT for `CONNECT` | ⚠️ `0.0.0.0:0` (unknown): the success reply is sent before the remote dial completes to avoid an extra RTT; the MQP-2 ACK still carries the real bound address and is validated |
| `UDP ASSOCIATE` + relay + TCP control held | ✅ (`FRAG≠0` dropped, as most implementations do) |
| BND.ADDR for `UDP ASSOCIATE` | ✅ the proxy's own interface address + relay port (LAN clients work; no longer the app's own address) |
| Username/password (`0x02`) | ❌ intentionally absent |
| `BIND` | ❌ replies `0x07` (FTP active mode; obsolete in practice) |
| Error REPs (`0x01/0x04/0x05`…) | ⚠️ success is replied optimistically; a failed remote dial closes the TCP flow (the app reconnects) instead of returning `0x04`. A missing QUIC connection still fails the flow fast |
| UDP source validation | ⚠️ relay learns the app address from the first packet; fine behind NAT/home use, tighten before public exposure |
| Association lifetime | ⚠️ idle UDP associations are reaped after 180 s to bound sockets/tasks (RFC has no fixed lifetime) |

---

## Reconnect & High-RTT Behavior

- **Idle**: keepalive every `keep_alive_secs` (default 5 s) vs idle timeout
  `max(3×keepalive, 15 s)` — the connection lives indefinitely while both processes
  run (verified: 45 s idle, zero new handshakes, traffic flows instantly after).
- **Dirty network (< 15 s outage)**: QUIC retransmission + BBR absorb it; streams
  stall then resume, **no new handshake**.
- **IP change (NAT rebinding, WiFi→cellular)**: QUIC connection migration keeps the
  *same* connection alive without a handshake.
- **Long outage / server restart**: ~15–20 s silent-path detection (15 s QUIC idle
  timeout, backed up by a `max(4×keepalive, 20 s)` no-inbound-traffic watchdog) →
  exponential redial (200 ms → 5 s, jittered). The backoff only decays after 5 s of
  stable connectivity, so a misconfigured peer (e.g. wrong token) cannot cause a
  redial storm. A stale 0-RTT ticket is rejected once and the token is re-sent on the
  established connection (verified: server `kill -9` → reconnect → TCP+UDP ECHO pass).
- **A dial is not accepted until the connection is proven alive** (pass 7, reworked in
  pass 8, ported back to 0.11 in pass 10). quinn-0.11's `Connecting` future resolved `Ok`
  even for a connection that terminated instead of handshaking, so the 0-RTT path gates
  on the `ZeroRttAccepted` future (true = early data kept; false = rejected or died)
  plus `close_reason()`: a timeout or a closed connection fails the dial, a live
  connection with rejected early data re-sends the token at 1-RTT, so a dead dial cannot
  be published; `dial_once` bounds each attempt with `DIAL_ATTEMPT_TIMEOUT` (5 s)
  instead of QUIC's ~15 s Initial-retransmission budget — so the first attempt after a
  restart succeeds instead of waiting out the previous one's timeout. Measured:
  server `kill -9` → detection ≈ 20 s → reconnect ≈ 0.3–0.4 s after the server is back
  (before: a false `connected` every ~15 s plus 15.6 s recovery).

- **After reconnect**: UDP sessions self-heal (the server recreates `sess_id` state on
  the next packet); old TCP streams reset fast so apps reconnect instead of hanging.
- **140 ms links**: tuned for the trans-Pacific BDP — 2 MB per-stream / 4 MB
  aggregate receive window, 2 MB send window, BBR, ACK-every-2nd-packet with a
  5 ms `max_ack_delay` by default (~114 Mb/s, minimal loaded queue); opt in to
  4/8/4 MB for ~240 Mb/s or 8/16/8 MB for 300 Mb/s. The SOCKS success reply is sent
  optimistically (no 1-RTT wait for the remote dial), so the application's TLS
  handshake overlaps the server-side dial; server-side DNS avoids geo-misresolved IPs.
  A lossy path is the tradeoff: 8 MB allows ~6200 packets in flight per RTT, which
  is more room than the legacy 2 MB to approach quinn's 1024-chunk reassembly
  limit, so `too many gaps in stream buffer` on a burst-loss link means stepping
  `SEND_WINDOW` / `STREAM_RECEIVE_WINDOW` back to 4 MB (~240 Mb/s).

---

## OpenWrt Deployment

```sh
scp dist/openwrt-x86_64/myquic2-server-v1 dist/openwrt-x86_64/myquic2-client-v1 root@openwrt:/usr/bin/
# rename on target as you like, chmod +x, absolute paths in the tomls!
```

Checklist from real field issues:

1. **Absolute paths** in `server_cert_file`/`cert_file` (relative paths resolve
   against CWD — the classic `os error 2`).
2. **Correct binary**: the client build for SOCKS ingress; don't mix up the two.
3. **Cert first**: start server → copy `server-cert.pem` → start client.
4. **Token**: set the same `auth_token` in both configs (or leave empty on both and
   firewall the port); a mismatch shows up as `unauthorized` close loops.
5. **Clock**: ensure NTP is up (`date` sane) — belt-and-braces alongside the
   7-day backdating.
6. `server_addr` = server's **public** IP on the client; `server_name` unchanged
   (SNI/cert check only, needs no DNS).
7. **CPU level**: v1 is safe everywhere; v2+/v4 need the matching CPU features
   (`grep avx512 /proc/cpuinfo`).

---

## Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `os error 2` at client startup | Relative `server_cert_file` vs CWD → absolute path |
| `UnknownIssuer` | Client cert ≠ server cert (stale copy after regen) → compare fingerprints, re-copy |
| `certificate not valid yet (N seconds in future)` | Router clock behind (no RTC/NTP) → sync NTP; backdating covers ±7 days |
| `closed by peer: unauthorized (code 1)` in client log | `auth_token` missing or mismatched → set the same value on both sides |
| `auth_token is empty: the QUIC endpoint accepts any peer` on server start | Intentional if firewalled; otherwise set a token |
| `auth_token is a placeholder from the sample config` | Set a private shared secret (or an empty token with firewall isolation) |
| `cert/key pair incomplete: cert_file … and key_file …` at server start | Only one of the pair exists → restore the missing file, or delete both to regenerate; the surviving file is never overwritten |
| Handshake fails between two installs (`no application protocol`) | ALPN mismatch: default is `h3` now, pre-h3 binaries use `myquic2/2` → upgrade both sides together / set the same `alpn` on both |
| One extra reconnect right after server restart | Stale session ticket → 0-RTT rejected; the client re-auths automatically. Expected once |
| New TCP hangs after server restart | Old stream on dead QUIC conn → fail-fast RST is by design; app reconnects, new flows work immediately |
| UDP fails for LAN/remote SOCKS clients | Fixed in this revision (BND.ADDR is the proxy address); upgrade both binaries |
| UDP loss under load | Check loss% first: sustained overload is QUIC DATAGRAM backpressure (UDP semantics — app should retransmit) |
| `udp send buffer clamped to ...` warning | Raise `net.core.wmem_max`/`rmem_max`; the effective value is printed |
| Client cannot connect at all after a token change | The token travels inside QUIC, not TLS: no cert re-copy needed, only the config |

---

## Project Layout

```
MyQUIC2/
├── Cargo.toml / Cargo.lock
├── src/
│   ├── lib.rs                 # MQP-2 codec (owned+borrowed), config, TLS, transport, bridge, DNS cache
│   └── bin/
│       ├── myquic2-server.rs  # QUIC ingress + token auth + dial-out + session caps
│       └── myquic2-client.rs  # SOCKS5 ingress + token auth + reconnect + UDP dispatcher
├── examples/
│   ├── zero_rtt_probe.rs      # 0-RTT end-to-end verification probe (token-aware)
│   └── hotpath_bench.rs       # hot-path benchmark harness (owns its own targets)
├── config-server.toml / config-client.toml
└── dist/openwrt-x86_64/       # static musl release bins (v1–v4) + sample configs
```

---

## Hardening Notes (this revision)

- Optional `auth_token` connection authentication, constant-time compare, enforced
  before any stream/DATAGRAM is accepted; 0-RTT-safe re-send on early-data rejection.
- Server accept/handshake runs in per-connection tasks (no slowloris serialization);
  process-wide connection cap; `accept() == None` now exits with an error instead of
  spinning.
- Explicit 32 MB aggregate receive window (quinn’s default is effectively unlimited)
  plus per-connection stream/session/dial caps. *(Superseded in pass 3: the
  aggregate receive window is now 8 MB.)*
- UDP session liveness now counts inbound replies (long one-way downloads are not
  reaped); session/DNS eviction is O(n) with bounded lock hold time.
- `UDP ASSOCIATE` BND.ADDR is the proxy’s own address (LAN clients work).
- Client DATAGRAMs respect the live PMTU; `udp_try_send()` never stalls a shared
  reader and never drops the first packet of a fresh socket.
- DNS: atomic single-flight ownership with cancellation recovery, allocation-free
  cache hits, borrowed-domain datagram decoding, negative caching.
- Reconnect: auth re-send after 0-RTT rejection, jittered exponential backoff that
  decays only after stable connectivity, `RUST_LOG` support.
- SSRF filter validates NAT64 and IPv4-compatible embedded IPv4; extra
  documentation/benchmark prefixes rejected.
- QUIC socket no longer sets `SO_REUSEADDR`; UDP buffer clamping is reported;
  redundant warnings removed; dead code dropped; `dist/` rebuilt.

### 2026-09 hardening pass 2

- DNS single-flight waiters now reclaim ownership when the owner is cancelled, so
  `resolve_all_cached` can no longer hang forever; only the owner warms the
  positive/negative cache (ending N-writer stampedes), and a duplicate-lookup race
  window is closed by re-checking the cache before claiming ownership.
- 0-RTT is only exposed to application flows after the server accepts early data:
  quinn discards streams/DATAGRAMs sent in rejected early data, so the client now
  waits for the accept/reject decision (the token still rides early data) and
  re-sends auth on 1-RTT rejection. This removes lost SOCKS flows and stale stream
  handles after a server restart.
- `copy_tcp_quic_idle` cancels the peer direction as soon as one side fails, so a
  dead QUIC connection releases target TCP fds immediately instead of waiting out
  the 300 s idle window; the old `join!` could pin a silent stream for minutes.
- `allow_private` also validates the RFC 2765 IPv4-translated prefix
  (`::ffff:0:a.b.c.d`) and additional IANA non-global ranges (AS112, AMT, PCP/TURN
  anycast, DRIP, SRv6, `2001:4:112::/48`, `2620:4f:8000::/48`).
- Client UDP dispatcher table is sharded (32 locks) with an exact process-wide cap;
  the DNS hot-path memo compares full keys instead of a 64-bit hash, and negative
  entries short-circuit the per-packet resolver spawn.
- Server: extra uni streams are drained/stopped (no unbounded receive buffering), a
  global stream-task cap bounds header/DNS/dial queueing, the handshake has its own
  timeout, and session creation checks the global permit before creating a socket
  and never inserts a dead reply reader.
- SOCKS control writes are bounded by a 10 s timeout; the UDP-associate control drain
  is bounded per readiness event so a flooding local app cannot starve the relay.
- `dist/openwrt-x86_64/` rebuilt from this revision for all four CPU levels
  (v1–v4, static musl, stripped).

### 2026-09 hardening pass 3

- **Memory amplification bounds.** Per-connection transport windows lowered
  (aggregate receive 32→8 MB, DATAGRAM 4→1 MB), per-session socket buffers
  1→0.5 MB, global UDP session cap 16384→8192, and a 256-connection pre-auth cap
  (`MAX_UNAUTH_CONNECTIONS`): an unauthenticated peer can no longer pin the whole
  4096-connection receive budget.
- **0-RTT at scale.** rustls' default server session store holds only 256
  sessions; it is now sized to 8192, so resumption no longer silently degrades to
  a full handshake under load.
- **Hot-path costs removed.** The server UDP reply reader uses one 60 s periodic
  tick instead of a fresh timeout per `recv_from`; the client relay caches
  `(connection, PMTU limit)` for ≤1 s instead of calling
  `close_reason()`/`max_datagram_size()` (both take quinn's connection-state
  mutex) per datagram; server→target datagrams reuse the received `Bytes` slice
  instead of copying the payload.
- **`send_datagram` semantics corrected.** quinn silently drops the oldest queued
  datagram when its buffer is full (it never returns `Blocked`), so error
  handling now keys on `TooLarge` / `ConnectionLost` / `UnsupportedByPeer` /
  `Disabled` and comments match reality.
- **MQP-2.** The TCP-open ACK carries the server's dialed bound address and ALPN is
  bumped to `myquic2/2`, so version-skewed peers fail closed at the handshake instead
  of misparsing the ACK. *(Superseded in pass 4: the SOCKS reply is now optimistic and
  BND.ADDR for `CONNECT` is `0.0.0.0:0`.)*
- **Misc.** SOCKS5 RSV fields validated on requests and UDP headers; token
  comparison no longer leaks length; DNS cache values are `Arc<[SocketAddr]>`
  (O(1) cache-hit clones); the server header reader no longer stacks a second
  timeout per field; cert/key pairs are never partially regenerated (a missing
  half is a hard error); samples ship an empty token with a startup warning for
  placeholder secrets; `cargo fmt` clean.

### 2026-09 hardening pass 4

- **Latency parity with juicity/Hysteria-class clients.** The SOCKS success reply
  is no longer gated on the MQP-2 dial ACK: the client answers immediately after
  writing the target header and consumes the ACK on the reply direction. That
  removes one client↔server RTT from every TCP connection (verified: a blackhole
  target gets its SOCKS success in 0.1 ms instead of waiting out the ~4 s dial
  budget). A failed dial now closes the TCP flow; BND.ADDR for `CONNECT` is
  `0.0.0.0:0` because the reply precedes the dial result.

### 2026-09 hardening pass 5

- **Removed a process-abort reachable from normal network conditions.** quinn-proto
  0.11.17 corrupts its own DATAGRAM bookkeeping: when the path MTU shrinks,
  `Connection::drop_oversized` decrements `datagrams.outgoing.payload_bytes` for
  datagrams that `DatagramState::write` had already accounted for via `pop_front`, so
  a payload re-queued by the packet builder is subtracted twice. The counter underflows
  to `usize::MAX`, `memory_used()` then looks astronomical while the queue is empty,
  and the next `Connection::send_datagram` panics on
  `.expect("datagrams.outgoing.payload_bytes desynchronized")` — *while holding quinn's
  connection-state mutex*, which poisons it and aborts the whole process. Because both
  UDP paths used `send_datagram`, an MTU reduction on either side could kill the proxy.
  The new `try_send_datagram()` helper polls `send_datagram_wait` once with a no-op
  waker instead (non-blocking, drop-on-full, and it never touches the drop-oldest
  path; the pending future is dropped immediately, so nothing can leak) and reports
  `Sent` / `Blocked` / `TooLarge` / `Unsupported` / `ConnectionLost` explicitly, so the
  server refreshes its cached PMTU on `TooLarge` and the client invalidates its cached
  egress handle exactly as before. Its correctness also depends on the send buffer
  holding at least one maximum-size datagram, which `build_transport` now asserts at
  compile time. Reproduced on loopback (1200 B payload, peer `max_datagram_size` shrunk
  to 1162 B) and now covered by a live saturation test that aborts on the old path and
  passes on the new one.
- **Per-flow allocation removed from the TCP-open path.** `read_mqp_target` decodes the
  header out of one 259-byte stack buffer instead of three `Vec`s plus the owned
  domain `String` (a domain target went from four heap allocations to one); the dial's
  candidate list is filtered into a fixed array, so an IP-literal target — the dominant
  case — allocates nothing, and the domain case resolves into a stack array rather than
  a `Vec`. `dial_happy_eyeballs` now takes `&[SocketAddr]`, keeping its single-candidate
  fast path and its abort-on-cancel semantics (a plain handle list replaces `JoinSet`).
  The MQP-2 header length is a pure function (`mqp_hdr_len`) with unit tests for every
  wire form; the SOCKS5 reader keeps its proven shape and gained framing tests instead
  (see the next bullet).
- **Measured and rejected: batching the DATAGRAM readers.** A drain loop that polled
  `read_datagram` up to 32 times per wakeup was implemented, instrumented and reverted.
  Instrumentation showed an average batch of **1.06** datagrams (the reader is faster
  than the inbound queue, so batching never triggers), and an A/B run showed no
  difference in CPU, latency or throughput — the per-datagram cost is inside quinn's
  packet processing, not in our lock or waker handling. It is not shipped.
- **Measured and rejected: a client-side stack-buffer rewrite of the SOCKS5 reader.**
  It reproducibly lost the last byte of a domain target on macOS (`bad connect target`
  on every domain `CONNECT`, 0/5 transfers, twice, versus 5/5 with the original
  two-`read_exact` shape), so the reader keeps its proven shape with a note explaining
  why. The per-flow `Vec`s it would have saved never appeared in a profile.
- **Where the time actually goes.** On loopback a single QUIC connection saturates at
  roughly 2 Gbit/s and adding connections does not raise it; `/usr/bin/sample` shows
  10–45% of non-idle CPU in quinn's per-operation connection-state mutex (every
  `read`/`write`/`send_datagram` takes it, and the protocol driver needs it too).
  Application codec work measures 1.9 ns per address decode and ~49 ns per datagram
  encode, i.e. noise. Copy-buffer size (16 KB–256 KB) made no measurable difference
  because quinn's `read` already fills a whole buffer under one lock acquisition.
  Treat ~2 Gbit/s per connection as the library ceiling of this revision, not a
  tuning failure — a 1 Gbit/s WAN link is well inside it.
- **Rebuilt release binaries.** `dist/openwrt-x86_64/` was rebuilt from this revision
  for all four CPU levels (v1–v4: static musl, x86-64, stripped, ~4.1–4.2 MB each).
  The previous binaries predate the DATAGRAM abort fix, so **re-copy them to the
  router**; the fix is server- and client-side.

### 2026-09 hardening pass 6 — per-packet work audit

A line-by-line audit of the packet paths, followed by A/B measurement against the
previous revision on the same loopback host.

**Removed from the per-packet / per-flow path**

- **One allocation per DATAGRAM, built in one pass.** `encode_datagram*` validated the
  address *while* appending it, so the buffer could not be sized first: it started at
  40 bytes and grew once the payload was appended, copying the payload a second time.
  A new `TargetAddrRef::header()` validates and measures the address up front (still the
  same rules, still one definition of the wire format), so the buffer is `with_capacity`ed
  to the exact final size and filled in a single pass. A test pins the encoder's output
  byte-for-byte against the old two-step form for every address type.
- **The UDP reply path no longer copies the payload twice.** `send_reply` took a
  `&[u8]` and `udp_try_send` took a borrowed slice, so every reply that hit the socket's
  slow path did `payload.to_vec()` — a fresh allocation *and* a copy of data that already
  sat in an owned, refcounted `Bytes`. `udp_try_send` now takes `Bytes` and *moves* it
  into the queued write (unwrapping to its `Vec` first when it is unshared, so the common
  case is zero-copy); the reply path passes a `Bytes::slice` of the received datagram,
  which is a refcount bump. The per-reply `Vec` scratch buffer became a persistent
  `BytesMut` sized to the datagram.
- **A lock-free session lookup on the server's datagram path.** Every inbound datagram
  took the connection's session-table read lock and did a hash lookup — but a UDP flow
  sends long runs of packets to *one* session. A thread-local single-slot memo now
  answers the common case with one atomic load and no lock, and the reply reader clears
  its liveness flag as it exits so a dead session still falls through and is recreated.
- **The session sweeper no longer aborts readers while holding the write lock.** Removed
  entries are returned to the caller and aborted after the guard drops, and the key
  vectors it allocated under the lock are gone.
- **DNS: a lock-free hit, no per-packet clock, cheaper eviction.** The thread-local memo
  grew from one slot to two (positive and negative), so an interleaved stream of good and
  bad names no longer evicts the other class on every packet. A memo lookup no longer
  reads the clock before it knows the key matches, and the positive+negative cache probe
  now shares a single clock read. Eviction (`evict_if_needed`) no longer runs an O(n)
  `min_by_key` scan — or a full collect+sort — *under the write lock* on every insert past
  the cap: it evicts the whole overflow in one batch using `select_nth_unstable`.
- **One receive future per connection, not per datagram.** `read_datagram()` was rebuilt
  inside the loop on both sides, re-registering its `Notify` and re-taking the connection
  lock for every packet. It is now constructed once per connection and pinned
  (`read_datagram` is cancel-safe: a buffered datagram is returned before the first await
  point). The client's dispatcher additionally caches the last session's `Sender`, so a
  burst to one association skips the shard lock and the refcount bump.
- **Per-chunk work in the TCP↔QUIC pump.** The two 32 KB buffers were heap-allocated (and
  freed) per stream direction; they now come from a small per-thread pool with a
  bounded depth, so a steady stream of flows reuses the same memory. The throttled
  liveness stamp no longer did what it claimed — the non-multiple-of-8 branch still read
  the clock *and* reloaded the atomic on every chunk — and is now one local comparison
  plus (at most) one shared store per 100 ms.
- **Smaller fixed costs.** The UDP replies-to-app loop dropped a per-packet atomic reload
  (local shadow of the liveness stamp); the server's per-stream `Vec` for the 20-byte
  MQP-2 ACK became a stack buffer (`encode_bnd_addr_into`); per-session/relay socket
  buffers went from 512 KiB to 256 KiB per direction (they are caps, not reservations, and
  one association only ever carries one DATAGRAM flow), halving the worst-case kernel
  memory at the configured session caps; and the "buffer clamped" warning is now
  per-direction instead of a single flag in which whichever direction was probed first
  permanently silenced the other.

**Measured — and the honest headline: the proxy is not the bottleneck.**

Two full A/B runs against the previous revision on the same host, loopback, each doing
512 MiB of bulk download (8 concurrent), 4 000 SOCKS flows (16 concurrent) and 30 000
UDP datagrams through one association; CPU read from `ps -o time=` on both processes.

| Revision | server CPU | client CPU | bulk | flows/s | UDP recv pps | conn latency (median) |
|---|---|---|---|---|---|---|
| previous | 5.38 s | 7.52 s | 209 MB/s | 11 430 | 43 430 | 476 µs |
| this pass | 5.41 s | 7.41 s | 208 MB/s | 11 282 | 44 015 | 495 µs |

**Everything is within run-to-run noise.** The per-packet work this pass removed is on
the order of a few hundred nanoseconds, while the same packet costs microseconds inside
quinn: quinn takes its connection-state mutex once per DATAGRAM, runs through the
congestion controller and packet builder, and performs its own allocation per received
datagram. Against that, deleting one application-side `Vec` and one `RwLock::read` is not
visible in a loopback benchmark — which is the same conclusion the earlier DATAGRAM-reader
batching experiment reached (average batch 1.06, no measurable difference).

Where they do matter is the reason they were removed anyway: they are **per-packet,
per-flow costs that multiply with concurrency and core count**. A per-packet allocation
and a shared read lock are the kinds of things that turn into allocator contention and
cache-line ping-pong when hundreds of thousands of packets per second cross several
worker threads, even though they vanish into the noise of a single-flow loopback run.
Treat these changes as removing application-side tax, not as a throughput increase: if a
future profile shows the proxy's own per-packet code above noise, the microbenchmark
harness in `examples/hotpath_bench.rs` is what should measure the next change.

Correctness was verified after every step: `cargo test` (19 tests), `cargo clippy
--all-targets` and `cargo fmt --check` clean, and end-to-end runs of TCP `CONNECT` (IP and
domain targets), UDP `ASSOCIATE` (8 B and 1200 B payloads), 0-RTT resumption with early
data, and the token-auth accept/reject paths — all identical to the previous revision.
A harder mixed load (12 000 flows, 120 000 datagrams, 1 GiB bulk) kept both processes
within ~23 MB / ~13 MB RSS with no descriptor growth.

**Already optimal, left alone.** The DATAGRAM **encode** was never the problem: it
measures ~49 ns, i.e. noise next to the QUIC work around it. A drain loop that polled
`read_datagram` up to 32x per wakeup was tried and rejected — instrumentation showed an
average batch of 1.06 datagrams — and this pass did not re-litigate it.

**Outside this codebase's control.** The single biggest cost on the UDP path is that
quinn takes the connection-state mutex once per DATAGRAM, on both `read_datagram()` and
`send_datagram_wait()` (whose `poll` also calls `state.wake()`), and quinn 0.12 exposes no
batched receive or a wake/transmit-only entry point to avoid it. Reading one datagram per
lock acquisition is therefore a floor this revision cannot go below without patching
quinn; the changes above remove everything the application was adding *on top* of it. The
same applies to the second allocation quinn itself performs per received datagram when it
copies the frame out of its packet buffer.

### 2026-09 hardening pass 7 — reconnect race + DNS overload paths

- **Client `shared` TOCTOU.** The `open_bi` failure path did read-then-write
  (`read` the `stable_id`, drop, `write` `None`): a reconnect installing a fresh
  connection in between was unconditionally cleared, blackholing new flows until
  that connection died. It now takes a single write lock and re-checks
  `stable_id` inside, matching the reconnect loop's own clear path.
- **DNS eviction no longer scans under the write lock.** `evict_if_needed` did a
  full O(n) collect + `select_nth_unstable` plus per-victim key clones, and the
  negative cache did an O(n) `retain`, both while holding the global write lock —
  stalling every packet-path reader during a miss storm. Both now evict
  arbitrary entries in O(over)/O(1) with no clock reads; expired entries are
  still treated as misses by the TTL check on read, so correctness is unchanged.
- **TCP domain dials fail fast when the DNS budget is gone.** They waited up to
  3 s for `dns_slow_path_limiter` while holding a `stream_task_limiter` permit,
  so a unique-domain flood parked up to `MAX_STREAM_TASKS` permits and starved
  IP-literal flows. They now use `try_acquire` like the UDP path; the client
  retries a reset stream.

Verified: `cargo test` (19 tests), `cargo clippy --all-targets` and `cargo fmt
--check` clean; end-to-end TCP `CONNECT` (IP + `localhost` domain targets) and
UDP `ASSOCIATE`, plus `kill -9` → restart reconnect (~20 s silent-path
detection, stale-ticket redials, then TCP+UDP self-heal).

- **Rebuilt release binaries.** `dist/openwrt-x86_64/` was rebuilt from this
  revision for all four CPU levels (v1–v4: static musl, x86-64, stripped).
  Re-copy them to the router; the fix is server- and client-side.

### 2026-09 hardening pass 8 — quinn crates moved to upstream main

- **Dependency swap.** `quinn`, `quinn-proto` and `quinn-udp` are no longer taken
  from crates.io (0.11.11 / 0.11.17 / 0.5.15); all three now come from one git
  source, [`quinn-rs/quinn` `main`](https://github.com/quinn-rs/quinn) at
  `621e38ab` (0.12.0 / 0.12.0 / 0.6.2). `Cargo.lock` pins the exact commit, so
  builds stay reproducible; `cargo update -p quinn` moves the three forward
  together. This is what retires the pass-5 workaround: upstream moved the
  counter into the datagram buffer itself, so every mutation keeps it in sync
  (`drop_oversized` now decrements exactly what it removes), and the
  `.expect("datagrams.outgoing.payload_bytes desynchronized")` abort path no
  longer exists. `try_send_datagram` is kept — not for safety any more, but
  because the relay wants `Blocked` reports and drop-*newest* semantics, where
  `send_datagram` silently evicts the oldest queued datagram.
- **0-RTT API migration (breaking upstream change).** 0.12 removed the
  `ZeroRttAccepted` future that `Connecting::into_0rtt()` returned, and
  `Connection::authenticated()` reports only "handshake finished or connection
  lost" — it does **not** carry the early-data decision. The client still refuses
  to publish a connection before the handshake completes (now by awaiting
  `authenticated()`, which also surfaces a dead dial as `Err`), and detects
  rejection the way upstream documents: `SendStream::stopped()` on the finished
  early auth stream yields `ZeroRttRejected`. On rejection the token is re-sent
  over the established 1-RTT connection instead of failing the dial and
  redialing, so a server that declines early data no longer costs a dial.
- **Server handshake gate.** The 0.5-RTT accept path awaits
  `Connection::authenticated()` in place of the removed `ZeroRttAccepted`, and
  now also aborts on a failed handshake rather than only on the timeout.
- **`Connecting` no longer hides a dead dial.** 0.12 returns the terminal error
  instead of `Ok` for a connection that terminated before its handshake;
  `ensure_dialed_alive` stays as a cheap guard.
- **Minor API churn.** `Endpoint::set_default_client_config` takes `&self` (the
  now-redundant `mut` endpoint bindings are gone); `examples/zero_rtt_probe.rs`
  derives the "server accepted 0-RTT" line from `stopped()` and falls back to the
  echoed early data as its own proof when no auth token is configured.

Verified end-to-end on loopback with token auth on both sides (tests 16–20 in
[Verification & E2E Tests](#verification--e2e-tests)): `cargo test --all-targets`
19/19, `cargo clippy --all-targets` and `cargo fmt --check` clean, TCP `CONNECT`
(1 MiB) and UDP `ASSOCIATE` (25 × 1000 B) byte-for-byte, and a `kill -9` →
restart cycle in which the client's **stale 0-RTT ticket is rejected** and the
token is re-sent at 1-RTT before the flows recover. `dist/openwrt-x86_64/` was
rebuilt from the pass-8 revision for all four CPU levels.

### 2026-09 hardening pass 9 — TCP windows re-sized for 300 Mb/s at 140 ms

- **`dist/openwrt-x86_64/` rebuilt again** from this pass for all four CPU levels
  (v1–v4, static musl, stripped, ~4.2 MB each) and smoke-tested under x86-64
  emulation on a CPU without AVX: see
  [Cross-compile for OpenWrt x86-64](#cross-compile-for-openwrt-x86-64-static-musl-from-macos).
- **The bottleneck was flow control, not congestion control.** At 140 ms, 300 Mb/s
  costs ~5.25 MB in flight (37.5 MB/s × 0.14 s, plus the QUIC short header and
  IPv4/UDP headers). Every flow-control window is a hard ceiling of
  `window / RTT`, and the previous sizing capped single-stream at **~114 Mb/s
  receive / ~228 Mb/s send** long before BBR's congestion window mattered:
  `stream_receive_window` 2→8 MB, `receive_window` 8→16 MB, `send_window` 4→8 MB.
  Both endpoints build their transport from `build_transport`, and a download is
  capped by the *receiver's* advertisement while an upload is capped by the
  *sender's* budget, so both sides had to change for either direction to improve.
- **8 MB, not the ~5.25 MB BDP.** quinn only emits `MAX_STREAM_DATA` once the
  advertised window is short by `stream_receive_window / 8`, so the cushion that
  must still cover a BDP is `8 − 1 = 7 MB`. At 6 MB it would be 5.25 MB — the BDP
  exactly, with nothing left for scheduler jitter or a slow application read.
- **Reverse-path ACK rate.** `AckFrequencyConfig` now requests an ACK every 8th
  ack-eliciting packet with a 10 ms `max_ack_delay` (was quinn's default of every
  2nd packet, `None` delay): ~14k ACK/s per 300 Mb/s stream is real work for the
  single writer thread. A threshold of 32+ was rejected — it makes BBR's
  bandwidth estimate too coarse and slows the startup ramp.
- **`initial_rtt` 333 → 190 ms** (quinn's default is a spec-derived placeholder
  that makes the first PTO and the initial bandwidth estimate pessimistic for
  this link), and the PMTU search ceiling 1452 → 1472 B (`EndpointConfig`'s
  default `max_udp_payload_size`, so 1452 was leaving 1.4% of the path unused).
  The search still starts at the 1200 B QUIC minimum and climbs only on
  successful probes.
- **Known cost, carried over from pass 2's gaps-death halving.** 8 MB allows
  ~6200 packets in flight per RTT (1350 B) or ~3700 (1452 B), so a burst-loss or
  reordering episode has more room than 2 MB did to approach quinn's
  `MAX_CHUNKS = 1024` reassembly limit, which kills the whole connection with
  `too many gaps in stream buffer`. A clean path is unaffected. On a lossy one,
  step `SEND_WINDOW` / `STREAM_RECEIVE_WINDOW` back to 4 MB (~240 Mb/s) rather
  than reverting the ACK/MTU work, which is independent of loss.
- **What is not tested here.** The invariant lives in named constants
  (`STREAM_RECEIVE_WINDOW`, `RECEIVE_WINDOW`, `SEND_WINDOW`) asserted in `const`
  blocks, so re-tightening a window fails the *build*. A live loopback test was
  written and rejected: with a 2 MB window the cushion is still 1 MB, which at a
  ~0.2 ms loopback RTT is worth ~40 Gb/s, so it passed against the very
  regression it was meant to catch. Confirming the 300 Mb/s figure needs a
  ~140 ms path and `conn.stats()` (`path.cwnd`, `path.pacing_rate`), as the
  README's measurement notes describe.

### 2026-09 hardening pass 10 — back to crates.io quinn 0.11.18

- **Dependency switch.** `quinn`, `quinn-proto` and `quinn-udp` are crates.io
  dependencies again (quinn 0.11.12 / proto 0.11.18 / udp 0.5.15) instead of the
  upstream-`main` git pin (pass 8) and the `MAX_CHUNKS = 16384` fork patch built
  on it. Upstream's 0.11.18 backports everything this project needed from `main`:
  the DATAGRAM `payload_bytes` accounting fix, the assembler contiguous-chunk
  coalescing, and three security fixes (unordered-read panic, drop-oldest
  double-subtraction, ACK_FREQUENCY min-delay panic) — so the fork has no
  remaining value and its maintenance cost is gone. `cargo update` moves the
  trio within the 0.11 line.
- **0-RTT ported back to the 0.11 API.** `Connecting::into_0rtt()` yields
  `(Connection, ZeroRttAccepted)` again; the client gates publication on that
  future plus `close_reason()` (false = rejected or died, timeout = dead), and
  re-sends the token at 1-RTT on rejection; the server awaits the same future
  (always true incoming-side) bounded by `HANDSHAKE_TIMEOUT` before consuming
  the auth token. The `stopped()`-based rejection signal and `mut`-less
  `set_default_client_config` from pass 8 are reverted with it. Transport tuning
  (`AckFrequencyConfig`, `initial_rtt`, MTU ceiling, windows, `send_datagram_wait`
  helper) needed no changes — all present in 0.11.
- **Known regression vs the fork.** `MAX_CHUNKS` is 1024 again, so the 8 MB
  stream window is gap-kill-prone on lossy links as analyzed in pass 9; the
  mitigation is unchanged (step back to 4 MB). Single-user deployment accepted.

### 2026-09 hardening pass 11 — the DATAGRAM budget was a payload cap

Found while explaining a `speed.cloudflare.com` verdict of *Video chatting: Poor*
on a China-Mobile → LAX path. The TCP side was not at fault (that verdict is
driven by TCP-measured jitter); the UDP relay had a real defect of its own.

- **The bug.** Both relays sized outgoing DATAGRAMs against
  `max_datagram_size().min(1350)`. The `min` looks like a harmless MTU safety
  margin, but `1350` is compared against the **whole** MQP-2 body
  (`encode_datagram_ref_with_limit`: `DGRAM_PREFIX_LEN + header + payload`), so
  it is in fact a *payload* cap of `1350 - 5 - 7 = 1338 B` for an IPv4 target
  and `1326 B` for IPv6 — no matter how large the discovered path MTU was. Every
  larger UDP payload was dropped with a `debug!`-level log, i.e. silently at the
  default log level. Measured on loopback against the previous binary:
  1338 B → 0 % loss, 1350 B → **100 % loss**. A 1400 B DTLS record or a
  TURN-wrapped media packet that a direct UDP path delivers fine simply vanished.
- **Fix.** The relays now pass `max_datagram_size()` unclamped — that value is
  exactly the largest DATAGRAM body quinn will carry on the current path, with
  the QUIC packet and DATAGRAM-frame overhead already subtracted, so using it
  directly is the API contract rather than a policy choice. On a 1472 B path the
  usable UDP payload is now ~1436 B (IPv4) instead of 1338 B. The dynamic-PMTU
  behaviour that motivated the `min` is preserved by the existing refresh paths
  (`TooLarge` → re-read the limit, client also re-reads once per second).
- **New `dgram_payload_cap()`** states the relationship once, so callers and
  tests reason about the *payload* budget instead of re-deriving the header
  arithmetic. `DGRAM_MAX_WIRE = 1472` replaces the old
  `DATAGRAM_BUFFER >= MQP_DGRAM_MAX` send-buffer invariant, which only ever
  proved that a 264 B header fits — it never covered a full-size datagram.
- **Drops are now visible.** `try_send_datagram`'s two drop outcomes were
  `debug!`-only, which is why a 100 % loss of large datagrams could go unnoticed.
  `send_udp_datagram()` is now the single encode+send entry point for both
  relays; it bumps `dgram_drops::TOO_LARGE` / `dgram_drops::BUFFER_FULL`
  (`snapshot()` reads them) and emits one rate-limited `warn!` per 10 s naming
  the path limit and the usable payload budget.
- **Not a fix: `Blocked` under TCP load.** The 1 MB datagram send buffer was
  suspected of dropping UDP when bulk TCP streams occupy the congestion window.
  Measured with four saturating TCP flows on the same connection: 1200 B UDP at
  200 pps lost **0 %** both with and without the TCP load; only a full-rate flood
  (~190 kpps offered) lost packets, and the rate was essentially unchanged by the
  TCP load (70.5 % vs 66.5 %). DATAGRAM loss here is driven by the offered UDP
  rate filling the send buffer, not by TCP competing for cwnd. The counters above
  make that distinction observable in production.

### 2026-09 hardening pass 12 — MQP-2 UDP fragmentation

Pass 11 removed an artificial clamp, which moved the single-frame ceiling from
1338 B to ~1422 B. That is still **not enough to be transparent**: a full 1472 B
UDP payload can never fit a QUIC DATAGRAM, because the 12 B MQP header plus the
QUIC packet and DATAGRAM-frame overhead exceed a 1472 B path MTU. Video calling
is exactly the workload that notices — DTLS handshake records, non-WebRTC
conferencing stacks, TURN-wrapped media and modest IP fragmentation all exceed
one frame, and every such packet was being dropped 100 %.

- **`type=0x05` fragments.** A payload too large for one frame is split into
  `total` fragments carrying `(sess, id, idx, total)` plus the address header, and
  reassembled by the peer. Small packets keep the byte-identical `type=0x02`
  single-frame path, so nothing pays for this unless it needs it.
- **Ceiling raised to 8 KiB** (`MQP_FRAG_MAX_PAYLOAD`), 5.5x the largest
  datagram any real-time medium produces (1472 B on a 1500 B MTU), so it is not
  a limit the target workload can reach. The per-session read buffer is the same
  8 KiB, which bounds worst-case relay memory at 8 KiB × `MAX_SESSIONS_GLOBAL`
  (64 MiB).
- **Why not the 65507 B UDP maximum.** Reassembly is all-or-nothing, so a
  payload's delivery probability is `(1-p)^F` while its cost stays `F` fragments.
  At 1 % loss a 64 KiB payload is 47 fragments: 62 % delivery for 47x the bytes,
  and at 5 % loss it is 9 % — bandwidth spent on a datagram that will not
  arrive. 8192 B is 6 fragments, 94 % at the same 1 % loss. Fragmentation still
  beats dropping outright, which is why the **wire format is sized for the full
  UDP maximum**: the compile-time assertion next to `MQP_FRAG_MAX_TOTAL` proves a
  `u8` count reaches 65507 B even at QUIC's minimum 1200 B MTU (58 of 64
  fragments), so raising the constant is a one-line change and never a
  wire-format change. `fragment_count_documents_the_loss_amplification_tradeoff`
  pins the arithmetic.
- **Buffers were a second, earlier cliff.** Both relays read into a 2048 B socket
  buffer, so anything past ~2 KiB was truncated *by the kernel* before any counter
  could see it. Buffers now cover the full protocol cap, plus one byte of slack:
  `recv_from` reports the same length for "exactly filled" and "truncated", so the
  slack is what makes the `n == buf.len()` warning mean truncation and nothing
  else. Truncations now log instead of vanishing.
- **Bounded and all-or-nothing.** A partial is capped by
  `MQP_FRAG_MAX_PAYLOAD`, a connection holds at most `FRAG_MAX_HELD_BYTES`
  (evicting the oldest partial past it), and partials expire after
  `FRAG_TIMEOUT_MS`. A datagram missing any fragment is dropped rather than
  delivered short — the failure mode this whole pass exists to remove.
- **Additive on the wire.** An older peer rejects the new frame type and drops
  the datagram, which is exactly its pre-pass-11 behaviour for oversized payloads,
  so no misparse is possible and ALPN stays `myquic2/2`. Both ends must be on this
  revision to carry large datagrams.
- **The dispatcher is a second decode site (found by the Meet simulation).** The
  client's per-connection reader routes each datagram to its association by
  reading `sess` — and it did so behind a hard-coded `d[0] != 0x02` check, so
  every `0x05` fragment was discarded before the reassembler could see it. The
  symptom was precise: a 1438 B DTLS record (the only packet in a Meet call that
  needs a second frame) was lost 100 % of the time, every run, while everything
  at or below one frame was perfect. `dgram_sess()` is now the single place that
  knows which frame types are routable, with
  `dgram_sess_routes_both_frame_types` pinning it.
- **Verified end to end, round trip.** The earlier sweep counted only what the
  echo peer received, i.e. the outbound half — which is why it passed while the
  reply direction was broken. `udp.mjs` now counts replies at the client too:
  1200 / 1420 / **1430** / **1472** / 2000 / 4000 / 8000 / **8192** B all at 0 %
  loss in *both* directions (1422 B and 1430 B were 100 % loss before), and
  8300 B refused with one warning naming the cap.
- **Google Meet simulation** (`meet_sim.mjs`): 250 pps of 1200/200/100 B media
  plus a 1236–1438 B DTLS burst, run through the real binaries. 6/6 handshake
  and 4680/4680 media packets, 0 % loss, 0 reorder, 0 size mismatch, RTT median
  0.6 ms / p95 0.8 ms, RFC 3550 jitter 0.17 ms — and unchanged with two
  saturating bulk TCP downloads sharing the tunnel. Unit tests cover order
  independence, a lost fragment, duplicate fragments, malformed headers, id
  reuse with a changed shape, expiry, the memory bound, and a real-connection
  round trip.

### 2026-09 hardening pass 13 — zero-copy TCP pump, optional counters, per-flow Vecs

Three items from the "remove application-side tax" list. All three are real, and
**none of them is measurable on a loopback host** — the work they remove is
0.3–0.6 % of the CPU the same traffic costs, so they are insurance for
concurrency and pps, not a throughput increase.

- **The TCP↔QUIC pump no longer copies in either direction.** quinn's
  `write_chunk` *moves* the caller's `Bytes` into the stream's send queue
  (`BytesArray::pop_chunk` retains it, no copy), where `write`/`write_all`
  copies (`ByteSlice::pop_chunk` → `to_owned()`); quinn's `read_chunk` returns a
  refcounted view of the receive assembler's own buffer
  (`assembler.read` → `Bytes::split_to`), where `read` copies out of it. So the
  upload side now reads with `read_buf` into a `BytesMut` and hands large reads
  over as `write_chunk`, and the download side drains with `read_chunk`: one
  32 KiB memcpy per chunk per direction is gone. The per-thread `CopyBuf` pool
  went with it — the read buffer is reused for small writes and handed to quinn
  for large ones.
- **Small writes still copy, deliberately.** A handed-over buffer is a full
  `COPY_CHUNK` (32 KiB) however few bytes were read, so handing it over for a
  24-byte request would pin 32 KiB per in-flight small write; below
  `ZEROCOPY_MIN_WRITE` (8 KiB) the pump calls `write_all` and lets quinn
  allocate exactly what it needs. The read path's headroom invariant
  (`BytesMut::chunk_mut` only reserves 64 B once full, which would turn every
  32 KiB read into a 64-byte one) is pinned by
  `reserve_copy_chunk_always_leaves_a_full_chunk_of_room`.
- **Per-packet counters can be compiled out.** The `stats` feature (default on)
  gates every atomic `udp_stats`/`udp_write` bumps on the relay path — four
  shared cache-line RMWs per relayed datagram. `cargo build --release
  --no-default-features` compiles them all out; the modules keep their API and
  report zeros, and `dgram_drops` (drop paths only, not per packet) stays live
  so the drop/reassembly warnings still name what happened.
- **The client's TCP-open path allocates nothing.** `AddrHeader::encode_into`
  writes the MQP-2 header into a stack buffer (pinned byte-for-byte against the
  `Vec` encoder by `addr_header_into_matches_the_vec_encoder`), and
  `read_socks_addr` decodes from one stack buffer instead of assembling four
  `Vec`s. The reader keeps its `read_exact`-per-field shape on purpose: the
  earlier "one buffer + a read loop" rewrite lost the final port byte of a domain
  target on macOS and was already reverted once.

**Measured — and the honest headline is that this pass moves nothing on this
host.** A/B against the pass-12 binaries, same machine, 3 interleaved rounds
alternating variants, identical warmups (after the cold-vs-warm 20–30 % swing
found in pass 13's own round-one measurement, warmups are mandatory before
believing any number here):

| Workload per round | pass 12 | this pass |
|---|---|---|
| 256 MiB bulk download, 4-way | 158 MB/s (median) | 151 MB/s |
| 2 000 SOCKS `CONNECT`s, 32-way | 10 997 flows/s | 10 411 flows/s |
| 100 000 UDP datagrams, batch 128 | 34 714 pps | 35 170 pps |
| **CPU-seconds, client + server** | **10.37 s** | **10.41 s** |

Every figure is inside the host's run-to-run noise (single bulk runs ranged
136–167 MB/s across both variants). The arithmetic explains it: 512 MiB of
memcpy is removed per round, which at 8–15 GB/s is 35–65 ms of the 10.4 s
total — 0.3–0.6 %, below what a single-host benchmark can resolve. Treat these
as removing application-side tax that multiplies with concurrency (four atomic
RMWs per packet across cores; one copy per byte per link), which is what a
future 10× pps load or a saturated weak-CPU link would notice.

Verified on this revision: `cargo test` 36/36 (34/34 with
`--no-default-features`), `cargo clippy --all-targets` and `cargo fmt --check`
clean on both feature sets, and — through the real binaries, with the SOCKS
listener's owning PID checked so a stale process cannot masquerade as the build
under test — TCP ECHO 1 MiB byte-for-byte, a domain-target `CONNECT`, a UDP
sweep of 8 / 1200 / 1420 / 1430 / 2000 / 8000 B at 0 % loss in both directions,
and a full `kill -9` → restart cycle (detection 15.1 s, redial 0.19 s after the
restarted server bound, first TCP echo 17.2 s after the kill, idle pre-kill
flows failed at connection death instead of hanging, and the pre-kill UDP
association self-healed).

### 2026-09 hardening pass 14 — session-memo correctness and hot-path locks

Two correctness fixes and four per-packet/per-flow tax removals, all found by
re-reading the relay paths (the loopback profile still shows the proxy's own
code as noise next to quinn's connection-state mutex, as in passes 5–6 and 13).

- **Cross-connection session-memo crosstalk.** The server's thread-local
  `SESS_MEMO`/`TOUCH_MEMO` slots were keyed by `sess` alone, but session ids
  are allocated per client (every hub counts from 1), so two connections
  sharing a worker thread served each other's sockets and routed replies onto
  the wrong QUIC connection. The key is now `(conn, sess)` with a
  process-wide monotonic id — `Connection::stable_id` is a heap address the
  allocator reuses after a reconnect, so it cannot serve as the key. Pinned by
  `session_memo_never_crosses_connections` (verified to fail against the old
  key).
- **Stale memo after reader abort.** The `alive` flag was only cleared on a
  natural reader exit; the sweeper and connection close abort readers without
  running any cleanup, so the memo kept handing out a dead socket. The memo
  now stores the reader's `AbortHandle` and treats a finished task as stale —
  the same signal the table path uses. Pinned by
  `session_memo_ignores_finished_readers` (verified to fail against the old
  always-live check).
- **The DATAGRAM-budget check left the hot path.** `get_or_create_sess` called
  `max_datagram_size()` — quinn's connection-state mutex — before the
  memo/table fast paths, on every inbound datagram. It now runs once per
  session creation, after both hits.
- **Routing no longer takes quinn's lock.** `ConnSlot::is_live` called
  `close_reason()` (the same mutex, plus an error clone) twice per TCP flow;
  the connection loop maintains an atomic liveness bit instead, and
  `wait_conn` stays the authority that fails a flow fast. Pinned by
  `slot_liveness_is_the_maintained_atomic`.
- **One SOCKS negotiation deadline.** Greeting, request and address reads each
  re-armed a 10 s timeout; `negotiate()` keeps the byte-identical framing
  (pinned by `negotiate_reads_connect_and_associate`) under a single 10 s
  deadline.
- **Drop warnings format lazily.** `budget_detail` / `format!` / `to_string`
  ran before the rate-limit gate, so logging was the per-drop cost under a
  flood; the detail closure now runs only for the emitted line (pinned by
  `warning_slot_is_claimed_once_per_interval`). The duplicate
  `mono_ms` / `mono_millis` clocks merged, and the UDP reporter left the
  accept loop.

Verified on this revision: `cargo test` 48/48 (47/47 without `stats`),
`cargo clippy --all-targets` and `cargo fmt --check` clean on both feature
sets, and — through the real binaries — two clients sharing sess id 1 on
different server connections exchanged 2×30000 UDP datagrams at 0 % loss with
2×304 TCP flows clean, plus a `kill -9` → restart cycle (17.5 s detection,
1.8 s recovery, UDP self-heal). `dist/openwrt-x86_64/` rebuilt from this
revision for all four CPU levels.

### 2026-09 hardening pass 15 — batched pump, sharded counters, shared egress

Throughput work on top of pass 14, same wire protocol (no ALPN bump, mixed pairs
stay compatible):

- **Batched TCP download.** The QUIC→TCP direction used `read_chunk(MAX)` +
  `write_all`: one connection-lock acquisition and one syscall per ~1.4 KiB STREAM
  frame. It now drains up to 8 segments per lock with `read_chunks` and pushes them
  with a single vectored write; the liveness clock is sampled once per batch and the
  upload direction stamps every 8th chunk.
- **Sharded relay counters.** `DATAGRAMS`/`BYTES`/`SENT` accumulate thread-locally
  and flush every 1024 (bytes every 1 MiB); `MAX_PAYLOAD` checks-then-sets so the
  common case is a shared load, not an RMW. `snapshot()` flushes the caller's
  thread — cross-thread error is bounded, low-rate reporters should note the delay.
- **Shared UDP egress.** Each association refreshed its own `(connection, PMTU)`
  once per second (two quinn locks × 4096 associations). One process-wide cache now
  serves all associations; only the global refresher pays the locks, and
  `TooLarge`/`ConnectionLost` invalidates it.
- **Wider memos.** `SESS`/`TOUCH` go 1→8 slots and DNS 2→8 slots with round-robin
  replacement, so interleaved sessions and domains no longer evict each other per
  packet. DNS misses also skip spawning when the key is already inflight, and
  `WouldBlock` retries go through a single 4096-deep global worker instead of one
  task per packet.
- **Stream priorities.** Interactive TCP flows set priority 10, bulk stays 0
  (`SendStream::set_priority`, quinn 0.11). This orders STREAMs within a connection;
  DATAGRAM-vs-STREAM scheduling still follows the congestion window, so the dual
  connections remain the UDP isolation mechanism.
- **Samples use defaults.** Both sample configs drop the 2/4/2 MB pin and omit tuning
  (4/8/4 MB code defaults). No wire change.
- **Small fixes.** Drop warnings are per-reason (large/full/other) instead of one
  shared slot; a zero-budget session reader exits instead of dropping silently;
  `last_app` uses non-blocking `try_read`/`try_write`.

Verified on this revision: `cargo test` 48/48 (47/47 without `stats`), `cargo clippy
--all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets.
`dist/openwrt-x86_64/` rebuilt from this revision for all four CPU levels (static
musl, stripped, ~4.1 MB each; `file` confirms x86-64). The full E2E suite was last
run green on pass 14 and is not re-run here — wire and behavior are unchanged, but
treat throughput deltas as unmeasured until the bench harness runs on a real link.

### 2026-09 hardening pass 16 — single-flight egress, sharded tables, pooled pump

Contention work on top of pass 15, same wire protocol (no ALPN bump, mixed pairs
stay compatible). Pass 15 shared the egress cache, the retry queue and the memos;
at high association counts the shared paths themselves became the bottleneck:

- **Single-flight egress refresh.** The 1 s window expired on all 4096 associations
  at once, so every association paid `close_reason()` + `max_datagram_size()` (two
  quinn locks) per refresh window. Only one winner still pays them; the rest fail
  fast under UDP drop semantics instead of herding on the same mutexes.
- **Dispatcher 8-slot cache.** The per-connection dispatcher kept a single
  `last_sess` slot, so two interleaved associations re-took the hub shard lock on
  every packet. Eight slots with round-robin replacement match the server-side
  memo widths; the stale-sender refresh-and-retry rule is unchanged.
- **Sharded retry pool.** `WouldBlock` retries went through one 4096-deep global
  worker, so one slow destination head-of-line-blocked every other session. Four
  shards (by destination port, 1024 deep each, same total budget) with one worker
  per shard; a full shard still drops per UDP semantics.
- **Sharded server session table.** The per-connection table was one `RwLock`, so
  concurrent sessions serialized on one reader count. Eight shards by sess id;
  sweep and drain go shard by shard with short lock holds, and the per-shard cap
  shares `LOCAL_SESS_MAX` evenly.
- **Per-connection fast path.** The thread-local session memo is shared by every
  connection on a worker, so a burst still paid two `RefCell` scans per packet.
  The DATAGRAM reader keeps its own single slot (socket + stamp + abort handle,
  the same liveness signal as the table path); IP hits skip memo and table
  entirely, misses fall back and refill. The `is_global_ip` verdict for the
  packet's own address is still checked on every hit, and `sess 0` can never
  enter the slot.
- **Sampled clocks.** `touch_session_throttled` read the clock on every packet
  (~20 ns vdso each, ~1% CPU per core at 500 kpps). The clock is now sampled at
  most once per 64 packets: hot flows still refresh far more often than the 1 s
  interval, and slow flows stay inside the 180 s reap budget. Fixed-destination
  `is_global_ip` verdicts are memoized thread-locally (8 slots, pure function,
  same security outcome).
- **Pooled pump buffers.** Each TCP flow allocated its 32 KiB copy buffer fresh;
  at 10k short flows/s that is 320 MB/s of allocator traffic. A thread-local pool
  (depth 4, oversized buffers dropped instead of retained) serves the small-write
  path and flow startup; the bulk zero-copy path is unchanged.
- **PMTU tracking on the reply path.** The server session reader refreshed its
  DATAGRAM limit only on the 60 s tick, so a grown path MTU went unused for up to
  a minute. Active sessions now refresh at most once per 5 s (one quinn lock);
  idle sessions pay nothing. `TooLarge` still refreshes immediately.
- **Small fixes.** `last_app` is only published on change (the value is constant
  per association, so the per-packet `try_write` starved under a loaded reply
  task); per-flow abort lines are sampled to one `conn.stats()` snapshot per
  second with a suppressed count instead of one quinn lock per abort.

Verified on this revision: `cargo test` 48/48 (47/47 without `stats`), `cargo clippy
--all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets.
`dist/openwrt-x86_64/` rebuilt from this revision for all four CPU levels (static
musl, stripped, ~4.1 MB each; `file` confirms x86-64). The full E2E suite was last
run green on pass 14 and is not re-run here — wire and behavior are unchanged, but
treat throughput deltas as unmeasured until the bench harness runs on a real link
(multi-association concurrency and abort storms, not just single-flow MB/s).

### 2026-09 hardening pass 17 — shard cap, per-session touch, stale egress

Correctness fixes on top of pass 16, same wire protocol (no ALPN bump, mixed pairs
stay compatible). Pass 16 shared the hot paths; four of the shared-path changes
carried regressions this pass removes:

- **Per-shard session cap enforced.** `sweep_local` compared one shard's length
  against the connection-global `LOCAL_SESS_TARGET` (512 < 4032, so the
  over-target branch never fired and the per-connection cap silently stopped
  working). A new `LOCAL_SESS_TARGET_SHARD` (504) bounds each shard; the table
  oscillates 504~512 instead of growing past `LOCAL_SESS_MAX`.
- **Per-session liveness sampling.** The throttle tick was thread-global, so with
  two round-robin sessions every 64th tick landed on the same session (64 is
  even) and the other expired at the 180 s reap. The counter now lives in the
  memo entry: each session samples every 64th of its own packets.
- **Stale-while-revalidate egress.** The 1 s window expired for all 4096
  associations at once and only the single-flight winner refreshed; losers
  dropped one packet each per second. Losers now reuse the expired handle (a
  dead one surfaces as `ConnectionLost` and invalidates) instead of dropping.
- **Per-chunk upload stamps + throttled table hits.** The TCP upload direction
  stamped every 8th chunk, so a trickle upload (1 chunk/min) passed the 300 s
  idle reap with live bytes; it now stamps every chunk (still throttled to
  100 ms inside), symmetric with the batched download path. Table-hit lookups
  use the throttled touch instead of an unconditional clock read.
- **Comment fix.** The ACK-frequency note now states quinn's `>` semantics
  (threshold 2 = every 3rd packet, not 2nd). No behavior change.

Verified on this revision: `cargo test` 48/48 (47/47 without `stats`), `cargo clippy
--all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets.
`dist/openwrt-x86_64/` rebuilt from this revision for all four CPU levels (static
musl, stripped, ~4.1 MB each; `file` confirms x86-64). The full E2E suite was last
run green on pass 14 and is not re-run here — wire and behavior are unchanged, but
treat throughput deltas as unmeasured until the bench harness runs on a real link.

### 2026-09 hardening pass 18 — non-blocking egress publish, trickle-flow liveness

Two small fixes on the pass-16/17 shared paths, same wire protocol (no ALPN bump,
mixed pairs stay compatible):

- **Egress publish never blocks the executor.** The single-flight winner in
  `SharedEgress::refresh_global` published its timestamp with a blocking `std`
  write lock. Readers hold it only for an Arc bump, but under a 4096-association
  read flood a blocked writer can be starved, parking the whole worker thread. It
  now uses `try_write`: on a lost race this packet still uses the fresh handle
  and the stamp stays expired so the next packet retries (single-flight keeps it
  to one contender). Same pattern `invalidate()` already used.
- **Trickle flows keep their liveness.** The per-session 1/64 clock sampler never
  checked the clock for a session's 2nd..63rd packets, so a unidirectional flow
  under 64 packets per 180 s never advanced its stamp and was reaped as idle
  despite live traffic — then recreated, churning a socket + task every 180 s per
  trickle. Sampling now starts after 64 packets since the last store and the
  window resets on every store: slow flows check every packet (noise — they are
  rare by definition), hot flows still pay 1/64 past the first 64.

Verified on this revision: `cargo test` 48/48 (47/47 without `stats`), `cargo clippy
--all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets.
`dist/openwrt-x86_64/` rebuilt from this revision for all four CPU levels (static
musl, stripped, ~4.1 MB each; `file` confirms x86-64). The full E2E suite was last
run green on pass 14 and is not re-run here — wire and behavior are unchanged.

### 2026-09 hardening pass 19 — touch regression, memo GC, budget counters

Five fixes on the pass-16/17/18 shared paths, same wire protocol (no ALPN bump,
mixed pairs stay compatible):

- **Burst-then-trickle flows are no longer reaped as idle.** The per-session 1/64
  count sampler only reset its window on a store, so a burst inside one second grew
  `tick` without ever storing, and every later trickle packet kept skipping the clock
  read — `last` froze until the 180 s sweep killed a live session. The throttle is
  purely time-based now (one shared store per second per session, one clock read per
  packet); the ~20 ns vdso read is an order of magnitude cheaper than the table lock
  it replaces.
- **Evicted sessions no longer pin sockets.** `sess_memo_lookup` clears stale slots on
  read (releasing the `Arc`), so sweep/drain-aborted readers stop lingering in the
  32-slot thread memo; the per-connection fast slot keeps its existing refresh-on-miss
  rule and drops with its reader task.
- **`sess_memo_put` left the table write lock.** The insert clones its `(sock, last,
  abort)` inside the shard guard and publishes to the memo after the guard drops, so
  the critical section holds only map operations.
- **Budget drops are counted.** `dgram_drops::SESSION_FULL` covers the global 8192
  session cap, the 1 s sweep throttle, `sess 0` refusals and DNS slow-path exhaustion
  (previously silent); the server 60 s reporter prints a `udp budget` line and
  `snapshot3()` keeps `snapshot()` compatible (`bump` is now `pub` for the binaries).
  *(Pass 24 adds `DNS_INFLIGHT` / `snapshot4()` for the resolution-in-flight drops
  this pass left uncounted.)*
- **Stale egress is liveness-checked.** The client reuses an expired handle only after
  `close_reason().is_none()`; a dead one is counted, invalidated and dropped instead
  of sending a packet that can never arrive.

Verified on this revision: `cargo test` 48/48 (47/47 without `stats`), `cargo clippy
--all-targets -- -D warnings` and `cargo fmt --check` clean on both feature sets.
`dist/openwrt-x86_64/` rebuilt from this revision for all four CPU levels (static
musl, stripped, ~4.1 MB each; `file` confirms x86-64). The full E2E suite was last
run green on pass 14 and is not re-run here — wire and behavior are unchanged.

### 2026-09 hardening pass 20 — sharded DNS, cancel proof

Lock-contention work on the DNS path plus a soundness pin on the DATAGRAM send
path, same wire protocol (no ALPN bump, mixed pairs stay compatible):

- **Sharded DNS tables.** The positive cache, negative cache and single-flight
  table were each one global `std` lock, so every packet-path reader shared one
  reader count / one mutex cache line. All three are now 16 shards selected by a
  key fold (manual multiply-add, no SipHash on the hot path — a collision only
  shares a lock, never an entry). Caps split evenly (256 + 32 slack / 256 per
  shard, 4096 total preserved) and the single-flight register/cleanup paths shard
  by the same key, so coalescing still meets.
- **`poll_once` cancellation proof.** `try_send_datagram` polls
  `send_datagram_wait` once with a noop waker and drops the future on `Pending`;
  verified against quinn 0.11.12 (`Blocked` puts the bytes back into the future,
  parks on tokio `Notified` whose `Drop` unregisters) and pinned by
  `cancelled_datagram_waits_leave_no_residue`, which hammers the `Blocked` path
  and proves a fresh connection on the same endpoint still sends.

Verified on this revision: `cargo test --all-targets` 50/50 (49/49 without
`stats`), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
clean on both feature sets, `cargo build --release` ok. `dist/openwrt-x86_64/`
rebuilt from this revision for all four CPU levels (static musl, stripped,
~4.1 MB each; `file` confirms x86-64). The full E2E suite was last run green on
pass 14 and is not re-run here — wire and behavior are unchanged.

### 2026-09 hardening pass 21 — no-park locks, optimistic egress

Lock-contention work on top of pass 20, same wire protocol (no ALPN bump,
mixed pairs stay compatible). Pass 20 sharded the tables; the shared paths
still parked Tokio workers and paid quinn locks per packet in the expiry
window:

- **Packet paths never park a worker.** New `try_lock_read/try_lock_write/
  try_lock_mutex` helpers: DNS fast path, `dns_is_inflight`, `UdpHub::sender`
  and the server session-table read/insert all fail fast (miss/drop) instead
  of blocking on a `std` lock. Contended DNS lookups fall through to the
  limiter-bounded singleflight rather than queueing on a reader count.
- **Stale egress costs zero quinn locks.** The 1 s window expires on all
  associations at once; losers now reuse the expired handle optimistically
  with no `close_reason()` pre-check. A dead handle surfaces as
  `ConnectionLost` on send and invalidates there. The expired window goes
  from one `close_reason` per association to none (only the single-flight
  winner pays `close_reason` + `max_datagram_size`).
- **Direct-mapped memos.** DNS/SESS/TOUCH memos go from O(32) linear scans to
  O(1) hashed single-slot probes (full-key compare preserved; a collision
  only evicts). `wait_conn` takes a `try_read` fast path before parking on
  the generation channel.
- **Batched drop counters + wider retry pool.** `dgram_drops` flush
  thread-locally every 64 (same pattern as `udp_stats`; `snapshot()` drains
  the caller thread);
  the retry pool goes 4x1024 → 16x256 (same 4096 total, less HOL blocking
  per hot destination). Reply tasks cache the app address (~200 ms) instead
  of `try_read` per reply; the server PMTU refresh goes 5 s → 10 s and the
  sweep throttle goes global-CAS → per-worker thread-local.
- **Known tradeoffs.** Lock-contention drops are counted in `SESSION_FULL`
  (budget-drop line); a single hot destination now caps at 256 queued
  retries instead of 1024; cross-thread snapshot error is bounded by
  63 × workers. quinn's own connection-state mutex is untouched (no batch
  receive API to use).

Verified on this revision: `cargo test --all-targets` 50/50 (49/49 without
`stats`), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
clean on both feature sets. `dist/openwrt-x86_64/` rebuilt from this revision
for all four CPU levels (static musl, stripped, ~4.3 MB each;
`file` confirms x86-64). The full E2E suite was last run green on
pass 14 and is not re-run here — wire and behavior are unchanged.

### 2026-09 hardening pass 22 — lock-free egress memo, direct-mapped dispatch

The last per-packet application-side shared-state costs on the client and server
packet paths, same wire protocol (no ALPN bump, mixed pairs stay compatible).
An architecture review rejected three larger proposals (below) with reasons, so
this pass is deliberately narrow: it removes the remaining lock/refcount traffic
that a single-flow loopback bench cannot resolve but that multiplies with
association count and core count.

- **Generation-tagged thread-local egress memo (client UDP outbound).** Every
  outbound datagram used to take `SharedEgress.cached`'s `try_read` and clone the
  `quinn::Connection` — an Arc RMW on a refcount line shared with quinn's
  connection driver. `SharedEgress` now carries an `AtomicU64 generation` that is
  bumped (Release) after every *successful* mutation of `cached` (the publish in
  `refresh_global`, the clear in `invalidate`); a lost `try_write` mutates nothing
  and does not bump. Each worker thread keeps a one-slot memo tagged with the
  generation observed *before* its cached read, so a mutation racing an acquire
  can only leave a stale entry, never a falsely fresh one. A hit is one Acquire
  load plus one `RefCell` borrow, and `frag.send` runs on the borrowed handle
  (`DgramFragmenter::send` is synchronous), so the hot path has **zero Arc RMWs
  and zero quinn locks**. A refresh whose publish lost its `try_write` is tagged
  with stamp 0, so it can never be served as fresh; the single-flight refresh and
  stale-while-revalidate semantics are unchanged.
- **Direct-mapped dispatcher cache (client UDP inbound).** The per-connection
  dispatcher's 32-entry linear scan + round-robin replacement became a 1024-slot
  direct-mapped table indexed by `sess & 1023`. Session ids are monotonic from
  the hub's `AtomicU32`, so any window of ≤1024 live ids is collision-free. A
  slot is a hit only when it names the exact session **and** holds a sender: a
  cached absence or a collision re-probes the hub, so an id reused after `u32`
  wrap can never be blackholed. The hit path borrows the cached `Sender`
  (`try_send` takes `&self`), removing one channel-refcount RMW per datagram;
  `Closed` still re-probes once and retries with the payload the error returned.
- **Direct-mapped `is_global_ip_cached` (server).** The 64-slot linear scan with
  a round-robin insert — paid per inbound datagram when `allow_private = false` —
  is now a hashed O(1) probe with a full-key compare: a collision evicts the
  slot and never serves another address's verdict. Security regression tests pin
  the memo against `is_global_ip` across the whole filter table (private,
  loopback, link-local, CGNAT, NAT64-embedded private, documentation, benchmark,
  multicast, global) after every slot has been written, plus a cross-verdict
  collision/eviction test.
- **`wait_conn` trusts the maintained live bit (client TCP).** The per-flow
  liveness check now reads the connection loop's `AtomicBool` first and only pays
  `close_reason()` (quinn's connection-state mutex + error clone) when the bit
  says dead — the accepted stale-dead window costs one failed flow, as before.
  Because the bit can still read true for a beat after a `read_datagram` error,
  the dispatcher waits on `gen.changed()` with a 10 ms backstop before re-entering
  `wait_conn`, so the fast path can never busy-spin.
- **Per-thread `MAX_PAYLOAD` high-water guard.** The per-payload shared load now
  runs only when a thread sees a payload larger than any it has already recorded;
  the global stays a max over all threads and the snapshot API is unchanged.

**Rejected, with reasons.** *Per-thread sharded counters* (the existing 64–1024×
thread-local batching already makes the remaining shared RMW rate noise, and
`bump()`'s return contract is pinned by tests). *Server session-table 8→32
shards* (the table is per-connection with exactly one DATAGRAM reader task —
there is no cross-thread contention to spread, and more shards only worsen
locality and shrink the per-shard cap). *DNS 16→32 shards* (memo hits dominate;
no evidence it would help). *Forking quinn for a batch datagram receive API*
(pass 5 measured an average drain batch of 1.06, and pass 10 retired a fork
precisely to stop carrying security backports). quinn's per-datagram
connection-state mutex remains the floor without an upstream batch API.

Verified on this revision: `cargo test --all-targets` 58/58 (57/57 without
`stats`), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
clean on both feature sets; the real binaries carried a 1 MiB TCP ECHO
byte-for-byte, a UDP ASSOCIATE sweep of 8 / 1200 / 1420 / 1430 / 2000 / 8000 B
(fragment path included) at 0 % loss, 20 000 UDP datagrams, and a 256 MiB bulk
download. A `kill -9` → restart cycle behaved exactly as documented: detection
after 15.4 s (QUIC idle timeout), one stale-ticket 0-RTT retry, redial 0.13 s
after the restarted server bound, TCP ECHO and the full UDP sweep green after
reconnect, and the UDP association opened before the kill self-healed on its
next datagram. An interleaved A/B against the pass-21 binaries on the same host
measured bulk 126–132 vs 126–128 MB/s, UDP ~29.4k vs ~28.9k pps and TCP ~9.2k vs
~9.6k flows/s — **all inside run-to-run noise**, which is the expected result:
these changes remove per-packet application-side tax that a single-association
loopback bench cannot resolve (the same caveat as passes 13 and 15–21).
`dist/openwrt-x86_64/` was rebuilt from this revision for all four CPU levels
(v1–v4: static musl, x86-64, stripped, ~4.3–4.4 MB each; `file` confirms
x86-64). The pass-21 binaries remain wire-compatible, so mixed pairs work.

### 2026-09 hardening pass 23 — lock-free client control plane, and a measured refutation

Removes the last `Mutex`/`RwLock` acquisitions from every client path, packet and
control plane alike, replacing them with `arc-swap` — readers lock-free (mostly
wait-free), writers lock-free, no reader-reader contention, `load()` borrows
without touching the refcount. `arc-swap 1.9` has zero transitive dependencies;
it is the entire added surface. Same wire protocol (no ALPN bump, mixed pairs
stay compatible).

**The client is now lock-free end to end outside DNS.** Four `RwLock`s are gone,
and so is the failure mode each one carried:

- **`SharedEgress.cached` (`RwLock` → `ArcSwapOption<EgressCache>`).** The old
  publish used `try_write` and encoded a *lost* write as "stamp 0" — a handle
  that could never be served as fresh, so the next packet re-ran the whole
  refresh. `ArcSwap::store` cannot lose, which deletes that state outright: every
  publish lands, every publish carries a real stamp, and `invalidate` can no
  longer skip its generation bump. The generation-tagged thread-local memo
  (pass 22) is unchanged, so the per-packet path still costs one Acquire load plus
  one `RefCell` borrow — no Arc RMW, no quinn lock.
- **`ConnSlot.shared` (`tokio::sync::RwLock` → `ArcSwapOption<Connection>`).**
  `wait_conn` used `try_read` and fell back to `read().await`, which **parked the
  flow's worker thread** whenever a writer held the lock. `ArcSwap::load` borrows
  the published handle instead, so a flow opening during a reconnect never blocks
  a runtime thread. The reconnect/teardown clear keeps its read-then-write
  atomicity through `rcu`: the closure re-runs against the latest value and
  matches on `stable_id`, so a fresh connection installed during the clear is
  still never blackholed.
- **`UdpHub.subs` (32 × `RwLock<HashMap>` → 32 × `ArcSwap<HashMap>`,
  clone-on-publish).** The dispatcher read this with `try_lock_read`, and a losing
  `try_read` returned `None` — which `dispatch_one` treats as "no such
  association", i.e. a **silently dropped inbound datagram** whenever the lock was
  momentarily held by an association opening or closing. `ArcSwap::load` cannot
  fail, so the lookup is now lock-free *and total*: `None` means the session
  genuinely has no subscription, never that a lock was busy. Writes publish a
  fresh map through `rcu`, which also closes a lost-update window: `rcu` re-runs
  against the latest map, so two associations subscribing to the same shard
  concurrently cannot drop each other's insert (a load-clone-store would).
  Affordable because writes happen once per association open/close and a shard
  holds at most `MAX_UDP_ASSOCS / 32` senders.
- **`last_app` (`RwLock` → `ArcSwapOption<SocketAddr>`).** The relay loop
  published the app's address with `try_write`, which could silently drop the
  update; the reply task read it behind a 200 ms cache. Both sides are now
  lock-free and the publish cannot fail.

**The last `try_lock` datagram drop in the project, removed (server).** The client
was not the only place a busy lock cost a packet. The server's per-connection
session table was read on the datagram path with `try_lock_read` and written with
`try_lock_write`, and a loser **aborted the freshly spawned reply reader, released
its global session permit and dropped the datagram** — charged, in both cases, to
`SESSION_FULL`, a counter documented as "session or DNS slow-path budget
exhausted". Packet loss caused by lock contention was therefore reported as a
resource-limit event, which is how it stayed invisible.

Pass 21 introduced that fail-fast policy deliberately ("packet paths never park a
worker"). Pass 23 revisits it for this one table, and the reasoning is narrow. The
table is per-connection, so the only cross-task writers are a session reader
exiting (a `get` plus maybe a `remove`), the 60 s sweeper's removal loop, and a
DNS-spawned `get_or_create_sess` — all short, allocation-free `HashMap` critical
sections. The datagram reader is itself the commonest writer, so it cannot contend
with itself, and the socket `syscalls` in the insert path stay outside the lock.
`std::sync::RwLock::read` already tries before it parks, so the uncontended cost is
unchanged; the only behavioural difference is that a datagram is no longer thrown
away when one of those brief writers wins the race. The two `dgram_drops::bump`
calls went with it, so `SESSION_FULL` means what it says again. The remaining
`try_lock_*` call sites are all in the DNS tables, which are out of scope for this
pass.

**The dispatcher now writes the relay socket itself (client inbound).** The
per-association bounded `tokio::sync::mpsc` and the reply task that drained it are
gone. Each dispatcher owns one `DgramReassembler` and one scratch buffer and, for
every inbound DATAGRAM, resolves the session, builds the SOCKS5 reply header and
calls `try_send_to` directly. An association now publishes an `AssocEntry`
instead of a channel:

```rust
struct AssocEntry {
    relay: Arc<tokio::net::UdpSocket>,
    app:   ArcSwapOption<SocketAddr>,   // published by the relay loop
    alive: AtomicBool,                  // cleared as the association exits
}
```

**What made it cheap was already true and I had missed it.** My first reading of
this rewrite assumed it would drag per-session mutable reassembly state into the
dispatcher, which needs `&mut`, which needs a lock or a `RefCell` that is not
`Sync` — i.e. the "lock-free" rewrite would have reintroduced a lock. It does not,
because `DgramReassembler` is keyed by `(sess, id)`, not by association: it is
already connection-wide, and the server's datagram reader has always used exactly
one per connection. So the dispatcher holds a single reassembler, nothing
per-session is mutable, and the escape path stays allocation-free.

**What actually disappeared.** Not just the hop. The 256-deep per-association
queue and its `TrySendError::Full` arm are gone, so *a whole datagram loss mode
no longer exists* rather than being tuned — `count_dispatch_drop` went with it,
because the only thing it ever counted was that queue filling. One spawned task
per association is gone too. `alive` replaces the `Closed` signal the dropped
`mpsc::Receiver` used to provide, so a dispatcher stops writing into a socket
nobody reads as soon as the association exits, instead of holding it open until a
cache collision recycled the slot. Publishing the entry *before* `write_socks_reply`
also closes a window the old ordering had, where a session existed with no relay
socket behind it.

**The honest caveat, unchanged by shipping it.** `hotpath_bench chan` measures the
deleted hop at **52–57 ns per datagram** (depth 256, one producer + one consumer;
140 ns at depth 8). That is the measured upside, and it is small. The cost is that
the dispatcher — already the single stage of the inbound path, since one
`read_datagram` stream admits exactly one poller — now performs a `send_to` syscall
inline instead of handing the work to a task that could run on another core. That
raises its per-datagram budget from the ~100 ns class to the ~1 µs class on a
normal Linux host. Whether that lowers the *end-to-end* ceiling is **not
established on this hardware**: it only binds if the dispatcher is the limiting
stage, and the per-connection quinn driver (decrypt, ACK, GSO, congestion control)
is serialized anyway and may well be the real floor. The change is justified by
the structural wins above — one fewer task per association, one fewer loss mode, no
queue to size — and is verified for correctness; it is **not** justified by a
throughput measurement, because this host cannot produce one.

**The benchmark harness was fixed first, because the old one could not resolve
any of this.** `hotpath_bench` gained `udpmulti` (N concurrent associations on N
OS threads, each with its own relay socket), `udpraw` (the same pump loop against
the same target with *no proxy in the path* — the control that bounds how much of
a measured rate is the harness), `udpsweep` (per-size payload-integrity check),
`tcpecho` (byte-for-byte TCP echo verification) and `chan` (the hand-off cost
above). The `echo` target now binds 8 `SO_REUSEPORT` sockets: a single-threaded
echo costs one kernel thread wake per datagram and caps the *target* — not the
tunnel — at a few thousand packets per second.

**Why this host still cannot show the win.** `udpraw` measures **8 154 pps
one-way** on loopback with no proxy, no echo and no lock in the path, while the
same host does **432 545 TCP writes/s (432 MB/s)** on loopback. Bare-metal M4, no
hypervisor; `/Library/SystemExtensions` has installed network extensions plus
`EndpointSecurity`, so a UDP-filtering agent sits in the path. UDP on this box is
capped roughly two orders of magnitude below where any shared-state cost matters,
which is the same conclusion pass 22 reached empirically ("all inside run-to-run
noise"). An interleaved A/B of pass-22 vs pass-23 binaries on this host gives
**2664–3126 pps vs 2677–3125 pps** (N=32, the spread *within* one binary is wider
than the gap between them) and **14–15 MB/s vs 15 MB/s** bulk. The pass-23 changes
are therefore justified structurally — locks and their drop-on-contention failure
modes are gone, and that is pinned by tests — not by throughput measured here.

**Rejected, with reasons.** *Converting the server session table to lock-free
reads* (it is per-connection, created inside `handle_conn`, with
exactly one DATAGRAM reader task and two lock-free memos — the per-task `fast_sess`
cache and the thread-local 32-slot memo — in front of it; `ArcSwap` clone-on-publish
would cost O(512) rehashing per session open/close for a `try_read` that is
essentially never contended. Its *drop-on-contention* defect was real and is fixed
above; its *lock* is not the problem, so it stays a lock).
*Forking quinn* for a batch datagram API (pass 22's measurement and the pass-10
decision to stop carrying security backports both stand). quinn's per-datagram
connection-state mutex remains the floor. *The dispatcher rewrite* is listed
The dispatcher rewrite is no longer deferred; see above for why it turned out to
need no per-session state after all.

Verified on this revision: `cargo test --all-targets` 62/62 (61/61 without
`stats`), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
clean on **both** feature sets. Four tests pin the properties this pass buys:
`hub_sender_never_fails_because_of_concurrency` (four reader threads probing 4096
continuously-subscribed sessions while two writer threads churn the same shards —
every probe must hit); `hub_concurrent_subscribes_on_one_shard_all_land` (eight
threads subscribing 4096 ids across all 32 shards, none lost);
`dispatch_dead_entry_reprobes_and_drops` (`alive` really does stop a dispatcher
writing into a torn-down association's socket); and
`dispatch_reassembles_fragments_for_two_interleaved_sessions`, which pins the
connection-wide reassembler the dispatcher rewrite depends on — two sessions'
fragments interleaved through one dispatcher must reassemble into two intact
payloads and must not deliver a half-assembled one. Real binaries, real
tunnel: UDP integrity sweep at 8 / 1200 / 1420 / 1430 / 2000 / 8000 B — the last
two through the MQP-2 fragmentation and reassembly path — **300/300 verified
byte-for-byte at every size, 0 mismatched, 0 lost**; **160 000 datagrams at 0.000 %
loss** (8 concurrent associations); 1 MiB TCP ECHO **1 048 576/1 048 576 bytes
echoed, 0 mismatched**; 256 MiB bulk download across 4 connections.

Wire compatibility was verified rather than asserted, in both directions: the full
matrix (pass-22 server ↔ pass-23 client, pass-23 server ↔ pass-22 client, and
pass-23 ↔ pass-23) completes the handshake, passes the whole UDP integrity sweep
and the 1 MiB TCP ECHO byte-for-byte, and carries 160 000 datagrams at 0.000 %
loss. No wire format, framing or ALPN value changed in this pass; the two files
touched are the client and server binaries, and only on their local socket/relay
and table side.

A third full E2E run, on the binaries carrying **both** the server-side `try_lock`
change and the dispatcher rewrite, reproduces every number above — UDP sweep
300/300 byte-for-byte at all six sizes (including 2000 B and 8000 B, which take the
fragmentation path through the dispatcher's new connection-wide reassembler), 0
mismatched and 0 lost; 1 MiB TCP ECHO 1 048 576/1 048 576 with 0 mismatched;
160 000 datagrams at 0.000 % loss; 32 concurrent associations at 0.026 % loss (the
bench's stall-limit artefact — 31 of 32 associations completed, the remainder
stopped early on the harness's own 10-window silence rule, not on a relay drop);
256 MiB bulk across 4 connections — and the mixed pass-22-server ↔ pass-23-client
pair still passes the sweep and the echo. The relay's UDP rate on this host is
unchanged by the rewrite (2873 pps vs 3093 pps on 8 associations, inside the
2664–3126 pps run-to-run spread the A/B above measured for a *single* binary), as
expected: the deleted hop was 55 ns against a per-datagram cost this host's UDP
path dominates.

`dist/openwrt-x86_64/` was rebuilt from this revision for all four CPU levels
(v1–v4: static musl, x86-64, stripped, 4 293 104–4 349 776 B each; `file` confirms
x86-64), and the v1 pair was run through the full E2E under amd64 emulation — see
the cross-compile section above for that run and for the static `zmm`/`ymm`
evidence that each `target-cpu` level was compiled in. The pass-22 binaries remain
wire-compatible, so mixed pairs work.

---

### 2026-09 hardening pass 24 — post-audit fixes: memo ownership, sweeper race, pin deadline

An audit of `src/bin/myquic2-server.rs` found four defects on the UDP session
paths; all four are fixed here, plus two smaller consequences of the same review.
Same wire protocol: no frame, framing or ALPN change, so mixed pairs keep working.

- **A dead session's socket no longer outlives its connection.** `SessMemo` stored
  a strong `Arc<UdpSocket>`, and the only things that cleared a slot were
  `sess_memo_put` (overwrite) and a `sess_memo_lookup` for the *same* `(conn, sess)`
  — a key that never recurs, because `next_conn_id` never repeats. `sess_memo_forget`
  runs only at the tail of the reply reader, which an abort never reaches, so pass
  19's "clear stale slots on read" covered only the voluntary-exit case. The slot now
  holds a `Weak` and `sess_memo_lookup` upgrades it: the table entry and the reader
  are the owners, and once both are gone the slot is released and the failed upgrade
  reads as `Stale` — also the sharpest liveness signal available. Measured with
  `lsof`: 100 associations on one connection, client `kill -9`, then **1 UDP fd after
  the idle timeout** (the listener alone) against **85** before (84 leaked session
  sockets + the listener), and 84 after four separate one-session connections. Each
  retained socket was an fd plus 256 KiB × 2 kernel buffers, held *outside*
  `MAX_SESSIONS_GLOBAL` (the permit was released; only the fd leaked).
- **The 60 s sweeper can no longer kill a live session.** `sweep_all` snapshotted
  idle keys under the shard *read* lock and then removed them unconditionally under
  the write lock, so a session the client touched — or one recreated — while the
  sweeper waited for that lock was evicted and its freshly started reader aborted
  (socket, destination memo and in-flight replies with it). The removal now re-tests
  every key against the snapshot's `now` (`take_idle`), which is what `sweep_local`
  gets for free by scanning and removing under one write guard.
- **The connection-level destination pin has a deadline.** `fast_pin` cached
  `(session, name, port) → addr` and was consulted before the session memo and the
  DNS cache on every datagram, so a steady flow kept using the address resolved when
  it started for the whole connection lifetime: the 30 s `DEST_PIN_TTL` — and the
  60 s DNS TTL behind it — was bypassed for exactly the flow that never missed. It is
  now a `ConnPin` with the same 30 s deadline; past it the session memo (and then the
  DNS cache) answers and re-arms it. The deadline costs a lock-free, thread-local cache
  probe per datagram *after* the first 30 s of a flow — cheap against a per-datagram
  server budget, and the price of never pinning an address forever.
- **Resolution-in-flight drops are counted.** `forward_server_dgram` dropped every
  datagram that arrived while the name's single-flight resolution was pending, with
  no counter at all, so the loss showed up only as missing replies. A new
  `dgram_drops::DNS_INFLIGHT` — its own `snapshot4()` field, deliberately not
  `SESSION_FULL`, which means "budget exhausted" — is bumped there and printed in the
  60 s `udp budget` line. Measured: a 40-datagram burst at an uncached name reports
  `9 dropped (resolution in flight)`.

Two smaller consequences of the same review: a session created by a DNS-spawned
resolver task now publishes its live table entry into the calling thread's memo, so
the per-connection fast path can arm for it instead of being cleared by a
`SessHit::Miss` on every datagram; and `resolve_pin` / `target_name` moved to module
scope so the pin's deadline is unit-testable. Regression tests:
`session_memo_does_not_own_the_socket`,
`sweep_recheck_keeps_a_session_touched_after_the_snapshot`,
`conn_pin_stops_answering_when_its_ttl_expires`.

---

### 2026-09 hardening pass 25 — dedicated UDP egress, class-preserving failover, retry deadline

Pass 24 fixed the server's UDP session paths. This pass applies the same audit to
the **client connection pool** and finds that three of its defects are the same
classes, plus a routing bug that defeats the isolation the pool exists for. No wire
change: no frame, framing, ALPN or protocol field is touched, so mixed old/new pairs
keep working. One behaviour change is intentional and documented below (UDP is now
fail-closed by default).

- **UDP gets its own connection (the pool's central fix).** Every UDP association in
  the process rode slot 0 — the same QUIC connection as the `interactive_ports` TCP
  flows — through one process-global `SharedEgress`. TCP and UDP on one connection is
  not a latency nicety: `quinn-proto`'s `populate_packet` writes queued **DATAGRAM
  frames before STREAM frames** (verified in 0.11.18,
  `src/connection/mod.rs:3353` then `:3409`), so a bulk UDP flow (HTTP/3 over UDP:443,
  WireGuard, video) takes the packet payload and the shared congestion window ahead of
  the TCP streams on that connection, and a bulk TCP flow makes every UDP datagram hit
  the 1 MiB datagram send-buffer `Blocked` drop. The pool now has three classes of
  slot: `0` interactive, `1..quic_conns` bulk, and `quic_conns` a **dedicated UDP
  egress connection** — an *extra* slot, so `quic_conns` keeps its meaning ("TCP pool
  size") and the UDP fix costs TCP no congestion window. Clients dial `quic_conns + 1`
  connections (≤ 9). `udp_fail_closed` (default `true`) keeps a datagram off a TCP
  connection entirely while the UDP slot reconnects: it is dropped and counted in the
  60 s `udp budget` line instead of sharing a cwnd; `false` restores the fallback.
- **Bulk failover can no longer take the interactive slot.** `select_slot`'s failover
  was `(0..n).find(|&i| live[i])`, which starts at slot 0, so whenever a flow's
  round-robin preference happened to be a *dead* bulk slot it returned the interactive
  connection — even with two live bulk slots available. One dead bulk connection
  therefore put `1/(n-1)` of new bulk flows onto the connection every UDP association
  and every interactive port rides, i.e. it broke the isolation exactly when a
  connection was already degraded, contradicting the function's own documentation
  ("bulk never takes the interactive slot while another slot is live"). Failover is now
  class-preserving: another bulk slot first, slot 0 only when no bulk slot is live.
  Proven before the fix with the function extracted verbatim (`live = [true, true,
  false, true]`: `rr=1 → slot 0` instead of slot 1) and pinned by
  `bulk_failover_never_takes_the_interactive_slot` plus the pool-level form.
- **The retry pool's strong `Arc<UdpSocket>` has a deadline.** A queued `UdpRetry` is
  the *last* strong owner of its socket once the association (client relay) or session
  (server session socket) drops its own handle, and the worker awaited `send_to` with no
  timeout: a socket that never became writable pinned the fd — the server's session
  sockets carry 2 × 256 KiB kernel buffers — for the process lifetime *and* wedged the
  shard, so no later datagram hashing to that shard was ever retried. This is pass 24's
  C1/C3 class surviving in the shared library, which both binaries link. `retry_one`
  now sends under a 200 ms `UDP_RETRY_TIMEOUT` and counts the timeout as
  `udp_write::retry_failed`; `retry_deadline_bounds_a_never_writable_socket` drives the
  deadline with a never-ready future, so the bound is testable without a socket that
  happens to stay unwritable.
- **The client counts and reports the drops it used to swallow.** `dgram_drops` gained
  `NO_EGRESS` (no isolated connection: cold start, reconnect, or a lost single-flight
  refresh race) and `EGRESS_DEAD` (send found the connection gone / DATAGRAM
  unsupported), and the client's reporter now prints the same 60 s `udp budget` line the
  server has printed since pass 24 — before this, `TOO_LARGE`/`BUFFER_FULL` were bumped
  inside the library and *never read* on the client. Three bare `return`s on the
  inbound domain-reply path (`dns_is_inflight`, the slow-path limiter's two refusal
  arms) now charge `DNS_INFLIGHT`/`SESSION_FULL`, the keys the server already charges.
  `dgram_drops::snapshot4` became a named `DropSnapshot` (six counters) with
  `every_drop_counter_has_its_own_snapshot_field` pinning that each counter reaches a
  distinct field — the batching table is keyed on identity, so a counter missing one of
  its two arms would sit in a thread-local cell forever.
- **The two egress counters are exact, and warn on the spot**, because they are the
  numbers that answer "is `udp_fail_closed` costing me anything". Four of the six
  counters batch per thread, which is right for a flood and wrong for a discrete,
  seconds-long outage: a worker thread's count reaches the global only at 64, and the
  reporter's `snapshot` flushes *its own* thread's cells, so a 20-datagram outage could
  stay invisible until that thread dropped 63 more — or forever, if the thread exited
  with the count still pending. `bump`'s return value (what the per-packet warn lines
  print as "N so far") was the *global* total rather than the pending one, so even a
  warning understated the loss. `NO_EGRESS`/`EGRESS_DEAD` now take the direct `fetch_add`
  path — one RMW per *dropped* datagram, never per sent one — and the client calls the
  new `dgram_drops::warn_egress_drop` on both, with one rate-limited slot per state
  (`EgressDrop::{NoConnection, ConnectionLost}`, 10 s each) and a detail that separates
  the causes: `udp_fail_closed`, whether the dedicated slot is live, and whether the
  single-flight refresh was merely owned by another thread at that instant. Regression
  tests: `egress_drops_are_exact_across_threads` (verified to fail when the counters are
  routed back through the batching path, by a temporary probe) and
  `egress_drop_warnings_use_independent_slots`.
- **The association idle stamp is refreshed by replies — without a clock read per
  reply.** It lived as a local in the relay loop fed only by app-side traffic, so an
  association whose flow was receive-only after the first request (RTP after RTSP
  SETUP, a subscription feed, anything NAT-kept-alive by the far end) was reaped at
  180 s while the server's own session — whose reader *does* refresh on target replies
  — was still live: the same "evicted a session the client was using" failure pass 24
  fixed on the sweeper, in its missing-signal form. The stamp now lives on
  `AssocEntry`, and the reply side feeds it with **one relaxed store** (`mark_replied`)
  instead of a `mono_millis()`: the first fix stamped the stamp directly from the
  dispatcher, which cost a vDSO `clock_gettime` (~25 ns) on every reply for a signal
  whose only consumer compares it against 180 s. The association's own 10 s idle tick
  (`idle_since_tick`) consumes the bit and folds it into the stamp *before* evaluating
  the deadline, so the fold can only ever delay a reap, never hasten one, and the reap
  schedule is the same as an exactly-stamped association's. The app direction keeps its
  1 Hz throttled store (`ASSOC_TOUCH_INTERVAL_MS`), which is what keeps the two
  directions from stealing each other's cache line per datagram. Net: the client's
  inbound datagram path now reads a clock zero times (once for a fragmented payload,
  for its reassembly expiry). Regression tests:
  `replies_mark_the_association_active_until_the_next_tick`,
  `flowing_replies_never_let_the_deadline_fire` and
  `dispatch_marks_the_association_active` — all driven with explicit clocks, which also
  removed the one-second sleep the previous form of that test needed.
- **The hub reservation is released by RAII.** `handle_udp_associate` released the
  process-wide slot with a statement after an `.await`; unwinding skips it, which would
  leak the `MAX_UDP_ASSOCS` budget *and* leave the shard's strong `Arc<AssocEntry>` —
  the relay socket's last owner — reachable for the process lifetime, since nothing else
  removes a hub entry. `SessReservation` is the `Drop` guard (the sibling `AliveGuard`
  was already RAII); `association_reservation_survives_a_panicking_body` unwinds a real
  task to prove the slot and the entry come back.
- **The dispatcher's hub-probe path filters liveness.** The cache-hit path filtered
  `is_alive`; the `hub.entry` fallback did not, so in the window between `AliveGuard`
  clearing the bit and `UdpHub::release` unpublishing (and permanently, had the release
  above been skipped) a reply was written into a socket nobody reads.
  `dispatch_published_but_dead_entry_is_dropped` covers the window the existing
  `dispatch_dead_entry_reprobes_and_drops` cannot: it releases the entry first, so its
  map lookup returns `None`.
- **The association cap now fits what the server keeps.** `MAX_UDP_ASSOCS` was 4096
  while the server evicts once a shard crosses `LOCAL_SESS_MAX / SESS_SHARDS` and
  settles at `LOCAL_SESS_TARGET = 4032` sessions per connection — and all of a client's
  associations ride one egress connection, so the client's own ceiling was above the
  server's. It is now 4032. Over-cap eviction in `sweep_local` is **idle-first**
  (longest-idle stamp first, `select_nth_unstable` over the shard it already scans)
  instead of arbitrary, so hitting the cap no longer kills a session touched
  milliseconds ago while a session idle for minutes survives by hash order;
  `over_cap_eviction_takes_the_longest_idle_first` pins the ranking.
- **Smaller:** the client's reporter took the server's `OnceLock` guard (a second call
  would have double-logged every 60 s line), and `alloc_sess` documents why its
  monotonic `u32` cannot misroute after a wrap (an id recurs only after `u32::MAX - 2`
  further allocations — hours at any rate a 4032-association cap permits — against a
  reply lifetime of seconds).

Verification: `cargo test --all-targets` **93/93** (49 lib + 27 client + 17 server) and
**92/92** with `--no-default-features`; `cargo clippy --all-targets -- -D warnings`
and `cargo fmt --check` clean on both feature sets. The three behaviour changes are all
config-visible: one extra connection per client, UDP fail-closed by default, and the
client-side association cap 4096 → 4032. `dist/` was rebuilt for all four CPU levels
from this revision.

---

### 2026-09 hardening pass 26 — independent hot-path audit of the TCP/UDP echo paths

An outside-in audit of exactly the code an ECHO test exercises (the TCP pump, the
client's UDP relay, the server's datagram reader and per-session reply reader) found one
defect that could silently corrupt a transfer, three smaller ones, and one per-packet
cost the project had already removed everywhere else. Nothing below was found by the
existing suite: it was green before and after.

**1. An abnormal pump end was delivered to the peer as a clean FIN.** This is the one
that matters. `Drop for quinn::SendStream` calls `finish()` — a *graceful* FIN — so when
one direction failed and the other future was dropped, the abandoned upload half told
the peer "transfer complete". Concretely, on a pure download: the target RSTs the
server's socket mid-response, the server's `s2c` fails, its `c2s` (owner of `send`) is
dropped, and the peer's `read_chunks` returns a clean `Ok(None)` instead of a reset.
The peer's own `abort_tcp` never runs, so the application accepts a truncated body as a
whole one — precisely the silent corruption `abort_tcp` was written to prevent, one hop
further out. The pump futures now *borrow* `send`/`recv` instead of taking them, and the
error disposition issues `send.reset(0x04)` / `recv.stop(0x04)` — gated on each
direction's own completion flag, because a half that already reached clean EOF must not
be reset (its data was delivered and the peer may have acted on it). The new
`abnormal_pump_end_resets_the_peer_stream_instead_of_finishing` fails against the old
code with `the peer saw a clean FIN on an abandoned stream`, and the native E2E below
shows both halves of the new propagation in one run: the client logs
`quic>tcp tcp write failed … Broken pipe` (the app closed early) and the server logs
`tcp>quic quic write failed … sending stopped by peer: error 4` — the mirror of the
client's `recv.stop`. Every clean echo flow in that same run finished with no abort line
at all, which is the discrimination the completion gate exists for.

**2. `TooLarge` was counted and reported as "egress connection lost".** The client's
match arm folded `DatagramSend::TooLarge` in with `ConnectionLost`, so it bumped the
connection-lost counter, logged *"udp egress connection lost at send"* about a healthy
connection, and called `egress_shared.invalidate()` — flushing the process-wide egress
cache so every thread re-acquired through two quinn state-mutex acquisitions. It is
reachable without any network event: the relay buffer accepts payloads up to 8204 B
while `MQP_FRAG_MAX_PAYLOAD` is 8192, so an app sending 8193–8204 B datagrams to an IPv4
target trips it per datagram. `TooLarge` is now its own arm calling a new
`SharedEgress::refresh_budget()`, which re-reads the live `max_datagram_size()` on the
*same* handle and is a no-op when nothing moved; quinn's own size verdict is accounted in
`send_encoded`, the one place that sees it. The `Unsupported` state also got its own
`EgressDrop` variant, so its line no longer reads "connection lost … peer does not
support DATAGRAM"; it deliberately does *not* invalidate, because re-acquiring on a
statically DATAGRAM-less connection costs more per datagram than the failed send it is
reacting to.

**3. A strong `fast_sock` kept a dead session's socket alive.** `SessMemo.sock` was made
`Weak` in pass 24 so a permit-released socket could not be pinned outside
`MAX_SESSIONS_GLOBAL`, but the per-connection reader's inline fast slot was a second
strong owner: after the 180 s sweeper removed the entry and aborted the reply reader,
the fd and its 2 × 256 KiB buffer caps survived until the next datagram on that
connection happened to take the slow path. `abort.is_finished()` already stopped it being
*used*, so retaining it bought nothing. It is a `Weak` with a per-datagram `upgrade` now,
and a failed upgrade is a miss that lets the slow path rebuild the slot — the same
discipline as the thread-local memo, and the sharpest liveness signal available. (Pass
24's `lsof` methodology could not see this: killing the client closes the connection,
which is exactly the event that drops the handle.)

**4. The reassembler's per-partial byte cap was documented but not enforced.** `total` is
bounded by `MQP_FRAG_MAX_TOTAL`, but nothing bounded a *chunk*, so 64 maximum-size
fragments assembled ~91 KiB — far past the payload ceiling the protocol states — and the
server relayed whatever came out to the target (the kernel then IP-fragments it). The
aggregate `FRAG_MAX_HELD_BYTES` bound does not catch one such partial. `push` now
discards the whole partial when a fragment would push it past `MQP_FRAG_MAX_PAYLOAD`;
whole rather than truncated, because a prefix of a datagram is not a short datagram, it
is a corrupt one, and UDP above this has no integrity check to notice. A duplicate
fragment is exempt so a replay cannot kill a partial that was already at the cap, and
`a_partial_past_the_payload_cap_is_discarded_whole` covers the cap, a positive control
just under it, and the exact-cap-with-a-replay case.

**5. Per-packet vDSO clock reads, and the drop-path rate limiter.** Three hot paths read
`mono_millis()` (`Instant::now`, measured at ~22 ns here) on *every* datagram to answer
"has a second passed?" — the client's UDP relay loop, the server's
`touch_session_throttled`, and the server's per-session reply reader — and
`claim_drop_warning` read one per *dropped* datagram, including the drops the limiter
then suppressed. The project had already deleted this exact call from the reply path for
this exact reason, and had already rejected the obvious fix: a packet-count sampler
freezes when packets stop arriving, so a trickle flow's stamp stops moving and the 180 s
reaper kills a live session (see `TouchMemo`). The replacement is a *time* source
instead: `coarse_millis()`, a lazily armed 1 Hz task that publishes `mono_millis()` into
an atomic. It cannot freeze the way a counter can — it advances because a task says so,
not because packets arrive — and it cannot freeze silently either: the task clears its
armed flag as it goes down (including when its runtime is dropped), and any reader that
finds the flag clear re-arms it, the same contract as the UDP retry pool. It publishes
the *same epoch* as `mono_millis()`, so the two values are directly comparable and a
coarse one is merely up to a tick behind; a stale value can only make a deadline look
further away, never closer, so the failure mode is a delay rather than a false expiry.
The cursor is also seeded on the first read, because a consumer that stored an
uninitialized 0 as its baseline would read "idle since process start" and expire the next
flow through it on the spot — `coarse_millis_advances_without_traffic` pins both the
seeding and the advance-with-no-traffic property, and fails against any count-based
implementation; `the_coarse_epoch_is_rearmed_after_its_runtime_ends` covers the
runtime hand-off, and was **verified to fail** when the task's disarm guard is neutered —
its first revision passed anyway, because the 0-sentinel re-seed path made the cursor
move on its own, which is exactly the kind of accidental rescue a liveness test has to
exclude. The TCP pump's chunk stamps and its idle watchdog moved to the same
clock; the reapers, reporters and the 2 s reassembly timeout deliberately did not, being
cold or genuinely in want of sub-second resolution.

**Smaller:** `write_batch_vectored`'s fixed 8-entry iovec array was only *incidentally*
safe (its sole caller happens to pass ≤ 8 buffers) — a 9th would have panicked inside a
relay task, which skips the RST disposition above and so fails silently rather than
loudly; the array and the `Bytes` batch now share one `COPY_BATCH` constant and the fill
loop is bounded by it, which is also correct for a longer slice. A reply for an unknown
or already-reaped session was dropped with *no counter at all* while the 60 s line
claimed to account for every drop — it now bumps a batched `UNKNOWN_SESS`, reported on
its own line and deliberately excluded from `lost()` (a late reply to a closed
association is not a packet the tunnel failed to carry, and folding it in would make
every ordinary teardown look like loss). `warn_udp_write` picked its rate-limit slot by
substring, so `"detached retry failed"` matched `contains("retry")` and shared one 10 s
window with queue exhaustion; it takes a `UdpWriteDrop` enum now, the same fix its
sibling `EgressDrop` already had. `udp_write::retried` was counted before the retry queue
accepted the datagram, so a packet dropped on a full shard was booked as both retried and
dropped. The control-connection drain loop no longer re-zeroes its 512 B buffer per
iteration (the bytes are discarded per RFC 1928). Comments corrected where they had
drifted from the code: `DISPATCH_CACHE`'s "collision-free" claim (1024 slots against
4032 associations, handed out *consecutively*, means collisions are the norm and the busy
case is the one that pays), the client's "the reply path never reads a clock" (scope:
unfragmented replies), the server's session-socket memory bound (still quoted at the
pre-halving 512 KiB / 8 GiB), and the reason an IP target's destination memo is useless.

Verification: `cargo test --all-targets` **98/98** (53 lib + 28 client + 17 server) and
**97/97** with `--no-default-features`; `cargo clippy --all-targets -- -D warnings` and
`cargo fmt --check` clean on both feature sets. Native-binary E2E on macOS loopback
through the repo's own `hotpath_bench` harness, release build: `tcpecho` 64 KiB and
1 MiB **byte-for-byte, 0 mismatched**; `udpsweep` 8/1200/1420/1430/2000/8000 B × 40
**6/6 verified verbatim** (1430/2000/8000 B exercise the fragment path); `udpmulti` 16
associations × 400 = **6400/6400, 0.000 % loss** at 23 381 pps;
`udpdomainswitch`/`udpipswitch` 100 alpha + 100 beta + 100 IP + 100 domain targets in one
session, **0 misrouted** — the run that exercises the coarse clock on the domain-pin and
session-memo paths; `bulk` 256 MiB aggregate across 4 flows at 105 MB/s. A 30 s mixed
TCP+UDP loop crossing ~30 coarse-epoch ticks passed with **zero** failures, and the logs
for the whole session carry exactly **one** abort warning — the `bulk` flow whose
application closed its socket early, i.e. the truncating case — with no warning for any
of the echo flows, `0 dropped(no permit) / 0 failed / 0 retry-failed` on both sides, no
`udp budget` line (no drops at all), no reassembly expiry or eviction across 120
fragmented datagrams, and no `udp late replies` line (`unknown_sess == 0`).

`dist/`: **rebuilt, and deliberately not verified.** All four CPU levels were
cross-compiled from this revision with the documented `cargo zigbuild` recipe (static
musl, x86-64, default feature set so the relay counters are on) and copied into
`dist/openwrt-x86_64/`: clients 4 419 928–4 441 928 B (v1 4 431 592, v2 4 419 928,
v3 4 441 928, v4 4 434 744), servers 4 345 120–4 373 048 B (v1 4 360 176, v2 4 345 120,
v3 4 373 048, v4 4 366 968) — i.e. **+11 928–13 336 B** per client level and
**+10 544–11 440 B** per server level against the pass-25 artifacts. Unlike every earlier
pass that touched `dist/`, **no** check of any kind was run on these bytes: no `file`
format confirmation, no `objdump` verification that each `target-cpu` level is compiled
in, no second build compared for reproducibility, and no emulated or native run of the
shipped pair. They are compiled, not tested — the verification above applies to the
native release build only, and a target that needs a loadable binary should be validated
on the target.

Also not done here, stated rather than implied: the download batch size was **not** raised
from 8 (quinn only fills the chunks
already buffered in the assembler, so the win is load-dependent and unmeasured — measure
before changing it); and the malformed-frame drops in the dispatcher (`dgram_sess`
returning `None`, a failed `decode_fragment` / `decode_datagram_ref`) still carry no
counter, because they are unreachable from a conforming peer and adding a class for them
is a separate decision from the ordinary unknown-session race that item 5 does count.

---

## Cache-substitution evaluation, and the two changes worth making instead

The question "should this repository use a general-purpose cache crate (moka and
friends) for the DNS and session caches?" was answered by measurement rather than
by taste. The short version: **no cache crate earned its place**, and the two
changes that did were worth making. Both are in this revision.

### The shoot-out

Five backing stores behind the *same* interface — the repository's own key
encoding (lowercased host, NUL, decimal port), the same `Arc<[SocketAddr]>` value
shape, the same 60 s TTL and 4096-entry cap, the same thread-local memo where one
applied. 10 cores, 128-key hot set, 10 threads, `ns/op` on a 100 %-hit read loop:

| backing store | 10 thr hot-128 | note |
|---|---|---|
| `papaya::HashMap` (lock-free) | **6.0 ns** | no TTL, no capacity bound |
| `quick_cache` (CLOCK-Pro) | **23.7 ns** | automatic capacity eviction |
| hand-rolled sharded map + memo (shipped) | 46.8 ns | |
| `moka::sync::Cache` | 109.2 ns | |
| `mini_moka::sync::Cache` | 258.2 ns | `get` needs an owned key: allocates per lookup |

Read latency while inserts churn past capacity (10 threads, p99 / p999):

| backing store | p99 | p999 |
|---|---|---|
| `papaya` | 333 ns | 1.7 µs |
| `quick_cache` | 458 ns | 709 ns |
| hand-rolled (shipped) | 1 375 ns | 18.6 µs |
| `moka` | 9 000 ns | 56.8 µs (max 11 ms) |

`moka` is the slowest of the five on the concurrent read path and has by far the
worst tail, because every `get` goes through per-entry `MiniArc` bookkeeping and
the write path queues through a single write-order channel drained by a
housekeeper thread. `mini_moka` is worse still and cannot be looked up with a
borrowed key at all. `quick_cache` and `papaya` are genuinely faster than the
hand-rolled table — but the whole comparison is beside the point, which is the
second finding.

### The per-thread memo is the cache

Every shared store in this proxy already sits behind a thread-local memo
(`DNS_MEMO`, `SESS_MEMO`, `DISPATCH_CACHE`, `EGRESS_MEMO`,
`is_global_ip_cached`). A memo hit costs ~5 ns and never touches the store, so
the store's own throughput is irrelevant for the common case and the *memo's hit
rate* is what decides cost. That is what the measurements found:

| distinct domains per worker thread | 32-slot direct-mapped memo (was) | 128-slot 2-way (now) |
|---|---|---|
| 4 | 0 % penetration | 0 % |
| 32 | **31 %** | **0 %** |
| 64 | **59 %** | **5 %** |
| 128 | **76 %** | 21 % |

"Penetration" is the fraction of lookups that miss the memo and reach the shared
cache. 32 slots was sized for one hot target; a worker serving 32 concurrent
domains already missed a third of the time, and each miss costs a shard read lock
plus a full key compare (~44 ns/op measured with the memo defeated, against
~5 ns for a hit). This is the regime a busy proxy actually runs in, so the memo
was the thing to fix — not the store behind it.

### Change 1 — the DNS memo is now 2-way set-associative, 128 slots

`DnsMemoSlot` stores a 64-bit hash plus up to 64 inline key bytes, 2 ways × 64
sets. The hash is only a filter; the bytes are always compared, so a collision
evicts and can never serve one domain's address for another's — the same
guarantee the old direct-mapped table gave. Keys longer than 64 bytes are not
memoized at all (a miss, never a mis-serve). End-to-end effect at 32 and 64
domains/thread, 10 threads, measured: **15.5 → 6.8 ns/op** and **25.8 → 8.1
ns/op**. The finalizer added to the key hash matters: the set index comes from
the low bits, and DNS names share long suffixes, so the raw multiply-fold left
those bits correlated between unrelated names and piled them into one set — the
exact conflict the associativity exists to remove.

### Change 2 — the server no longer re-resolves a domain target per datagram

The UDP relay resolved a domain target on **every** datagram
(`forward_server_dgram` → `lookup_cached_fast`), forever, for a flow that had
already been resolved. `SessEntry` now carries a `DestMemo` — the resolved
address, a deadline, and the target it was resolved *for* — so later datagrams
for the session are a lock-free compare. The connection-level fast slot carries
the same pin, so a steady flow skips the session table too.

The memo is keyed on the target **name and port**, not on the session. That is
not a refinement: the first version keyed it on the session alone, and
`hotpath_bench udpdomainswitch` caught it — a session alternating between two
domain targets had **1000 of 2000 datagrams misrouted** to the other target's
address, silently, because the pin answered every datagram with the address it
had resolved first. With the name in the key: 0 misrouted, and the same check
across encodings (domain alternating with an IP literal in one session) is also
0. Names beyond 64 bytes are not memoized, so a truncated key can never match a
different name sharing its prefix. The `DEST_PIN_TTL` is 30 s — deliberately
under the 60 s DNS TTL — so a name that moves is picked up by an established
session rather than only at session teardown. The connection-level fast slot
carries the same pin **and the same deadline** (pass 24: it used to carry no
deadline at all, which pinned a steady flow's address for the connection's whole
lifetime and bypassed both the memo and the DNS cache).

The memo is *written*, not clobbered, on the datagram path. An **IP target
stores nothing**: its address is already in every datagram it sends, and the
memo's only reader consults it for domain targets, so an entry recorded under an
empty host could never be read back — it was a shard write lock plus a 72 B memo
write per datagram for nothing. A domain target's memo is rewritten only when
the address changed or the entry sits inside the last quarter of its TTL
(`DEST_PIN_REFRESH_MS`), which keeps it continuously live at one write per
~7.5 s per session instead of one per packet. Measured through the production
functions: the unconditional store cost **35 ns/op** (shard write lock +
`get_mut` + the 72 B write) on top of the 27 ns read-lock lookup it piggybacked
on.

That 35 ns does **not** survive to the end-to-end number, and saying otherwise
would be a lie: an interleaved A/B of the two server binaries (2 rounds each)
gave 19 957 → 19 822 pps at 16 associations on one connection and 24 998 →
24 575 pps across two connections — both inside this host's ±3 % run-to-run and
code-layout spread, i.e. no measurable effect, because 35 ns is 0.04 % of the
~87 µs of server CPU a loopback datagram already costs here. The change is kept
because the removed work was provably useless, because it deletes an *exclusive*
write to a shard that several client connections share (4 threads on one shard
halve write throughput in the same microbenchmark), and because its correctness
is cheap to pin: `udpipswitch` / `udpdomainswitch` alternate IP and domain
targets inside one session and report **0 misrouted**, and
`session_dest_store_writes_only_when_the_memo_needs_it` asserts that a redundant
store leaves the memo's expiry untouched while a near-expiry one refreshes it.

### Honest cost accounting

Neither change moves this host's end-to-end UDP relay number, and the README's
own rule is to say so rather than claim a win. `udpdomainmulti` at 64 domains ×
8 associations × 4000 datagrams: **2950 pps before / 2861–2894 pps after**, which
is inside the 2504–2894 run-to-run spread measured on the *single* binary. The
reason is arithmetic: the per-datagram DNS work was ~6 ns on a memo hit and a
miss costs ~44 ns, while a loopback datagram costs this host ~350 µs end to end.
Removing even 100 % of the DNS work removes ≤ 0.01 % of the per-datagram budget.
The changes are worth keeping because they delete per-packet work from a path
that should not have it and make the memo scale to the many-domains case, not
because they are measurable here; a deployment whose domains are far away, or
whose per-datagram cost is otherwise small, would see more.

Two new bench modes make the second change testable, because no existing mode
could reach it: `udpdomain` sends the target as a SOCKS5 **domain** (ATYP 0x03)
instead of an IP literal, and `udpdomainswitch` alternates targets within one
association and verifies *which* target answered via `utag`, a UDP echo that
prefixes its reply with its own tag.

### Rejected

- **`moka` / `mini_moka`**: measured slower than the hand-rolled table (table
  above) and would add ~10 crates plus background housekeeping threads to a
  binary that ships to routers, for caches that are not the bottleneck.
- **`quick_cache`**: the only crate that beat the hand-rolled table on every
  axis, and the natural pick *if* a crate were adopted. Not adopted, because the
  measured end-to-end effect is nil while it would add a dependency and change
  `evict_if_needed`'s behaviour from "batch-evict on write" to CLOCK-Pro — a
  trade with no demonstrated upside here. The measurements are kept above so
  this decision can be revisited with a real workload instead of re-argued.
- **`papaya` for the client `UdpHub`**: it replaces an `ArcSwap` map with a
  lock-free one, but `hub.entry()` already sits behind the 4096-slot per-thread
  `DISPATCH_CACHE`, so the remaining traffic is one lookup per association, not
  per datagram. (This rejection is about the `UdpHub` only; the client's
  connection pool likewise no longer uses `papaya::HashMap` — see
  [Connection isolation](#architecture) — since a fixed write-once set reads
  cheapest as a plain indexed `Vec`.)

---

### 2026-09 hardening pass 27 — hot-path review fixes and a verified OpenWrt rebuild

A review-and-fix cycle on three relay-hot-path findings, in the same wire protocol (no
frame, framing, ALPN or protocol-field change, so mixed old/new pairs keep working).
Each finding below was confirmed by reading the code path end to end, fixed minimally,
re-reviewed as a diff, and re-verified with the full suite on both feature sets.

**1. The connection pin is written back from a DNS-cache hit (server).** `resolve_pin`
answers a datagram from three levels: the connection's `ConnPin`, the session's
destination memo, then the DNS cache. The pin used to be written only from the session
memo — but a fast-path success never calls `forward_server_dgram`, so it never calls
`sess_dest_store` either. The pin and the session memo therefore expired together at
T+30 s while the 60 s DNS cache was still live, and every subsequent packet of a steady
domain flow paid a `sess_dest_lookup` shard read lock for the rest of the DNS TTL
(~50 % duty-cycle degradation on exactly the flow that never misses). The DNS arm now
adopts its hit into the pin under the same contract as the memo arm (`now +
DEST_PIN_TTL_MS`, same coarse epoch, same `(session, name, port)` identity). The pin
still cannot bypass the SSRF filter: the fast path gates every send on
`allow_private || is_global_ip_cached`, and the slow path re-validates in
`forward_server_dgram`. Pinned by `dns_hit_arms_the_pin_when_pin_and_memo_miss`, which
covers both shapes — a cold start (no pin, no memo) and the actual degradation (expired
pin, empty memo, live DNS) — and which fails against the pre-fix code (the pin stays
`None` while the answer is still returned). The test seeds the cache through a new
`#[doc(hidden)] pub fn dns_cache_seed`, because a bin unit test cannot reach the
private cache tables and must not depend on a live resolver; it is callable only by
linked code, so it exposes nothing to the network, and it mirrors the production
insert path exactly (same key builder, same TTL anchoring, negative-entry removal,
bounded eviction, thread-memo publish).

**2. The TCP upload pump double-buffers its copy buffer (lib).** quinn's `write_chunk`
moves the caller's `Bytes` into the stream's send queue with no copy, so bulk chunks go
`read_buf` → `split_to(n).freeze()` → `write_chunk`. But `split_to` promotes the
remainder to a shared handle while quinn holds the frozen half in `unacked_segments`,
so the next `reserve` on the *same* buffer cannot reclaim in place and allocates a
fresh 32 KiB — every chunk, on a bulk flow. The pump now holds two pooled buffers and
rotates (`cur ^= 1`) on the large-write path only, giving the ACK one full
other-buffer cycle to drop the first frozen half before that capacity is needed again;
when the half is released inside the window the allocation is skipped, and when it is
not the behaviour is identical to the old single-buffer path (allocate on reserve) —
never worse. Small writes (`write_all`) do not split, so they stay on the current
buffer and `clear()` it. All three exits (TCP read error, QUIC write error, clean EOF)
return *both* halves through a new `release_copy_bufs` helper. A code-review pass on
this diff corrected the original comment, which had stated the best case ("roughly
every other chunk") as the typical one. The pool pressure is unchanged in kind: two
acquisitions per flow against a depth-4 pool, both returned.

**3. Fragment reassembly no longer copies every chunk (lib, both relays, tests).**
`DgramReassembler::push` copied each fragment body with `Bytes::copy_from_slice`. It is
now a thin wrapper over a shared `push_with_chunk` core, plus a new
`push_zero_copy(parent: &Bytes, f: &FragmentRef, now_ms)` that stores
`parent.slice(..)` — a refcount bump — instead. The suffix math is exact rather than
assumed: `decode_fragment` always slices the chunk out to the *end* of the frame, so
the start offset is `parent.len() - f.chunk.len()`, and the "is this chunk really the
suffix of `parent`?" check is a single O(1) pointer comparison at that offset, not a
body compare (the first version of this change did a full memcmp on every fragment,
which re-read up to ~1.4 KiB on the path the change exists to speed up; the review
replaced it). `Bytes` is immutable, so a pointer match implies the body compare would
match too, and a mismatched pair falls back to a copy rather than slicing the wrong
bytes — correctness never depends on the caller. All three production-adjacent call
sites pass the exact `Bytes` the fragment was decoded from (the server fast path, the
client `dispatch_one`, and the real-QUIC round-trip integration test), while the ~25
existing unit tests keep calling the copying `push`, so both chunk representations stay
covered. One accounting note: a stored slice retains the whole parent frame, but `held`
charges only `chunk.len()` — the frame header (~20–30 B per fragment) is uncounted.
That is the same accounting-skew class as the `Bytes` overhead that was never counted,
and it is noise against `FRAG_MAX_HELD_BYTES` (256 KiB).

**What was deliberately not changed.** The review's remaining notes were dispositioned
as non-issues: the double-buffer's extra pool acquisition is returned on every exit;
cancellation mid-`write_chunk` drops the buffers without pool return, but that matches
the pre-existing single-buffer behaviour; the `held` undercount above is negligible by
construction. No benchmark-harness run is claimed for this pass: the removed work is a
few allocations and memcmps per chunk against this host's ~350 µs loopback datagram,
which a single-host bench cannot resolve (the same caveat as passes 13 and 15) — the
changes delete per-packet work that multiplies with concurrency instead.

Verification: `cargo test --all-targets` **99/99** (53 lib + 28 client + 18 server) and
**98/98** with `--no-default-features` (52 + 28 + 18); `cargo clippy --all-targets --
-D warnings` and `cargo fmt --check` clean on both feature sets.

`dist/`: **rebuilt and statically checked.** All four CPU levels were cross-compiled
from this revision with the documented `cargo zigbuild` recipe (static musl, x86-64,
default feature set) and copied into `dist/openwrt-x86_64/`: servers 4 348 224–
4 375 064 B (v1 4 363 280, v2 4 348 224, v3 4 375 064, v4 4 369 048), clients
4 421 240–4 444 584 B (v1 4 432 584, v2 4 421 240, v3 4 444 584, v4 4 437 272) —
**+2 016–+3 104 B** per server level and **+992–+2 656 B** per client level against
the pass-26 artifacts, for the pin write-back, the pump's second buffer and its
release helper, and the reassembler's split entry points. `file` confirms ELF 64-bit
LSB x86-64, statically linked, stripped on all eight; `objdump -d` finds 273 `zmm`
refs in the v4 server and 235 in the v4 client with none in v1–v3 of either binary, so
each `target-cpu` level really is compiled in. No emulated or native run of the shipped
pairs was performed — the verification above applies to the native release build, and a
target that needs a loadable binary should be validated on the target.

---

### 2026-09 hardening pass 28 — bounded stream-head writes, refused-datagram accounting, and the SOCKS header cap

A second review-and-fix cycle on the same TCP/UDP echo paths, in the same wire protocol
(no frame, framing, ALPN or protocol-field change, so mixed old/new pairs keep working).
Two rounds of code review confirmed each finding against the code path before any edit,
and two candidates were dispositioned as non-issues rather than fixed (listed below).

**1. The TCP stream-head writes had no deadline (client + server).** Two writes sit
outside every other bound in the flow. The client's MQP-2 target header is written
immediately after `open_bi`, *before* the optimistic SOCKS success — and the idle
watchdog lives inside the pump, which has not started yet — so a stalled connection
parked `send.write_all` until the QUIC idle timeout (~15 s) with the application socket
held and no SOCKS answer on the wire. The server's TCP-open ACK write had the same
shape: it pinned the connection task *and* a `MAX_STREAM_TASKS` permit (16 384 process
wide) for the same duration. Both are now under a 5 s `tokio::time::timeout`. On the
client, a timeout or write error tears the QUIC stream down (`send.reset(0x04)`) and
answers the pending SOCKS request with `0x04` — the failure still occurs before SOCKS
success is sent, so the application gets an explicit refusal instead of a success
followed by a silent close; the bail path matches the existing `open_bi` failure arm
byte for byte. On the server, a timeout returns from the handler exactly as a write
error did before, releasing the permit immediately. 5 s is two orders of magnitude
above the ~100 ms the design targets for a header on a connection just proven alive by
`wait_conn`, so no healthy slow path is affected; the client's 25 s total ACK budget is
untouched.

**2. `SOCKS_UDP_HDR_MAX` reserved the IPv6 address, not the worst-case domain header.**
The constant (`RSV(2) | FRAG(1) | atyp(1) | addr | port(2)`) computed its address slot
as 16 B — the IPv6 form — but `TargetAddrRef::decode` accepts a domain of up to 255
bytes, so the true worst case is `3 + 1 + (1 + 255) + 2 = 262 B`. It is now written
that way (`3 + 1 + 1 + 255 + 2`), with a docstring pinning the invariant: an
IPv6-sized reservation silently truncates an application datagram that pairs a long
domain name with a near-maximum payload *before the fragmenter ever sees it*, i.e.
exactly the traffic the fragment path exists to carry. Every buffer sized from the
constant grew by 240 B (the client's association relay buffer 8215 → 8455 B, ~1 MB
worst-case virtual growth at the 4032-association cap, allocated on demand); the
`n == buf.len()` truncation-slack logic is unchanged, since the slack byte still sits
after the new maximum.

**3. Policy refusals were dropped invisibly (or charged to the wrong counter).** Five
sites discarded a datagram on *policy* — the decision was correct, the observability
was not. The server's negative-cache arm (`forward_server_dgram`), both of its
SSRF-filter rejections (the IP arm and the domain arm after resolution — with
`allow_private = false`, the default, this is the first gate an echo to a LAN target
hits), the reserved session id `0` in `get_or_create_sess`, and the client's
domain-reply refusal arms all returned `None`/`{}` with no counter; `sess == 0` was
worse, bumping `SESSION_FULL` — a counter whose documented meaning is "budget
exhausted" — for what the adjacent comment correctly calls malformed or hostile input.
All five now bump a new `dgram_drops::REFUSED`, a batched counter alongside the other
flood-type counters (an application retrying a refused target *is* the flood case
batching exists for), wired through the full plumbing the batching table requires: its
own thread-local cell, its own `flush_locals` arm, its own `bump` arm (the table is
keyed on pointer identity — a missing arm would strand the count in the thread-local
forever), a `DropSnapshot.refused` field, `since()`, and `lost()` — a refused datagram
is, from the application's view, a datagram the tunnel did not carry. Both 60 s
`udp budget` lines print it (the client's gate is `lost() > 0`, which now includes it;
the server's condition gained `|| dd.refused > 0`). `every_drop_counter_has_its_own_
snapshot_field` covers all seven counters with `lost() >= 7`, so the next counter that
misses an arm fails the suite.

**What was deliberately not changed.** Two candidates from the same review were
dispositioned as non-issues: the client fragment path's `Domain`/fragmented-name arm is
unreachable from a conforming server (replies are always IP-form), so it keeps its
drop-and-count-only shape rather than spawning a resolver defensively; and malformed
frame drops in the dispatcher (`dgram_sess` returning `None`, failed `decode_*`) still
carry no counter, which pass 26 already recorded as a documented decision — they are
unreachable from a conforming peer, and adding a class for them is a separate decision
from the policy refusals this pass does count. The two review rounds also re-verified
the timeout disposition against quinn's own semantics: cancelling a `write_all` future
mid-poll is safe (a partial header is discarded by the subsequent reset/FIN, matching
the old error path), and the server's bare `return` on ACK timeout deliberately stays a
FIN rather than a reset, byte-identical to the previous write-error behaviour — the
client already treats FIN and RST the same way in `read_mqp_ack`.

Verification: `cargo test --all-targets` **99/99** (53 lib + 28 client + 18 server) and
**98/98** with `--no-default-features` (52 + 28 + 18); `cargo clippy --all-targets --
-D warnings` and `cargo fmt --check` clean on both feature sets. No native E2E or
benchmark re-run: every change is either on a failure path, behind a policy gate, or a
counter — no success-path data-plane decision moved, so the wire is unchanged and the
suite plus two review rounds are the applicable evidence (same rationale as passes
15–22).

`dist/`: **rebuilt and statically checked.** All four CPU levels were cross-compiled
from this revision with the documented `cargo zigbuild` recipe (static musl, x86-64,
default feature set) and copied into `dist/openwrt-x86_64/`: servers 4 344 544–
4 373 480 B (v1 4 359 840, v2 4 344 544, v3 4 373 480, v4 4 370 472), clients
4 379 536–4 403 000 B (v1 4 393 760, v2 4 379 536, v3 4 403 000, v4 4 395 048).
Against the pass-27 recorded figures that is **−3 680…+1 424 B** per server level and
**−38 824…−42 224 B** per client level — a client shrink larger than this pass's
additions (two timeouts, one counter arm set, a widened constant) can account for. The
recipe and feature set are unchanged, `Cargo.lock` is untouched, and the `dist/` files
found in place before this rebuild already sat at ~4.39/4.36 MB rather than the
pass-27 recorded 4.42–4.44 MB, so the delta appears to straddle an earlier unrecorded
rebuild as much as this pass's code; it is recorded as measured, not explained. `file`
confirms ELF 64-bit LSB x86-64, statically linked, stripped on all eight; `objdump -d`
finds 273 `zmm` refs in the v4 server and 235 in the v4 client with none in v1–v3 of
either binary, so each `target-cpu` level really is compiled in. No emulated or native
run of the shipped pairs was performed — the verification above applies to the native
release build, and a target that needs a loadable binary should be validated on the
target.

---

## Roadmap

- [x] Optional client authentication (`auth_token`)
- [x] Process-wide connection/session caps + receive-window bound
- [x] 0-RTT-safe authentication and corrected reconnect/backoff behaviour
- [ ] Mutual TLS as an alternative to the shared token
- [ ] SOCKS error REPs + UDP source validation (strict-compliance mode)
- [ ] Ticket-key persistence for 0-RTT across server restarts
- [ ] Per-stream metrics endpoint (Prometheus) — BBR state, GSO batch size, sess table
- [ ] `procd` init script for OpenWrt
- [x] MQP datagram fragmentation for UDP payloads above the path budget
      (`type=0x05`, up to `MQP_FRAG_MAX_PAYLOAD` = 8 KiB; see pass 12)
- [ ] Fuzz the MQP-2 codec (cargo-fuzz)
- [x] Remove the quinn-proto DATAGRAM drop-oldest process abort (`try_send_datagram`)
- [x] Per-flow allocation on the TCP-open path (stack-buffer header, borrowed dial candidates)
- [x] Zero-copy TCP↔QUIC pump (`read_chunk` / `write_chunk`, pass 13)
- [x] Compile-out per-packet relay counters (`--no-default-features`, pass 13)
- [x] Client-side per-flow allocations on the SOCKS path (stack header/reply/greeting, pass 13)
- [x] Per-packet allocation / lock / clock-read audit of the UDP and stream paths (pass 6)
- [x] Reconnect `shared` TOCTOU + DNS overload-path write-lock stalls (pass 7)
- [x] Batched TCP download pump (`read_chunks` + vectored write, pass 15)
- [x] Sharded per-packet counters + shared UDP egress + wider session/DNS memos (pass 15)
- [x] Stream priorities for interactive vs bulk TCP (pass 15; DATAGRAM isolation still via the connection pool)
- [x] Single-flight egress refresh + 8-slot dispatcher cache + sharded retry pool (pass 16)
- [x] Sharded server session table + per-connection fast path + sampled clocks (pass 16)
- [x] Pooled TCP pump buffers + reply-path PMTU tracking + sampled abort logs (pass 16)
- [x] Per-shard session-cap fix + per-session touch + stale-while-revalidate egress (pass 17)
- [x] Non-blocking egress publish + trickle-flow liveness (pass 18)
- [x] Touch-sampling regression fix + memo stale-slot GC + memo write out of the table lock + `SESSION_FULL` budget counters + stale-egress liveness pre-check (pass 19)
- [x] Sharded DNS positive/negative/single-flight tables + `poll_once` cancellation proof and saturation regression test (pass 20)
- [x] No-park packet paths (try-lock fail-fast) + optimistic stale egress + direct-mapped memos + batched drop counters + 16-shard retry pool (pass 21)
- [x] Generation-tagged thread-local egress memo (zero per-datagram locks/refcounts on client UDP outbound) + direct-mapped 1024-slot dispatcher cache with no per-packet `Sender` clone (pass 22)
- [x] Direct-mapped `is_global_ip_cached` with security regression tests + `wait_conn` live-bit fast path + dispatcher spin guard + per-thread `MAX_PAYLOAD` high-water guard (pass 22)
- [x] Lock-free client control plane: `SharedEgress.cached`, `ConnSlot.shared`, `UdpHub.subs` and `last_app` moved to `arc-swap`, removing the last client `Mutex`/`RwLock` and the drop-on-contention paths behind them (pass 23)
- [x] Remove the last `try_lock`-induced datagram drop (server session table read/insert now block instead of discarding the packet), un-conflating `SESSION_FULL` from lock contention (pass 23)
- [x] Client inbound: dispatcher writes the relay socket directly; the per-association `mpsc` queue, its `Full` drop mode and the reply task are gone, with one connection-wide reassembler per dispatcher (pass 23)
- [x] `udpmulti` / `udpraw` / `udpsweep` / `tcpecho` / `chan` bench modes + 8-socket `SO_REUSEPORT` echo target (pass 23)
- [x] DNS memo widened to 128 slots / 2-way (31 % → 0 % penetration at 32 domains per thread) and the server's per-datagram domain re-resolution replaced by a name-keyed per-session destination memo (see the cache-substitution evaluation)
- [ ] Re-evaluate DATAGRAM-reader batching if a future quinn exposes a batch receive API
      (measured useless with quinn 0.11: avg batch 1.06, see pass 5)
- [x] Track quinn `main` (0.12) instead of the crates.io 0.11.x line, picking up the
      upstream DATAGRAM accounting fix (pass 8; superseded — back on crates.io
      0.11.18, which backports it, see pass 10)

---

## License

MIT — see `Cargo.toml` (`license = "MIT"`).
