//! Inbound DATAGRAM dispatcher.
use super::*;
use futures_util::future::FutureExt as _;
use myquic2::mqp::ctl_stream::{self, CtlRate};
use myquic2::mqp::r2;
use myquic2::mqp::r2_flow::{FlowBinding, RegistryError};
use myquic2::mqp::r3::CtlMessage;
use myquic2::mqp::wire::{self, FrameKind, Wire};
use myquic2::udp::{R2Assembled, R2Reassembler};

/// Direct-mapped dispatcher cache, one slot per session id modulo the table
/// size. A collision only means the slot is re-probed, never that a packet is
/// misrouted (the slot validates the exact id *and* the entry's liveness).
///
/// **Collisions are expected, not exceptional.** Session ids come from the
/// hub's monotonic `AtomicU32` and are never reused while live, but releases
/// leave gaps, so the live set is a subset — not a window — of the counter
/// range: under churn two live ids `DISPATCH_CACHE` apart collide, and more
/// than `DISPATCH_CACHE` live associations collide by pigeonhole. Sized at 4096
/// (`MAX_UDP_ASSOCS` 4032 rounded up to a power of two) so a full house averages
/// one id per slot instead of four: round-robin hit rate goes from ~2% to ~37%
/// under churn, 100% for a fresh consecutive window. Costs ~192 KiB per
/// dispatcher: `DispatchSlot` is a `u32`, an `Option<Weak>` and the pinned
/// `Option<SocketAddr>` app address — about 48 B with padding, x 4096. (The
/// table is sized for the default cap; a lowered `max_udp_assocs` only leaves
/// it over-sized, never under.) Still noise against the ~256 KiB of kernel
/// socket caps each live association already carries.
/// Must be a power of two (the index is a mask).
pub(crate) const DISPATCH_CACHE: usize = 4096;

/// One cached session → endpoint binding. A slot is a hit only when it names the
/// exact session *and* the entry is still alive: a cached absence, a collision,
/// or a torn-down association re-probes the hub. Treating absence as a hit would
/// blackhole a session id if it were ever reused after `u32` wrap, and treating a
/// dead entry as a hit would keep writing into a socket nobody reads.
///
/// The entry is `Weak` on purpose. This cache lives in a dispatcher task that
/// outlives every association, so a strong reference here made the cache the
/// relay socket's *last* owner once `UdpHub::release` dropped the hub's and the
/// association task exited: up to `DISPATCH_CACHE` dead relay sockets — an fd
/// plus its 2 x 32 KiB kernel buffers each — stayed open until a session id
/// colliding on the same index happened to arrive (or the connection was
/// redialed, which rebuilds the cache). Measured before the fix: 1200
/// short-lived associations left **1024** UDP fds open in the client, which on a
/// 1024-fd router exhausts the table by itself.
///
/// Upgrading on a hit costs two RMWs (the `Weak` CAS plus the `Arc` strong
/// increment), plus one more when the upgraded `Arc` drops at the end of the
/// dispatch — that floor is inherent to `Weak` ownership and is kept on
/// purpose (see above). What a hit no longer pays is the app-address load:
/// `app` pins the entry's `SocketAddr` (a `Copy` value, not a reference, so
/// it extends no lifetime) and steady-state hits skip `AssocEntry::app()`'s
/// `ArcSwapOption` load entirely. Per-N=1 hit census after the pin: 1 upgrade
/// (2 RMW) + 1 `Arc` drop (1 RMW) + 1 `is_alive` load + 1 `mark_replied`
/// store; shared-atomics stats (`udp_stats::payload`, `udp_write::sent`)
/// stay thread-local batched (1 RMW per 256). Before the pin the same hit
/// additionally paid the `ArcSwapOption` load on every datagram.
pub(crate) struct DispatchSlot {
    pub(crate) sess: u32,
    pub(crate) entry: Option<std::sync::Weak<AssocEntry>>,
    /// The entry's app address as of the last probe. `None` means "the app
    /// had not sent yet when the slot was filled" — the hit path re-reads
    /// once and backfills, so later hits skip the load too.
    ///
    /// This never goes stale: the relay loop locks to the first app address
    /// for the association's life (see `udp_associate_inner`), and a cached
    /// address is only ever *used* behind a successful upgrade-plus-`is_alive`
    /// of the exact entry it was read from (a reused session id upgrades a
    /// dead weak and re-probes instead).
    pub(crate) app: Option<SocketAddr>,
}

/// One dispatcher reply staged for a grouped flush: the relay socket and app
/// it goes out on, the source address to report, and the owned payload.
///
/// Staged per drain burst and flushed grouped by consecutive `(sock, app)`
/// runs (see `flush_staged`): one `sendmmsg` per run on Linux, one
/// `try_send_to` per frame on the portable fallback. Runs flush in encounter
/// order, so batching preserves reply order exactly and cannot head-of-line
/// block one destination behind another.
///
/// `sock` is `None` for the non-leading items of one staged BATCH frame: every
/// item of a frame shares the association (one `lookup_entry` per frame, one
/// `mark_replied` per frame), so cloning the relay `Arc` per *item* paid a
/// refcount round-trip per payload for ownership the run already has. The
/// head item always carries `Some`, and staged items of one frame are always
/// consecutive, so a `None` inherits the nearest preceding `Some` in staging
/// order (see `flush_staged`). Single replies always carry `Some`.
pub(crate) struct StagedReply {
    pub(crate) sock: Option<Arc<tokio::net::UdpSocket>>,
    pub(crate) app: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) payload: Bytes,
    /// Write `payload` as-is (config-driven UDP forward listener) instead of
    /// prefixing the SOCKS5 UDP reply header. Taken from
    /// [`AssocEntry::raw_reply`] at staging time so the flush does not have to
    /// consult the hub again.
    pub(crate) raw: bool,
    /// The relay socket is dual-stack IPv6, so the app address must be mapped
    /// with [`map_for_dual`] before `send_to`. See [`AssocEntry::reply_v6`].
    pub(crate) reply_v6: bool,
}

pub(crate) fn stage_reply(
    entry: &AssocEntry,
    app: SocketAddr,
    dst: SocketAddr,
    payload: Bytes,
) -> StagedReply {
    entry.mark_replied();
    StagedReply {
        sock: Some(entry.relay.clone()),
        app,
        dst,
        payload,
        raw: entry.raw_reply,
        reply_v6: entry.reply_v6,
    }
}

/// Follower variant of [`stage_reply`] for a TRAIN item whose association (and
/// relay) is the same as the previously staged item's: `sock` stays `None` —
/// the flush inherits the run head behind it (see `StagedReply`) — so a run of
/// N items pays exactly one relay `Arc` clone (the head's) instead of N.
fn stage_reply_follow(
    entry: &AssocEntry,
    app: SocketAddr,
    dst: SocketAddr,
    payload: Bytes,
) -> StagedReply {
    entry.mark_replied();
    StagedReply {
        sock: None,
        app,
        dst,
        payload,
        raw: entry.raw_reply,
        reply_v6: entry.reply_v6,
    }
}

/// Result of resolving a session id for a batch frame.
///
/// `lookup_entry` used to return `Option`, so the batch path could not tell
/// "no such association" from "association has no app address yet" and bumped
/// `udp_write::no_app` for both — while the unknown-session case was already
/// counted in `dgram_drops::UNKNOWN_SESS` inside the hub probe. That reported
/// `no-app` for replies to associations this process had already torn down,
/// which is the ordinary late-reply race, not a missing app address. The split
/// keeps the 60 s `udp write` line honest; the single-frame path already
/// distinguishes the two and is unchanged.
enum Lookup {
    /// Live association and its app address.
    Hit(Arc<AssocEntry>, SocketAddr),
    /// No such association: never published, already released, or a dead entry
    /// the hub still serves. The drop is counted where it is decided (the hub
    /// probe bumps `UNKNOWN_SESS`); the call site only drops.
    NoEntry,
    /// The association is live but has no recorded app address yet, so a reply
    /// has nowhere to go: count it in `udp_write::no_app`.
    NoApp,
}

fn lookup_entry(cache: &mut [DispatchSlot; DISPATCH_CACHE], hub: &UdpHub, sess: u32) -> Lookup {
    let idx = (sess as usize) & (DISPATCH_CACHE - 1);
    let cached = if cache[idx].sess == sess {
        cache[idx]
            .entry
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .filter(|e| e.is_alive())
    } else {
        None
    };
    let (entry, app) = match cached {
        Some(e) => match cache[idx].app {
            Some(app) => (e, Some(app)),
            None => {
                let app = e.app();
                cache[idx].app = app;
                (e, app)
            }
        },
        None => {
            let Some(fresh) = hub.entry(sess) else {
                cache[idx] = DispatchSlot {
                    sess,
                    entry: None,
                    app: None,
                };
                dgram_drops::bump(&dgram_drops::UNKNOWN_SESS);
                return Lookup::NoEntry;
            };
            if !fresh.is_alive() {
                cache[idx] = DispatchSlot {
                    sess,
                    entry: None,
                    app: None,
                };
                // Served by the hub but already dead: the association is
                // exiting, so this is the same "no such association" outcome as
                // the arm above and must be counted the same way (the old arm
                // returned without a bump even though the enum documents the
                // hub probe as the counting site).
                dgram_drops::bump(&dgram_drops::UNKNOWN_SESS);
                return Lookup::NoEntry;
            }
            let app = fresh.app();
            cache[idx] = DispatchSlot {
                sess,
                entry: Some(Arc::downgrade(&fresh)),
                app,
            };
            (fresh, app)
        }
    };
    match app {
        Some(app) => Lookup::Hit(entry, app),
        None => Lookup::NoApp,
    }
}

fn stage_v3_reply(
    app: SocketAddr,
    addr: TargetAddrRef<'_>,
    payload: Bytes,
    raw: bool,
    reply_v6: bool,
    out: &mut Vec<StagedReply>,
    head: &mut Option<Arc<tokio::net::UdpSocket>>,
) -> bool {
    match addr {
        TargetAddrRef::Ip(dst) => {
            udp_stats::payload(payload.len());
            out.push(StagedReply {
                sock: head.take(),
                app,
                dst,
                payload,
                raw,
                reply_v6,
            });
            true
        }
        TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
            CachedLookup::Addr(dst) => {
                udp_stats::payload(payload.len());
                out.push(StagedReply {
                    sock: head.take(),
                    app,
                    dst,
                    payload,
                    raw,
                    reply_v6,
                });
                true
            }
            // The server always echoes replies with an IP-form source address.
            // A domain here is hostile or a future peer; resolve it only from
            // this thread's positive cache, never by spawning a task per item.
            CachedLookup::Negative | CachedLookup::Unknown => {
                dgram_drops::bump(&dgram_drops::REFUSED);
                false
            }
        },
    }
}

/// Batch-capable staging: routes one QUIC DATAGRAM that may hold 1 app payload
/// (0x02), N packed MQP-2 payloads (0x06 BATCH), or an MQP-3 SINGLE/TRAIN.
/// Single frames behave exactly like [`dispatch_stage`]; packed frames stage
/// one reply per item. Returns the number of replies staged (0 = dropped or
/// handed to a resolver).
pub(crate) fn dispatch_stage_multi(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
    d: Bytes,
    reasm: &mut DgramReassembler,
    out: &mut Vec<StagedReply>,
) -> usize {
    if is_v3(&d) {
        let (entry, app) = match lookup_entry(cache, hub, sess) {
            Lookup::Hit(entry, app) => (entry, app),
            Lookup::NoEntry => return 0,
            Lookup::NoApp => {
                udp_write::no_app();
                return 0;
            }
        };
        let kind = d[0] & MQP3_KIND_MASK;
        let mut staged = 0usize;
        let mut head = Some(entry.relay.clone());
        match kind {
            MQP3_SINGLE => {
                let Ok(s) = decode_single(&d) else {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    return 0;
                };
                if s.sess != sess {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    return 0;
                }
                let table = entry.flows.load();
                let addr = match s.inline {
                    Some(a) => Some(a),
                    // A compressed downlink must name an IP flow: the client's
                    // table entry for a domain is the *requested* name, not a
                    // valid SOCKS reply source. The server never compresses a
                    // domain flow; reject one that does instead of writing a
                    // domain where the app expects an IP.
                    None => match table.get(s.flow) {
                        Some(a @ TargetAddr::Ip(_)) => Some(a.as_ref()),
                        _ => None,
                    },
                };
                let Some(addr) = addr else {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    return 0;
                };
                if stage_v3_reply(
                    app,
                    addr,
                    {
                        let off = s.payload.as_ptr() as usize - d.as_ptr() as usize;
                        d.slice(off..off + s.payload.len())
                    },
                    entry.raw_reply,
                    entry.reply_v6,
                    out,
                    &mut head,
                ) {
                    staged = 1;
                    // A compressed downlink is only possible after the server
                    // accepted an inline open; it is the implicit ACK that lets
                    // the association compress this flow.
                    if s.inline.is_none() {
                        entry.confirm_flow(s.flow);
                    }
                }
            }
            MQP3_TRAIN => {
                let Ok(t) = decode_train(&d) else {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    return 0;
                };
                if t.sess != sess {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                    return 0;
                }
                let table = entry.flows.load();
                for item in t.items() {
                    let addr = match item.inline {
                        Some(a) => Some(a),
                        None => match table.get(item.flow) {
                            Some(a @ TargetAddr::Ip(_)) => Some(a.as_ref()),
                            _ => None,
                        },
                    };
                    let Some(addr) = addr else {
                        dgram_drops::bump(&dgram_drops::REFUSED);
                        continue;
                    };
                    if stage_v3_reply(
                        app,
                        addr,
                        {
                            let off = item.payload.as_ptr() as usize - d.as_ptr() as usize;
                            d.slice(off..off + item.payload.len())
                        },
                        entry.raw_reply,
                        entry.reply_v6,
                        out,
                        &mut head,
                    ) {
                        staged += 1;
                        if item.inline.is_none() {
                            entry.confirm_flow(item.flow);
                        }
                    }
                }
            }
            MQP3_FRAG => {
                // Legacy (v0.2.0) compact FRAG is decode-ready but was never
                // wired to a reassembler, and no rev2 peer emits it: large
                // payloads now ride rev2 `FRAG` (handled in `dispatch_r2_frag`).
                // Count it rather than silently losing it if an old peer sends
                // the form.
                dgram_drops::bump(&dgram_drops::REFUSED);
            }
            _ => {}
        }
        if staged > 0 {
            // One liveness flag per frame, not per item: every item shares the
            // association and `mark_replied` is an idempotent relaxed store.
            entry.mark_replied();
        }
        return staged;
    }
    if is_batch(&d) {
        let Ok(b) = decode_batch(&d) else {
            return 0;
        };
        if b.sess != sess {
            dgram_drops::bump(&dgram_drops::REFUSED);
            return 0;
        }
        let (entry, app) = match lookup_entry(cache, hub, sess) {
            Lookup::Hit(entry, app) => (entry, app),
            // `lookup_entry` already counted the unknown session; both drop
            // arms stage nothing and the caller returns 0.
            Lookup::NoEntry => return 0,
            Lookup::NoApp => {
                udp_write::no_app();
                return 0;
            }
        };
        match b.addr {
            TargetAddrRef::Ip(dst) => {
                // One liveness flag per frame, not per item: every item of a
                // batch shares the association, `mark_replied` is an
                // idempotent relaxed store, and its only consumer folds it
                // into the idle stamp at the association's own tick.
                entry.mark_replied();
                // One relay `Arc` per frame, not per item: the head item
                // carries it and the rest inherit it at flush (see
                // `StagedReply::sock`), so a 16-item frame pays one refcount
                // round-trip instead of sixteen.
                let mut head = Some(entry.relay.clone());
                for p in b.payloads() {
                    udp_stats::payload(p.len());
                    out.push(StagedReply {
                        sock: head.take(),
                        app,
                        dst,
                        payload: d.slice_ref(p),
                        raw: entry.raw_reply,
                        reply_v6: entry.reply_v6,
                    });
                }
                return b.len();
            }
            TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
                CachedLookup::Addr(dst) => {
                    entry.mark_replied();
                    let mut head = Some(entry.relay.clone());
                    for q in b.payloads() {
                        udp_stats::payload(q.len());
                        out.push(StagedReply {
                            sock: head.take(),
                            app,
                            dst,
                            payload: d.slice_ref(q),
                            raw: entry.raw_reply,
                            reply_v6: entry.reply_v6,
                        });
                    }
                    return b.len();
                }
                // Deliberately no resolver spawn here, unlike the single-frame
                // path: the server always echoes replies with an IP-form source
                // address, so a domain batch address is either hostile or a
                // future peer — spawning one resolver task per *item* of a
                // burst would turn a forged batch into a task-spawn amplifier.
                CachedLookup::Negative | CachedLookup::Unknown => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                }
            },
        }
        return 0;
    }
    match dispatch_stage(cache, hub, sess, d, reasm) {
        Some(s) => {
            out.push(s);
            1
        }
        None => 0,
    }
}
/// Route one inbound DATAGRAM to its association, staging the reply.
///
/// Same routing, decoding, reassembly, DNS and drop accounting as the
/// immediate path; only the final socket write is deferred so one drain
/// burst's same-destination replies can share a syscall (`flush_staged`).
/// `None` means dropped — or handed to a spawned resolver, which sends
/// immediately exactly as before.
pub(crate) fn dispatch_stage(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
    d: Bytes,
    reasm: &mut DgramReassembler,
) -> Option<StagedReply> {
    let idx = (sess as usize) & (DISPATCH_CACHE - 1);
    // A hit needs the exact session *and* an endpoint that is still alive. The
    // upgrade also answers "has the association exited?": once it has, the weak
    // reference is dead (so nothing keeps its relay socket open) and the hub
    // would no longer serve the session either.
    let cached = if cache[idx].sess == sess {
        cache[idx]
            .entry
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .filter(|e| e.is_alive())
    } else {
        None
    };
    let (entry, app) = match cached {
        Some(e) => match cache[idx].app {
            // Steady state: the pinned address skips the `ArcSwapOption`
            // load. Sound because the address locks to the first sender for
            // the association's life, and this arm already proved the entry
            // this address was read from is still the live owner of `sess`.
            Some(app) => (e, Some(app)),
            // The slot was filled before the app sent anything: re-read once
            // and backfill so the datagrams after this one hit the arm above.
            None => {
                let app = e.app();
                cache[idx].app = app;
                (e, app)
            }
        },
        None => {
            // Miss, collision, torn-down association, or an upgrade that lost to
            // the association's exit: re-probe the hub.
            let Some(fresh) = hub.entry(sess) else {
                cache[idx] = DispatchSlot {
                    sess,
                    entry: None,
                    app: None,
                };
                // No such association: the reply belongs to a session that has
                // already been torn down. Still dropped — best-effort UDP, and
                // the server's own reap is what stops it — but *counted*, because
                // this fires in a perfectly ordinary race: the client reaps an
                // idle association (or the app closes the control TCP) at 180 s
                // while the server's session is still live and its target keeps
                // answering, so every reply until the server's own timeout shows
                // up here. It used to be a bare `return`, which made the 60 s
                // budget line's silence a claim the code could not support.
                dgram_drops::bump(&dgram_drops::UNKNOWN_SESS);
                return None;
            };
            // `hub.entry` answers "is it published", not "is it alive": between
            // `AliveGuard` clearing the bit and `UdpHub::release` unpublishing
            // (and permanently, if that release is ever skipped) the map still
            // serves the entry. Without this filter the reply would be written
            // into a socket nobody reads, which is exactly what the cache-hit
            // path above filters with `is_alive`.
            if !fresh.is_alive() {
                cache[idx] = DispatchSlot {
                    sess,
                    entry: None,
                    app: None,
                };
                // Published but already dead (the association is exiting):
                // same unknown-session outcome as the arm above, counted the
                // same way.
                dgram_drops::bump(&dgram_drops::UNKNOWN_SESS);
                return None;
            }
            let app = fresh.app();
            cache[idx] = DispatchSlot {
                sess,
                entry: Some(Arc::downgrade(&fresh)),
                app,
            };
            (fresh, app)
        }
    };
    // `app` above is either the pinned address (no refcount traffic on the
    // per-datagram path) or the one fresh probe's `ArcSwapOption::load` — the
    // 200 ms app-address cache the reply task needed is gone with the lock it
    // was working around.
    let Some(app) = app else {
        udp_write::no_app();
        return None;
    };

    if d.first() == Some(&MQP_DGRAM_FRAG) {
        let Ok(f) = decode_fragment(&d) else {
            return None;
        };
        let (_, a, whole) = reasm.push(&f, coarse_millis())?;
        udp_stats::payload(whole.len());
        match a.as_ref() {
            TargetAddrRef::Ip(dst) => return Some(stage_reply(&entry, app, dst, whole)),
            TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
                CachedLookup::Addr(dst) => return Some(stage_reply(&entry, app, dst, whole)),
                // Unreachable from a conforming server (replies are always
                // IP-form); counted rather than silently dropped so a
                // future or hostile peer cannot create invisible loss here.
                CachedLookup::Negative | CachedLookup::Unknown => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                }
            },
        }
        return None;
    }

    let Ok((_, a, p)) = decode_datagram_ref(&d) else {
        return None;
    };
    let off = d.len() - p.len();
    let payload = d.slice(off..);
    udp_stats::payload(payload.len());
    match a {
        TargetAddrRef::Ip(dst) => return Some(stage_reply(&entry, app, dst, payload)),
        TargetAddrRef::Domain(h, p) => {
            // The server always echoes replies with an IP-form source address, so
            // this branch is defensive; this thread's DNS memo is still consulted
            // synchronously so a known-bad name never spawns a resolver task.
            match lookup_cached_fast(h, p) {
                CachedLookup::Negative => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                }
                CachedLookup::Addr(dst) => return Some(stage_reply(&entry, app, dst, payload)),
                CachedLookup::Unknown => {
                    // Fail fast on the slow-path budget with exactly one bump
                    // per refusal: `try_acquire_owned` is the only check, so
                    // a permit freed between a probe and the acquire is still
                    // usable and an exhausted budget is counted once (same
                    // single-acquire shape as the server's forward path).
                    // `DNS_BUDGET`, not `SESSION_FULL`: see the server's
                    // `forward_server_dgram` for why the two must not share a
                    // counter.
                    let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            dgram_drops::bump(&dgram_drops::DNS_BUDGET);
                            return None;
                        }
                    };
                    // A spawn that delivers its own payload, instead of
                    // dropping: an ingress reply has no other signal, so
                    // dropping it blackholes an app query the app may never
                    // retry. Moka coalesces every concurrent waiter for the
                    // name into one upstream query, so N waiters cost N task
                    // shells (bounded by the limiter above) and one
                    // resolution.
                    //
                    // Hand the resolver task its own handle on the association.
                    // It checks nothing else: a reply resolved after the
                    // association died writes into a socket the entry keeps
                    // alive, which is the same best-effort UDP semantics as a
                    // reply that arrives late on any other path.
                    let entry = entry.clone();
                    let host = h.to_string();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let dst = match resolve_all_cached(&host, p).await {
                            Ok(v) => match v.first().copied() {
                                Some(s) => s,
                                None => {
                                    dgram_drops::bump(&dgram_drops::REFUSED);
                                    return;
                                }
                            },
                            Err(_) => {
                                dgram_drops::bump(&dgram_drops::REFUSED);
                                return;
                            }
                        };
                        let mut pkt = bytes::BytesMut::with_capacity(256);
                        send_reply(&entry, dst, &payload, &mut pkt);
                    });
                    return None;
                }
            }
        }
    }
    None
}

/// Route one inbound DATAGRAM to its association, writing the relay socket
/// directly.
///
/// Immediate single-datagram form of [`dispatch_stage`]: stages at most one
/// reply and sends it through the caller's scratch buffer, exactly as the old
/// per-datagram path did (borrowed fast path, owned copy only on WouldBlock).
/// The dispatcher loop stages bursts and flushes them grouped instead.
///
/// Test-only: the unit tests drive one datagram at a time through this.
#[cfg(test)]
pub(crate) fn dispatch_one(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
    d: Bytes,
    reasm: &mut DgramReassembler,
    pkt: &mut bytes::BytesMut,
) {
    let Some(s) = dispatch_stage(cache, hub, sess, d, reasm) else {
        return;
    };
    let sock = s
        .sock
        .as_ref()
        .expect("a staged single reply always carries its relay socket");
    let dst = if s.reply_v6 {
        map_for_dual(s.app)
    } else {
        s.app
    };
    if s.raw {
        // Raw forward listener: the peer is an ordinary UDP application, so a
        // SOCKS5 header would be delivered as payload bytes.
        udp_try_send_slice(sock, dst, &s.payload);
        return;
    }
    pkt.truncate(0);
    encode_reply(pkt, s.dst, &s.payload);
    udp_try_send_slice(sock, dst, &pkt[..]);
}

/// Flush staged replies grouped by consecutive `(sock, app)` runs.
///
/// Each run shares one `sendmmsg` on Linux (one `try_send_to` per frame on the
/// portable fallback); runs flush in encounter order, so reply order is
/// preserved exactly. `hdrs`/`offs` are reused across bursts (cleared, never
/// freed), so the steady path allocates nothing per reply. A run of one — the
/// common shape, since replies arrive one per drain burst — skips the
/// 32-entry `refs` array entirely and passes a 1-element `[SendFrame; 1]`:
/// building and zero-initializing the full array cost 512 B of stack stores
/// plus a fill loop per single reply, with no grouping to pay for it.
///
/// **Only the ≤22-byte SOCKS5 header is staged, never the payload.** The frame
/// handed to [`udp_try_send_grouped`] is `(header, payload)` and Linux sends the
/// two as separate iovecs of one datagram, so a reply is copied zero times
/// here. The earlier shape concatenated header + payload into a full-size
/// `arena` per reply — one whole-payload memcpy per datagram on the download
/// path — and that arena was `with_capacity(32 * 2048)` while the protocol
/// allows 8 KiB payloads, so a burst of large replies also reallocated it.
/// Every frame keeps its own accounting: `WouldBlock` still queues into the
/// detached-retry pool per frame.
pub(crate) fn flush_staged(
    staged: &mut Vec<StagedReply>,
    hdrs: &mut Vec<u8>,
    offs: &mut Vec<(usize, usize)>,
) {
    let mut i = 0;
    while i < staged.len() {
        // The run's socket lives on the head item; trailing items of one
        // staged BATCH frame carry `None` and inherit it (see
        // `StagedReply::sock`). Staging always emits a frame's items
        // consecutively with the head first, so the head is `Some` here.
        let run_sock: &Arc<tokio::net::UdpSocket> = staged[i]
            .sock
            .as_ref()
            .expect("a flush run head always carries the relay socket");
        let run_app = staged[i].app;
        let run_v6 = staged[i].reply_v6;
        let run_raw = staged[i].raw;
        let run_dst = if run_v6 {
            map_for_dual(run_app)
        } else {
            run_app
        };
        let mut j = i + 1;
        while j < staged.len()
            && staged[j].app == run_app
            && staged[j].reply_v6 == run_v6
            && staged[j].raw == run_raw
            && staged[j]
                .sock
                .as_ref()
                .is_none_or(|s| Arc::ptr_eq(s, run_sock))
        {
            // A `None` item inherits this run; a `Some` item whose socket is
            // a different relay ends it. A `None` can only follow its own
            // frame's head (staging emits frames consecutively), so
            // inheritance never crosses runs. `raw` joins the run key even
            // though one relay socket currently implies one reply mode: the
            // empty-header vs SOCKS-header choice is per item, so a future
            // second entry on one socket must split the run instead of
            // mixing a framed and an unframed datagram into one sendmsg.
            j += 1;
        }
        let mut k = i;
        while k < j {
            let n = (j - k).min(LAST_HOP_DRAIN);
            hdrs.clear();
            offs.clear();
            for s in &staged[k..k + n] {
                if s.raw {
                    // Raw forward listener: zero-length header, the payload is
                    // the whole datagram. `offs` still gets an entry so the
                    // frame assembly below is unchanged (the header slice is
                    // empty and the payload slice is the datagram).
                    offs.push((hdrs.len(), 0));
                } else {
                    let start = hdrs.len();
                    encode_reply_header(hdrs, s.dst);
                    offs.push((start, hdrs.len() - start));
                }
            }
            if n == 1 {
                // Single-reply run: one header, one payload, one frame. No
                // `refs` array to initialize or fill — this is the path a
                // session that receives one reply per burst always takes.
                let (o, l) = offs[0];
                let frame: [SendFrame<'_>; 1] = [(&hdrs[o..o + l], &staged[k].payload[..])];
                udp_try_send_grouped(run_sock, run_dst, &frame);
                k += 1;
                continue;
            }
            let mut refs: [SendFrame<'_>; LAST_HOP_DRAIN] = [(&[], &[]); LAST_HOP_DRAIN];
            for ((r, (o, l)), s) in refs.iter_mut().zip(offs.iter()).zip(&staged[k..k + n]) {
                *r = (&hdrs[*o..*o + *l], &s.payload[..]);
            }
            udp_try_send_grouped(run_sock, run_dst, &refs[..n]);
            k += n;
        }
        i = j;
    }
    staged.clear();
}

// ---------------- MQP-3 wire rev2 downlink ----------------

/// The SOCKS5 reply source of a bound flow: the learned reply source
/// (`DATA OPEN|SRC` / a rebind) when present, else the exact IP target.
///
/// A domain flow that has not learned a source yet has nowhere to deliver: the
/// requested name is not a valid SOCKS5 reply source, so the frame is dropped
/// and counted instead of writing a domain where the app expects an address.
fn r2_reply_dst(binding: &FlowBinding) -> Option<SocketAddr> {
    binding.reply_src().or_else(|| binding.target.socket_addr())
}

/// Reply destination of a self-describing inline address.
///
/// The server always echoes IP-form sources; a domain here is hostile or a
/// future peer, so only this thread's positive DNS cache may resolve it (same
/// rule as the legacy inline path: no resolver task per item).
fn r2_addr_dst(addr: TargetAddrRef<'_>) -> Option<SocketAddr> {
    match addr {
        TargetAddrRef::Ip(dst) => Some(dst),
        TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
            CachedLookup::Addr(dst) => Some(dst),
            CachedLookup::Negative | CachedLookup::Unknown => None,
        },
    }
}

/// Resolve a session id to its live association entry, counting the same
/// no-app / unknown-session cases as the legacy paths.
fn r2_lookup(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
) -> Option<(Arc<AssocEntry>, SocketAddr)> {
    match lookup_entry(cache, hub, sess) {
        Lookup::Hit(entry, app) => Some((entry, app)),
        // `lookup_entry` already counted the unknown session.
        Lookup::NoEntry => None,
        Lookup::NoApp => {
            udp_write::no_app();
            None
        }
    }
}

/// Confirm a learned `OPEN|SRC` reply source with `CTL FLOW_ACK` (`status = 0`).
///
/// The peer only marks its binding "confirmed" when this arrives, and until
/// then it keeps re-sending the idempotent `OPEN|SRC` (see the shared
/// `FlowBinding::reply_src_acked` contract). So an ACK lost on the unreliable
/// DATAGRAM path costs one more binding frame, never a blackholed flow — but a
/// receiver that never ACKs turns every downlink frame into a binding frame
/// and leaves the source unconfirmed forever. `None` (unit tests without a live
/// connection) simply skips the send.
fn send_flow_ack(conn: Option<&quinn::Connection>, id: u32) {
    let Some(conn) = conn else {
        return;
    };
    match r2_send_ctl(
        conn,
        &r2::Ctl::FlowAck {
            id,
            status: r2::R2_ACK_OPEN,
        },
    ) {
        DatagramSend::Sent => counters::flow_ack_tx(),
        _ => counters::ctl_tx_fail(),
    }
}

/// Best-effort rejection notice for a binding frame this side refuses.
///
/// The peer answers a reject by closing the offending flow and sending
/// `INLINE` for the target until its TTL expires, which is the only recovery
/// a rejected `OPEN` has; staying silent leaves the peer re-sending frames for
/// an id we will never install.
///
/// rev2 sends `CTL FLOW_REJECT` on the DATAGRAM plane; rev3 has no control
/// DATAGRAMs, so the same notice rides the reliable control stream as
/// `REJECT{fid}` (14-bit id; an id that cannot be a fid is unencodable on rev3
/// anyway, so there is nothing to reject).
fn send_flow_reject(rev2: &ConnRev2, conn: Option<&quinn::Connection>, id: u32, reason: u8) {
    match rev2.wire() {
        Wire::Rev2 => {
            let Some(conn) = conn else {
                return;
            };
            match r2_send_ctl(conn, &r2::Ctl::FlowReject { id, reason }) {
                DatagramSend::Sent => counters::flow_reject_tx(),
                _ => counters::ctl_tx_fail(),
            }
        }
        Wire::Rev3 => {
            let Some(fid) = wire::fid_for(id) else {
                return;
            };
            if rev2.send_ctl(CtlMessage::Reject { fid, reason }) {
                counters::flow_reject_tx();
            } else {
                counters::ctl_tx_fail();
            }
        }
    }
}

/// Install a server-owned flow announced by a standalone `DATA OPEN`/`OPEN|SRC`.
///
/// rev2 wire ids are half-owned (`local << 1 | owner`): the server may open a
/// flow for an unsolicited / full-cone reply (owner bit 1) that this endpoint
/// has never seen. The OPEN is self-describing (`sess + addr`, `addr` being the
/// actual reply source), so the binding can be created locally: the reply is
/// staged now, and the app's later traffic to that source reuses the same id
/// (`ensure_binding` finds it through [`FlowRegistry::find_server_flow`]).
///
/// Only a standalone OPEN can install — a steady frame or a `TRAIN` item carries
/// no address, so there is no way to name the flow. A full or conflicting
/// registry drops the frame instead of evicting a live flow, and an unknown
/// *client-owned* id is never installable (only owner bit 1 is).
///
/// Every failure is reported to the peer (rev2 `CTL FLOW_REJECT`, rev3
/// `REJECT` on the control stream) so it can stop using this id and fall back
/// to `INLINE` (`TABLE_FULL` when the per-connection registry is at its cap,
/// `POLICY` for everything else); without it a lost or refused `OPEN` left the
/// sender repeating frames this side can never resolve.
fn install_server_flow(
    rev2: &ConnRev2,
    conn: Option<&quinn::Connection>,
    id: u32,
    sess: Option<u32>,
    addr: Option<TargetAddrRef<'_>>,
) -> Option<Arc<FlowBinding>> {
    if !r2::wire_id_server_owned(id) {
        send_flow_reject(rev2, conn, id, r2::R2_REJECT_POLICY);
        return None;
    }
    let (Some(sess), Some(addr)) = (sess, addr) else {
        send_flow_reject(rev2, conn, id, r2::R2_REJECT_POLICY);
        return None;
    };
    let Some(src) = r2_addr_dst(addr) else {
        send_flow_reject(rev2, conn, id, r2::R2_REJECT_POLICY);
        return None;
    };
    let binding = FlowBinding::new_shared(id, sess, TargetAddr::Ip(src));
    binding.set_reply_src(src);
    binding.mark_open();
    match rev2.registry.insert(binding) {
        Ok(binding) => {
            counters::server_flow_accept();
            Some(binding)
        }
        Err(e) => {
            dgram_drops::bump(&dgram_drops::REFUSED);
            counters::rx_drop();
            let reason = match e {
                RegistryError::Full => r2::R2_REJECT_TABLE_FULL,
                RegistryError::Conflict => r2::R2_REJECT_POLICY,
            };
            send_flow_reject(rev2, conn, id, reason);
            None
        }
    }
}

/// Handle one rev2 `CTL` frame.
///
/// Every opcode is idempotent and loss-tolerant by construction: a lost `CAPS`
/// only delays readiness (the `HELLO` retry covers it, and a missing `CAPS`
/// never fails the connection — W2), a lost `FLOW_ACK` only delays compression
/// (the uplink keeps sending `OPEN`), and a lost `FLOW_CLOSE`/`SESS_CLOSE` is
/// backstopped by the server's idle sweep.
///
/// `hub` is the process association table: a `SESS_CLOSE` is only recorded for
/// a session whose association is still live (see the arm below), so the hub
/// read is what keeps the bounded notification set free of stale ids.
///
/// Test entry point: reads the coarse clock itself. The production dispatcher
/// calls [`handle_r2_ctl_at`] with the drain burst's single clock read.
#[cfg(test)]
pub(crate) fn handle_r2_ctl(rev2: &ConnRev2, hub: &UdpHub, r2_reasm: &mut R2Reassembler, d: &[u8]) {
    handle_r2_ctl_at(rev2, hub, r2_reasm, d, coarse_millis());
}

/// [`handle_r2_ctl`] with the caller's coarse-clock read (W8a: one clock read
/// per drain burst instead of one per control frame).
pub(crate) fn handle_r2_ctl_at(
    rev2: &ConnRev2,
    hub: &UdpHub,
    r2_reasm: &mut R2Reassembler,
    d: &[u8],
    now_ms: u64,
) {
    // rev3 has no CTL DATAGRAMs: its control plane is the reliable stream. A
    // DATAGRAM that happens to carry a rev2 CTL first byte is not a control
    // frame there, so it must never mutate state (the wire-aware classifier
    // already routes rev3 DATAGRAMs elsewhere; this is the belt-and-braces).
    if rev2.wire() != Wire::Rev2 {
        counters::ctl_drop();
        return;
    }
    let Ok(ctl) = r2::decode_ctl(d) else {
        counters::ctl_drop();
        return;
    };
    // Peer-controlled control frames that do purge work: `SESS_CLOSE`,
    // `FLOW_CLOSE` and `FLOW_REJECT` are idempotent but not free (each takes the
    // registry/session shards, the stager queue and the reassembler), so the
    // per-connection rate budget bounds a CTL flood to O(CTL_MAX_PER_SEC)
    // instead of line rate — the spec's rate/total cap requirement. `CAPS` and
    // `FLOW_ACK` are deliberately exempt: the handshake depends on CAPS (and
    // HELLO retries arrive at a fixed cadence), and a FLOW_ACK is one cheap map
    // probe. Excess frames are dropped and counted, not answered.
    if matches!(
        ctl,
        r2::Ctl::SessClose { .. } | r2::Ctl::FlowClose { .. } | r2::Ctl::FlowReject { .. }
    ) && !rev2.ctl.ctl_allowed(now_ms)
    {
        counters::ctl_rate_limited();
        return;
    }
    match ctl {
        r2::Ctl::Caps(caps) => rev2.on_caps(caps),
        r2::Ctl::FlowAck { id, .. } => match rev2.registry.get(id) {
            Some(binding) => {
                binding.mark_open();
                counters::flow_ack_rx();
            }
            None => counters::rx_unknown_id(),
        },
        r2::Ctl::FlowReject { id, reason } => match rev2.registry.remove(id) {
            Some(binding) => {
                // Known flow: only now is the per-id cleanup worth its scan.
                let _ = r2_reasm.drop_flow(id);
                let _ = rev2.stager.lock().drop_flow_scoped(binding.session, id);
                binding.mark_closed();
                // The uplink falls back to `INLINE` for this target for the
                // reason's window (spec §3.4) instead of re-opening on every
                // payload; the binding's target is the key the uplink looks up.
                // The window is stored on the coarse epoch: that is the clock
                // `ensure_binding`/`is_rejected` probe with, so both sides of
                // the TTL comparison share one epoch (and the drain burst's
                // clock read is reused — W8a).
                rev2.note_rejected(binding.target.clone(), reason, now_ms);
                counters::flow_reject_rx();
            }
            // Duplicate/unknown reject: no queued state can exist for an id
            // this side never installed, so the scans are skipped entirely.
            None => counters::rx_unknown_id(),
        },
        r2::Ctl::FlowClose { id } => match rev2.registry.remove(id) {
            Some(binding) => {
                // Known flow: purge its queued stager items and in-flight
                // reassembly now. The stager scan is scoped to the owning
                // session, so this stays O(one queue) instead of O(all queues).
                let _ = r2_reasm.drop_flow(id);
                let _ = rev2.stager.lock().drop_flow_scoped(binding.session, id);
                binding.mark_closed();
                counters::flow_close_rx();
            }
            // Duplicate/unknown close (legal and idempotent on the wire): no
            // scan on the peer-controlled frame path.
            None => counters::rx_unknown_id(),
        },
        // The client keeps the association alive; the notification only makes
        // the next uplink burst re-open its flows on the (re)created session.
        // Bounded inside `ConnRev2`, so a hostile peer cannot grow it.
        r2::Ctl::SessClose { sess, .. } => {
            let _ = r2_reasm.drop_session(sess);
            let _ = rev2.stager.lock().drop_session(sess);
            // Both client-owned and accepted server-owned bindings of the
            // closed session must go: a receive-only (server-owned) binding is
            // otherwise never removed by the association's own uplink sync.
            let _ = rev2.registry.remove_session(sess);
            // Record the notification only for a session with a live
            // association. A close for an unknown/exiting session has no
            // consumer: it would occupy the bounded set for the connection's
            // life (keeping the per-datagram `closed_len` short-circuit open)
            // and, once the cap is reached, evict a live association's close —
            // i.e. blackhole it. A peer can therefore not accumulate stale ids
            // here no matter how many `SESS_CLOSE` frames it sends.
            let live = hub.entry(sess).is_some_and(|e| e.is_alive());
            if live {
                rev2.note_session_closed(sess);
            }
            counters::sess_close_rx();
        }
        // This endpoint originates `HELLO`; a HELLO from the server is not a
        // rev2 flow-control event. Count and ignore.
        r2::Ctl::Hello { .. } => counters::ctl_drop(),
    }
}

/// Recovery for a steady frame naming a flow this side never installed.
///
/// rev2 needs none: the sender keeps repeating `OPEN` while its binding is
/// `Opening`, so an unknown steady id is just a stale frame (counted).
/// rev3 has no ACK/OPEN gate at all — the *receiver* is the one that notices a
/// lost context window, so it asks the peer to re-send binding context
/// (`NEED_CONTEXT{id}`) on the control stream. Rate-limited per connection by
/// [`ConnRev2::send_need_context`]; the frame itself is still dropped (UDP
/// semantics: it was sent before the peer had the binding).
fn repair_unknown_flow(rev2: &ConnRev2, wire_id: u32) {
    if rev2.wire() == Wire::Rev3 {
        rev2.send_need_context(wire_id);
    }
}

/// Apply one rev3 control-stream message (`REJECT`/`SESS_CLOSE`/`FLOW_CLOSE`/
/// `NEED_CONTEXT`/`GOAWAY`).
///
/// Mirrors the rev2 `CTL` handlers action for action, minus the DATAGRAM plane:
/// the stream is reliable and ordered, so the client never repeats and no frame
/// can be lost, but every action stays idempotent because the server may retry a
/// reap notice and a `NEED_CONTEXT` can race a re-arm.
///
/// `hub` gates the `SESS_CLOSE` note exactly like the rev2 arm: only a session
/// with a live association can consume it, so a peer cannot park stale ids in
/// the bounded notification set.
pub(crate) fn handle_r3_ctl(
    rev2: &ConnRev2,
    hub: &UdpHub,
    r2_reasm: &mut R2Reassembler,
    msg: CtlMessage,
) {
    counters::ctl_stream_rx();
    match msg {
        CtlMessage::Reject { fid, reason } => {
            let Some(id) = wire::wire_id_for_fid(fid) else {
                counters::rx_unknown_id();
                return;
            };
            match rev2.registry.remove(id) {
                Some(binding) => {
                    // Known flow: the per-id cleanup is worth its scans.
                    let _ = r2_reasm.drop_flow(id);
                    let _ = rev2.stager.lock().drop_flow_scoped(binding.session, id);
                    binding.mark_closed();
                    // The uplink sends `INLINE` for the target for the reason's
                    // window instead of re-opening on every payload.
                    rev2.note_rejected(binding.target.clone(), reason, coarse_millis());
                    counters::flow_reject_rx();
                }
                // Duplicate/unknown reject: no queued state can exist for an id
                // this side never installed, so the scans are skipped.
                None => counters::rx_unknown_id(),
            }
        }
        CtlMessage::SessClose { sess, .. } => {
            let _ = r2_reasm.drop_session(sess);
            let _ = rev2.stager.lock().drop_session(sess);
            // Both client-owned and accepted server-owned bindings of the
            // reaped session must go (see the rev2 `SESS_CLOSE` arm).
            let _ = rev2.registry.remove_session(sess);
            let live = hub.entry(sess).is_some_and(|e| e.is_alive());
            if live {
                rev2.note_session_closed(sess);
            }
            counters::sess_close_rx();
        }
        CtlMessage::FlowClose { fid, .. } => {
            let Some(id) = wire::wire_id_for_fid(fid) else {
                counters::rx_unknown_id();
                return;
            };
            match rev2.registry.remove(id) {
                Some(binding) => {
                    let _ = r2_reasm.drop_flow(id);
                    let _ = rev2.stager.lock().drop_flow_scoped(binding.session, id);
                    binding.mark_closed();
                    counters::flow_close_rx();
                }
                None => counters::rx_unknown_id(),
            }
        }
        CtlMessage::NeedContext { fid } => {
            let Some(id) = wire::wire_id_for_fid(fid) else {
                counters::ctl_stream_drop();
                return;
            };
            match rev2.registry.get(id) {
                // Re-arm the no-ACK context window: the receiver missed the
                // first K copies, so the next payloads carry the binding form
                // again (the sender self-confirms after K, see
                // `FlowBinding::take_context_slot`).
                Some(binding) => {
                    binding.rearm_context();
                    counters::need_context_rx();
                }
                // The peer asks for a flow this generation never installed:
                // nothing to re-arm (its `REJECT`/re-`OPEN` path owns that).
                None => counters::rx_unknown_id(),
            }
        }
        // The server is shedding this connection on its side: the client's own
        // egress/reconnect path is authoritative for its flows, so this only
        // feeds observability.
        CtlMessage::Goaway => counters::ctl_stream_drop(),
        // Server→client is REJECT/SESS_CLOSE/NEED_CONTEXT/GOAWAY; the rest are
        // client→server directions and are a protocol anomaly here.
        CtlMessage::AssocClose { .. } => counters::ctl_stream_drop(),
    }
}

/// Spawn the generation's rev3 control-stream task.
///
/// One task per published generation owns the client-opened bidi stream (marker
/// `0xFF`): it opens it immediately after the generation is published — so on a
/// resumed connection the marker and the first messages ride the 0-RTT flight —
/// writes every message the packet path queues through [`ConnRev2::send_ctl`]
/// in order, and forwards inbound messages to the dispatcher loop, which owns
/// the flow/stager/reassembly state. QUIC supplies reliability and ordering, so
/// this direction has no app-level retry and no rate budget.
///
/// The task ends when the stream fails (the connection died) or when the
/// dispatcher stops consuming (generation replaced); the next generation opens
/// its own stream.
fn spawn_ctl_stream(
    conn: quinn::Connection,
    mut to_server: tokio::sync::mpsc::Receiver<CtlMessage>,
    to_dispatcher: tokio::sync::mpsc::Sender<CtlMessage>,
) {
    tokio::spawn(async move {
        let Ok((mut sender, mut receiver)) = ctl_stream::open_client_stream(&conn).await else {
            // No control plane on this generation (connection already dead).
            return;
        };
        loop {
            tokio::select! {
                msg = to_server.recv() => match msg {
                    Some(msg) => {
                        if sender.send(msg).await.is_err() {
                            return;
                        }
                    }
                    // The generation's connection state is gone: finish the
                    // stream so the server sees a clean control-plane teardown.
                    None => {
                        let _ = sender.into_inner().finish();
                        return;
                    }
                },
                msg = receiver.recv() => match msg {
                    Ok(Some(msg)) => {
                        // Bounded, and awaited: a peer that outruns the
                        // dispatcher stalls its own reliable stream instead of
                        // growing this queue (the same backpressure the server
                        // applies to its inbound handoff).
                        if to_dispatcher.send(msg).await.is_err() {
                            return;
                        }
                    }
                    // Clean EOF or a stream error: the connection path
                    // (watchdog/reconnect) owns the outcome.
                    _ => return,
                },
            }
        }
    });
}

/// One rev2 `DATA` frame: steady (`wire_id` only), `OPEN`/`OPEN|SRC`, or
/// `INLINE` (session + address).
fn dispatch_r2_data(
    rev2: &ConnRev2,
    conn: Option<&quinn::Connection>,
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    d: &Bytes,
    out: &mut Vec<StagedReply>,
) -> usize {
    let wire = rev2.wire();
    let Ok(f) = wire::decode_data(wire, d) else {
        counters::rx_drop();
        return 0;
    };
    let Some(id) = f.wire_id else {
        // INLINE: no flow bound, self-describing session + address. The
        // sender's fail-safe when its table is full.
        let (Some(sess), Some(addr)) = (f.sess, f.addr) else {
            counters::rx_drop();
            return 0;
        };
        let Some((entry, app)) = r2_lookup(cache, hub, sess) else {
            return 0;
        };
        let Some(dst) = r2_addr_dst(addr) else {
            dgram_drops::bump(&dgram_drops::REFUSED);
            counters::rx_drop();
            return 0;
        };
        let payload = d.slice_ref(f.payload);
        udp_stats::payload(payload.len());
        counters::rx_frame();
        out.push(stage_reply(&entry, app, dst, payload));
        return 1;
    };
    counters::rx_frame();
    let binding = match rev2.registry.get(id) {
        Some(binding) => binding,
        None => {
            // rev3 no-ACK: a steady frame for an unknown server-owned id means
            // our copy of that reply flow's binding context was lost (open or
            // frame loss). Ask for the context instead of rejecting a flow the
            // server still believes in; the frame itself is dropped.
            if wire == Wire::Rev3 && f.addr.is_none() && r2::wire_id_server_owned(id) {
                counters::rx_unknown_id();
                repair_unknown_flow(rev2, id);
                return 0;
            }
            // Unknown id: only a server-owned standalone OPEN can install a
            // flow (full-cone / unsolicited reply). An unknown client-owned id
            // or an address-less steady frame is still a drop — never guess.
            match install_server_flow(rev2, conn, id, f.sess, f.addr) {
                Some(binding) => binding,
                None => {
                    counters::rx_unknown_id();
                    return 0;
                }
            }
        }
    };
    // An extended frame carries the session as a cross-check: ids are
    // connection-scoped, so a mismatch names the wrong association and is
    // dropped instead of delivered.
    if f.sess.is_some_and(|s| s != binding.session) {
        counters::rx_drop();
        return 0;
    }
    // `OPEN|SRC` is how the server teaches the client the actual reply source
    // (domain flow binding, port change, anycast): record it for the SOCKS5
    // reply header, exactly like the shipped inline path. On rev2 the frame is
    // confirmed with `CTL FLOW_ACK` (the peer re-sends until it arrives); rev3
    // has no ACK plane — the server repeats the context itself for the first
    // K replies, so the client only records the source.
    if f.src
        && let Some(src) = f.addr
        && let Some(src) = r2_addr_dst(src)
    {
        binding.set_reply_src(src);
        if wire == Wire::Rev2 {
            send_flow_ack(conn, binding.wire_id);
        }
    }
    // Any compressed downlink proves the server installed this id: that is the
    // implicit ACK the rev2 uplink waits for (a pure-uplink flow otherwise
    // relies on `CTL FLOW_ACK`); on rev3 it simply confirms the binding early.
    binding.mark_open();
    let Some(dst) = r2_reply_dst(&binding) else {
        dgram_drops::bump(&dgram_drops::REFUSED);
        counters::rx_drop();
        return 0;
    };
    let Some((entry, app)) = r2_lookup(cache, hub, binding.session) else {
        return 0;
    };
    let payload = d.slice_ref(f.payload);
    udp_stats::payload(payload.len());
    out.push(stage_reply(&entry, app, dst, payload));
    1
}

/// One rev2 `TRAIN` frame: a same-flow or dict run of already-open flows.
///
/// Items that name an uninstalled id are dropped individually (counted), never
/// mapped to a guessed session: the codec has already validated the frame
/// shape and item bounds, so the loop cannot read past the datagram.
///
/// **Frame-batched id resolution** (PERF-9, mirroring the server's ingress):
/// one `FlowRegistry::get_batch` read-lock hold fills one stack slot per
/// *distinct* id, instead of one `registry.get` read-lock per item. The dedupe
/// is a fixed open-addressing table — the codec bounds the item count at
/// [`r2::R2_MAX_TRAIN_ITEMS`] — so no allocation and one probe per item in the
/// common all-distinct case.
///
/// Per-item work below is hoisted because a run frame is *made of* repeats:
///
/// * reply-dst derivation for *deliverable* items (`mark_open` +
///   `r2_reply_dst`) runs once per distinct id: the per-slot memo keeps
///   `(session, reply_dst)`. Drop accounting deliberately stays **per item**:
///   an uninstalled id or a no-destination item is dropped and counted exactly
///   as often as it occurs in the frame, precisely as before;
/// * `r2_lookup` (a `Weak` upgrade, an `is_alive` probe and an app read) runs
///   once per session *run*: the memo holds the last staged item's
///   `(sess, entry, app)`, and a frame's items of one session are consecutive
///   because the sender packs them that way;
/// * the staged reply becomes a [`stage_reply_follow`] (relay `Arc` inherited
///   by the flush) after a run's head, so N same-session items pay one relay
///   clone instead of N.
///
/// Per-item delivery accounting is unchanged: every item whose id is not
/// installed and every item with no reply destination is still counted per
/// occurrence; `mark_replied` keeps its per-frame shape, `lookup` side effects
/// (unknown-session bumps) and staging order stay as before. Follower `None`s
/// only ever follow this frame's own run head (the memo starts empty per frame),
/// which is what `flush_staged`'s run-head invariant requires.
fn dispatch_r2_train(
    rev2: &ConnRev2,
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    d: &Bytes,
    out: &mut Vec<StagedReply>,
) -> usize {
    let Ok(t) = wire::decode_train(rev2.wire(), d) else {
        counters::rx_drop();
        return 0;
    };
    // Pass 1: dedupe the frame's ids into a fixed slot table.
    const TRAIN_MAX: usize = r2::R2_MAX_TRAIN_ITEMS;
    const TRAIN_HASH_CAP: usize = 128; // power of two, >= 2 * TRAIN_MAX
    let mut slots: [(u32, Option<Arc<FlowBinding>>); TRAIN_MAX] =
        std::array::from_fn(|_| (0, None));
    let mut slot_of: [u16; TRAIN_HASH_CAP] = [u16::MAX; TRAIN_HASH_CAP];
    let mut item_slot: [u16; TRAIN_MAX] = [0; TRAIN_MAX];
    let mut n_slots = 0usize;
    for (i, (wire_id, _)) in t.items().enumerate() {
        debug_assert!(i < TRAIN_MAX, "the codec bounds the train item count");
        let mut h = (wire_id.wrapping_mul(0x9E37_79B1) as usize) & (TRAIN_HASH_CAP - 1);
        let slot = loop {
            let s = slot_of[h];
            if s == u16::MAX {
                let s = n_slots as u16;
                n_slots += 1;
                slot_of[h] = s;
                slots[usize::from(s)] = (wire_id, None);
                break s;
            }
            if slots[usize::from(s)].0 == wire_id {
                break s;
            }
            h = (h + 1) & (TRAIN_HASH_CAP - 1);
        };
        item_slot[i] = slot;
    }
    // One read-lock hold for the whole frame.
    rev2.registry.get_batch(&mut slots[..n_slots]);

    // Per-slot resolution memo: a deliverable id is resolved once (session +
    // reply destination); a miss is re-counted per item below, keeping the
    // pre-batching drop accounting exact.
    #[derive(Clone, Copy)]
    enum Resolved {
        Pending,
        Hit {
            sess: u32,
            dst: SocketAddr,
        },
        /// Uninstalled id: skipped (and counted) per item, but the rev3 repair
        /// hint is sent at most once per frame for it.
        Unknown,
    }
    let mut resolved: [Resolved; TRAIN_MAX] = std::array::from_fn(|_| Resolved::Pending);

    let mut staged = 0usize;
    // The association of the last item actually staged into `out`: its
    // session, the entry Arc (already upgraded by the lookup — kept alive so
    // the follower call needs nothing but a reference) and its app address.
    let mut last_pushed: Option<(u32, Arc<AssocEntry>, SocketAddr)> = None;
    for (i, (_id, payload)) in t.items().enumerate() {
        let slot = usize::from(item_slot[i]);
        let (sess, dst) = match resolved[slot] {
            Resolved::Hit { sess, dst } => (sess, dst),
            Resolved::Unknown => {
                // Already reported for this frame; the counter stays per item
                // (the rev2 drop accounting contract).
                counters::rx_unknown_id();
                continue;
            }
            Resolved::Pending => match slots[slot].1.as_ref() {
                None => {
                    // TRAIN items never install a flow: a run carries no
                    // address, so an uninstalled id is a stale frame
                    // (counted per item, as before), never a new binding.
                    // rev3: a server-owned id we do not hold is a lost
                    // reply-flow context — ask for it once per frame.
                    if rev2.wire() == Wire::Rev3 && r2::wire_id_server_owned(slots[slot].0) {
                        repair_unknown_flow(rev2, slots[slot].0);
                    }
                    resolved[slot] = Resolved::Unknown;
                    counters::rx_unknown_id();
                    continue;
                }
                Some(binding) => {
                    binding.mark_open();
                    let Some(dst) = r2_reply_dst(binding) else {
                        dgram_drops::bump(&dgram_drops::REFUSED);
                        counters::rx_drop();
                        continue;
                    };
                    let sess = binding.session;
                    resolved[slot] = Resolved::Hit { sess, dst };
                    (sess, dst)
                }
            },
        };
        // Same association as the previous staged item: skip the lookup (the
        // entry probe and its counters) entirely and stage as a follower.
        if let Some((psess, pentry, papp)) = last_pushed.as_ref()
            && *psess == sess
        {
            udp_stats::payload(payload.len());
            counters::rx_frame();
            out.push(stage_reply_follow(pentry, *papp, dst, d.slice_ref(payload)));
            staged += 1;
            continue;
        }
        let Some((entry, app)) = r2_lookup(cache, hub, sess) else {
            continue;
        };
        udp_stats::payload(payload.len());
        counters::rx_frame();
        out.push(stage_reply(&entry, app, dst, d.slice_ref(payload)));
        last_pushed = Some((sess, entry, app));
        staged += 1;
    }
    staged
}

/// One rev2 `FRAG` frame: feed it to the per-connection reassembler and stage
/// the completed payload exactly like a `DATA` frame of the same shape.
///
/// The reassembler owns every bound (8 KiB payload, 256 partials, 256 KiB held,
/// 2 s timeout), so a peer that sends one fragment and stops cannot pin memory
/// here — the dispatcher's existing reassembly tick expires it.
#[allow(clippy::too_many_arguments)]
fn dispatch_r2_frag(
    rev2: &ConnRev2,
    conn: Option<&quinn::Connection>,
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    r2_reasm: &mut R2Reassembler,
    d: &Bytes,
    out: &mut Vec<StagedReply>,
    now_ms: u64,
) -> usize {
    let wire = rev2.wire();
    let Ok(f) = wire::decode_frag(wire, d) else {
        counters::rx_drop();
        return 0;
    };
    counters::frag_rx();
    // The reassembler is wire-configured too, but the view is already
    // revision-neutral (internal wire ids), so the same keying/bounds apply.
    let Some(a) = r2_reasm.push_view(d, &f, now_ms) else {
        // Partial (or a refused/duplicate fragment): nothing to deliver yet.
        return 0;
    };
    counters::frag_complete();
    let R2Assembled {
        wire_id,
        sess,
        addr,
        src,
        payload,
    } = a;
    let (sess, dst) = match wire_id {
        Some(id) => {
            let binding = match rev2.registry.get(id) {
                Some(binding) => binding,
                None => {
                    // rev3 no-ACK: a completed steady fragment set for an
                    // unknown server-owned id is a lost reply-flow context —
                    // ask for it (the reassembled payload is dropped).
                    if wire == Wire::Rev3 && addr.is_none() && r2::wire_id_server_owned(id) {
                        counters::rx_unknown_id();
                        repair_unknown_flow(rev2, id);
                        return 0;
                    }
                    // A fragmented server-owned OPEN|SRC is self-describing
                    // through its first fragment, so it installs like the
                    // single-frame form; a steady fragment set (no address)
                    // or an unknown client-owned id is still a drop.
                    match install_server_flow(
                        rev2,
                        conn,
                        id,
                        sess,
                        addr.as_ref().map(TargetAddr::as_ref),
                    ) {
                        Some(binding) => binding,
                        None => {
                            counters::rx_unknown_id();
                            return 0;
                        }
                    }
                }
            };
            // Ids are connection-scoped; an inline context carrying another
            // session would name the wrong association.
            if sess.is_some_and(|s| s != binding.session) {
                counters::rx_drop();
                return 0;
            }
            // A compressed downlink for this id is the implicit ACK.
            binding.mark_open();
            let src_dst = if src {
                addr.as_ref().and_then(|a| r2_addr_dst(a.as_ref()))
            } else {
                None
            };
            if let Some(src_addr) = src_dst {
                // `OPEN|SRC` (or a rebind) teaches the actual reply source.
                // rev2 confirms it so the peer can stop re-sending the binding
                // frame; rev3 has no ACK plane (the server repeats the context
                // for the first K replies itself).
                binding.set_reply_src(src_addr);
                if wire == Wire::Rev2 {
                    send_flow_ack(conn, binding.wire_id);
                }
            }
            let Some(dst) = src_dst.or_else(|| r2_reply_dst(&binding)) else {
                dgram_drops::bump(&dgram_drops::REFUSED);
                counters::rx_drop();
                return 0;
            };
            (binding.session, dst)
        }
        None => {
            // The self-describing `INLINE` fail-safe: session + address on
            // every fragment (the reassembler already refused a partial whose
            // context disagreed).
            let (Some(sess), Some(addr)) = (sess, addr) else {
                counters::rx_drop();
                return 0;
            };
            let Some(dst) = r2_addr_dst(addr.as_ref()) else {
                dgram_drops::bump(&dgram_drops::REFUSED);
                counters::rx_drop();
                return 0;
            };
            (sess, dst)
        }
    };
    let Some((entry, app)) = r2_lookup(cache, hub, sess) else {
        return 0;
    };
    // One booking for the whole reassembled payload, exactly like one `DATA`
    // frame (the fragment frames themselves are not payloads).
    udp_stats::payload(payload.len());
    counters::rx_frame();
    out.push(stage_reply(&entry, app, dst, payload));
    1
}

/// Decode and route one inbound MQP-3 rev2 or rev3 datagram.
///
/// Returns the number of replies staged. rev2 is dispatched *before* the
/// legacy v3/MQP-2 paths (which the caller selects by first byte): the two wire
/// generations intentionally share a rev2 connection during staging, and the
/// safe first-byte ranges (`0x0X` vs `0x1X..`) keep them disjoint. A **rev3**
/// connection never runs the legacy fallbacks: its DATAGRAM plane carries only
/// rev3 frames (the TCP plane is stream-native), so an unclassifiable byte is a
/// malformed frame, not an old-generation one.
///
/// Test entry point: it classifies the first byte and reads the coarse clock
/// itself. The production dispatcher classifies **once** per datagram and
/// passes its drain-burst clock read through [`dispatch_inbound`] (W8a).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_r2(
    rev2: &ConnRev2,
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    r2_reasm: &mut R2Reassembler,
    conn: Option<&quinn::Connection>,
    d: Bytes,
    out: &mut Vec<StagedReply>,
) -> usize {
    let Some(kind) = wire::kind(rev2.wire(), &d) else {
        return 0;
    };
    dispatch_frame_kind(
        kind,
        rev2,
        cache,
        hub,
        r2_reasm,
        conn,
        d,
        out,
        coarse_millis(),
    )
}

/// [`dispatch_r2`] on an already-classified first byte and an already-read
/// coarse clock (W8a).
///
/// The [`FrameKind`] is the *only* thing the revision-aware first-byte
/// classification yields, so classifying in [`dispatch_inbound`] and passing it
/// here removes the second identical match; `now_ms` removes a
/// `coarse_millis()` per `CTL`/`FRAG` frame in favour of one per drain burst.
#[allow(clippy::too_many_arguments)]
fn dispatch_frame_kind(
    kind: FrameKind,
    rev2: &ConnRev2,
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    r2_reasm: &mut R2Reassembler,
    conn: Option<&quinn::Connection>,
    d: Bytes,
    out: &mut Vec<StagedReply>,
    now_ms: u64,
) -> usize {
    match kind {
        // Only rev2 classifies a DATAGRAM as control; rev3 control rides the
        // reliable stream (the handler has its own rev2 guard as well).
        FrameKind::Ctl => {
            handle_r2_ctl_at(rev2, hub, r2_reasm, &d, now_ms);
            0
        }
        FrameKind::Data => dispatch_r2_data(rev2, conn, cache, hub, &d, out),
        FrameKind::Train => dispatch_r2_train(rev2, cache, hub, &d, out),
        // Rev2 FRAG is reassembled here and never routed into the legacy
        // MQP-2 fragment path (the first-byte dispatch keeps them disjoint).
        FrameKind::Frag => dispatch_r2_frag(rev2, conn, cache, hub, r2_reasm, &d, out, now_ms),
    }
}

/// Route one inbound DATAGRAM: the connection's wire frames first, then (rev2
/// only) the legacy MQP-3/MQP-2/BATCH paths keyed by session.
///
/// `now_ms` is the caller's single coarse-clock read for the drain burst
/// (W8a); `CTL`/`FRAG` handling uses it instead of taking its own, and the
/// revision-aware classification below is the one the wire dispatcher consumes
/// (`dispatch_frame_kind`), so no datagram is classified twice.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_inbound(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    rev2: &ConnRev2,
    conn: Option<&quinn::Connection>,
    d: Bytes,
    reasm: &mut DgramReassembler,
    r2_reasm: &mut R2Reassembler,
    out: &mut Vec<StagedReply>,
    now_ms: u64,
) {
    if let Some(kind) = wire::kind(rev2.wire(), &d) {
        dispatch_frame_kind(kind, rev2, cache, hub, r2_reasm, conn, d, out, now_ms);
        return;
    }
    if rev2.wire() != Wire::Rev2 {
        // rev3 carries no legacy frames; a byte that is not a rev3 frame is
        // malformed, and falling into the MQP-2 decoder could only misparse it.
        counters::rx_drop();
        return;
    }
    let sess_of = |d: &Bytes| {
        dgram_sess(d)
            .or_else(|| batch_sess(d))
            .or_else(|| v3_sess(d))
    };
    match sess_of(&d) {
        Some(sess) => {
            dispatch_stage_multi(cache, hub, sess, d, reasm, out);
        }
        None => {
            dgram_drops::bump(&dgram_drops::REFUSED);
        }
    }
}

pub(crate) fn spawn_dispatcher(slot: ConnSlot, hub: Arc<UdpHub>) {
    tokio::spawn(async move {
        let mut gen_rx = slot.gen_rx.clone();
        // Backstop across consecutive dead reads, 100ms -> 1s cap. A read
        // error fires before the conn loop clears `live` + `bump_gen`, so a
        // fixed 10ms backstop spins every slot at 100Hz for the whole dead
        // window; exponential growth bounds it at ~10Hz then ~1Hz while
        // `gen_rx.changed()` keeps priority wakeup (fresh generation resets).
        let mut backoff = Duration::from_millis(100);
        loop {
            let conn = match slot.wait_conn(&mut gen_rx, Duration::from_secs(10)).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            // MQP-3 rev2 state of **this** generation, read coherently with the
            // connection handle (C10). `wait_conn` can return a connection that
            // a death+redial replaces before the state load below; pairing that
            // old connection with the next generation's id tables would resolve
            // a buffered old-generation frame against unrelated live bindings
            // (client ids restart at 1 on every dial). `rev2_for` re-checks the
            // publication, and a mismatch waits for the next generation event
            // instead of dispatching against a neighbouring generation.
            let Some(rev2) = slot.rev2_for(&conn) else {
                tokio::select! {
                    _ = gen_rx.changed() => {}
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                continue;
            };
            let reader = conn.read_datagram();
            tokio::pin!(reader);
            let mut cache: [DispatchSlot; DISPATCH_CACHE] = std::array::from_fn(|_| DispatchSlot {
                sess: u32::MAX,
                entry: None,
                app: None,
            });
            // One reassembler for the whole connection, exactly as the server's
            // datagram reader has always used: it is keyed by `(sess, id)`, so a
            // per-association copy would only duplicate state. Each pool slot
            // keeps its own, which is correct because a payload's fragments all
            // travel on the connection that carried them.
            let mut reasm = DgramReassembler::new();
            // The rev2 reassembler, one per connection like the legacy one:
            // its key is connection-scoped (`wire_id`/`INLINE`+session), so a
            // per-association copy would only duplicate state and the same
            // payload's frames all travel on this connection.
            let mut r2_reasm = R2Reassembler::new_with_wire(rev2.wire());
            // rev3 control plane: one client-opened bidi stream per generation.
            // The dispatcher loop owns the flow/stager/reassembly state, so the
            // stream task only does I/O: it writes what `ConnRev2::send_ctl`
            // queues and forwards inbound messages here. A rev2 generation keeps
            // a channel whose sender lives in `_ctl_keepalive`, so the select arm
            // below simply never becomes ready and no stream is opened.
            //
            // Both directions are **bounded** at `CTL_QUEUE`: the outbound one
            // because its producer is the packet path at the peer's frame rate
            // (`send_ctl` drops and counts instead of growing), the inbound one
            // because a peer that floods the control stream would otherwise
            // outrun this loop — the stream task awaits its `send`, so the
            // backlog becomes QUIC flow control on the peer's own stream.
            let (dispatch_ctl_tx, mut dispatch_ctl_rx) =
                tokio::sync::mpsc::channel::<CtlMessage>(rev2::CTL_QUEUE);
            let wire = rev2.wire();
            let _ctl_keepalive = if wire == Wire::Rev3 {
                let (to_server_tx, to_server_rx) =
                    tokio::sync::mpsc::channel::<CtlMessage>(rev2::CTL_QUEUE);
                // Install synchronously, before the first inbound datagram can
                // be dispatched: a repair or a close queued from then on always
                // has a writer.
                rev2.install_ctl_writer(to_server_tx);
                spawn_ctl_stream(conn.clone(), to_server_rx, dispatch_ctl_tx);
                None
            } else {
                Some(dispatch_ctl_tx)
            };
            // Receiver-side control budget (a hostile/buggy peer can flood
            // idempotent messages even on a reliable stream).
            let mut ctl_rx_rate = CtlRate::default_budget();
            // `push` only runs when a fragment arrives, so a peer that sends
            // fragments and then goes quiet would pin its partials for the
            // connection's lifetime; this tick is what makes `FRAG_TIMEOUT_MS` a
            // real deadline (see `DgramReassembler::expire`). It is armed **only
            // while held bytes exist** (the `if` guard on the select branch
            // below, the same guard the server's reader uses): a connection with
            // no partial reassembly would otherwise wake its slot 2x/s forever
            // for a sweep that can never free anything.
            let mut reasm_tick =
                tokio::time::interval(Duration::from_millis(FRAG_SWEEP_INTERVAL_MS));
            reasm_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut reader_failed = false;
            // Staged replies of one drain burst plus their reused header
            // buffer: grouped by (sock, app) at flush and cleared per burst,
            // so this queueing is bounded by LAST_HOP_DRAIN, never unbounded.
            // `hdrs` holds only the per-reply SOCKS5 headers (<= 22 B each, so
            // 704 B for a full burst) — the payloads are borrowed from the
            // staged replies, not copied.
            let mut staged: Vec<StagedReply> = Vec::with_capacity(LAST_HOP_DRAIN);
            let mut hdrs: Vec<u8> = Vec::with_capacity(LAST_HOP_DRAIN * SOCKS_UDP_HDR_MAX);
            let mut offs: Vec<(usize, usize)> = Vec::with_capacity(LAST_HOP_DRAIN);
            loop {
                tokio::select! {
                    d = &mut reader => {
                        let head: Bytes = match d {
                            Ok(d) => d,
                            Err(_) => { reader_failed = true; break; }
                        };
                        // Bounded QUIC-ingress drain: the awaited head plus up
                        // to LAST_HOP_DRAIN - 1 already-buffered datagrams via
                        // `now_or_never` (`read_datagram` is cancel-safe: a
                        // buffered datagram returns before its first await
                        // point, and a Pending probe parks nothing — the noop
                        // waker drops with it). One wakeup moves up to 32
                        // replies; a drained connection error breaks out after
                        // flushing what was staged.
                        //
                        // W8a: one coarse-clock read per drain burst, shared by
                        // the rev2 `CTL` rate budget and the FRAG reassembler
                        // deadline, instead of one per frame.
                        let now_ms = coarse_millis();
                        let mut drained = 1usize;
                        if staged.len() < LAST_HOP_DRAIN * 2 {
                            dispatch_inbound(
                                &mut cache,
                                &hub,
                                &rev2,
                                Some(&conn),
                                head,
                                &mut reasm,
                                &mut r2_reasm,
                                &mut staged,
                                now_ms,
                            );
                        }
                        for _ in 1..LAST_HOP_DRAIN {
                            if staged.len() >= LAST_HOP_DRAIN * 2 {
                                break;
                            }
                            match reader.as_mut().now_or_never() {
                                Some(Ok(d)) => {
                                    drained += 1;
                                    dispatch_inbound(
                                        &mut cache,
                                        &hub,
                                        &rev2,
                                        Some(&conn),
                                        d,
                                        &mut reasm,
                                        &mut r2_reasm,
                                        &mut staged,
                                        now_ms,
                                    );
                                }
                                Some(Err(_)) => { reader_failed = true; break; }
                                None => break,
                            }
                        }
                        record_drain_batch(drained);
                        flush_staged(&mut staged, &mut hdrs, &mut offs);
                        // Saturation yields. Every extra datagram above is
                        // served by `now_or_never` with a noop waker, and quinn's
                        // `read_datagram` returns an already-buffered datagram
                        // before its first await point — so a *full* burst
                        // leaves this branch ready again immediately and the
                        // task would keep its worker indefinitely (Tokio only
                        // forces `Pending` once the task budget is spent, and
                        // none of this loop's branches consumes any). A full
                        // burst is by definition the saturated case, so that is
                        // exactly where the yield belongs; a partial burst
                        // already drained the peer, and the next `select!`
                        // parks as before.
                        if drained >= LAST_HOP_DRAIN {
                            tokio::task::yield_now().await;
                        }
                        if reader_failed {
                            break;
                        }
                    }
                    msg = dispatch_ctl_rx.recv() => {
                        if let Some(msg) = msg {
                            if ctl_rx_rate.allow(coarse_millis()) {
                                handle_r3_ctl(&rev2, &hub, &mut r2_reasm, msg);
                            } else {
                                counters::ctl_stream_drop();
                            }
                        }
                    }
                    _ = gen_rx.changed() => break,
                    _ = reasm_tick.tick(),
                        if reasm.held_bytes() > 0 || r2_reasm.held_bytes() > 0 =>
                    {
                        let now = coarse_millis();
                        reasm.expire(now);
                        r2_reasm.expire(now);
                    }
                }
            }
            if reader_failed {
                // A read error can fire before the connection loop clears the
                // live bit; without this, wait_conn would immediately hand back
                // the same dead connection and the dispatcher would busy-spin.
                // Wait for the generation bump, with an exponential backstop
                // (100ms -> 1s): gen_rx.changed() keeps priority wakeup so a
                // fresh connection resets immediately, while a dead window
                // that outlives several reads decays to ~1Hz instead of 100Hz.
                tokio::select! {
                    _ = gen_rx.changed() => {
                        backoff = Duration::from_millis(100);
                    }
                    _ = tokio::time::sleep(backoff) => {
                        backoff = (backoff * 2).min(Duration::from_secs(1));
                    }
                }
            } else {
                backoff = Duration::from_millis(100);
            }
        }
    });
}
