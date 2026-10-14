//! Inbound DATAGRAM dispatcher.
use super::*;
use futures_util::future::FutureExt as _;

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
/// under churn, 100% for a fresh consecutive window. Costs 64 KiB per
/// dispatcher (`DispatchSlot` is a `u32` plus an `Option<Weak>`, 16 B with
/// padding, x 4096) — noise against the ~64 KiB of kernel socket caps each
/// association already carries.
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
pub(crate) struct StagedReply {
    pub(crate) sock: Arc<tokio::net::UdpSocket>,
    pub(crate) app: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) payload: Bytes,
}

fn stage_reply(
    entry: &AssocEntry,
    app: SocketAddr,
    dst: SocketAddr,
    payload: Bytes,
) -> StagedReply {
    entry.mark_replied();
    StagedReply {
        sock: entry.relay.clone(),
        app,
        dst,
        payload,
    }
}

fn lookup_entry(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
) -> Option<(Arc<AssocEntry>, SocketAddr)> {
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
                return None;
            };
            if !fresh.is_alive() {
                cache[idx] = DispatchSlot {
                    sess,
                    entry: None,
                    app: None,
                };
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
    app.map(|a| (entry, a))
}

/// Batch-capable staging: routes one QUIC DATAGRAM that may hold 1 app payload
/// (0x02) or N packed payloads (0x06 BATCH). Single frames behave
/// exactly like [`dispatch_stage`]; batch frames stage one reply per item.
/// Returns the number of replies staged (0 = dropped or handed to a resolver).
pub(crate) fn dispatch_stage_multi(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
    d: Bytes,
    reasm: &mut DgramReassembler,
    out: &mut Vec<StagedReply>,
) -> usize {
    if is_batch(&d) {
        let Ok(b) = decode_batch(&d) else {
            return 0;
        };
        if b.sess != sess {
            dgram_drops::bump(&dgram_drops::REFUSED);
            return 0;
        }
        let Some((entry, app)) = lookup_entry(cache, hub, sess) else {
            udp_write::no_app();
            return 0;
        };
        match b.addr {
            TargetAddrRef::Ip(dst) => {
                // One liveness flag per frame, not per item: every item of a
                // batch shares the association, `mark_replied` is an
                // idempotent relaxed store, and its only consumer folds it
                // into the idle stamp at the association's own tick.
                entry.mark_replied();
                for p in b.payloads() {
                    udp_stats::payload(p.len());
                    out.push(StagedReply {
                        sock: entry.relay.clone(),
                        app,
                        dst,
                        payload: d.slice_ref(p),
                    });
                }
                return b.len();
            }
            TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
                CachedLookup::Addr(dst) => {
                    entry.mark_replied();
                    for q in b.payloads() {
                        udp_stats::payload(q.len());
                        out.push(StagedReply {
                            sock: entry.relay.clone(),
                            app,
                            dst,
                            payload: d.slice_ref(q),
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
    pkt.truncate(0);
    encode_reply(pkt, s.dst, &s.payload);
    udp_try_send_slice(&s.sock, map_for_dual(s.app), &pkt[..]);
}

/// Flush staged replies grouped by consecutive `(sock, app)` runs.
///
/// Each run shares one `sendmmsg` on Linux (one `try_send_to` per frame on the
/// portable fallback); runs flush in encounter order, so reply order is
/// preserved exactly. `hdrs`/`offs` are reused across bursts (cleared, never
/// freed) and the `refs` array lives on the stack, so the steady path allocates
/// nothing per reply.
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
        let mut j = i + 1;
        while j < staged.len()
            && Arc::ptr_eq(&staged[j].sock, &staged[i].sock)
            && staged[j].app == staged[i].app
        {
            j += 1;
        }
        let mut k = i;
        while k < j {
            let n = (j - k).min(LAST_HOP_DRAIN);
            hdrs.clear();
            offs.clear();
            for s in &staged[k..k + n] {
                let start = hdrs.len();
                encode_reply_header(hdrs, s.dst);
                offs.push((start, hdrs.len() - start));
            }
            let mut refs: [SendFrame<'_>; LAST_HOP_DRAIN] = [(&[], &[]); LAST_HOP_DRAIN];
            for ((r, (o, l)), s) in refs.iter_mut().zip(offs.iter()).zip(&staged[k..k + n]) {
                *r = (&hdrs[*o..*o + *l], &s.payload[..]);
            }
            udp_try_send_grouped(&staged[i].sock, map_for_dual(staged[i].app), &refs[..n]);
            k += n;
        }
        i = j;
    }
    staged.clear();
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
            // `push` only runs when a fragment arrives, so a peer that sends
            // fragments and then goes quiet would pin its partials for the
            // connection's lifetime; this tick is what makes `FRAG_TIMEOUT_MS` a
            // real deadline (see `DgramReassembler::expire`).
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
                        let mut drained = 1usize;
                        let sess_of = |d: &Bytes| dgram_sess(d).or_else(|| batch_sess(d));
                        if let Some(sess) = sess_of(&head) {
                            if staged.len() < LAST_HOP_DRAIN * 2 {
                                dispatch_stage_multi(
                                    &mut cache,
                                    &hub,
                                    sess,
                                    head,
                                    &mut reasm,
                                    &mut staged,
                                );
                            }
                        } else {
                            dgram_drops::bump(&dgram_drops::REFUSED);
                        }
                        for _ in 1..LAST_HOP_DRAIN {
                            if staged.len() >= LAST_HOP_DRAIN * 2 {
                                break;
                            }
                            match reader.as_mut().now_or_never() {
                                Some(Ok(d)) => {
                                    drained += 1;
                                    if let Some(sess) = sess_of(&d) {
                                        dispatch_stage_multi(
                                            &mut cache,
                                            &hub,
                                            sess,
                                            d,
                                            &mut reasm,
                                            &mut staged,
                                        );
                                    } else {
                                        dgram_drops::bump(&dgram_drops::REFUSED);
                                    }
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
                    _ = gen_rx.changed() => break,
                    _ = reasm_tick.tick() => { reasm.expire(coarse_millis()); }
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
