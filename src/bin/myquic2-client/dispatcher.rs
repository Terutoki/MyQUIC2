//! Inbound DATAGRAM dispatcher.
use super::*;

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
/// padding, x 4096) — noise against the 512 KiB of kernel socket caps each
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
/// plus its 2 x 256 KiB kernel buffers each — stayed open until a session id
/// colliding on the same index happened to arrive (or the connection was
/// redialed, which rebuilds the cache). Measured before the fix: 1200
/// short-lived associations left **1024** UDP fds open in the client, which on a
/// 1024-fd router exhausts the table by itself. Upgrading on a hit costs two
/// atomics (the `Weak` CAS and the `Arc` drop that follows it), not one, on a
/// path that already performs a `send_to`.
pub(crate) struct DispatchSlot {
    pub(crate) sess: u32,
    pub(crate) entry: Option<std::sync::Weak<AssocEntry>>,
}

/// Route one inbound DATAGRAM to its association, writing the relay socket
/// directly.
///
/// This is the pass-23 replacement for "push into the association's queue and let
/// its reply task do the work". Nothing per-session is mutable here: the
/// reassembler is keyed by `(sess, id)` and therefore connection-wide, and the
/// scratch buffer is reused across datagrams, so the escape path stays
/// allocation-free.
pub(crate) fn dispatch_one(
    cache: &mut [DispatchSlot; DISPATCH_CACHE],
    hub: &UdpHub,
    sess: u32,
    d: Bytes,
    reasm: &mut DgramReassembler,
    pkt: &mut bytes::BytesMut,
) {
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
    let entry = match cached {
        Some(e) => e,
        None => {
            // Miss, collision, torn-down association, or an upgrade that lost to
            // the association's exit: re-probe the hub.
            let Some(fresh) = hub.entry(sess) else {
                cache[idx] = DispatchSlot { sess, entry: None };
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
                return;
            };
            // `hub.entry` answers "is it published", not "is it alive": between
            // `AliveGuard` clearing the bit and `UdpHub::release` unpublishing
            // (and permanently, if that release is ever skipped) the map still
            // serves the entry. Without this filter the reply would be written
            // into a socket nobody reads, which is exactly what the cache-hit
            // path above filters with `is_alive`.
            if !fresh.is_alive() {
                cache[idx] = DispatchSlot { sess, entry: None };
                return;
            }
            cache[idx] = DispatchSlot {
                sess,
                entry: Some(Arc::downgrade(&fresh)),
            };
            fresh
        }
    };
    // `ArcSwapOption::load` borrows, so this costs no refcount traffic on the
    // per-datagram path; the 200 ms app-address cache the reply task needed is
    // gone with the lock it was working around.
    let Some(app) = entry.app() else {
        udp_write::no_app();
        return;
    };

    if d.first() == Some(&MQP_DGRAM_FRAG) {
        let Ok(f) = decode_fragment(&d) else {
            return;
        };
        let Some((_, a, whole)) = reasm.push(&f, mono_millis()) else {
            return;
        };
        udp_stats::payload(whole.len());
        match a.as_ref() {
            TargetAddrRef::Ip(dst) => send_reply_addr(&entry, app, dst, &whole, pkt),
            TargetAddrRef::Domain(h, p) => match lookup_cached_fast(h, p) {
                CachedLookup::Addr(dst) => send_reply_addr(&entry, app, dst, &whole, pkt),
                // Unreachable from a conforming server (replies are always
                // IP-form); counted rather than silently dropped so a
                // future or hostile peer cannot create invisible loss here.
                CachedLookup::Negative | CachedLookup::Unknown => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                }
            },
        }
        return;
    }

    let Ok((_, a, p)) = decode_datagram_ref(&d) else {
        return;
    };
    let off = d.len() - p.len();
    let payload = d.slice(off..);
    udp_stats::payload(payload.len());
    match a {
        TargetAddrRef::Ip(dst) => send_reply_addr(&entry, app, dst, &payload, pkt),
        TargetAddrRef::Domain(h, p) => {
            // The server always echoes replies with an IP-form source address, so
            // this branch is defensive; the negative cache is still consulted
            // synchronously so a known-bad name never spawns a resolver task.
            match lookup_cached_fast(h, p) {
                CachedLookup::Negative => {
                    dgram_drops::bump(&dgram_drops::REFUSED);
                }
                CachedLookup::Addr(dst) => send_reply_addr(&entry, app, dst, &payload, pkt),
                CachedLookup::Unknown => {
                    // Both of these are counted. The server's equivalent drop
                    // (`forward_server_dgram`) charges `DNS_INFLIGHT`, and an
                    // uncounted drop here showed up only as missing replies: a
                    // 40-datagram burst at one uncached name silently loses 39
                    // of them, and under contention that can be a sustained
                    // loss with no counter and no log at all. A contended
                    // shard mutex is unknown, never inflight: it is counted
                    // apart as `DNS_CONTENTION` and falls through to the
                    // limiter-bounded spawn below instead of parking on the
                    // shard mutex (same tri-state contract as the server).
                    match dns_inflight_status(h, p) {
                        DnsInflight::Inflight => {
                            dgram_drops::bump(&dgram_drops::DNS_INFLIGHT);
                            return;
                        }
                        DnsInflight::Contended => {
                            dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
                        }
                        DnsInflight::Absent => {}
                    }
                    if dns_slow_path_limiter().available_permits() == 0 {
                        dgram_drops::bump(&dgram_drops::SESSION_FULL);
                        return;
                    }
                    let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            dgram_drops::bump(&dgram_drops::SESSION_FULL);
                            return;
                        }
                    };
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
                                None => return,
                            },
                            Err(e) => {
                                if myquic2::is_dns_contended(&e) {
                                    dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
                                }
                                return;
                            }
                        };
                        let mut pkt = bytes::BytesMut::with_capacity(256);
                        send_reply(&entry, dst, &payload, &mut pkt);
                    });
                }
            }
        }
    }
}

pub(crate) fn spawn_dispatcher(slot: ConnSlot, hub: Arc<UdpHub>) {
    tokio::spawn(async move {
        let mut gen = slot.gen_rx.clone();
        // Backstop across consecutive dead reads, 100ms -> 1s cap. A read
        // error fires before the conn loop clears `live` + `bump_gen`, so a
        // fixed 10ms backstop spins every slot at 100Hz for the whole dead
        // window; exponential growth bounds it at ~10Hz then ~1Hz while
        // `gen.changed()` keeps priority wakeup (fresh generation resets).
        let mut backoff = Duration::from_millis(100);
        loop {
            let conn = match slot.wait_conn(&mut gen, Duration::from_secs(10)).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let reader = conn.read_datagram();
            tokio::pin!(reader);
            let mut cache: [DispatchSlot; DISPATCH_CACHE] = std::array::from_fn(|_| DispatchSlot {
                sess: u32::MAX,
                entry: None,
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
            let mut pkt = bytes::BytesMut::with_capacity(256);
            let mut reader_failed = false;
            loop {
                tokio::select! {
                    d = &mut reader => {
                        let d: Bytes = match d {
                            Ok(d) => d,
                            Err(_) => { reader_failed = true; break; }
                        };
                        let Some(sess) = dgram_sess(&d) else {
                            continue;
                        };
                        dispatch_one(&mut cache, &hub, sess, d, &mut reasm, &mut pkt);
                    }
                    _ = gen.changed() => break,
                    _ = reasm_tick.tick() => { reasm.expire(mono_millis()); }
                }
            }
            if reader_failed {
                // A read error can fire before the connection loop clears the
                // live bit; without this, wait_conn would immediately hand back
                // the same dead connection and the dispatcher would busy-spin.
                // Wait for the generation bump, with an exponential backstop
                // (100ms -> 1s): gen.changed() keeps priority wakeup so a
                // fresh connection resets immediately, while a dead window
                // that outlives several reads decays to ~1Hz instead of 100Hz.
                tokio::select! {
                    _ = gen.changed() => {
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
