//! Per-session UDP reader and session creation.
use super::*;

/// Userspace receive buffer per session reader: one full-protocol-cap datagram
/// plus the truncation-detection slack byte (`n == buf.len()` means the kernel
/// truncated, so the length is load-bearing).
pub(crate) const SESS_RECV_BUF_LEN: usize = UDP_RECV_MAX + UDP_RECV_SLACK;

/// Compile-time userspace bound: one reader buffer per session, so the live
/// set can never exceed the session cap times it (~67 MiB worst case).
const _: () = assert!(SESS_RECV_BUF_LEN == UDP_RECV_MAX + UDP_RECV_SLACK);
const _: () = assert!(
    MAX_SESSIONS_GLOBAL * SESS_RECV_BUF_LEN <= 70 * 1024 * 1024,
    "8192 x 8 KiB must stay a bounded worst case"
);

/// Idle session-reader buffers retained per worker thread.
///
/// Each *live* reader holds its buffer for life, so the live set is already
/// bounded by `MAX_SESSIONS_GLOBAL` (`SESS_RECV_BUF_LEN` each, ~67 MiB worst
/// case) and sockets stay strictly per-session — pooled here are only the
/// userspace byte buffers, never sockets, tasks or permits. What churn
/// multiplies is allocator traffic: every create zeroes 8 KiB and every
/// teardown frees it. This pool recycles the freed buffers (moved, never
/// shared) up to this depth per thread; beyond it they drop as before.
/// Thread-local because the buffers are exclusive `&mut` scratch — sharing
/// them across threads would need a lock on the per-reply path.
pub(crate) const SESS_BUF_POOL_DEPTH: usize = 8;

thread_local! {
    static SESS_BUF_POOL: std::cell::RefCell<Vec<Vec<u8>>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Take a session-reader buffer, recycled when one is idle.
pub(crate) fn sess_recv_buf() -> Vec<u8> {
    SESS_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        while let Some(buf) = p.pop() {
            if buf.len() == SESS_RECV_BUF_LEN {
                return buf;
            }
        }
        vec![0u8; SESS_RECV_BUF_LEN]
    })
}

/// Return a session-reader buffer for reuse. Wrong-sized buffers (none exist
/// in the tree today; this is defence in depth) are dropped, and past the
/// depth the buffer drops as before — so the pool itself is bounded.
pub(crate) fn sess_recycle_buf(buf: Vec<u8>) {
    if buf.len() != SESS_RECV_BUF_LEN {
        return;
    }
    // No re-zeroing: `recv_from` overwrites the prefix on the next use and
    // only `buf[..n]` is ever read, so stale tail bytes are never observed.
    // All sessions live in this process, so there is no cross-tenant leak.
    SESS_BUF_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < SESS_BUF_POOL_DEPTH {
            p.push(buf);
        }
    })
}

/// Minimum gap between live DATAGRAM-budget re-reads after a `TooLarge` send
/// verdict on this reader task. Mirrors the client's
/// `BUDGET_PROBE_INTERVAL_MS` (100 ms): without it a PMTU shrink costs one
/// quinn connection-state lock per oversized reply for the whole window, i.e.
/// a re-probe storm on exactly the mutex the steady path takes once per frame.
/// Inside the window the reader keeps the last known budget and the datagram
/// is dropped with size accounting (UDP semantics).
pub(crate) const READER_BUDGET_PROBE_INTERVAL_MS: u64 = 100;

/// Whether a `TooLarge` verdict may re-read the live budget now. Pure so the
/// throttle is testable without a live connection; `now_ms` is the
/// [`mono_millis`] epoch. Zero means never probed: the mono epoch counts from
/// process start, so a small `now` must not read as "probed 0 ms ago".
pub(crate) fn too_large_probe_due(last_probe_ms: u64, now_ms: u64) -> bool {
    last_probe_ms == 0 || now_ms.saturating_sub(last_probe_ms) >= READER_BUDGET_PROBE_INTERVAL_MS
}

#[cfg(test)]
pub(crate) fn sess_buf_pool_len() -> usize {
    SESS_BUF_POOL.with(|p| p.borrow().len())
}

/// Wire length of the `atyp | addr | port` header a packed frame carries for
/// `src`. A reply's source is always IP-form (the session reader reports the
/// address the target answered from), so this is 7 or 19 bytes.
fn reply_addr_len(src: SocketAddr) -> usize {
    match src {
        SocketAddr::V4(_) => 1 + 4 + 2,
        SocketAddr::V6(_) => 1 + 16 + 2,
    }
}

/// One reply waiting in the MQP-3 TRAIN arena.
///
/// `flow` is the inbound flow whose destination produced this source, or
/// [`MQP3_NO_FLOW`] for an unsolicited/full-cone source (and for a domain
/// target, whose resolved IP the client does not know). A no-flow item carries
/// its source inline; a known flow is compressed and the client's own flow
/// table supplies the source address.
pub(crate) struct ReplyItem {
    pub(crate) flow: u8,
    pub(crate) src: SocketAddr,
    pub(crate) off: usize,
    pub(crate) len: usize,
}

/// Stage one small reply into the current MQP-3 TRAIN.
///
/// Unlike the MQP-2 BATCH stager this does **not** require a shared source: a
/// train can mix destinations, which is the case that matters for DNS/game
/// fanout. `last_flow` is a one-entry memo of `(source, flow)` so a steady
/// source does not reload the flow snapshot or scan the table per reply.
///
/// `false` means the run is full or the next item would exceed the path
/// budget; the caller flushes and retries. Saturating arithmetic, because
/// `limit` is a live path budget.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reply_stage_v3(
    arena: &mut Vec<u8>,
    staged: &mut Vec<ReplyItem>,
    staged_wire: &mut usize,
    flows: &arc_swap::ArcSwap<FlowTable>,
    last_flow: &mut Option<(SocketAddr, u8)>,
    src: SocketAddr,
    payload: &[u8],
    limit: usize,
) -> bool {
    if staged.len() >= MQP3_MAX_TRAIN_ITEMS {
        return false;
    }
    let flow = match *last_flow {
        Some((s, f)) if s == src => f,
        _ => {
            let snap = flows.load();
            let f = snap.flow_for_ip(src).unwrap_or(MQP3_NO_FLOW);
            *last_flow = Some((src, f));
            f
        }
    };
    // A known IP flow is compressed. A no-flow item (unsolicited source, a
    // source port that changed, or a domain target) carries its address inline:
    // the client resolves flow ids from its outbound destination table, which
    // for a domain is not a valid SOCKS reply source.
    let addr_len = if flow == MQP3_NO_FLOW {
        reply_addr_len(src)
    } else {
        0
    };
    let base = if staged.is_empty() {
        MQP3_TRAIN_HEADER_LEN
    } else {
        *staged_wire
    };
    let next = base.saturating_add(train_item_len(flow, addr_len, payload.len()));
    if next > limit {
        return false;
    }
    let off = arena.len();
    arena.extend_from_slice(payload);
    staged.push(ReplyItem {
        flow,
        src,
        off,
        len: payload.len(),
    });
    *staged_wire = next;
    true
}

/// Send one staged reply as a `SINGLE`, falling back to the MQP-2 fragment
/// sender. Returns true when a `TooLarge` verdict should trigger a budget
/// probe.
fn flush_reply_single(
    c2: &quinn::Connection,
    s: u32,
    frag: &mut DgramFragmenter,
    item: &ReplyItem,
    payload: &[u8],
    limit: usize,
) -> bool {
    let ta = TargetAddr::Ip(item.src);
    let inline = (item.flow == MQP3_NO_FLOW).then(|| ta.as_ref());
    let sent = match encode_single(s, item.flow, inline.as_ref(), false, payload, limit) {
        Some(body) => try_send_datagram(c2, body),
        None => DatagramSend::TooLarge,
    };
    match sent {
        DatagramSend::Sent => {
            udp_stats::payload(payload.len());
            false
        }
        DatagramSend::Blocked | DatagramSend::TooLarge => {
            frag.send(c2, s, &ta.as_ref(), payload, limit).outcome() == DatagramSend::TooLarge
        }
        // The caller's next action is the same for a dead/unsupported
        // connection: flush what remains, then leave the reader. Nothing is
        // counted here; the per-frame verdict is one event, not one per reply.
        DatagramSend::Unsupported | DatagramSend::ConnectionLost => false,
    }
}

/// Flush the staged replies as one MQP-3 TRAIN, or as per-reply
/// `SINGLE`/fragment sends if the frame is refused.
///
/// Accounting is per reply, never per frame: a successful train books every
/// payload, a refused train books nothing and the fallback books each payload
/// through `flush_reply_single`/`DgramFragmenter::send`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn flush_reply_train(
    c2: &quinn::Connection,
    s: u32,
    frag: &mut DgramFragmenter,
    arena: &mut Vec<u8>,
    staged: &mut Vec<ReplyItem>,
    staged_wire: &mut usize,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
) {
    if staged.is_empty() {
        *staged_wire = 0;
        arena.clear();
        return;
    }
    let mut too_large = false;
    if staged.len() == 1 {
        let item = &staged[0];
        too_large = flush_reply_single(
            c2,
            s,
            frag,
            item,
            &arena[item.off..item.off + item.len],
            *limit,
        );
    } else {
        let n = staged.len().min(MQP3_MAX_TRAIN_ITEMS);
        let mut addrs: [TargetAddr; MQP3_MAX_TRAIN_ITEMS] =
            std::array::from_fn(|_| TargetAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))));
        let mut refs: [TrainItem<'_>; MQP3_MAX_TRAIN_ITEMS] = [TrainItem {
            flow: 0,
            inline: None,
            src_override: false,
            payload: &[],
        }; MQP3_MAX_TRAIN_ITEMS];
        for (i, item) in staged.iter().take(n).enumerate() {
            addrs[i] = TargetAddr::Ip(item.src);
        }
        for (i, item) in staged.iter().take(n).enumerate() {
            let inline = (item.flow == MQP3_NO_FLOW).then(|| addrs[i].as_ref());
            refs[i] = TrainItem {
                flow: item.flow,
                inline,
                src_override: false,
                payload: &arena[item.off..item.off + item.len],
            };
        }
        let sent = encode_train(s, &refs[..n], *limit)
            .map(|body| try_send_datagram(c2, body))
            .unwrap_or(DatagramSend::TooLarge);
        match sent {
            DatagramSend::Sent => {
                for item in staged.iter().take(n) {
                    udp_stats::payload(item.len);
                }
                tracing::debug!("udp session {s}: {n} replies sent as one MQP-3 train");
            }
            DatagramSend::Blocked | DatagramSend::TooLarge => {
                for item in staged.iter().take(n) {
                    too_large |= flush_reply_single(
                        c2,
                        s,
                        frag,
                        item,
                        &arena[item.off..item.off + item.len],
                        *limit,
                    );
                }
            }
            DatagramSend::Unsupported | DatagramSend::ConnectionLost => {}
        }
    }
    staged.clear();
    arena.clear();
    *staged_wire = 0;
    if too_large {
        let now_probe = mono_millis().max(1);
        if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
            *last_too_large_probe_ms = now_probe;
            *limit = c2.max_datagram_size().unwrap_or(0);
        }
    }
}

/// Stage one small reply into the current run's arena.
///
/// `false` means "do not stage this reply": a different source, a full run, or
/// no room left in the frame budget. The caller flushes the run and retries; a
/// reply that still cannot be staged on its own is sent as a single datagram.
///
/// The budget check uses [`batch_frame_len`], the same arithmetic as
/// `encode_batch`: it charges the fixed part plus **every** item's 2-byte
/// length prefix, not just the one being added. A run that would hold
/// `staged.len() + 1` items therefore costs
/// `BATCH_PREFIX_LEN + addr + 1 + Σ(2 + len)`. Charging a single prefix (the
/// previous shape) under-counted an N-item run by `2 * N` bytes: 16 x 88 B
/// replies need `5 + 7 + 1 + 16 x 90 = 1453 B`, so at a 1452 B path budget the
/// 16th was admitted and `encode_batch` then refused the frame — the flush
/// degraded to 16 per-reply sends and the staging copy had been paid for
/// nothing, which is exactly the waste this budget exists to prevent.
/// Saturating arithmetic: `limit` is a live path budget and this runs under
/// panic=abort, so an absurd value must clamp, not wrap.
///
/// The arena is reused across bursts and cleared on every flush, so the steady
/// state allocates nothing per reply — the copy into the arena is the only one
/// the caller pays, and `encode_batch` reads the payloads straight out of it.
#[cfg(test)]
pub(crate) fn reply_stage(
    arena: &mut Vec<u8>,
    staged: &mut Vec<(usize, usize)>,
    staged_src: &mut Option<SocketAddr>,
    src: SocketAddr,
    payload: &[u8],
    limit: usize,
) -> bool {
    if staged_src.is_some_and(|s| s != src) || staged.len() >= MAX_BATCH_ITEMS {
        return false;
    }
    if batch_frame_len(
        reply_addr_len(src),
        staged.len().saturating_add(1),
        arena.len().saturating_add(payload.len()),
    ) > limit
    {
        return false;
    }
    let off = arena.len();
    arena.extend_from_slice(payload);
    staged.push((off, payload.len()));
    *staged_src = Some(src);
    true
}

/// Flush staged small replies for one target as a single MQP-2 BATCH frame.
///
/// Server-side mirror of the client association's N-pack: up to
/// [`MAX_BATCH_ITEMS`] replies that share one `(ip, port)` source ride one
/// DATAGRAM — one quinn connection-state lock and one AEAD instead of one
/// per reply. `arena`/`staged` are the run's reused buffers (see
/// [`reply_stage`]); both are cleared here, and staging never waits: the caller
/// flushes at burst end, on a source change, on a large reply and before every
/// `break 'session`, so nothing survives across awaits.
///
/// **Accounting is per reply, not per frame.** `send_udp_batch` books a full
/// send buffer once for the whole frame, so a blocked N-item batch would count
/// N lost app datagrams as one drop — and a frame that never fit has to fall
/// back to per-reply sends anyway. Both are avoided by driving the encode/send
/// here: a frame that was not queued counts nothing, and the per-reply fallback
/// re-sends each reply through `DgramFragmenter::send`, which does its own
/// exactly-once accounting — the same bookkeeping an unbatched reply gets. That
/// fallback now only fires when the path budget shrank under a staged run.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn flush_reply_batch(
    c2: &quinn::Connection,
    s: u32,
    frag: &mut DgramFragmenter,
    arena: &mut Vec<u8>,
    staged: &mut Vec<(usize, usize)>,
    staged_src: &mut Option<SocketAddr>,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
) {
    let Some(src) = staged_src.take() else {
        return;
    };
    if staged.is_empty() {
        arena.clear();
        return;
    }
    let ta = TargetAddr::Ip(src);
    let aref = ta.as_ref();
    // A run of one is not a batch: the BATCH wrapper buys a count byte, a
    // per-item length prefix and one extra decode on the client for a frame
    // that carries a single payload anyway, and the single-`0x02` path through
    // `DgramFragmenter::send` is the same encoder every unbatched reply already
    // uses (prefix cache, exactly-once drop accounting, fragmentation for an
    // oversized body). Low-rate flows — DNS-style request/response, a game's
    // keepalives — deliver one reply per wakeup, so this is their steady shape,
    // not a corner. It also makes the "N replies as one batch frame" debug line
    // below fire only when the grouping actually happened.
    if staged.len() == 1 {
        let (off, len) = staged[0];
        let sent = frag.send(c2, s, &aref, &arena[off..off + len], *limit);
        staged.clear();
        arena.clear();
        // Same 100 ms probe throttle as the per-reply fallback below (and the
        // main loop): a size verdict is a path-budget signal, never a
        // connection fault.
        if sent.outcome() == DatagramSend::TooLarge {
            let now_probe = mono_millis().max(1);
            if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
                *last_too_large_probe_ms = now_probe;
                *limit = c2.max_datagram_size().unwrap_or(0);
            }
        }
        return;
    }
    let mut refs: [&[u8]; MAX_BATCH_ITEMS] = [&[][..]; MAX_BATCH_ITEMS];
    let n = staged.len().min(MAX_BATCH_ITEMS);
    for (r, (off, len)) in refs.iter_mut().zip(staged.iter().take(n)) {
        *r = &arena[*off..*off + *len];
    }
    if let Some(body) = encode_batch(s, &aref, &refs[..n], *limit)
        && try_send_datagram(c2, body) == DatagramSend::Sent
    {
        for (_, len) in staged.iter().take(n) {
            udp_stats::payload(*len);
        }
        // Only true groups reach here (a run of one took the single-`0x02`
        // path above), so this line is the operational answer to "is the
        // batching earning its keep".
        tracing::debug!("udp session {s}: {n} replies sent as one batch frame");
        staged.clear();
        arena.clear();
        return;
    }
    // The frame was not queued and nothing was counted for it, so every reply
    // goes out on its own below — the same path (and the same per-datagram drop
    // accounting) an unstaged reply takes.
    let mut too_large = false;
    for (off, len) in staged.drain(..) {
        if frag
            .send(c2, s, &aref, &arena[off..off + len], *limit)
            .outcome()
            == DatagramSend::TooLarge
        {
            // A per-reply size verdict is the one real path-budget signal
            // here (the batch encoder declining to fit does not imply a
            // single reply would not). Probe under the same 100 ms throttle
            // the main loop uses, never per reply.
            too_large = true;
        }
    }
    arena.clear();
    if too_large {
        let now_probe = mono_millis().max(1);
        if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
            *last_too_large_probe_ms = now_probe;
            *limit = c2.max_datagram_size().unwrap_or(0);
        }
    }
}

/// What processing one reply did to the reader's drain loop.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyDisposition {
    /// Keep draining the current burst.
    Continue,
    /// Tear the reader down: the path budget collapsed to zero, or the
    /// connection reported DATAGRAM support lost / connection lost (the staged
    /// replies were flushed by the arm that returned this).
    BreakSession,
}

/// Process one reply from the session's target socket.
///
/// This is the entire body of the reader's drain loop, and it is deliberately
/// **fully synchronous**: on Linux the `recvmmsg` burst arm runs it while
/// borrowing the thread-local burst scratch in place (`with_burst_msg`) instead
/// of copying the payload into the session buffer first — that copy was one full
/// payload memcpy per drained reply. Any future `await` in here would have to
/// move back behind an owned copy in the caller.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_session_reply(
    c2: &quinn::Connection,
    s: u32,
    payload: &[u8],
    src_raw: SocketAddr,
    reply_filter: ReplyFilter,
    frag: &mut DgramFragmenter,
    arena: &mut Vec<u8>,
    staged: &mut Vec<ReplyItem>,
    staged_wire: &mut usize,
    flows: &arc_swap::ArcSwap<FlowTable>,
    last_flow: &mut Option<(SocketAddr, u8)>,
    limit: &mut usize,
    last_too_large_probe_ms: &mut u64,
    last_touch: &mut u64,
    last_limit_refresh: &mut u64,
    last2: &std::sync::atomic::AtomicU64,
    recent: &arc_swap::ArcSwap<RecentAddrs>,
    recent_epoch: &std::sync::atomic::AtomicU64,
    allow_snap: &mut Option<Arc<RecentAddrs>>,
    allow_epoch: &mut u64,
) -> ReplyDisposition {
    let n = payload.len();
    // N=1 CONTRACT (server reply path): a datagram sent through the cached
    // `limit` pays exactly one quinn take per frame — the `SendDatagram::poll`
    // lock inside `try_send_datagram`. Auxiliary takes are all throttled off
    // this path: the 60 s idle tick re-reads the budget at most once per tick,
    // active sessions refresh PMTU at most once per 10 s, `TooLarge` re-probes
    // at most once per `READER_BUDGET_PROBE_INTERVAL_MS`, and
    // `Unsupported`/`ConnectionLost` break the reader instead of re-acquiring
    // (DATAGRAM support is negotiated at the handshake, so a re-check could
    // never find a better budget — only spend another take per datagram).
    // Coarse epoch gates the per-reply intervals (the 1 s liveness touch and
    // the 10 s PMTU refresh); the liveness value itself is the mono epoch,
    // matching `touch_session_throttled` and every sweep reader.
    let now = coarse_millis();
    if now.saturating_sub(*last_touch) >= 1000 {
        *last_touch = now;
        last2.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
    }
    // Active sessions track PMTU growth without waiting for the 60 s idle tick:
    // at most one quinn lock per session per 10 s, and only while the session
    // is actually receiving replies.
    if now.saturating_sub(*last_limit_refresh) >= 10_000 {
        *last_limit_refresh = now;
        match c2.max_datagram_size() {
            Some(m) => *limit = m,
            None => return ReplyDisposition::BreakSession,
        }
    }
    // Truncation detection: the reader buffer is one slack byte past the
    // protocol cap (`SESS_RECV_BUF_LEN`), so a datagram *at least* that long is
    // exactly the shape `recv_from` would have reported as `n == buf.len()`.
    // The burst arm sees the kernel's own reported length (up to `BURST_SLOT`,
    // which is larger than this buffer), so `>=` reproduces the old predicate
    // for both arms instead of the burst path letting an over-long reply
    // through.
    if n >= SESS_RECV_BUF_LEN {
        // Rate-limited, exactly like every other drop on this path: the rate
        // is chosen by the *target* (any reply above the protocol cap), and an
        // unthrottled `warn!` here put a formatted line through tracing's
        // process-wide writer lock once per packet.
        let dropped = dgram_drops::bump(&dgram_drops::TOO_LARGE);
        dgram_drops::warn_oversize_recv(dgram_drops::OversizeRecv::TargetReply, dropped, || {
            format!("; session {s}")
        });
        return ReplyDisposition::Continue;
    }
    if *limit == 0 {
        // The staged replies cannot go out either: flush counts them through
        // the per-reply path (each is a TooLarge drop) instead of losing them
        // silently on the way out.
        flush_reply_train(
            c2,
            s,
            &mut *frag,
            &mut *arena,
            &mut *staged,
            &mut *staged_wire,
            limit,
            &mut *last_too_large_probe_ms,
        );
        return ReplyDisposition::BreakSession;
    }
    let src = SocketAddr::new(unmap(src_raw.ip()), src_raw.port());
    // Reply-source validation: the socket is unconnected, so any source that
    // reaches the ephemeral port would otherwise be forwarded as the target's
    // answer. The default drops anything sent from a host this session never
    // sent to (see `RecentAddrs`: the port is deliberately not part of the key,
    // so a server answering from a different port still gets through).
    // `ReplyFilter::FullCone` (`udp_full_cone`) is the operator opt-in that
    // behaves like a full-cone NAT's external endpoint — endpoint-independent
    // filtering, any source admitted — which is what lets a peer initiate to a
    // client app that has not sent to it yet.
    //
    // Full-cone still classifies the source against the allowlist (the same
    // epoch-gated mirror, so a steady flow is one relaxed load plus the 16-slot
    // scan): the classification only feeds the 60 s "unsolicited (full-cone)"
    // counter. It is *not* a drop decision.
    let on_allowlist = {
        // Epoch-gated mirror: the outbound path (and a spawned resolver task's
        // foreign push) bumps `recent_epoch` on every allowlist mutation, so a
        // steady flow validates against the task-local snapshot and only
        // reloads it when something actually moved. `remember_dst` moves the
        // epoch only when it really pushed a snapshot, so the steady slow-path
        // flow does not force a reload per reply.
        let epoch_now = recent_epoch.load(std::sync::atomic::Ordering::Relaxed);
        if *allow_epoch != epoch_now {
            *allow_snap = Some(recent.load_full());
            *allow_epoch = epoch_now;
        }
        allow_snap
            .as_ref()
            .is_some_and(|r| !r.is_empty() && r.contains(&src))
    };
    // A destination can fall out of the 16-entry recent ring while its flow is
    // still live (a 32-resolver DNS fanout is exactly that shape). The flow
    // table is an exact, session-scoped record of accepted IP targets, so it is
    // a second authorization source rather than a routing-only hint. Only
    // checked on a ring miss, and only IP flows match (`flow_for_ip` skips
    // domain entries, which have no resolved client-side address).
    let on_flow = !on_allowlist && flows.load().flow_for_ip(src).is_some();
    if on_flow {
        // The one-entry staging memo may have cached NO_FLOW before this mapping
        // was installed (the target's first reply can race the accept loop's
        // install). Invalidate it here so the reply is compressed now, instead
        // of staying inline until a different source happens to evict the memo.
        *last_flow = None;
    }
    if !on_allowlist && !on_flow {
        if reply_filter == ReplyFilter::FullCone {
            // Admitted anyway; counted so an operator can see whether (and how
            // much) unsolicited traffic is actually arriving.
            udp_stats::unsolicited();
        } else {
            dgram_drops::bump(&dgram_drops::REFUSED);
            return ReplyDisposition::Continue;
        }
    }
    // Reply packing: a small reply rides the run's MQP-3 TRAIN instead of its
    // own DATAGRAM. Unlike the old BATCH, a run may mix sources; a large reply,
    // the burst end and the exit paths below flush what is staged first — order
    // on the wire is preserved and nothing waits (the payload is copied once,
    // into the reused arena).
    //
    // Staging is budget-aware: `reply_stage_v3` refuses a reply that would not
    // fit the frame, so a run always encodes (unless the path budget shrank
    // after staging). A reply that cannot be staged even alone falls through to
    // the single-datagram send below.
    if n <= BATCH_SMALL_MAX {
        if reply_stage_v3(
            arena,
            staged,
            staged_wire,
            flows,
            last_flow,
            src,
            payload,
            *limit,
        ) {
            return ReplyDisposition::Continue;
        }
        flush_reply_train(
            c2,
            s,
            &mut *frag,
            &mut *arena,
            &mut *staged,
            &mut *staged_wire,
            limit,
            &mut *last_too_large_probe_ms,
        );
        if reply_stage_v3(
            arena,
            staged,
            staged_wire,
            flows,
            last_flow,
            src,
            payload,
            *limit,
        ) {
            return ReplyDisposition::Continue;
        }
    }
    flush_reply_train(
        c2,
        s,
        &mut *frag,
        &mut *arena,
        &mut *staged,
        &mut *staged_wire,
        limit,
        &mut *last_too_large_probe_ms,
    );
    let ta = TargetAddr::Ip(src);
    let sent = frag.send(c2, s, &ta.as_ref(), payload, *limit);
    if sent.fragmented() {
        tracing::debug!("udp session {s}: {n} B sent as {} fragments", sent.frames);
    }
    match sent.outcome() {
        DatagramSend::Sent => {}
        DatagramSend::Blocked => {}
        DatagramSend::TooLarge => {
            // Size verdict, never a connection fault: keep the reader and the
            // cached budget, re-reading the live budget at most once per probe
            // interval. Unthrottled, every oversized reply in a PMTU-shrink
            // window took quinn's connection-state lock on top of the one
            // per-frame take the send itself already paid. `.max(1)`: the zero
            // stamp means "never probed" (see `too_large_probe_due`), and the
            // mono epoch counts from process start, so a verdict inside the
            // first millisecond must still arm the throttle.
            let now_probe = mono_millis().max(1);
            if too_large_probe_due(*last_too_large_probe_ms, now_probe) {
                *last_too_large_probe_ms = now_probe;
                *limit = c2.max_datagram_size().unwrap_or(0);
            }
        }
        DatagramSend::Unsupported | DatagramSend::ConnectionLost => {
            // Best-effort delivery for what is staged before the reader exits:
            // on a dead connection each per-reply send reports the same terminal
            // outcome, and nothing is counted for it — the same disposition an
            // unstaged reply on this path gets.
            flush_reply_train(
                c2,
                s,
                &mut *frag,
                &mut *arena,
                &mut *staged,
                &mut *staged_wire,
                limit,
                &mut *last_too_large_probe_ms,
            );
            return ReplyDisposition::BreakSession;
        }
    }
    ReplyDisposition::Continue
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn sess_reader_task(
    conn_id: usize,
    s: u32,
    rs: Arc<tokio::net::UdpSocket>,
    ss2: SessTable,
    c2: quinn::Connection,
    last2: Arc<std::sync::atomic::AtomicU64>,
    recent: Arc<arc_swap::ArcSwap<RecentAddrs>>,
    recent_epoch: Arc<std::sync::atomic::AtomicU64>,
    flows: Arc<arc_swap::ArcSwap<FlowTable>>,
    reply_filter: ReplyFilter,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Pooled (see `sess_recv_buf`): `SESS_RECV_BUF_LEN` is the truncation
    // witness (`handle_session_reply` drops a reply whose length reaches it),
    // and this buffer is the head/portable-fallback copy target: on Linux the
    // drained burst replies are handled in place from the recvmmsg scratch and
    // never touch it.
    let mut buf = sess_recv_buf();
    let mut frag = DgramFragmenter::new();
    let mut limit = c2.max_datagram_size().unwrap_or(0);
    let mut last_touch = 0u64;
    let mut last_limit_refresh = coarse_millis();
    // Last live-budget re-read caused by a `TooLarge` verdict (mono epoch, 0 =
    // never). Gates the re-probe so a PMTU shrink cannot cost one quinn lock
    // per oversized reply; see `READER_BUDGET_PROBE_INTERVAL_MS`.
    let mut last_too_large_probe_ms = 0u64;
    // Task-local mirror of the reply-source allowlist. This task is the
    // allowlist's only reader, and every mutation of the shared snapshot bumps
    // `recent_epoch` — including a spawned resolver task's foreign push, which
    // this task cannot otherwise see. The snapshot is therefore reloaded only
    // when the epoch moves: one relaxed epoch load per reply instead of an
    // `ArcSwap` hazard-pointer read whose cache line a concurrent foreign push
    // would invalidate on the download hot path. `u64::MAX` can never be a
    // real epoch (it counts pushes), so the first reply always loads.
    let mut allow_snap: Option<Arc<RecentAddrs>> = None;
    let mut allow_epoch: u64 = u64::MAX;
    // Staged small replies for one MQP-3 TRAIN. A train can mix sources, so a
    // run is bounded only by item count and the path budget; a large reply, the
    // burst end and every session-exiting path flush it through
    // `flush_reply_train`, so nothing survives across awaits. Payloads live in
    // one reused arena; the arena starts empty and grows to at most one frame.
    let mut arena: Vec<u8> = Vec::new();
    let mut staged: Vec<ReplyItem> = Vec::with_capacity(MQP3_MAX_TRAIN_ITEMS);
    let mut staged_wire = 0usize;
    let mut last_flow: Option<(SocketAddr, u8)> = None;
    'session: loop {
        let (n, src) = tokio::select! {
            r = rs.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(_) => break,
            },
            _ = tick.tick() => {
                if c2.close_reason().is_some()
                    || mono_millis()
                        .saturating_sub(last2.load(std::sync::atomic::Ordering::Relaxed))
                        >= SESS_IDLE_MS
                {
                    break;
                }
                limit = match c2.max_datagram_size() {
                    Some(m) => m,
                    // DATAGRAM support is negotiated at the handshake; a mid-life
                    // disable leaves this reader with nothing to deliver, so exit
                    // and let the entry self-reap instead of holding a socket.
                    None => break,
                };
                continue;
            }
        };
        // Bounded reply drain (mirrors the client relay loops): the awaited
        // head plus up to `LAST_HOP_DRAIN - 1` more, so one wakeup moves up to
        // 32 replies instead of one reply per wakeup. On Linux the extras come
        // from one `recvmmsg` burst per refill and are handled **in place**
        // through `with_burst_msg`: the burst scratch already holds the bytes,
        // so copying them into `buf` first (the old `burst_msg_copy` arm) was
        // one full payload memcpy per drained reply. The portable fallback
        // (non-Linux, or a kernel without `recvmmsg`) still copies into `buf`
        // and runs the same body there — `with_burst_msg` returns `None` off
        // Linux, so that is the arm macOS/BSD runs, unchanged.
        //
        // Tokio keeps recv readiness set until a `WouldBlock`, so the remainder
        // is picked up on the next poll; nothing queues in userspace. A drained
        // error ends the burst, not the session: the head already proved the
        // socket live this poll.
        let mut drained = 1usize;
        let mut head: Option<(usize, SocketAddr)> = Some((n, src));
        // recvmmsg burst state (Linux): `burst_i < burst_n` consumes staged
        // datagrams; otherwise one refill syscall covers the remaining
        // per-wakeup budget. Both counters stay 0 on the portable path, where
        // the `try_recv_from` arm below runs.
        let mut burst_n = 0usize;
        let mut burst_i = 0usize;
        // The per-reply body is fully synchronous, so every arm can run it
        // while a borrowed payload is live (the Linux burst arm does exactly
        // that). Kept as a macro so the argument list exists once.
        macro_rules! handle_reply {
            ($msg:expr, $src:expr) => {
                handle_session_reply(
                    &c2,
                    s,
                    $msg,
                    $src,
                    reply_filter,
                    &mut frag,
                    &mut arena,
                    &mut staged,
                    &mut staged_wire,
                    flows.as_ref(),
                    &mut last_flow,
                    &mut limit,
                    &mut last_too_large_probe_ms,
                    &mut last_touch,
                    &mut last_limit_refresh,
                    last2.as_ref(),
                    recent.as_ref(),
                    recent_epoch.as_ref(),
                    &mut allow_snap,
                    &mut allow_epoch,
                )
            };
        }
        loop {
            let disposition = if let Some((n, src)) = head.take() {
                // The head was already copied into `buf` by `recv_from`.
                handle_reply!(&buf[..n], src)
            } else if burst_i < burst_n {
                let i = burst_i;
                burst_i += 1;
                match with_burst_msg(i, |msg, src| handle_reply!(msg, src)) {
                    Some(disposition) => {
                        drained += 1;
                        disposition
                    }
                    // No burst scratch reachable here (portable fallback): copy
                    // the staged message out to `buf` and run the same body on
                    // it, exactly like the old drain arm.
                    None => match burst_msg_copy(i, &mut buf) {
                        Some((n, src)) => {
                            drained += 1;
                            handle_reply!(&buf[..n], src)
                        }
                        None => break,
                    },
                }
            } else {
                if drained >= LAST_HOP_DRAIN {
                    break;
                }
                match recv_burst(&rs, LAST_HOP_DRAIN - drained) {
                    Some(0) => break,
                    Some(k) => {
                        burst_n = k;
                        burst_i = 1;
                        match with_burst_msg(0, |msg, src| handle_reply!(msg, src)) {
                            Some(disposition) => {
                                drained += 1;
                                disposition
                            }
                            None => match burst_msg_copy(0, &mut buf) {
                                Some((n, src)) => {
                                    drained += 1;
                                    handle_reply!(&buf[..n], src)
                                }
                                None => break,
                            },
                        }
                    }
                    None => match rs.try_recv_from(&mut buf) {
                        Ok((n, src)) => {
                            drained += 1;
                            handle_reply!(&buf[..n], src)
                        }
                        Err(_) => break,
                    },
                }
            };
            match disposition {
                ReplyDisposition::Continue => {}
                ReplyDisposition::BreakSession => break 'session,
            }
        }
        // The burst ends here, so whatever is staged goes out before the
        // reader parks: the last reply of a burst must not wait for the next
        // target reply to be flushed.
        flush_reply_train(
            &c2,
            s,
            &mut frag,
            &mut arena,
            &mut staged,
            &mut staged_wire,
            &mut limit,
            &mut last_too_large_probe_ms,
        );
        record_drain_batch(drained);
    }
    // Every exit above breaks to here, so the buffer is recycled exactly once
    // per reader lifetime, however the task ended (idle reap, abort-adjacent
    // error, lost DATAGRAM support).
    sess_recycle_buf(buf);
    sess_memo_forget(conn_id, s, &rs);
    {
        let sh = ss2.shard(s);
        let mut w = sh.write();
        let mut removed = false;
        if let Some(cur) = w.get(&s)
            && Arc::ptr_eq(&cur.sock, &rs)
        {
            removed = w.remove(&s).is_some();
        }
        if removed {
            ss2.note_live_remove(1);
        }
    }
    // The table may now be empty: if this was its last session, drop out of the
    // fair-share denominator so other connections immediately get their full
    // share back. Must run with the write guard above dropped (see
    // `note_empty_state`).
    ss2.note_empty_state();
}

pub(crate) async fn get_or_create_sess(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    // `(host, port, resolved address)` when the caller already knows a *named*
    // destination, so the session can memoize it. An IP target passes `None`:
    // its address is already in every datagram it sends, and the memo is only
    // ever read back for domain targets (`sess_dest_store`).
    // `(host, port, resolved address, remaining life of that resolution)` — the
    // life is the source's, so the memo cannot outlive it (see `pin_life_ms`).
    dest: Option<(&str, u16, SocketAddr, u64)>,
) -> Option<Arc<tokio::net::UdpSocket>> {
    // Session 0 is reserved (never allocated by any client hub): a wire
    // datagram carrying it is malformed or hostile, not a new session.
    // Refusing here keeps it from pinning a global permit until the sweep.
    if s == 0 {
        dgram_drops::bump(&dgram_drops::REFUSED);
        return None;
    }
    // Zero-lock fast path: the common case (a burst of packets for one session)
    // allocates nothing and never touches the table. The memo's liveness check
    // is the same signal the table path uses (`JoinHandle::is_finished`) — one
    // atomic load — so a session whose reader has exited, aborted included,
    // still falls through and is recreated.
    match sess_memo_lookup(conn_id, s) {
        SessHit::Fresh(sock, last, _, _) => {
            // Refresh liveness without the table lock; a session captured here is
            // scheduled by its reader and may be exiting, in which case one reply
            // is dropped and the next packet recreates it.
            touch_session_throttled(conn_id, s, &last);
            if let Some((h, p, d, life)) = dest {
                sess_dest_store(ss, s, h, p, d, life);
            }
            return Some(sock);
        }
        SessHit::Stale | SessHit::Miss => {}
    }
    // Fast path: single shard read + lock-free timestamp bump. A session whose
    // reply reader has already exited is treated as absent so its next packet
    // recreates it instead of black-holing.
    //
    // The read *blocks* rather than failing fast. Pass 21 made this a
    // `try_lock_read` that dropped the datagram on failure and counted it in
    // `SESSION_FULL`, reasoning that a packet path must never park a worker.
    // Pass 23 revisited that: the table is per-connection, so the only
    // cross-task writers are a session reader exiting (a `get` plus maybe a
    // `remove`), the 60 s sweeper's removal loop, and a DNS-spawned
    // `get_or_create_sess` -- all short, allocation-free critical sections. The
    // datagram reader is by far the commonest writer itself, so it cannot
    // contend with itself. Against that, the old behaviour silently dropped a
    // datagram every time any of those brief writers won the race, and charged
    // the drop to a counter documented as "budget exhausted", hiding relay loss
    // inside a resource-limit metric. `parking_lot`'s `RwLock::read` already
    // spin-tries before it parks, so the uncontended cost is unchanged; only the drop is
    // gone.
    {
        let sh = ss.shard(s);
        let r = sh.read();
        if let Some(e) = r.get(&s)
            && !e.reader.is_finished()
        {
            let sock = e.sock.clone();
            let last = e.last.clone();
            let abort = e.reader.abort_handle();
            let epoch = e.recent_epoch.clone();
            touch_session_throttled(conn_id, s, &e.last);
            drop(r);
            // Publish this thread's memo from the table. A session created
            // by a DNS-spawned resolver task lives on another worker's memo
            // (or on none), and without this the per-connection fast path
            // could never arm for it: the caller's `SessHit::Miss` would
            // clear the fast state on every datagram instead of adopting
            // the session that was just used.
            sess_memo_put(conn_id, s, sock.clone(), last, abort, epoch);
            if let Some((h, p, d, life)) = dest {
                sess_dest_store(ss, s, h, p, d, life);
            }
            return Some(sock);
        }
    }
    // Fair share first: one connection must not grow past an equal split of the
    // process-wide budget while others live. Only expired sessions are
    // reclaimed here; live ones keep their sockets and the global semaphore
    // still caps the true total.
    //
    // The reap is **throttled** (per worker, 1/s) for the same reason the global
    // pool's failed-acquire path is: past the cap every further new-session
    // datagram reaches this branch, and an unthrottled `sweep_all` would walk
    // all shards and every session entry *per packet* — an O(sessions) CPU
    // amplifier any peer can drive with fabricated session ids, for a sweep
    // that can only ever free sessions that went idle >= SESS_IDLE_MS ago.
    let fair_cap = fair_sess_cap();
    // Served from the bounded sample (see `len_upper_bound`): past the cap every
    // further new-session datagram reaches this branch, so a fresh 8-lock
    // measurement per forged packet is pure lock traffic — but the bound counts
    // every insert since the sample, so a burst cannot outrun the share.
    // Re-measured exactly once the bound reaches the cap, and after a sweep
    // actually ran (it may have freed sessions).
    let now = mono_millis();
    if ss.len_upper_bound(now) >= fair_cap {
        if claim_fair_sweep(now) {
            let evicted = ss.sweep_all(now);
            abort_evicted(evicted);
            let now2 = mono_millis();
            let n2 = ss.len();
            ss.store_len(n2, now2);
            if n2 >= fair_cap {
                dgram_drops::bump(&dgram_drops::FAIR_SHARE);
                return None;
            }
        } else {
            dgram_drops::bump(&dgram_drops::FAIR_SHARE);
            return None;
        }
    }
    // No DATAGRAM support on this path: refuse before pinning a global permit,
    // a kernel socket and a reader task for a session whose replies would all
    // be dropped (`limit == 0` in the reader). Negotiated at the handshake, so
    // it never flaps mid-connection — and since a hit above can only be a
    // session that passed this check already, it stays off the per-packet path
    // instead of taking the connection-state lock for every datagram.
    //
    // Deliberately *after* the cheap fair-share gates: `max_datagram_size`
    // takes quinn's connection-state mutex, and a peer can force this branch
    // once per packet with a fabricated session id. The gates above need no
    // quinn lock, so a forged id that is over the connection's fair share is
    // refused without ever touching the mutex; only a datagram that could
    // really create a session pays the probe. (Before this move the probe ran
    // first, i.e. a forged-id flood took the state lock per packet to reach a
    // refusal that needed no lock at all.)
    cd.max_datagram_size()?;
    // Check the global pool BEFORE creating the socket: once every session slot
    // is held there is no point paying socket()+setsockopt()+bind() per packet.
    let permit = match session_limiter().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Throttled reap through the process-wide sweep window (see
            // `FAIR_SWEEP_LAST_MS`): a per-worker throttle here let W workers
            // run W full-table sweeps per second under permit pressure.
            if !claim_fair_sweep(mono_millis()) {
                dgram_drops::bump(&dgram_drops::SESSION_FULL);
                return None;
            }
            let evicted = ss.sweep_all(mono_millis());
            abort_evicted(evicted);
            match session_limiter().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    dgram_drops::bump(&dgram_drops::SESSION_FULL);
                    return None;
                }
            }
        }
    };
    // Create the socket outside the write lock: socket()/setsockopt()/bind()
    // are syscalls and must not stall the datagram reader for every session.
    // Both syscall failures are resource events the operator has to see, so
    // neither is allowed to return silently.
    let raw = match udp_socket_dual_small("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            if warn_sess_create_failed() {
                warn!("udp session socket not created ({n} so far): {e:#}");
            }
            return None;
        }
    };
    let sock = match tokio::net::UdpSocket::from_std(raw) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
            if warn_sess_create_failed() {
                warn!("udp session socket not registered ({n} so far): {e}");
            }
            return None;
        }
    };
    let c2_pre = cd.clone();
    let rs_pre = sock.clone();
    let ss_pre = ss.clone();
    let last_pre = Arc::new(std::sync::atomic::AtomicU64::new(mono_millis()));
    let recent_pre: Arc<arc_swap::ArcSwap<RecentAddrs>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(RecentAddrs::default()));
    let recent_epoch: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(0));
    let flows_pre: Arc<arc_swap::ArcSwap<FlowTable>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(FlowTable::default()));
    let h_pre = tokio::spawn(sess_reader_task(
        conn_id,
        s,
        rs_pre,
        ss_pre,
        c2_pre,
        last_pre.clone(),
        recent_pre.clone(),
        recent_epoch.clone(),
        flows_pre.clone(),
        ss.reply_filter,
    ));
    let reader_abort = h_pre.abort_handle();
    let mut stale_dead: Vec<SessEntry> = Vec::new();
    let mut swept: Vec<SessEntry> = Vec::new();
    let (inserted, memo_data, reader_died) = {
        let sh = ss.shard(s);
        // Blocks for the same reason the read path does: a losing `try_lock_write`
        // used to abort the freshly spawned reader, release the global permit and
        // drop the datagram, which is strictly worse than waiting out a short
        // `HashMap` mutation. The socket syscalls above deliberately stay outside
        // this critical section.
        let mut w = sh.write();
        if let Some(e) = w.get(&s) {
            if !e.reader.is_finished() {
                touch_session_throttled(conn_id, s, &e.last);
                let sock2 = e.sock.clone();
                let last2 = e.last.clone();
                let abort2 = e.reader.abort_handle();
                // The *live entry's* allowlist epoch, not the fresh one built for
                // the reader that is about to be aborted: the memo must describe
                // the session that stays in the table, or the mirror would never
                // see that session's pushes move.
                let epoch2 = e.recent_epoch.clone();
                drop(w);
                h_pre.abort();
                drop(permit);
                // Same reason as the read path above: adopt the live entry into
                // this thread's memo so the caller's fast path can arm.
                sess_memo_put(conn_id, s, sock2.clone(), last2, abort2, epoch2);
                if let Some((h, p, d, life)) = dest {
                    sess_dest_store(ss, s, h, p, d, life);
                }
                return Some(sock2);
            }
            if let Some(e) = w.remove(&s) {
                stale_dead.push(e);
            }
            if !stale_dead.is_empty() {
                ss.note_live_remove(stale_dead.len());
            }
        }
        // Over its fair share, this shard reaps its expired sessions now instead
        // of waiting for the 60 s sweeper. Live over-share is left alone (the
        // connection-level fair-share gate is the resource bound); the reap is
        // gated on the process-wide sweep window, or every forged new-session
        // datagram would run an O(shard) scan under this write lock — a CPU
        // amplifier any peer could drive.
        if shard_over_share(w.len(), fair_sess_cap()) && claim_fair_sweep(mono_millis()) {
            swept = sweep_local(&mut w);
            ss.note_live_remove(swept.len());
        }
        let dead = h_pre.is_finished();
        w.insert(
            s,
            SessEntry {
                sock: sock.clone(),
                reader: h_pre,
                last: last_pre.clone(),
                _permit: permit,
                dest: dest
                    .and_then(|(h, p, a, life)| Some((PortKey::new(h, p)?, a, life)))
                    .map_or(DestMemo::NONE, |(key, addr, life)| DestMemo {
                        key,
                        addr,
                        expires: coarse_millis() + pin_life_ms(life),
                    }),
                recent: recent_pre.clone(),
                recent_epoch: recent_epoch.clone(),
                flows: flows_pre.clone(),
            },
        );
        ss.note_live_insert();
        if dead || w.get(&s).map(|e| e.reader.is_finished()).unwrap_or(false) {
            if let Some(e) = w.remove(&s) {
                e.reader.abort();
            }
            // The insert above is undone while this guard is still held, so the
            // decrement always pairs with its increment.
            ss.note_live_remove(1);
            (false, None, true)
        } else {
            (
                true,
                Some((sock.clone(), last_pre.clone(), reader_abort.clone())),
                false,
            )
        }
    };
    if inserted {
        udp_stats::session();
        ss.note_insert();
    }
    // This connection may have just become a session holder: join the fair-share
    // denominator. Called after the write guard is dropped (see
    // `note_empty_state`), and on the `dead` branch too, where the insert was
    // rolled back and the connection may not hold anything at all.
    ss.note_empty_state();
    if let Some((msock, mlast, mabort)) = memo_data {
        sess_memo_put(conn_id, s, msock, mlast, mabort, recent_epoch);
    }
    if reader_died {
        // The freshly spawned reply reader exited before the entry was
        // published (e.g. the session socket failed on first use). The datagram
        // is dropped; count it instead of leaving an operator with a session
        // that silently never comes up.
        let n = dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
        if warn_sess_create_failed() {
            warn!("udp session {s} reader exited before publish ({n} so far)");
        }
    }
    abort_evicted(stale_dead);
    abort_evicted(swept);
    if inserted { Some(sock) } else { None }
}
