//! Session memos (thread-local fast paths).
use super::*;

/// Monotonic connection ids for the session memos.
///
/// Session ids are allocated per client — every client hub counts from 1 — so
/// `(conn, sess)` is the identity of a session and the connection half must
/// never repeat. `Connection::stable_id` is a heap address, and the allocator
/// hands the same address to the next connection after a reconnect, so a memo
/// entry left behind by a dead connection could match a different one. A
/// process-wide counter cannot alias.
pub(crate) fn next_conn_id() -> usize {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
/// Per-thread memo of the most recently used session socket.
///
/// A datagram-heavy flow sends a long run of packets to the *same* session, so
/// the connection-level `RwLock` read plus hash lookup in `get_or_create_sess`
/// is pure per-packet overhead for all but the first packet of the run. The
/// memo is direct-mapped on purpose: a miss simply falls through to the table.
/// The key is `(conn, sess)`, never `sess` alone: session ids are allocated per
/// client, so two connections sharing this thread would otherwise serve each
/// other's sockets and route replies onto the wrong QUIC connection.
pub(crate) struct SessMemo {
    /// Owning connection id ([`next_conn_id`]): the slot is shared by every
    /// connection whose DATAGRAM reader runs on this worker thread.
    pub(crate) conn: usize,
    pub(crate) sess: u32,
    /// Weak on purpose: the table entry and the reply reader own the socket, so
    /// the memo must never be its last owner. A strong `Arc` here outlived the
    /// connection — a slot is only rewritten by a later session hashing to the
    /// same index on the same thread, and `next_conn_id` never repeats, so the
    /// fd and its kernel buffers were pinned for the process lifetime. A failed
    /// `upgrade` is also the sharpest liveness signal available: it means the
    /// session's socket is gone.
    pub(crate) sock: std::sync::Weak<tokio::net::UdpSocket>,
    /// The session table's liveness stamp, kept so a memo hit can refresh it
    /// without re-taking the table lock.
    pub(crate) last: Arc<std::sync::atomic::AtomicU64>,
    /// The reply reader's abort handle. `is_finished` is the liveness signal,
    /// the same one the table path uses: a flag the reader cleared on its way
    /// out would stay set when the sweeper or a connection close aborts the
    /// reader mid-await, and that path runs no cleanup at all.
    pub(crate) abort: tokio::task::AbortHandle,
    /// The session's allowlist epoch (see [`SessEntry::recent_epoch`]), so the
    /// fast path can tell whether the allowlist it recorded into is still the
    /// one it saw.
    pub(crate) recent_epoch: Arc<std::sync::atomic::AtomicU64>,
}

/// 256 direct-mapped slots: session ids hash uniformly (odd multiplier is a
/// bijection mod power-of-two), so 32 interleaved sessions already thrashed the
/// old 32-slot table back to the table lock on every packet. This memo is a
/// separate cache from the fast session table in `accept.rs` (which is now
/// larger than 256 slots after the inline pin was removed): a memo miss costs
/// the slow path one shard read, and `arm_fast` deliberately keeps the fast
/// slot on a miss, so the two sizes no longer need to track each other. Past
/// 256 entries still just miss through to the table — a miss is never a
/// mis-serve, the key compare guarantees that.
pub(crate) const SESS_MEMO_SLOTS: usize = 256;

thread_local! {
    static SESS_MEMO: std::cell::RefCell<[Option<SessMemo>; SESS_MEMO_SLOTS]> =
        std::cell::RefCell::new(std::array::from_fn(|_| None));
}

pub(crate) fn sess_memo_idx(conn: usize, sess: u32) -> usize {
    (conn.wrapping_mul(31) ^ (sess as usize).wrapping_mul(0x9e3779b9)) % SESS_MEMO_SLOTS
}

/// Publish `(conn, sess)` into this thread's memo. The socket is stored weakly
/// (see [`SessMemo::sock`]); callers hand over a strong `Arc` purely as the
/// upgrade source while the session is alive.
pub(crate) fn sess_memo_put(
    conn: usize,
    sess: u32,
    sock: Arc<tokio::net::UdpSocket>,
    last: Arc<std::sync::atomic::AtomicU64>,
    abort: tokio::task::AbortHandle,
    recent_epoch: Arc<std::sync::atomic::AtomicU64>,
) {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        m[idx] = Some(SessMemo {
            conn,
            sess,
            sock: Arc::downgrade(&sock),
            last,
            abort,
            recent_epoch,
        });
    });
}

/// Drop the memo when it still points at this reader generation. Called by a
/// reply reader as it exits, so the next inbound packet for that session
/// recreates it instead of sending into a socket nobody reads.
///
/// The slot is cleared only when it still names the exiting reader's own
/// socket (same allocation, via `Weak::ptr_eq`): a session recreated after
/// this reader started carries a freshly bound socket, so clearing on
/// `(conn, sess)` alone wiped the *new* session's memo when the old reader
/// exited after the recreate. A false clear only costs one table slow path
/// (the table re-put fills the memo again); a false keep would serve a dead
/// socket, and the lookup already treats that as `Stale`.
pub(crate) fn sess_memo_forget(conn: usize, sess: u32, sock: &Arc<tokio::net::UdpSocket>) {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        let expected = Arc::downgrade(sock);
        if m[idx].as_ref().is_some_and(|x| {
            x.conn == conn && x.sess == sess && std::sync::Weak::ptr_eq(&x.sock, &expected)
        }) {
            m[idx] = None;
        }
    });
}

/// Outcome of a session-memo probe.
pub(crate) enum SessHit {
    Miss,
    /// A live session socket, its liveness stamp, its reader abort handle (the
    /// abort handle lets per-connection fast paths validate liveness without
    /// re-probing the thread-local memo) and its allowlist epoch.
    Fresh(
        Arc<tokio::net::UdpSocket>,
        Arc<std::sync::atomic::AtomicU64>,
        tokio::task::AbortHandle,
        Arc<std::sync::atomic::AtomicU64>,
    ),
    /// The memo cannot serve `(conn, sess)`: either its reader has exited or its
    /// socket is gone (see [`SessMemo::sock`]). The table (not the memo) must
    /// decide, so this falls through and lets the table path recreate the
    /// session.
    Stale,
}

/// Probe the thread-local session memo for `(conn, sess)`.
///
/// The connection is part of the key because a session id is only unique
/// within one connection (every client hub allocates ids from 1), and this slot
/// is shared by every connection whose DATAGRAM reader runs on this worker
/// thread. Matching on `sess` alone served one connection's socket to another,
/// so that connection's datagrams went out on the wrong session.
pub(crate) fn sess_memo_lookup(conn: usize, sess: u32) -> SessHit {
    SESS_MEMO.with(|c| {
        let mut m = c.borrow_mut();
        let idx = sess_memo_idx(conn, sess);
        match m[idx].as_ref() {
            Some(x) if x.conn == conn && x.sess == sess => {
                // Live means the reader has not exited *and* something still
                // owns the socket: `upgrade` fails once the table entry and the
                // reader are gone, which is exactly when the slot must be
                // released instead of pinning a dead fd.
                let live = if x.abort.is_finished() {
                    None
                } else {
                    x.sock.upgrade()
                };
                if let Some(sock) = live {
                    SessHit::Fresh(
                        sock,
                        x.last.clone(),
                        x.abort.clone(),
                        x.recent_epoch.clone(),
                    )
                } else {
                    m[idx] = None;
                    SessHit::Stale
                }
            }
            _ => SessHit::Miss,
        }
    })
}
/// Per-thread view of the last liveness refresh, so the throttling decision
/// costs no table lock. A `(connection, session, ms)` triple: session ids are
/// only unique within a connection, so `(session, ms)` alone let two
/// connections share — and thereby defeat — one throttle window.
///
/// NOTE: an earlier revision sampled the clock 1/64 by packet count. That
/// starved trickle flows: a burst past 64 packets froze `tick` large without
/// a store, and every later trickle packet kept skipping the clock read, so
/// `last` froze until the 180s reap. The clock read (~20ns vdso) is an order
/// of magnitude cheaper than the hash lookup + table lock it replaces, so the
/// throttle is purely time-based now: at most one shared store per second per
/// session, every packet pays one clock read.
pub(crate) struct TouchMemo {
    pub(crate) conn: usize,
    pub(crate) sess: u32,
    pub(crate) ms: u64,
}

/// Same 128-slot sizing as the session memo above: the throttle decision must
/// not itself become the per-packet cost, and 32 interleaved sessions thrashed
/// the old table into an unconditional store per packet pair.
pub(crate) const TOUCH_SLOTS: usize = 128;

thread_local! {
    static TOUCH_MEMO: std::cell::RefCell<[Option<TouchMemo>; TOUCH_SLOTS]> =
        std::cell::RefCell::new(std::array::from_fn(|_| None));
}

pub(crate) fn touch_memo_idx(conn: usize, sess: u32) -> usize {
    (conn.wrapping_mul(31) ^ (sess as usize).wrapping_mul(0x9e3779b9)) % TOUCH_SLOTS
}

/// Refresh `last` at most once per [`TOUCH_INTERVAL_MS`], using a thread-local
/// copy of the last refresh time.
///
/// Single clock for liveness: the throttle gate runs on the cheap
/// [`coarse_millis`] epoch (one relaxed load per datagram), but the value
/// stored into `last` is [`mono_millis`]. Every other writer of `last`
/// (session creation) and every reader (`sweep_all`, `take_idle`,
/// `sweep_local`, the reader idle tick) already uses the mono epoch, so
/// storing the 1 s-quantized coarse sample here made the sweep subtract a
/// stamp up to one tick older than the true touch — reaping a live session up
/// to ~1 s before its 180 s budget ran out. The precise read costs a TSC/OS
/// clock read and runs only when the touch is actually due (at most once per
/// second per session), so the per-packet cost stays one coarse read.
pub(crate) fn touch_session_throttled(conn: usize, sess: u32, last: &std::sync::atomic::AtomicU64) {
    pub(crate) const TOUCH_INTERVAL_MS: u64 = 1000;
    // Throttle gate only: cheap, advances on its own (unlike a packet-count
    // sampler, which froze `last` on trickle flows — see `TouchMemo`).
    let gate = coarse_millis();
    let due = TOUCH_MEMO.with(|c| {
        let mut c = c.borrow_mut();
        let idx = touch_memo_idx(conn, sess);
        match c[idx].as_mut() {
            Some(e) if e.conn == conn && e.sess == sess => {
                if gate.saturating_sub(e.ms) >= TOUCH_INTERVAL_MS {
                    e.ms = gate;
                    true
                } else {
                    false
                }
            }
            _ => {
                c[idx] = Some(TouchMemo {
                    conn,
                    sess,
                    ms: gate,
                });
                true
            }
        }
    });
    if due {
        last.store(mono_millis(), std::sync::atomic::Ordering::Relaxed);
    }
}
