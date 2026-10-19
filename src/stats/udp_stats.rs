//! UDP relay activity, so "is my UDP traffic actually going through the tunnel,
//! and how large does it get?" is answerable from the log rather than a packet
//! capture — on a QUIC tunnel a capture can only ever show ciphertext.
//!
//! [`UdpSnapshot::max_payload`] is a **high-water mark, not a limit**: it is the
//! empirical answer to "is `MQP_FRAG_MAX_PAYLOAD` big enough for this
//! deployment", measured on real traffic instead of argued from protocol specs.
//! A deployment whose high-water mark stays under `UDP_RECV_MAX` never needs a
//! larger cap, whatever its workload is.
use std::sync::atomic::{AtomicU64, Ordering};

static DATAGRAMS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static FRAGMENTED: AtomicU64 = AtomicU64::new(0);
static MAX_PAYLOAD: AtomicU64 = AtomicU64::new(0);
static SESSIONS: AtomicU64 = AtomicU64::new(0);
static REASSEMBLY_EXPIRED: AtomicU64 = AtomicU64::new(0);
static REASSEMBLY_EVICTED: AtomicU64 = AtomicU64::new(0);
static UNSOLICITED: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static L_DATAGRAMS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static L_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Fragmented payloads counted by [`fragmented`].
    ///
    /// Batched like `L_DATAGRAMS`: the counter used to be a direct
    /// `FRAGMENTED.fetch_add` on the per-payload send path, so a workload that
    /// fragments most of its packets (the shipped 1200 B initial MTU makes
    /// every payload above ~1150 B a two-frame send) paid one process-wide
    /// cache-line RMW per datagram from every relay thread — exactly the
    /// contention the sibling counters avoid at 1/256. It is a *separate*
    /// counter from the datagrams cell because only some payloads fragment.
    static L_FRAGMENTED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// `udp_full_cone` inbound datagrams whose source was not on the session's
    /// allowlist, counted by [`unsolicited`]. Batched with the same threshold
    /// for the same reason: a busy full-cone session can take these per packet.
    static L_UNSOLICITED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// This thread's payload high-water mark. It guards the shared
    /// `MAX_PAYLOAD` read on the per-payload path: the global is only
    /// touched when this thread sees a payload larger than any it has
    /// already recorded, so a steady flow costs one Cell compare and no
    /// shared cache-line access at all.
    static L_MAX_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Thread-local flush thresholds. One shared atomic RMW per 256 records still
/// keeps a flood off the cache line, while the 60 s report stays honest for
/// flows down to a few records per second: at the previous 1024/1 MiB a
/// session worker below ~17 pps could sit under the threshold for the whole
/// reporting interval and the line read 0. The same 256 bound batches the
/// rarer [`fragmented`]/[`unsolicited`] events. The remaining bound (a thread
/// that exits with a pending count, or a report thread other than the one
/// that counted) is documented on `snapshot`.
const FLUSH_DATAGRAMS: u64 = 256;
const FLUSH_BYTES: u64 = 256 * 1024;

fn flush_locals() {
    L_DATAGRAMS.with(|c| {
        let v = c.get();
        if v != 0 {
            DATAGRAMS.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
    L_BYTES.with(|c| {
        let v = c.get();
        if v != 0 {
            BYTES.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
    L_FRAGMENTED.with(|c| {
        let v = c.get();
        if v != 0 {
            FRAGMENTED.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
    L_UNSOLICITED.with(|c| {
        let v = c.get();
        if v != 0 {
            UNSOLICITED.fetch_add(v, Ordering::Relaxed);
            c.set(0);
        }
    });
}

/// One relayed UDP payload of `len` bytes.
pub fn payload(len: usize) {
    stats_only! {
        L_DATAGRAMS.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            if v >= FLUSH_DATAGRAMS {
                DATAGRAMS.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        L_BYTES.with(|c| {
            let v = c.get().wrapping_add(len as u64);
            c.set(v);
            if v >= FLUSH_BYTES {
                BYTES.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
        let l = len as u64;
        L_MAX_SEEN.with(|c| {
            if l > c.get() {
                c.set(l);
                if l > MAX_PAYLOAD.load(Ordering::Relaxed) {
                    MAX_PAYLOAD.fetch_max(l, Ordering::Relaxed);
                }
            }
        });
    }
    let _ = len;
}

/// One payload that needed `frames` frames to carry.
///
/// Thread-locally batched like [`payload`] (flushed at [`FLUSH_DATAGRAMS`], or
/// by a [`snapshot`] on the *same* thread): the counter used to be one
/// process-wide RMW per fragmented payload, which is exactly what a
/// high-fragmentation workload pays per datagram.
pub fn fragmented(frames: u8) {
    stats_only! {
        if frames > 1 {
            L_FRAGMENTED.with(|c| {
                let v = c.get().wrapping_add(1);
                c.set(v);
                if v >= FLUSH_DATAGRAMS {
                    FRAGMENTED.fetch_add(v, Ordering::Relaxed);
                    c.set(0);
                }
            });
        }
    }
    let _ = frames;
}

/// An inbound relay datagram admitted by the server's `udp_full_cone` mode
/// whose source is **not** on the session's recent-destination IP allowlist.
///
/// This is the unsolicited ingress a full-cone NAT forwards by definition. It
/// is counted on the accepted (not dropped) path because the reader still
/// classifies the source against the allowlist — every accepted reply is
/// already in [`UdpSnapshot::datagrams`]; this counter separates the peer that
/// answered from a peer that initiated, so a deployment can tell whether the
/// exposure is actually being used. Always zero in the default
/// (address-restricted) mode.
///
/// Thread-locally batched with the same threshold as [`fragmented`]: a busy
/// full-cone session takes these per inbound datagram, so a direct shared
/// `fetch_add` here would put the process-wide counter line back on the
/// packet path.
pub fn unsolicited() {
    stats_only! {
        L_UNSOLICITED.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            if v >= FLUSH_DATAGRAMS {
                UNSOLICITED.fetch_add(v, Ordering::Relaxed);
                c.set(0);
            }
        });
    }
}

/// A new UDP session (server) or SOCKS association (client) was established.
pub fn session() {
    stats_only! {
        SESSIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// A partial datagram was discarded because a fragment never arrived.
///
/// Drop-path only (never per packet): this is the only signal for a fragment
/// lost in transit.
pub fn reassembly_expired() {
    REASSEMBLY_EXPIRED.fetch_add(1, Ordering::Relaxed);
}

/// Drop-path only: a peer sending fragments whose sum exceeds the protocol's
/// payload ceiling or the aggregate reassembly budget.
pub fn reassembly_evicted() {
    REASSEMBLY_EVICTED.fetch_add(1, Ordering::Relaxed);
}

/// `(expired, evicted)` reassembly losses since process start. These are the
/// only drops that happen after the wire, so no send-side counter can see
/// them: a fragment lost in transit shows up here, not in `udp_write`.
pub fn reassembly_drops() -> (u64, u64) {
    (
        REASSEMBLY_EXPIRED.load(Ordering::Relaxed),
        REASSEMBLY_EVICTED.load(Ordering::Relaxed),
    )
}

/// Totals since process start.
///
/// **Batching bound.** `datagrams`, `bytes`, `fragmented` and `unsolicited`
/// accumulate in thread-local cells (flushed at [`FLUSH_DATAGRAMS`] /
/// [`FLUSH_BYTES`], or by a `snapshot` on the *same* thread), and a reporter
/// task runs on its own thread — so a worker's pending count is visible at the
/// next report only once it crosses the threshold, and a thread that exits with
/// a pending count drops it. 256 datagrams bounds the worst-case undercount to
/// ~15 s at 17 pps, which is why the threshold is not the old 1024. Every
/// `snapshot` call flushes the *caller's* cells first, so tests and a reporter
/// running on the counting thread see their own records exactly.
pub fn snapshot() -> UdpSnapshot {
    flush_locals();
    UdpSnapshot {
        datagrams: DATAGRAMS.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
        fragmented: FRAGMENTED.load(Ordering::Relaxed),
        max_payload: MAX_PAYLOAD.load(Ordering::Relaxed),
        sessions: SESSIONS.load(Ordering::Relaxed),
        unsolicited: UNSOLICITED.load(Ordering::Relaxed),
    }
}

/// See [`udp_stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpSnapshot {
    pub datagrams: u64,
    pub bytes: u64,
    pub fragmented: u64,
    /// High-water mark over the process lifetime; never differenced, because a
    /// maximum cannot be subtracted.
    pub max_payload: u64,
    pub sessions: u64,
    /// Inbound replies admitted by `udp_full_cone` from sources this session had
    /// never sent to (see [`unsolicited`]). Always zero in restricted mode.
    pub unsolicited: u64,
}

impl UdpSnapshot {
    /// Counters accumulated since `prev`. `max_payload` stays the cumulative
    /// high-water mark for the reason above.
    pub fn since(&self, prev: &Self) -> Self {
        Self {
            datagrams: self.datagrams.saturating_sub(prev.datagrams),
            bytes: self.bytes.saturating_sub(prev.bytes),
            fragmented: self.fragmented.saturating_sub(prev.fragmented),
            max_payload: self.max_payload,
            sessions: self.sessions.saturating_sub(prev.sessions),
            unsolicited: self.unsolicited.saturating_sub(prev.unsolicited),
        }
    }

    /// Nothing happened in this interval; callers use it to stay quiet.
    pub fn is_idle(&self) -> bool {
        self.datagrams == 0 && self.sessions == 0
    }
}

impl std::fmt::Display for UdpSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} session(s), {} datagram(s) / {:.2} MiB, {} fragmented",
            self.sessions,
            self.datagrams,
            self.bytes as f64 / (1024.0 * 1024.0),
            self.fragmented
        )?;
        // Only in the opt-in mode, so the default 60 s relay line stays
        // byte-identical to before the counter existed.
        if self.unsolicited > 0 {
            write!(f, ", {} unsolicited (full-cone)", self.unsolicited)?;
        }
        Ok(())
    }
}
