//! Frame-buffer lifecycle decision bench: the production per-frame shape
//! (`Vec::with_capacity(exact)` + `Bytes::from`) against the trialled frame
//! pool (`Bytes::from_owner` + a sharded reusable buffer stack), on the two
//! lifecycles a relay frame actually has.
//!
//! **Verdict (measured): pooling loses.** The production encoders in
//! `src/mqp/` therefore allocate one exact-fit `Vec` per frame and hand it to
//! `Bytes::from(Vec)`, whose `len == capacity` fast path (`into_boxed_slice`
//! in place) reuses the Vec's allocation as the shared state — no second
//! allocation, and the allocator (mimalloc) recycles it on the allocating
//! thread. The pooled route cannot avoid paying a control-block `Box` per
//! frame (`Bytes::from_owner` boxes `Owned { ref_cnt, owner }`), and a pooled
//! buffer has fixed 2048 B capacity while frames vary, so it can never hit
//! the exact-fit path either. On top of that the pool hands hot buffers
//! across cores every frame, which per-thread allocator caches do not.
//! Numbers on the dev box (M-series, mimalloc, 2 M frames per cell, two
//! runs):
//!
//! ```text
//! payload    lifecycle      plain        pooled        delta
//! 128 B      same-thread    15..19 ns    22..25 ns     +45..52%
//! 128 B      cross-thread   29..38 ns    123..147 ns   +284..324%
//! 1200 B     same-thread    25 ns        34..35 ns     +39..42%
//! 1200 B     cross-thread   51..53 ns    118..136 ns   +128..158%
//! ```
//!
//! This example is kept as the reproducible record of that decision: if a
//! future change (a different allocator, a different `bytes` release, batched
//! handoff) wants to re-trial pooling, it must beat this table first. Run
//! with `--release`:
//!
//! ```sh
//! cargo run --release --example frame_bench
//! ```
//!
//! Only comparable within one machine/run; absolute values depend on the
//! allocator and core count.

use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use std::hint::black_box;
use std::sync::mpsc::sync_channel;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;

/// `0x02 | sess=42 u32le | atyp=0x01 127.0.0.1:8080` — the same 12 bytes the
/// IPv4 steady-state prefix cache holds in `mqp::datagram`.
const HEADER: [u8; 12] = [0x02, 42, 0, 0, 0, 0x01, 127, 0, 0, 1, 0x1f, 0x90];

const SAME_THREAD_ITERS: usize = 2_000_000;
const CROSS_THREAD_ITERS: usize = 2_000_000;
const CROSS_BATCH: usize = 64;

fn plain_frame(payload: &[u8]) -> Bytes {
    let mut v = Vec::with_capacity(HEADER.len() + payload.len());
    v.extend_from_slice(&HEADER);
    v.extend_from_slice(payload);
    Bytes::from(v)
}

// ---------------- the trialled pool, verbatim in shape ----------------

const FRAME_CLASS: usize = 2048;
const SHARDS: usize = 16;
const DEPTH: usize = 64;

struct FramePool {
    shards: Box<[ArrayQueue<Vec<u8>>]>,
}

struct FrameBuf {
    v: Vec<u8>,
    pool: Arc<FramePool>,
}

impl AsRef<[u8]> for FrameBuf {
    fn as_ref(&self) -> &[u8] {
        &self.v
    }
}

impl Drop for FrameBuf {
    fn drop(&mut self) {
        self.pool.put(std::mem::take(&mut self.v));
    }
}

impl FramePool {
    fn new() -> Self {
        Self {
            shards: (0..SHARDS)
                .map(|_| ArrayQueue::new(DEPTH))
                .collect::<Box<_>>(),
        }
    }

    fn take(&self) -> Vec<u8> {
        let me = shard_index();
        for k in 0..SHARDS {
            if let Some(v) = self.shards[(me + k) % SHARDS].pop() {
                return v;
            }
        }
        Vec::with_capacity(FRAME_CLASS)
    }

    fn put(&self, mut v: Vec<u8>) {
        if v.capacity() < FRAME_CLASS || v.capacity() > 2 * FRAME_CLASS {
            return;
        }
        v.clear();
        let _ = self.shards[shard_index()].push(v);
    }

    fn freeze(self: &Arc<Self>, v: Vec<u8>) -> Bytes {
        Bytes::from_owner(FrameBuf {
            v,
            pool: Arc::clone(self),
        })
    }
}

fn shard_index() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static IDX: usize = NEXT.fetch_add(1, Ordering::Relaxed) % SHARDS;
    }
    IDX.with(|i| *i)
}

fn global_pool() -> &'static Arc<FramePool> {
    static POOL: OnceLock<Arc<FramePool>> = OnceLock::new();
    POOL.get_or_init(|| Arc::new(FramePool::new()))
}

fn pooled_frame(payload: &[u8]) -> Bytes {
    let mut v = global_pool().take();
    v.extend_from_slice(&HEADER);
    v.extend_from_slice(payload);
    global_pool().freeze(v)
}

// ---------------- measurement ----------------

fn bench_same_thread(iterations: usize, payload: &[u8], make: fn(&[u8]) -> Bytes) -> f64 {
    let start = Instant::now();
    for _ in 0..iterations {
        let b = make(payload);
        black_box(&b);
        drop(b);
    }
    start.elapsed().as_nanos() as f64 / iterations as f64
}

/// Producer encodes batches and hands them over; the consumer drops them on
/// its own thread — the "frame freed by quinn's driver task" shape. The
/// batch handoff amortizes the channel cost so the buffer path dominates.
fn bench_cross_thread(iterations: usize, payload: &[u8], make: fn(&[u8]) -> Bytes) -> f64 {
    let (tx, rx) = sync_channel::<Vec<Bytes>>(8);
    let consumer = std::thread::spawn(move || {
        while let Ok(batch) = rx.recv() {
            for b in batch {
                black_box(&b);
                drop(b);
            }
        }
    });
    let start = Instant::now();
    let mut sent = 0;
    while sent < iterations {
        let n = CROSS_BATCH.min(iterations - sent);
        let mut batch = Vec::with_capacity(n);
        for _ in 0..n {
            batch.push(make(payload));
        }
        tx.send(batch).expect("consumer alive");
        sent += n;
    }
    drop(tx);
    consumer.join().expect("consumer");
    start.elapsed().as_nanos() as f64 / iterations as f64
}

fn main() {
    println!(
        "frame_bench — MQP-2 outbound frame buffers (mimalloc); the pooled design measured slower, see the header"
    );
    println!(
        "{:<10} {:<12} {:>12} {:>12} {:>9}",
        "payload", "lifecycle", "plain", "pooled", "delta"
    );
    // Warmup: touch the pool and the allocator once before the timed loops.
    for payload in [vec![0xABu8; 128], vec![0xABu8; 1200]] {
        for _ in 0..10_000 {
            drop(plain_frame(&payload));
            drop(pooled_frame(&payload));
        }
        let label = format!("{} B", payload.len());
        for (lifecycle, iters) in [
            ("same-thread", SAME_THREAD_ITERS),
            ("cross-thread", CROSS_THREAD_ITERS),
        ] {
            let plain = if lifecycle == "same-thread" {
                bench_same_thread(iters, &payload, plain_frame)
            } else {
                bench_cross_thread(iters, &payload, plain_frame)
            };
            let pooled = if lifecycle == "same-thread" {
                bench_same_thread(iters, &payload, pooled_frame)
            } else {
                bench_cross_thread(iters, &payload, pooled_frame)
            };
            let delta = (pooled - plain) / plain * 100.0;
            println!(
                "{label:<10} {lifecycle:<12} {:>9.1} ns {:>9.1} ns {:>+8.1}%",
                plain, pooled, delta
            );
        }
    }
}
