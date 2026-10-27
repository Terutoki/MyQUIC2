//! MQP-3 rev2 / rev3 parse-cost micro-bench: what a per-DATAGRAM frame costs in
//! CPU and in header bytes, and what the removable parts are.
//!
//! This is the measurement companion of `analysis/rev3/parse-cost.md`. It is
//! **not** an end-to-end bench (that is `examples/hotpath_bench.rs`) and it does
//! not re-trial frame pooling (`examples/frame_bench.rs` already rejected it by
//! measurement: keep the exact `Vec` + `Bytes::from` per frame). Every cell is
//! the *incremental* cost of one codec/table operation, so the report can price
//! a proposed change instead of arguing it.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --example rev3_bench
//! ```
//!
//! Notes on interpreting the numbers:
//!
//! * `ns/op` is the **minimum of 5 rounds** after a 10 % warmup, so it is the
//!   best-case (uncontended) cost of the operation, which is what a per-datagram
//!   path pays in steady state. Run-to-run noise on a laptop is ~+/- 10 %; only
//!   compare cells measured in the same run.
//! * The decode benches pass a `Bytes` frame that is already in cache (a hot
//!   loop on one frame): they price the *bytes-in-registers* work, not the
//!   cold-cache datagram arrival. The per-packet cache miss is transport cost,
//!   not codec cost.
//! * `decode + iterate` is what the client/server actually do with a TRAIN
//!   (dedupe pass then dispatch pass); `decode` alone is the eager-validation
//!   pass inside `r2::decode_train`.
//! * The `ref_*` functions are hand-written clean-slate references: a
//!   single-pass decoder / encoder with no `[u32; 64]` by-value copies and no
//!   double varint traversal. They are the target shape for a rev3 codec; the
//!   delta against the production `r2::*` function is the price of the current
//!   design.
//!
//! The table printed at the end is the wire-header arithmetic from
//! `src/mqp/r2.rs` (no timing): use it to check the report's byte-layout table.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;

use myquic2::mqp::addr::TargetAddr;
use myquic2::mqp::r2;
use myquic2::mqp::r2_flow::{FlowBinding, FlowRegistry, SessionFlows};

const ROUNDS: u32 = 5;

/// Fixture-encoding cap: a *real* DATAGRAM budget is ~1162 B (so a 1162 B frame
/// of 60 B payloads carries ~18 TRAIN items, not 64). The benches that need the
/// codec's 64-item maximum use this larger cap so the per-item CPU cost can be
/// isolated from the DATAGRAM-size limit; the report says so.
const BENCH_LIMIT: usize = 1 << 16;

fn bench<F>(label: &str, iters: u64, mut f: F) -> f64
where
    F: FnMut() -> u64,
{
    // Warmup: 10 % of the measured iterations (min 1) so the first round never
    // pays page faults / allocator growth.
    let warm = (iters / 10).max(1);
    let mut acc = 0u64;
    for _ in 0..warm {
        acc = acc.wrapping_add(f());
    }
    let mut best = f64::MAX;
    for _ in 0..ROUNDS {
        let start = Instant::now();
        let mut a = 0u64;
        for _ in 0..iters {
            a = a.wrapping_add(f());
        }
        let ns = start.elapsed().as_nanos() as f64 / iters as f64;
        black_box(a);
        best = best.min(ns);
    }
    black_box(acc);
    println!("{label:<60} {best:>9.2} ns/op");
    best
}

// ---------------- wire helpers used by the reference codecs ----------------

/// LEB128 length (same definition as `r2::varint_len`; local copy so the
/// reference encoder/decoder helpers stay self-contained).
fn varint_len(mut n: u32) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

fn put_varint(out: &mut Vec<u8>, mut n: u32) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn rd_varint(b: &[u8], off: &mut usize) -> Option<u32> {
    let mut value = 0u32;
    for i in 0..5 {
        let byte = *b.get(*off)?;
        *off += 1;
        if i == 4 {
            if byte & 0xF0 != 0 {
                return None;
            }
            return Some(value | (u32::from(byte) << 28));
        }
        value |= u32::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

// ---------------- clean-slate reference encoders ----------------

/// Steady DATA written in one varint pass into an exact-size `Vec`.
fn ref_encode_data_steady(id: u32, payload: &[u8]) -> Bytes {
    let mut hdr = [0u8; 5];
    let mut n = 0usize;
    let mut v = id;
    loop {
        if v < 0x80 {
            hdr[n] = v as u8;
            n += 1;
            break;
        }
        hdr[n] = (v as u8) | 0x80;
        n += 1;
        v >>= 7;
    }
    let mut out = Vec::with_capacity(1 + n + payload.len());
    out.push(0x00);
    out.extend_from_slice(&hdr[..n]);
    out.extend_from_slice(payload);
    Bytes::from(out)
}

/// Dict TRAIN written once, with the caller-provided exact capacity (the
/// production encoder recomputes it in a second validation pass).
fn ref_encode_train_dict(flows: &[u32], items: &[(u8, &[u8])], cap: usize) -> Bytes {
    let mut out = Vec::with_capacity(cap);
    out.push(0x04);
    out.push(0x01);
    out.push(items.len() as u8);
    out.push(flows.len() as u8);
    for f in flows {
        put_varint(&mut out, *f);
    }
    for (idx, p) in items {
        out.push(*idx);
        put_varint(&mut out, p.len() as u32);
        out.extend_from_slice(p);
    }
    Bytes::from(out)
}

// ---------------- clean-slate reference decoders ----------------

/// Same-flow TRAIN decoded **and iterated in one pass**, no `[u32; 64]` copy:
/// the id is a local and each item is bounds-checked exactly once.
fn ref_decode_train_same(b: &[u8]) -> Option<u64> {
    if *b.first()? != r2::R2_TRAIN || *b.get(1)? != r2::R2_TRAIN_FORM_SAME {
        return None;
    }
    let count = usize::from(*b.get(2)?);
    if count == 0 || count > r2::R2_MAX_TRAIN_ITEMS {
        return None;
    }
    let mut off = 3usize;
    let id = rd_varint(b, &mut off)?;
    let mut acc = u64::from(id);
    for _ in 0..count {
        let len = rd_varint(b, &mut off)? as usize;
        let end = off.checked_add(len)?;
        let payload = b.get(off..end)?;
        off = end;
        acc = acc.wrapping_add(payload.len() as u64);
    }
    if off != b.len() {
        return None;
    }
    Some(acc)
}

/// Dict TRAIN decoded and iterated in one pass. The flow list still has to be
/// materialized because item indices are random access, but the item pass is
/// the only pass over the items.
fn ref_decode_train_dict(b: &[u8]) -> Option<u64> {
    if *b.first()? != r2::R2_TRAIN || *b.get(1)? != r2::R2_TRAIN_FORM_DICT {
        return None;
    }
    let count = usize::from(*b.get(2)?);
    if count == 0 || count > r2::R2_MAX_TRAIN_ITEMS {
        return None;
    }
    let mut off = 3usize;
    let nfl = usize::from(*b.get(off)?);
    off += 1;
    if nfl == 0 || nfl > count || nfl > r2::R2_MAX_TRAIN_ITEMS {
        return None;
    }
    let mut flows = [0u32; r2::R2_MAX_TRAIN_ITEMS];
    for slot in flows.iter_mut().take(nfl) {
        let f = rd_varint(b, &mut off)?;
        if f == 0 {
            return None;
        }
        *slot = f;
    }
    let mut acc = 0u64;
    for _ in 0..count {
        let idx = usize::from(*b.get(off)?);
        off += 1;
        if idx >= nfl {
            return None;
        }
        acc = acc.wrapping_add(u64::from(flows[idx]));
        let len = rd_varint(b, &mut off)? as usize;
        let end = off.checked_add(len)?;
        let payload = b.get(off..end)?;
        off = end;
        acc = acc.wrapping_add(payload.len() as u64);
    }
    if off != b.len() {
        return None;
    }
    Some(acc)
}

// ---------------- fixture builders ----------------

fn v4(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

fn v6(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
}

fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect()
}

fn steady_frame(id: u32, payload: &[u8]) -> Bytes {
    r2::encode_data_steady(id, payload, BENCH_LIMIT).expect("steady frame")
}

fn same_train(frame_id: u32, items: &[Vec<u8>]) -> Bytes {
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    r2::encode_train_same(frame_id, &refs, BENCH_LIMIT).expect("same train")
}

fn dict_train(flows: &[u32], items: &[(u8, Vec<u8>)]) -> Bytes {
    let refs: Vec<(u8, &[u8])> = items.iter().map(|(i, p)| (*i, p.as_slice())).collect();
    r2::encode_train_dict(flows, &refs, BENCH_LIMIT).expect("dict train")
}

// ---------------- decode benches ----------------

fn bench_decode_data() {
    println!("\n== DATA decode (r2::decode_data; one varint + payload slice) ==");
    let pl = payload(128);
    for (label, id) in [
        ("steady id=2 (1 B varint, 2 B hdr)", 2u32),
        ("steady id=200 (2 B varint, 3 B hdr)", 200u32),
        ("steady id=20000 (3 B varint, 4 B hdr)", 20_000u32),
    ] {
        let frame = steady_frame(id, &pl);
        bench(label, 2_000_000, || {
            let d = r2::decode_data(black_box(&frame[..])).expect("decode");
            d.payload.len() as u64 + u64::from(d.id.unwrap_or(0))
        });
    }

    // OPEN / INLINE: address decode cost (TargetAddrRef::decode, no alloc).
    let open_v4 =
        r2::encode_data_open(200, 7, &r2::ip_ref(v4(53)), false, &pl, BENCH_LIMIT).unwrap();
    bench("DATA OPEN IPv4 id=200 (15 B hdr)", 1_500_000, || {
        let d = r2::decode_data(black_box(&open_v4[..])).expect("decode open");
        d.payload.len() as u64 + u64::from(d.sess.unwrap_or(0))
    });
    let open_v6 =
        r2::encode_data_open(200, 7, &r2::ip_ref(v6(53)), false, &pl, BENCH_LIMIT).unwrap();
    bench("DATA OPEN IPv6 id=200 (27 B hdr)", 1_500_000, || {
        let d = r2::decode_data(black_box(&open_v6[..])).expect("decode open v6");
        d.payload.len() as u64 + u64::from(d.sess.unwrap_or(0))
    });
    let addr_dom = myquic2::mqp::addr::TargetAddrRef::Domain("example.com", 53);
    let open_dom = r2::encode_data_open(200, 7, &addr_dom, false, &pl, BENCH_LIMIT).unwrap();
    bench("DATA OPEN domain L=11 id=200 (23 B hdr)", 1_500_000, || {
        let d = r2::decode_data(black_box(&open_dom[..])).expect("decode open dom");
        d.payload.len() as u64 + u64::from(d.sess.unwrap_or(0))
    });
    // The domain form pays UTF-8 validation (`std::str::from_utf8`) where the
    // IP forms pay only bounds checks; the delta vs OPEN IPv4 above is its cost
    // (the extra address bytes are the same slice work either way).
    let inline_v4 =
        r2::encode_data_inline(7, &r2::ip_ref(v4(53)), false, &pl, BENCH_LIMIT).unwrap();
    bench("DATA INLINE IPv4 (13 B hdr)", 1_500_000, || {
        let d = r2::decode_data(black_box(&inline_v4[..])).expect("decode inline");
        d.payload.len() as u64 + u64::from(d.sess.unwrap_or(0))
    });
}

fn bench_decode_train() {
    println!("\n== TRAIN decode (r2::decode_train = eager validation pass) ==");
    for n in [1usize, 8, 64] {
        let items: Vec<Vec<u8>> = (0..n).map(|_| payload(60)).collect();
        let frame = same_train(2, &items);
        bench(
            &format!("same n={n}: decode only (validation pass)"),
            400_000,
            || {
                let t = r2::decode_train(black_box(&frame[..])).expect("decode train");
                u64::from(t.count)
            },
        );
        bench(
            &format!("same n={n}: decode + iterate once (r2::TrainItems)"),
            300_000,
            || {
                let t = r2::decode_train(black_box(&frame[..])).expect("decode train");
                let mut acc = 0u64;
                for (id, p) in t.items() {
                    acc = acc.wrapping_add(u64::from(id)).wrapping_add(p.len() as u64);
                }
                acc
            },
        );
        bench(
            &format!("same n={n}: decode + iterate twice (dedupe + dispatch)"),
            300_000,
            || {
                let t = r2::decode_train(black_box(&frame[..])).expect("decode train");
                let mut acc = 0u64;
                for (id, p) in t.items() {
                    acc = acc.wrapping_add(u64::from(id)).wrapping_add(p.len() as u64);
                }
                for (id, p) in t.items() {
                    acc = acc.wrapping_add(u64::from(id)).wrapping_add(p.len() as u64);
                }
                acc
            },
        );
        bench(
            &format!("same n={n}: ref single-pass decode+iterate"),
            300_000,
            || ref_decode_train_same(black_box(&frame[..])).expect("ref decode"),
        );
    }

    // Dict form: nfl distinct flows, items round-robin over them.
    for nfl in [2usize, 8, 64] {
        let flows: Vec<u32> = (0..nfl as u32)
            .map(|local| r2::make_wire_id(local + 1, false).unwrap())
            .collect();
        let items: Vec<(u8, Vec<u8>)> = (0..nfl).map(|i| ((i % nfl) as u8, payload(60))).collect();
        let frame = dict_train(&flows, &items);
        bench(
            &format!("dict nfl={nfl}: decode + iterate twice (production shape)"),
            200_000,
            || {
                let t = r2::decode_train(black_box(&frame[..])).expect("decode dict");
                let mut acc = 0u64;
                for (id, p) in t.items() {
                    acc = acc.wrapping_add(u64::from(id)).wrapping_add(p.len() as u64);
                }
                for (id, p) in t.items() {
                    acc = acc.wrapping_add(u64::from(id)).wrapping_add(p.len() as u64);
                }
                acc
            },
        );
        bench(
            &format!("dict nfl={nfl}: ref single-pass decode+iterate"),
            200_000,
            || ref_decode_train_dict(black_box(&frame[..])).expect("ref dict"),
        );
    }
}

fn bench_decode_frag() {
    println!("\n== FRAG decode (r2::decode_frag; steady header, chunk view) ==");
    let chunk = payload(1_100);
    let frame = r2::encode_frag_steady(200, 7, 0, 2, &chunk, BENCH_LIMIT).expect("frag");
    bench(
        "FRAG steady id=200 (9 B hdr, 1100 B chunk)",
        1_000_000,
        || {
            let f = r2::decode_frag(black_box(&frame[..])).expect("decode frag");
            f.chunk.len() as u64 + u64::from(f.frag_id)
        },
    );
    // The reassembler's per-fragment hash work (`(wire_id, frag_id)` map) is
    // part of fragment cost, not codec cost; see the report.
}

// ---------------- encode benches ----------------

fn bench_encode_data() {
    println!("\n== DATA encode (exact Vec + Bytes::from; 1 alloc + 1 payload copy) ==");
    let pl = payload(128);
    for (label, id) in [
        ("steady id=2 (2 B hdr)", 2u32),
        ("steady id=200 (3 B hdr)", 200u32),
        ("steady id=20000 (4 B hdr)", 20_000u32),
    ] {
        bench(label, 1_000_000, || {
            let b = r2::encode_data_steady(black_box(id), black_box(pl.as_slice()), 1_400)
                .expect("encode");
            u64::from(b.len() as u32)
        });
    }
    bench(
        "steady id=200: ref single-varint-pass encoder",
        1_000_000,
        || {
            let b = ref_encode_data_steady(black_box(200), black_box(pl.as_slice()));
            u64::from(b.len() as u32)
        },
    );

    let addr = r2::ip_ref(v4(53));
    bench(
        "OPEN IPv4 id=200 (15 B hdr, addr validated once)",
        500_000,
        || {
            let b = r2::encode_data_open(200, 7, &addr, false, black_box(pl.as_slice()), 1_400)
                .expect("open");
            u64::from(b.len() as u32)
        },
    );
    bench("INLINE IPv4 (13 B hdr)", 500_000, || {
        let b = r2::encode_data_inline(7, &addr, false, black_box(pl.as_slice()), 1_400)
            .expect("inline");
        u64::from(b.len() as u32)
    });
}

fn bench_encode_train() {
    println!("\n== TRAIN encode (two-pass: *_len validation then write) ==");
    let items: Vec<Vec<u8>> = (0..64).map(|_| payload(60)).collect();
    let same_refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    bench(
        "same n=64: encode (train_same_len + write)",
        100_000,
        || {
            let b = r2::encode_train_same(200, &same_refs, BENCH_LIMIT).expect("train same");
            u64::from(b.len() as u32)
        },
    );
    bench(
        "same n=64: train_same_len alone (validation+measure)",
        200_000,
        || r2::train_same_len(200, &same_refs).expect("len") as u64,
    );

    for nfl in [2usize, 8, 64] {
        let flows: Vec<u32> = (0..nfl as u32)
            .map(|local| r2::make_wire_id(local + 1, false).unwrap())
            .collect();
        let item_vecs: Vec<Vec<u8>> = (0..nfl).map(|_| payload(60)).collect();
        let item_refs: Vec<(u8, &[u8])> = item_vecs
            .iter()
            .enumerate()
            .map(|(i, p)| ((i % nfl) as u8, p.as_slice()))
            .collect();
        let cap = r2::train_dict_len(&flows, &item_refs).expect("dict len");
        bench(
            &format!("dict nfl={nfl}: train_dict_len alone (O(nfl^2) dedupe)"),
            200_000,
            || {
                r2::train_dict_len(black_box(flows.as_slice()), black_box(item_refs.as_slice()))
                    .expect("len") as u64
            },
        );
        bench(
            &format!("dict nfl={nfl}: encode_train_dict (len + write)"),
            150_000,
            || {
                let b = r2::encode_train_dict(
                    black_box(flows.as_slice()),
                    black_box(item_refs.as_slice()),
                    BENCH_LIMIT,
                )
                .expect("dict");
                u64::from(b.len() as u32)
            },
        );
        bench(
            &format!("dict nfl={nfl}: ref write-only (cap precomputed = {cap})"),
            200_000,
            || {
                let b = ref_encode_train_dict(
                    black_box(flows.as_slice()),
                    black_box(item_refs.as_slice()),
                    black_box(cap),
                );
                u64::from(b.len() as u32)
            },
        );
    }
}

// ---------------- flow/session table benches ----------------

/// Direct-indexed replacement for the `RwLock<HashMap>` registry: one mask, one
/// load, one full-id compare. 16 B/slot (full `wire_id` + optional `Arc`) keeps
/// a stale frame from matching a slot whose id wrapped (the full id is
/// compared, so no-reuse safety does not depend on the index).
struct DirectTable {
    slots: Vec<Option<(u32, Arc<FlowBinding>)>>,
}

impl DirectTable {
    fn with_capacity(slots: usize) -> Self {
        Self {
            slots: (0..slots).map(|_| None).collect::<Vec<_>>(),
        }
    }

    fn insert(&mut self, binding: Arc<FlowBinding>) {
        let idx = binding.wire_id as usize & (self.slots.len() - 1);
        self.slots[idx] = Some((binding.wire_id, binding));
    }

    fn get(&self, wire_id: u32) -> Option<Arc<FlowBinding>> {
        let idx = wire_id as usize & (self.slots.len() - 1);
        match &self.slots[idx] {
            Some((id, binding)) if *id == wire_id => Some(binding.clone()),
            _ => None,
        }
    }
}

fn bench_registry() {
    println!("\n== FlowRegistry lookup (RwLock<HashMap<foldhash>> + Arc clone) ==");
    let reg = FlowRegistry::new(4096);
    let direct_cap = 8192usize; // wire_id space for 4096 flows x 2 owners
    let mut direct = DirectTable::with_capacity(direct_cap);
    let mut ids = Vec::new();
    for local in 1..=64u32 {
        let wire_id = r2::make_wire_id(local, false).unwrap();
        ids.push(wire_id);
        let binding = FlowBinding::new_shared(wire_id, 1, TargetAddr::Ip(v4(1000 + local as u16)));
        direct.insert(binding.clone());
        let _ = reg.insert(binding).expect("insert");
    }
    let hot = ids[31];
    bench("get(hot id) + Arc clone/drop", 2_000_000, || {
        let b = reg.get(black_box(hot));
        b.as_ref().map_or(0, |b| u64::from(b.session))
    });
    bench(
        "direct table get(hot id) + Arc clone/drop",
        2_000_000,
        || {
            let b = direct.get(black_box(hot));
            b.as_ref().map_or(0, |b| u64::from(b.session))
        },
    );
    // Cycle over 64 ids: the hash and the slot compare stay in the same
    // cache lines in both shapes, so the delta is the lock+hash, not the miss.
    let mut cursor = 0usize;
    bench("get(cycling 64 ids) + Arc clone/drop", 1_000_000, || {
        cursor = (cursor + 1) & 63;
        let b = reg.get(black_box(ids[cursor]));
        b.as_ref().map_or(0, |b| u64::from(b.session))
    });
    let mut cursor = 0usize;
    bench(
        "direct get(cycling 64 ids) + Arc clone/drop",
        1_000_000,
        || {
            cursor = (cursor + 1) & 63;
            let b = direct.get(black_box(ids[cursor]));
            b.as_ref().map_or(0, |b| u64::from(b.session))
        },
    );

    // get_batch: one read-lock hold for a whole TRAIN frame (production shape
    // for up to 64 distinct item ids).
    let mut slots: Vec<(u32, Option<Arc<FlowBinding>>)> = (0..64).map(|i| (ids[i], None)).collect();
    bench("get_batch(64 ids) one read-lock hold", 300_000, || {
        reg.get_batch(black_box(slots.as_mut_slice()));
        slots.iter().filter(|(_, b)| b.is_some()).count() as u64
    });
}

fn bench_session_flows() {
    println!("\n== SessionFlows (per-session reverse table) ==");
    for n in [1usize, 8, 64] {
        let mut flows = SessionFlows::new();
        for i in 0..n {
            let wire_id = r2::make_wire_id(i as u32 + 1, false).unwrap();
            let binding = FlowBinding::new_shared(wire_id, 1, TargetAddr::Ip(v4(1000 + i as u16)));
            assert!(flows.insert(binding));
        }
        let first = TargetAddr::Ip(v4(1000));
        let last = TargetAddr::Ip(v4(1000 + (n - 1) as u16));
        let ref_first = first.as_ref();
        let ref_last = last.as_ref();
        bench(&format!("find(target at slot 0), n={n}"), 1_000_000, || {
            flows
                .find(black_box(&ref_first))
                .map_or(0, |b| u64::from(b.session))
        });
        bench(
            &format!("find(target at slot n-1), n={n} (worst case)"),
            1_000_000,
            || {
                flows
                    .find(black_box(&ref_last))
                    .map_or(0, |b| u64::from(b.session))
            },
        );
        // Server reply path: classify one reply source; worst case = last slot.
        let src = v4(1000 + (n - 1) as u16);
        bench(
            &format!("match_source(last flow), n={n} (per reply)"),
            500_000,
            || match flows.match_source(black_box(src)) {
                Some(_) => 1,
                None => 0,
            },
        );
        bench(
            &format!("match_source(first flow), n={n}"),
            500_000,
            || match flows.match_source(black_box(v4(1000))) {
                Some(_) => 1,
                None => 0,
            },
        );
    }
}

// ---------------- wire-header arithmetic (no timing) ----------------

fn print_wire_table() {
    println!("\n== wire header bytes (from src/mqp/r2.rs length functions) ==");
    println!("-- steady DATA header (1 kind + varint(wire_id)) --");
    println!(
        "{:>12}  {:>8}  {:>6}  {:>8}",
        "local_id", "wire_id", "id_len", "DATA hdr"
    );
    for local in [1u32, 63, 64, 127, 128, 8191, 8192, 1_048_575] {
        for owner in [false, true] {
            let wire_id = r2::make_wire_id(local, owner).unwrap();
            println!(
                "{:>12}  {:>8}  {:>6}  {:>8}",
                local,
                wire_id,
                varint_len(wire_id),
                r2::data_steady_len(wire_id, 0)
            );
        }
    }

    println!("\n-- form headers (payload_len = 0) --");
    let addr_v4 = r2::ip_ref(v4(53));
    let addr_v6 = r2::ip_ref(v6(53));
    let addr_dom = myquic2::mqp::addr::TargetAddrRef::Domain("example.com", 53);
    let l4 = addr_v4.header().unwrap().len();
    let l6 = addr_v6.header().unwrap().len();
    let ld = addr_dom.header().unwrap().len();
    for (label, id) in [("id=2", 2u32), ("id=200", 200u32), ("id=20000", 20_000u32)] {
        println!(
            "  {label:>8}: DATA open v4={} v6={} dom={} | inline v4={} v6={} dom={}",
            r2::data_open_len(id, l4, 0),
            r2::data_open_len(id, l6, 0),
            r2::data_open_len(id, ld, 0),
            r2::data_inline_len(l4, 0),
            r2::data_inline_len(l6, 0),
            r2::data_inline_len(ld, 0),
        );
        println!(
            "  {label:>8}: FRAG steady={} open v4={} v6={} dom={} | inline v4={} v6={} dom={}",
            r2::frag_steady_len(id, 0),
            r2::frag_open_len(id, l4, 0),
            r2::frag_open_len(id, l6, 0),
            r2::frag_open_len(id, ld, 0),
            r2::frag_inline_len(l4, 0),
            r2::frag_inline_len(l6, 0),
            r2::frag_inline_len(ld, 0),
        );
    }

    println!("\n-- TRAIN headers (payload_len = 0) --");
    let empty: &[u8] = &[];
    let one: [&[u8]; 1] = [empty];
    let flows2 = [2u32, 200u32];
    let items1: [(u8, &[u8]); 1] = [(0, empty)];
    for id in [2u32, 200, 20_000] {
        println!(
            "  id={id:>6}: same n=1 hdr={} | dict nfl=1 item0 hdr={}",
            r2::train_same_len(id, &one).unwrap(),
            r2::train_dict_len(&flows2[..1], &items1).unwrap(),
        );
    }

    let p60 = payload(60);
    let refs64: Vec<&[u8]> = (0..64).map(|_| p60.as_slice()).collect();
    let total64 = r2::train_same_len(2, &refs64).unwrap();
    println!(
        "  64-item same train, 60 B payloads, 1 B id: {total64} B total ({:.2} B/item)",
        total64 as f64 / 64.0
    );

    let flows8: Vec<u32> = (0..8u32)
        .map(|local| r2::make_wire_id(local + 1, false).unwrap())
        .collect();
    let payloads8: Vec<Vec<u8>> = (0..8).map(|_| payload(60)).collect();
    let refs8: Vec<(u8, &[u8])> = payloads8
        .iter()
        .enumerate()
        .map(|(i, p)| (i as u8, p.as_slice()))
        .collect();
    let total8 = r2::train_dict_len(&flows8, &refs8).unwrap();
    println!(
        "  8-flow dict train, 8 x 60 B items: {total8} B total ({:.2} B/item)",
        total8 as f64 / 8.0
    );

    println!("\n-- CTL frame bytes --");
    let ctl_cases = [
        (
            "HELLO",
            r2::Ctl::Hello {
                wire_ver: r2::R2_WIRE_VER,
                flags: 0,
            },
        ),
        ("CAPS", r2::Ctl::Caps(r2::Caps::default())),
        (
            "FLOW_ACK id=2",
            r2::Ctl::FlowAck {
                id: 2,
                status: r2::R2_ACK_OPEN,
            },
        ),
        (
            "FLOW_ACK id=200",
            r2::Ctl::FlowAck {
                id: 200,
                status: r2::R2_ACK_OPEN,
            },
        ),
        (
            "FLOW_REJECT id=200",
            r2::Ctl::FlowReject {
                id: 200,
                reason: r2::R2_REJECT_POLICY,
            },
        ),
        ("FLOW_CLOSE id=2", r2::Ctl::FlowClose { id: 2 }),
        ("FLOW_CLOSE id=200", r2::Ctl::FlowClose { id: 200 }),
        ("SESS_CLOSE", r2::Ctl::SessClose { sess: 7, reason: 0 }),
    ];
    for (label, ctl) in ctl_cases {
        let enc = r2::encode_ctl(&ctl);
        debug_assert_eq!(enc.len(), ctl.len());
        println!("  {label:<20} {} B", enc.len());
    }
}

// ---------------- id-length distribution math ----------------

fn print_id_length_math() {
    println!("\n== LEB128 length distribution vs flows ever opened ==");
    println!("wire_id = (local<<1)|owner; local starts at 1 and is never reused.");
    println!("1 B varint: wire_id <= 127  => local <= 63        (63 flows/owner)");
    println!("2 B varint: wire_id <= 16383 => local <= 8191     (8128 flows/owner)");
    println!("3 B varint: wire_id <= 2^21-1 => local <= 1048575");
    println!("CAPS max_conn_flows = 4096 live flows/connection.\n");
    println!(
        "{:>10}  {:>12}  {:>12}  {:>10}",
        "flows ever", "avg id bytes", "avg DATA hdr", "2 B hdr frac"
    );
    for n in [1u64, 63, 64, 128, 512, 1024, 4096, 8192] {
        let one_byte = n.min(63);
        let rest = n - one_byte;
        // The owner bit does not move the 63/8192 boundaries; use local ids
        // 1..=n for the client half.
        let id_bytes = (one_byte + rest.min(8128) * 2) as f64 / n as f64
            + if n > 8191 {
                3.0 * (n - 8191) as f64 / n as f64
            } else {
                0.0
            };
        let hdr = id_bytes + 1.0;
        println!(
            "{n:>10}  {id_bytes:>12.3}  {hdr:>12.3}  {:>10.1}%",
            100.0 * one_byte as f64 / n as f64
        );
    }
}

fn main() {
    println!(
        "rev3_bench — MQP-3 rev2 parse/encode/table cost (release build; min of {ROUNDS} rounds)"
    );
    println!(
        "compare cells only within this run; a 128 B exact-Vec frame alloc+copy+free measured ~15-19 ns in examples/frame_bench.rs"
    );

    bench_decode_data();
    bench_decode_train();
    bench_decode_frag();
    bench_encode_data();
    bench_encode_train();
    bench_registry();
    bench_session_flows();

    print_wire_table();
    print_id_length_math();

    println!("\ndone.");
}
