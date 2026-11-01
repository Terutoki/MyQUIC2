//! Micro-benchmark for the per-packet sync DNS probe (`lookup_cached_fast`).
//!
//! Not part of the shipped product: it exists so the cost of the memo probe —
//! key build, hash, set probe, clock read — can be measured instead of argued
//! about. Run with `cargo run --release --example dns_probe_bench`.
//!
//! `hit` is the warm path a busy relay takes for every datagram whose target is
//! already resolved; `miss` is the same probe for a name that is not cached
//! (no clock read: the memo answers before any deadline is compared).

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use myquic2::dns::{CachedLookup, dns_cache_seed, lookup_cached_fast};

/// Names chosen to span the length range a real proxy sees: short brand names,
/// ordinary two-label names, and the deep CDN names that dominate datagram
/// traffic in practice.
const HOSTS: &[&str] = &[
    "a.co",
    "example.com",
    "api.openai.com",
    "images.cdn.example.com",
    "eu-west-1.assets.static.exampleservice.example.com",
];

fn addr(i: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 443)
}

fn bench<F: FnMut() -> CachedLookup>(label: &str, iters: u64, mut f: F) {
    // Warm the branch predictors and the memo.
    let mut acc = 0u64;
    for _ in 0..iters / 20 {
        acc += u64::from(matches!(f(), CachedLookup::Addr(_)));
    }
    let t = Instant::now();
    for _ in 0..iters {
        acc += u64::from(matches!(f(), CachedLookup::Addr(_)));
    }
    let ns = t.elapsed().as_nanos() as f64 / iters as f64;
    println!("{label:<28} {ns:>7.2} ns/op   (checksum {acc})");
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    for (i, host) in HOSTS.iter().enumerate() {
        dns_cache_seed(host, 443, addr(i as u8 + 1)).await;
    }

    let iters = 20_000_000u64;
    let mut i = 0usize;
    bench("warm hit (per-datagram)", iters, || {
        i += 1;
        lookup_cached_fast(black_box(HOSTS[i % HOSTS.len()]), 443)
    });

    let mut j = 0usize;
    bench("cold miss (no clock read)", iters, || {
        j += 1;
        // Same length/shape as a resident name, but never seeded.
        let name = black_box(match j % 2 {
            0 => "api.openai.org",
            _ => "images.cdn.example.org",
        });
        lookup_cached_fast(name, 443)
    });

    // Clock cost on its own: the warm probe pays it once per hit.
    bench("coarse_millis() alone", iters, || {
        black_box(myquic2::coarse_millis());
        CachedLookup::Unknown
    });

    // One fixed host per shape: isolates the per-byte part of key build + hash.
    bench("warm hit, 4-byte host", iters, || {
        lookup_cached_fast(black_box("a.co"), 443)
    });
    bench("warm hit, 50-byte host", iters, || {
        lookup_cached_fast(
            black_box("eu-west-1.assets.static.exampleservice.example.com"),
            443,
        )
    });

    // Negatives take the same probe plus an epoch load.
    for (i, host) in HOSTS.iter().enumerate() {
        myquic2::dns::dns_neg_cache_seed(host, 8443 + i as u16).await;
    }
    let mut k = 0usize;
    bench("negative hit (per-datagram)", iters, || {
        k += 1;
        lookup_cached_fast(
            black_box(HOSTS[k % HOSTS.len()]),
            8443 + (k % HOSTS.len()) as u16,
        )
    });
}
