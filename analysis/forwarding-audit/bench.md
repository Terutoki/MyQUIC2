# Benchmark audit — does commit 41031b4 (client TCP/UDP forward listeners) degrade SOCKS5 TCP/UDP ECHO performance?

Task: task-4. Author: bench-engineer. Date: 2026-10-23 (Asia/Shanghai).
Repo: `/Users/eric/WorkSpace/MyQUIC2`. Machine: macOS arm64 (Apple silicon), 10 cores, 16 GiB.
Toolchain: cargo/rustc 1.99.0. Release builds, no PGO/LTO changes vs `Cargo.toml` defaults.

## TL;DR verdict

| Question | Verdict | Strongest evidence |
|---|---|---|
| **A. SOCKS5 UDP ECHO regression, parent client `1135076` → HEAD client `7232088`** | **No regression in steady-state service quality; small (~5–8 %) burst-headroom / loss-probability degradation in the unpaced blast path.** Paced and multi-association UDP is identical (0.000 % loss in every run); serial UDP latency p50 is identical; at 44 k pps offered the HEAD client starts losing (0.77/1.70 %) while the parent does not (0.00/0.015 %). | `udppaced` 30 k pps: loss 0 % median both arms; `udp` 10 k blast clean median 33,088 → 30,571 pps (−7.6 %, Mann-Whitney z = +3.49); 1–2-datagram loss episodes 9/55 parent vs 19/55 HEAD runs (Fisher p = 0.048) |
| **A. SOCKS5 TCP ECHO regression** | **No.** Steady-state TCP echo throughput and connect/echo latency are unchanged within noise. | 8 MiB `tcpecho` after warm-up: median 89.1 MB/s parent vs 89.5 MB/s HEAD; `lattcp` echo p50 131–136 µs parent vs 131–137 µs HEAD (ranges overlap) |
| **B. Merely configuring 1 idle `tcp_forward` + 1 idle `udp_forward`** | **No measurable interference.** | UDP clean pps 29,512 (no fwd) vs 30,700 (idle fwd); `lat` p50 117/117 µs; all paced/bidir/multipaced losses 0 % both |
| **C. New forwarding paths themselves** | **No obvious perf problem.** UDP forward ≈ or better than SOCKS baseline at 0 loss; TCP forward bulk = SOCKS bulk; 50 concurrent UDP peers at 50.8 k pps aggregate, 0 loss. | see §4 |
| **S0 (lead request): TCP forward data corruption?** | **No — harness verifier artifact, not a relay bug.** | SHA-256 full-stream: tcp_forward 10/10 OK, SOCKS tcpecho control 10/10 OK, direct target control 5/5 OK; corrected chunk compare 20/20 clean (§4.3) |

No repository source file was modified. Working trees: main tree at `7232088`; parent worktree `/tmp/mq2-parent` at `1135076`. Build artifacts in `/tmp/mq2-target-head` and `/tmp/mq2-target-parent` (main tree `target/` untouched).

## 1. Setup and methodology

### 1.1 Builds and binaries

```
git -C /tmp/mq2-parent log --oneline -1        # 1135076 fix(audit): harden rev2 ...
git -C /Users/eric/WorkSpace/MyQUIC2 log -1    # 7232088 chore(release): v0.2.2
CARGO_TARGET_DIR=/tmp/mq2-target-head   cargo build --release --bin myquic2-server --bin myquic2-client --example hotpath_bench
CARGO_TARGET_DIR=/tmp/mq2-target-parent cargo build --release --bin myquic2-client
```

Build timings: HEAD 1 m 43 s, parent 1 m 42 s (parallel). SHA-256 of the exact binaries used:

| binary | sha256 |
|---|---|
| HEAD server `myquic2-server` (used for **all** arms) | `95cbe0cf23776ac86bd439901a9398fa972f04b1768bfe4288ca0e641db7952b` |
| HEAD client `myquic2-client` | `dd901383086b71752d7e76f919afc5e10e451efc986da2b7cd29762c022e511a` |
| parent client `myquic2-client` | `39997607bf60ce99e6e01e06f18394f8aa91d985c7d4a38954683c34db0eca0b` |
| load generator `examples/hotpath_bench` (used for all arms) | `9b3fc7c2ffdd10fc0db19590ec17cd849b5f505464236ea583b452a665c064f1` |

`git diff --stat 1135076 41031b4` touches only the client binary, `src/config/client_conf.rs`, `src/lib.rs` (re-export line), `src/stats/udp_stats.rs` (tests only), tests/docs/README/Cargo. The server ingest/forward path and the wire are unchanged, so **both A arms run against the identical HEAD server binary**, which cancels server-side drift.

### 1.2 Topology (loopback, high ports)

```
hotpath_bench techo 19000      TCP echo target (one thread per connection)
hotpath_bench echo  19001      UDP echo target (8 SO_REUSEPORT threads)
myquic2-server  127.0.0.1:18443  (HEAD build, BBR, gso, quic_endpoints=1, allow_private=true, auth off)
myquic2-client  127.0.0.1:18080  SOCKS5 TCP CONNECT + UDP ASSOCIATE
  arm parent : client binary built from 1135076, config identical to headA
  arm headA  : HEAD client, no forward listeners
  arm headB  : HEAD client + [[tcp_forward]] 127.0.0.1:18181 -> 127.0.0.1:19000
                             + [[udp_forward]] 127.0.0.1:18282 -> 127.0.0.1:19001
               (both bound, ZERO traffic in scenario B)
```

Server config: `listen=127.0.0.1:18443`, `cert_file`/`key_file` = repo-root `server-cert.pem`/`server-key.pem` (SAN `test.com`), `server_name="test.com"`, `congestion="bbr"`, `gso=true`, `keep_alive_secs=5`, `allow_private=true`, `auth_token=""`, `quic_endpoints=1`.
Client config: `socks_listen=127.0.0.1:18080`, `server_addr=127.0.0.1:18443`, `server_cert_file` as above, `server_name="test.com"`, `auth_token=""`, `congestion="bbr"`, `gso=true`, `keep_alive_secs=5`, `reconnect_timeout_secs=5`, `quic_conns=4`. All other knobs at defaults.
Exact config files are archived in `bench-raw/configs/`.

### 1.3 Measurement discipline

- **Fresh server+client per arm-run** (kill by captured PID; no leftover daemons). Targets stay up across runs.
- **Interleaved arms**: campaigns rotate arm order per repetition (rep1 P→A→B, rep2 B→P→A, …; supplement/latfocus/tcpecho-ab alternate P/HEAD each rep) so drift/thermal/load hits both arms equally.
- **Warm-up phase is discarded** in every arm-run (UDP, TCP echo, paced, latency primitives).
- System load average was 4.0–6.1 on 10 cores throughout (unrelated processes on the box, see per-run `uptime` lines in raw logs). This is the dominant noise source and it hit all arms.
- **The 5 s stall artifact:** `hotpath_bench udp` classifies a datagram as lost after SO_RCVTIMEO failures; a single lost datagram costs ~5.2 s of wall time (10 × 500 ms stalls) before the run ends. Any `udp` run with `recv < sent` is therefore reported separately as a "lossy run" and its `recv_pps` is **not** used. Clean = `recv == sent == 10000 && wall < 2 s`.
- **clean-only selection bias caveat:** the UDP pps medians are computed over clean runs, which conditions on outcome. The arm that loses more often can have its slow-shape runs filtered out; the lossy-frequency metric is therefore reported alongside the pps median, never instead of it.
- `tcpecho` is **bimodal** per client instance: the first few 8 MiB transfers after client start run at ~17–56 MB/s, steady state is ~80–95 MB/s. Scenario-A TCP verdict uses a dedicated A/B with 3 warm-up + 5 measured runs per instance (3 reps), plus the raw campaign medians for transparency.

## 2. Scenario A — SOCKS5 UDP/TCP ECHO, parent client vs HEAD client (same HEAD server)

### 2.1 UDP unpaced blast (`udp 127.0.0.1:18080 127.0.0.1:19001 10000 64`)

Campaign: 3 reps × 5 runs = 15 runs/arm. Supplement: 4 reps × 10 runs = 40 runs/arm.

| arm | campaign clean/total | campaign clean pps median [min, q1–q3, max] | supplement clean/total | supplement clean pps median [min, q1–q3, max] |
|---|---|---|---|---|
| parent `1135076` | 12/15 | **31,176** [27,720; 28,763–36,328; 37,766] | 34/40 | **33,088** [27,697; 30,792–34,441; 37,949] |
| HEAD `7232088` | 8/15 | **29,512** [26,599; 27,831–32,638; 34,200] | 28/40 | **30,571** [24,100; 28,024–32,608; 34,243] |

- Delta of clean medians: **−5.3 %** (campaign), **−7.6 %** (supplement). Supplement Mann-Whitney U = 723 vs n1=34/n2=28 → **z = +3.49** (two-sided ≈ 5·10⁻⁴). Direction is consistent across two independent interleaved campaigns.
- Lossy-run frequency (≥1 datagram missing from a 10,000-packet blast): campaign 3/15 vs 7/15; supplement 6/40 vs 12/40; **pooled 9/55 (16.4 %) parent vs 19/55 (34.5 %) HEAD**, Fisher exact two-sided **p = 0.048**. Effect is small in absolute terms (0.01–0.02 % of datagrams at most, most runs 1–2 lost).

### 2.2 UDP paced (knee sweep, fixed 4 s window, payload 128 B)

`udppaced <socks> 127.0.0.1:19001 4 128 <rate>`, 2 interleaved runs per (rate, arm), loss %:

| offered pps | parent run1 / run2 | HEAD run1 / run2 |
|---|---|---|
| 32,000 | 0.000 / 0.163 | 0.031 / 0.000 |
| 36,000 | 0.000 / 0.062 | 0.203 / 0.005 |
| 40,000 | 0.000 / 0.128 | 0.000 / 0.194 |
| **44,000** | **0.000 / 0.015** | **0.774 / 1.701** |

The only clear separation is at the highest offered rate: HEAD loses ~0.8–1.7 % where the parent is clean. Below 44 k pps both arms are effectively 0 % loss with occasional 0.0x % blips. n = 2 per point — directional, not a precise knee location.

Other paced modes in the campaign suite (3 reps/arm): 6 s `udppaced` at 30 k pps loss: parent [0, 0.062, 0, 0.098, 0, 0] %, HEAD [0, 0.029, 0, 0, 0, 0.184] % → median 0 both. 6 s `udpbidir` at 20 k pps: **0.000 % all 6 runs per arm**. 6 s `udpmultipaced` 4 assocs × 4 k pps: **0.000 % all runs, recv_pps 14,538–14,541 identical**.

### 2.3 UDP serial latency (`lat <socks> 127.0.0.1:19001 500 64`)

| measurement context | parent p50 / p99 (µs, median of runs) | HEAD p50 / p99 |
|---|---|---|
| **isolated** (fresh client, no preceding blast; latfocus: 3 reps × 5 runs/arm) | **116 / 320** (p50 range 110–118, p99 range 220–501) | **116 / 327** (p50 113–118, p99 267–445) |
| in-suite, measured after the blast phase (campaign, 3 arm-runs) | 116 / 284 | 117 / 397 |
| in-suite, measured after the blast phase (supplement, 4 arm-runs) | 116.5 / 164.5 | 117.5 / 312.5 |

Isolated measurement: **no latency difference**. The in-suite p99 gap (HEAD higher in both campaigns, but with heavily overlapping IQRs and a much larger spread than the median difference) is **unresolved**: it may be carry-over state from the preceding blast phase (HEAD had more stalled/lossy blast runs), or a genuine tail effect only visible after burst load. Since it does not reproduce on a fresh client and p50/p90 are identical, it is reported as secondary/needs a longer soak, not as a confirmed regression.

### 2.4 TCP ECHO

`lattcp` (fresh SOCKS CONNECT + 64 B echo, p50 in µs, median of runs):

| context | connect p50 parent / HEAD | echo p50 parent / HEAD |
|---|---|---|
| campaign (9 runs/arm) | 99 / 106 | 131 / 137 |
| supplement (12 runs/arm) | 99 / 100.5 | 131 / 132 |
| latfocus, 300 iters (3 runs/arm) | 107 / 101 | 136 / 131 |

All differences are inside the per-run spread and do not keep a consistent sign → no TCP latency regression.

`tcpecho` 8 MiB throughput:

| context | parent MB/s | HEAD MB/s |
|---|---|---|
| campaign (2 runs/arm-run, mostly un-warmed) | median 45.6 [4.0–67.0] | median 64.2 [24.2–76.5] |
| supplement (5 runs/arm-run) | median 61.9 [4.7–102.8] | median 53.1 [9.0–91.9] |
| **clean A/B, 3 warm-up + 5 measured × 3 reps** | **median 89.1** [27.2–92.9] | **median 89.5** [28.0–93.6] |
| clean A/B, fast-mode subset only (>70 MB/s) | 88.7–92.9 | 80.4–93.6 |

The bimodality (slow mode 17–56 MB/s vs fast mode 80–95 MB/s) appears in **both** arms with equal frequency in the cleaned A/B (parent 4/15 slow runs, HEAD 4/15), i.e. it is a pre-existing client/loopback scheduling property unrelated to the commit. Steady-state throughput is unchanged.

### 2.5 Verdict A and code plausibility

- **UDP**: no service-quality regression for paced traffic; a **small, statistically detectable loss of burst headroom** in the unpaced blast path (clean pps −5…−8 %, 1–2-packet loss episodes twice as frequent, first clear knee loss at 44 k pps for HEAD only). User-visible impact is limited to clients pushing unpaced UDP bursts right at the ceiling; paced real-time traffic (RTP-like, ≤40 k pps single association) and multi-association paced traffic are unaffected.
- **TCP**: no regression (latency and steady-state echo throughput unchanged).
- Code-level reading of the diff is consistent with a *small per-datagram overhead on the shared SOCKS UDP reply path*: `StagedReply` gained `raw: bool` + `reply_v6: bool`; `dispatch_one`/`flush_staged` now branch on them per reply; the uplink send block was moved into a non-generic `send_payload_uplink(..., SessionKind::Socks)` function (new call boundary with an extra enum arg, only the debug label uses it). No lock, queue or allocation change. A few-ns-to-~1 µs/reply cost is plausible; this benchmark does not prove causality, only the size of the observable effect.

## 3. Scenario B — HEAD client with idle forward listeners vs without

Both arms are the **HEAD client binary**; `headB` additionally has one bound `tcp_forward` and one bound `udp_forward` listener (loopback, valid targets, **no datagrams/connections sent through them**). 3 interleaved reps each.

| metric | headA (no forward cfg) | headB (idle forward listeners) |
|---|---|---|
| UDP blast clean runs / total | 8/15 | 10/15 |
| UDP blast clean pps median [min–max] | 29,512 [26,599–34,200] | 30,700 [25,221–34,962] |
| UDP `lat` p50 / p99 (µs) | 117 / 397 | 117 / 360 |
| `lattcp` connect / echo p50 (µs) | 106 / 137 | 101 / 135 |
| `udppaced` 30 k loss % (6 runs) | 0, 0.029, 0, 0, 0, 0.184 | 0, 0.030, 0, 0.067, 0, 0 |
| `udpbidir` 20 k loss % | 0.000 (×3) | 0.000 (×3) |
| `udpmultipaced` 4×4 k loss % / recv_pps | 0.000 (×3) / 14,538–14,541 | 0.000 (×3) / 14,539–14,540 |
| `tcpecho` 8 MiB MB/s | median 64.2 [24.2–76.5] | median 27.0 [8.9–82.0] (same bimodality) |

**Verdict B: no measurable interference from merely configuring idle forward listeners**, at the resolution of 3 reps per arm. Differences are within the run-to-run spread and have no consistent sign; the one large `tcpecho` gap is the warm-up bimodality documented in §2.4 (both arms draw slow and fast instances). This is a "no signal observed" result, not an equivalence proof; a ~5 % effect could hide under the loopback noise.

## 4. Scenario C — absolute performance of the new forwarding paths (HEAD client + listeners)

Client `headB`, same server, forward targets = the same local echo targets used by the SOCKS baseline (19000 TCP, 19001 UDP). Driver: `bench_forward.py` (python3, UDP batching identical in spirit to `hotpath_bench udp`; the SOCKS baseline column is the headB arm of §3/§2 measured minutes apart, same binaries/process config).

### 4.1 UDP forward (`127.0.0.1:18282 -> 127.0.0.1:19001`)

| metric | forward path | SOCKS baseline (headB) |
|---|---|---|
| throughput, 1000 B payload, n=10,000, batch 64, 5 runs | **32,088 / 32,267 / 31,950 / 33,562 / 33,791 pps → median 32,267, 5/5 clean, 0.000 % loss** | clean median 30,700 pps, 10/25 runs lossy at 10 k |
| serial RTT, 500 × 64 B, 5 runs | p50 113 / 112 / 114 / 113 / 112 µs → **median 113**; p99 316–423 → median **378** | p50 median 117; p99 median 360 |
| 50 concurrent peer sessions × 2000 datagrams (128 B, batch 32) | run1: 100,000/100,000 in 1.965 s = **50,886 pps, 0.000 % loss**; run2: 100,000/100,000 in 1.968 s = **50,805 pps, 0.000 % loss** | not measured (SOCKS uses one association/thread shape) |

Reading: the UDP forward path is at least as fast as the SOCKS path (no SOCKS5 UDP header per datagram, no association handshake), per-peer session demux scales cleanly to 50 peers, and there is no loss beyond the tunnel's own.

### 4.2 TCP forward (`127.0.0.1:18181 -> 127.0.0.1:19000`)

| metric | forward path | SOCKS baseline |
|---|---|---|
| bulk echo, 8 MiB, SHA-256 verified, 10 runs | 18.6, 28.3, 52.6, 90.1, 83.2, 38.0, 89.3, 91.5, 90.8, 90.4 MB/s → **median 86.3**; first 3 connections cold, steady state 83–91 MB/s | `tcpecho` 8 MiB, 10 runs: 73.4–95.2 MB/s, median ≈ 92.5 |
| stream RTT (one open stream, 500 × 64 B, 5 runs) | p50 95/95/96/96/96 µs → **median 96**, p99 285–333 → median **313** | `lattcp` echo p50 131–137 µs (includes a fresh SOCKS CONNECT per iteration; not strictly comparable) |

### 4.3 S0 — TCP integrity through the forward listener (requested by lead)

The first python verifier build reported `mismatched=1..4` on 2 of 4 chunked `tcp-bulk` runs. **This was a bug in the verifier, not in the relay**: it built expected bytes as `reps[start:start+k]` with a `reps` buffer only 2×65536 B long; whenever a `recv_into` returned 65–131 KiB at a non-zero stream offset the slice was truncated and `len(exp) != k` counted a false mismatch. Corrected verifiers, run against the same binaries/config:

| verification | runs | result |
|---|---|---|
| SHA-256 of whole 8 MiB stream, direct to `techo` target (no proxy) — control | 5 | 5/5 hash match, 1155–1697 MB/s |
| SHA-256 of whole 8 MiB stream through `tcp_forward` listener | 10 | **10/10 hash match**, 18.6–91.5 MB/s |
| SHA-256 of whole 8 MiB stream through SOCKS `tcpecho` (Rust harness, byte compare) | 10 | **10/10 OK**, 73.4–95.2 MB/s |
| corrected chunk-by-chunk compare, direct target / forward listener | 10 / 20 | **0 bad chunks / 0 bad chunks** |

Conclusion: **no data corruption or reordering through the TCP forward listener; the earlier FAILs are an artifact of the benchmark harness and must not be read as a relay bug.** Scripts archived in `bench-raw/scripts/` (`tcpverify.py`, `tcpdebug.py`, `bench_forward.py` pre-fix logic documented in `bench-raw/BUG-tcp-verifier.md`).

## 5. Noise assessment / limitations

- macOS loopback + 10-core box with **load average 4–6 from unrelated processes** throughout; every number above is a median over interleaved repetitions, and the raw per-run values (including load lines) are archived so spread can be re-derived. Absolute values are not comparable to idle-machine or Linux numbers.
- Loopback RTT ≈ 0, so transport congestion-control/latency effects are invisible; this audit measures framing/CPU/scheduling effects (which is what the commit touches), not WAN behaviour.
- UDP blast pps uses clean-run medians (selection bias caveat above); lossy-run frequency is the unbiased discrete metric for the same runs.
- The 5 s stall artifact makes per-run `udp` wall/pps useless on lossy runs; no numbers were fabricated by re-running-until-clean — all 15 + 40 runs per arm are counted, only classified.
- Scenario B and the knee sweep have small n (3 reps / 2 runs per point); they can detect large interference, not a <5 % effect.
- Scenario C uses a single-threaded python driver; its own ceiling is above 50 k pps (multi-peer aggregate), but python-side scheduling noise is larger than the Rust harness, so C numbers are approximate.
- The in-suite UDP p99-after-blast difference (§2.3) is left explicitly unresolved.

## 6. Reproduction

```sh
# build
git worktree add /tmp/mq2-parent 1135076
CARGO_TARGET_DIR=/tmp/mq2-target-head   cargo build --release --bin myquic2-server --bin myquic2-client --example hotpath_bench   # main tree
CARGO_TARGET_DIR=/tmp/mq2-target-parent (cd /tmp/mq2-parent && cargo build --release --bin myquic2-client)

# targets
/tmp/mq2-target-head/release/examples/hotpath_bench techo 19000 &
/tmp/mq2-target-head/release/examples/hotpath_bench echo  19001 &
# server + one client arm (configs in bench-raw/configs/), then:
/tmp/mq2-target-head/release/examples/hotpath_bench udp     127.0.0.1:18080 127.0.0.1:19001 10000 64
/tmp/mq2-target-head/release/examples/hotpath_bench lat     127.0.0.1:18080 127.0.0.1:19001 500 64
/tmp/mq2-target-head/release/examples/hotpath_bench lattcp  127.0.0.1:18080 127.0.0.1:19000 200 64
/tmp/mq2-target-head/release/examples/hotpath_bench tcpecho 127.0.0.1:18080 127.0.0.1:19000 8388608
/tmp/mq2-target-head/release/examples/hotpath_bench udppaced 127.0.0.1:18080 127.0.0.1:19001 6 128 30000
/tmp/mq2-target-head/release/examples/hotpath_bench udpbidir 127.0.0.1:18080 127.0.0.1:19001 6 128 20000
/tmp/mq2-target-head/release/examples/hotpath_bench udpmultipaced 127.0.0.1:18080 127.0.0.1:19001 4 6 128 4000
# scenario C
python3 bench-raw/scripts/bench_forward.py udp-pps 127.0.0.1:18282 10000 64 1000
python3 bench-raw/scripts/bench_forward.py udp-multi 127.0.0.1:18282 50 2000 32 128
python3 bench-raw/scripts/tcpverify.py 127.0.0.1:18181 8388608 fwd
```

Orchestration scripts (raw, unpolished) are archived under `bench-raw/scripts/`; every run's stdout/stderr-equivalent is under `bench-raw/`.

## 7. Raw artifacts (`analysis/forwarding-audit/bench-raw/`)

- `campaign.out`, `raw-{parent,headA,headB}-r{1..3}.log` — scenario A/B suite, 3 interleaved reps, exact commands + load lines + every measurement line.
- `supplement.out`, `raw2-{parent,headA}-r{1..4}.log` — second A campaign, 4 reps × 10 UDP blasts + 3 lat + 3 lattcp + 5 tcpecho per arm-run.
- `latfocus.out` — isolated serial UDP latency A/B on fresh clients (3 reps × 5 runs).
- `knee.out` — paced loss knee sweep 32/36/40/44 k pps, 2 reps each.
- `tcpecho-ab.out` — TCP echo throughput A/B, 3 warm-up + 5 measured × 3 reps.
- `forward.out` — scenario C forward-path UDP/TCP measurements.
- `tcp-integrity.out`, `dbg` log — S0 SHA-256 and chunk-compare verification runs.
- `final-numbers.txt` — machine-generated medians/min/IQR/max per metric per arm.
- `binary-sha256.txt`, `build-head.log`, `build-parent.log`, `configs/`, `scripts/`, `BUG-tcp-verifier.md`.
