#!/usr/bin/env python3
"""MQP-3 wire-cost model: current v3 vs refactored (connection-scoped flow id).

All numbers are MODEL ESTIMATES, not measurements. Assumptions are stated in
PROTOCOL_ANALYSIS.md-style detail below and must be re-validated on the target
Linux host with examples/hotpath_bench.rs + tcpdump counters.

Fixed cost model (IPv4, no loss, no ACK-only packets):
  * QUIC packet: IP 20 + UDP 8 + QUIC short header 27 = 55 B
  * DATAGRAM frame: 1 B type + LEB128(len)  -> 2 B for body <= 63, else 3 B
  * body budget: 1162 B at MTU 1200, 1362 B at MTU 1400
  * MQP frame = MQP header + payload; one or more MQP frames per QUIC packet

Frame shapes modelled:
  CURRENT MQP-3 (src/mqp/v3.rs):
    SINGLE: 1 + 4 sess + [1 flow if flow!=0] + [addr if inline] + payload
    TRAIN : 6 hdr (kind/flags, sess u32, count) + [1 flow if same-flow form]
            item: 1 flags + [1 flow if mixed && flow!=0] + LEB128(len)
                  + [addr if inline] + payload
            same-flow form only for non-zero, all-inline-free items
    FRAG  : v3 codec exists but is not wired; production uses MQP-2 0x05:
            11 fixed (type|sess|id|idx|total) + addr + chunk, address repeated
  REFACTOR candidate A (chosen for the design doc):
    byte0 = kind(2b) | flags(6b); flow id = LEB128 (1 B for id < 128)
    SINGLE steady: 2 B (kind/flags + id); open forms carry session u32 + addr
    TRAIN simple: 2 B header + payload-count* (LEB128(len) + payload)
                  for same-flow, no-inline items
    TRAIN mixed : 2 B header + item (LEB128(len) + 1 flow + payload)
    FRAG        : 1 kind + 1 flow + 2 frag-id + 1 packed idx/total + chunk
  REFACTOR candidate B (aggressive): byte0 = kind(3b)|flow(5b) -> 1 B steady,
    escape form for flow >= 32; otherwise same as A.
"""

from dataclasses import dataclass

PKT = 55
BUDGET1200 = 1162
BUDGET1400 = 1362

IPV4 = 7
IPV6 = 19


def dom(L: int) -> int:
    return 4 + L  # atyp + len + name + port


def vlen(n: int) -> int:
    """LEB128 byte count."""
    ln = 1
    while n >= 0x80:
        n >>= 7
        ln += 1
    return ln


def dgh(body: int) -> int:
    """QUIC DATAGRAM frame header (type + varint length)."""
    return 1 + vlen(body)


# ---------------- current MQP-3 ----------------

def cur_single(flow: int, addr_len: int, p: int) -> int:
    return 1 + 4 + (1 if flow != 0 else 0) + addr_len + p


def cur_train(items, same_flow: bool = True) -> int:
    """items: list of (flow, addr_len, payload_len)."""
    flows = {i[0] for i in items}
    inline_any = any(i[1] for i in items)
    sf = (
        same_flow
        and len(flows) == 1
        and items[0][0] != 0
        and not inline_any
    )
    total = 6 + (1 if sf else 0)
    for flow, addr_len, p in items:
        total += 1 + (1 if (flow != 0 and not sf) else 0) + vlen(p) + addr_len + p
    return total


def cur_frag(flow: int, addr_len: int, chunks) -> int:
    return sum(11 + (1 if flow != 0 else 0) + addr_len + c for c in chunks)


# ---------------- refactor candidate A ----------------

def new_single(flow: int, p: int, id_bytes: int = 1) -> int:
    return 1 + id_bytes + p


def new_open_single(sess_id_bytes: int, addr_len: int, p: int) -> int:
    # kind/flags + flow id + session id + addr + payload
    return 1 + 1 + sess_id_bytes + addr_len + p


def new_train_simple(n_items: int, p: int) -> int:
    return 2 + n_items * (vlen(p) + p)


def new_train_mixed(items) -> int:
    """items: list of (flow, p) with flow id 1 B (id<128)."""
    return 2 + sum(1 + vlen(p) + p for _, p in items)


def new_frag(chunks) -> int:
    return sum(1 + 1 + 2 + 1 + c for c in chunks)


# ---------------- refactor candidate B ----------------

def new_b_single(flow: int, p: int) -> int:
    if flow < 32:
        return 1 + p  # kind(3b)|flow(5b)
    return 1 + 1 + 1 + p  # escape kind + len? simplified: kind+flags byte, id varint


# ---------------- packing helpers ----------------

def pack(frames, budget):
    """Greedy bin-pack frame body sizes into QUIC packets; returns (pkts, bytes)."""
    pkts = 0
    used = 0
    total = 0
    for f in frames:
        if f > budget:
            raise ValueError(f"frame {f} exceeds budget {budget}")
        if used and used + f > budget:
            pkts += 1
            used = 0
        used += f
        total += f + dgh(f)  # DATAGRAM frame header + MQP body
        if used == budget:
            pkts += 1
            used = 0
    if used:
        pkts += 1
    return pkts, total + pkts * PKT


def own_packet(frames):
    """Every frame gets its own QUIC packet (low-rate, no temporal coalescing)."""
    bytes_ = sum(f + dgh(f) + PKT for f in frames)
    return len(frames), bytes_


def report(name, frames, payload_total, budget=BUDGET1200, silent=False, packable=True):
    n = len(frames)
    assert n > 0
    op, ob = own_packet(frames)
    if packable:
        pp, pb = pack(frames, budget)
    else:
        pp, pb = n, ob
    if not silent:
        print(
            f"{name:<58} frames={n:<5} payload={payload_total:<7} "
            f"own={ob:<7}({ob / payload_total * 100:5.1f}%) "
            f"packed={pb:<7}({pb / payload_total * 100:5.1f}%) "
            f"pkts={pp}"
        )
    return dict(frames=n, own=ob, packed=pb, pkts=pp)


def overhead_per_item(name, hdr, items, payload_total):
    print(
        f"  {name:<46} hdr={hdr:>5} B  overhead/item={hdr / items:5.2f} B "
        f"({hdr / payload_total * 100:4.1f}% hdr/payload)"
    )


print("=" * 118)
print("A. STEADY-STATE HEADER PER PAYLOAD (one payload per frame, flow 0 / extra flow)")
print("=" * 118)
cases = [
    ("IPv4 flow0", 0, 0, IPV4),
    ("IPv4 extra flow", 3, 0, IPV4),
    ("IPv6 flow0", 0, 0, IPV6),
    ("domain L=20 flow0", 0, 1, dom(20)),
]
for label, flow, inline, alen in cases:
    for p in (28, 60, 200, 512, 1000):
        if inline:  # domain / NO_FLOW: current must stay inline every frame
            cs = cur_single(0xFF, alen, p)
            note = "current-inline vs new-compressed"
        else:
            cs = cur_single(flow, 0, p)
            note = "steady compressed"
        ns = new_single(max(flow, 1), p)
        print(
            f"  {label:<20} p={p:<5} cur={cs:<5} new={ns:<5} save={cs - ns:<3} "
            f"({(cs - ns) / (cs + dgh(cs) + PKT) * 100:4.1f}% own-packet)  [{note}]"
        )
    print()

print("=" * 118)
print("B. TRAIN ITEM OVERHEAD (same burst, flow-0 small IP payloads)")
print("=" * 118)
for p in (28, 60, 200):
    for k in (2, 8, 18, 40):
        cur = cur_train([(0, 0, p)] * k)
        new_simple = new_train_simple(k, p)
        print(
            f"  p={p:<4} k={k:<3} cur={cur:<6}({cur / (k * p) * 100:5.2f}%)  "
            f"new={new_simple:<6}({new_simple / (k * p) * 100:5.2f}%)  "
            f"save={cur - new_simple:<4} B"
        )
    print()

print("=" * 118)
print("C. WORKLOAD SCENARIOS (wire bytes per payload; own packet = low rate, packed = high rate)")
print("=" * 118)

# C1: STUN/game 28 B, one flow, steady
k, p = 1000, 28
cur = [cur_single(0, 0, p)] * k
new = [new_single(0, p)] * k
report("C1 28B flow0 steady (1000 datagrams)", cur, k * p)
report("C1 new", new, k * p)
print()

# C2: DNS IP 60 B, one flow
k, p = 1000, 60
report("C2 60B flow0 steady current", [cur_single(0, 0, p)] * k, k * p)
report("C2 60B flow0 steady new    ", [new_single(0, p)] * k, k * p)
print()

# C3: DNS domain 40 B query, L=20, current inline every frame vs new compressed
k, p, L = 1000, 40, 20
alen = dom(L)
report("C3 domain-40B current inline (NO_FLOW)", [cur_single(0xFF, alen, p)] * k, k * p)
report("C3 domain-40B new steady compressed   ", [new_single(1, p)] * k, k * p)
print()

# C3b: domain response 300 B
k, p = 1000, 300
report("C3b domain-300B current inline", [cur_single(0xFF, alen, p)] * k, k * p)
report("C3b domain-300B new compressed", [new_single(1, p)] * k, k * p)
print()

# C4: pure-uplink 60 B IP flow (never confirmed today -> inline forever)
k, p = 1000, 60
report("C4 pure-uplink 60B current inline-forever", [cur_single(0, IPV4, p)] * k, k * p)
report("C4 pure-uplink 60B new compressed (ACK)  ", [new_single(1, p)] * k, k * p)
print()

# C5: fragmented 1200 B payload (MTU 1200 -> 2 fragments)
chunks_cur = [1144, 1200 - 1144]
chunks_new = [1157, 1200 - 1157]
report("C5 1200B current v2 FRAG x2", [cur_frag(0, IPV4, [c]) for c in chunks_cur], 1200, packable=False)
report("C5 1200B new compact FRAG x2", [new_frag([c]) for c in chunks_new], 1200, packable=False)
print()

# C6: 32 small flows in one burst, same session (TRAIN)
k, p = 32, 60
items = [(0, 0, p)] + [(i, 0, p) for i in range(1, 32)]
cur_tr = cur_train(items)
# split current into two trains of <= 1162 body
cur_frames = []
rest = items[:]
while rest:
    n = len(rest)
    while n > 1 and cur_train(rest[:n]) > BUDGET1200:
        n -= 1
    cur_frames.append(cur_train(rest[:n]))
    rest = rest[n:]
new_items = items
new_frames = []
rest = new_items[:]
while rest:
    n = len(rest)
    while n > 1 and new_train_mixed([(f, p) for f, _, p in rest[:n]]) > BUDGET1200:
        n -= 1
    new_frames.append(new_train_mixed([(f, p) for f, _, p in rest[:n]]))
    rest = rest[n:]
report("C6 32-flow fanout 60B current", cur_frames, k * p)
report("C6 32-flow fanout 60B new    ", new_frames, k * p)
print()

# C7: many sessions, 1 small reply per session, 32 sessions, low rate
k = 32
p = 60
# current: per-session SINGLE, each its own packet (no cross-session train)
cur = [cur_single(0, 0, p)] * k
# new: cross-session TRAIN, 2 packets; item = len1+flow1+payload
per_frame = 1 + 1 + p  # mixed-flow item
n_per_pkt = (BUDGET1200 - 2) // per_frame
print(f"  cross-session train items/packet = {n_per_pkt}")
new_frames = []
rest_n = k
while rest_n:
    n = min(rest_n, n_per_pkt)
    new_frames.append(2 + n * per_frame)
    rest_n -= n
report("C7 32 sessions x 60B current (own pkt each)", cur, k * p)
report("C7 32 sessions x 60B new (x-session train)  ", new_frames, k * p)
print()

# C8: high-pps packed 28B/60B, flow0, current TRAIN vs new simple TRAIN
for p in (28, 60):
    cur_k = (BUDGET1200 - 6) // (2 + p)
    new_k = (BUDGET1200 - 2) // (1 + p)
    cf = [cur_train([(0, 0, p)] * cur_k)]
    nf = [new_train_simple(new_k, p)]
    print(f"  p={p}: current {cur_k} items/train, new {new_k} items/train")
    report(f"C8 {p}B high-pps current", cf, cur_k * p)
    report(f"C8 {p}B high-pps new    ", nf, new_k * p)
    # normalise to per-payload wire
    print(
        f"      per-payload wire: current={pack(cf, BUDGET1200)[1] / cur_k:.2f} B, "
        f"new={pack(nf, BUDGET1200)[1] / new_k:.2f} B\n"
    )

# C9: candidate B steady header on tiny payloads
print("=" * 118)
print("D. CANDIDATE B (1-byte steady header) marginal gain over candidate A")
print("=" * 118)
for p in (28, 60, 200):
    a = new_single(1, p)
    b = new_b_single(1, p)
    print(
        f"  p={p:<4} A={a:<4} B={b:<4} save={a - b} "
        f"({(a - b) / (a + dgh(a) + PKT) * 100:4.1f}% of own-packet wire)"
    )
