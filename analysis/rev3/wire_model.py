#!/usr/bin/env python3
"""Byte/interaction model for the MQP-3 rev2 wire vs a clean-slate rev3 sketch.

All current-wire numbers are derived from src/mqp/r2.rs and src/mqp/addr.rs:

  DATA steady     1 + varint(wire_id) + payload
  DATA OPEN       2 + varint(wire_id) + 4(sess) + addr + payload
  DATA INLINE     2 + 4(sess) + addr + payload
  TRAIN same      3 + varint(id) + sum(varint(len) + payload)
  TRAIN dict      4 + sum(varint(flow_id)) + sum(1(idx) + varint(len) + payload)
  FRAG steady     1 + varint(id) + 4(frag_id) + 1(idx) + 1(total) + chunk
  CTL HELLO 8, CAPS 17, FLOW_ACK/REJECT 3 + varint(id), FLOW_CLOSE 2 + varint(id)
  addr            IPv4 7, IPv6 19, domain 4 + L

QUIC/IPv4 fixed cost per packet (single DATAGRAM frame, no coalescing):
  20 IP + 8 UDP + 27 QUIC short header/tag + DATAGRAM frame type 1 + len varint (1-2)
  = 55 + 2..3 bytes.

rev3 sketch modelled here (see analysis/rev3/report.md):
  1-byte header: kind in the top 3 bits, flags in the low 5 bits.
  DATA hot:    hdr + 1B slot                                  -> 2 B
  DATA ext:    hdr + 0xFE + u16 id                            -> 4 B
  OPEN:        hdr + 1B slot + 2B session(u16) + addr + payload
  TRAIN:       hdr + 1B count + count * (1B slot + 1B len(<=255) + payload)
  FRAG:        hdr + 1B slot + 4B frag_id + 1B idx/total + chunk
  No HELLO/CAPS, no per-flow FLOW_ACK; a sender repeats inline OPEN context for
  OPEN_REPEAT frames of a flow (0 for one-packet flows), and a receiver acks
  nothing.
"""

IPV4_PACKET = 55  # IP 20 + UDP 8 + QUIC short header 1+8+2+16 = 55
DATAGRAM_FRAME = 2  # type byte + 1-byte length (payload < 64 uses 1 B; else 2)


def varint(n):
    if n < 128:
        return 1
    if n < 16384:
        return 2
    if n < 1 << 21:
        return 3
    if n < 1 << 28:
        return 4
    return 5


def addr_len(kind, domain_len=0):
    return {"v4": 7, "v6": 19, "domain": 4 + domain_len}[kind]


# ---- current wire -----------------------------------------------------------


def cur_data_steady(wire_id, payload, kind="v4"):
    return 1 + varint(wire_id) + payload


def cur_data_open(wire_id, sess, payload, kind="v4", domain_len=0):
    return 2 + varint(wire_id) + 4 + addr_len(kind, domain_len) + payload


def cur_data_inline(sess, payload, kind="v4", domain_len=0):
    return 2 + 4 + addr_len(kind, domain_len) + payload


def cur_ack(wire_id):
    return 3 + varint(wire_id)


def cur_train_same(wire_id, sizes):
    return 3 + varint(wire_id) + sum(varint(n) + n for n in sizes)


def cur_train_dict(flows, items):
    """items: list of (flow_index, payload_size)."""
    return 4 + sum(varint(f) for f in flows) + sum(1 + varint(n) + n for _, n in items)


# ---- rev3 sketch ------------------------------------------------------------


def r3_data_hot(payload):
    return 2 + payload


def r3_data_ext(payload):
    return 4 + payload


def r3_open(payload, kind="v4", domain_len=0, slot=1):
    return 1 + slot + 2 + addr_len(kind, domain_len) + payload


def r3_train(items):
    """items: list of (slot <= 254, payload_size)."""
    return 2 + sum(1 + varint(n) + n for _, n in items)


def wire(frames_bytes, packets):
    """Wire bytes for `frames_bytes` MQP bytes spread over `packets` QUIC packets."""
    return frames_bytes + packets * (IPV4_PACKET + DATAGRAM_FRAME)


# ---- scenarios --------------------------------------------------------------

FLOWS_TYPICAL = 200  # a connection's cumulative flow opens: wire_id ~400 -> 2B varint
WID = 2 * FLOWS_TYPICAL


def scenario(name, rows):
    print(f"\n== {name} ==")
    print(f"{'metric':44s} {'current':>10s} {'rev3':>10s} {'delta':>10s}")
    for label, cur, new in rows:
        d = (new - cur) / cur * 100 if cur else 0
        print(f"{label:44s} {cur:10.1f} {new:10.1f} {d:+9.1f}%")


def main():
    print("wire_id varint length vs cumulative client flow opens")
    print(f"{'cumulative opens':>18s} {'wire_id':>9s} {'DATA hdr':>9s} {'OPEN hdr v4':>12s}")
    for k in [1, 63, 64, 1000, 4096, 8192, 1_000_000]:
        # local id == k for the k-th alloc, wire_id = (k<<1)|owner
        wid = k << 1
        print(f"{k:18d} {wid:9d} {1 + varint(wid):9d} {2 + varint(wid) + 4 + 7:12d}")

    # A. DNS-over-SOCKS, domain target, one query (50 B) + one reply (100 B).
    #    Current: OPEN + server FLOW_ACK + downlink OPEN|SRC + client FLOW_ACK.
    cur = cur_data_open(WID, 7, 50, "domain", 11) + cur_ack(WID)
    cur += cur_data_open(WID, 7, 100, "v4") + cur_ack(WID)
    cur_pkts = 4
    new = r3_open(50, "domain", 11) + r3_open(100, "v4")
    new_pkts = 2
    scenario(
        "A. DNS-over-SOCKS: domain target, 50 B query + 100 B reply",
        [
            ("MQP bytes (both directions)", cur, new),
            ("QUIC packets", cur_pkts, new_pkts),
            ("total IPv4 wire bytes", wire(cur, cur_pkts), wire(new, new_pkts)),
        ],
    )

    # B. IP target, one query (50 B) + one reply (100 B).
    cur = cur_data_open(WID, 7, 50) + cur_ack(WID) + cur_data_steady(WID, 100)
    cur_pkts = 3
    new = r3_open(50) + r3_data_hot(100)
    new_pkts = 2
    scenario(
        "B. IP target: one 50 B datagram + one 100 B reply",
        [
            ("MQP bytes (both directions)", cur, new),
            ("QUIC packets", cur_pkts, new_pkts),
            ("total IPv4 wire bytes", wire(cur, cur_pkts), wire(new, new_pkts)),
        ],
    )

    # C. steady 128 B datagrams, both directions, 1000 payloads each way.
    cur_pp = cur_data_steady(WID, 128)
    new_pp = r3_data_hot(128)
    scenario(
        "C. steady 128 B flow, 1000 payloads/direction",
        [
            ("MQP bytes per payload", cur_pp, new_pp),
            ("wire bytes per payload (1 pkt each)", wire(cur_pp, 1) / 1, wire(new_pp, 1) / 1),
        ],
    )

    # D. cross-session small-packet fan-out: 8 flows, 64 x 60 B items, dict TRAIN.
    items64 = [(i % 8, 60) for i in range(64)]
    flows8 = [WID + 2 * i for i in range(8)]
    cur = cur_train_dict(flows8, items64)
    new = r3_train(items64)
    # pack per 1472 B DATAGRAM budget at the MQP level (approx: no QUIC frame hdr)
    cur_frames = -(-cur // 1472)
    new_frames = -(-new // 1472)
    scenario(
        "D. 64 x 60 B fan-out over 8 flows (TRAIN)",
        [
            ("MQP bytes", cur, new),
            ("MQP frames (1472 B budget)", cur_frames, new_frames),
            ("wire bytes (1 pkt/frame)", wire(cur, cur_frames), wire(new, new_frames)),
        ],
    )

    # E. 1000 one-shot domain flows (DNS churn), 50 B query only (uplink-only).
    #    Current: OPEN + FLOW_ACK; client never reuses. rev3: OPEN only, no ack.
    cur = 1000 * (cur_data_open(WID, 7, 50, "domain", 11) + cur_ack(WID))
    cur_pkts = 1000 * 2
    new = 1000 * r3_open(50, "domain", 11)
    new_pkts = 1000
    scenario(
        "E. 1000 one-shot domain flows (50 B query, uplink only)",
        [
            ("MQP bytes", cur, new),
            ("QUIC packets", cur_pkts, new_pkts),
            ("wire KB", wire(cur, cur_pkts) / 1024, wire(new, new_pkts) / 1024),
        ],
    )

    # F. 1000 one-shot IP flows, 50 B + 100 B reply.
    cur = 1000 * (cur_data_open(WID, 7, 50) + cur_ack(WID) + cur_data_steady(WID, 100))
    cur_pkts = 1000 * 3
    new = 1000 * (r3_open(50) + r3_data_hot(100))
    new_pkts = 1000 * 2
    scenario(
        "F. 1000 one-shot IP flows (50 B query + 100 B reply)",
        [
            ("MQP bytes", cur, new),
            ("QUIC packets", cur_pkts, new_pkts),
            ("wire KB", wire(cur, cur_pkts) / 1024, wire(new, new_pkts) / 1024),
        ],
    )

    # G. per-connection setup interactions today vs rev3.
    #    current: HELLO(8) + CAPS(17) + auth token stream (>=1 stream frame, not
    #    modelled) ; rev3: ALPN version + TLS-bound auth, no app frames.
    cur = 8 + 17
    cur_pkts = 2
    new = 0
    new_pkts = 0
    scenario(
        "G. per-connection setup control (HELLO + CAPS)",
        [
            ("MQP bytes", cur, new),
            ("QUIC packets", cur_pkts, new_pkts),
            ("wire bytes", wire(cur, cur_pkts), wire(new, new_pkts)),
        ],
    )


if __name__ == "__main__":
    main()
