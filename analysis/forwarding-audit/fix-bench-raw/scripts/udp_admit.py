#!/usr/bin/env python3
"""External UDP admission / eviction checks for myquic2 udp_forward listeners.

Modes:
  peers <listen> <n> [aging_s]
      n distinct ephemeral source sockets each send one datagram; report how
      many peers got a reply (admitted) vs refused. With aging_s > 0, wait that
      long (all peers idle) then a fresh peer retries every 100 ms up to 45 s
      and the admit latency is reported.
  evict <listen> <wait_before_b_s> [max_wait_s]
      peer A sends one datagram and gets its reply, then stays idle; peer B
      sends every 100 ms until it gets a reply. Reports A idle time at B's
      admission and the measured admit latency.
Usage examples:
  udp_admit.py peers 127.0.0.1:18282 5 5.2
  udp_admit.py evict 127.0.0.1:18282 0.5 60
"""
import socket
import sys
import time

PAYLOAD = b"ADMIT-UDP-0123456789"  # 20 B


def make_peer(addr, idx):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.6)
    s.connect(addr)
    return s


def try_peer(addr, idx, timeout=0.6):
    s = make_peer(addr, idx)
    pkt = PAYLOAD + idx.to_bytes(2, "big")
    t0 = time.perf_counter()
    try:
        s.send(pkt)
        data = s.recv(2048)
        rtt = (time.perf_counter() - t0) * 1e3
        if data == pkt:
            return s, "admitted", rtt
        return s, f"bad-reply({data.hex()})", rtt
    except socket.timeout:
        return s, "refused-timeout", None
    except OSError as e:
        return s, f"refused-err({e!r})", None


def mode_peers(addr, n, aging_s):
    peers = []
    admitted = 0
    for i in range(n):
        s, verdict, rtt = try_peer(addr, i)
        print(f"peer[{i}] verdict={verdict}" + (f" rtt_ms={rtt:.2f}" if rtt is not None else ""))
        peers.append(s)
        if verdict == "admitted":
            admitted += 1
    print(f"SUMMARY n={n} admitted={admitted} refused={n - admitted}")
    if aging_s > 0:
        print(f"aging: keeping {n} source sockets open and idle for {aging_s}s")
        time.sleep(aging_s)
        idx = n
        t0 = time.perf_counter()
        deadline = t0 + 45.0
        got = False
        while time.perf_counter() < deadline:
            s, verdict, rtt = try_peer(addr, idx)
            if verdict == "admitted":
                dt = time.perf_counter() - t0
                print(f"aged_new_peer=admitted after {dt:.2f}s (rtt_ms={rtt:.2f})")
                got = True
                break
            time.sleep(0.1)
        if not got:
            print("aged_new_peer=refused (45s cap)")
        print(f"AGING_RESULT {'PASS' if got else 'FAIL'}")
    for s in peers:
        s.close()


def mode_evict_noreply(addr, wait_before_b, max_wait):
    """Control: peer A sends but the target never replies (black-hole target),
    so no `replied` activity flag exists; A must become evictable at the 5 s
    idle floor."""
    a = make_peer(addr, 0)
    pkt = PAYLOAD + (0).to_bytes(2, "big")
    a.send(pkt)
    print("peerA=sent (black-hole target, no reply expected)")
    t_send = time.perf_counter()
    time.sleep(wait_before_b)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b.settimeout(0.6)
    b.connect(addr)
    b_pkt = PAYLOAD + (1).to_bytes(2, "big")
    t_b_start = time.perf_counter()
    deadline = t_b_start + max_wait
    admitted_at = None
    attempts = 0
    while time.perf_counter() < deadline:
        attempts += 1
        b.send(b_pkt)
        try:
            data = b.recv(2048)
            if data == b_pkt:
                admitted_at = time.perf_counter()
                break
        except socket.timeout:
            pass
        time.sleep(0.1)
    if admitted_at is None:
        print(f"peerB=refused after {max_wait:.0f}s cap, attempts={attempts}")
        print("EVICT_NOREPLY_RESULT FAIL")
        return
    admit_latency = admitted_at - t_b_start
    a_idle_at_admit = admitted_at - t_send
    print(f"peerB=admitted attempts={attempts} b_admit_latency={admit_latency:.2f}s "
          f"a_idle_at_admit={a_idle_at_admit:.2f}s")
    print(f"EVICT_NOREPLY_RESULT {'PASS' if admit_latency < 10.0 else 'FAIL'}")
    a.close()
    b.close()


def mode_evict(addr, wait_before_b, max_wait):
    a = make_peer(addr, 0)
    pkt = PAYLOAD + (0).to_bytes(2, "big")
    a.send(pkt)
    try:
        data = a.recv(2048)
        assert data == pkt, data.hex()
        print("peerA=admitted(reply received)")
    except (socket.timeout, AssertionError) as e:
        print(f"peerA=FAILED {e!r}")
        return
    t_reply = time.perf_counter()
    time.sleep(wait_before_b)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b.settimeout(0.6)
    b.connect(addr)
    b_pkt = PAYLOAD + (1).to_bytes(2, "big")
    t_b_start = time.perf_counter()
    deadline = t_b_start + max_wait
    admitted_at = None
    attempts = 0
    while time.perf_counter() < deadline:
        attempts += 1
        b.send(b_pkt)
        try:
            data = b.recv(2048)
            if data == b_pkt:
                admitted_at = time.perf_counter()
                break
        except socket.timeout:
            pass
        time.sleep(0.1)
    if admitted_at is None:
        print(f"peerB=refused after {max_wait:.0f}s cap, attempts={attempts}")
        print("EVICT_RESULT FAIL")
        return
    admit_latency = admitted_at - t_b_start
    a_idle_at_admit = admitted_at - t_reply
    print(f"peerB=admitted attempts={attempts} b_admit_latency={admit_latency:.2f}s "
          f"a_idle_at_admit={a_idle_at_admit:.2f}s")
    print(f"EVICT_RESULT {'PASS' if admit_latency < 180.0 else 'FAIL'} "
          f"(admit latency must be << 180 s idle-reap)")
    a.close()
    b.close()


if __name__ == "__main__":
    cmd = sys.argv[1]
    addr = sys.argv[2].rsplit(":", 1)
    addr = (addr[0], int(addr[1]))
    if cmd == "peers":
        n = int(sys.argv[3])
        aging = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
        mode_peers(addr, n, aging)
    elif cmd == "evict-noreply":
        wait_before_b = float(sys.argv[3]) if len(sys.argv) > 3 else 6.0
        max_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 20.0
        mode_evict_noreply(addr, wait_before_b, max_wait)
    elif cmd == "evict":
        wait_before_b = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
        max_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 60.0
        mode_evict(addr, wait_before_b, max_wait)
    else:
        print(__doc__)
        sys.exit(2)
