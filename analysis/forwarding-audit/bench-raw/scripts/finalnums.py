#!/usr/bin/env python3
"""Final numbers digest for bench.md."""
import re
import glob
import statistics
from collections import defaultdict

RX = {
    "load": re.compile(r"load averages?: ([\d.]+)"),
    "udp": re.compile(r"udp sent=(\d+) recv=(\d+) batch=(\d+) wall=([\d.]+)s recv_pps=(\d+)"),
    "lat": re.compile(r"lat n=(\d+) payload=(\d+) samples=(\d+) lost=(\d+) stale=(\d+) bad=(\d+) wall=([\d.]+)s p50=(\d+) p90=(\d+) p99=(\d+) p999=(\d+) max=(\d+) mean=(\d+)"),
    "lattcp": re.compile(r"lattcp .*connect_ok=(\d+) connect_lost=(\d+) echo_ok=(\d+) echo_lost=(\d+).*?connect p50=(\d+) p90=(\d+) p99=(\d+) p999=(\d+) max=(\d+) mean=(\d+).*?echo p50=(\d+) p90=(\d+) p99=(\d+) p999=(\d+) max=(\d+) mean=(\d+)"),
    "tcpecho": re.compile(r"tcpecho bytes=(\d+) echoed=(\d+) mismatched=(\d+) wall=([\d.]+)s ([\d.]+) MB/s (\w+)"),
    "paced": re.compile(r"udppaced .*sent=(\d+) recv=(\d+) send_errs=(\d+) wall=[\d.]+s sent_pps=(\d+) recv_pps=(\d+) loss=([\d.]+)%"),
    "bidir": re.compile(r"udpbidir .*sent=(\d+) recv=(\d+) send_errs=(\d+) wall=[\d.]+s sent_pps=(\d+) recv_pps=(\d+) loss=([\d.]+)%"),
    "multipaced": re.compile(r"udpmultipaced .*sent=(\d+) recv=(\d+) send_errs=(\d+) wall=[\d.]+s .*recv_pps=(\d+) loss=([\d.]+)%"),
}


def parse(path, d):
    for line in open(path, errors="replace"):
        line = line.strip()
        m = RX["load"].search(line)
        if m:
            d["load"].append(float(m.group(1)))
        m = RX["udp"].match(line)
        if m:
            d["udp"].append(dict(sent=int(m.group(1)), recv=int(m.group(2)),
                                 wall=float(m.group(4)), pps=int(m.group(5)), n=int(m.group(1))))
        m = RX["lat"].match(line)
        if m:
            d["lat"].append(dict(n=int(m.group(1)), lost=int(m.group(4)),
                                 p50=int(m.group(8)), p90=int(m.group(9)), p99=int(m.group(10)),
                                 max=int(m.group(12)), mean=int(m.group(13))))
        m = RX["lattcp"].match(line)
        if m:
            d["lattcp"].append(dict(connect_p50=int(m.group(5)), connect_p99=int(m.group(7)),
                                    echo_p50=int(m.group(11)), echo_p99=int(m.group(13)),
                                    lost=int(m.group(2)) + int(m.group(4))))
        m = RX["tcpecho"].match(line)
        if m:
            d["tcpecho"].append(dict(mbps=float(m.group(5)), ok=m.group(6) == "OK"))
        m = RX["paced"].match(line)
        if m:
            d["paced"].append(dict(sent=int(m.group(1)), recv=int(m.group(2)),
                                   loss=float(m.group(6)), recv_pps=int(m.group(5))))
        m = RX["bidir"].match(line)
        if m:
            d["bidir"].append(dict(loss=float(m.group(6))))
        m = RX["multipaced"].match(line)
        if m:
            d["multipaced"].append(dict(loss=float(m.group(5)), recv_pps=int(m.group(4))))
    return d


def iqr(v):
    v = sorted(v)
    n = len(v)
    q1 = statistics.median(v[: n // 2]) if n > 1 else v[0]
    q3 = statistics.median(v[(n + 1) // 2:]) if n > 1 else v[0]
    return q1, q3


def show(name, vals, unit=""):
    vals = sorted(vals)
    q1, q3 = iqr(vals)
    print(f"  {name}: n={len(vals)} median={statistics.median(vals):.1f}{unit} "
          f"min={vals[0]:.1f} q1={q1:.1f} q3={q3:.1f} max={vals[-1]:.1f}{unit}")


def newdict():
    return defaultdict(list)


camp = defaultdict(newdict)
for path in glob.glob("/tmp/mq2-bench/logs/raw-*.log"):
    m = re.search(r"raw-(\w+)-r(\d+)\.log", path)
    if m.group(1) == "headA" and m.group(2) == "0":
        continue
    parse(path, camp[m.group(1)])

supp = defaultdict(newdict)
for path in glob.glob("/tmp/mq2-bench/logs/raw2-*.log"):
    m = re.search(r"raw2-(\w+)-r\d+\.log", path)
    parse(path, supp[m.group(1)])

latf = defaultdict(list)
lattcpf = defaultdict(list)
cur = None
for line in open("/tmp/mq2-bench/logs/latfocus.out"):
    m = re.match(r"### latfocus arm=(\w+)", line)
    if m:
        cur = m.group(1)
        continue
    m = RX["lat"].match(line.strip())
    if m and int(m.group(1)) == 500 and cur:
        latf[cur].append(dict(p50=int(m.group(8)), p99=int(m.group(10)), max=int(m.group(12))))
    m = RX["lattcp"].match(line.strip())
    if m and cur:
        lattcpf[cur].append(dict(connect=int(m.group(5)), echo=int(m.group(11))))

knee = defaultdict(lambda: defaultdict(list))
cur = None
for line in open("/tmp/mq2-bench/logs/knee.out"):
    m = re.match(r"### rate=(\d+) arm=(\w+)", line)
    if m:
        cur = (int(m.group(1)), m.group(2))
        continue
    m = RX["paced"].match(line.strip())
    if m and cur:
        knee[cur[1]][cur[0]].append(float(m.group(6)))

ab_tcp = defaultdict(list)
cur = None
measured = False
for line in open("/tmp/mq2-bench/logs/tcpecho-ab.out"):
    m = re.match(r"### tcpecho-ab arm=(\w+)", line)
    if m:
        cur = m.group(1)
        measured = False
        continue
    if line.strip() == "# measured":
        measured = True
        continue
    m = RX["tcpecho"].match(line.strip())
    if m and cur and measured:
        ab_tcp[cur].append(float(m.group(5)))

print("=" * 72)
print("A. SOCKS5 baseline: parent vs HEAD (no forward config)")
for arm in ["parent", "headA"]:
    print(f"-- {arm}")
    for tag, src in (("campaign", camp), ("supplement", supp)):
        udp = [u for u in src[arm]["udp"] if u["n"] == 10000]
        clean = [u for u in udp if u["recv"] == u["sent"] and u["wall"] < 2]
        print(f"  {tag} udp blast n=10000: runs={len(udp)} clean={len(clean)} lossy={len(udp)-len(clean)}")
        show(f"  {tag} clean_pps", [u["pps"] for u in clean])
    show("  campaign lat p50 us", [x["p50"] for x in camp[arm]["lat"]])
    show("  campaign lat p99 us", [x["p99"] for x in camp[arm]["lat"]])
    show("  supplement lat p50 us", [x["p50"] for x in supp[arm]["lat"]])
    show("  supplement lat p99 us", [x["p99"] for x in supp[arm]["lat"]])
    show("  latfocus lat p50 us", [x["p50"] for x in latf[arm]])
    show("  latfocus lat p99 us", [x["p99"] for x in latf[arm]])
    show("  campaign lattcp connect_p50 us", [x["connect_p50"] for x in camp[arm]["lattcp"]])
    show("  campaign lattcp echo_p50 us", [x["echo_p50"] for x in camp[arm]["lattcp"]])
    show("  latfocus lattcp connect_p50 us", [x["connect"] for x in lattcpf[arm]])
    show("  latfocus lattcp echo_p50 us", [x["echo"] for x in lattcpf[arm]])
    show("  campaign tcpecho MB/s", [x["mbps"] for x in camp[arm]["tcpecho"]])
    show("  supplement tcpecho MB/s", [x["mbps"] for x in supp[arm]["tcpecho"]])
    show("  clean tcpecho-ab MB/s (after warmup)", ab_tcp[arm])
    print(f"  campaign paced30k loss%: {[p['loss'] for p in camp[arm]['paced']]}")
    print(f"  campaign bidir loss%: {[b['loss'] for b in camp[arm]['bidir']]}")
    print(f"  campaign multipaced loss%: {[b['loss'] for b in camp[arm]['multipaced']]} "
          f"recv_pps={[b['recv_pps'] for b in camp[arm]['multipaced']]}")
print("-- paced knee sweep loss% by offered rate (2 runs each)")
for rate in [32000, 36000, 40000, 44000]:
    print(f"  {rate}: parent={knee['parent'][rate]} headA={knee['headA'][rate]}")

print("=" * 72)
print("B. HEAD with idle forward listeners (headB) vs without (headA)")
for arm in ["headA", "headB"]:
    print(f"-- {arm}")
    udp = [u for u in camp[arm]["udp"] if u["n"] == 10000]
    clean = [u for u in udp if u["recv"] == u["sent"] and u["wall"] < 2]
    print(f"  udp blast: runs={len(udp)} clean={len(clean)} lossy={len(udp)-len(clean)}")
    show("  clean_pps", [u["pps"] for u in clean])
    show("  lat p50 us", [x["p50"] for x in camp[arm]["lat"]])
    show("  lat p99 us", [x["p99"] for x in camp[arm]["lat"]])
    show("  lattcp connect_p50 us", [x["connect_p50"] for x in camp[arm]["lattcp"]])
    show("  lattcp echo_p50 us", [x["echo_p50"] for x in camp[arm]["lattcp"]])
    show("  tcpecho MB/s", [x["mbps"] for x in camp[arm]["tcpecho"]])
    print(f"  paced30k loss%: {[p['loss'] for p in camp[arm]['paced']]}")
    print(f"  bidir loss%: {[b['loss'] for b in camp[arm]['bidir']]}")
    print(f"  multipaced loss%: {[b['loss'] for b in camp[arm]['multipaced']]} "
          f"recv_pps={[b['recv_pps'] for b in camp[arm]['multipaced']]}")

print("=" * 72)
print("C. forward path absolute (client-head-b, scenarioC forward.out)")
fwd = newdict()
parse("/tmp/mq2-bench/logs/forward.out", fwd)
show("  udp_forward pps 1000B n=10000 (all runs)", [u["pps"] for u in fwd["udp"] if u["n"] == 10000])
clean = [u for u in fwd["udp"] if u["n"] == 10000 and u["recv"] == u["sent"]]
print(f"  udp_forward clean runs: {len(clean)}/{sum(1 for u in fwd['udp'] if u['n'] == 10000)}")
show("  udp_forward lat p50 us", [x["p50"] for x in fwd["lat"] if x["n"] == 500])
show("  udp_forward lat p99 us", [x["p99"] for x in fwd["lat"] if x["n"] == 500])
show("  udp_forward lat max us", [x["max"] for x in fwd["lat"] if x["n"] == 500])

# tcp forward latency lines are printed by python bench_forward.py tcp-lat
tcp_lat = []
for line in open("/tmp/mq2-bench/logs/forward.out"):
    m = re.match(r"tcp-lat .* n=500 .*?p50=(\d+) p90=(\d+) p99=(\d+) max=(\d+) mean=(\d+)", line)
    if m:
        tcp_lat.append(dict(p50=int(m.group(1)), p99=int(m.group(3)), max=int(m.group(4))))
show("  tcp_forward lat p50 us", [x["p50"] for x in tcp_lat])
show("  tcp_forward lat p99 us", [x["p99"] for x in tcp_lat])

# multi-peer lines
mp = []
for line in open("/tmp/mq2-bench/logs/forward.out"):
    m = re.match(r"udp-multi .*sent=(\d+) recv=(\d+).*wall=([\d.]+)s recv_pps=(\d+) loss=([\d.]+)%", line)
    if m:
        mp.append(dict(sent=int(m.group(1)), recv=int(m.group(2)), pps=int(m.group(4)), loss=float(m.group(5))))
print(f"  udp_forward multi-peer runs: {[(r['sent'], r['recv'], r['pps'], r['loss']) for r in mp]}")

# tcp bulk integrity lines from fixed script retest
for line in open("/tmp/mq2-bench/logs/tcp-integrity.out"):
    if line.startswith("tcpverify fwd") or line.startswith("tcpverify direct"):
        pass
