#!/usr/bin/env python3
"""Summarize post-fix A/B campaign (fix-ab) vs the pre-fix baseline in bench.md."""
import re
import glob
import statistics
from collections import defaultdict

RX = {
    "udp": re.compile(r"udp sent=(\d+) recv=(\d+) batch=(\d+) wall=([\d.]+)s recv_pps=(\d+)"),
    "lat": re.compile(r"lat n=(\d+) .*?p50=(\d+) p90=(\d+) p99=(\d+) p999=(\d+) max=(\d+) mean=(\d+)"),
    "lattcp": re.compile(r"lattcp .*?connect p50=(\d+) p90=(\d+) p99=(\d+) p999=(\d+) max=(\d+) mean=(\d+).*?echo p50=(\d+) p90=(\d+) p99=(\d+) p999=(\d+) max=(\d+) mean=(\d+)"),
    "tcpecho": re.compile(r"tcpecho bytes=(\d+) echoed=(\d+) mismatched=(\d+) wall=([\d.]+)s ([\d.]+) MB/s (\w+)"),
    "paced": re.compile(r"udppaced .*?sent=(\d+) recv=(\d+) send_errs=(\d+) wall=[\d.]+s sent_pps=(\d+) recv_pps=(\d+) loss=([\d.]+)%"),
    "bidir": re.compile(r"udpbidir .*?sent=(\d+) recv=(\d+) send_errs=(\d+) wall=[\d.]+s sent_pps=(\d+) recv_pps=(\d+) loss=([\d.]+)%"),
}

data = defaultdict(lambda: defaultdict(list))
for path in sorted(glob.glob("/tmp/mq2-bench/logs/fix-ab-*.log")):
    m0 = re.search(r"fix-ab-(parent|fixed)-r\d+\.log", path)
    if not m0: continue
    arm = m0.group(1)
    d = data[arm]
    for line in open(path):
        line = line.strip()
        m = RX["udp"].match(line)
        if m:
            d["udp"].append(dict(sent=int(m.group(1)), recv=int(m.group(2)), wall=float(m.group(4)), pps=int(m.group(5))))
        m = RX["lat"].match(line)
        if m:
            d["lat"].append(dict(p50=int(m.group(2)), p90=int(m.group(3)), p99=int(m.group(4)), max=int(m.group(6)), mean=int(m.group(7))))
        m = RX["lattcp"].match(line)
        if m:
            d["lattcp"].append(dict(connect_p50=int(m.group(1)), connect_p99=int(m.group(3)), echo_p50=int(m.group(7)), echo_p99=int(m.group(9))))
        m = RX["tcpecho"].match(line)
        if m:
            d["tcpecho"].append(dict(mbps=float(m.group(5)), ok=m.group(6) == "OK"))
        m = RX["paced"].match(line)
        if m:
            d["paced"].append(dict(loss=float(m.group(6)), recv_pps=int(m.group(5))))
        m = RX["bidir"].match(line)
        if m:
            d["bidir"].append(dict(loss=float(m.group(6))))


def iqr(v):
    v = sorted(v)
    n = len(v)
    return (statistics.median(v[: n // 2]) if n > 1 else v[0],
            statistics.median(v[(n + 1) // 2:]) if n > 1 else v[0])


def show(name, vals, unit=""):
    vals = sorted(vals)
    q1, q3 = iqr(vals)
    print(f"  {name}: n={len(vals)} median={statistics.median(vals):.1f}{unit} min={vals[0]:.1f} q1={q1:.1f} q3={q3:.1f} max={vals[-1]:.1f}{unit}")


PRE = {  # pre-fix numbers from analysis/forwarding-audit/bench.md
    "parent": dict(udp_med=33088, udp_clean=34, udp_n=40, lat_p50=116.0, lat_p99=320.0,
                   conn_p50=99.0, echo_p50=131.0, tcp_med=89.1),
    "prefix_fixed": dict(udp_med=30571, udp_clean=28, udp_n=40, lat_p50=116.0, lat_p99=327.0,
                         conn_p50=100.5, echo_p50=132.0, tcp_med=89.5),
}

print("=" * 76)
print("A. post-fix HEAD vs parent (fresh interleaved campaign, 3 reps/arm)")
for arm in ["parent", "fixed"]:
    d = data[arm]
    udp = [u for u in d["udp"] if u["sent"] == 10000]
    clean = [u for u in udp if u["recv"] == u["sent"] and u["wall"] < 2]
    print(f"-- {arm}")
    print(f"  udp blast n=10000: runs={len(udp)} clean={len(clean)} lossy={len(udp)-len(clean)}")
    show("  clean_pps", [u["pps"] for u in clean])
    show("  lat p50 us", [x["p50"] for x in d["lat"]])
    show("  lat p99 us", [x["p99"] for x in d["lat"]])
    show("  lattcp connect_p50 us", [x["connect_p50"] for x in d["lattcp"]])
    show("  lattcp echo_p50 us", [x["echo_p50"] for x in d["lattcp"]])
    show("  tcpecho MB/s (all 5/instance)", [x["mbps"] for x in d["tcpecho"]])
    show("  paced30k loss %", [x["loss"] for x in d["paced"]])
    show("  paced30k recv_pps", [x["recv_pps"] for x in d["paced"]])
    show("  bidir20k loss %", [x["loss"] for x in d["bidir"]])

print("\nPre-fix baseline (bench.md):")
print(f"  parent:    udp clean median 33,088 ({PRE['parent']['udp_clean']}/{PRE['parent']['udp_n']} clean), "
      f"lat p50/p99 116/320 us, lattcp connect/echo 99/131 us, tcp 89.1 MB/s")
print(f"  pre-fix HEAD: udp clean median 30,571 ({PRE['prefix_fixed']['udp_clean']}/{PRE['prefix_fixed']['udp_n']} clean), "
      f"lat p50/p99 116/327 us, lattcp connect/echo 100.5/132 us, tcp 89.5 MB/s")
