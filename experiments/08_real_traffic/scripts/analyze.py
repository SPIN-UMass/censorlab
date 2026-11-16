#!/usr/bin/env python3
"""analyze.py — aggregate the real-traffic study (scenario × mix × tool).

Reads results/<scenario>/<mix>/{table4.json,accuracy.json} produced by run.sh
and writes:

    results/real_traffic.csv    one row per (scenario, mix, tool)
    results/real_traffic.json   same, plus mix metadata

Columns: scenario, mix, background (ustc|iscx|combined), background_packets,
total_packets, tool, status,
wall_median_us, wall_stdev_us, startup_us, net_us, cpu_us, max_rss_kb,
net_per_packet_us, throughput_pps, n, tpr, tnr, background_flows,
background_flagged, note.

Usage: python3 experiments/08_real_traffic/scripts/analyze.py
"""

import csv
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXP_DIR = os.path.dirname(SCRIPT_DIR)
EXPERIMENTS = os.path.dirname(EXP_DIR)
sys.path.insert(0, os.path.join(EXPERIMENTS, "common"))
from scenario import TOOLS  # noqa: E402

_MIX_LINE = re.compile(r"^([a-z][a-z0-9_]*)=([0-9]+)\s*$")
_BLANK = re.compile(r"^\s*(#.*)?$")


def load_mixes(path):
    mixes = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if _BLANK.match(line):
                continue
            m = _MIX_LINE.match(line)
            if not m:
                raise ValueError(f"{path}:{lineno}: unrecognized line {line!r}")
            if m.group(1).endswith(tuple("_" + b for b in BACKGROUNDS if b != "ustc")):
                raise ValueError(f"{path}:{lineno}: mix name {m.group(1)!r} uses a reserved suffix")
            mixes.append((m.group(1), int(m.group(2))))
    return mixes


# Background datasets (see common.sh): result directories are
# results/<scenario>/<mix> for ustc and results/<scenario>/<mix>_<background> otherwise.
BACKGROUNDS = ("ustc", "iscx", "combined")


def mix_id(mix, background):
    return mix if background == "ustc" else f"{mix}_{background}"


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def main():
    mixes = load_mixes(os.path.join(EXP_DIR, "mixes.conf"))
    results_root = os.path.join(EXP_DIR, "results")
    rows = []
    for scenario in sorted(d for d in os.listdir(results_root)
                           if os.path.isdir(os.path.join(results_root, d))):
        for background, mix, bg_packets in ((b, m, n) for b in BACKGROUNDS for m, n in mixes):
            rdir = os.path.join(results_root, scenario, mix_id(mix, background))
            t4 = load_json(os.path.join(rdir, "table4.json"))
            acc = load_json(os.path.join(rdir, "accuracy.json"))
            if t4 is None:
                continue
            acc_rows = {r["tool"]: r for r in (acc or {}).get("rows", [])}
            total_packets = (acc or {}).get("packets")
            for r in t4["rows"]:
                a = acc_rows.get(r["tool"], {})
                net = r.get("net_us")
                rows.append({
                    "scenario": scenario,
                    "mix": mix,
                    "background": background,
                    "background_packets": bg_packets,
                    "total_packets": total_packets,
                    "tool": r["tool"],
                    "status": r.get("status"),
                    "wall_median_us": r.get("wall_median_us"),
                    "wall_stdev_us": r.get("wall_stdev_us"),
                    "startup_us": r.get("startup_us"),
                    "net_us": net,
                    "cpu_us": r.get("cpu_us"),
                    "max_rss_kb": r.get("max_rss_kb"),
                    "net_per_packet_us": (round(net / total_packets, 3)
                                          if net is not None and total_packets else None),
                    "throughput_pps": (round(total_packets / (net / 1e6))
                                       if net and total_packets and net > 0 else None),
                    "n": r.get("n"),
                    "tpr": a.get("tpr"),
                    "tnr": a.get("tnr"),
                    "background_flows": a.get("background_flows"),
                    "background_flagged": a.get("background_flagged"),
                    "note": r.get("note", ""),
                })

    if not rows:
        print("no results under", results_root)
        return

    fieldnames = list(rows[0].keys())
    with open(os.path.join(results_root, "real_traffic.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(results_root, "real_traffic.json"), "w") as f:
        json.dump({"experiment": "08_real_traffic", "mixes": dict(mixes), "rows": rows}, f, indent=2)

    # ---- summary -----------------------------------------------------------
    def fmt(v, w, scale=1, nd=0):
        if v is None:
            return f"{'—':>{w}}"
        return f"{v / scale:>{w}.{nd}f}"

    for scenario in sorted({r["scenario"] for r in rows}):
        print("=" * 126)
        print(f"{scenario}")
        print("=" * 126)
        print(f"{'mix':<15} {'pkts':>7} {'tool':<11} {'wall(ms)':>9} {'±sd':>7} {'startup':>8} {'net(ms)':>8} "
              f"{'us/pkt':>7} {'kpps':>6} {'cpu(ms)':>8} {'RSS(MB)':>8} {'TPR':>6} {'TNR':>6} {'bg-flag':>9}")
        print("-" * 126)
        for r in rows:
            if r["scenario"] != scenario or r["status"] != "measured":
                continue
            bg = (f"{r['background_flagged']}/{r['background_flows']}"
                  if r["background_flows"] else "-")
            print(f"{mix_id(r['mix'], r['background']):<15} {fmt(r['total_packets'], 7)} {r['tool']:<11} "
                  f"{fmt(r['wall_median_us'], 9, 1000, 1)} {fmt(r['wall_stdev_us'], 7, 1000, 1)} "
                  f"{fmt(r['startup_us'], 8, 1000, 1)} {fmt(r['net_us'], 8, 1000, 1)} "
                  f"{fmt(r['net_per_packet_us'], 7, 1, 2)} {fmt(r['throughput_pps'], 6, 1000, 0)} "
                  f"{fmt(r['cpu_us'], 8, 1000, 1)} {fmt(r['max_rss_kb'], 8, 1024, 1)} "
                  f"{fmt(r['tpr'], 6, 1, 3)} {fmt(r['tnr'], 6, 1, 3)} {bg:>9}")
        print()
    print(f"wrote {os.path.join(results_root, 'real_traffic.csv')}")


if __name__ == "__main__":
    main()
