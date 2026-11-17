#!/usr/bin/env python3
"""matrix.py — run every corpus censor program against every traffic set.

For each (traffic, program) cell CensorLab is run in PCAP mode and the flows on
which the program took any action (reset/drop/inject/delay/rewrite) are counted
with common/report.py's flow table:

    detection rate = flagged flows / flows in the capture

For the circumvention captures a hit is a correct detection; for the benign
control every hit is collateral damage (false positive rate).  Also records the
breakdown of actions and the run time.  Writes results/resilience_matrix.{csv,json}
(resilience_matrix_<background>.* for iscx/combined).

Inputs: corpus.conf (NAME=censor.toml), traffic.conf (NAME=pcap[:client_ip]).
The benign control is built on demand from real application traffic, selected
with --background (or $BACKGROUND), as in experiment 08:
  ustc      USTC-TFC2016 benign captures (pcap/benign.pcap; the original study)
  iscx      ISCXVPN2016 non-VPN captures (pcap/benign_iscx.pcap)
  combined  half the packets from each dataset (pcap/benign_combined.pcap; default)
For iscx/combined the benign traffic set is named benign_<background>.

Usage: python3 experiments/11_resilience_matrix/scripts/matrix.py [--benign-packets 50000]
           [--background ustc|iscx|combined]
"""

import argparse
import collections
import csv
import json
import os
import re
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXP_DIR = os.path.dirname(SCRIPT_DIR)
EXPERIMENTS = os.path.dirname(EXP_DIR)
REPO = os.path.dirname(EXPERIMENTS)
sys.path.insert(0, os.path.join(EXPERIMENTS, "common"))
from pcaprecords import PcapWriter, five_tuple, iter_records, to_ethernet  # noqa: E402
from report import FlowTable, adapt_censorlab  # noqa: E402

_CONF = re.compile(r"^([A-Za-z][A-Za-z0-9]*)=([A-Za-z0-9_./-]+)(?::([0-9.]*))?\s*$")
_BLANK = re.compile(r"^\s*(#.*)?$")


def read_conf(path):
    out = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if _BLANK.match(line):
                continue
            m = _CONF.match(line)
            if not m:
                raise ValueError(f"{path}:{lineno}: unrecognized line {line!r}")
            out.append((m.group(1), m.group(2), m.group(3) or ""))
    return out


# dataset name -> (directory of .pcap captures, how to obtain it)
DATASETS = {
    "ustc": (os.path.join(EXPERIMENTS, "datasets", "ustc-tfc2016"),
             "bash experiments/datasets/fetch_ustc_tfc2016.sh"),
    "iscx": (os.path.join(EXPERIMENTS, "datasets", "iscxvpn2016", "pcap"),
             "bash experiments/datasets/fetch_iscxvpn2016.sh (after the manual download)"),
}
BACKGROUNDS = {"ustc": ["ustc"], "iscx": ["iscx"], "combined": ["ustc", "iscx"]}


def benign_name(background):
    """Traffic-set name of the benign control; plain 'benign' keeps the original USTC rows."""
    return "benign" if background == "ustc" else f"benign_{background}"


def build_benign(path, n_packets, background):
    """First IP packets of the background captures, re-framed as Ethernet.

    The packet budget is split evenly across the background's datasets and then
    across each dataset's captures, so every application is represented.
    """
    datasets = BACKGROUNDS[background]
    sources = []
    for ds in datasets:
        d, hint = DATASETS[ds]
        files = sorted(f for f in os.listdir(d) if f.endswith(".pcap")) if os.path.isdir(d) else []
        if not files:
            sys.exit(f"benign control needs the {ds} dataset: {hint}")
        sources.append((d, files))
    n = 0
    with PcapWriter(path) as w:
        for d, files in sources:
            per_file = max(1, n_packets // len(datasets) // len(files))
            for name in files:
                taken = 0
                for ts, frame, lt in iter_records(os.path.join(d, name)):
                    eth = to_ethernet(frame, lt)
                    if eth is None:
                        continue
                    w.write(ts, eth)
                    n += 1
                    taken += 1
                    if taken >= per_file:
                        break
    return n


def most_common_client(pcap):
    """Most frequent source address of TCP SYN-ish / first packets — good enough as 'client'."""
    counts = collections.Counter()
    for _ts, frame, lt in iter_records(pcap):
        t = five_tuple(frame, lt)
        if t:
            counts[t[1]] += 1
    return counts.most_common(1)[0][0] if counts else "0.0.0.0"


def run_program(config, pcap, client_ip):
    t0 = time.perf_counter()
    proc = subprocess.run(["censorlab", "-c", config, "pcap", pcap, client_ip],
                          capture_output=True, text=True, errors="replace")
    return proc.stdout + proc.stderr, time.perf_counter() - t0, proc.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign-packets", type=int, default=50_000)
    ap.add_argument("--background", choices=sorted(BACKGROUNDS),
                    default=os.environ.get("BACKGROUND", "combined"))
    args = ap.parse_args()

    corpus = read_conf(os.path.join(EXP_DIR, "corpus.conf"))
    traffic = read_conf(os.path.join(EXP_DIR, "traffic.conf"))
    # traffic.conf names the USTC benign capture; other backgrounds get their own file and name
    if args.background != "ustc":
        suffix = f"_{args.background}.pcap"
        traffic = [(benign_name(args.background), p.removesuffix(".pcap") + suffix, c) if t == "benign"
                   else (t, p, c) for t, p, c in traffic]
    results_dir = os.path.join(EXP_DIR, "results")
    os.makedirs(results_dir, exist_ok=True)

    rows = []
    for tname, tpath, client in traffic:
        pcap = os.path.join(REPO, tpath)
        if tname == benign_name(args.background) and not os.path.exists(pcap):
            print(f"building benign control ({args.benign_packets} packets, {args.background}) ...")
            build_benign(pcap, args.benign_packets, args.background)
        if not os.path.exists(pcap):
            print(f"  [skip] {tname}: {tpath} missing (run scripts/capture.sh)")
            continue
        flows = FlowTable(pcap)
        flow_proto = {flow: key[0] for key, flow in flows.key_to_flow.items()}
        client_ip = client or most_common_client(pcap)
        print(f"== {tname}: {len(flows.pkt_to_flow)} packets, {flows.num_flows} flows, client {client_ip}")
        for pname, ppath, _ in corpus:
            config = os.path.join(REPO, ppath)
            out, secs, rc = run_program(config, pcap, client_ip)
            log = os.path.join(results_dir, f"{tname}__{pname}.txt")
            with open(log, "w") as f:
                f.write(out)
            positives = adapt_censorlab(log, flows)
            actions = collections.Counter(positives.values())
            by_proto = collections.Counter(flow_proto[f] for f in positives)
            rate = len(positives) / flows.num_flows if flows.num_flows else 0.0
            rows.append({
                "traffic": tname, "program": pname, "config": ppath,
                "flows": flows.num_flows, "flagged": len(positives), "rate": round(rate, 4),
                "flagged_tcp": by_proto["tcp"], "flagged_udp": by_proto["udp"],
                "actions": ";".join(f"{k}={v}" for k, v in sorted(actions.items())),
                "seconds": round(secs, 3), "exit_code": rc,
            })
            print(f"  {pname:<22} {len(positives):>5}/{flows.num_flows:<5} {rate:6.1%}  {rows[-1]['actions']}")

    if not rows:
        print("nothing to do")
        return
    fields = list(rows[0].keys())
    # the USTC run keeps the original file names; other backgrounds get their own
    stem = "resilience_matrix" if args.background == "ustc" else f"resilience_matrix_{args.background}"
    out_csv = os.path.join(results_dir, f"{stem}.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(results_dir, f"{stem}.json"), "w") as f:
        json.dump({"experiment": "11_resilience_matrix", "background": args.background, "rows": rows}, f, indent=2)

    # matrix view: programs × traffic sets
    tnames = [t for t, _, _ in traffic if any(r["traffic"] == t for r in rows)]
    print()
    width = max([13] + [len(t) + 2 for t in tnames])
    print(f"{'program':<22}" + "".join(f"{t:>{width}}" for t in tnames))
    print("-" * (22 + width * len(tnames)))
    by = {(r["traffic"], r["program"]): r for r in rows}
    for pname, _, _ in corpus:
        cells = []
        for t in tnames:
            r = by.get((t, pname))
            cells.append(f"{r['rate']:>{width - 1}.1%} " if r else f"{'—':>{width - 1}} ")
        print(f"{pname:<22}" + "".join(cells))
    print(f"\nwrote {out_csv}")


if __name__ == "__main__":
    main()
