#!/usr/bin/env python3
"""matrix.py — run every corpus censor program against every traffic set.

For each (traffic, program) cell CensorLab is run in PCAP mode and the flows on
which the program took any action (reset/drop/inject/delay/rewrite) are counted
with common/report.py's flow table:

    detection rate = flagged flows / flows in the capture

For the circumvention captures a hit is a correct detection; for the benign
control every hit is collateral damage (false positive rate).  Also records the
breakdown of actions and the run time.  Writes results/resilience_matrix.{csv,json}.

Inputs: corpus.conf (NAME=censor.toml), traffic.conf (NAME=pcap[:client_ip]).
The benign control is built on demand from the USTC-TFC2016 dataset.

Usage: python3 experiments/11_resilience_matrix/scripts/matrix.py [--benign-packets 50000]
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


def build_benign(path, n_packets):
    """First n IP packets of the USTC-TFC2016 captures, re-framed as Ethernet."""
    dataset = os.path.join(EXPERIMENTS, "datasets", "ustc-tfc2016")
    files = sorted(f for f in os.listdir(dataset) if f.endswith(".pcap")) if os.path.isdir(dataset) else []
    if not files:
        sys.exit("benign control needs the dataset: bash experiments/datasets/fetch_ustc_tfc2016.sh")
    # take an equal share from every capture so all applications are represented
    per_file = max(1, n_packets // len(files))
    n = 0
    with PcapWriter(path) as w:
        for name in files:
            taken = 0
            for ts, frame, lt in iter_records(os.path.join(dataset, name)):
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
    args = ap.parse_args()

    corpus = read_conf(os.path.join(EXP_DIR, "corpus.conf"))
    traffic = read_conf(os.path.join(EXP_DIR, "traffic.conf"))
    results_dir = os.path.join(EXP_DIR, "results")
    os.makedirs(results_dir, exist_ok=True)

    rows = []
    for tname, tpath, client in traffic:
        pcap = os.path.join(REPO, tpath)
        if tname == "benign" and not os.path.exists(pcap):
            print(f"building benign control ({args.benign_packets} packets) ...")
            build_benign(pcap, args.benign_packets)
        if not os.path.exists(pcap):
            print(f"  [skip] {tname}: {tpath} missing (run scripts/capture.sh)")
            continue
        flows = FlowTable(pcap)
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
            rate = len(positives) / flows.num_flows if flows.num_flows else 0.0
            rows.append({
                "traffic": tname, "program": pname, "config": ppath,
                "flows": flows.num_flows, "flagged": len(positives), "rate": round(rate, 4),
                "actions": ";".join(f"{k}={v}" for k, v in sorted(actions.items())),
                "seconds": round(secs, 3), "exit_code": rc,
            })
            print(f"  {pname:<22} {len(positives):>5}/{flows.num_flows:<5} {rate:6.1%}  {rows[-1]['actions']}")

    if not rows:
        print("nothing to do")
        return
    fields = list(rows[0].keys())
    with open(os.path.join(results_dir, "resilience_matrix.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(results_dir, "resilience_matrix.json"), "w") as f:
        json.dump({"experiment": "11_resilience_matrix", "rows": rows}, f, indent=2)

    # matrix view: programs × traffic sets
    tnames = [t for t, _, _ in traffic if any(r["traffic"] == t for r in rows)]
    print()
    print(f"{'program':<22}" + "".join(f"{t:>13}" for t in tnames))
    print("-" * (22 + 13 * len(tnames)))
    by = {(r["traffic"], r["program"]): r for r in rows}
    for pname, _, _ in corpus:
        cells = []
        for t in tnames:
            r = by.get((t, pname))
            cells.append(f"{r['rate']:>12.1%} " if r else f"{'—':>12} ")
        print(f"{pname:<22}" + "".join(cells))
    print(f"\nwrote {os.path.join(results_dir, 'resilience_matrix.csv')}")


if __name__ == "__main__":
    main()
