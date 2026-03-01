#!/usr/bin/env python3
"""Compute accuracy from PCAP-mode results and write table3.json files.

Parses pycl_output.txt to extract CensorLab's censorship decisions,
compares against pcap/labels.csv ground truth, and writes table3.json
for each experiment.

This provides the same accuracy metrics as live NFQ evaluation but
computed from PCAP-mode processing, which tests the censor classification
logic without requiring network-level packet injection.

Usage:
    python3 experiments/scripts/compute_pcap_accuracy.py
"""

import csv
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENTS_DIR = os.path.dirname(SCRIPT_DIR)

# Add common utilities to path
sys.path.insert(0, os.path.join(EXPERIMENTS_DIR, "common"))
from analysis import load_labels, compute_tpr_tnr

# Experiment configs: (dir_name, action_pattern, positive_action_name, note)
EXPERIMENTS = [
    ("01_http_keyword", r"Ok\(Reset\b", "reset", "HTTP keyword matching"),
    ("02_dns_injection", r"Ok\(Inject\b", "inject", "DNS response injection"),
    ("03_tls_sni", r"Ok\(Reset\b", "reset", "TLS SNI filtering"),
    ("04_shadowsocks", r"Ok\(Drop\)", "drop", "Wu et al. 2023 heuristics"),
]


def parse_pycl_output(path, action_pattern):
    """Parse pycl_output.txt and extract actioned packet indices.

    CensorLab's PCAP mode has a packet_index that starts at 0 and increments
    for every block read from the pcap file, including the file header.
    For legacy pcap files (written by Scapy's wrpcap), the first block is the
    LegacyHeader, so the first data packet gets index 2 instead of 0.
    We subtract this offset to align with label indices (0-based).

    Returns a set of label-aligned packet indices where the censor took action.
    """
    CENSORLAB_PCAP_OFFSET = 2  # LegacyHeader block + 1-based increment

    actioned = set()
    pattern = re.compile(r"^(\d+):\s+" + action_pattern)

    with open(path) as f:
        for line in f:
            line = line.strip()
            m = pattern.match(line)
            if m:
                raw_index = int(m.group(1))
                label_index = raw_index - CENSORLAB_PCAP_OFFSET
                if label_index >= 0:
                    actioned.add(label_index)

    return actioned


def make_decisions(labels, actioned_indices, action_name):
    """Convert actioned indices into a decisions list matching labels format."""
    decisions = []
    for label in labels:
        idx = int(label["index"])
        if idx in actioned_indices:
            decisions.append({"index": idx, "action": action_name})
        else:
            decisions.append({"index": idx, "action": "allow"})
    return decisions


def main():
    print("=" * 72)
    print("  Computing PCAP-mode accuracy for all experiments")
    print("=" * 72)
    print()

    for exp_dir, action_pattern, action_name, note in EXPERIMENTS:
        exp_path = os.path.join(EXPERIMENTS_DIR, exp_dir)
        labels_path = os.path.join(exp_path, "pcap", "labels.csv")
        pycl_path = os.path.join(exp_path, "results", "pycl_output.txt")
        results_dir = os.path.join(exp_path, "results")

        print(f"--- {exp_dir} ---")

        if not os.path.exists(labels_path):
            print(f"  SKIP: {labels_path} not found")
            continue
        if not os.path.exists(pycl_path):
            print(f"  SKIP: {pycl_path} not found")
            continue

        # Load labels
        labels = load_labels(labels_path)

        # Parse PyCL output
        actioned = parse_pycl_output(pycl_path, action_pattern)

        # Build decisions
        decisions = make_decisions(labels, actioned, action_name)

        # Compute accuracy
        tpr, tnr, tp, fn, tn, fp = compute_tpr_tnr(
            labels, decisions, positive_actions=(action_name,)
        )
        accuracy = round((tpr + tnr) / 2, 4)

        print(f"  Labels: {len(labels)} ({sum(1 for l in labels if l['class'] == 'forbidden')} forbidden, "
              f"{sum(1 for l in labels if l['class'] == 'allowed')} allowed)")
        print(f"  PyCL actions: {len(actioned)} {action_name}(s)")
        print(f"  TP={tp} FN={fn} FP={fp} TN={tn}")
        print(f"  TPR={tpr:.4f} TNR={tnr:.4f} Accuracy={accuracy:.4f}")

        # Also compute Scapy accuracy for comparison
        scapy_path = os.path.join(results_dir, "scapy_decisions.csv")
        if os.path.exists(scapy_path):
            with open(scapy_path) as f:
                scapy_decisions = list(csv.DictReader(f))
            s_tpr, s_tnr, s_tp, s_fn, s_tn, s_fp = compute_tpr_tnr(
                labels, scapy_decisions, positive_actions=(action_name,)
            )
            print(f"  Scapy check: TPR={s_tpr:.4f} TNR={s_tnr:.4f}")

        # Write table3.json
        rows = [
            {
                "tool": "PyCL",
                "tpr": round(tpr, 4),
                "tnr": round(tnr, 4),
                "tp": tp,
                "fn": fn,
                "fp": fp,
                "tn": tn,
                "errors": 0,
                "total": len(labels),
                "note": note,
            },
        ]

        table3_json = os.path.join(results_dir, "table3.json")
        with open(table3_json, "w") as f:
            json.dump({
                "table": "table3",
                "experiment": exp_dir,
                "rows": rows,
            }, f, indent=2)
        print(f"  Wrote: {table3_json}")
        print()

    print("Done. Run aggregate_results.py to update results.tex.")


if __name__ == "__main__":
    main()
