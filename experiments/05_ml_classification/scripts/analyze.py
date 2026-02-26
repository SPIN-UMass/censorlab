#!/usr/bin/env python3
"""Analyze experiment 5 results and output structured data for TeX import.

Reads raw_timings.csv, loc.csv, and optionally live eval results.
Outputs:
  - results/table4.csv  — Table 4 (showcase: timing + LOC)
  - results/table4.json — Table 4 as JSON
  - results/table3.csv  — Table 3 (evaluation: TPR/TNR), if live eval available
  - results/table3.json — Table 3 as JSON

Usage:
    # After running run_showcase.sh:
    python3 analyze.py

    # After running run_evaluation.sh:
    python3 analyze.py --live-eval results/live_eval_results.csv
"""

import argparse
import csv
import json
import os
import statistics
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(EXPERIMENT_DIR, "results")

# Add common utilities to path
sys.path.insert(0, os.path.join(EXPERIMENT_DIR, "..", "common"))
from analysis import load_labels, load_decisions, compute_tpr_tnr


def load_raw_timings(path):
    """Load raw_timings.csv -> {tool: [time_us, ...]}."""
    timings = {}
    if not os.path.exists(path):
        return timings
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            tool = row["tool"]
            try:
                t = int(row["time_us"])
            except (ValueError, KeyError):
                continue
            timings.setdefault(tool, []).append(t)
    return timings


def load_loc(path):
    """Load loc.csv -> {tool: {file, loc}}."""
    loc = {}
    if not os.path.exists(path):
        return loc
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            loc[row["tool"]] = {"file": row["file"], "loc": int(row["loc"])}
    return loc


def analyze_showcase():
    """Generate Table 4 data from showcase results."""
    raw_timings_path = os.path.join(RESULTS_DIR, "raw_timings.csv")
    loc_path = os.path.join(RESULTS_DIR, "loc.csv")

    timings = load_raw_timings(raw_timings_path)
    loc_data = load_loc(loc_path)

    if not timings and not loc_data:
        return False

    print("=" * 72)
    print("TABLE 4: PCAP-Mode Timing & Lines of Code (Showcase)")
    print("=" * 72)
    print()

    tool_order = ["PyCL", "CensorLang", "Scapy"]
    tool_notes = {
        "PyCL": "ONNX model classification",
        "CensorLang": "entropy heuristic (no ML support)",
        "Scapy": "ONNX model classification",
    }

    rows = []
    for tool in tool_order:
        t_list = timings.get(tool, [])
        loc_info = loc_data.get(tool, {})
        loc_val = loc_info.get("loc", "")

        if t_list:
            median_us = statistics.median(t_list)
            min_us = min(t_list)
            max_us = max(t_list)
            mean_us = statistics.mean(t_list)
            stdev_us = statistics.stdev(t_list) if len(t_list) > 1 else 0
            n = len(t_list)
        else:
            median_us = min_us = max_us = mean_us = stdev_us = None
            n = 0

        row = {
            "tool": tool,
            "median_us": median_us,
            "mean_us": round(mean_us, 1) if mean_us is not None else None,
            "stdev_us": round(stdev_us, 1) if stdev_us is not None else None,
            "min_us": min_us,
            "max_us": max_us,
            "n": n,
            "loc": loc_val if loc_val != "" else None,
            "note": tool_notes.get(tool, ""),
        }
        rows.append(row)

    # Print table
    print(f"{'Tool':<14} {'Median (us)':<14} {'Mean (us)':<14} {'Stdev':<12} {'LOC':<6} {'Note'}")
    print("-" * 72)
    for r in rows:
        med = f"{r['median_us']}" if r["median_us"] is not None else "N/A"
        mean = f"{r['mean_us']}" if r["mean_us"] is not None else "N/A"
        std = f"{r['stdev_us']}" if r["stdev_us"] is not None else "N/A"
        loc = str(r["loc"]) if r["loc"] is not None else "N/A"
        print(f"{r['tool']:<14} {med:<14} {mean:<14} {std:<12} {loc:<6} {r['note']}")
    print()

    # Write CSV
    table4_csv = os.path.join(RESULTS_DIR, "table4.csv")
    with open(table4_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "tool", "median_us", "mean_us", "stdev_us", "min_us", "max_us", "n", "loc", "note"
        ])
        writer.writeheader()
        writer.writerows(rows)
    print(f"  CSV: {table4_csv}")

    # Write JSON
    table4_json = os.path.join(RESULTS_DIR, "table4.json")
    with open(table4_json, "w") as f:
        json.dump({"table": "table4", "experiment": "05_ml_classification", "rows": rows}, f, indent=2)
    print(f"  JSON: {table4_json}")

    # Also compute PCAP accuracy for Scapy if labels exist
    # NOTE: Exp 5 uses flow-based labels (flow_index, class=blocked/normal)
    # and flow-based decisions (flow_first_pkt, action=drop/allow),
    # so we adapt rather than using the shared per-packet compute_tpr_tnr.
    labels_path = os.path.join(EXPERIMENT_DIR, "pcap", "labels.csv")
    scapy_decisions = os.path.join(RESULTS_DIR, "scapy_decisions.csv")
    if os.path.exists(labels_path) and os.path.exists(scapy_decisions):
        with open(labels_path) as f:
            labels = list(csv.DictReader(f))
        with open(scapy_decisions) as f:
            decisions = list(csv.DictReader(f))
        # Build lookup: first_packet_index -> action
        dec_map = {int(d["flow_first_pkt"]): d["action"] for d in decisions}
        tp = fn = tn = fp = 0
        for l in labels:
            first_pkt = int(l["first_packet_index"])
            cls = l["class"]  # "blocked" or "normal"
            action = dec_map.get(first_pkt, "allow")
            if cls == "blocked":
                if action == "drop":
                    tp += 1
                else:
                    fn += 1
            else:
                if action == "drop":
                    fp += 1
                else:
                    tn += 1
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        print(f"\n  Scapy PCAP accuracy check: TPR={tpr:.4f} TNR={tnr:.4f} (TP={tp} FN={fn} FP={fp} TN={tn})")

    print()
    return True


def analyze_live_eval(results_csv):
    """Generate Table 3 data from live evaluation results."""
    print("=" * 72)
    print("TABLE 3: Live NFQ Evaluation — TPR/TNR")
    print("=" * 72)
    print()

    if not os.path.exists(results_csv):
        print(f"ERROR: Results file not found: {results_csv}")
        return

    with open(results_csv) as f:
        results = list(csv.DictReader(f))

    tp = sum(1 for r in results if r["class"] == "blocked" and r["outcome"] == "dropped")
    fn = sum(1 for r in results if r["class"] == "blocked" and r["outcome"] != "dropped")
    tn = sum(1 for r in results if r["class"] == "normal" and r["outcome"] == "completed")
    fp = sum(1 for r in results if r["class"] == "normal" and r["outcome"] == "dropped")
    errors = sum(1 for r in results if r["outcome"] == "error")

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    rows = [
        {
            "tool": "PyCL",
            "tpr": round(tpr, 4),
            "tnr": round(tnr, 4),
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "errors": errors,
            "total": len(results),
            "note": "ONNX model classification",
        },
        {
            "tool": "CensorLang",
            "tpr": None,
            "tnr": None,
            "tp": None,
            "fn": None,
            "fp": None,
            "tn": None,
            "errors": None,
            "total": None,
            "note": "entropy heuristic (cannot use ML models)",
        },
    ]

    # Print table
    print(f"{'Tool':<16} {'TPR':<10} {'TNR':<10} {'TP':<6} {'FN':<6} {'FP':<6} {'TN':<6} {'Note'}")
    print("-" * 72)
    for r in rows:
        tpr_s = f"{r['tpr']:.4f}" if r["tpr"] is not None else "N/A"
        tnr_s = f"{r['tnr']:.4f}" if r["tnr"] is not None else "N/A"
        tp_s = str(r["tp"]) if r["tp"] is not None else "N/A"
        fn_s = str(r["fn"]) if r["fn"] is not None else "N/A"
        fp_s = str(r["fp"]) if r["fp"] is not None else "N/A"
        tn_s = str(r["tn"]) if r["tn"] is not None else "N/A"
        print(f"{r['tool']:<16} {tpr_s:<10} {tnr_s:<10} {tp_s:<6} {fn_s:<6} {fp_s:<6} {tn_s:<6} {r['note']}")
    print()

    # Write CSV
    table3_csv = os.path.join(RESULTS_DIR, "table3.csv")
    with open(table3_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "tool", "tpr", "tnr", "tp", "fn", "fp", "tn", "errors", "total", "note"
        ])
        writer.writeheader()
        writer.writerows(rows)
    print(f"  CSV: {table3_csv}")

    # Write JSON
    table3_json = os.path.join(RESULTS_DIR, "table3.json")
    with open(table3_json, "w") as f:
        json.dump({"table": "table3", "experiment": "05_ml_classification", "rows": rows}, f, indent=2)
    print(f"  JSON: {table3_json}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Analyze Experiment 5 results")
    parser.add_argument(
        "--live-eval", type=str, default=None,
        help="Path to live evaluation results CSV (for Table 3)",
    )
    args = parser.parse_args()

    has_showcase = analyze_showcase()

    if args.live_eval:
        analyze_live_eval(args.live_eval)

    if not has_showcase and not args.live_eval:
        print("No results found. Run one of:")
        print("  bash experiments/05_ml_classification/scripts/run_showcase.sh")


if __name__ == "__main__":
    main()
