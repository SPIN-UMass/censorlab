#!/usr/bin/env python3
"""Analyze benchmark results and produce throughput/latency summary.

Reads benchmark_results.csv and computes:
- Per-packet latency (us/packet) for each censor at each PCAP size
- Throughput (packets/second) for each censor
- Overhead compared to null censor

Outputs:
- results/benchmark_summary.csv
- results/benchmark_summary.json

Usage:
    # After running run_benchmarks.sh:
    python3 experiments/07_benchmarks/scripts/analyze.py

    # With custom results path:
    python3 analyze.py --results path/to/benchmark_results.csv
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


def load_benchmark_results(path):
    """Load benchmark_results.csv -> {(censor, pcap_size): [time_us, ...]}."""
    results = {}
    if not os.path.exists(path):
        return results
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            censor = row["censor"]
            try:
                pcap_size = int(row["pcap_size"])
                time_us = int(row["time_us"])
            except (ValueError, KeyError):
                continue
            key = (censor, pcap_size)
            results.setdefault(key, []).append(time_us)
    return results


def compute_stats(time_list):
    """Compute summary statistics for a list of timings (microseconds)."""
    if not time_list:
        return None
    n = len(time_list)
    return {
        "n": n,
        "median_us": statistics.median(time_list),
        "mean_us": round(statistics.mean(time_list), 1),
        "stdev_us": round(statistics.stdev(time_list), 1) if n > 1 else 0.0,
        "min_us": min(time_list),
        "max_us": max(time_list),
    }


def analyze(results_path):
    """Generate benchmark summary from raw results."""
    results = load_benchmark_results(results_path)

    if not results:
        print(f"ERROR: No results found in {results_path}")
        print("Run the benchmark first:")
        print("  bash experiments/07_benchmarks/scripts/run_benchmarks.sh")
        return False

    # Collect all censors and sizes seen in the data
    censors = sorted(set(c for c, _ in results.keys()))
    pcap_sizes = sorted(set(s for _, s in results.keys()))

    # Build null baseline for overhead computation
    null_medians = {}
    for size in pcap_sizes:
        key = ("null", size)
        if key in results:
            null_medians[size] = statistics.median(results[key])

    # Build summary rows
    rows = []
    for censor in censors:
        for size in pcap_sizes:
            key = (censor, size)
            time_list = results.get(key, [])
            stats = compute_stats(time_list)
            if stats is None:
                continue

            median_us = stats["median_us"]
            per_packet_us = round(median_us / size, 3)
            throughput_pps = round(size / (median_us / 1e6)) if median_us > 0 else 0
            throughput_mbps = None  # Would require packet size data

            # Compute overhead relative to null censor
            null_median = null_medians.get(size)
            if null_median and null_median > 0:
                overhead = round(median_us / null_median, 3)
            else:
                overhead = None

            row = {
                "censor": censor,
                "pcap_size": size,
                "median_us": median_us,
                "mean_us": stats["mean_us"],
                "stdev_us": stats["stdev_us"],
                "min_us": stats["min_us"],
                "max_us": stats["max_us"],
                "n": stats["n"],
                "per_packet_us": per_packet_us,
                "throughput_pps": throughput_pps,
                "overhead_vs_null": overhead,
            }
            rows.append(row)

    # Print summary table
    print("=" * 96)
    print("EXPERIMENT 7: Throughput/Latency Benchmark Summary")
    print("=" * 96)
    print()

    # Group by censor
    for censor in censors:
        censor_rows = [r for r in rows if r["censor"] == censor]
        if not censor_rows:
            continue

        print(f"--- {censor} ---")
        print(f"  {'Packets':<10} {'Median (us)':<14} {'Mean (us)':<14} {'Stdev':<12} "
              f"{'us/pkt':<10} {'pkt/s':<12} {'Overhead':<10}")
        print(f"  {'-' * 82}")

        for r in censor_rows:
            overhead_s = f"{r['overhead_vs_null']:.3f}x" if r["overhead_vs_null"] is not None else "baseline"
            print(f"  {r['pcap_size']:<10} {r['median_us']:<14} {r['mean_us']:<14} "
                  f"{r['stdev_us']:<12} {r['per_packet_us']:<10} {r['throughput_pps']:<12} "
                  f"{overhead_s:<10}")
        print()

    # Write summary CSV
    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary_csv = os.path.join(RESULTS_DIR, "benchmark_summary.csv")
    fieldnames = [
        "censor", "pcap_size", "median_us", "mean_us", "stdev_us",
        "min_us", "max_us", "n", "per_packet_us", "throughput_pps",
        "overhead_vs_null",
    ]
    with open(summary_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  CSV:  {summary_csv}")

    # Write summary JSON
    summary_json = os.path.join(RESULTS_DIR, "benchmark_summary.json")
    summary_data = {
        "table": "benchmark_summary",
        "experiment": "07_benchmarks",
        "censors": censors,
        "pcap_sizes": pcap_sizes,
        "rows": rows,
    }
    with open(summary_json, "w") as f:
        json.dump(summary_data, f, indent=2)
    print(f"  JSON: {summary_json}")

    # Print overall highlights
    print()
    print("=" * 96)
    print("HIGHLIGHTS")
    print("=" * 96)

    for censor in censors:
        censor_rows = [r for r in rows if r["censor"] == censor]
        if not censor_rows:
            continue
        # Use the largest PCAP size for the headline throughput
        largest = max(censor_rows, key=lambda r: r["pcap_size"])
        overhead_s = f"{largest['overhead_vs_null']:.3f}x vs null" if largest["overhead_vs_null"] is not None else "baseline"
        print(f"  {censor:>12}: {largest['throughput_pps']:>10} pkt/s  "
              f"({largest['per_packet_us']} us/pkt)  [{overhead_s}]  "
              f"@ {largest['pcap_size']} packets")

    print()
    return True


def main():
    parser = argparse.ArgumentParser(description="Analyze Experiment 7 benchmark results")
    parser.add_argument(
        "--results", type=str, default=None,
        help="Path to benchmark_results.csv (default: results/benchmark_results.csv)",
    )
    args = parser.parse_args()

    if args.results is None:
        args.results = os.path.join(RESULTS_DIR, "benchmark_results.csv")

    success = analyze(args.results)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
