#!/usr/bin/env python3
"""Analyze model extraction experiment results.

Reads probe_results.csv and computes basic statistics about the
extraction attack:
  - Total probes sent
  - Blocked / allowed / error counts and percentages
  - Estimated decision boundary characteristics
  - Coverage of the (len1, len2) space

Outputs:
  - results/extraction_stats.csv  — summary statistics
  - results/extraction_stats.json — summary as JSON

Usage:
    python3 analyze.py --input results/probe_results.csv
"""

import argparse
import csv
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(EXPERIMENT_DIR, "results")


def load_results(path):
    """Load probe results from CSV."""
    results = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                "len1": int(row["len1"]),
                "len2": int(row["len2"]),
                "outcome": row["outcome"],
            })
    return results


def compute_stats(results):
    """Compute summary statistics from probe results."""
    total = len(results)
    blocked = [r for r in results if r["outcome"] == "blocked"]
    allowed = [r for r in results if r["outcome"] == "allowed"]
    errors = [r for r in results if r["outcome"] == "error"]

    stats = {
        "total_probes": total,
        "blocked": len(blocked),
        "allowed": len(allowed),
        "errors": len(errors),
        "blocked_pct": round(100.0 * len(blocked) / total, 2) if total > 0 else 0,
        "allowed_pct": round(100.0 * len(allowed) / total, 2) if total > 0 else 0,
        "error_pct": round(100.0 * len(errors) / total, 2) if total > 0 else 0,
    }

    # Compute mean packet lengths for each class
    if blocked:
        stats["blocked_mean_len1"] = round(
            sum(r["len1"] for r in blocked) / len(blocked), 1
        )
        stats["blocked_mean_len2"] = round(
            sum(r["len2"] for r in blocked) / len(blocked), 1
        )
    else:
        stats["blocked_mean_len1"] = None
        stats["blocked_mean_len2"] = None

    if allowed:
        stats["allowed_mean_len1"] = round(
            sum(r["len1"] for r in allowed) / len(allowed), 1
        )
        stats["allowed_mean_len2"] = round(
            sum(r["len2"] for r in allowed) / len(allowed), 1
        )
    else:
        stats["allowed_mean_len1"] = None
        stats["allowed_mean_len2"] = None

    # Estimate boundary region: find probes near the boundary
    # by looking at nearby probes with different outcomes
    # (This is a rough heuristic — the plot is the real output)
    valid = [r for r in results if r["outcome"] in ("blocked", "allowed")]
    if valid:
        max_len1 = max(r["len1"] for r in valid)
        max_len2 = max(r["len2"] for r in valid)
        min_len1 = min(r["len1"] for r in valid)
        min_len2 = min(r["len2"] for r in valid)
        stats["len1_range"] = f"{min_len1}-{max_len1}"
        stats["len2_range"] = f"{min_len2}-{max_len2}"
    else:
        stats["len1_range"] = "N/A"
        stats["len2_range"] = "N/A"

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Analyze model extraction experiment results"
    )
    parser.add_argument(
        "--input", type=str, default=None,
        help="Input CSV path (default: results/probe_results.csv)",
    )
    args = parser.parse_args()

    input_path = args.input or os.path.join(RESULTS_DIR, "probe_results.csv")

    if not os.path.exists(input_path):
        print(f"ERROR: Results file not found: {input_path}")
        print("Run generate_probes.py first, or run the full experiment:")
        print("  bash experiments/06_model_extraction/scripts/run_extraction.sh")
        sys.exit(1)

    results = load_results(input_path)
    stats = compute_stats(results)

    # Print summary
    print("=" * 72)
    print("EXPERIMENT 6: Model Extraction — Statistics")
    print("=" * 72)
    print()
    print(f"  Total probes:    {stats['total_probes']}")
    print(f"  Blocked:         {stats['blocked']} ({stats['blocked_pct']}%)")
    print(f"  Allowed:         {stats['allowed']} ({stats['allowed_pct']}%)")
    print(f"  Errors:          {stats['errors']} ({stats['error_pct']}%)")
    print()

    if stats["blocked_mean_len1"] is not None:
        print(f"  Blocked mean lengths:  len1={stats['blocked_mean_len1']}, "
              f"len2={stats['blocked_mean_len2']}")
    if stats["allowed_mean_len1"] is not None:
        print(f"  Allowed mean lengths:  len1={stats['allowed_mean_len1']}, "
              f"len2={stats['allowed_mean_len2']}")
    print(f"  len1 range:      {stats['len1_range']}")
    print(f"  len2 range:      {stats['len2_range']}")
    print()

    # Write CSV
    stats_csv = os.path.join(RESULTS_DIR, "extraction_stats.csv")
    with open(stats_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(stats.keys()))
        writer.writeheader()
        writer.writerow(stats)
    print(f"  CSV:  {stats_csv}")

    # Write JSON
    stats_json = os.path.join(RESULTS_DIR, "extraction_stats.json")
    with open(stats_json, "w") as f:
        json.dump(
            {"experiment": "06_model_extraction", "stats": stats},
            f, indent=2,
        )
    print(f"  JSON: {stats_json}")
    print()


if __name__ == "__main__":
    main()
