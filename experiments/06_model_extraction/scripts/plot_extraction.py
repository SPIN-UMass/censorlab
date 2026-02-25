#!/usr/bin/env python3
"""Plot model extraction results showing reconstructed decision boundary.

Reads probe_results.csv and creates a scatter plot:
- Blue dots: allowed connections
- Red dots: blocked connections
- Decision boundary visible as the separation between regions

The plot demonstrates that an attacker can reconstruct the censor's
internal model boundary by observing which packet-length pairs get
blocked vs allowed.

Output: results/model_extraction.pdf

Usage:
    python3 plot_extraction.py --input results/probe_results.csv
    python3 plot_extraction.py --input results/probe_results.csv --output results/model_extraction.pdf
"""

import argparse
import csv
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


def main():
    parser = argparse.ArgumentParser(
        description="Plot model extraction scatter plot"
    )
    parser.add_argument(
        "--input", type=str, default=None,
        help="Input CSV path (default: results/probe_results.csv)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output plot path (default: results/model_extraction.pdf)",
    )
    args = parser.parse_args()

    input_path = args.input or os.path.join(RESULTS_DIR, "probe_results.csv")
    output_path = args.output or os.path.join(RESULTS_DIR, "model_extraction.pdf")

    if not os.path.exists(input_path):
        print(f"ERROR: Input file not found: {input_path}")
        print("Run generate_probes.py first.")
        sys.exit(1)

    # Try importing matplotlib
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("ERROR: matplotlib and numpy required. Install with:")
        print("  pip install matplotlib numpy")
        sys.exit(1)

    # Load results
    results = load_results(input_path)
    total = len(results)
    print(f"Loaded {total} probe results from {input_path}")

    # Separate by outcome
    allowed = [(r["len1"], r["len2"]) for r in results if r["outcome"] == "allowed"]
    blocked = [(r["len1"], r["len2"]) for r in results if r["outcome"] == "blocked"]
    errors = [(r["len1"], r["len2"]) for r in results if r["outcome"] == "error"]

    print(f"  Allowed: {len(allowed)}")
    print(f"  Blocked: {len(blocked)}")
    print(f"  Errors:  {len(errors)} (excluded from plot)")

    # Plot
    fig, ax = plt.subplots(1, 1, figsize=(6, 5))

    if allowed:
        ax.scatter(
            [a[0] for a in allowed], [a[1] for a in allowed],
            c="blue", alpha=0.3, s=2, label=f"Allowed ({len(allowed)})",
            rasterized=True,
        )
    if blocked:
        ax.scatter(
            [b[0] for b in blocked], [b[1] for b in blocked],
            c="red", alpha=0.3, s=2, label=f"Blocked ({len(blocked)})",
            rasterized=True,
        )

    ax.set_xlabel("First packet length (bytes)")
    ax.set_ylabel("Second packet length (bytes)")
    ax.set_title("Model Extraction: Reconstructed Decision Boundary")
    ax.legend(loc="upper right", markerscale=5)

    # Set axis limits
    max_len = max(
        max((r["len1"] for r in results), default=1500),
        max((r["len2"] for r in results), default=1500),
    )
    ax.set_xlim(0, max_len + 50)
    ax.set_ylim(0, max_len + 50)

    fig.tight_layout()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig.savefig(output_path, dpi=150)
    print(f"Saved plot to {output_path}")

    # Also save a PNG version for quick viewing
    png_path = output_path.replace(".pdf", ".png")
    if png_path != output_path:
        fig.savefig(png_path, dpi=150)
        print(f"Saved PNG to {png_path}")

    plt.close(fig)


if __name__ == "__main__":
    main()
