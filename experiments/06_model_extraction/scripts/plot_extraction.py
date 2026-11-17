#!/usr/bin/env python3
"""Plot model extraction results over the model's true decision boundary.

Background: the censor model's true decision regions, computed from its
weights (results/model_params.json, written by train_model.py): light red
where P(obfs4) > 0.5 (blocked), light blue elsewhere.  Dots: probe outcomes
observed through CensorLab (red blocked, blue allowed; errors as black x).
Lines: the true boundary (solid) and, if results/extraction_stats.json
exists, the boundary reconstructed from the probes alone (dashed).

Output: results/model_extraction.pdf (+ .png)

Usage:
    python3 plot_extraction.py [--input results/probe_results.csv]
"""

import argparse
import csv
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap
from matplotlib.lines import Line2D

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(EXPERIMENT_DIR, "results")

RED, BLUE = "#c62828", "#1565c0"
RED_BG, BLUE_BG = "#f6d5d5", "#d6e4f5"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", default=os.path.join(RESULTS_DIR, "probe_results.csv"))
    parser.add_argument("--params", default=os.path.join(RESULTS_DIR, "model_params.json"))
    parser.add_argument("--stats", default=os.path.join(RESULTS_DIR, "extraction_stats.json"))
    parser.add_argument("--output", default=os.path.join(RESULTS_DIR, "model_extraction.pdf"))
    parser.add_argument("--max-len", type=int, default=1500)
    args = parser.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f"ERROR: {args.input} not found")
    with open(args.input, newline="") as f:
        rows = list(csv.DictReader(f))
    with open(args.params) as f:
        p = json.load(f)
    recon = None
    if os.path.exists(args.stats):
        with open(args.stats) as f:
            s = json.load(f)["stats"]
        recon = (s["recon_w1"], s["recon_w2"], s["recon_b"])

    lim = args.max_len + 1
    g = np.linspace(0, lim, 601)
    G1, G2 = np.meshgrid(g, g)
    true_blocked = p["w1"] * G1 + p["w2"] * G2 + p["b"] > 0

    fig, ax = plt.subplots(figsize=(4.5, 4.0))
    ax.pcolormesh(G1, G2, true_blocked.astype(int), cmap=ListedColormap([BLUE_BG, RED_BG]),
                  shading="auto", rasterized=True, zorder=0)

    def pts(outcome):
        sel = [r for r in rows if r["outcome"] == outcome]
        return [int(r["len1"]) for r in sel], [int(r["len2"]) for r in sel]

    for outcome, color in (("allowed", BLUE), ("blocked", RED)):
        x, y = pts(outcome)
        ax.scatter(x, y, s=1.5, c=color, linewidths=0, rasterized=True, zorder=2)
    ex, ey = pts("error")
    if ex:
        ax.scatter(ex, ey, s=12, c="black", marker="x", linewidths=0.8, zorder=3)

    x = np.array([0, lim])
    ax.plot(x, -(p["w1"] * x + p["b"]) / p["w2"], color="black", lw=1.2, zorder=4)
    if recon is not None:
        ax.plot(x, -(recon[0] * x + recon[2]) / recon[1], color="black", lw=1.2,
                ls=(0, (4, 3)), zorder=4)

    handles = [
        Line2D([], [], ls="", marker="o", ms=4, color=RED, label=f"Blocked probe ({len(pts('blocked')[0])})"),
        Line2D([], [], ls="", marker="o", ms=4, color=BLUE, label=f"Allowed probe ({len(pts('allowed')[0])})"),
        Line2D([], [], color="black", lw=1.2, label="True boundary"),
    ]
    if recon is not None:
        handles.append(Line2D([], [], color="black", lw=1.2, ls=(0, (4, 3)), label="Reconstructed"))
    if ex:
        handles.append(Line2D([], [], ls="", marker="x", color="black", label=f"Error ({len(ex)})"))
    ax.legend(handles=handles, loc="lower right", fontsize=7, framealpha=0.9)
    ax.set_xlim(0, lim)
    ax.set_ylim(0, lim)
    ax.set_xlabel("First data packet length (bytes)")
    ax.set_ylabel("Second data packet length (bytes)")
    fig.tight_layout()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    fig.savefig(args.output, dpi=300)
    png = os.path.splitext(args.output)[0] + ".png"
    fig.savefig(png, dpi=150)
    print(f"Saved {args.output} and {png}")


if __name__ == "__main__":
    main()
