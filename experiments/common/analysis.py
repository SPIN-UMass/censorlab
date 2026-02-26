"""Shared analysis utilities for CensorLab experiments.

Provides timing parsing, LOC counting, and TPR/TNR computation for the
PoPETs evaluation tables.
"""

import csv
import os
import re
import subprocess


def count_loc(filepath):
    """Count non-blank, non-comment lines of code.

    Handles Python (#), Zeek (##!/#), CensorLang (#), and TOML (#) comments.
    """
    if not os.path.exists(filepath):
        return 0
    count = 0
    with open(filepath) as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("##!"):
                count += 1
    return count


def parse_timing_file(path):
    """Parse a timing file containing a single float (seconds)."""
    with open(path) as f:
        return float(f.read().strip())


def parse_censorlab_timing_us(output_text):
    """Parse CensorLab PCAP mode timing from its stdout/stderr.

    CensorLab prints: "Pcap mode took <N>us to process the file (<M>us including I/O)"
    Returns elapsed microseconds including I/O (int) or None if not found.
    """
    match = re.search(r"\((\d+)us including I/O\)", output_text)
    if match:
        return int(match.group(1))
    return None


def load_labels(labels_csv):
    """Load ground truth labels from CSV.

    Returns list of dicts with keys: index, keyword, class.
    """
    with open(labels_csv) as f:
        return list(csv.DictReader(f))


def load_decisions(decisions_csv):
    """Load tool decisions from CSV.

    Returns list of dicts with keys: index, action.
    """
    with open(decisions_csv) as f:
        return list(csv.DictReader(f))


def compute_tpr_tnr(labels, decisions, positive_actions=("reset",)):
    """Compute TPR and TNR from labels and decisions.

    Labels: list of {index, keyword, class} where class is 'forbidden' or 'allowed'.
    Decisions: list of {index, action} where action indicates censor intervention.
    positive_actions: tuple of action strings that count as "blocked" (default: ("reset",)).
                      For DNS injection experiments, use ("inject",).
                      For drop experiments, use ("drop",).

    Returns (tpr, tnr, tp, fn, tn, fp).
    """
    label_map = {int(l["index"]): l["class"] for l in labels}
    decision_map = {int(d["index"]): d["action"] for d in decisions}

    tp = fn = tn = fp = 0
    for idx, cls in label_map.items():
        action = decision_map.get(idx, "allow")
        blocked = action in positive_actions
        if cls == "forbidden":
            if blocked:
                tp += 1
            else:
                fn += 1
        else:  # allowed
            if blocked:
                fp += 1
            else:
                tn += 1

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    return tpr, tnr, tp, fn, tn, fp


def format_table_row(tool, timing_s, loc, tpr=None, tnr=None, note=""):
    """Format a single row for the results tables."""
    tpr_str = f"{tpr:.3f}" if tpr is not None else "N/A"
    tnr_str = f"{tnr:.3f}" if tnr is not None else "N/A"
    timing_str = f"{timing_s:.4f}" if timing_s is not None else "N/A"
    return {
        "tool": tool,
        "timing_s": timing_str,
        "loc": str(loc),
        "tpr": tpr_str,
        "tnr": tnr_str,
        "note": note,
    }
