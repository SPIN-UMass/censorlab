#!/usr/bin/env python3
"""Analyze model extraction results: fidelity and reconstructed boundary.

Inputs:
  - results/probe_results.csv  (generate_probes.py)
  - model.onnx                 (the censor's true model, train_model.py)
  - results/model_params.json  (its weights, train_model.py)

Reports:
  - blocked / allowed / error counts
  - fidelity: agreement between each probe's observed outcome and the true
    model's decision for its (len1, len2), evaluated with onnxruntime on the
    same model.onnx CensorLab loaded (P(obfs4) > 0.5 -> blocked)
  - reconstructed boundary: a logistic regression fitted on the observed
    probe outcomes only (what a black-box attacker can do), compared with the
    true boundary: angle between the boundary normals, both lines as
    len2 = slope * len1 + intercept, and the fraction of the
    [1, max_len]^2 length space on which the two classifiers disagree

Outputs: results/extraction_stats.json, results/extraction_stats.csv

Usage:
    python3 analyze.py [--input results/probe_results.csv]
"""

import argparse
import csv
import json
import math
import os
import sys

import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(EXPERIMENT_DIR, "results")


def load_results(path):
    with open(path, newline="") as f:
        return [{"len1": int(r["len1"]), "len2": int(r["len2"]), "outcome": r["outcome"]}
                for r in csv.DictReader(f)]


def onnx_blocked(model_path, X):
    """True model decision per (len1, len2), exactly as CensorLab evaluates it."""
    import onnxruntime as ort
    sess = ort.InferenceSession(model_path)
    p = np.array([sess.run(["probabilities"], {"float_input": x.reshape(1, 2).astype(np.float32)})[0][0, 0]
                  for x in X])
    return p > 0.5


def fit_reconstruction(X, y, seed):
    """Black-box reconstruction: logistic regression on the probe outcomes.
    Returns raw-length (w1, w2, b) with blocked <=> w1*len1 + w2*len2 + b > 0."""
    from sklearn.linear_model import LogisticRegression
    mean, std = X.mean(axis=0), X.std(axis=0)
    clf = LogisticRegression(C=1e4, max_iter=10000, random_state=seed)
    clf.fit((X - mean) / std, y)
    w = clf.coef_[0] / std
    b = float(clf.intercept_[0] - np.sum(clf.coef_[0] * mean / std))
    return float(w[0]), float(w[1]), b


def line(w1, w2, b):
    """Boundary w1*l1 + w2*l2 + b = 0 as l2 = slope*l1 + intercept."""
    if w2 == 0:
        return None, None
    return -w1 / w2, -b / w2


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", default=os.path.join(RESULTS_DIR, "probe_results.csv"))
    parser.add_argument("--model", default=os.path.join(EXPERIMENT_DIR, "model.onnx"))
    parser.add_argument("--params", default=os.path.join(RESULTS_DIR, "model_params.json"))
    parser.add_argument("--max-len", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f"ERROR: {args.input} not found; run scripts/run_docker.sh first")
    results = load_results(args.input)
    with open(args.params) as f:
        params = json.load(f)

    total = len(results)
    valid = [r for r in results if r["outcome"] in ("blocked", "allowed")]
    n_blocked = sum(r["outcome"] == "blocked" for r in valid)
    n_allowed = len(valid) - n_blocked
    n_error = total - len(valid)
    X = np.array([[r["len1"], r["len2"]] for r in valid], dtype=np.float64)
    observed = np.array([r["outcome"] == "blocked" for r in valid])

    # Fidelity against the true model
    predicted = onnx_blocked(args.model, X)
    tw = (params["w1"], params["w2"], params["b"])
    predicted_params = X @ np.array(tw[:2]) + tw[2] > 0
    agree = int((predicted == observed).sum())
    conf = {
        "true_blocked_observed_blocked": int((predicted & observed).sum()),
        "true_blocked_observed_allowed": int((predicted & ~observed).sum()),
        "true_allowed_observed_blocked": int((~predicted & observed).sum()),
        "true_allowed_observed_allowed": int((~predicted & ~observed).sum()),
    }

    # Black-box reconstruction from the observed outcomes
    rw = fit_reconstruction(X, observed.astype(int), args.seed)
    recon_acc_obs = float(((X @ np.array(rw[:2]) + rw[2] > 0) == observed).mean())
    n1, n2 = np.array(tw[:2]), np.array(rw[:2])
    cos = float(n1 @ n2 / (np.linalg.norm(n1) * np.linalg.norm(n2)))
    angle = math.degrees(math.acos(max(-1.0, min(1.0, cos))))
    g = np.arange(1, args.max_len + 1, dtype=np.float64)
    G1, G2 = np.meshgrid(g, g)
    true_grid = tw[0] * G1 + tw[1] * G2 + tw[2] > 0
    recon_grid = rw[0] * G1 + rw[1] * G2 + rw[2] > 0
    t_slope, t_int = line(*tw)
    r_slope, r_int = line(*rw)

    stats = {
        "total_probes": total,
        "blocked": n_blocked,
        "allowed": n_allowed,
        "errors": n_error,
        "blocked_pct": round(100.0 * n_blocked / total, 2) if total else 0.0,
        "allowed_pct": round(100.0 * n_allowed / total, 2) if total else 0.0,
        "error_pct": round(100.0 * n_error / total, 2) if total else 0.0,
        "fidelity_pct": round(100.0 * agree / len(valid), 3) if valid else None,
        "fidelity_agree": agree,
        "fidelity_disagree": len(valid) - agree,
        "params_vs_onnx_mismatches": int((predicted != predicted_params).sum()),
        "true_blocked_space_pct": round(100.0 * true_grid.mean(), 2),
        "true_w1": tw[0], "true_w2": tw[1], "true_b": tw[2],
        "true_slope": t_slope, "true_intercept": t_int,
        "recon_w1": rw[0], "recon_w2": rw[1], "recon_b": rw[2],
        "recon_slope": r_slope, "recon_intercept": r_int,
        "recon_angle_deg": round(angle, 4),
        "recon_accuracy_on_probes_pct": round(100.0 * recon_acc_obs, 3),
        "recon_space_disagreement_pct": round(100.0 * (true_grid != recon_grid).mean(), 4),
        **conf,
    }

    print("=" * 72)
    print("EXPERIMENT 6: Model Extraction")
    print("=" * 72)
    print(f"  Probes: {total}  blocked {n_blocked} ({stats['blocked_pct']}%)  "
          f"allowed {n_allowed} ({stats['allowed_pct']}%)  errors {n_error}")
    print(f"  Fidelity vs true model: {agree}/{len(valid)} = {stats['fidelity_pct']}%")
    print(f"  Confusion: {conf}")
    print(f"  True boundary:          len2 = {t_slope:.5f}*len1 + {t_int:.2f}")
    print(f"  Reconstructed boundary: len2 = {r_slope:.5f}*len1 + {r_int:.2f}")
    print(f"  Normal angle {angle:.3f} deg; length-space disagreement "
          f"{stats['recon_space_disagreement_pct']}%")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(os.path.join(RESULTS_DIR, "extraction_stats.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(stats.keys()))
        writer.writeheader()
        writer.writerow(stats)
    with open(os.path.join(RESULTS_DIR, "extraction_stats.json"), "w") as f:
        json.dump({"experiment": "06_model_extraction", "stats": stats}, f, indent=2)
        f.write("\n")
    print(f"  Wrote {RESULTS_DIR}/extraction_stats.{{json,csv}}")


if __name__ == "__main__":
    main()
