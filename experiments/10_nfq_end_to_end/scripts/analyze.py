#!/usr/bin/env python3
"""analyze.py — tabulate the live NFQ evaluation.

Reads results/<scenario>/<variant>/{live_eval_results.csv,latency.csv,iperf.json}
and writes results/nfq_end_to_end.{csv,json} with, per (scenario, variant):
TPR, TNR, TP/FN/FP/TN, connection-latency median/p95 (ms), iperf3 throughput
(Mbit/s) and retransmits.

Outcome vocabulary of the live generators: 01/03 reset|completed, 02 response
IP (10.10.10.10 = injected, 93.184.216.34 = real), 04 dropped|completed.
"""

import csv
import json
import os
import statistics

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXP_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS = os.path.join(EXP_DIR, "results")
VARIANTS = ["none", "null", "pycl", "censorlang"]
POISON_IP = "10.10.10.10"


def censored(scenario, row):
    """True if the censor intervened on this request."""
    if scenario == "02_dns_injection":
        # PyCL injects (outcome "injected"); CensorLang can only drop the query,
        # which the generator reports as an error/timeout rather than "normal".
        return row.get("outcome") in ("injected",) or row.get("response_ip") in (POISON_IP, "timeout")
    return row.get("outcome") in ("reset", "dropped")


def accuracy(scenario, path):
    if not os.path.exists(path):
        return {}
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    tp = sum(1 for r in rows if r["class"] == "forbidden" and censored(scenario, r))
    fn = sum(1 for r in rows if r["class"] == "forbidden" and not censored(scenario, r))
    fp = sum(1 for r in rows if r["class"] == "allowed" and censored(scenario, r))
    tn = sum(1 for r in rows if r["class"] == "allowed" and not censored(scenario, r))
    err = sum(1 for r in rows if r.get("outcome", "").startswith("error"))
    return {"tpr": round(tp / (tp + fn), 4) if tp + fn else None,
            "tnr": round(tn / (tn + fp), 4) if tn + fp else None,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn, "errors": err, "requests": len(rows)}


def latency(path):
    if not os.path.exists(path):
        return {}
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    ok = sorted(float(r["total_s"]) * 1000 for r in rows if r["outcome"] == "ok")
    if not ok:
        return {"probe_ok": 0, "probe_n": len(rows)}
    return {"probe_ok": len(ok), "probe_n": len(rows),
            "latency_median_ms": round(statistics.median(ok), 3),
            "latency_p95_ms": round(ok[int(len(ok) * 0.95) - 1] if len(ok) >= 20 else ok[-1], 3),
            "latency_stdev_ms": round(statistics.stdev(ok), 3) if len(ok) > 1 else 0.0}


def throughput(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            d = json.load(f)
        return {"throughput_mbps": round(d["end"]["sum_received"]["bits_per_second"] / 1e6, 1),
                "retransmits": d["end"]["sum_sent"].get("retransmits")}
    except (KeyError, json.JSONDecodeError):
        return {}


def main():
    rows = []
    for scenario in sorted(d for d in os.listdir(RESULTS) if os.path.isdir(os.path.join(RESULTS, d))):
        for variant in VARIANTS:
            d = os.path.join(RESULTS, scenario, variant)
            if not os.path.isdir(d):
                continue
            row = {"scenario": scenario, "variant": variant}
            row.update(accuracy(scenario, os.path.join(d, "live_eval_results.csv")))
            row.update(latency(os.path.join(d, "latency.csv")))
            row.update(throughput(os.path.join(d, "iperf.json")))
            rows.append(row)
    if not rows:
        print("no results")
        return
    fields = ["scenario", "variant", "tpr", "tnr", "tp", "fn", "fp", "tn", "errors", "requests",
              "probe_ok", "probe_n", "latency_median_ms", "latency_p95_ms", "latency_stdev_ms",
              "throughput_mbps", "retransmits"]
    with open(os.path.join(RESULTS, "nfq_end_to_end.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(RESULTS, "nfq_end_to_end.json"), "w") as f:
        json.dump({"experiment": "10_nfq_end_to_end", "rows": rows}, f, indent=2)

    def g(r, k, fmt="{}"):
        v = r.get(k)
        return "—" if v is None else fmt.format(v)

    print(f"{'scenario':<20} {'variant':<11} {'TPR':>6} {'TNR':>6} {'lat med ms':>10} {'p95':>7} {'Mbit/s':>8} {'retx':>5}")
    print("-" * 80)
    for r in rows:
        print(f"{r['scenario']:<20} {r['variant']:<11} {g(r,'tpr','{:.3f}'):>6} {g(r,'tnr','{:.3f}'):>6} "
              f"{g(r,'latency_median_ms','{:.2f}'):>10} {g(r,'latency_p95_ms','{:.2f}'):>7} "
              f"{g(r,'throughput_mbps','{:.0f}'):>8} {g(r,'retransmits'):>5}")
    print(f"\nwrote {os.path.join(RESULTS, 'nfq_end_to_end.csv')}")


if __name__ == "__main__":
    main()
