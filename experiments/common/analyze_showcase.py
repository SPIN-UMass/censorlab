#!/usr/bin/env python3
"""analyze_showcase.py — turn one scenario's raw showcase measurements into Table 4 data.

Reads <scenario>/results/{raw_timings.csv,loc.csv,tools.csv} written by
common/showcase.sh and writes:

    results/table4.csv / table4.json   one row per tool:
        time_us      legacy metric (tool-internal where available) — median
        wall_us      process wall-clock — median / mean / stdev / min / max
        startup_us   median wall-clock on the one-frame baseline PCAP
        net_us       wall_us − startup_us   (steady-state processing)
        cpu_us       user+sys CPU — median
        max_rss_kb   peak RSS — median
        n            measured iterations
        loc          lines of code of the censor program / rules
        status       measured | unavailable | not-expressible
        note         scenario-specific caveat

Then runs report.py over the kept native outputs to produce accuracy.json /
table3.json (TPR/TNR per tool).

Usage:
    python3 experiments/common/analyze_showcase.py <scenario_dir> [--results DIR] [--pcap PCAP] [--no-accuracy]
"""

import argparse
import csv
import json
import os
import statistics
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from scenario import TOOLS, load_scenario, tool_enabled, tool_note  # noqa: E402


def load_raw(path):
    """-> {tool: {phase: [row, ...]}} with numeric fields converted."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                rec = {k: int(row[k]) for k in
                       ("time_us", "wall_us", "user_us", "sys_us", "max_rss_kb", "exit_code")
                       if k in row and row[k] != ""}
            except ValueError:
                continue
            # Legacy files only have tool,iteration,time_us
            rec.setdefault("wall_us", rec.get("time_us"))
            phase = row.get("phase", "measure")
            out.setdefault(row["tool"], {}).setdefault(phase, []).append(rec)
    return out


def load_loc(path):
    loc = {}
    if os.path.exists(path):
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                loc[row["tool"]] = {"file": row["file"], "loc": int(row["loc"])}
    return loc


def load_tools(path):
    status = {}
    if os.path.exists(path):
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                status[row["tool"]] = row["status"]
    return status


def med(values):
    return statistics.median(values) if values else None


def stats(values):
    if not values:
        return {"median": None, "mean": None, "stdev": None, "min": None, "max": None}
    return {
        "median": statistics.median(values),
        "mean": round(statistics.mean(values), 1),
        "stdev": round(statistics.stdev(values), 1) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def analyze(scenario_dir, results_dir=None, pcap=None, accuracy=True):
    sc = load_scenario(scenario_dir)
    results = results_dir or os.path.join(sc["DIR"], "results")
    raw = load_raw(os.path.join(results, "raw_timings.csv"))
    loc = load_loc(os.path.join(results, "loc.csv"))
    status = load_tools(os.path.join(results, "tools.csv"))

    rows = []
    for tool in TOOLS:
        measured = [r for r in raw.get(tool, {}).get("measure", []) if r.get("exit_code", 0) == 0]
        baseline = [r for r in raw.get(tool, {}).get("baseline", []) if r.get("exit_code", 0) == 0]
        failed = [r for r in raw.get(tool, {}).get("measure", []) if r.get("exit_code", 0) != 0]

        if not measured and not tool_enabled(sc, tool) and tool not in loc:
            continue  # tool plays no role in this scenario at all

        wall = stats([r["wall_us"] for r in measured])
        legacy = stats([r["time_us"] for r in measured])
        cpu = med([r["user_us"] + r["sys_us"] for r in measured if "user_us" in r])
        rss = med([r["max_rss_kb"] for r in measured if "max_rss_kb" in r])
        startup = med([r["wall_us"] for r in baseline])
        net = (wall["median"] - startup) if (wall["median"] is not None and startup is not None) else None

        st = status.get(tool)
        if st is None:
            st = "measured" if measured else ("not-expressible" if not tool_enabled(sc, tool) else "unavailable")

        rows.append({
            "tool": tool,
            # legacy columns (kept for aggregate_results.py compatibility)
            "median_us": legacy["median"],
            "mean_us": legacy["mean"],
            "stdev_us": legacy["stdev"],
            "min_us": legacy["min"],
            "max_us": legacy["max"],
            # consistent cross-tool columns
            "wall_median_us": wall["median"],
            "wall_mean_us": wall["mean"],
            "wall_stdev_us": wall["stdev"],
            "wall_min_us": wall["min"],
            "wall_max_us": wall["max"],
            "startup_us": startup,
            "net_us": net,
            "cpu_us": cpu,
            "max_rss_kb": rss,
            "n": len(measured),
            "failed_runs": len(failed),
            "loc": loc.get(tool, {}).get("loc"),
            "status": st,
            "note": tool_note(sc, tool),
        })

    # ---- print ------------------------------------------------------------
    print("=" * 100)
    print(f"TABLE 4 — {sc['ID']}: {sc['NAME']}")
    print("=" * 100)
    print(f"{'Tool':<11} {'status':<15} {'legacy(us)':>11} {'wall(us)':>10} {'±sd':>8} "
          f"{'startup':>9} {'net(us)':>9} {'cpu(us)':>9} {'rss(KB)':>8} {'n':>3} {'LOC':>5}  note")
    print("-" * 100)

    def fmt(v, w):
        return f"{'—':>{w}}" if v is None else f"{int(v):>{w}}"

    for r in rows:
        print(f"{r['tool']:<11} {r['status']:<15} {fmt(r['median_us'], 11)} {fmt(r['wall_median_us'], 10)} "
              f"{fmt(r['wall_stdev_us'], 8)} {fmt(r['startup_us'], 9)} {fmt(r['net_us'], 9)} "
              f"{fmt(r['cpu_us'], 9)} {fmt(r['max_rss_kb'], 8)} {r['n']:>3} {fmt(r['loc'], 5)}  {r['note']}")
    print()

    # ---- write ------------------------------------------------------------
    os.makedirs(results, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else ["tool"]
    with open(os.path.join(results, "table4.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(results, "table4.json"), "w") as f:
        json.dump({"table": "table4", "experiment": sc["ID"], "macro": sc["MACRO"], "rows": rows}, f, indent=2)
    print(f"  wrote {os.path.join(results, 'table4.csv')}")
    print(f"  wrote {os.path.join(results, 'table4.json')}")

    if accuracy:
        from report import report_scenario
        print()
        print("Accuracy against ground truth (PCAP mode):")
        report_scenario(sc["DIR"], pcap_override=pcap, results_dir=results)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario_dir")
    ap.add_argument("--results", default=None)
    ap.add_argument("--pcap", default=None, help="PCAP the runs used (default: scenario PCAP)")
    ap.add_argument("--no-accuracy", action="store_true")
    args = ap.parse_args()
    analyze(args.scenario_dir, args.results, args.pcap, accuracy=not args.no_accuracy)


if __name__ == "__main__":
    main()
