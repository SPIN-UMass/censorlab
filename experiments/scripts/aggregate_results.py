#!/usr/bin/env python3
"""Aggregate results from all experiments and output LaTeX macros.

Reads table4.json and table3.json from each experiment's results/ directory,
then writes a results.tex file with \\newcommand macros that can be
\\input{} in the paper.

Usage:
    python3 experiments/scripts/aggregate_results.py [--output PATH]

Default output: ../clab-paper/experiments/results.tex (relative to this script)
"""

import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENTS_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, "..", "..", "..", "clab-paper", "experiments", "results.tex")

# Mapping from experiment directory to paper scenario names
EXPERIMENT_SCENARIOS = {
    "01_http_keyword": "HttpKeyword",
    "02_dns_injection": "DnsInjection",
    "03_tls_sni": "SniFiltering",
    "04_shadowsocks": "Shadowsocks",
    "05_ml_classification": "MlClassification",
    "06_model_extraction": "ModelExtraction",
    "07_benchmarks": "Benchmarks",
}

# Tool name mapping for LaTeX command names (no special chars)
TOOL_NAMES = {
    "PyCL": "PyCL",
    "CensorLang": "CL",
    "Zeek": "Zeek",
    "Scapy": "Scapy",
}

# Table 3 protocol columns by experiment
# Each experiment maps to (column_name, censor_name) for Table 3
TABLE3_COLUMNS = {
    "01_http_keyword": ("HTTP", "HttpKeyword"),
    "02_dns_injection": ("DNS", "DnsInjection"),
    "03_tls_sni": [("HTTPS", "SniFilteringHttps"), ("Tor", "SniFilteringTor")],
    "04_shadowsocks": [("Shadowsocks", "GfwShadowsocks"), ("Obfs4", "GfwObfsfour")],
}


def sanitize_cmd(name):
    """Make a string safe for use as a LaTeX command name (letters only)."""
    return "".join(c for c in name if c.isalpha())


def format_time_s(us_value):
    """Convert microseconds to seconds, formatted with appropriate precision."""
    if us_value is None:
        return None
    secs = us_value / 1_000_000
    if secs >= 100:
        return f"{secs:.1f}"
    elif secs >= 1:
        return f"{secs:.2f}"
    else:
        return f"{secs:.4f}"


def format_time_ms(us_value):
    """Convert microseconds to milliseconds, formatted to 1 decimal place."""
    if us_value is None:
        return None
    return f"{us_value / 1_000:.1f}"


def load_json(path):
    """Load a JSON file, returning None if it doesn't exist."""
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def collect_table4(experiments_dir):
    """Collect Table 4 data from all experiments.

    Returns dict of {(scenario, tool): {median_us, loc}} entries.
    """
    data = {}
    for exp_dir, scenario in EXPERIMENT_SCENARIOS.items():
        if scenario in ("ModelExtraction", "Benchmarks"):
            continue  # These don't contribute to Table 4

        json_path = os.path.join(experiments_dir, exp_dir, "results", "table4.json")
        table4 = load_json(json_path)
        if table4 is None:
            print(f"  [SKIP] {exp_dir}: no results/table4.json", file=sys.stderr)
            continue

        for row in table4.get("rows", []):
            tool = row["tool"]
            data[(scenario, tool)] = {
                "median_us": row.get("median_us"),
                "loc": row.get("loc"),
            }
        print(f"  [OK]   {exp_dir}: Table 4 loaded", file=sys.stderr)

    return data


def collect_table3(experiments_dir):
    """Collect Table 3 data from all experiments.

    Returns dict of {column_name: {accuracy, tpr, tnr}} entries.
    """
    data = {}
    for exp_dir, mapping in TABLE3_COLUMNS.items():
        json_path = os.path.join(experiments_dir, exp_dir, "results", "table3.json")
        table3 = load_json(json_path)
        if table3 is None:
            print(f"  [SKIP] {exp_dir}: no results/table3.json", file=sys.stderr)
            continue

        # Normalize mapping to list of tuples
        if isinstance(mapping, tuple):
            mappings = [mapping]
        else:
            mappings = mapping

        rows = table3.get("rows", [])
        # Use PyCL row (primary tool) for Table 3 accuracy
        pycl_row = next((r for r in rows if r["tool"] == "PyCL"), None)
        if pycl_row is None and rows:
            pycl_row = rows[0]

        if pycl_row:
            for col_name, cmd_name in mappings:
                tpr = pycl_row.get("tpr")
                tnr = pycl_row.get("tnr")
                if tpr is not None and tnr is not None:
                    accuracy = round((float(tpr) + float(tnr)) / 2, 4)
                else:
                    accuracy = None
                data[cmd_name] = {
                    "col_name": col_name,
                    "tpr": tpr,
                    "tnr": tnr,
                    "accuracy": accuracy,
                }
            print(f"  [OK]   {exp_dir}: Table 3 loaded", file=sys.stderr)
        else:
            print(f"  [SKIP] {exp_dir}: no PyCL row in table3.json", file=sys.stderr)

    return data


def collect_benchmarks(experiments_dir):
    """Collect benchmark data from experiment 7.

    Returns dict of {(censor, pcap_size): {median_us, per_packet_us, throughput_pps, overhead}} entries.
    """
    json_path = os.path.join(experiments_dir, "07_benchmarks", "results", "benchmark_summary.json")
    summary = load_json(json_path)
    if summary is None:
        print("  [SKIP] 07_benchmarks: no results/benchmark_summary.json", file=sys.stderr)
        return {}

    data = {}
    for row in summary.get("rows", []):
        key = (row["censor"], row["pcap_size"])
        data[key] = {
            "median_us": row.get("median_us"),
            "per_packet_us": row.get("per_packet_us"),
            "throughput_pps": row.get("throughput_pps"),
            "overhead_vs_null": row.get("overhead_vs_null"),
        }
    print("  [OK]   07_benchmarks: benchmark summary loaded", file=sys.stderr)
    return data


def generate_latex_macros(table4, table3, benchmarks):
    """Generate LaTeX \\newcommand macros from collected data."""
    lines = []
    lines.append("% Auto-generated by experiments/scripts/aggregate_results.py")
    lines.append("% Do not edit manually — rerun the script to update.")
    lines.append("")

    # --- Table 4: Timing and LOC ---
    lines.append("% ============================================================")
    lines.append("% Table 4: PCAP-Mode Timing (seconds) & Lines of Code")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Result<Scenario><Tool><Metric>")
    lines.append("% Metrics: Time (seconds), Loc (lines of code)")
    lines.append("")

    # Scenarios in table order
    table4_scenarios = ["SniFiltering", "Shadowsocks", "DnsInjection", "MlClassification"]
    table4_tools = ["PyCL", "CensorLang", "Zeek", "Scapy"]

    for scenario in table4_scenarios:
        lines.append(f"% {scenario}")
        for tool in table4_tools:
            tool_cmd = TOOL_NAMES[tool]
            key = (scenario, tool)
            entry = table4.get(key)

            cmd_base = f"Result{sanitize_cmd(scenario)}{sanitize_cmd(tool_cmd)}"

            if entry and entry["median_us"] is not None:
                time_s = format_time_s(entry["median_us"])
                lines.append(f"\\newcommand{{\\{cmd_base}Time}}{{{time_s}}}")
            else:
                lines.append(f"\\newcommand{{\\{cmd_base}Time}}{{N/A}}")

            if entry and entry["loc"] is not None:
                lines.append(f"\\newcommand{{\\{cmd_base}Loc}}{{{entry['loc']}}}")
            else:
                lines.append(f"\\newcommand{{\\{cmd_base}Loc}}{{N/A}}")

        lines.append("")

    # --- Table 3: Accuracy (TPR+TNR averaged) ---
    lines.append("% ============================================================")
    lines.append("% Table 3: Evaluation Accuracy (avg of TPR and TNR)")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Result<Censor>Accuracy")
    lines.append("% Also: \\Result<Censor>TPR, \\Result<Censor>TNR")
    lines.append("")

    table3_order = ["HttpKeyword", "DnsInjection", "SniFilteringHttps",
                    "SniFilteringTor", "GfwShadowsocks", "GfwObfsfour"]

    for cmd_name in table3_order:
        entry = table3.get(cmd_name)
        cmd_safe = sanitize_cmd(cmd_name)

        if entry and entry["accuracy"] is not None:
            lines.append(f"\\newcommand{{\\Result{cmd_safe}Accuracy}}{{{entry['accuracy']}}}")
            lines.append(f"\\newcommand{{\\Result{cmd_safe}TPR}}{{{entry['tpr']}}}")
            lines.append(f"\\newcommand{{\\Result{cmd_safe}TNR}}{{{entry['tnr']}}}")
        else:
            lines.append(f"\\newcommand{{\\Result{cmd_safe}Accuracy}}{{---}}")
            lines.append(f"\\newcommand{{\\Result{cmd_safe}TPR}}{{---}}")
            lines.append(f"\\newcommand{{\\Result{cmd_safe}TNR}}{{---}}")

    lines.append("")

    # --- Benchmarks ---
    if benchmarks:
        lines.append("% ============================================================")
        lines.append("% Experiment 7: Throughput/Latency Benchmarks")
        lines.append("% ============================================================")
        lines.append("% Command format: \\Bench<Censor><SizeName><Metric>")
        lines.append("% Metrics: MedianUs, PerPktUs, ThroughputPps, Overhead")
        lines.append("")

        censor_names = {"null": "Null", "sni_filter": "SniFilter", "entropy": "Entropy"}
        size_names = {1000: "OneK", 5000: "FiveK", 10000: "TenK", 50000: "FiftyK"}
        sizes = sorted(set(s for _, s in benchmarks.keys()))

        for (censor, size), entry in sorted(benchmarks.items()):
            censor_cmd = censor_names.get(censor, sanitize_cmd(censor))
            size_cmd = size_names.get(size, f"N{size}")
            cmd_base = f"Bench{censor_cmd}{size_cmd}"

            if entry["median_us"] is not None:
                lines.append(f"\\newcommand{{\\{cmd_base}MedianUs}}{{{entry['median_us']}}}")
            if entry["per_packet_us"] is not None:
                lines.append(f"\\newcommand{{\\{cmd_base}PerPktUs}}{{{entry['per_packet_us']}}}")
            if entry["throughput_pps"] is not None:
                lines.append(f"\\newcommand{{\\{cmd_base}ThroughputPps}}{{{entry['throughput_pps']}}}")
            if entry["overhead_vs_null"] is not None:
                lines.append(f"\\newcommand{{\\{cmd_base}Overhead}}{{{entry['overhead_vs_null']}}}")

        lines.append("")

    # --- Comparison percentages ---
    lines.append("% ============================================================")
    lines.append("% Comparison Percentages (for introduction / showcase text)")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Comp<Scenario><Tool>Vs<Baseline><Metric>")
    lines.append("% Formula: round((baseline - censorlab) / baseline * 100)")
    lines.append("")

    COMPARISONS = [
        ("Shadowsocks", "PyCL", "Zeek"),
        ("SniFiltering", "PyCL", "Zeek"),
        ("MlClassification", "PyCL", "Scapy"),
    ]

    for scenario, tool, baseline in COMPARISONS:
        tool_cmd = TOOL_NAMES[tool]
        baseline_cmd = TOOL_NAMES[baseline]
        tool_key = (scenario, tool)
        baseline_key = (scenario, baseline)
        tool_entry = table4.get(tool_key)
        baseline_entry = table4.get(baseline_key)

        for metric, extract in [("Loc", "loc"), ("Time", "median_us")]:
            cmd_name = f"Comp{sanitize_cmd(scenario)}{sanitize_cmd(tool_cmd)}Vs{sanitize_cmd(baseline_cmd)}{metric}"
            tool_val = tool_entry.get(extract) if tool_entry else None
            base_val = baseline_entry.get(extract) if baseline_entry else None

            if tool_val is not None and base_val is not None and base_val != 0:
                pct = round((base_val - tool_val) / base_val * 100)
                lines.append(f"\\newcommand{{\\{cmd_name}}}{{{pct}}}")
            else:
                lines.append(f"\\newcommand{{\\{cmd_name}}}{{N/A}}")

    lines.append("")
    lines.append("% End of auto-generated results")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate experiment results into LaTeX macros"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output path for results.tex (default: ../clab-paper/results.tex)",
    )
    parser.add_argument(
        "--experiments-dir",
        type=str,
        default=EXPERIMENTS_DIR,
        help="Path to experiments/ directory",
    )
    args = parser.parse_args()

    output_path = args.output or os.path.normpath(DEFAULT_OUTPUT)

    print(f"Aggregating results from: {args.experiments_dir}", file=sys.stderr)
    print(f"Output: {output_path}", file=sys.stderr)
    print(file=sys.stderr)

    # Collect data
    print("Collecting Table 4 (showcase timing + LOC):", file=sys.stderr)
    table4 = collect_table4(args.experiments_dir)

    print(file=sys.stderr)
    print("Collecting Table 3 (evaluation accuracy):", file=sys.stderr)
    table3 = collect_table3(args.experiments_dir)

    print(file=sys.stderr)
    print("Collecting benchmarks:", file=sys.stderr)
    benchmarks = collect_benchmarks(args.experiments_dir)

    # Generate LaTeX
    latex = generate_latex_macros(table4, table3, benchmarks)

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(latex)

    print(file=sys.stderr)
    print(f"Wrote {output_path}", file=sys.stderr)

    # Print summary
    t4_count = sum(1 for k, v in table4.items() if v.get("median_us") is not None)
    t3_count = sum(1 for k, v in table3.items() if v.get("accuracy") is not None)
    b_count = len(benchmarks)
    print(f"  Table 4 entries: {t4_count}", file=sys.stderr)
    print(f"  Table 3 entries: {t3_count}", file=sys.stderr)
    print(f"  Benchmark entries: {b_count}", file=sys.stderr)

    # Also print the macros to stdout for review
    print(latex)


if __name__ == "__main__":
    main()
