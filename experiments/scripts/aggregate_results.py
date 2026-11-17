#!/usr/bin/env python3
"""Aggregate results from all experiments and output LaTeX macros.

Reads table4.json and table3.json from each experiment's results/ directory,
then writes a results.tex file with \\newcommand macros that can be
\\input{} in the paper.

Usage:
    python3 experiments/scripts/aggregate_results.py [--output PATH]

Default output: experiments/results.tex in this repository
"""

import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENTS_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, "..", "results.tex")

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
    "Suricata": "Suricata",
    "Snort": "Snort",
    "OpenGFW": "OpenGFW",
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
                "wall_median_us": row.get("wall_median_us"),
                "wall_stdev_us": row.get("wall_stdev_us"),
                "startup_us": row.get("startup_us"),
                "net_us": row.get("net_us"),
                "cpu_us": row.get("cpu_us"),
                "max_rss_kb": row.get("max_rss_kb"),
                "n": row.get("n"),
                "status": row.get("status", "measured"),
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


def collect_accuracy(experiments_dir):
    """Collect per-tool PCAP-mode accuracy from each scenario's results/accuracy.json.

    Returns {(scenario, tool): {tpr, tnr}}.
    """
    data = {}
    for exp_dir, scenario in EXPERIMENT_SCENARIOS.items():
        acc = load_json(os.path.join(experiments_dir, exp_dir, "results", "accuracy.json"))
        if acc is None:
            continue
        for row in acc.get("rows", []):
            data[(scenario, row["tool"])] = {"tpr": row.get("tpr"), "tnr": row.get("tnr")}
        print(f"  [OK]   {exp_dir}: accuracy loaded", file=sys.stderr)
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


def collect_static_analysis(experiments_dir):
    """Collect experiment 09: {program: row}."""
    data = load_json(os.path.join(experiments_dir, "09_static_analysis", "results", "static_analysis.json"))
    if data is None:
        print("  [SKIP] 09_static_analysis: no results/static_analysis.json", file=sys.stderr)
        return {}
    print("  [OK]   09_static_analysis: static analysis loaded", file=sys.stderr)
    return {row["program"]: row for row in data.get("rows", [])}


def collect_real_traffic(experiments_dir):
    """Collect experiment 08: list of rows (scenario, mix, tool, metrics)."""
    data = load_json(os.path.join(experiments_dir, "08_real_traffic", "results", "real_traffic.json"))
    if data is None:
        print("  [SKIP] 08_real_traffic: no results/real_traffic.json", file=sys.stderr)
        return []
    print("  [OK]   08_real_traffic: real-traffic study loaded", file=sys.stderr)
    return data.get("rows", [])


def static_analysis_macros(static):
    lines = []
    if not static:
        return lines
    lines.append("% ============================================================")
    lines.append("% Experiment 9: CensorLang static cost bounds")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Static<Program><Metric>")
    lines.append("% Metrics: Lines, ConnBytes (per-connection state the engine allocates:")
    lines.append("%          full register banks + model buffers + engine state),")
    lines.append("%          ConnTouchedBytes (same, counting only registers the program uses),")
    lines.append("%          HostBytes (host registers the program uses),")
    lines.append("%          Ops (worst-case constant-time ops per packet),")
    lines.append("%          Regex (regex evaluations per packet), ModelCalls,")
    lines.append("%          RegBytes (registers the program names), RegAllocBytes (full banks),")
    lines.append("%          EngineBytes (fixed per-connection engine state), HostAllocBytes,")
    lines.append("%          MaxLinesPerPacket, Conditions, Writes, Returns (worst case per packet)")
    lines.append("")
    for program, r in static.items():
        base = f"Static{sanitize_cmd(program)}"
        lines.append(f"\\newcommand{{\\{base}Lines}}{{{r['lines']}}}")
        lines.append(f"\\newcommand{{\\{base}ConnBytes}}{{{r['per_connection_bytes']}}}")
        if "per_connection_touched_bytes" in r:
            lines.append(f"\\newcommand{{\\{base}ConnTouchedBytes}}{{{r['per_connection_touched_bytes']}}}")
        lines.append(f"\\newcommand{{\\{base}HostBytes}}{{{r['per_host_register_bytes']}}}")
        lines.append(f"\\newcommand{{\\{base}Ops}}{{{r['constant_ops']}}}")
        lines.append(f"\\newcommand{{\\{base}Regex}}{{{r['regex_evaluations']}}}")
        lines.append(f"\\newcommand{{\\{base}ModelCalls}}{{{r['model_calls']}}}")
        if "per_connection_allocated_register_bytes" in r:
            engine = (r["per_connection_bytes"] - r["per_connection_allocated_register_bytes"]
                      - r["per_connection_model_io_bytes"])
            lines.append(f"\\newcommand{{\\{base}RegBytes}}{{{r['per_connection_register_bytes']}}}")
            lines.append(f"\\newcommand{{\\{base}RegAllocBytes}}{{{r['per_connection_allocated_register_bytes']}}}")
            lines.append(f"\\newcommand{{\\{base}EngineBytes}}{{{engine}}}")
            lines.append(f"\\newcommand{{\\{base}HostAllocBytes}}{{{r['per_host_allocated_register_bytes']}}}")
            lines.append(f"\\newcommand{{\\{base}MaxLinesPerPacket}}{{{r['max_lines_per_packet']}}}")
            for k in ("conditions", "writes", "returns"):
                lines.append(f"\\newcommand{{\\{base}{k.capitalize()}}}{{{r[k]}}}")
    lines.append("")
    return lines


def real_traffic_macros(rows):
    lines = []
    if not rows:
        return lines
    lines.append("% ============================================================")
    lines.append("% Experiment 8: real-traffic workloads with background mixes")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Real<Scenario><Mix><Tool><Metric>")
    lines.append("% Mix ∈ BgZero BgTenK BgNinetyK BgThreeNinetyK (USTC-TFC2016), each optionally")
    lines.append("%   suffixed Iscx (ISCXVPN2016) or Combined (USTC+ISCX); Metrics: WallTime, WallStdev,")
    lines.append("%   StartupTime, NetTime (s), UsPerPkt, Kpps, Cpu (s), Rss (MB), TPR, TNR,")
    lines.append("%   BgFlagged, BgFlows, Packets")
    lines.append("")
    mix_names = {"bg0": "BgZero", "bg10k": "BgTenK", "bg90k": "BgNinetyK", "bg390k": "BgThreeNinetyK"}
    background_names = {"ustc": "", "iscx": "Iscx", "combined": "Combined"}
    scenario_macro = {k: v for k, v in EXPERIMENT_SCENARIOS.items()}
    for r in rows:
        if r.get("status") != "measured":
            continue
        scn = scenario_macro.get(r["scenario"], sanitize_cmd(r["scenario"]))
        mix = mix_names.get(r["mix"], sanitize_cmd(r["mix"]))
        # USTC-only rows keep the original macro names; other backgrounds
        # (ISCXVPN2016, USTC+ISCX combined) get a suffix on the mix.
        mix += background_names.get(r.get("background", "ustc"), sanitize_cmd(r.get("background", "")))
        tool = TOOL_NAMES.get(r["tool"], sanitize_cmd(r["tool"]))
        base = f"Real{scn}{mix}{tool}"

        def emit(metric, value):
            lines.append(f"\\newcommand{{\\{base}{metric}}}{{{value if value is not None else 'N/A'}}}")

        emit("WallTime", format_time_s(r.get("wall_median_us")))
        emit("WallStdev", format_time_s(r.get("wall_stdev_us")))
        emit("StartupTime", format_time_s(r.get("startup_us")))
        emit("NetTime", format_time_s(r.get("net_us")))
        emit("UsPerPkt", r.get("net_per_packet_us"))
        pps = r.get("throughput_pps")
        emit("Kpps", f"{pps / 1000:.1f}" if pps else None)
        emit("Cpu", format_time_s(r.get("cpu_us")))
        rss = r.get("max_rss_kb")
        emit("Rss", f"{rss / 1024:.1f}" if rss else None)
        emit("TPR", r.get("tpr"))
        emit("TNR", r.get("tnr"))
        emit("BgFlagged", r.get("background_flagged"))
        emit("BgFlows", r.get("background_flows"))
        emit("Packets", r.get("total_packets"))
    lines.append("")
    return lines


def collect_nfq(experiments_dir):
    """Collect experiment 10: list of rows (scenario, variant, metrics)."""
    data = load_json(os.path.join(experiments_dir, "10_nfq_end_to_end", "results", "nfq_end_to_end.json"))
    if data is None:
        print("  [SKIP] 10_nfq_end_to_end: no results/nfq_end_to_end.json", file=sys.stderr)
        return []
    print("  [OK]   10_nfq_end_to_end: live NFQ results loaded", file=sys.stderr)
    return data.get("rows", [])


def collect_resilience(experiments_dir):
    """Collect experiment 11: list of rows (traffic, program, rate)."""
    data = load_json(os.path.join(experiments_dir, "11_resilience_matrix", "results", "resilience_matrix.json"))
    if data is None:
        print("  [SKIP] 11_resilience_matrix: no results/resilience_matrix.json", file=sys.stderr)
        return []
    print("  [OK]   11_resilience_matrix: resilience matrix loaded", file=sys.stderr)
    rows = list(data.get("rows", []))
    # Other benign backgrounds (matrix.py --background iscx|combined) re-run the
    # circumvention captures too; only their benign_<bg> rows are new.
    for bg in ("iscx", "combined"):
        extra = load_json(os.path.join(experiments_dir, "11_resilience_matrix", "results",
                                       f"resilience_matrix_{bg}.json"))
        if extra is None:
            continue
        print(f"  [OK]   11_resilience_matrix: {bg} benign control loaded", file=sys.stderr)
        rows.extend(r for r in extra.get("rows", []) if r["traffic"] == f"benign_{bg}")
    return rows


def collect_model_extraction(experiments_dir):
    """Collect experiment 06: the stats dict from extraction_stats.json."""
    data = load_json(os.path.join(experiments_dir, "06_model_extraction", "results", "extraction_stats.json"))
    if data is None:
        print("  [SKIP] 06_model_extraction: no results/extraction_stats.json", file=sys.stderr)
        return {}
    print("  [OK]   06_model_extraction: extraction stats loaded", file=sys.stderr)
    return data.get("stats", {})


def model_extraction_macros(stats):
    """\\ModelExtraction<Metric> macros (experiment 06, Figure model_extraction)."""
    if not stats:
        return []
    lines = [
        "",
        "% ============================================================",
        "% Experiment 06: model extraction (\\ModelExtraction<Metric>)",
        "% ============================================================",
    ]

    def emit(metric, value):
        lines.append(f"\\newcommand{{\\ModelExtraction{metric}}}{{{value if value is not None else 'N/A'}}}")

    emit("Probes", stats.get("total_probes"))
    emit("Blocked", stats.get("blocked"))
    emit("Allowed", stats.get("allowed"))
    emit("Errors", stats.get("errors"))
    emit("BlockedPct", stats.get("blocked_pct"))
    emit("FidelityPct", stats.get("fidelity_pct"))
    for prefix, name in (("true", "True"), ("recon", "Recon")):
        slope = stats.get(f"{prefix}_slope")
        intercept = stats.get(f"{prefix}_intercept")
        emit(f"{name}Slope", f"{slope:.3f}" if slope is not None else None)
        emit(f"{name}Intercept", f"{intercept:.1f}" if intercept is not None else None)
    angle = stats.get("recon_angle_deg")
    emit("AngleDeg", f"{angle:.3f}" if angle is not None else None)
    dis = stats.get("recon_space_disagreement_pct")
    emit("DisagreementPct", f"{dis:.3f}" if dis is not None else None)
    return lines


def nfq_macros(rows):
    lines = []
    if not rows:
        return lines
    lines.append("% ============================================================")
    lines.append("% Experiment 10: live NFQ end-to-end (accuracy, latency, throughput)")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Nfq<Scenario><Variant><Metric>")
    lines.append("% Variant ∈ None Null PyCL CL; Metrics: TPR, TNR, LatencyMs (median per-connection),")
    lines.append("%   LatencyPNinetyFiveMs, Mbps (iperf3), Retransmits, Requests")
    lines.append("")
    variant_names = {"none": "None", "null": "Null", "pycl": "PyCL", "censorlang": "CL"}
    for r in rows:
        scn = EXPERIMENT_SCENARIOS.get(r["scenario"], sanitize_cmd(r["scenario"]))
        base = f"Nfq{scn}{variant_names.get(r['variant'], sanitize_cmd(r['variant']))}"

        def emit(metric, value):
            lines.append(f"\\newcommand{{\\{base}{metric}}}{{{value if value is not None else 'N/A'}}}")

        emit("TPR", r.get("tpr"))
        emit("TNR", r.get("tnr"))
        emit("LatencyMs", r.get("latency_median_ms"))
        emit("LatencyPNinetyFiveMs", r.get("latency_p95_ms"))
        emit("Mbps", r.get("throughput_mbps"))
        emit("Retransmits", r.get("retransmits"))
        emit("Requests", r.get("requests"))
    lines.append("")
    return lines


def resilience_macros(rows):
    lines = []
    if not rows:
        return lines
    lines.append("% ============================================================")
    lines.append("% Experiment 11: resilience matrix (corpus program × traffic set)")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Res<Program><Traffic>Rate (percent of flows acted on),")
    lines.append("%                 \\Res<Program><Traffic>Flagged[Tcp|Udp], \\Res<Traffic>Flows")
    lines.append("")
    seen_traffic = set()
    for r in rows:
        t = sanitize_cmd(r["traffic"]).capitalize()
        base = f"Res{sanitize_cmd(r['program'])}{t}"
        # from the counts: the stored rate is already rounded to 4 places
        rate = 100 * r["flagged"] / r["flows"] if r["flows"] else 0.0
        lines.append(f"\\newcommand{{\\{base}Rate}}{{{rate:.1f}}}")
        lines.append(f"\\newcommand{{\\{base}Flagged}}{{{r['flagged']}}}")
        for proto in ("tcp", "udp"):
            if f"flagged_{proto}" in r:
                lines.append(f"\\newcommand{{\\{base}Flagged{proto.capitalize()}}}{{{r[f'flagged_{proto}']}}}")
        if r["traffic"] not in seen_traffic:
            seen_traffic.add(r["traffic"])
            lines.append(f"\\newcommand{{\\Res{t}Flows}}{{{r['flows']}}}")
    lines.append("")
    return lines


def generate_latex_macros(table4, table3, benchmarks, accuracy=None, static=None, real=None, nfq=None, resilience=None, extraction=None):
    accuracy = accuracy or {}
    static = static or {}
    real = real or []
    nfq = nfq or []
    resilience = resilience or []
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
    table4_scenarios = ["HttpKeyword", "SniFiltering", "Shadowsocks", "DnsInjection", "MlClassification"]
    table4_tools = ["PyCL", "CensorLang", "Zeek", "Scapy", "Suricata", "Snort", "OpenGFW"]

    lines.append("% Additional per-tool metrics (all measured identically, as separate processes):")
    lines.append("%   WallTime     median process wall-clock (s)")
    lines.append("%   WallStdev    stdev of wall-clock across runs (s)")
    lines.append("%   StartupTime  median wall-clock on a one-frame PCAP = process startup/teardown (s)")
    lines.append("%   NetTime      WallTime - StartupTime = steady-state processing (s)")
    lines.append("%   Cpu          median user+sys CPU time (s)")
    lines.append("%   Rss          median peak resident set size (MB)")
    lines.append("%   Runs         number of measured iterations")
    lines.append("%   Status       measured | unavailable | not-expressible")
    lines.append("% `Time` keeps the legacy semantics (tool-internal timer where one exists).")
    lines.append("")

    for scenario in table4_scenarios:
        lines.append(f"% {scenario}")
        for tool in table4_tools:
            tool_cmd = TOOL_NAMES[tool]
            key = (scenario, tool)
            entry = table4.get(key) or {}

            cmd_base = f"Result{sanitize_cmd(scenario)}{sanitize_cmd(tool_cmd)}"

            def emit(metric, value):
                lines.append(f"\\newcommand{{\\{cmd_base}{metric}}}{{{value if value is not None else 'N/A'}}}")

            emit("Time", format_time_s(entry.get("median_us")))
            emit("Loc", entry.get("loc"))
            emit("WallTime", format_time_s(entry.get("wall_median_us")))
            emit("WallStdev", format_time_s(entry.get("wall_stdev_us")))
            emit("StartupTime", format_time_s(entry.get("startup_us")))
            emit("NetTime", format_time_s(entry.get("net_us")))
            emit("Cpu", format_time_s(entry.get("cpu_us")))
            rss = entry.get("max_rss_kb")
            emit("Rss", f"{rss / 1024:.1f}" if rss is not None else None)
            emit("Runs", entry.get("n"))
            emit("Status", entry.get("status", "N/A"))

        lines.append("")

    # --- Per-tool accuracy on the labelled PCAPs (Table 5 correctness check) ---
    lines.append("% ============================================================")
    lines.append("% Per-tool PCAP-mode accuracy against ground-truth labels")
    lines.append("% ============================================================")
    lines.append("% Command format: \\Acc<Scenario><Tool>TPR / TNR")
    lines.append("")
    for scenario in table4_scenarios:
        for tool in table4_tools:
            entry = accuracy.get((scenario, tool))
            cmd_base = f"Acc{sanitize_cmd(scenario)}{sanitize_cmd(TOOL_NAMES[tool])}"
            if entry:
                lines.append(f"\\newcommand{{\\{cmd_base}TPR}}{{{entry['tpr']}}}")
                lines.append(f"\\newcommand{{\\{cmd_base}TNR}}{{{entry['tnr']}}}")
            else:
                lines.append(f"\\newcommand{{\\{cmd_base}TPR}}{{---}}")
                lines.append(f"\\newcommand{{\\{cmd_base}TNR}}{{---}}")
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

    lines.extend(static_analysis_macros(static))
    lines.extend(real_traffic_macros(real))
    lines.extend(nfq_macros(nfq))
    lines.extend(resilience_macros(resilience))
    lines.extend(model_extraction_macros(extraction or {}))

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
        help="Output path for results.tex (default: experiments/results.tex)",
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

    print(file=sys.stderr)
    print("Collecting per-tool accuracy:", file=sys.stderr)
    accuracy = collect_accuracy(args.experiments_dir)

    print(file=sys.stderr)
    print("Collecting static analysis and real-traffic study:", file=sys.stderr)
    static = collect_static_analysis(args.experiments_dir)
    real = collect_real_traffic(args.experiments_dir)
    nfq = collect_nfq(args.experiments_dir)
    resilience = collect_resilience(args.experiments_dir)
    extraction = collect_model_extraction(args.experiments_dir)

    # Generate LaTeX
    latex = generate_latex_macros(table4, table3, benchmarks, accuracy, static, real, nfq, resilience, extraction)

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
