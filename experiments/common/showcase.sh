#!/usr/bin/env bash
# showcase.sh — generic Table 4 runner for one scenario directory.
#
# Runs every tool the scenario declares in scenario.conf (PyCL, CensorLang,
# Zeek, Scapy, Suricata, Snort, OpenGFW) against the labelled test PCAP and
# records timing, CPU, memory and LOC.  Methodology (MR4):
#
#   * WARMUP untimed run(s) per tool first (page cache, JIT, etc.)
#   * ITERATIONS measured runs per tool, in a single randomized, interleaved
#     order across tools (so no tool systematically benefits from ordering)
#   * ITERATIONS baseline runs per tool on common/baseline.pcap (process
#     startup/teardown cost), also interleaved
#   * the first measured run's native outputs are kept for the accuracy report
#
# Outputs (in <scenario>/results/):
#   raw_timings.csv    one row per run (see harness.sh for columns)
#   loc.csv            tool,file,loc
#   tools.csv          tool,status     (measured | unavailable | not-expressible)
#   <tool> artifacts   pycl_output.txt, zeek_matches.log, suricata_eve.json, …
#
# Usage:
#   bash experiments/common/showcase.sh <scenario_dir> [ITERATIONS] [WARMUP]
#   PCAP=/path/to/other.pcap bash experiments/common/showcase.sh <scenario_dir>
#
# Environment:
#   PCAP        override the scenario PCAP (used by 08_real_traffic)
#   RESULTS_DIR override the output directory
#   TOOLS       space-separated subset of tools to run

set -euo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "$COMMON_DIR/harness.sh"

if [ $# -lt 1 ]; then
    echo "usage: $0 <scenario_dir> [ITERATIONS] [WARMUP]" >&2
    exit 2
fi

load_scenario "$1"
ITERATIONS="${2:-5}"
WARMUP="${3:-1}"
PCAP="${PCAP:-$SC_DIR/$(sc_get PCAP)}"
RESULTS_DIR="${RESULTS_DIR:-$SC_DIR/results}"
RAW_TIMINGS="$RESULTS_DIR/raw_timings.csv"
LOC_FILE="$RESULTS_DIR/loc.csv"
TOOLS_FILE="$RESULTS_DIR/tools.csv"

mkdir -p "$RESULTS_DIR"

# Remove artifacts from previous runs so a tool that no longer runs cannot
# leave a stale decision log behind for the accuracy report.
rm -f "$RESULTS_DIR"/{pycl_output.txt,censorlang_output.txt,zeek_matches.log,scapy_decisions.csv,scapy_timing.txt} \
      "$RESULTS_DIR"/{suricata_eve.json,snort_alerts.csv,opengfw_output.jsonl} \
      "$RESULTS_DIR"/*_decisions.csv "$RESULTS_DIR"/*_failed_run.log

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
if [ ! -f "$PCAP" ]; then
    gen="$(sc_get GENERATE)"
    if [ -n "$gen" ] && [ -f "$SC_DIR/$gen" ]; then
        echo "Generating PCAP via $gen ..."
        python3 "$SC_DIR/$gen"
    fi
    if [ ! -f "$PCAP" ]; then
        echo "ERROR: PCAP not found: $PCAP" >&2
        exit 1
    fi
fi
ensure_baseline_pcap

echo "============================================================"
echo "  $(sc_get ID): $(sc_get NAME) — Table 4 showcase"
echo "============================================================"
echo "PCAP:        $PCAP"
echo "Iterations:  $ITERATIONS (warm-up: $WARMUP)"
echo ""

# ---------------------------------------------------------------------------
# Tool selection
# ---------------------------------------------------------------------------
echo "tool,status" > "$TOOLS_FILE"
RUN_TOOLS=()
for tool in "${SC_TOOLS[@]}"; do
    if [ -n "${TOOLS:-}" ] && ! [[ " $TOOLS " == *" $tool "* ]]; then
        continue
    fi
    if ! sc_tool_enabled "$tool"; then
        echo "$tool,not-expressible" >> "$TOOLS_FILE"
        echo "  $tool: not expressible in this scenario (skipped)"
    elif ! tool_available "$tool"; then
        echo "$tool,unavailable" >> "$TOOLS_FILE"
        echo "  $tool: binary '$(tool_binary "$tool")' not on PATH (skipped)"
    else
        echo "$tool,measured" >> "$TOOLS_FILE"
        RUN_TOOLS+=("$tool")
    fi
done
echo ""

if [ ${#RUN_TOOLS[@]} -eq 0 ]; then
    echo "ERROR: no tools to run" >&2
    exit 1
fi

echo "tool,iteration,phase,time_us,wall_us,user_us,sys_us,max_rss_kb,exit_code" > "$RAW_TIMINGS"

# ---------------------------------------------------------------------------
# Warm-up (untimed)
# ---------------------------------------------------------------------------
if [ "$WARMUP" -gt 0 ]; then
    echo "--- Warm-up ($WARMUP per tool) ---"
    for tool in "${RUN_TOOLS[@]}"; do
        for i in $(seq 1 "$WARMUP"); do
            measure_run "$tool" "$i" warmup "$PCAP" "$RESULTS_DIR"
        done
    done
    echo ""
fi

# ---------------------------------------------------------------------------
# Measured runs — randomized interleaving of (tool, iteration) pairs
# ---------------------------------------------------------------------------
schedule=()
for tool in "${RUN_TOOLS[@]}"; do
    for i in $(seq 1 "$ITERATIONS"); do
        schedule+=("$tool:$i:measure")
        schedule+=("$tool:$i:baseline")
    done
done
mapfile -t schedule < <(printf '%s\n' "${schedule[@]}" | shuf)

echo "--- Measured runs (${#schedule[@]} total, randomized order) ---"
for entry in "${schedule[@]}"; do
    IFS=: read -r tool i phase <<< "$entry"
    if [ "$phase" = baseline ]; then
        measure_run "$tool" "$i" baseline "$BASELINE_PCAP" "$RESULTS_DIR"
    else
        measure_run "$tool" "$i" measure "$PCAP" "$RESULTS_DIR"
    fi
done
echo ""

# Warm-up rows are kept in the CSV for auditing but analysis ignores them.

# ---------------------------------------------------------------------------
# LOC
# ---------------------------------------------------------------------------
echo "--- Lines of code ---"
echo "tool,file,loc" > "$LOC_FILE"
for tool in "${SC_TOOLS[@]}"; do
    sc_tool_enabled "$tool" || continue
    prog="$(sc_tool_program "$tool")"
    loc=$(count_loc "$SC_DIR/$prog")
    echo "$tool,$prog,$loc" >> "$LOC_FILE"
    printf '  %-11s %-40s %s\n' "$tool" "$prog" "$loc"
done
echo ""

echo "=== Done: $(sc_get ID) ==="
echo "Raw timings: $RAW_TIMINGS"
echo "Analyze:     python3 $COMMON_DIR/analyze_showcase.py $SC_DIR"
