#!/usr/bin/env bash
# run_showcase.sh — Table 4: PCAP-mode timing benchmark + LOC count
#
# Runs all tools (PyCL, CensorLang, Zeek, Scapy) against the test PCAP
# multiple times and collects timing results.
#
# All results are written as structured CSV to results/ for later TeX import.
#
# Prerequisites:
#   nix develop .#experiments   (or have censorlab, python3+scapy, zeek in PATH)
#   python3 experiments/01_http_keyword/pcap/generate_pcap.py
#
# Usage:
#   bash experiments/01_http_keyword/scripts/run_showcase.sh [ITERATIONS]


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$EXPERIMENT_DIR/results"
PCAP="$EXPERIMENT_DIR/pcap/test.pcap"
LABELS="$EXPERIMENT_DIR/pcap/labels.csv"
ITERATIONS="${1:-5}"

mkdir -p "$RESULTS_DIR"

# Helper: run censorlab
# Usage: run_censorlab <config_basename> <pcap_relpath> <client_ip>
# Paths are relative to EXPERIMENT_DIR.
run_censorlab() {
    local config_base="$1"
    local pcap_rel="$2"
    local client_ip="$3"
    censorlab -c "$EXPERIMENT_DIR/$config_base" pcap "$EXPERIMENT_DIR/$pcap_rel" "$client_ip"
}

# Verify PCAP exists
if [ ! -f "$PCAP" ]; then
    echo "ERROR: Test PCAP not found at $PCAP"
    echo "Run: python3 $EXPERIMENT_DIR/pcap/generate_pcap.py"
    exit 1
fi

echo "=== Experiment 1: HTTP Keyword Filtering — Showcase (Table 4) ==="
echo "PCAP: $PCAP"
echo "Iterations: $ITERATIONS"
echo ""

# Initialize the raw timings CSV (one row per run per tool)
RAW_TIMINGS="$RESULTS_DIR/raw_timings.csv"
echo "tool,iteration,time_us" > "$RAW_TIMINGS"

# Helper: extract microseconds from CensorLab output
# CensorLab prints: "Pcap mode took <N>us to process the file"
extract_censorlab_us() {
    echo "$1" | grep -oP 'took \K\d+(?=us)' || echo ""
}

# ---------------------------------------------------------------------------
# 1. CensorLab (PyCL)
# ---------------------------------------------------------------------------
echo "--- CensorLab (PyCL) ---"

for i in $(seq 1 "$ITERATIONS"); do
    output=$(run_censorlab "censor.toml" "pcap/test.pcap" "10.0.0.1" 2>&1)
    # Save full output on first run for decision analysis
    if [ "$i" -eq 1 ]; then
        echo "$output" > "$RESULTS_DIR/pycl_output.txt"
    fi
    timing_us=$(extract_censorlab_us "$output")
    if [ -n "$timing_us" ]; then
        echo "PyCL,$i,$timing_us" >> "$RAW_TIMINGS"
        echo "  Run $i: ${timing_us}us"
    else
        echo "  Run $i: (timing not found in output)"
    fi
done

# ---------------------------------------------------------------------------
# 2. CensorLab (CensorLang)
# ---------------------------------------------------------------------------
echo ""
echo "--- CensorLab (CensorLang) ---"

for i in $(seq 1 "$ITERATIONS"); do
    output=$(run_censorlab "censor_lang.toml" "pcap/test.pcap" "10.0.0.1" 2>&1)
    if [ "$i" -eq 1 ]; then
        echo "$output" > "$RESULTS_DIR/censorlang_output.txt"
    fi
    timing_us=$(extract_censorlab_us "$output")
    if [ -n "$timing_us" ]; then
        echo "CensorLang,$i,$timing_us" >> "$RAW_TIMINGS"
        echo "  Run $i: ${timing_us}us"
    else
        echo "  Run $i: (timing not found in output)"
    fi
done

# ---------------------------------------------------------------------------
# 3. Zeek
# ---------------------------------------------------------------------------
echo ""
echo "--- Zeek ---"

if command -v zeek &> /dev/null; then
    ZEEK_WORKDIR=$(mktemp -d)
    for i in $(seq 1 "$ITERATIONS"); do
        pushd "$ZEEK_WORKDIR" > /dev/null
        start_time=$(date +%s%N)
        zeek -C -r "$PCAP" "$EXPERIMENT_DIR/comparison/zeek_http_keyword.zeek" 2>&1 || true
        end_time=$(date +%s%N)
        elapsed_us=$(( (end_time - start_time) / 1000 ))
        echo "Zeek,$i,$elapsed_us" >> "$RAW_TIMINGS"
        echo "  Run $i: ${elapsed_us}us"
        # Save first-run logs
        if [ "$i" -eq 1 ] && [ -f http_keyword_matches.log ]; then
            cp http_keyword_matches.log "$RESULTS_DIR/zeek_matches.log"
        fi
        rm -f *.log
        popd > /dev/null
    done
    rm -rf "$ZEEK_WORKDIR"
else
    echo "  SKIPPED: zeek not found in PATH"
fi

# ---------------------------------------------------------------------------
# 4. Scapy
# ---------------------------------------------------------------------------
echo ""
echo "--- Scapy ---"

for i in $(seq 1 "$ITERATIONS"); do
    python3 "$EXPERIMENT_DIR/comparison/scapy_http_keyword.py" "$PCAP" \
        --output "$RESULTS_DIR/scapy_decisions.csv" 2>&1 | tee /tmp/scapy_run.txt
    # scapy_http_keyword.py writes timing (seconds) to scapy_timing.txt
    timing_s=$(cat "$RESULTS_DIR/scapy_timing.txt" 2>/dev/null || true)
    if [ -n "$timing_s" ]; then
        # Convert seconds to microseconds for consistent units
        timing_us=$(python3 -c "print(int(float('$timing_s') * 1000000))")
        echo "Scapy,$i,$timing_us" >> "$RAW_TIMINGS"
    fi
done

# ---------------------------------------------------------------------------
# LOC counts (structured CSV)
# ---------------------------------------------------------------------------
echo ""
echo "=== Lines of Code ==="
LOC_FILE="$RESULTS_DIR/loc.csv"
echo "tool,file,loc" > "$LOC_FILE"

count_loc() {
    # Count non-blank, non-comment lines (# and ##! comments)
    grep -cve '^\s*$' -e '^\s*#' -e '^\s*##!' "$1" 2>/dev/null || echo 0
}

pycl_loc=$(count_loc "$EXPERIMENT_DIR/censor.py")
echo "PyCL,censor.py,$pycl_loc" >> "$LOC_FILE"
echo "  PyCL (censor.py): $pycl_loc"

cl_loc=$(count_loc "$EXPERIMENT_DIR/censor.cl")
echo "CensorLang,censor.cl,$cl_loc" >> "$LOC_FILE"
echo "  CensorLang (censor.cl): $cl_loc"

zeek_loc=$(count_loc "$EXPERIMENT_DIR/comparison/zeek_http_keyword.zeek")
echo "Zeek,zeek_http_keyword.zeek,$zeek_loc" >> "$LOC_FILE"
echo "  Zeek (zeek_http_keyword.zeek): $zeek_loc"

scapy_loc=$(count_loc "$EXPERIMENT_DIR/comparison/scapy_http_keyword.py")
echo "Scapy,scapy_http_keyword.py,$scapy_loc" >> "$LOC_FILE"
echo "  Scapy (scapy_http_keyword.py): $scapy_loc"

echo ""
echo "=== Done ==="
echo "Raw timings: $RAW_TIMINGS"
echo "LOC counts:  $LOC_FILE"
echo "Run analysis: python3 $SCRIPT_DIR/analyze.py"
