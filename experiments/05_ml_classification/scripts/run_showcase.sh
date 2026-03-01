#!/usr/bin/env bash
# run_showcase.sh — Table 4: PCAP-mode timing benchmark + LOC count
#
# Runs all tools (PyCL, CensorLang, Scapy) against the test PCAP
# multiple times and collects timing results.
#
# NOTE: PyCL mode requires model.onnx to exist.  If it does not, the PyCL
# benchmark is skipped with a warning.  CensorLang uses an entropy heuristic
# and does not require a model.
#
# All results are written as structured CSV to results/ for later TeX import.
#
# Prerequisites:
#   nix develop .#experiments   (or have censorlab, python3+scapy in PATH)
#   python3 experiments/05_ml_classification/pcap/generate_pcap.py
#
# Usage:
#   bash experiments/05_ml_classification/scripts/run_showcase.sh [ITERATIONS]


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$EXPERIMENT_DIR/results"
PCAP="$EXPERIMENT_DIR/pcap/test.pcap"
LABELS="$EXPERIMENT_DIR/pcap/labels.csv"
MODEL="$EXPERIMENT_DIR/model.onnx"
ITERATIONS="${1:-5}"

mkdir -p "$RESULTS_DIR"

# Helper: run censorlab
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

echo "=== Experiment 5: ML Protocol Classification — Showcase (Table 4) ==="
echo "PCAP: $PCAP"
echo "Iterations: $ITERATIONS"
echo ""

# Initialize the raw timings CSV (one row per run per tool)
RAW_TIMINGS="$RESULTS_DIR/raw_timings.csv"
echo "tool,iteration,time_us" > "$RAW_TIMINGS"

# Helper: extract microseconds from CensorLab output
extract_censorlab_us() {
    echo "$1" | grep -oP '\(\K\d+(?=us including I/O\))' || echo ""
}

# ---------------------------------------------------------------------------
# 1. CensorLab (PyCL) — requires model.onnx
# ---------------------------------------------------------------------------
echo "--- CensorLab (PyCL) ---"

if [ ! -f "$MODEL" ]; then
    echo "  model.onnx not found — training automatically..."
    python3 "$EXPERIMENT_DIR/train_model.py" --output "$MODEL"
    if [ ! -f "$MODEL" ]; then
        echo "  ERROR: Training failed. SKIPPED: PyCL benchmark requires model.onnx"
    fi
fi

if [ ! -f "$MODEL" ]; then
    echo "  SKIPPED: PyCL benchmark requires model.onnx"
else
    for i in $(seq 1 "$ITERATIONS"); do
        output=$(run_censorlab "censor.toml" "pcap/test.pcap" "10.0.0.1" 2>&1)
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
fi

# ---------------------------------------------------------------------------
# 2. CensorLab (CensorLang) — ONNX model classification
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
# 3. Scapy — ONNX model classification (same model as PyCL)
# ---------------------------------------------------------------------------
echo ""
echo "--- Scapy ---"

for i in $(seq 1 "$ITERATIONS"); do
    python3 "$EXPERIMENT_DIR/comparison/scapy_ml_classification.py" "$PCAP" \
        --output "$RESULTS_DIR/scapy_decisions.csv" 2>&1 | tee /tmp/scapy_run.txt
    timing_s=$(cat "$RESULTS_DIR/scapy_timing.txt" 2>/dev/null || true)
    if [ -n "$timing_s" ]; then
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

scapy_loc=$(count_loc "$EXPERIMENT_DIR/comparison/scapy_ml_classification.py")
echo "Scapy,scapy_ml_classification.py,$scapy_loc" >> "$LOC_FILE"
echo "  Scapy (scapy_ml_classification.py): $scapy_loc"

echo ""
echo "=== Done ==="
echo "Raw timings: $RAW_TIMINGS"
echo "LOC counts:  $LOC_FILE"
echo "Run analysis: python3 $SCRIPT_DIR/analyze.py"
