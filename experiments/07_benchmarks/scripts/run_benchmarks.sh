#!/usr/bin/env bash
# run_benchmarks.sh — Throughput and Latency Benchmarks
#
# Runs CensorLab in PCAP mode with different censors and PCAP sizes
# to measure processing throughput and per-packet latency.
#
# All results are written as structured CSV to results/ for later analysis.
#
# Prerequisites:
#   nix develop .#experiments   (or have censorlab, python3+scapy in PATH)
#   python3 experiments/07_benchmarks/pcap/generate_pcap.py  (auto-generated if missing)
#
# Usage:
#   bash experiments/07_benchmarks/scripts/run_benchmarks.sh [ITERATIONS]


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$EXPERIMENT_DIR/results"
ITERATIONS="${1:-10}"
WARMUP_RUNS=2

mkdir -p "$RESULTS_DIR"

# PCAP sizes to benchmark (number of packets)
PCAP_SIZES=(1000 5000 10000 50000)

# Censors to benchmark
CENSORS=("null" "sni_filter" "entropy")

# Helper: run censorlab
# Usage: run_censorlab <config_relpath> <pcap_relpath>
# Paths are relative to EXPERIMENT_DIR.
run_censorlab() {
    local config="$1"
    local pcap="$2"
    censorlab -c "$EXPERIMENT_DIR/$config" pcap "$EXPERIMENT_DIR/$pcap" "10.0.0.1"
}

# Helper: extract microseconds from CensorLab output
# CensorLab prints: "Pcap mode took <N>us to process the file"
extract_us() {
    echo "$1" | grep -oP 'took \K\d+(?=us)' || echo ""
}

# Initialize results CSV (one row per run)
RESULTS_CSV="$RESULTS_DIR/benchmark_results.csv"
echo "censor,pcap_size,iteration,time_us" > "$RESULTS_CSV"

echo "=== Experiment 7: Throughput/Latency Benchmarks ==="
echo "Warmup runs per configuration: $WARMUP_RUNS"
echo "Measured iterations per configuration: $ITERATIONS"
echo "PCAP sizes: ${PCAP_SIZES[*]}"
echo "Censors: ${CENSORS[*]}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Generate PCAPs if needed
# ---------------------------------------------------------------------------
echo "--- Generating benchmark PCAPs ---"
for size in "${PCAP_SIZES[@]}"; do
    pcap_path="$EXPERIMENT_DIR/pcap/bench_${size}.pcap"
    if [ ! -f "$pcap_path" ]; then
        echo "  Generating PCAP with $size packets..."
        python3 "$EXPERIMENT_DIR/pcap/generate_pcap.py" --n "$size" --output "$pcap_path"
    else
        echo "  PCAP already exists: bench_${size}.pcap"
    fi
done
echo ""

# ---------------------------------------------------------------------------
# Step 2: Build randomized execution order
# ---------------------------------------------------------------------------
configs=()
for censor in "${CENSORS[@]}"; do
    for size in "${PCAP_SIZES[@]}"; do
        configs+=("${censor}:${size}")
    done
done

# Shuffle the configurations to avoid cache/ordering effects
mapfile -t configs < <(printf '%s\n' "${configs[@]}" | shuf)

# ---------------------------------------------------------------------------
# Step 3: Run benchmarks (randomized order)
# ---------------------------------------------------------------------------
total_configs=${#configs[@]}
current=0

for entry in "${configs[@]}"; do
    censor="${entry%%:*}"
    size="${entry##*:}"
    current=$((current + 1))
    pcap_rel="pcap/bench_${size}.pcap"
    config_rel="censors/${censor}.toml"

    echo "--- [$current/$total_configs] $censor @ $size packets ---"

    # Warmup runs (not recorded)
    for i in $(seq 1 "$WARMUP_RUNS"); do
        output=$(run_censorlab "$config_rel" "$pcap_rel" 2>&1)
        timing_us=$(extract_us "$output")
        echo "  Warmup $i: ${timing_us:-N/A}us"
    done

    # Measured runs
    for i in $(seq 1 "$ITERATIONS"); do
        output=$(run_censorlab "$config_rel" "$pcap_rel" 2>&1)
        timing_us=$(extract_us "$output")
        if [ -n "$timing_us" ]; then
            echo "$censor,$size,$i,$timing_us" >> "$RESULTS_CSV"
            echo "  Run $i: ${timing_us}us"
        else
            echo "  Run $i: (timing not found in output)"
            # Save problematic output for debugging
            echo "$output" > "$RESULTS_DIR/debug_${censor}_${size}_${i}.txt"
        fi
    done
    echo ""
done

# ---------------------------------------------------------------------------
# Step 4: Summary
# ---------------------------------------------------------------------------
echo "=== Done ==="
echo "Raw results: $RESULTS_CSV"
echo ""
echo "Run analysis:"
echo "  python3 $SCRIPT_DIR/analyze.py"
