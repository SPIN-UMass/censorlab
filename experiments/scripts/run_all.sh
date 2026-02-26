#!/usr/bin/env bash
# run_all.sh — Run the full PCAP-mode experiment pipeline end-to-end.
#
# Steps:
#   1. Generate PCAPs for experiments 01-05 (if missing)
#   2. Train ONNX model for experiment 05 (if missing)
#   3. Run run_showcase.sh for experiments 01-05
#   4. Run run_benchmarks.sh for experiment 07
#   5. Run analyze.py for each experiment
#   6. Run aggregate_results.py
#   7. Print summary
#
# Experiment 06 is excluded (requires live NFQ mode).
#
# Usage:
#   bash experiments/scripts/run_all.sh [ITERATIONS]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENTS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$EXPERIMENTS_DIR")"
ITERATIONS="${1:-3}"

echo "============================================================"
echo "  CensorLab — Full Experiment Pipeline"
echo "============================================================"
echo "Experiments directory: $EXPERIMENTS_DIR"
echo "Iterations per experiment: $ITERATIONS"
echo ""

SHOWCASE_EXPERIMENTS=(
    "01_http_keyword"
    "02_dns_injection"
    "03_tls_sni"
    "04_shadowsocks"
    "05_ml_classification"
)

FAILED=()

# ----------------------------------------------------------------
# Step 1: Generate PCAPs for experiments 01-05
# ----------------------------------------------------------------
echo "=== Step 1: Generating PCAPs ==="
for exp in "${SHOWCASE_EXPERIMENTS[@]}"; do
    pcap_path="$EXPERIMENTS_DIR/$exp/pcap/test.pcap"
    # Exp 05 also needs train.pcap for the train/test split
    if [ "$exp" = "05_ml_classification" ]; then
        train_path="$EXPERIMENTS_DIR/$exp/pcap/train.pcap"
        if [ -f "$pcap_path" ] && [ -f "$train_path" ]; then
            echo "  [$exp] PCAPs already exist, skipping"
        else
            echo "  [$exp] Generating train + test PCAPs..."
            python3 "$EXPERIMENTS_DIR/$exp/pcap/generate_pcap.py"
        fi
    elif [ -f "$pcap_path" ]; then
        echo "  [$exp] PCAP already exists, skipping"
    else
        echo "  [$exp] Generating PCAP..."
        python3 "$EXPERIMENTS_DIR/$exp/pcap/generate_pcap.py"
    fi
done
echo ""

# ----------------------------------------------------------------
# Step 2: Train ONNX model for experiment 05 (if missing)
# ----------------------------------------------------------------
echo "=== Step 2: Training ML model (experiment 05) ==="
model_path="$EXPERIMENTS_DIR/05_ml_classification/model.onnx"
if [ -f "$model_path" ]; then
    echo "  Model already exists, skipping"
else
    echo "  Training model..."
    python3 "$EXPERIMENTS_DIR/05_ml_classification/train_model.py"
fi
echo ""

# ----------------------------------------------------------------
# Step 3: Run showcase benchmarks (experiments 01-05)
# ----------------------------------------------------------------
echo "=== Step 3: Running showcase benchmarks (experiments 01-05) ==="
for exp in "${SHOWCASE_EXPERIMENTS[@]}"; do
    echo ""
    echo "--- $exp ---"
    if bash "$EXPERIMENTS_DIR/$exp/scripts/run_showcase.sh" "$ITERATIONS"; then
        echo "  [$exp] Showcase complete"
    else
        echo "  [$exp] WARNING: showcase failed"
        FAILED+=("$exp/run_showcase.sh")
    fi
done
echo ""

# ----------------------------------------------------------------
# Step 4: Run benchmarks (experiment 07)
# ----------------------------------------------------------------
echo "=== Step 4: Running throughput benchmarks (experiment 07) ==="
if bash "$EXPERIMENTS_DIR/07_benchmarks/scripts/run_benchmarks.sh" "$ITERATIONS"; then
    echo "  [07_benchmarks] Benchmarks complete"
else
    echo "  [07_benchmarks] WARNING: benchmarks failed"
    FAILED+=("07_benchmarks/run_benchmarks.sh")
fi
echo ""

# ----------------------------------------------------------------
# Step 5: Run analysis for each experiment
# ----------------------------------------------------------------
echo "=== Step 5: Running analysis ==="
for exp in "${SHOWCASE_EXPERIMENTS[@]}"; do
    echo "  [$exp] Analyzing..."
    if python3 "$EXPERIMENTS_DIR/$exp/scripts/analyze.py"; then
        echo "  [$exp] Analysis complete"
    else
        echo "  [$exp] WARNING: analysis failed"
        FAILED+=("$exp/analyze.py")
    fi
done

echo "  [07_benchmarks] Analyzing..."
if python3 "$EXPERIMENTS_DIR/07_benchmarks/scripts/analyze.py"; then
    echo "  [07_benchmarks] Analysis complete"
else
    echo "  [07_benchmarks] WARNING: analysis failed"
    FAILED+=("07_benchmarks/analyze.py")
fi
echo ""

# ----------------------------------------------------------------
# Step 6: Aggregate results
# ----------------------------------------------------------------
echo "=== Step 6: Aggregating results ==="
if python3 "$EXPERIMENTS_DIR/scripts/aggregate_results.py" --output "$EXPERIMENTS_DIR/results.tex"; then
    echo "  Aggregated results written to experiments/results.tex"
else
    echo "  WARNING: aggregation failed"
    FAILED+=("aggregate_results.py")
fi
echo ""

# ----------------------------------------------------------------
# Step 7: Summary
# ----------------------------------------------------------------
echo "============================================================"
echo "  Pipeline Complete"
echo "============================================================"
echo ""

# Check which result files exist
echo "Result files:"
for exp in "${SHOWCASE_EXPERIMENTS[@]}"; do
    t4="$EXPERIMENTS_DIR/$exp/results/table4.json"
    if [ -f "$t4" ]; then
        echo "  [OK]   $exp/results/table4.json"
    else
        echo "  [MISS] $exp/results/table4.json"
    fi
done

bench="$EXPERIMENTS_DIR/07_benchmarks/results/benchmark_summary.json"
if [ -f "$bench" ]; then
    echo "  [OK]   07_benchmarks/results/benchmark_summary.json"
else
    echo "  [MISS] 07_benchmarks/results/benchmark_summary.json"
fi

agg="$EXPERIMENTS_DIR/results.tex"
if [ -f "$agg" ]; then
    echo "  [OK]   experiments/results.tex"
else
    echo "  [MISS] experiments/results.tex"
fi

echo ""
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "Warnings (${#FAILED[@]} steps had issues):"
    for f in "${FAILED[@]}"; do
        echo "  - $f"
    done
    exit 1
else
    echo "All steps completed successfully."
fi
