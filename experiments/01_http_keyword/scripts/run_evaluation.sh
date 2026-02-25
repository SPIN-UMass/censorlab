#!/usr/bin/env bash
# run_evaluation.sh — Table 3: Live NFQ TPR/TNR evaluation
#
# Starts CensorLab in NFQ mode, runs the traffic generator to send
# HTTP requests through the censor, and computes TPR/TNR.
#
# Prerequisites:
#   - CensorLab built with: cargo build --release
#   - Network capabilities set: ./set_permissions.sh
#   - iptables NFQ rule configured (see below)
#   - A simple HTTP server running on the target
#
# Usage:
#   sudo bash experiments/01_http_keyword/scripts/run_evaluation.sh
#
# This script is designed to run inside the Docker Compose environment
# (experiments/docker-compose.yml) or on a configured host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$EXPERIMENT_DIR/results"

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-8080}"
NUM_REQUESTS="${NUM_REQUESTS:-10000}"

mkdir -p "$RESULTS_DIR"

echo "=== Experiment 1: HTTP Keyword Filtering — Evaluation (Table 3) ==="
echo "Target: $TARGET_HOST:$TARGET_PORT"
echo "Requests: $NUM_REQUESTS"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Set up iptables NFQUEUE rule
# ---------------------------------------------------------------------------
echo "--- Setting up iptables NFQ rule ---"
# Queue outbound HTTP traffic to NFQUEUE 0
iptables -I OUTPUT -p tcp --dport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -I INPUT -p tcp --sport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true

cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    iptables -D OUTPUT -p tcp --dport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true
    iptables -D INPUT -p tcp --sport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true
    # Kill censorlab if we started it
    if [ -n "${CENSOR_PID:-}" ]; then
        kill "$CENSOR_PID" 2>/dev/null || true
        wait "$CENSOR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 2: Start CensorLab in NFQ mode (background)
# ---------------------------------------------------------------------------
echo "--- Starting CensorLab (NFQ mode) ---"
censorlab -c "$EXPERIMENT_DIR/censor.toml" nfq &
CENSOR_PID=$!
sleep 2  # Give censorlab time to initialize

if ! kill -0 "$CENSOR_PID" 2>/dev/null; then
    echo "ERROR: CensorLab failed to start"
    exit 1
fi
echo "  CensorLab PID: $CENSOR_PID"

# ---------------------------------------------------------------------------
# Step 3: Run traffic generator
# ---------------------------------------------------------------------------
echo ""
echo "--- Running traffic generator ---"
python3 "$SCRIPT_DIR/generate_traffic.py" \
    --host "$TARGET_HOST" \
    --port "$TARGET_PORT" \
    --num-requests "$NUM_REQUESTS" \
    --output "$RESULTS_DIR/live_eval_results.csv"

# ---------------------------------------------------------------------------
# Step 4: Analyze results
# ---------------------------------------------------------------------------
echo ""
echo "--- Analysis ---"
python3 "$SCRIPT_DIR/analyze.py" --live-eval "$RESULTS_DIR/live_eval_results.csv"

echo ""
echo "=== Evaluation complete ==="
echo "Results: $RESULTS_DIR/live_eval_results.csv"
