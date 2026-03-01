#!/usr/bin/env bash
# run_evaluation.sh — Table 3: Live NFQ TPR/TNR evaluation
#
# Starts CensorLab in NFQ mode, runs the traffic generator to send
# DNS queries through the censor, and computes TPR/TNR.
#
# Prerequisites:
#   - CensorLab built with: cargo build --release
#   - Network capabilities set: ./set_permissions.sh
#   - iptables NFQ rule configured (see below)
#
# Usage:
#   sudo bash experiments/02_dns_injection/scripts/run_evaluation.sh
#
# This script is designed to run inside the Docker Compose environment
# (experiments/docker-compose.yml) or on a configured host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$EXPERIMENT_DIR/results"

RESOLVER="${RESOLVER:-127.0.0.1}"
NUM_QUERIES="${NUM_QUERIES:-500}"

mkdir -p "$RESULTS_DIR"

echo "=== Experiment 2: DNS Injection — Evaluation (Table 3) ==="
echo "Resolver: $RESOLVER"
echo "Queries per class: $NUM_QUERIES"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Set up iptables NFQUEUE rule
# ---------------------------------------------------------------------------
echo "--- Setting up iptables NFQ rule ---"
# Queue outbound DNS traffic (UDP port 53) to NFQUEUE 0
iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0 2>/dev/null || true

cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0 2>/dev/null || true
    iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0 2>/dev/null || true
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
    --resolver "$RESOLVER" \
    --n "$NUM_QUERIES" \
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
