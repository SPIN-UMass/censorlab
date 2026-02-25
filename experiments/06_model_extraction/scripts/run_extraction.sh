#!/usr/bin/env bash
# run_extraction.sh — Model Extraction Experiment
#
# Sends connections with random packet lengths through CensorLab
# and records the censoring decision to reconstruct the model boundary.
#
# Steps:
#   1. Set up iptables NFQUEUE rule (Tap mode — observe only)
#   2. Start CensorLab in NFQ mode
#   3. Start a simple TCP echo server
#   4. Send 10,000 probe connections with random packet length pairs
#   5. Record which pairs were blocked vs allowed
#   6. Generate scatter plot of results
#
# Prerequisites:
#   - CensorLab built with: cargo build --release
#   - Network capabilities set: ./set_permissions.sh
#   - model.onnx trained and placed in experiment directory
#   - python3 with matplotlib and numpy for plotting
#
# Usage:
#   sudo bash experiments/06_model_extraction/scripts/run_extraction.sh
#
# This script is designed to run inside the Docker Compose environment
# (experiments/docker-compose.yml) or on a configured host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$EXPERIMENT_DIR/results"

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-8888}"
NUM_PROBES="${NUM_PROBES:-10000}"
MAX_LEN="${MAX_LEN:-1500}"
SEED="${SEED:-42}"

mkdir -p "$RESULTS_DIR"

echo "=== Experiment 6: Model Extraction — Reconstructing Decision Boundary ==="
echo "Target: $TARGET_HOST:$TARGET_PORT"
echo "Probes: $NUM_PROBES"
echo "Max packet length: $MAX_LEN"
echo "Seed: $SEED"
echo ""

# ---------------------------------------------------------------------------
# Verify model exists
# ---------------------------------------------------------------------------
if [ ! -f "$EXPERIMENT_DIR/model.onnx" ]; then
    echo "ERROR: model.onnx not found in $EXPERIMENT_DIR"
    echo "Train the model first and place model.onnx in the experiment directory."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Set up iptables NFQUEUE rule
# ---------------------------------------------------------------------------
echo "--- Setting up iptables NFQ rule (Tap mode) ---"
iptables -I OUTPUT -p tcp --dport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -I INPUT  -p tcp --sport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true

cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    iptables -D OUTPUT -p tcp --dport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true
    iptables -D INPUT  -p tcp --sport "$TARGET_PORT" -j NFQUEUE --queue-num 0 2>/dev/null || true
    # Kill censorlab if we started it
    if [ -n "${CENSOR_PID:-}" ]; then
        kill "$CENSOR_PID" 2>/dev/null || true
        wait "$CENSOR_PID" 2>/dev/null || true
    fi
    # Kill echo server if we started it
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 2: Start CensorLab in NFQ mode (background)
# ---------------------------------------------------------------------------
echo "--- Starting CensorLab (NFQ / Tap mode) ---"
censorlab -c "$EXPERIMENT_DIR/censor.toml" nfq &
CENSOR_PID=$!
sleep 2  # Give censorlab time to initialize

if ! kill -0 "$CENSOR_PID" 2>/dev/null; then
    echo "ERROR: CensorLab failed to start"
    exit 1
fi
echo "  CensorLab PID: $CENSOR_PID"

# ---------------------------------------------------------------------------
# Step 3: Start a simple TCP echo server (background)
# ---------------------------------------------------------------------------
echo "--- Starting TCP echo server on port $TARGET_PORT ---"
python3 -c "
import socket, threading, sys

def handle(conn):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
    except Exception:
        pass
    finally:
        conn.close()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', int(sys.argv[1])))
srv.listen(128)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
" "$TARGET_PORT" &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: Echo server failed to start"
    exit 1
fi
echo "  Echo server PID: $SERVER_PID"

# ---------------------------------------------------------------------------
# Step 4: Send probe connections
# ---------------------------------------------------------------------------
echo ""
echo "--- Sending $NUM_PROBES probe connections ---"
python3 "$SCRIPT_DIR/generate_probes.py" \
    --host "$TARGET_HOST" \
    --port "$TARGET_PORT" \
    --n "$NUM_PROBES" \
    --max-len "$MAX_LEN" \
    --seed "$SEED" \
    --output "$RESULTS_DIR/probe_results.csv"

# ---------------------------------------------------------------------------
# Step 5: Analyze results
# ---------------------------------------------------------------------------
echo ""
echo "--- Analysis ---"
python3 "$SCRIPT_DIR/analyze.py" --input "$RESULTS_DIR/probe_results.csv"

# ---------------------------------------------------------------------------
# Step 6: Generate scatter plot
# ---------------------------------------------------------------------------
echo ""
echo "--- Generating scatter plot ---"
python3 "$SCRIPT_DIR/plot_extraction.py" \
    --input "$RESULTS_DIR/probe_results.csv" \
    --output "$RESULTS_DIR/model_extraction.pdf"

echo ""
echo "=== Model extraction experiment complete ==="
echo "Results:    $RESULTS_DIR/probe_results.csv"
echo "Analysis:   $RESULTS_DIR/extraction_stats.json"
echo "Plot:       $RESULTS_DIR/model_extraction.pdf"
