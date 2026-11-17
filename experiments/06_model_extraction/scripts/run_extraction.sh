#!/usr/bin/env bash
# run_extraction.sh — Model Extraction Experiment, client side.
#
# Runs on the client host: starts CensorLab in Tap (NFQ) mode with the
# "extractor" model, sends NUM_PROBES probe connections whose first two data
# packets have random lengths to the probe sink (probe_server.py) on
# TARGET_HOST, then analyzes and plots the outcomes.
#
# Normally invoked by run_docker.sh, which creates the two-container topology
# (client with CensorLab + sink on another container) and runs this script in
# the client container.  The sink must be on another host: traffic to a local
# address would cross CensorLab's OUTPUT and PREROUTING hooks twice (every
# packet counted twice by censor.py), and loopback addresses have no
# direction, so CensorLab ignores them by default.
#
# Prerequisites (all present in the censorlab-experiments image):
#   - censorlab, iptables, CAP_NET_ADMIN + CAP_NET_RAW
#   - model.onnx (python3 experiments/06_model_extraction/train_model.py)
#   - python3 with numpy, matplotlib, scikit-learn, onnxruntime
#   - probe_server.py running on TARGET_HOST:TARGET_PORT, logging to SERVER_LOG
#
# Usage:
#   TARGET_HOST=172.31.6.20 bash experiments/06_model_extraction/scripts/run_extraction.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$EXPERIMENT_DIR/results"

TARGET_HOST="${TARGET_HOST:?set TARGET_HOST to the probe sink (see run_docker.sh)}"
TARGET_PORT="${TARGET_PORT:-8888}"
NUM_PROBES="${NUM_PROBES:-10000}"
MAX_LEN="${MAX_LEN:-1500}"
SEED="${SEED:-42}"
WORKERS="${WORKERS:-16}"
SERVER_LOG="${SERVER_LOG:-$RESULTS_DIR/server_log.csv}"

case "$TARGET_HOST" in
    127.*|localhost|::1)
        echo "ERROR: TARGET_HOST must be another host, not loopback (see header)" >&2
        exit 1 ;;
esac
if [ ! -f "$EXPERIMENT_DIR/model.onnx" ]; then
    echo "ERROR: model.onnx not found; run: python3 $EXPERIMENT_DIR/train_model.py" >&2
    exit 1
fi
mkdir -p "$RESULTS_DIR"

echo "=== Experiment 6: Model Extraction ==="
echo "Target: $TARGET_HOST:$TARGET_PORT  probes: $NUM_PROBES  lengths: 1-$MAX_LEN  seed: $SEED"

cleanup() {
    if [ -n "${CENSOR_PID:-}" ] && kill -0 "$CENSOR_PID" 2>/dev/null; then
        kill -INT "$CENSOR_PID" 2>/dev/null || true
        wait "$CENSOR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# CensorLab installs (and on exit removes) its own NFQUEUE rules in
# raw/PREROUTING and raw/OUTPUT
echo "--- Starting CensorLab (Tap/NFQ mode) ---"
censorlab -c "$EXPERIMENT_DIR/censor.toml" nfq > "$RESULTS_DIR/censorlab.log" 2>&1 &
CENSOR_PID=$!
for _ in $(seq 1 50); do
    if iptables -t raw -S OUTPUT 2>/dev/null | grep -q "CENSORLAB NFQ TAP" &&
       iptables -t raw -S PREROUTING 2>/dev/null | grep -q "CENSORLAB NFQ TAP"; then
        break
    fi
    kill -0 "$CENSOR_PID" 2>/dev/null || { echo "ERROR: CensorLab exited"; cat "$RESULTS_DIR/censorlab.log"; exit 1; }
    sleep 0.2
done
iptables -t raw -S | grep "CENSORLAB NFQ TAP" || { echo "ERROR: NFQUEUE rules not installed"; exit 1; }

echo "--- Sending probes ---"
python3 "$SCRIPT_DIR/generate_probes.py" \
    --host "$TARGET_HOST" --port "$TARGET_PORT" --n "$NUM_PROBES" \
    --max-len "$MAX_LEN" --seed "$SEED" --workers "$WORKERS" \
    --server-log "$SERVER_LOG" --output "$RESULTS_DIR/probe_results.csv"

kill -0 "$CENSOR_PID" 2>/dev/null || { echo "ERROR: CensorLab exited during the run"; exit 1; }
cleanup
CENSOR_PID=
echo "CensorLab censorship events: $(grep -c 'Censorship event' "$RESULTS_DIR/censorlab.log" || true)"

echo "--- Analysis ---"
python3 "$SCRIPT_DIR/analyze.py" --input "$RESULTS_DIR/probe_results.csv"

echo "--- Plot ---"
python3 "$SCRIPT_DIR/plot_extraction.py" \
    --input "$RESULTS_DIR/probe_results.csv" --output "$RESULTS_DIR/model_extraction.pdf"

echo "=== Model extraction experiment complete ==="
