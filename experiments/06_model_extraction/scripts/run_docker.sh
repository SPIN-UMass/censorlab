#!/usr/bin/env bash
# run_docker.sh — run Experiment 6 (model extraction) in Docker, no host sudo.
#
# Topology (one user-defined bridge, MTU 9000 so a 1500-byte probe segment is
# never split by TCP segmentation):
#
#   client 172.31.6.10  (CensorLab Tap/NFQ + probes; NET_ADMIN, NET_RAW)
#      └──▶ sink 172.31.6.20:8888 (probe_server.py; records bytes per connection)
#
# CensorLab runs on the client host as in the paper.  Each packet crosses
# exactly one of its hooks: outgoing raw/OUTPUT, incoming raw/PREROUTING.
#
# Usage:
#   bash experiments/06_model_extraction/scripts/run_docker.sh
#   NUM_PROBES=500 bash experiments/06_model_extraction/scripts/run_docker.sh
#
# Requires the censorlab-experiments image (experiments/scripts/run_all_docker.sh
# builds it) and a trained model.onnx (train_model.py; committed).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(dirname "$SCRIPT_DIR")"
EXPERIMENTS="$(dirname "$EXP_DIR")"
IMAGE="${IMAGE:-censorlab-experiments}"
NET=censorlab-exp06
SUBNET=172.31.6.0/24
CLIENT_IP=172.31.6.10
SINK_IP=172.31.6.20
SINK=censorlab-exp06-sink
MNT=/censorlab/experiments
RESULTS="$MNT/06_model_extraction/results"

cleanup() {
    docker rm -f "$SINK" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    # Files written by the (root) containers back to the invoking user
    docker run --rm -v "$EXPERIMENTS/06_model_extraction:/x" --entrypoint chown "$IMAGE" \
        -R "$(id -u):$(id -g)" /x >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create --driver bridge --subnet "$SUBNET" \
    -o com.docker.network.driver.mtu=9000 "$NET" >/dev/null

docker run -d --name "$SINK" --network "$NET" --ip "$SINK_IP" \
    -v "$EXPERIMENTS:$MNT" "$IMAGE" \
    python3 "$MNT/06_model_extraction/scripts/probe_server.py" \
        --port 8888 --log "$RESULTS/server_log.csv" >/dev/null
for _ in $(seq 1 50); do
    docker logs "$SINK" 2>&1 | grep -q "probe sink listening" && break
    sleep 0.2
done
docker logs "$SINK" 2>&1 | grep -q "probe sink listening" || { docker logs "$SINK"; exit 1; }

docker run --rm --network "$NET" --ip "$CLIENT_IP" \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    -e TARGET_HOST="$SINK_IP" -e TARGET_PORT=8888 \
    -e NUM_PROBES="${NUM_PROBES:-10000}" -e SEED="${SEED:-42}" -e WORKERS="${WORKERS:-16}" \
    -e SERVER_LOG="$RESULTS/server_log.csv" \
    -v "$EXPERIMENTS:$MNT" "$IMAGE" \
    bash "$MNT/06_model_extraction/scripts/run_extraction.sh"
