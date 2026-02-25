#!/usr/bin/env bash
# run_all_docker.sh — Build the Docker image and run all experiments.
#
# One-command entry point for non-Nix users. Builds the nix-in-docker
# image, then runs the full PCAP-mode pipeline inside the container.
# Results are written back to the host via a bind mount.
#
# Usage:
#   bash experiments/scripts/run_all_docker.sh [ITERATIONS]
#
# Options (via environment variables):
#   REBUILD=1  Force rebuild of the Docker image even if it exists

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ITERATIONS="${1:-3}"
IMAGE_NAME="censorlab-experiments"
REBUILD="${REBUILD:-0}"

if [ "$REBUILD" = "1" ] || ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "=== Building Docker image ==="
    docker build -f "$REPO_ROOT/experiments/Dockerfile" -t "$IMAGE_NAME" "$REPO_ROOT"
    echo ""
else
    echo "=== Docker image '$IMAGE_NAME' already exists (set REBUILD=1 to force rebuild) ==="
fi

echo "=== Running all experiments (iterations=$ITERATIONS) ==="
docker run --rm \
    -v "$REPO_ROOT/experiments:/censorlab/experiments" \
    "$IMAGE_NAME" \
    bash experiments/scripts/run_all.sh "$ITERATIONS"
