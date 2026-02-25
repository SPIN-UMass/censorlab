#!/usr/bin/env bash
# run_all_docker.sh — Build the Docker image and run all experiments.
#
# One-command entry point for non-Nix users. Builds the nix-in-docker
# image, then runs the full PCAP-mode pipeline inside the container.
# Results are written back to the host via a bind mount.
#
# Usage:
#   bash experiments/scripts/run_all_docker.sh [ITERATIONS]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ITERATIONS="${1:-3}"
IMAGE_NAME="censorlab-experiments"

echo "=== Building Docker image ==="
docker build -f "$REPO_ROOT/experiments/Dockerfile" -t "$IMAGE_NAME" "$REPO_ROOT"
echo ""

echo "=== Running all experiments (iterations=$ITERATIONS) ==="
docker run --rm \
    -v "$REPO_ROOT/experiments:/censorlab/experiments" \
    "$IMAGE_NAME" \
    bash experiments/scripts/run_all.sh "$ITERATIONS"
