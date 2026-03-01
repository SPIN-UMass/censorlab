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
# The Docker image is automatically rebuilt when source files change.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ITERATIONS="${1:-3}"
IMAGE_NAME="censorlab-experiments"

# Compute a fingerprint of files that affect the Docker image.
# Uses git so it's portable across Linux and macOS.
# NOTE: These paths must match the COPY sources in the Dockerfile.
compute_build_hash() {
    (cd "$REPO_ROOT" && {
        git rev-parse HEAD
        git diff HEAD -- docker/ flake.nix flake.lock Cargo.toml Cargo.lock \
            build.rs src/ demos/ website/ .gitmodules
        git submodule status
    } 2>/dev/null | git hash-object --stdin 2>/dev/null) || echo "unknown"
}

BUILD_HASH=$(compute_build_hash)
STORED_HASH=$(docker inspect --format '{{index .Config.Labels "censorlab.build_hash"}}' \
    "$IMAGE_NAME" 2>/dev/null || echo "")

if [ "$BUILD_HASH" = "unknown" ] || [ "$BUILD_HASH" != "$STORED_HASH" ]; then
    echo "=== Building Docker image (source changes detected) ==="
    docker build -f "$REPO_ROOT/docker/Dockerfile" \
        --build-arg BUILD_HASH="$BUILD_HASH" \
        -t "$IMAGE_NAME" "$REPO_ROOT"
    echo ""
else
    echo "=== Docker image '$IMAGE_NAME' is up to date ==="
fi

echo "=== Running all experiments (iterations=$ITERATIONS) ==="
docker run --rm \
    -v "$REPO_ROOT/experiments:/censorlab/experiments" \
    "$IMAGE_NAME" \
    bash experiments/scripts/run_all.sh "$ITERATIONS"

# Copy results.tex to paper repo if available
PAPER_RESULTS="$REPO_ROOT/../clab-paper/experiments/results.tex"
EXP_RESULTS="$REPO_ROOT/experiments/results.tex"
if [ -f "$EXP_RESULTS" ]; then
    if [ -d "$(dirname "$PAPER_RESULTS")" ]; then
        cp "$EXP_RESULTS" "$PAPER_RESULTS"
        echo "=== Copied results.tex → clab-paper/experiments/results.tex ==="
    else
        echo ""
        echo "=== ACTION REQUIRED ==="
        echo "Copy results.tex to your paper repo:"
        echo "  cp $EXP_RESULTS <paper-repo>/experiments/results.tex"
    fi
fi
