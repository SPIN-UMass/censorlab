#!/usr/bin/env bash
# censorlab.sh — Run CensorLab in Docker with one command.
#
# Builds the Docker image if needed, auto-detects NFQ vs PCAP mode,
# and picks the right Compose service (host networking + capabilities
# for NFQ, isolated container otherwise).
#
# Usage:
#   bash docker/censorlab.sh [censorlab args...]
#   bash docker/censorlab.sh --shell          (NFQ-capable shell, host networking)
#   bash docker/censorlab.sh --shell-no-nfq   (isolated shell, no host networking)
#   bash docker/censorlab.sh -c demos/dns_blocking/censor.toml nfq
#   bash docker/censorlab.sh -c censor.toml pcap traffic.pcap
#
# The image is automatically rebuilt when source files change.
#
# Environment variables:
#   DOCKER_ARGS    Extra arguments passed to `docker compose run`
#                  e.g. DOCKER_ARGS="-v /path/to/configs:/censorlab/custom"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure git submodules are initialized (needed for website assets like Font Awesome)
if [ -f "$REPO_ROOT/.gitmodules" ] && command -v git &>/dev/null; then
    git -C "$REPO_ROOT" submodule update --init --recursive 2>/dev/null || true
fi

# Compute a fingerprint of files that affect the Docker image.
# Uses git so it's portable across Linux and macOS.
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
    censorlab:latest 2>/dev/null || echo "")

if [ "$BUILD_HASH" = "unknown" ] || [ "$BUILD_HASH" != "$STORED_HASH" ]; then
    echo "=== Building CensorLab Docker image ==="
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" build \
        --build-arg BUILD_HASH="$BUILD_HASH" censorlab
    echo ""
fi

# --shell flag: drop into an interactive shell (with host networking + NET_ADMIN/NET_RAW by default)
# Use --shell-no-nfq for a shell without host networking/capabilities
if [ "${1:-}" = "--shell" ] || [ "${1:-}" = "--shell-no-nfq" ]; then
    SERVICE="censorlab-nfq"
    if [ "${1:-}" = "--shell-no-nfq" ]; then
        SERVICE="censorlab"
    fi
    # shellcheck disable=SC2086
    exec docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm \
        --service-ports ${DOCKER_ARGS:-} "$SERVICE" bash
fi

# Auto-detect NFQ mode by scanning args for "nfq"
SERVICE="censorlab"
for arg in "$@"; do
    if [ "$arg" = "nfq" ]; then
        SERVICE="censorlab-nfq"
        break
    fi
done

# shellcheck disable=SC2086
exec docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm \
    ${DOCKER_ARGS:-} "$SERVICE" censorlab "$@"
