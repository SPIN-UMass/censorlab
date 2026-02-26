#!/usr/bin/env bash
# censorlab.sh — Run CensorLab in Docker with one command.
#
# Builds the Docker image if needed, auto-detects NFQ vs PCAP mode,
# and picks the right Compose service (host networking + capabilities
# for NFQ, isolated container otherwise).
#
# Usage:
#   bash docker/censorlab.sh [censorlab args...]
#   bash docker/censorlab.sh --shell
#   bash docker/censorlab.sh -c demos/dns_blocking/censor.toml nfq
#   bash docker/censorlab.sh -c censor.toml pcap traffic.pcap
#
# Environment variables:
#   REBUILD=1      Force rebuild of the Docker image
#   DOCKER_ARGS    Extra arguments passed to `docker compose run`
#                  e.g. DOCKER_ARGS="-v /path/to/configs:/censorlab/custom"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REBUILD="${REBUILD:-0}"

# Build image if missing or rebuild requested
if [ "$REBUILD" = "1" ] || ! docker image inspect censorlab:latest &>/dev/null; then
    echo "=== Building CensorLab Docker image ==="
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" build censorlab
    echo ""
fi

# --shell flag: drop into an interactive shell
# Use --shell-nfq for a shell with host networking + NET_ADMIN/NET_RAW
if [ "${1:-}" = "--shell" ] || [ "${1:-}" = "--shell-nfq" ]; then
    SERVICE="censorlab"
    if [ "${1:-}" = "--shell-nfq" ]; then
        SERVICE="censorlab-nfq"
    fi
    # shellcheck disable=SC2086
    exec docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm \
        ${DOCKER_ARGS:-} "$SERVICE" bash
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
