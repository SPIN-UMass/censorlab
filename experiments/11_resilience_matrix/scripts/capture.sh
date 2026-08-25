#!/usr/bin/env bash
# capture.sh — record genuine Shadowsocks, obfs4 and Snowflake traffic.
#
# Brings up docker-compose.yml (server + client containers running the real
# tools) and lets the client tunnel N_FETCHES HTTP fetches through each tool
# while tcpdump records the wire traffic.  PCAPs and per-fetch logs land in
# pcap/ (git-ignored; the PCAPs are regenerated, not committed).
#
# Usage: N_FETCHES=60 bash experiments/11_resilience_matrix/scripts/capture.sh
# Requires: nix build .#docker-circumvention && docker load < result
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$EXP_DIR/../.." && pwd)"
export REPO="$REPO_ROOT" RESULTS="$EXP_DIR/pcap" N_FETCHES="${N_FETCHES:-60}" TOOLS="${TOOLS:-shadowsocks obfs4 snowflake}"
COMPOSE=(docker compose -f "$EXP_DIR/docker-compose.yml" -p censorlab-capture)

if ! docker image inspect censorlab-circumvention:latest >/dev/null 2>&1; then
    echo "censorlab-circumvention image missing: nix build .#docker-circumvention && docker load < result" >&2
    exit 1
fi
mkdir -p "$RESULTS"
cleanup() { "${COMPOSE[@]}" down -t 1 >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
"${COMPOSE[@]}" up --abort-on-container-exit --exit-code-from client --no-color 2>&1 \
    | grep -E '^(client|server)-1' | sed -E 's/^(client|server)-1  \| /\1: /'
cleanup
echo ""
echo "Captures:"
ls -la "$RESULTS"/*.pcap
