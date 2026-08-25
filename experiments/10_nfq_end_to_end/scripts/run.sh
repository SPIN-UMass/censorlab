#!/usr/bin/env bash
# run.sh — live NFQ end-to-end evaluation (MR2): accuracy, latency, throughput.
#
# For every scenario × censor variant the Compose topology is brought up with
# CensorLab in NFQ mode on the censor container, the client runs the latency
# probe, an iperf3 transfer and the scenario's live traffic generator, and the
# results land in results/<scenario>/<variant>/.
#
# Variants:
#   none        no CensorLab process — plain forwarding (baseline)
#   null        CensorLab NFQ with demos/null (every packet queued, no program work)
#   pycl        CensorLab NFQ with the scenario's PyCL program
#   censorlang  CensorLab NFQ with the scenario's CensorLang program
#
# Usage:
#   bash experiments/10_nfq_end_to_end/scripts/run.sh [N_REQUESTS] [PROBE_N] [IPERF_SECONDS]
#   SCENARIOS="03_tls_sni" VARIANTS="none pycl" bash …/run.sh
#
# Requires: docker with the censorlab-live image loaded
#   nix build .#docker-live && docker load < result
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(dirname "$SCRIPT_DIR")"
EXPERIMENTS="$(dirname "$EXP_DIR")"
REPO_ROOT="$(dirname "$EXPERIMENTS")"
N_REQUESTS="${1:-200}"
PROBE_N="${2:-200}"
IPERF_SECONDS="${3:-5}"
read -r -a SCENARIOS <<< "${SCENARIOS:-01_http_keyword 02_dns_injection 03_tls_sni 04_shadowsocks}"
read -r -a VARIANTS <<< "${VARIANTS:-none null pycl censorlang}"
CLIENT_IP=172.30.0.10
COMPOSE=(docker compose -f "$EXP_DIR/docker-compose.yml" -p censorlab-nfq)

if ! docker image inspect censorlab-live:latest >/dev/null 2>&1; then
    echo "censorlab-live image missing: nix build .#docker-live && docker load < result" >&2
    exit 1
fi

censor_cmd() {
    local scenario="$1" variant="$2"
    case "$variant" in
        none)       echo "sleep infinity" ;;
        null)       echo "censorlab -c /censorlab/demos/null/censor.toml nfq --client-ip $CLIENT_IP" ;;
        pycl)       echo "censorlab -c /censorlab/experiments/$scenario/censor.toml nfq --client-ip $CLIENT_IP" ;;
        censorlang) echo "censorlab -c /censorlab/experiments/$scenario/censor_lang.toml nfq --client-ip $CLIENT_IP" ;;
        *) echo "unknown variant $variant" >&2; return 1 ;;
    esac
}

cleanup() { "${COMPOSE[@]}" down -t 1 >/dev/null 2>&1 || true; }
trap cleanup EXIT

for scenario in "${SCENARIOS[@]}"; do
    for variant in "${VARIANTS[@]}"; do
        results="$EXP_DIR/results/$scenario/$variant"
        mkdir -p "$results"
        echo ""
        echo "################  $scenario × $variant  ################"
        export REPO="$REPO_ROOT" RESULTS="$results"
        export CENSOR_CMD; CENSOR_CMD="$(censor_cmd "$scenario" "$variant")"
        export CLIENT_CMD="SCENARIO=$scenario N_REQUESTS=$N_REQUESTS PROBE_N=$PROBE_N IPERF_SECONDS=$IPERF_SECONDS bash /censorlab/experiments/10_nfq_end_to_end/scripts/client.sh"
        cleanup
        if "${COMPOSE[@]}" up --abort-on-container-exit --exit-code-from client --no-color 2>&1 \
                | grep -E '^client-1' | sed 's/^client-1  | //' | tee "$results/client.log"; then
            echo "  [ok] $scenario/$variant"
        else
            echo "  [FAILED] $scenario/$variant (see $results/client.log)"
        fi
        "${COMPOSE[@]}" logs --no-color censor > "$results/censor.log" 2>&1 || true
        cleanup
    done
done

python3 "$SCRIPT_DIR/analyze.py"
