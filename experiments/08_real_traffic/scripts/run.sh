#!/usr/bin/env bash
# run.sh — measure every tool on every scenario × background mix.
#
# For each (scenario, mix) the shared Table 4 harness is run on the mixed PCAP
# (warm-up, randomized interleaved iterations, per-tool startup baseline) and
# analysed against the mix's re-indexed labels.  Results land in
# results/<scenario>/<mixid>/ (raw_timings.csv, table4.json, accuracy.json, …),
# where <mixid> is the mix name for BACKGROUND=ustc and <mix>_<background>
# otherwise (see common.sh).
#
# Usage:
#   bash experiments/08_real_traffic/scripts/run.sh [ITERATIONS] [WARMUP]
#   SCENARIOS="03_tls_sni" MIXES="bg0 bg90k" TOOLS="PyCL Zeek" bash …/run.sh 3
#   BACKGROUND=ustc bash …/run.sh 3      # USTC-TFC2016 only (default: combined)
#
# CensorLab's connection table is sized so that no connection is evicted for
# space: the largest mixes have more flows (bg390k: 117 909 for ustc, 75 240
# for combined) than the default max_connections of 65 536.  The default here
# exceeds the packet count of every mix; set CENSORLAB_MAX_CONNECTIONS to
# change it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(dirname "$SCRIPT_DIR")"
EXPERIMENTS="$(dirname "$EXP_DIR")"
ITERATIONS="${1:-3}"
WARMUP="${2:-1}"

# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"
check_background
export CENSORLAB_MAX_CONNECTIONS="${CENSORLAB_MAX_CONNECTIONS:-1000000}"
load_mixes "$EXP_DIR/mixes.conf"

read -r -a SCENARIOS <<< "${SCENARIOS:-${DEFAULT_SCENARIOS[*]}}"
read -r -a MIXES <<< "${MIXES:-${MIX_NAMES[*]}}"

for scenario in "${SCENARIOS[@]}"; do
    for mix in "${MIXES[@]}"; do
        id="$(mix_id "$mix")"
        pcap="$EXP_DIR/pcap/${scenario}_${id}.pcap"
        labels="$EXP_DIR/pcap/${scenario}_${id}.labels.csv"
        if [ ! -f "$pcap" ]; then
            echo "missing $pcap — run BACKGROUND=$BACKGROUND scripts/prepare.sh first" >&2
            exit 1
        fi
        results="$EXP_DIR/results/$scenario/$id"
        echo ""
        echo "################  $scenario × $id  (${MIX_PACKETS[$mix]} background packets, $BACKGROUND)  ################"
        PCAP="$pcap" RESULTS_DIR="$results" \
            bash "$EXPERIMENTS/common/showcase.sh" "$EXPERIMENTS/$scenario" "$ITERATIONS" "$WARMUP"
        python3 "$EXPERIMENTS/common/analyze_showcase.py" "$EXPERIMENTS/$scenario" \
            --results "$results" --pcap "$pcap" --labels "$labels"
    done
done

python3 "$SCRIPT_DIR/analyze.py"
