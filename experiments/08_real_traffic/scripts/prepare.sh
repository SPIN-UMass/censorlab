#!/usr/bin/env bash
# prepare.sh — fetch the background dataset(s) and build every scenario × mix PCAP.
#
# Outputs pcap/<scenario>_<mixid>.pcap and pcap/<scenario>_<mixid>.labels.csv
# (git-ignored; regenerated deterministically from the scenario PCAPs and the
# datasets, which are themselves checksum-verified).  <mixid> is the mix name
# for BACKGROUND=ustc and <mix>_<background> otherwise (see common.sh).
#
# Usage: [BACKGROUND=ustc|iscx|combined] bash experiments/08_real_traffic/scripts/prepare.sh [SCENARIO ...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(dirname "$SCRIPT_DIR")"
EXPERIMENTS="$(dirname "$EXP_DIR")"
USTC_DIR="$EXPERIMENTS/datasets/ustc-tfc2016"
ISCX_DIR="$EXPERIMENTS/datasets/iscxvpn2016"   # symlink to $ISCXVPN2016_DIR

# shellcheck source=../../common/scenario.sh
source "$EXPERIMENTS/common/scenario.sh"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"
check_background

SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=("${DEFAULT_SCENARIOS[@]}")

# One --background group per dataset; interleave.py splits each mix's packet
# budget evenly across groups.
BG_ARGS=()
DATASET_STAMPS=()
if [ "$BACKGROUND" = ustc ] || [ "$BACKGROUND" = combined ]; then
    bash "$EXPERIMENTS/datasets/fetch_ustc_tfc2016.sh"
    mapfile -t USTC < <(ls "$USTC_DIR"/*.pcap | sort)
    echo "USTC-TFC2016 captures: ${USTC[*]##*/}"
    BG_ARGS+=(--background "${USTC[@]}")
fi
if [ "$BACKGROUND" = iscx ] || [ "$BACKGROUND" = combined ]; then
    bash "$EXPERIMENTS/datasets/fetch_iscxvpn2016.sh"
    mapfile -t ISCX < <(ls "$ISCX_DIR"/pcap/*.pcap | sort)
    echo "ISCXVPN2016 captures:  ${ISCX[*]##*/}"
    BG_ARGS+=(--background "${ISCX[@]}")
    DATASET_STAMPS+=("$ISCX_DIR/SHA256SUMS")
fi

load_mixes "$EXP_DIR/mixes.conf"
mkdir -p "$EXP_DIR/pcap"

# fresh <out> <dep>... — true if <out> is newer than every dependency
fresh() {
    local out="$1" dep
    shift
    for dep in "$@"; do
        [ "$out" -nt "$dep" ] || return 1
    done
}

for scenario in "${SCENARIOS[@]}"; do
    load_scenario "$EXPERIMENTS/$scenario"
    spcap="$SC_DIR/$(sc_get PCAP)"
    slabels="$SC_DIR/$(sc_get LABELS)"
    [ -f "$spcap" ] || python3 "$SC_DIR/$(sc_get GENERATE)"
    for mix in "${MIX_NAMES[@]}"; do
        n="${MIX_PACKETS[$mix]}"
        id="$(mix_id "$mix")"
        out="$EXP_DIR/pcap/${scenario}_${id}.pcap"
        lbl="$EXP_DIR/pcap/${scenario}_${id}.labels.csv"
        if [ -f "$out" ] && [ -f "$lbl" ] && fresh "$out" "$spcap" "${DATASET_STAMPS[@]}"; then
            echo "  [ok]  ${scenario}_${id}"
            continue
        fi
        if [ "$n" -eq 0 ]; then
            cp "$spcap" "$out"
            cp "$slabels" "$lbl"
            echo "  [cp]  ${scenario}_${id}"
        else
            printf '  [mix] %s: ' "${scenario}_${id}"
            python3 "$EXPERIMENTS/datasets/interleave.py" \
                --scenario-pcap "$spcap" --scenario-labels "$slabels" \
                "${BG_ARGS[@]}" --background-packets "$n" \
                --output "$out" --output-labels "$lbl"
        fi
    done
done
echo "PCAPs in $EXP_DIR/pcap"
