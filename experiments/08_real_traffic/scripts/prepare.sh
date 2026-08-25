#!/usr/bin/env bash
# prepare.sh — fetch the background dataset and build every scenario × mix PCAP.
#
# Outputs pcap/<scenario>_<mix>.pcap and pcap/<scenario>_<mix>.labels.csv
# (git-ignored; regenerated deterministically from the scenario PCAPs and the
# dataset, which is itself checksum-verified).
#
# Usage: bash experiments/08_real_traffic/scripts/prepare.sh [SCENARIO ...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(dirname "$SCRIPT_DIR")"
EXPERIMENTS="$(dirname "$EXP_DIR")"
DATASET_DIR="$EXPERIMENTS/datasets/ustc-tfc2016"

# shellcheck source=../../common/scenario.sh
source "$EXPERIMENTS/common/scenario.sh"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=("${DEFAULT_SCENARIOS[@]}")

bash "$EXPERIMENTS/datasets/fetch_ustc_tfc2016.sh"
mapfile -t BACKGROUND < <(ls "$DATASET_DIR"/*.pcap | sort)
echo "Background captures: ${BACKGROUND[*]##*/}"

load_mixes "$EXP_DIR/mixes.conf"
mkdir -p "$EXP_DIR/pcap"

for scenario in "${SCENARIOS[@]}"; do
    load_scenario "$EXPERIMENTS/$scenario"
    spcap="$SC_DIR/$(sc_get PCAP)"
    slabels="$SC_DIR/$(sc_get LABELS)"
    [ -f "$spcap" ] || python3 "$SC_DIR/$(sc_get GENERATE)"
    for mix in "${MIX_NAMES[@]}"; do
        n="${MIX_PACKETS[$mix]}"
        out="$EXP_DIR/pcap/${scenario}_${mix}.pcap"
        lbl="$EXP_DIR/pcap/${scenario}_${mix}.labels.csv"
        if [ -f "$out" ] && [ -f "$lbl" ] && [ "$out" -nt "$spcap" ]; then
            echo "  [ok]  ${scenario}_${mix}"
            continue
        fi
        if [ "$n" -eq 0 ]; then
            cp "$spcap" "$out"
            cp "$slabels" "$lbl"
            echo "  [cp]  ${scenario}_${mix}"
        else
            printf '  [mix] %s: ' "${scenario}_${mix}"
            python3 "$EXPERIMENTS/datasets/interleave.py" \
                --scenario-pcap "$spcap" --scenario-labels "$slabels" \
                --background "${BACKGROUND[@]}" --background-packets "$n" \
                --output "$out" --output-labels "$lbl"
        fi
    done
done
echo "PCAPs in $EXP_DIR/pcap"
