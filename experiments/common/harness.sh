#!/usr/bin/env bash
# harness.sh — shared measurement library for the PCAP-mode experiments.
#
# Every tool is run as a separate process and measured the *same* way:
#
#   wall_us     wall-clock time of the whole process ($EPOCHREALTIME, µs)
#   user_us     user CPU time      (GNU time %U)
#   sys_us      system CPU time    (GNU time %S)
#   max_rss_kb  peak resident set  (GNU time %M)
#   time_us     tool-reported processing time where the tool exposes one
#               (CensorLab: "… including I/O"; Scapy: timed loop), else wall_us.
#               This is the legacy Table 4 metric kept for comparability.
#
# Each tool is additionally run against `common/baseline.pcap` (a single ARP
# frame) to measure fixed process startup/teardown cost (phase=baseline), so
# that steady-state cost can be reported as wall − baseline.  This is what
# separates e.g. Zeek's script-compilation startup from its analysis time.
#
# Rows are appended to $RAW_TIMINGS as:
#   tool,iteration,phase,time_us,wall_us,user_us,sys_us,max_rss_kb,exit_code
#
# Requires: bash ≥ 5 (EPOCHREALTIME), GNU time, and the tool binaries on PATH.

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENTS_ROOT="$(dirname "$HARNESS_DIR")"
TOOLS_DIR="$EXPERIMENTS_ROOT/tools"
BASELINE_PCAP="$HARNESS_DIR/baseline.pcap"

# shellcheck source=scenario.sh
source "$HARNESS_DIR/scenario.sh"

TIME_BIN="$(type -P time || true)"
if [ -z "$TIME_BIN" ]; then
    echo "harness: GNU time not found on PATH (nix develop .#experiments provides it)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------

# tool_binary <Tool> — executable that must exist for the tool to run
tool_binary() {
    case "$1" in
        PyCL|CensorLang) echo censorlab ;;
        Zeek)            echo zeek ;;
        Scapy)           echo python3 ;;
        Suricata)        echo suricata ;;
        Snort)           echo snort ;;
        OpenGFW)         echo OpenGFW ;;
    esac
}

tool_available() {
    command -v "$(tool_binary "$1")" >/dev/null 2>&1
}

# Snort 3 resolves `include` relative to --include-path; snort_defaults.lua ships
# in <prefix>/etc/snort next to the binary.
snort_etc_dir() {
    local bin; bin="$(command -v snort)" || return 1
    echo "$(dirname "$(dirname "$(readlink -f "$bin")")")/etc/snort"
}

# ---------------------------------------------------------------------------
# Per-tool command construction.
#   tool_argv <Tool> <pcap> <workdir>   -> sets global array ARGV
# The command is executed with cwd=<workdir>; tools that write logs to cwd
# (Zeek) therefore write into the per-run work directory.
# ---------------------------------------------------------------------------
tool_argv() {
    local tool="$1" pcap="$2" workdir="$3"
    ARGV=()
    case "$tool" in
        PyCL)
            ARGV=(censorlab -c "$SC_DIR/$(sc_get PYCL_CONFIG)" pcap "$pcap" "$(sc_get CLIENT_IP)") ;;
        CensorLang)
            ARGV=(censorlab -c "$SC_DIR/$(sc_get CL_CONFIG)" pcap "$pcap" "$(sc_get CLIENT_IP)") ;;
        Zeek)
            ARGV=(zeek -C -r "$pcap" "$SC_DIR/$(sc_get ZEEK_SCRIPT)") ;;
        Scapy)
            ARGV=(python3 "$SC_DIR/$(sc_get SCAPY_SCRIPT)" "$pcap" --output "$workdir/scapy_decisions.csv") ;;
        Suricata)
            ARGV=(suricata -c "$TOOLS_DIR/suricata/suricata.yaml" -S "$SC_DIR/$(sc_get SURICATA_RULES)"
                  --set "classification-file=$TOOLS_DIR/suricata/classification.config"
                  --set "reference-config-file=$TOOLS_DIR/suricata/reference.config"
                  --set "threshold-file=$TOOLS_DIR/suricata/threshold.config"
                  -r "$pcap" -l "$workdir" -k none --runmode single) ;;
        Snort)
            ARGV=(snort -c "$TOOLS_DIR/snort/snort.lua" --include-path "$(snort_etc_dir)"
                  -R "$SC_DIR/$(sc_get SNORT_RULES)"
                  -r "$pcap" -l "$workdir" -A alert_csv -q) ;;
        OpenGFW)
            ARGV=(OpenGFW -c "$TOOLS_DIR/opengfw/config.yaml" -p "$pcap" -f json
                  "$SC_DIR/$(sc_get OPENGFW_RULES)") ;;
        *)
            echo "tool_argv: unknown tool $tool" >&2; return 1 ;;
    esac
}

# tool_internal_us <Tool> <log> <workdir> — tool-reported processing time in µs, or ""
tool_internal_us() {
    local tool="$1" log="$2" workdir="$3"
    case "$tool" in
        PyCL|CensorLang)
            grep -oP '\(\K\d+(?=us including I/O\))' "$log" | head -1 ;;
        Scapy)
            # scapy_*.py writes seconds to <scenario>/results/scapy_timing.txt
            local tf="$SC_DIR/results/scapy_timing.txt"
            if [ -f "$tf" ]; then
                awk '{ printf "%d", $1 * 1000000 }' "$tf"
            fi ;;
        *)
            echo "" ;;
    esac
}

# tool_collect <Tool> <workdir> <results_dir> — keep first-iteration artifacts
# (raw output + native decision log) for the accuracy report.
tool_collect() {
    local tool="$1" workdir="$2" results="$3" log="$4"
    case "$tool" in
        PyCL)       cp "$log" "$results/pycl_output.txt" ;;
        CensorLang) cp "$log" "$results/censorlang_output.txt" ;;
        Zeek)
            local zlog="$workdir/$(sc_get ZEEK_LOG).log"
            [ -f "$zlog" ] && cp "$zlog" "$results/zeek_matches.log" ;;
        Scapy)
            [ -f "$workdir/scapy_decisions.csv" ] && cp "$workdir/scapy_decisions.csv" "$results/scapy_decisions.csv" ;;
        Suricata)
            [ -f "$workdir/eve.json" ] && cp "$workdir/eve.json" "$results/suricata_eve.json" ;;
        Snort)
            [ -f "$workdir/alert_csv.txt" ] && cp "$workdir/alert_csv.txt" "$results/snort_alerts.csv" ;;
        OpenGFW)    cp "$log" "$results/opengfw_output.jsonl" ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# measure_run <Tool> <iteration> <phase> <pcap> <results_dir>
#   Runs the tool once in a fresh work directory and appends a row to
#   $RAW_TIMINGS.  On the first measured iteration, native outputs are kept.
# ---------------------------------------------------------------------------
measure_run() {
    local tool="$1" iteration="$2" phase="$3" pcap="$4" results="$5"
    local workdir log timefile t0 t1 wall_us rc user_s sys_s rss_kb user_us sys_us internal_us

    workdir="$(mktemp -d)"
    log="$workdir/run.log"
    timefile="$workdir/time.txt"
    rm -f "$SC_DIR/results/scapy_timing.txt"

    tool_argv "$tool" "$pcap" "$workdir" || return 1

    t0=$EPOCHREALTIME
    (
        cd "$workdir" &&
        "$TIME_BIN" -f '%U %S %M' -o "$timefile" -- "${ARGV[@]}" >"$log" 2>&1
    )
    rc=$?
    t1=$EPOCHREALTIME

    wall_us=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%d", (b - a) * 1000000 }')
    if [ -f "$timefile" ]; then
        read -r user_s sys_s rss_kb < <(tail -1 "$timefile")
    else
        user_s=0; sys_s=0; rss_kb=0
    fi
    user_us=$(awk -v s="$user_s" 'BEGIN { printf "%d", s * 1000000 }')
    sys_us=$(awk -v s="$sys_s" 'BEGIN { printf "%d", s * 1000000 }')

    internal_us="$(tool_internal_us "$tool" "$log" "$workdir")"
    [ -z "$internal_us" ] && internal_us="$wall_us"

    echo "$tool,$iteration,$phase,$internal_us,$wall_us,$user_us,$sys_us,$rss_kb,$rc" >> "$RAW_TIMINGS"
    printf '  %-11s %-9s run %-3s wall=%8dus cpu=%8dus rss=%7dKB%s\n' \
        "$tool" "$phase" "$iteration" "$wall_us" "$((user_us + sys_us))" "$rss_kb" \
        "$([ "$rc" -ne 0 ] && echo " exit=$rc" || true)"

    if [ "$phase" = measure ] && [ "$iteration" = 1 ]; then
        tool_collect "$tool" "$workdir" "$results" "$log"
    fi
    if [ "$rc" -ne 0 ]; then
        cp "$log" "$results/${tool,,}_failed_run.log"
    fi
    rm -rf "$workdir"
}

# ---------------------------------------------------------------------------
# LOC: non-blank, non-comment lines.  `#` comments cover Python, CensorLang,
# Zeek (##! too), Suricata/Snort rules, and YAML (OpenGFW).
# ---------------------------------------------------------------------------
count_loc() {
    grep -cve '^\s*$' -e '^\s*#' "$1" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# ensure_baseline_pcap — a one-frame PCAP used to measure process startup cost
# ---------------------------------------------------------------------------
ensure_baseline_pcap() {
    if [ ! -f "$BASELINE_PCAP" ]; then
        python3 - "$BASELINE_PCAP" <<'PY'
import sys
from scapy.all import Ether, ARP, wrpcap
pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.1", pdst="10.0.0.2")
pkt.time = 0
wrpcap(sys.argv[1], [pkt])
PY
    fi
}
