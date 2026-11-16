#!/usr/bin/env bash
# scenario.sh — loader for the declarative per-scenario `scenario.conf`.
#
# `scenario.conf` is a flat KEY=value file (a *regular* language, deliberately:
# no shell expansion, no nesting, no includes).  Every line must match one of:
#
#     # comment / blank
#     KEY=bareword                 bareword: [A-Za-z0-9_./:-]*
#     KEY="quoted value"           quoted:   anything except " $ ` \
#
# Keys are [A-Z][A-Z0-9_]*.  Each key is exported as SC_<KEY>.  Lines that do
# not match are a hard error — the file is fully recognized before anything is
# evaluated, and it is never `source`d.
#
# Recognized keys (paths are relative to the scenario directory):
#
#   ID              directory name, e.g. 03_tls_sni
#   NAME            human-readable scenario name
#   MACRO           LaTeX macro stem used by aggregate_results.py (SniFiltering)
#   CLIENT_IP       client IP passed to `censorlab pcap`
#   PCAP            labelled test PCAP
#   LABELS          ground-truth labels CSV (index,…,class)
#   GENERATE        script that regenerates PCAP + LABELS
#   POSITIVE_ACTIONS  space-separated actions counted as "censored" (reset drop inject)
#   PYCL_CONFIG / PYCL_PROGRAM       CensorLab Python mode
#   CL_CONFIG   / CL_PROGRAM         CensorLab CensorLang mode
#   ZEEK_SCRIPT / ZEEK_LOG           Zeek script and the log stream it writes
#   SCAPY_SCRIPT                     Scapy reference implementation
#   SURICATA_RULES                   Suricata rules file
#   SNORT_RULES                      Snort 3 rules file
#   OPENGFW_RULES                    OpenGFW ruleset (YAML)
#   NOTE_<TOOL>     free-text caveat shown in Table 4 (TOOL ∈ PYCL CL ZEEK SCAPY SURICATA SNORT OPENGFW)
#
# A tool whose *_CONFIG / *_SCRIPT / *_RULES key is absent is "not expressible"
# for that scenario and is skipped (and reported as such).

# Canonical tool identifiers, in Table 4 column order.
SC_TOOLS=(PyCL CensorLang Zeek Scapy Suricata Snort OpenGFW)

# Map canonical tool name -> scenario.conf key prefix
sc_tool_prefix() {
    case "$1" in
        PyCL)       echo PYCL ;;
        CensorLang) echo CL ;;
        Zeek)       echo ZEEK ;;
        Scapy)      echo SCAPY ;;
        Suricata)   echo SURICATA ;;
        Snort)      echo SNORT ;;
        OpenGFW)    echo OPENGFW ;;
        *)          return 1 ;;
    esac
}

# load_scenario <scenario_dir>
# Populates SC_DIR and SC_<KEY> variables.  Returns non-zero on any malformed line.
load_scenario() {
    local dir="$1"
    local conf="$dir/scenario.conf"
    local line key val lineno=0

    if [ ! -f "$conf" ]; then
        echo "load_scenario: missing $conf" >&2
        return 1
    fi

    # Reset any previously loaded scenario
    for v in $(compgen -v | grep '^SC_[A-Z0-9_]*$' | grep -v -E '^SC_(TOOLS|DIR)$'); do
        unset "$v"
    done

    SC_DIR="$(cd "$dir" && pwd)"

    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        if [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]]; then
            continue
        elif [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=\"([^\"\$\`\\]*)\"[[:space:]]*$ ]]; then
            key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9_./:-]*)[[:space:]]*$ ]]; then
            key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
        else
            echo "load_scenario: $conf:$lineno: unrecognized line: $line" >&2
            return 1
        fi
        printf -v "SC_$key" '%s' "$val"
    done < "$conf"

    # Required keys
    for req in ID NAME MACRO CLIENT_IP PCAP LABELS POSITIVE_ACTIONS; do
        local var="SC_$req"
        if [ -z "${!var:-}" ]; then
            echo "load_scenario: $conf: missing required key $req" >&2
            return 1
        fi
    done
    return 0
}

# sc_get <KEY> [default]  — read a loaded scenario value
sc_get() {
    local var="SC_$1"
    printf '%s' "${!var:-${2:-}}"
}

# sc_tool_enabled <Tool> — true if the scenario provides an implementation
sc_tool_enabled() {
    local p; p="$(sc_tool_prefix "$1")" || return 1
    case "$1" in
        PyCL|CensorLang) [ -n "$(sc_get "${p}_CONFIG")" ] ;;
        Zeek|Scapy)      [ -n "$(sc_get "${p}_SCRIPT")" ] ;;
        *)               [ -n "$(sc_get "${p}_RULES")" ] ;;
    esac
}

# sc_tool_program <Tool> — path (relative to SC_DIR) of the file whose LOC we count
sc_tool_program() {
    local p; p="$(sc_tool_prefix "$1")" || return 1
    case "$1" in
        PyCL|CensorLang) sc_get "${p}_PROGRAM" ;;
        Zeek|Scapy)      sc_get "${p}_SCRIPT" ;;
        *)               sc_get "${p}_RULES" ;;
    esac
}
