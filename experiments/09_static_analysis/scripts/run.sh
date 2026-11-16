#!/usr/bin/env bash
# run.sh — static cost bounds for every CensorLang program in programs.conf.
#
# Uses `censorlab analyze --json`, which derives from the program text alone:
#   * per-connection state, bytes: allocated (full register banks + model
#     buffers + engine state) and touched (registers the program uses instead
#     of the full banks)
#   * per-host state (host registers touched / allocated, bytes)
#   * worst-case per-packet operation counts (loop-free: each line at most once)
#   * number of regex evaluations (each linear in payload length) and model calls
#
# Output: results/<NAME>.json per program and results/static_analysis.{csv,json}
# Usage:  bash experiments/09_static_analysis/scripts/run.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$EXP_DIR/../.." && pwd)"
RESULTS="$EXP_DIR/results"
mkdir -p "$RESULTS"

lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    if [[ "$line" =~ ^([A-Za-z][A-Za-z0-9]*)=([A-Za-z0-9_./-]+)[[:space:]]*$ ]]; then
        name="${BASH_REMATCH[1]}"; path="${BASH_REMATCH[2]}"
    else
        echo "programs.conf:$lineno: unrecognized line: $line" >&2
        exit 1
    fi
    # Analyse under the config the program ships with (its [execution.censorlang]
    # limits and [models]), as the engine would load it
    cfg="$(dirname "$REPO_ROOT/$path")/censor_lang.toml"
    cfg_args=()
    [[ -f "$cfg" ]] && cfg_args=(-c "$cfg")
    echo "--- $name ($path) ---"
    censorlab "${cfg_args[@]}" analyze "$REPO_ROOT/$path" | sed 's/^/  /'
    censorlab "${cfg_args[@]}" analyze --json "$REPO_ROOT/$path" > "$RESULTS/$name.json"
done < "$EXP_DIR/programs.conf"

python3 "$SCRIPT_DIR/analyze.py"
