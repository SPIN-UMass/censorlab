#!/usr/bin/env bash
# test_harness.sh — self-test for harness.sh error handling.
#
# Runs measure_run under `set -euo pipefail` (as showcase.sh does) with a
# stub tool that exits nonzero, and checks that the run is still recorded
# (exit_code column) and its log preserved as <tool>_failed_run.log.
#
# Usage: bash experiments/common/test_harness.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "$HERE/harness.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SC_DIR="$TMP/scenario"
RESULTS="$TMP/results"
RAW_TIMINGS="$TMP/raw_timings.csv"
mkdir -p "$SC_DIR/results" "$RESULTS"
: > "$RAW_TIMINGS"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Stub: replace the real tool command with one that fails.
tool_argv() { ARGV=(sh -c 'echo boom; exit 3'); }

# 1. measure_run must survive a failing tool and record it.
measure_run PyCL 1 measure /dev/null "$RESULTS" >/dev/null
row="$(tail -1 "$RAW_TIMINGS")"
[ "${row##*,}" = 3 ] || fail "expected exit_code 3 in raw timings, got row: $row"
[ -f "$RESULTS/pycl_failed_run.log" ] || fail "pycl_failed_run.log not written"
grep -q boom "$RESULTS/pycl_failed_run.log" || fail "failed-run log has wrong content"

# 2. A successful run records exit_code 0 and no failed-run log.
rm -f "$RESULTS/pycl_failed_run.log"
tool_argv() { ARGV=(true); }
measure_run PyCL 2 measure /dev/null "$RESULTS" >/dev/null
row="$(tail -1 "$RAW_TIMINGS")"
[ "${row##*,}" = 0 ] || fail "expected exit_code 0, got row: $row"
[ ! -f "$RESULTS/pycl_failed_run.log" ] || fail "failed-run log written for a successful run"

# 3. count_loc prints exactly one number.
printf '# comment\n\n' > "$TMP/empty.py"
[ "$(count_loc "$TMP/empty.py")" = 0 ] || fail "count_loc on comment-only file: '$(count_loc "$TMP/empty.py")'"
printf 'a\n# c\nb\n' > "$TMP/two.py"
[ "$(count_loc "$TMP/two.py")" = 2 ] || fail "count_loc on two-line file"
[ "$(count_loc "$TMP/missing.py")" = 0 ] || fail "count_loc on missing file: '$(count_loc "$TMP/missing.py")'"

# 4. censorlab_config: unchanged without an override; with one, a copy in the
#    work directory next to links to the scenario's files (config paths are
#    relative to the config file).
(
    unset -f tool_argv
    source "$HERE/harness.sh"
    printf '[execution]\nscript = "censor.py"\n' > "$SC_DIR/censor.toml"
    : > "$SC_DIR/censor.py"
    W="$TMP/work"; mkdir -p "$W"
    unset CENSORLAB_MAX_CONNECTIONS
    [ "$(censorlab_config "$SC_DIR/censor.toml" "$W")" = "$SC_DIR/censor.toml" ] \
        || fail "censorlab_config changed the config without an override"
    out="$(CENSORLAB_MAX_CONNECTIONS=1000 censorlab_config "$SC_DIR/censor.toml" "$W")"
    [ "$out" = "$W/config/censor.toml" ] || fail "censorlab_config override path: $out"
    [ ! -L "$out" ] || fail "overridden config is a link to the original"
    [ "$(tail -2 "$out")" = $'[conntrack]\nmax_connections = 1000' ] || fail "override not appended"
    [ "$W/config/censor.py" -ef "$SC_DIR/censor.py" ] || fail "scenario files not linked next to the config"
    ! grep -q conntrack "$SC_DIR/censor.toml" || fail "scenario config was modified"
    ! (CENSORLAB_MAX_CONNECTIONS=10k censorlab_config "$SC_DIR/censor.toml" "$W") 2>/dev/null \
        || fail "non-numeric CENSORLAB_MAX_CONNECTIONS accepted"
    printf '[conntrack]\n' >> "$SC_DIR/censor.toml"
    ! (CENSORLAB_MAX_CONNECTIONS=1000 censorlab_config "$SC_DIR/censor.toml" "$W") 2>/dev/null \
        || fail "config that already has [conntrack] accepted"
) || exit 1

echo "test_harness: OK"
