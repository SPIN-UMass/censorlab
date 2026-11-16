#!/usr/bin/env bash
# run_showcase.sh — Table 4 showcase for this scenario.
#
# Thin wrapper around the shared harness; the scenario is fully described by
# ../scenario.conf.  See experiments/common/showcase.sh for methodology.
#
# Usage: bash run_showcase.sh [ITERATIONS] [WARMUP]
set -euo pipefail
SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$SCENARIO_DIR/../common/showcase.sh" "$SCENARIO_DIR" "$@"
