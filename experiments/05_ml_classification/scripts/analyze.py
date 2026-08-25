#!/usr/bin/env python3
"""analyze.py — Table 4 (timing/CPU/memory/LOC) and accuracy (TPR/TNR) for this scenario.

Thin wrapper around experiments/common/analyze_showcase.py; see that module
for the output schema.  Usage: python3 analyze.py [--results DIR] [--pcap PCAP]
"""
import os
import sys

SCENARIO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(SCENARIO_DIR, "..", "common"))

from analyze_showcase import main  # noqa: E402

if __name__ == "__main__":
    sys.argv.insert(1, SCENARIO_DIR)
    main()
