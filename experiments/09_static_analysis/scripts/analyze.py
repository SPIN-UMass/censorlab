#!/usr/bin/env python3
"""analyze.py — tabulate the per-program static analyses into one CSV/JSON.

Reads results/<NAME>.json (from `censorlab analyze --json`) in programs.conf
order and writes results/static_analysis.{csv,json}.
"""

import csv
import json
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXP_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS = os.path.join(EXP_DIR, "results")

_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9]*)=([A-Za-z0-9_./-]+)\s*$")
_BLANK = re.compile(r"^\s*(#.*)?$")


def programs():
    out = []
    with open(os.path.join(EXP_DIR, "programs.conf")) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if _BLANK.match(line):
                continue
            m = _LINE.match(line)
            if not m:
                raise ValueError(f"programs.conf:{lineno}: unrecognized line {line!r}")
            out.append((m.group(1), m.group(2)))
    return out


def main():
    rows = []
    for name, path in programs():
        p = os.path.join(RESULTS, f"{name}.json")
        if not os.path.exists(p):
            continue
        with open(p) as f:
            a = json.load(f)
        pp = a["per_packet"]
        rows.append({
            "program": name,
            "path": path,
            "source_lines": a["source_lines"],
            "lines": a["lines"],
            "max_lines_per_packet": a["max_lines_per_packet"],
            "regexes": a["regexes"],
            "models": ";".join(a["models"]),
            "fields": ";".join(a["fields"]),
            "conn_regs_float": len(a["connection_registers"]["float"]),
            "conn_regs_int": len(a["connection_registers"]["int"]),
            "conn_regs_bool": len(a["connection_registers"]["bool"]),
            "per_connection_register_bytes": a["per_connection_register_bytes"],
            "per_connection_bytes": a["per_connection_bytes"],
            "host_regs": (len(a["host_registers"]["float"]) + len(a["host_registers"]["int"])
                          + len(a["host_registers"]["bool"])),
            "per_host_register_bytes": a["per_host_register_bytes"],
            "conditions": pp["conditions"],
            "reads": pp["reads"],
            "writes": pp["writes"],
            "copies": pp["copies"],
            "arithmetic": pp["arithmetic"],
            "logic": pp["logic"],
            "returns": pp["returns"],
            "constant_ops": (pp["conditions"] + pp["reads"] + pp["writes"] + pp["copies"]
                             + pp["arithmetic"] + pp["logic"] + pp["returns"]),
            "regex_evaluations": pp["regex"],
            "model_calls": pp["model_calls"],
            "ends_with_unconditional_return": a["ends_with_unconditional_return"],
        })
    if not rows:
        print("no analyses found; run scripts/run.sh")
        return
    with open(os.path.join(RESULTS, "static_analysis.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(RESULTS, "static_analysis.json"), "w") as f:
        json.dump({"experiment": "09_static_analysis", "rows": rows}, f, indent=2)

    print(f"{'program':<18} {'lines':>5} {'regex':>5} {'conn B':>6} {'host B':>6} "
          f"{'ops/pkt':>7} {'regex/pkt':>9} {'model/pkt':>9}")
    print("-" * 76)
    for r in rows:
        print(f"{r['program']:<18} {r['lines']:>5} {r['regexes']:>5} {r['per_connection_bytes']:>6} "
              f"{r['per_host_register_bytes']:>6} {r['constant_ops']:>7} {r['regex_evaluations']:>9} "
              f"{r['model_calls']:>9}")
    print(f"\nwrote {os.path.join(RESULTS, 'static_analysis.csv')}")


if __name__ == "__main__":
    main()
