#!/usr/bin/env python3
"""report.py — TPR/TNR reporting module for labelled PCAPs.

Scores any tool's native output against the ground-truth labels shipped with
a scenario PCAP.  Every adapter reduces a tool's output to the same normalized
decision table, ``index,action``, where ``index`` is the *flow ordinal* (order
of first appearance of the bidirectional 5-tuple in the PCAP) and ``action`` is
the tool's verdict (``allow`` if the tool did nothing).  Ground truth uses the
same flow ordinal, so scoring is one join.

Supported label schemas (auto-detected):
    index,…,class                       one row per flow (01–04)
    flow_index,first_packet_index,…,class   (05)
``class`` ∈ {forbidden, blocked} are positives; {allowed, normal} negatives.

Adapters (``--tool``):
    censorlab   stdout of `censorlab … pcap` ("N: Ok(Reset …)" lines)
    scapy       decisions CSV written by comparison/scapy_*.py
    zeek        Zeek TSV log (orig_h/orig_p/resp_h/resp_p columns)
    suricata    eve.json (alert events; pcap_cnt or 5-tuple)
    snort       Snort 3 alert_csv output
    opengfw     OpenGFW JSON log lines ("ruleset match" events)

Usage:
    report.py normalize --tool zeek --pcap test.pcap --labels labels.csv \
                        --input zeek_matches.log --output zeek_decisions.csv
    report.py score --labels labels.csv --decisions zeek_decisions.csv
    report.py scenario <scenario_dir>        # all tools with artifacts present

The third form writes <scenario>/results/accuracy.json and table3.json.
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import OrderedDict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from scenario import load_scenario  # noqa: E402

POSITIVE_CLASSES = {"forbidden", "blocked"}
NEGATIVE_CLASSES = {"allowed", "normal"}

# CensorLab's PCAP mode numbers blocks from the file header: the first data
# packet of a legacy pcap is reported as index 2.
CENSORLAB_PCAP_OFFSET = 2


# ---------------------------------------------------------------------------
# Flow table
# ---------------------------------------------------------------------------
class FlowTable:
    """Maps packet indices and 5-tuples to flow ordinals for one PCAP."""

    def __init__(self, pcap_path):
        from scapy.all import IP, IPv6, TCP, UDP, PcapReader  # lazy: scapy is slow to import

        self.pkt_to_flow = []
        self.key_to_flow = OrderedDict()
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                key = None
                ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                if ip is not None:
                    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
                    if l4 is not None:
                        proto = "tcp" if pkt.haslayer(TCP) else "udp"
                        key = self.make_key(proto, ip.src, l4.sport, ip.dst, l4.dport)
                if key is None:
                    self.pkt_to_flow.append(None)
                    continue
                if key not in self.key_to_flow:
                    self.key_to_flow[key] = len(self.key_to_flow)
                self.pkt_to_flow.append(self.key_to_flow[key])

    @staticmethod
    def make_key(proto, a_ip, a_port, b_ip, b_port):
        ends = sorted([(str(a_ip), int(a_port)), (str(b_ip), int(b_port))])
        return (proto, ends[0], ends[1])

    def flow_of_packet(self, pkt_index):
        if 0 <= pkt_index < len(self.pkt_to_flow):
            return self.pkt_to_flow[pkt_index]
        return None

    def flow_of_tuple(self, a_ip, a_port, b_ip, b_port, proto=None):
        protos = [proto] if proto else ["tcp", "udp"]
        for p in protos:
            f = self.key_to_flow.get(self.make_key(p, a_ip, a_port, b_ip, b_port))
            if f is not None:
                return f
        return None

    @property
    def num_flows(self):
        return len(self.key_to_flow)


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------
def load_labels(path):
    """Return OrderedDict flow_index -> class ('forbidden'|'allowed')."""
    labels = OrderedDict()
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if "index" in row:
                idx = int(row["index"])
            elif "flow_index" in row:
                idx = int(row["flow_index"])
            else:
                raise ValueError(f"{path}: no index/flow_index column")
            cls = row["class"].strip().lower()
            if cls in POSITIVE_CLASSES:
                labels[idx] = "forbidden"
            elif cls in NEGATIVE_CLASSES:
                labels[idx] = "allowed"
            else:
                raise ValueError(f"{path}: unknown class {cls!r}")
    return labels


# ---------------------------------------------------------------------------
# Adapters: native output -> {flow_index: action}
# ---------------------------------------------------------------------------
_CENSORLAB_LINE = re.compile(r"^(\d+):\s+Ok\((Reset|Drop|Inject|Delay|Rewrite)\b")


def adapt_censorlab(path, flows):
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            m = _CENSORLAB_LINE.match(line.strip())
            if not m:
                continue
            pkt = int(m.group(1)) - CENSORLAB_PCAP_OFFSET
            flow = flows.flow_of_packet(pkt)
            if flow is not None:
                out.setdefault(flow, m.group(2).lower())
    return out


def adapt_scapy(path, flows):
    out = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            action = row.get("action", "allow").strip().lower()
            if action in ("", "allow", "none"):
                continue
            if "index" in row:
                pkt = int(row["index"])
            elif "flow_first_pkt" in row:
                pkt = int(row["flow_first_pkt"])
            else:
                continue
            flow = flows.flow_of_packet(pkt)
            if flow is not None:
                out.setdefault(flow, action)
    return out


def adapt_zeek(path, flows):
    out = {}
    fields = None
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:
                continue
            row = dict(zip(fields, line.rstrip("\n").split("\t")))
            try:
                flow = flows.flow_of_tuple(
                    row["orig_h"], int(row["orig_p"]), row["resp_h"], int(row["resp_p"]))
            except (KeyError, ValueError):
                continue
            if flow is not None:
                out.setdefault(flow, row.get("action", "alert").lower())
    return out


def adapt_suricata(path, flows):
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "alert":
                continue
            flow = None
            if "pcap_cnt" in ev:
                flow = flows.flow_of_packet(int(ev["pcap_cnt"]) - 1)
            if flow is None and "src_ip" in ev:
                flow = flows.flow_of_tuple(
                    ev["src_ip"], ev.get("src_port", 0), ev["dest_ip"], ev.get("dest_port", 0),
                    proto=str(ev.get("proto", "")).lower() or None)
            if flow is not None:
                action = str(ev.get("alert", {}).get("action", "alert")).lower()
                out.setdefault(flow, action)
    return out


_ADDR_PORT = re.compile(r"^(.*):(\d+)$")


def adapt_snort(path, flows):
    """Snort 3 alert_csv: timestamp, pkt_num, proto, pkt_gen, pkt_len, dir, src_ap, dst_ap, rule, action."""
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            parts = [p.strip() for p in line.rstrip("\n").split(",")]
            if len(parts) < 8 or not parts[1].isdigit():
                continue
            flow = flows.flow_of_packet(int(parts[1]) - 1)
            if flow is None:
                ms, md = _ADDR_PORT.match(parts[6]), _ADDR_PORT.match(parts[7])
                if ms and md:
                    flow = flows.flow_of_tuple(ms.group(1), int(ms.group(2)),
                                               md.group(1), int(md.group(2)),
                                               proto=parts[2].lower() or None)
            if flow is not None:
                action = parts[9].lower() if len(parts) > 9 and parts[9] else "alert"
                out.setdefault(flow, action)
    return out


def adapt_opengfw(path, flows):
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("msg") != "ruleset match":
                continue
            ms, md = _ADDR_PORT.match(str(ev.get("src", ""))), _ADDR_PORT.match(str(ev.get("dst", "")))
            if not (ms and md):
                continue
            flow = flows.flow_of_tuple(ms.group(1), int(ms.group(2)), md.group(1), int(md.group(2)))
            if flow is not None:
                out.setdefault(flow, str(ev.get("action", "block")).lower())
    return out


ADAPTERS = {
    "censorlab": adapt_censorlab,
    "scapy": adapt_scapy,
    "zeek": adapt_zeek,
    "suricata": adapt_suricata,
    "snort": adapt_snort,
    "opengfw": adapt_opengfw,
}

# Native artifact each tool leaves in <scenario>/results/, and its adapter.
TOOL_ARTIFACTS = [
    ("PyCL", "pycl_output.txt", "censorlab"),
    ("CensorLang", "censorlang_output.txt", "censorlab"),
    ("Zeek", "zeek_matches.log", "zeek"),
    ("Scapy", "scapy_decisions.csv", "scapy"),
    ("Suricata", "suricata_eve.json", "suricata"),
    ("Snort", "snort_alerts.csv", "snort"),
    ("OpenGFW", "opengfw_output.jsonl", "opengfw"),
]


# ---------------------------------------------------------------------------
# Normalize + score
# ---------------------------------------------------------------------------
def normalize(tool, native_path, flows, labels):
    """Return list of {index, action} covering every labelled flow."""
    positives = ADAPTERS[tool](native_path, flows)
    return [{"index": idx, "action": positives.get(idx, "allow")} for idx in labels]


def write_decisions(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["index", "action"])
        w.writeheader()
        w.writerows(rows)


def score(labels, decisions):
    """labels: {idx: class}; decisions: iterable of {index, action}. Anything but 'allow' is positive."""
    dmap = {int(d["index"]): d["action"] for d in decisions}
    tp = fn = tn = fp = 0
    for idx, cls in labels.items():
        positive = dmap.get(idx, "allow") != "allow"
        if cls == "forbidden":
            tp += positive
            fn += not positive
        else:
            fp += positive
            tn += not positive
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    return {"tpr": round(tpr, 4), "tnr": round(tnr, 4),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "errors": 0, "total": len(labels)}


# ---------------------------------------------------------------------------
# Whole-scenario report
# ---------------------------------------------------------------------------
def report_scenario(scenario_dir, pcap_override=None, results_dir=None):
    sc = load_scenario(scenario_dir)
    sdir = sc["DIR"]
    results = results_dir or os.path.join(sdir, "results")
    pcap = pcap_override or os.path.join(sdir, sc["PCAP"])
    labels = load_labels(os.path.join(sdir, sc["LABELS"]))
    flows = FlowTable(pcap)

    rows = []
    for tool, artifact, adapter in TOOL_ARTIFACTS:
        native = os.path.join(results, artifact)
        if not os.path.exists(native):
            continue
        decisions = normalize(adapter, native, flows, labels)
        write_decisions(decisions, os.path.join(results, f"{tool.lower()}_decisions.csv"))
        row = {"tool": tool}
        row.update(score(labels, decisions))
        row["note"] = sc.get(f"NOTE_{sc['_prefix'][tool]}", "")
        rows.append(row)

    out = {"table": "table3", "experiment": sc["ID"], "pcap": os.path.relpath(pcap, sdir),
           "flows": flows.num_flows, "labels": len(labels), "rows": rows}
    with open(os.path.join(results, "accuracy.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(results, "table3.json"), "w") as f:
        json.dump(out, f, indent=2)

    print(f"{'Tool':<12} {'TPR':>7} {'TNR':>7} {'TP':>5} {'FN':>5} {'FP':>5} {'TN':>5}  Note")
    print("-" * 72)
    for r in rows:
        print(f"{r['tool']:<12} {r['tpr']:>7.4f} {r['tnr']:>7.4f} {r['tp']:>5} {r['fn']:>5} "
              f"{r['fp']:>5} {r['tn']:>5}  {r['note']}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("normalize", help="convert a tool's native output to index,action")
    n.add_argument("--tool", required=True, choices=sorted(ADAPTERS))
    n.add_argument("--pcap", required=True)
    n.add_argument("--labels", required=True)
    n.add_argument("--input", required=True)
    n.add_argument("--output", required=True)

    s = sub.add_parser("score", help="score a normalized decisions CSV")
    s.add_argument("--labels", required=True)
    s.add_argument("--decisions", required=True)

    r = sub.add_parser("scenario", help="score every tool artifact in <scenario>/results")
    r.add_argument("scenario_dir")
    r.add_argument("--pcap", default=None, help="PCAP the artifacts were produced from")
    r.add_argument("--results", default=None, help="results directory (default <scenario>/results)")

    args = ap.parse_args()
    if args.cmd == "normalize":
        labels = load_labels(args.labels)
        flows = FlowTable(args.pcap)
        write_decisions(normalize(args.tool, args.input, flows, labels), args.output)
    elif args.cmd == "score":
        labels = load_labels(args.labels)
        with open(args.decisions, newline="") as f:
            decisions = list(csv.DictReader(f))
        print(json.dumps(score(labels, decisions), indent=2))
    else:
        report_scenario(args.scenario_dir, args.pcap, args.results)


if __name__ == "__main__":
    main()
