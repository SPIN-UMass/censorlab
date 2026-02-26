#!/usr/bin/env python3
"""Scapy-based ML classification comparison (Experiment 5).

Reads a PCAP, groups packets into flows by (src_ip, dst_ip, src_port, dst_port),
collects packet lengths and directions over a window, then classifies each flow
using the same ONNX model as PyCL via onnxruntime.

Self-times processing for Table 4 comparison.

Usage:
    python3 scapy_ml_classification.py <pcap> [--model model.onnx] [--output results.csv]
"""

import argparse
import csv
import os
import sys
import time
from collections import defaultdict

import numpy as np
import onnxruntime as ort
from scapy.all import rdpcap, TCP, Raw, IP

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

WINDOW_SIZE = 10
CLIENT_IP = "10.0.0.1"


def process_pcap(pcap_path, model_path):
    """Process PCAP and return (flow_decisions list, elapsed seconds)."""
    packets = rdpcap(pcap_path)
    session = ort.InferenceSession(model_path)
    input_name = session.get_inputs()[0].name

    # Group packets into flows by 4-tuple
    flows = defaultdict(list)
    for i, pkt in enumerate(packets):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP]
            tcp = pkt[TCP]
            # Normalize flow key (smaller IP first)
            if ip.src < ip.dst:
                key = (ip.src, ip.dst, tcp.sport, tcp.dport)
            else:
                key = (ip.dst, ip.src, tcp.dport, tcp.sport)
            flows[key].append((i, pkt))

    decisions = []

    start = time.perf_counter()
    for flow_key, flow_pkts in flows.items():
        # Collect features over the window (matching PyCL censor.py)
        lens = []
        dirs = []
        for _, pkt in flow_pkts[:WINDOW_SIZE]:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                lens.append(float(len(payload)))
            else:
                lens.append(0.0)
            # Direction: 0.0 = client->server, 1.0 = server->client
            if pkt[IP].src == CLIENT_IP:
                dirs.append(0.0)
            else:
                dirs.append(1.0)

        # Pad or truncate to WINDOW_SIZE
        lens = (lens[:WINDOW_SIZE] + [0.0] * max(0, WINDOW_SIZE - len(lens)))
        dirs = (dirs[:WINDOW_SIZE] + [0.0] * max(0, WINDOW_SIZE - len(dirs)))

        features = np.array([lens + dirs], dtype=np.float32)
        result = session.run(None, {input_name: features})
        # result[1] is probabilities, shape [1, 2]
        # Class 0 = blocked, so prob[0][0] > 0.5 means blocked
        probs = result[1]
        if probs[0][0] > 0.5:
            action = "drop"
        else:
            action = "allow"

        first_pkt_idx = flow_pkts[0][0]
        decisions.append({
            "flow_first_pkt": first_pkt_idx,
            "num_packets": len(flow_pkts),
            "action": action,
        })
    elapsed = time.perf_counter() - start

    return decisions, elapsed


def main():
    parser = argparse.ArgumentParser(
        description="Scapy ML classification comparison (ONNX model)"
    )
    parser.add_argument("pcap", help="Input PCAP file")
    parser.add_argument(
        "--model", default=None,
        help="ONNX model path (default: <experiment_dir>/model.onnx)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output CSV (default: results/scapy_decisions.csv)",
    )
    args = parser.parse_args()

    if args.model is None:
        args.model = os.path.join(EXPERIMENT_DIR, "model.onnx")
    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "scapy_decisions.csv")

    if not os.path.exists(args.model):
        print(f"ERROR: ONNX model not found at {args.model}", file=sys.stderr)
        print("Run: python3 train_model.py", file=sys.stderr)
        sys.exit(1)

    decisions, elapsed = process_pcap(args.pcap, args.model)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["flow_first_pkt", "num_packets", "action"])
        writer.writeheader()
        writer.writerows(decisions)

    drop_count = sum(1 for d in decisions if d["action"] == "drop")
    print(f"Scapy: processed {len(decisions)} flows in {elapsed:.4f}s")
    print(f"  Dropped: {drop_count}, Allowed: {len(decisions) - drop_count}")
    print(f"  Results: {args.output}")

    # Also write timing to a separate file
    timing_path = os.path.join(EXPERIMENT_DIR, "results", "scapy_timing.txt")
    with open(timing_path, "w") as f:
        f.write(f"{elapsed:.6f}\n")
    print(f"  Timing: {timing_path}")


if __name__ == "__main__":
    main()
