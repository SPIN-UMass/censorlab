#!/usr/bin/env python3
"""Scapy-based ML classification comparison (Experiment 5).

Reads a PCAP, groups packets into flows by (src_ip, dst_ip, src_port, dst_port),
collects packet lengths and directions over a window, then uses a heuristic
entropy-based threshold to classify traffic as "blocked" or "normal".

NOTE: Scapy has no native ONNX model support.  This script uses a statistical
heuristic (payload entropy + length variance) as a comparison baseline.  The
heuristic approximates ML classification for encrypted proxy detection:
- High entropy (>7.0) + high length variance -> likely encrypted proxy
- Lower entropy or predictable sizes -> likely normal HTTPS

Self-times processing for Table 4 comparison.

Usage:
    python3 scapy_ml_classification.py <pcap> [--output results.csv]
"""

import argparse
import csv
import math
import os
import sys
import time
from collections import defaultdict

from scapy.all import rdpcap, TCP, Raw, IP

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

WINDOW_SIZE = 10

# Heuristic thresholds (tuned to approximate ML model behavior)
ENTROPY_THRESHOLD = 7.0
LENGTH_VARIANCE_THRESHOLD = 50000


def compute_entropy(data):
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def compute_variance(values):
    """Compute variance of a list of numbers."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((x - mean) ** 2 for x in values) / (len(values) - 1)


def process_pcap(pcap_path):
    """Process PCAP and return (flow_decisions list, elapsed seconds)."""
    packets = rdpcap(pcap_path)

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
        # Collect features over the window
        lens = []
        entropies = []
        for _, pkt in flow_pkts[:WINDOW_SIZE]:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                lens.append(len(payload))
                entropies.append(compute_entropy(payload))
            else:
                lens.append(0)
                entropies.append(0.0)

        if not lens or all(l == 0 for l in lens):
            action = "allow"
        else:
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
            length_var = compute_variance(lens)

            # Heuristic: high entropy + high length variance -> blocked
            if avg_entropy > ENTROPY_THRESHOLD and length_var > LENGTH_VARIANCE_THRESHOLD:
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
        description="Scapy ML classification comparison (heuristic)"
    )
    parser.add_argument("pcap", help="Input PCAP file")
    parser.add_argument(
        "--output", default=None,
        help="Output CSV (default: results/scapy_decisions.csv)",
    )
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "scapy_decisions.csv")

    decisions, elapsed = process_pcap(args.pcap)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["flow_first_pkt", "num_packets", "action"])
        writer.writeheader()
        writer.writerows(decisions)

    drop_count = sum(1 for d in decisions if d["action"] == "drop")
    print(f"Scapy: processed {len(decisions)} flows in {elapsed:.4f}s")
    print(f"  Dropped: {drop_count}, Allowed: {len(decisions) - drop_count}")
    print(f"  Results: {args.output}")
    print(f"  NOTE: Using entropy+variance heuristic (no ONNX model support)")

    # Also write timing to a separate file
    timing_path = os.path.join(EXPERIMENT_DIR, "results", "scapy_timing.txt")
    with open(timing_path, "w") as f:
        f.write(f"{elapsed:.6f}\n")
    print(f"  Timing: {timing_path}")


if __name__ == "__main__":
    main()
