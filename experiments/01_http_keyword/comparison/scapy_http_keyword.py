#!/usr/bin/env python3
"""Scapy-based HTTP keyword filtering comparison (Experiment 1).

Reads a PCAP, iterates TCP packets on port 80, and matches GFW keywords
in the payload.  Self-times processing for Table 4 comparison.

Usage:
    python3 scapy_http_keyword.py <pcap> [--output results.csv]
"""

import argparse
import csv
import os
import sys
import time

from scapy.all import rdpcap, TCP, Raw

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

KEYWORDS = [
    b"falun", b"falungong", b"freegate", b"ultrasurf", b"dynaweb",
    b"tiananmen", b"dalailama", b"tianwang", b"tibetpost", b"minghui",
    b"epochtimes", b"ntdtv", b"wujie", b"zhengjian", b"edoors",
    b"renminbao", b"xinsheng", b"aboluowang", b"bannedbook", b"boxun",
    b"chinadigitaltimes", b"dongtaiwang", b"greatfire", b"huaglad",
    b"kanzhongguo", b"minzhuzhongguo", b"pincong", b"rfa",
    b"secretchina", b"soundofhope", b"voachinese", b"wangzhuan",
    b"weijingsheng", b"weiquanwang", b"zhuichaguoji",
]


def process_pcap(pcap_path):
    """Process PCAP and return (decisions list, elapsed seconds)."""
    packets = rdpcap(pcap_path)
    decisions = []

    start = time.perf_counter()
    for i, pkt in enumerate(packets):
        action = "allow"
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            if tcp.dport == 80 or tcp.sport == 80:
                payload = bytes(pkt[Raw].load).lower()
                for kw in KEYWORDS:
                    if kw in payload:
                        action = "reset"
                        break
        decisions.append({"index": i, "action": action})
    elapsed = time.perf_counter() - start

    return decisions, elapsed


def main():
    parser = argparse.ArgumentParser(description="Scapy HTTP keyword filter")
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
        writer = csv.DictWriter(f, fieldnames=["index", "action"])
        writer.writeheader()
        writer.writerows(decisions)

    reset_count = sum(1 for d in decisions if d["action"] == "reset")
    print(f"Scapy: processed {len(decisions)} packets in {elapsed:.4f}s")
    print(f"  Resets: {reset_count}, Allowed: {len(decisions) - reset_count}")
    print(f"  Results: {args.output}")

    # Also write timing to a separate file
    timing_path = os.path.join(EXPERIMENT_DIR, "results", "scapy_timing.txt")
    with open(timing_path, "w") as f:
        f.write(f"{elapsed:.6f}\n")
    print(f"  Timing: {timing_path}")


if __name__ == "__main__":
    main()
