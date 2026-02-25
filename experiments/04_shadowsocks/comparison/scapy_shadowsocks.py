#!/usr/bin/env python3
"""Scapy-based Shadowsocks/encrypted protocol detection comparison (Experiment 4).

Reads a PCAP, iterates TCP packets, and applies the same GFW-style heuristics
from Wu et al. 2023 to detect fully encrypted traffic.  Self-times processing
for Table 4 comparison.

Usage:
    python3 scapy_shadowsocks.py <pcap> [--output results.csv]
"""

import argparse
import csv
import math
import os
import sys
import time

from scapy.all import rdpcap, TCP, Raw

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

EXEMPT_LENGTHS = {517, 518, 519, 520, 521, 1460, 1500}

# Known protocol fingerprints (first bytes)
PROTOCOL_FINGERPRINTS = [
    b"\x16\x03",    # TLS record (handshake)
    b"\x14\x03",    # TLS ChangeCipherSpec
    b"\x15\x03",    # TLS Alert
    b"\x17\x03",    # TLS Application Data
    b"GET ",        # HTTP GET
    b"POST ",       # HTTP POST
    b"HEAD ",       # HTTP HEAD
    b"PUT ",        # HTTP PUT
    b"HTTP/",       # HTTP response
    b"SSH-",        # SSH identification
    b"\x00\x00",    # Often DNS/other
]


def shannon_entropy_normalized(data):
    """Compute Shannon entropy normalized to 0-1 range."""
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
    return entropy / 8.0


def avg_popcount(data):
    """Compute average number of set bits per byte."""
    if not data:
        return 0.0
    total = sum(bin(b).count("1") for b in data)
    return total / len(data)


def is_printable_ascii(b):
    return 0x20 <= b <= 0x7E


def detect_encrypted(payload):
    """Apply Wu et al. 2023 heuristics to detect fully encrypted traffic.

    Returns 'drop' if detected as encrypted, 'allow' otherwise.
    """
    if not payload or len(payload) == 0:
        return "allow"

    # Rule 4: Exempt common lengths
    if len(payload) in EXEMPT_LENGTHS:
        return "allow"

    # Rule 3: Check protocol fingerprints
    for fp in PROTOCOL_FINGERPRINTS:
        if payload[:len(fp)] == fp:
            return "allow"

    # Rule 2: First 6 bytes must not be printable ASCII
    if len(payload) >= 6:
        if all(is_printable_ascii(b) for b in payload[:6]):
            return "allow"

    # Rule 5: Popcount check (avg bits per byte in [3.4, 4.6])
    popcount = avg_popcount(payload)
    if popcount < 3.4 or popcount > 4.6:
        return "allow"

    # Rule 6: Entropy check (normalized 0-1; 0.375 = 3.0/8.0)
    entropy = shannon_entropy_normalized(payload)
    if entropy < 0.375:
        return "allow"

    return "drop"


def process_pcap(pcap_path):
    """Process PCAP and return (decisions list, elapsed seconds)."""
    packets = rdpcap(pcap_path)
    decisions = []

    start = time.perf_counter()
    for i, pkt in enumerate(packets):
        action = "allow"
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            action = detect_encrypted(payload)
        decisions.append({"index": i, "action": action})
    elapsed = time.perf_counter() - start

    return decisions, elapsed


def main():
    parser = argparse.ArgumentParser(description="Scapy Shadowsocks detection filter")
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

    drop_count = sum(1 for d in decisions if d["action"] == "drop")
    print(f"Scapy: processed {len(decisions)} packets in {elapsed:.4f}s")
    print(f"  Drops: {drop_count}, Allowed: {len(decisions) - drop_count}")
    print(f"  Results: {args.output}")

    # Also write timing to a separate file
    timing_path = os.path.join(EXPERIMENT_DIR, "results", "scapy_timing.txt")
    with open(timing_path, "w") as f:
        f.write(f"{elapsed:.6f}\n")
    print(f"  Timing: {timing_path}")


if __name__ == "__main__":
    main()
