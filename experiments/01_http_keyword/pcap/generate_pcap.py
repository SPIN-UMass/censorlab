#!/usr/bin/env python3
"""Generate a test PCAP with HTTP GET requests for keyword filtering evaluation.

Creates N forbidden-keyword packets and N allowed-keyword packets as individual
TCP segments (Ethernet/IP/TCP with HTTP payload).  Writes a labels.csv mapping
packet indices to ground truth for later accuracy analysis.

Usage:
    python3 generate_pcap.py [--n 500] [--output test.pcap]
"""

import argparse
import csv
import os
import random
import sys

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)


def load_keywords(path):
    """Load keywords from a file, ignoring comments and blank lines."""
    keywords = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                keywords.append(line)
    return keywords


def make_http_get(keyword, host="example.com"):
    """Build a minimal HTTP GET request containing the keyword in the URI."""
    return (
        f"GET /{keyword} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: censorlab-test/1.0\r\n"
        f"\r\n"
    ).encode()


def main():
    parser = argparse.ArgumentParser(description="Generate HTTP keyword test PCAP")
    parser.add_argument(
        "--n", type=int, default=500,
        help="Number of packets per class (default: 500)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output PCAP path (default: <experiment>/pcap/test.pcap)",
    )
    parser.add_argument(
        "--labels", type=str, default=None,
        help="Output labels CSV path (default: <experiment>/pcap/labels.csv)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "pcap", "test.pcap")
    if args.labels is None:
        args.labels = os.path.join(EXPERIMENT_DIR, "pcap", "labels.csv")

    random.seed(args.seed)

    forbidden_kw = load_keywords(os.path.join(EXPERIMENT_DIR, "data", "gfw_keywords.txt"))
    allowed_kw = load_keywords(os.path.join(EXPERIMENT_DIR, "data", "allowed_keywords.txt"))

    if not forbidden_kw:
        print("ERROR: No forbidden keywords found", file=sys.stderr)
        sys.exit(1)
    if not allowed_kw:
        print("ERROR: No allowed keywords found", file=sys.stderr)
        sys.exit(1)

    packets = []
    labels = []

    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    base_sport = 10000

    # Generate forbidden-keyword packets
    for i in range(args.n):
        kw = random.choice(forbidden_kw)
        sport = base_sport + i
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=80, flags="PA", seq=1000, ack=1)
            / Raw(load=make_http_get(kw))
        )
        packets.append(pkt)
        labels.append({"index": len(packets) - 1, "keyword": kw, "class": "forbidden"})

    # Generate allowed-keyword packets
    for i in range(args.n):
        kw = random.choice(allowed_kw)
        sport = base_sport + args.n + i
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=80, flags="PA", seq=1000, ack=1)
            / Raw(load=make_http_get(kw))
        )
        packets.append(pkt)
        labels.append({"index": len(packets) - 1, "keyword": kw, "class": "allowed"})

    # Shuffle to interleave forbidden/allowed
    combined = list(zip(packets, labels))
    random.shuffle(combined)
    packets, labels = zip(*combined)
    packets = list(packets)
    labels = list(labels)

    # Re-index after shuffle
    for i, lbl in enumerate(labels):
        lbl["index"] = i

    # Write PCAP
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    wrpcap(args.output, packets)
    print(f"Wrote {len(packets)} packets to {args.output}")

    # Write labels CSV
    os.makedirs(os.path.dirname(args.labels), exist_ok=True)
    with open(args.labels, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "keyword", "class"])
        writer.writeheader()
        writer.writerows(labels)
    print(f"Wrote labels to {args.labels}")


if __name__ == "__main__":
    main()
