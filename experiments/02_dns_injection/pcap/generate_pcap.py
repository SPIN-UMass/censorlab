#!/usr/bin/env python3
"""Generate a test PCAP with DNS queries for DNS injection evaluation.

Creates N forbidden-domain queries and N allowed-domain queries as individual
UDP packets (Ethernet/IP/UDP with DNS payload).  Writes a labels.csv mapping
packet indices to ground truth for later accuracy analysis.

Usage:
    python3 generate_pcap.py [--n 500] [--output test.pcap]
"""

import argparse
import csv
import os
import random
import struct
import sys

from scapy.all import Ether, IP, UDP, DNS, DNSQR, Raw, wrpcap

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)


def load_domains(path):
    """Load domains from a file, ignoring comments and blank lines."""
    domains = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


def main():
    parser = argparse.ArgumentParser(description="Generate DNS query test PCAP")
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

    forbidden = load_domains(os.path.join(EXPERIMENT_DIR, "data", "forbidden_domains.txt"))
    allowed = load_domains(os.path.join(EXPERIMENT_DIR, "data", "allowed_domains.txt"))

    if not forbidden:
        print("ERROR: No forbidden domains found", file=sys.stderr)
        sys.exit(1)
    if not allowed:
        print("ERROR: No allowed domains found", file=sys.stderr)
        sys.exit(1)

    packets = []
    labels = []

    client_ip = "10.0.0.1"
    dns_server = "8.8.8.8"
    base_sport = 10000

    # Generate forbidden-domain queries
    for i in range(args.n):
        domain = random.choice(forbidden)
        sport = base_sport + i
        txid = random.randint(0, 0xFFFF)
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=dns_server)
            / UDP(sport=sport, dport=53)
            / DNS(id=txid, rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        packets.append(pkt)
        labels.append({"index": len(packets) - 1, "domain": domain, "class": "forbidden"})

    # Generate allowed-domain queries
    for i in range(args.n):
        domain = random.choice(allowed)
        sport = base_sport + args.n + i
        txid = random.randint(0, 0xFFFF)
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=dns_server)
            / UDP(sport=sport, dport=53)
            / DNS(id=txid, rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        packets.append(pkt)
        labels.append({"index": len(packets) - 1, "domain": domain, "class": "allowed"})

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
        writer = csv.DictWriter(f, fieldnames=["index", "domain", "class"])
        writer.writeheader()
        writer.writerows(labels)
    print(f"Wrote labels to {args.labels}")


if __name__ == "__main__":
    main()
