#!/usr/bin/env python3
"""Generate a test PCAP with TLS ClientHello packets for SNI filtering evaluation.

Creates N forbidden-domain ClientHello packets and N allowed-domain ClientHello
packets as individual TCP segments (Ethernet/IP/TCP with TLS ClientHello payload
containing the SNI extension).  Writes a labels.csv mapping packet indices to
ground truth for later accuracy analysis.

Usage:
    python3 generate_pcap.py [--n 500] [--output test.pcap]
"""

import argparse
import csv
import os
import random
import struct
import sys

from scapy.all import Ether, IP, TCP, Raw, wrpcap

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


def build_tls_client_hello(sni):
    """Build a minimal TLS ClientHello record with SNI extension.

    Constructs a valid-enough TLS 1.2 ClientHello that contains the
    Server Name Indication extension with the given domain name.
    """
    sni_bytes = sni.encode("ascii")

    # SNI extension (type 0x0000)
    # ServerName structure: type(1) + length(2) + name
    server_name = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    # ServerNameList: length(2) + entries
    sni_list = struct.pack("!H", len(server_name)) + server_name
    # Extension: type(2) + length(2) + data
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions = sni_ext
    extensions_data = struct.pack("!H", len(extensions)) + extensions

    # ClientHello body
    client_version = struct.pack("!H", 0x0303)  # TLS 1.2
    client_random = os.urandom(32)
    session_id_len = struct.pack("!B", 0)  # No session ID
    # Cipher suites: length(2) + suites
    cipher_suites = struct.pack("!H", 4) + struct.pack("!HH", 0x1301, 0x1302)
    # Compression methods: length(1) + null
    compression = struct.pack("!BB", 1, 0)

    hello = (
        client_version
        + client_random
        + session_id_len
        + cipher_suites
        + compression
        + extensions_data
    )

    # Handshake header: type(1) + length(3)
    handshake = struct.pack("!B", 1) + struct.pack("!I", len(hello))[1:] + hello

    # TLS record header: content_type(1) + version(2) + length(2)
    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake

    return record


def main():
    parser = argparse.ArgumentParser(description="Generate TLS SNI test PCAP")
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
    server_ip = "10.0.0.2"
    base_sport = 10000

    # Generate forbidden-domain TLS ClientHello packets
    for i in range(args.n):
        domain = random.choice(forbidden)
        sport = base_sport + i
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=443, flags="PA", seq=1000, ack=1000)
            / Raw(load=build_tls_client_hello(domain))
        )
        packets.append(pkt)
        labels.append({"index": len(packets) - 1, "domain": domain, "class": "forbidden"})

    # Generate allowed-domain TLS ClientHello packets
    for i in range(args.n):
        domain = random.choice(allowed)
        sport = base_sport + args.n + i
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=443, flags="PA", seq=1000, ack=1000)
            / Raw(load=build_tls_client_hello(domain))
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
