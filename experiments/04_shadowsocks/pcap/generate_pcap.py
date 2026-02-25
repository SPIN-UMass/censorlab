#!/usr/bin/env python3
"""Generate a test PCAP with encrypted and normal traffic for Shadowsocks detection evaluation.

Creates N "shadowsocks-like" packets (random bytes, high entropy, non-printable
first bytes, popcount ~4) and N "normal" packets (TLS ClientHello with identifiable
protocol fingerprint).  Writes a labels.csv mapping packet indices to ground truth
for later accuracy analysis.

Usage:
    python3 generate_pcap.py [--n 500] [--output test.pcap]
"""

import argparse
import csv
import math
import os
import random
import sys

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

EXEMPT_LENGTHS = {517, 518, 519, 520, 521, 1460, 1500}


def load_exempt_lengths(path):
    """Load exempt lengths from data file, ignoring comments and blank lines."""
    lengths = set()
    if not os.path.exists(path):
        return lengths
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    lengths.add(int(line))
                except ValueError:
                    pass
    return lengths


def avg_popcount(data):
    """Compute average number of set bits per byte."""
    if not data:
        return 0.0
    total = sum(bin(b).count("1") for b in data)
    return total / len(data)


def make_shadowsocks_payload(exempt_lengths, size=None):
    """Generate random-looking payload that mimics Shadowsocks.

    Ensures:
      - Not an exempt length
      - First 6 bytes are not all printable ASCII
      - High entropy (random bytes)
      - Popcount close to 4.0 (natural for random data)
    """
    if size is None:
        size = random.randint(50, 1400)
    # Ensure it's not an exempt length
    while size in exempt_lengths:
        size = random.randint(50, 1400)
    # Random bytes (high entropy, non-ASCII start)
    payload = os.urandom(size)
    # Ensure first 6 bytes are not all printable ASCII
    attempts = 0
    while len(payload) >= 6 and all(0x20 <= b <= 0x7E for b in payload[:6]):
        payload = os.urandom(size)
        attempts += 1
        if attempts > 100:
            # Force non-printable first byte
            payload = bytes([0x01]) + os.urandom(size - 1)
            break
    return payload


def make_tls_client_hello(sni="example.com"):
    """Generate a minimal TLS 1.2 ClientHello payload with proper header.

    This produces a recognizable TLS fingerprint (\x16\x03) that the censor
    should whitelist.
    """
    # SNI extension
    sni_bytes = sni.encode()
    sni_ext = (
        b"\x00\x00"  # Extension type: server_name (0)
        + len(sni_bytes + b"\x00\x00\x03\x00").to_bytes(2, "big")
        + (len(sni_bytes + b"\x00\x03").to_bytes(2, "big"))
        + b"\x00"  # Host name type: host_name (0)
        + len(sni_bytes).to_bytes(2, "big")
        + sni_bytes
    )

    # Cipher suites (common TLS 1.2 suites)
    cipher_suites = (
        b"\xc0\x2c"  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        b"\xc0\x2b"  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        b"\xc0\x30"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        b"\xc0\x2f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    )

    # ClientHello body
    client_hello = (
        b"\x03\x03"  # Client version: TLS 1.2
        + os.urandom(32)  # Client random
        + b"\x00"  # Session ID length: 0
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + b"\x01\x00"  # Compression methods: null
        + len(sni_ext).to_bytes(2, "big")
        + sni_ext
    )

    # Handshake header
    handshake = (
        b"\x01"  # HandshakeType: ClientHello
        + len(client_hello).to_bytes(3, "big")
        + client_hello
    )

    # TLS record header
    record = (
        b"\x16"  # ContentType: Handshake
        b"\x03\x01"  # TLS 1.0 (for compatibility, standard practice)
        + len(handshake).to_bytes(2, "big")
        + handshake
    )

    return record


def make_http_get(path="/index.html", host="example.com"):
    """Generate a plain HTTP GET request (identifiable protocol)."""
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: text/html\r\n"
        f"\r\n"
    ).encode()


def make_ssh_banner():
    """Generate an SSH protocol identification string."""
    return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"


def main():
    parser = argparse.ArgumentParser(description="Generate Shadowsocks detection test PCAP")
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

    exempt_lengths = load_exempt_lengths(
        os.path.join(EXPERIMENT_DIR, "data", "exempt_lengths.txt")
    )

    packets = []
    labels = []

    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    base_sport = 10000

    # Normal traffic domains for TLS/HTTP variety
    normal_domains = [
        "example.com", "google.com", "cloudflare.com", "amazon.com",
        "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    ]

    # Generate shadowsocks-like packets (encrypted, should be blocked)
    for i in range(args.n):
        sport = base_sport + i
        payload = make_shadowsocks_payload(exempt_lengths)
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=443, flags="PA", seq=1000, ack=1)
            / Raw(load=payload)
        )
        packets.append(pkt)
        labels.append({
            "index": len(packets) - 1,
            "type": "shadowsocks",
            "class": "forbidden",
        })

    # Generate normal traffic packets (identifiable protocols, should be allowed)
    for i in range(args.n):
        sport = base_sport + args.n + i
        # Mix of TLS, HTTP, and SSH payloads
        r = random.random()
        if r < 0.6:
            # TLS ClientHello (most common)
            domain = random.choice(normal_domains)
            payload = make_tls_client_hello(domain)
            traffic_type = "tls"
        elif r < 0.85:
            # HTTP GET
            domain = random.choice(normal_domains)
            payload = make_http_get(host=domain)
            traffic_type = "http"
        else:
            # SSH banner
            payload = make_ssh_banner()
            traffic_type = "ssh"

        dport = 80 if traffic_type == "http" else (22 if traffic_type == "ssh" else 443)
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1000, ack=1)
            / Raw(load=payload)
        )
        packets.append(pkt)
        labels.append({
            "index": len(packets) - 1,
            "type": traffic_type,
            "class": "allowed",
        })

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
        writer = csv.DictWriter(f, fieldnames=["index", "type", "class"])
        writer.writeheader()
        writer.writerows(labels)
    print(f"Wrote labels to {args.labels}")


if __name__ == "__main__":
    main()
