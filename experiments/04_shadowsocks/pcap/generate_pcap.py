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

import struct

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
from pcapgen import tcp_flow, write_dataset  # noqa: E402

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


def make_server_reply(traffic_type):
    """A plausible first server segment for each traffic type."""
    if traffic_type == "shadowsocks":
        return os.urandom(random.randint(64, 1200))
    if traffic_type == "tls":
        body = struct.pack("!H", 0x0303) + os.urandom(32) + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
        hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
        return struct.pack("!BHH", 22, 0x0303, len(hs)) + hs
    if traffic_type == "http":
        body = b"<html><body>ok</body></html>\n"
        return (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    return b"SSH-2.0-OpenSSH_9.6\r\n"


def main():
    parser = argparse.ArgumentParser(description="Generate Shadowsocks detection test PCAP")
    parser.add_argument(
        "--n", type=int, default=500,
        help="Number of flows per class (default: 500)",
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

    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    base_sport = 10000

    # Normal traffic domains for TLS/HTTP variety
    normal_domains = [
        "example.com", "google.com", "cloudflare.com", "amazon.com",
        "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    ]

    # (first client payload, dport, type, class) per flow
    specs = []
    for _ in range(args.n):
        specs.append((make_shadowsocks_payload(exempt_lengths), 443, "shadowsocks", "forbidden"))
    for _ in range(args.n):
        r = random.random()
        if r < 0.6:
            specs.append((make_tls_client_hello(random.choice(normal_domains)), 443, "tls", "allowed"))
        elif r < 0.85:
            specs.append((make_http_get(host=random.choice(normal_domains)), 80, "http", "allowed"))
        else:
            specs.append((make_ssh_banner(), 22, "ssh", "allowed"))
    random.shuffle(specs)

    # One complete TCP connection per label: handshake, first client data
    # segment (the packet Wu et al.'s heuristics inspect), a server reply,
    # and teardown.
    flows = []
    labels = []
    for i, (payload, dport, traffic_type, cls) in enumerate(specs):
        flows.append(tcp_flow(
            client_ip, server_ip, base_sport + i, dport,
            client_data=payload,
            server_data=make_server_reply(traffic_type),
        ))
        labels.append({"type": traffic_type, "class": cls})

    n_pkts = write_dataset(flows, labels, args.output, args.labels, ["index", "type", "class"])
    print(f"Wrote {n_pkts} packets ({len(flows)} flows) to {args.output}")
    print(f"Wrote labels to {args.labels}")


if __name__ == "__main__":
    main()
