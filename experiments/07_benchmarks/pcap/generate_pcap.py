#!/usr/bin/env python3
"""Generate benchmark PCAPs with varying packet counts.

Creates PCAPs with N packets for throughput/timing benchmarks.
Packets are a mix of TCP (port 443 TLS ClientHello, port 80 HTTP, etc.)
and UDP packets to exercise different censor code paths.

Usage:
    python3 generate_pcap.py [--n 10000] [--output bench.pcap]
"""

import argparse
import os
import random
import struct
import sys

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)


def make_tls_client_hello(sni="www.example.com"):
    """Build a minimal TLS 1.2 ClientHello with the given SNI extension."""
    # SNI extension
    sni_bytes = sni.encode()
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes  # host_name type + length + name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry  # server_name_list length
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list  # extension type + length

    extensions = sni_ext
    extensions_field = struct.pack("!H", len(extensions)) + extensions

    # ClientHello body
    client_random = os.urandom(32)
    session_id = b"\x00"  # no session ID
    cipher_suites = struct.pack("!HH", 2, 0xc02f)  # length=2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    compression = b"\x01\x00"  # 1 method, null

    client_hello_body = (
        b"\x03\x03"  # TLS 1.2
        + client_random
        + session_id
        + cipher_suites
        + compression
        + extensions_field
    )

    # Handshake header (type=1 ClientHello)
    handshake = struct.pack("!B", 1) + struct.pack("!I", len(client_hello_body))[1:] + client_hello_body

    # TLS record header
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake

    return record


def make_http_get(path="/index.html", host="www.example.com"):
    """Build a minimal HTTP GET request."""
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: censorlab-bench/1.0\r\n"
        f"Accept: */*\r\n"
        f"\r\n"
    ).encode()


def make_random_tcp_payload(size=256):
    """Build a random TCP payload (simulates encrypted traffic)."""
    return os.urandom(size)


def make_udp_dns_query(domain="example.com"):
    """Build a minimal DNS A query."""
    # Transaction ID
    txid = struct.pack("!H", random.randint(0, 0xFFFF))
    # Flags: standard query
    flags = struct.pack("!H", 0x0100)
    # Counts: 1 question, 0 answers, 0 authority, 0 additional
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    # Question: domain name
    qname = b""
    for label in domain.split("."):
        qname += struct.pack("!B", len(label)) + label.encode()
    qname += b"\x00"
    # Type A, Class IN
    qtype_qclass = struct.pack("!HH", 1, 1)
    return txid + flags + counts + qname + qtype_qclass


def generate_packets(n, seed=42):
    """Generate n mixed packets for benchmarking.

    Distribution:
      - 30% TLS ClientHello (port 443)
      - 30% HTTP GET (port 80)
      - 25% random TCP data (various ports)
      - 15% UDP DNS queries (port 53)
    """
    random.seed(seed)
    packets = []

    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    src_mac = "aa:bb:cc:dd:ee:01"
    dst_mac = "aa:bb:cc:dd:ee:02"

    sni_domains = [
        "www.example.com", "mail.google.com", "blocked.example.com",
        "cdn.cloudflare.com", "api.github.com", "docs.python.org",
        "en.wikipedia.org", "www.reddit.com", "news.ycombinator.com",
    ]

    http_paths = [
        "/index.html", "/api/v1/users", "/search?q=test",
        "/static/style.css", "/images/logo.png", "/robots.txt",
    ]

    dns_domains = [
        "example.com", "google.com", "cloudflare.com",
        "github.com", "wikipedia.org", "reddit.com",
    ]

    n_tls = int(n * 0.30)
    n_http = int(n * 0.30)
    n_random = int(n * 0.25)
    n_udp = n - n_tls - n_http - n_random  # remainder goes to UDP

    base_sport = 10000

    # TLS ClientHello packets (port 443)
    for i in range(n_tls):
        sni = random.choice(sni_domains)
        sport = base_sport + (i % 50000)
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=443, flags="PA", seq=1000, ack=1)
            / Raw(load=make_tls_client_hello(sni))
        )
        packets.append(pkt)

    # HTTP GET packets (port 80)
    for i in range(n_http):
        path = random.choice(http_paths)
        host = random.choice(sni_domains)
        sport = base_sport + (i % 50000)
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=80, flags="PA", seq=1000, ack=1)
            / Raw(load=make_http_get(path, host))
        )
        packets.append(pkt)

    # Random TCP data packets (various ports, simulates encrypted traffic)
    random_ports = [8080, 8443, 1080, 9050, 4433, 5555, 6666, 7777]
    for i in range(n_random):
        dport = random.choice(random_ports)
        payload_size = random.randint(64, 1400)
        sport = base_sport + (i % 50000)
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1000, ack=1)
            / Raw(load=make_random_tcp_payload(payload_size))
        )
        packets.append(pkt)

    # UDP DNS query packets (port 53)
    for i in range(n_udp):
        domain = random.choice(dns_domains)
        sport = base_sport + (i % 50000)
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=client_ip, dst=server_ip)
            / UDP(sport=sport, dport=53)
            / Raw(load=make_udp_dns_query(domain))
        )
        packets.append(pkt)

    # Shuffle to interleave packet types
    random.shuffle(packets)

    return packets


def main():
    parser = argparse.ArgumentParser(description="Generate benchmark PCAPs")
    parser.add_argument(
        "--n", type=int, default=10000,
        help="Number of packets to generate (default: 10000)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output PCAP path (default: <experiment>/pcap/bench_<n>.pcap)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "pcap", f"bench_{args.n}.pcap")

    packets = generate_packets(args.n, seed=args.seed)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    wrpcap(args.output, packets)
    print(f"Wrote {len(packets)} packets to {args.output}")
    print(f"  TLS ClientHello (443): {int(args.n * 0.30)}")
    print(f"  HTTP GET (80):         {int(args.n * 0.30)}")
    print(f"  Random TCP data:       {int(args.n * 0.25)}")
    print(f"  UDP DNS (53):          {args.n - int(args.n * 0.30) - int(args.n * 0.30) - int(args.n * 0.25)}")


if __name__ == "__main__":
    main()
