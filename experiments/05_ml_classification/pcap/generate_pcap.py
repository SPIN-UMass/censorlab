#!/usr/bin/env python3
"""Generate train and test PCAPs with two traffic classes for ML classification.

Creates separate train and test sets of "encrypted proxy" flows (mimicking
Shadowsocks/obfs4 patterns) and "normal HTTPS" flows (typical TLS payload
sizes).  Each flow contains multiple packets to fill the ML classification
window.  The two sets use non-overlapping source ports.

Writes labels CSVs mapping flow indices to ground truth for accuracy analysis.

Usage:
    python3 generate_pcap.py [--n 50] [--n-train 100]
"""

import argparse
import csv
import os
import random
import sys

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

# Number of packets per flow (must be >= ML window size)
PACKETS_PER_FLOW = 12


def generate_encrypted_proxy_flow(flow_id, client_ip, server_ip, sport):
    """Generate packets mimicking encrypted proxy traffic (Shadowsocks/obfs4).

    Characteristics:
    - Random-looking payload lengths (uniformly distributed, 50-1400 bytes)
    - High entropy payloads (random bytes)
    - Bidirectional traffic with no clear pattern
    """
    packets = []
    seq_c = 1000
    seq_s = 2000

    for i in range(PACKETS_PER_FLOW):
        # Alternate directions somewhat randomly
        if random.random() < 0.5:
            # Client -> Server
            payload_len = random.randint(50, 1400)
            payload = os.urandom(payload_len)
            pkt = (
                Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
                / IP(src=client_ip, dst=server_ip)
                / TCP(sport=sport, dport=443, flags="PA", seq=seq_c, ack=seq_s)
                / Raw(load=payload)
            )
            seq_c += payload_len
        else:
            # Server -> Client
            payload_len = random.randint(50, 1400)
            payload = os.urandom(payload_len)
            pkt = (
                Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")
                / IP(src=server_ip, dst=client_ip)
                / TCP(sport=443, dport=sport, flags="PA", seq=seq_s, ack=seq_c)
                / Raw(load=payload)
            )
            seq_s += payload_len
        packets.append(pkt)

    return packets


def generate_normal_https_flow(flow_id, client_ip, server_ip, sport):
    """Generate packets mimicking normal HTTPS/TLS traffic.

    Characteristics:
    - ClientHello ~300-500 bytes, ServerHello+Certs ~2000-4000 bytes
    - Application data mostly ~100-500 bytes (requests) and ~1400 bytes (responses)
    - More predictable size distribution than encrypted proxies
    """
    packets = []
    seq_c = 1000
    seq_s = 2000

    # Typical TLS handshake + application data pattern
    size_pattern = [
        # (direction, min_size, max_size)
        ("c2s", 300, 500),    # ClientHello
        ("s2c", 1200, 1400),  # ServerHello + Cert (part 1)
        ("s2c", 1200, 1400),  # ServerHello + Cert (part 2)
        ("s2c", 200, 400),    # ServerHelloDone
        ("c2s", 100, 200),    # ClientKeyExchange
        ("c2s", 50, 100),     # ChangeCipherSpec + Finished
        ("s2c", 50, 100),     # ChangeCipherSpec + Finished
        # Application data
        ("c2s", 100, 400),    # HTTP request
        ("s2c", 1300, 1400),  # HTTP response (full segment)
        ("s2c", 1300, 1400),  # HTTP response (full segment)
        ("s2c", 200, 800),    # HTTP response (last segment)
        ("c2s", 50, 150),     # ACK / next request
    ]

    for direction, min_size, max_size in size_pattern:
        payload_len = random.randint(min_size, max_size)
        # Use semi-structured payload (not fully random, lower entropy)
        payload = bytes([random.randint(0, 255) if random.random() < 0.7
                        else 0x00 for _ in range(payload_len)])

        if direction == "c2s":
            pkt = (
                Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
                / IP(src=client_ip, dst=server_ip)
                / TCP(sport=sport, dport=443, flags="PA", seq=seq_c, ack=seq_s)
                / Raw(load=payload)
            )
            seq_c += payload_len
        else:
            pkt = (
                Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")
                / IP(src=server_ip, dst=client_ip)
                / TCP(sport=443, dport=sport, flags="PA", seq=seq_s, ack=seq_c)
                / Raw(load=payload)
            )
            seq_s += payload_len
        packets.append(pkt)

    return packets


def generate_dataset(n_per_class, client_ip, server_ip, base_sport):
    """Generate n_per_class blocked + n_per_class normal flows, shuffled.

    Returns (packets, labels) where packets is a flat list and labels is a list
    of dicts with flow_index, first_packet_index, num_packets, class.
    """
    all_flows = []  # list of (class, flow_packets)

    # Generate encrypted proxy flows
    for i in range(n_per_class):
        sport = base_sport + i
        flow_pkts = generate_encrypted_proxy_flow(i, client_ip, server_ip, sport)
        all_flows.append(("blocked", flow_pkts))

    # Generate normal HTTPS flows
    for i in range(n_per_class):
        sport = base_sport + n_per_class + i
        flow_pkts = generate_normal_https_flow(i, client_ip, server_ip, sport)
        all_flows.append(("normal", flow_pkts))

    # Shuffle flows
    random.shuffle(all_flows)

    # Flatten into packet list and build labels (per-flow, not per-packet)
    packets = []
    labels = []
    for flow_idx, (cls, flow_pkts) in enumerate(all_flows):
        first_pkt_idx = len(packets)
        packets.extend(flow_pkts)
        labels.append({
            "flow_index": flow_idx,
            "first_packet_index": first_pkt_idx,
            "num_packets": len(flow_pkts),
            "class": cls,
        })

    return packets, labels, all_flows


def write_dataset(packets, labels, all_flows, pcap_path, labels_path, name):
    """Write a PCAP and labels CSV for a dataset."""
    os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
    wrpcap(pcap_path, packets)

    os.makedirs(os.path.dirname(labels_path), exist_ok=True)
    with open(labels_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "flow_index", "first_packet_index", "num_packets", "class"
        ])
        writer.writeheader()
        writer.writerows(labels)

    blocked_count = sum(1 for c, _ in all_flows if c == "blocked")
    normal_count = sum(1 for c, _ in all_flows if c == "normal")
    print(f"[{name}] Wrote {len(packets)} packets ({len(all_flows)} flows) to {pcap_path}")
    print(f"[{name}] Labels: {labels_path}")
    print(f"[{name}] Blocked: {blocked_count}, Normal: {normal_count}")


def main():
    parser = argparse.ArgumentParser(description="Generate ML classification train/test PCAPs")
    parser.add_argument(
        "--n", type=int, default=50,
        help="Number of test flows per class (default: 50)",
    )
    parser.add_argument(
        "--n-train", type=int, default=100,
        help="Number of training flows per class (default: 100)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    random.seed(args.seed)

    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    base_sport = 10000

    pcap_dir = os.path.join(EXPERIMENT_DIR, "pcap")

    # Generate training set (ports base_sport .. base_sport + 2*n_train - 1)
    train_packets, train_labels, train_flows = generate_dataset(
        args.n_train, client_ip, server_ip, base_sport,
    )
    write_dataset(
        train_packets, train_labels, train_flows,
        os.path.join(pcap_dir, "train.pcap"),
        os.path.join(pcap_dir, "train_labels.csv"),
        "train",
    )

    # Generate test set (ports base_sport + 2*n_train onward, no overlap)
    test_base_sport = base_sport + 2 * args.n_train
    test_packets, test_labels, test_flows = generate_dataset(
        args.n, client_ip, server_ip, test_base_sport,
    )
    write_dataset(
        test_packets, test_labels, test_flows,
        os.path.join(pcap_dir, "test.pcap"),
        os.path.join(pcap_dir, "labels.csv"),
        "test",
    )


if __name__ == "__main__":
    main()
