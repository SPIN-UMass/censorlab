#!/usr/bin/env python3
"""Scapy-based DNS injection comparison (Experiment 2).

Reads a PCAP, iterates UDP packets on port 53, parses DNS queries, and
checks if the queried domain matches any forbidden domain.  Self-times
processing for Table 4 comparison.

Note: Scapy can craft injection packets but cannot inject them into a
live network without raw socket access.  This script performs detection
and decision-making only (matching CensorLab's PCAP mode).

Usage:
    python3 scapy_dns_injection.py <pcap> [--output results.csv]
"""

import argparse
import csv
import os
import sys
import time

from scapy.all import rdpcap, UDP, DNS, DNSQR

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

FORBIDDEN = [
    "google.com", "facebook.com", "twitter.com", "youtube.com",
    "wikipedia.org", "instagram.com", "whatsapp.com", "telegram.org",
    "signal.org", "reddit.com", "nytimes.com", "bbc.com",
    "reuters.com", "theguardian.com", "washingtonpost.com",
    "amnesty.org", "hrw.org", "rsf.org", "torproject.org",
    "eff.org", "vpngate.net", "psiphon.ca", "lanternvpn.org",
    "protonvpn.com", "mullvad.net", "github.com", "medium.com",
    "blogspot.com", "wordpress.com", "tumblr.com", "dropbox.com",
    "soundcloud.com", "vimeo.com", "twitch.tv", "discord.com",
]


def process_pcap(pcap_path):
    """Process PCAP and return (decisions list, elapsed seconds)."""
    packets = rdpcap(pcap_path)
    decisions = []

    start = time.perf_counter()
    for i, pkt in enumerate(packets):
        action = "allow"
        if pkt.haslayer(UDP) and pkt.haslayer(DNS):
            dns = pkt[DNS]
            if pkt[UDP].dport == 53 and dns.qr == 0 and dns.qdcount > 0:
                qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                qname_lower = qname.lower()
                for domain in FORBIDDEN:
                    if domain in qname_lower:
                        action = "inject"
                        break
        decisions.append({"index": i, "action": action})
    elapsed = time.perf_counter() - start

    return decisions, elapsed


def main():
    parser = argparse.ArgumentParser(description="Scapy DNS injection filter")
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

    inject_count = sum(1 for d in decisions if d["action"] == "inject")
    print(f"Scapy: processed {len(decisions)} packets in {elapsed:.4f}s")
    print(f"  Injections: {inject_count}, Allowed: {len(decisions) - inject_count}")
    print(f"  Results: {args.output}")

    # Also write timing to a separate file
    timing_path = os.path.join(EXPERIMENT_DIR, "results", "scapy_timing.txt")
    with open(timing_path, "w") as f:
        f.write(f"{elapsed:.6f}\n")
    print(f"  Timing: {timing_path}")


if __name__ == "__main__":
    main()
