#!/usr/bin/env python3
"""Scapy-based TLS SNI filtering comparison (Experiment 3).

Reads a PCAP, iterates TCP packets on port 443, manually parses TLS
ClientHello to extract the SNI extension, and checks if the domain
matches any forbidden domain.  Self-times processing for Table 4
comparison.

Usage:
    python3 scapy_tls_sni.py <pcap> [--output results.csv]
"""

import argparse
import csv
import os
import struct
import sys
import time

from scapy.all import rdpcap, TCP, Raw

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

FORBIDDEN = [
    "google.com", "facebook.com", "twitter.com", "youtube.com",
    "instagram.com", "whatsapp.com", "telegram.org", "signal.org",
    "wikipedia.org", "reddit.com", "discord.com", "medium.com",
    "soundcloud.com", "tumblr.com", "vimeo.com", "pinterest.com",
    "nytimes.com", "washingtonpost.com", "bbc.com", "theguardian.com",
    "reuters.com", "amnesty.org", "hrw.org", "rsf.org",
    "torproject.org", "psiphon.ca", "lanternvpn.org", "mullvad.net",
    "protonvpn.com", "nordvpn.com", "expressvpn.com",
    "github.com", "gitlab.com", "stackoverflow.com", "twitch.tv",
]


def extract_sni(data):
    """Extract SNI from a TLS ClientHello record.

    Parses the TLS record header, handshake header, and ClientHello
    structure to find the SNI extension (type 0x0000).

    Returns the SNI hostname as a string, or None if not found.
    """
    if len(data) < 5:
        return None

    # TLS record header
    content_type = data[0]
    if content_type != 22:  # Handshake
        return None
    record_len = struct.unpack("!H", data[3:5])[0]
    pos = 5

    if len(data) < pos + 4:
        return None

    # Handshake header
    handshake_type = data[pos]
    if handshake_type != 1:  # ClientHello
        return None
    handshake_len = struct.unpack("!I", b"\x00" + data[pos + 1:pos + 4])[0]
    pos += 4

    if len(data) < pos + 2:
        return None

    # ClientHello: version(2) + random(32) + session_id_len(1) + ...
    pos += 2  # version
    pos += 32  # random

    if pos >= len(data):
        return None
    session_id_len = data[pos]
    pos += 1 + session_id_len

    if pos + 2 > len(data):
        return None
    cipher_suites_len = struct.unpack("!H", data[pos:pos + 2])[0]
    pos += 2 + cipher_suites_len

    if pos >= len(data):
        return None
    compression_len = data[pos]
    pos += 1 + compression_len

    # Extensions
    if pos + 2 > len(data):
        return None
    extensions_len = struct.unpack("!H", data[pos:pos + 2])[0]
    pos += 2

    extensions_end = pos + extensions_len
    while pos + 4 <= extensions_end and pos + 4 <= len(data):
        ext_type = struct.unpack("!H", data[pos:pos + 2])[0]
        ext_len = struct.unpack("!H", data[pos + 2:pos + 4])[0]
        pos += 4

        if ext_type == 0x0000:  # SNI
            if pos + 2 > len(data):
                return None
            sni_list_len = struct.unpack("!H", data[pos:pos + 2])[0]
            sni_pos = pos + 2
            sni_end = sni_pos + sni_list_len
            while sni_pos + 3 <= sni_end and sni_pos + 3 <= len(data):
                name_type = data[sni_pos]
                name_len = struct.unpack("!H", data[sni_pos + 1:sni_pos + 3])[0]
                sni_pos += 3
                if name_type == 0 and sni_pos + name_len <= len(data):
                    return data[sni_pos:sni_pos + name_len].decode("ascii", errors="ignore")
                sni_pos += name_len
            return None

        pos += ext_len

    return None


def process_pcap(pcap_path):
    """Process PCAP and return (decisions list, elapsed seconds)."""
    packets = rdpcap(pcap_path)
    decisions = []

    start = time.perf_counter()
    for i, pkt in enumerate(packets):
        action = "allow"
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            if tcp.dport == 443 or tcp.sport == 443:
                payload = bytes(pkt[Raw].load)
                sni = extract_sni(payload)
                if sni:
                    sni_lower = sni.lower()
                    for domain in FORBIDDEN:
                        if domain in sni_lower:
                            action = "reset"
                            break
        decisions.append({"index": i, "action": action})
    elapsed = time.perf_counter() - start

    return decisions, elapsed


def main():
    parser = argparse.ArgumentParser(description="Scapy TLS SNI filter")
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
