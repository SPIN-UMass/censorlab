#!/usr/bin/env python3
"""Generate live DNS query traffic for NFQ-mode evaluation.

Sends DNS queries for both forbidden and allowed domains through the
system's default resolver.  Records outcomes (normal response vs
injected/poisoned response) for TPR/TNR evaluation.

Usage:
    python3 generate_traffic.py [--resolver 127.0.0.1] [--output results.csv]
"""

import argparse
import csv
import os
import random
import socket
import struct
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

POISON_IP = "10.10.10.10"


def load_domains(path):
    """Load domains from a file, ignoring comments and blank lines."""
    domains = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


def build_dns_query(domain, txid):
    """Build a raw DNS query packet."""
    # Header: ID, flags (standard query, RD=1), QDCOUNT=1
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    # Question section
    question = b""
    for label in domain.split("."):
        question += struct.pack("B", len(label)) + label.encode()
    question += b"\x00"  # root label
    question += struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def parse_dns_response(data):
    """Parse a DNS response and extract the first A record IP."""
    if len(data) < 12:
        return None
    # Skip header
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    pos = 12
    # Skip questions
    for _ in range(qdcount):
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1 + length
        pos += 4  # QTYPE + QCLASS
    # Parse first answer
    for _ in range(ancount):
        if pos >= len(data):
            break
        # Name (may be pointer)
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
        if pos + 10 > len(data):
            break
        rtype = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 8  # type(2) + class(2) + ttl(4)
        rdlength = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        if rtype == 1 and rdlength == 4 and pos + 4 <= len(data):
            ip = socket.inet_ntoa(data[pos:pos + 4])
            return ip
        pos += rdlength
    return None


def send_query(domain, resolver, timeout=2.0):
    """Send a DNS query and return the response IP (or error string)."""
    txid = random.randint(0, 0xFFFF)
    query = build_dns_query(domain, txid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (resolver, 53))
        data, _ = sock.recvfrom(4096)
        ip = parse_dns_response(data)
        return ip
    except socket.timeout:
        return "timeout"
    except Exception as e:
        return f"error:{e}"
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Generate DNS evaluation traffic")
    parser.add_argument(
        "--resolver", type=str, default="127.0.0.1",
        help="DNS resolver to query through (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output CSV path (default: results/live_eval_results.csv)",
    )
    parser.add_argument(
        "--n", type=int, default=50,
        help="Number of queries per class (default: 50)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed",
    )
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "live_eval_results.csv")

    random.seed(args.seed)

    forbidden = load_domains(os.path.join(EXPERIMENT_DIR, "data", "forbidden_domains.txt"))
    allowed = load_domains(os.path.join(EXPERIMENT_DIR, "data", "allowed_domains.txt"))

    queries = []
    for _ in range(args.n):
        d = random.choice(forbidden)
        queries.append({"domain": d, "class": "forbidden"})
    for _ in range(args.n):
        d = random.choice(allowed)
        queries.append({"domain": d, "class": "allowed"})
    random.shuffle(queries)

    results = []
    for i, q in enumerate(queries):
        ip = send_query(q["domain"], args.resolver)
        if ip == POISON_IP:
            outcome = "injected"
        elif ip is None or ip.startswith("error") or ip == "timeout":
            outcome = "error"
        else:
            outcome = "normal"
        results.append({
            "index": i,
            "domain": q["domain"],
            "class": q["class"],
            "response_ip": ip or "",
            "outcome": outcome,
        })
        print(f"  [{i+1}/{len(queries)}] {q['domain']} -> {ip} ({outcome})")
        time.sleep(0.05)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "domain", "class", "response_ip", "outcome"])
        writer.writeheader()
        writer.writerows(results)

    injected = sum(1 for r in results if r["outcome"] == "injected")
    normal = sum(1 for r in results if r["outcome"] == "normal")
    errors = sum(1 for r in results if r["outcome"] == "error")
    print(f"\nResults: {len(results)} queries ({injected} injected, {normal} normal, {errors} errors)")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
