#!/usr/bin/env python3
"""Generate a test PCAP with HTTP GET requests for keyword filtering evaluation.

Creates N forbidden-keyword and N allowed-keyword HTTP connections, each a complete
TCP flow (handshake, GET, 200 response, teardown) so that stateful tools attach
their HTTP analyzers.  Writes a labels.csv mapping flow indices to ground truth.

Usage:
    python3 generate_pcap.py [--n 500] [--output test.pcap]
"""

import argparse
import csv
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
from pcapgen import tcp_flow, write_dataset  # noqa: E402

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


def make_http_response(body=b"<html><body>ok</body></html>\n"):
    """Minimal HTTP/1.1 200 response."""
    return (
        f"HTTP/1.1 200 OK\r\n"
        f"Server: censorlab-test/1.0\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body


def main():
    parser = argparse.ArgumentParser(description="Generate HTTP keyword test PCAP")
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

    forbidden_kw = load_keywords(os.path.join(EXPERIMENT_DIR, "data", "gfw_keywords.txt"))
    allowed_kw = load_keywords(os.path.join(EXPERIMENT_DIR, "data", "allowed_keywords.txt"))

    if not forbidden_kw:
        print("ERROR: No forbidden keywords found", file=sys.stderr)
        sys.exit(1)
    if not allowed_kw:
        print("ERROR: No allowed keywords found", file=sys.stderr)
        sys.exit(1)

    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    base_sport = 10000

    # One complete HTTP/1.1 connection per label (handshake, GET, 200 OK,
    # teardown).  Forbidden and allowed flows are interleaved.
    specs = [(random.choice(forbidden_kw), "forbidden") for _ in range(args.n)] + \
            [(random.choice(allowed_kw), "allowed") for _ in range(args.n)]
    random.shuffle(specs)

    flows = []
    labels = []
    for i, (kw, cls) in enumerate(specs):
        flows.append(tcp_flow(
            client_ip, server_ip, base_sport + i, 80,
            client_data=make_http_get(kw),
            server_data=make_http_response(),
        ))
        labels.append({"keyword": kw, "class": cls})

    n_pkts = write_dataset(flows, labels, args.output, args.labels, ["index", "keyword", "class"])
    print(f"Wrote {n_pkts} packets ({len(flows)} flows) to {args.output}")
    print(f"Wrote labels to {args.labels}")


if __name__ == "__main__":
    main()
