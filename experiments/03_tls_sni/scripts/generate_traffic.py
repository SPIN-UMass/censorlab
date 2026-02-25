#!/usr/bin/env python3
"""Generate live TLS traffic for NFQ evaluation (Table 3).

Sends TLS ClientHello messages through the NFQ censor -- half with
forbidden SNI domains, half with allowed SNI domains.  Records whether
each connection succeeded or was reset (TCP RST).

Uses raw sockets to construct minimal TLS ClientHello messages with
controlled SNI values, avoiding the need for a real TLS server.

Usage:
    python3 generate_traffic.py --host 127.0.0.1 --port 443 --num-requests 100
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


def load_domains(path):
    """Load domains from file, skipping comments and blanks."""
    domains = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


def build_tls_client_hello(sni):
    """Build a minimal TLS ClientHello record with SNI extension."""
    sni_bytes = sni.encode("ascii")

    # SNI extension (type 0x0000)
    server_name = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions = sni_ext
    extensions_data = struct.pack("!H", len(extensions)) + extensions

    # ClientHello body
    client_version = struct.pack("!H", 0x0303)  # TLS 1.2
    client_random = os.urandom(32)
    session_id_len = struct.pack("!B", 0)
    cipher_suites = struct.pack("!H", 4) + struct.pack("!HH", 0x1301, 0x1302)
    compression = struct.pack("!BB", 1, 0)

    hello = (
        client_version
        + client_random
        + session_id_len
        + cipher_suites
        + compression
        + extensions_data
    )

    # Handshake header
    handshake = struct.pack("!B", 1) + struct.pack("!I", len(hello))[1:] + hello

    # TLS record header
    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake

    return record


def send_tls_hello(host, port, sni, timeout=5.0):
    """Send a TLS ClientHello and check if the connection was reset.

    Returns:
        'completed' -- received some response (server hello or alert)
        'reset'     -- connection reset by peer (TCP RST)
        'error'     -- other error (timeout, refused, etc.)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        hello = build_tls_client_hello(sni)
        sock.sendall(hello)

        # Try to read response
        try:
            data = sock.recv(4096)
            if data:
                return "completed"
            return "completed"  # Clean close
        except ConnectionResetError:
            return "reset"
        except socket.timeout:
            return "completed"  # Timeout on read = likely allowed (slow server)
    except ConnectionResetError:
        return "reset"
    except ConnectionRefusedError:
        return "error"
    except socket.timeout:
        return "error"
    except OSError as e:
        if e.errno == 104:  # ECONNRESET
            return "reset"
        return "error"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Generate live TLS traffic")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=443, help="Target port")
    parser.add_argument("--num-requests", type=int, default=100, help="Total requests")
    parser.add_argument("--output", default=None, help="Output CSV path")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-request timeout (s)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "live_eval_results.csv")

    random.seed(args.seed)

    forbidden = load_domains(os.path.join(EXPERIMENT_DIR, "data", "forbidden_domains.txt"))
    allowed = load_domains(os.path.join(EXPERIMENT_DIR, "data", "allowed_domains.txt"))

    # Build request plan: half forbidden, half allowed
    n_per_class = args.num_requests // 2
    plan = []
    for _ in range(n_per_class):
        plan.append(("forbidden", random.choice(forbidden)))
    for _ in range(n_per_class):
        plan.append(("allowed", random.choice(allowed)))
    random.shuffle(plan)

    results = []
    errors = 0

    print(f"Sending {len(plan)} TLS ClientHello requests to {args.host}:{args.port}...")
    start = time.perf_counter()

    for i, (cls, domain) in enumerate(plan):
        outcome = send_tls_hello(args.host, args.port, domain, args.timeout)
        results.append({
            "index": i,
            "class": cls,
            "domain": domain,
            "outcome": outcome,
        })
        if outcome == "error":
            errors += 1

        if (i + 1) % 100 == 0:
            elapsed = time.perf_counter() - start
            print(f"  {i+1}/{len(plan)} ({elapsed:.1f}s elapsed, {errors} errors)")

    total_time = time.perf_counter() - start

    # Write results
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "class", "domain", "outcome"])
        writer.writeheader()
        writer.writerows(results)

    # Compute TPR/TNR
    tp = sum(1 for r in results if r["class"] == "forbidden" and r["outcome"] == "reset")
    fn = sum(1 for r in results if r["class"] == "forbidden" and r["outcome"] != "reset")
    tn = sum(1 for r in results if r["class"] == "allowed" and r["outcome"] == "completed")
    fp = sum(1 for r in results if r["class"] == "allowed" and r["outcome"] == "reset")

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    print(f"\n=== Results ===")
    print(f"Total: {len(plan)} requests in {total_time:.1f}s")
    print(f"Errors: {errors}")
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"TPR={tpr:.4f}  TNR={tnr:.4f}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
