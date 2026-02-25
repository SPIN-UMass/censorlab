#!/usr/bin/env python3
"""Send probe connections with random packet lengths to extract model boundary.

Each probe sends exactly 2 data packets with specified lengths through
the censor. Records the outcome (blocked/allowed) for each length pair.

The attacker does not know the model weights, but can observe whether
CensorLab drops a connection after the first two data packets. By
sending many probes with random (len1, len2) pairs, the attacker
reconstructs the decision boundary of the underlying classifier.

Output: results/probe_results.csv with columns: len1, len2, outcome

Usage:
    python3 generate_probes.py --host 127.0.0.1 --port 8888 --n 10000
"""

import argparse
import csv
import os
import random
import socket
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)


def send_probe(host, port, len1, len2, timeout=2.0):
    """Send a probe connection with two data packets of given lengths.

    Connects to the echo server, sends two payloads of the specified
    lengths, then attempts to receive data. If the connection is reset
    or times out after the second packet, the probe is considered
    "blocked". Otherwise it is "allowed".

    Returns: "blocked", "allowed", or "error"
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))

        # Send first data packet
        payload1 = b"A" * len1
        sock.sendall(payload1)

        # Small delay to ensure packets are separated
        time.sleep(0.01)

        # Send second data packet
        payload2 = b"B" * len2
        sock.sendall(payload2)

        # Wait for echo response — if the censor drops the connection,
        # we will get a ConnectionResetError or timeout
        time.sleep(0.05)

        # Try to receive echoed data
        try:
            data = sock.recv(4096)
            if data:
                return "allowed"
            else:
                # Server closed connection cleanly (EOF)
                return "blocked"
        except ConnectionResetError:
            return "blocked"
        except socket.timeout:
            # No response — likely blocked
            return "blocked"

    except ConnectionResetError:
        return "blocked"
    except ConnectionRefusedError:
        return "error"
    except socket.timeout:
        return "error"
    except Exception as e:
        print(f"  Probe error: {e}", file=sys.stderr)
        return "error"
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Send probe connections to extract model decision boundary"
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Target host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=8888,
        help="Target port (default: 8888)",
    )
    parser.add_argument(
        "--n", type=int, default=10000,
        help="Number of probe connections (default: 10000)",
    )
    parser.add_argument(
        "--max-len", type=int, default=1500,
        help="Maximum packet length in bytes (default: 1500)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output CSV path (default: results/probe_results.csv)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "probe_results.csv")

    random.seed(args.seed)

    results = []
    blocked_count = 0
    allowed_count = 0
    error_count = 0

    print(f"Sending {args.n} probe connections to {args.host}:{args.port}")
    print(f"Packet length range: 1-{args.max_len} bytes")
    print()

    for i in range(args.n):
        len1 = random.randint(1, args.max_len)
        len2 = random.randint(1, args.max_len)
        outcome = send_probe(args.host, args.port, len1, len2)

        results.append({
            "index": i,
            "len1": len1,
            "len2": len2,
            "outcome": outcome,
        })

        if outcome == "blocked":
            blocked_count += 1
        elif outcome == "allowed":
            allowed_count += 1
        else:
            error_count += 1

        # Progress reporting every 500 probes
        if (i + 1) % 500 == 0 or i == 0:
            print(
                f"  [{i+1}/{args.n}] "
                f"blocked={blocked_count} allowed={allowed_count} errors={error_count}"
            )

        # Small delay between probes to avoid overwhelming the system
        time.sleep(0.005)

    # Write results CSV
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["index", "len1", "len2", "outcome"]
        )
        writer.writeheader()
        writer.writerows(results)

    print()
    print(f"Results: {len(results)} probes "
          f"({blocked_count} blocked, {allowed_count} allowed, {error_count} errors)")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
