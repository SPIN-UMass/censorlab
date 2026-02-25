#!/usr/bin/env python3
"""Generate live HTTP traffic for NFQ evaluation (Table 3).

Sends HTTP GET requests through the NFQ censor — half with forbidden
keywords, half with allowed keywords.  Records whether each request
succeeded (connection completed) or was reset (connection refused/reset).

Usage:
    python3 generate_traffic.py --host 127.0.0.1 --port 8080 --num-requests 10000
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


def load_keywords(path):
    """Load keywords from file, skipping comments and blanks."""
    keywords = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                keywords.append(line)
    return keywords


def send_http_request(host, port, keyword, timeout=5.0):
    """Send one HTTP GET request and return whether it was reset.

    Returns:
        'completed' — response received (or connection closed normally)
        'reset'     — connection reset by peer (TCP RST)
        'error'     — other error (timeout, refused, etc.)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        request = (
            f"GET /{keyword} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        sock.sendall(request)

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
    parser = argparse.ArgumentParser(description="Generate live HTTP traffic")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=8080, help="Target port")
    parser.add_argument("--num-requests", type=int, default=10000, help="Total requests")
    parser.add_argument("--output", default=None, help="Output CSV path")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-request timeout (s)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "live_eval_results.csv")

    random.seed(args.seed)

    forbidden = load_keywords(os.path.join(EXPERIMENT_DIR, "data", "gfw_keywords.txt"))
    allowed = load_keywords(os.path.join(EXPERIMENT_DIR, "data", "allowed_keywords.txt"))

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

    print(f"Sending {len(plan)} requests to {args.host}:{args.port}...")
    start = time.perf_counter()

    for i, (cls, keyword) in enumerate(plan):
        outcome = send_http_request(args.host, args.port, keyword, args.timeout)
        results.append({
            "index": i,
            "class": cls,
            "keyword": keyword,
            "outcome": outcome,
        })
        if outcome == "error":
            errors += 1

        if (i + 1) % 1000 == 0:
            elapsed = time.perf_counter() - start
            print(f"  {i+1}/{len(plan)} ({elapsed:.1f}s elapsed, {errors} errors)")

    total_time = time.perf_counter() - start

    # Write results
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "class", "keyword", "outcome"])
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
