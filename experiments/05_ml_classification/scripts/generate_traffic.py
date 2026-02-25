#!/usr/bin/env python3
"""Generate live traffic for ML classification NFQ-mode evaluation.

Creates two classes of TCP connections through the NFQ censor:
- "blocked" class: connections that mimic encrypted proxy traffic
  (random payload sizes, high entropy payloads)
- "normal" class: connections that mimic normal HTTPS traffic
  (typical TLS handshake + application data patterns)

Records whether each connection was dropped or completed for TPR/TNR
evaluation.

NOTE: For realistic evaluation, this should be run alongside actual
Shadowsocks/obfs4 clients for the blocked class and normal HTTPS
browsing for the normal class.  This script provides a synthetic
approximation.

Usage:
    python3 generate_traffic.py --host 127.0.0.1 --port 443 --num-flows 100
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

PACKETS_PER_FLOW = 12


def send_encrypted_proxy_flow(host, port, timeout=5.0):
    """Send traffic mimicking an encrypted proxy connection.

    Returns:
        'completed' — all data sent/received successfully
        'dropped'   — connection reset or timed out (likely dropped by censor)
        'error'     — other error
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        for _ in range(PACKETS_PER_FLOW):
            payload_len = random.randint(50, 1400)
            payload = os.urandom(payload_len)
            try:
                sock.sendall(payload)
                time.sleep(0.01)
            except (ConnectionResetError, BrokenPipeError):
                return "dropped"
            except socket.timeout:
                return "dropped"

        # Try to read response
        try:
            sock.recv(4096)
            return "completed"
        except ConnectionResetError:
            return "dropped"
        except socket.timeout:
            return "completed"
    except ConnectionResetError:
        return "dropped"
    except ConnectionRefusedError:
        return "error"
    except socket.timeout:
        return "dropped"
    except OSError as e:
        if e.errno == 104:  # ECONNRESET
            return "dropped"
        return "error"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def send_normal_https_flow(host, port, timeout=5.0):
    """Send traffic mimicking a normal HTTPS connection.

    Returns:
        'completed' — all data sent/received successfully
        'dropped'   — connection reset or timed out (likely dropped by censor)
        'error'     — other error
    """
    # Typical TLS-like payload sizes
    sizes = [350, 50, 100, 200, 50, 150, 300, 50, 100, 50, 200, 50]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        for size in sizes:
            # Semi-structured payload (lower entropy than random)
            payload = bytes([random.randint(0, 255) if random.random() < 0.7
                            else 0x00 for _ in range(size)])
            try:
                sock.sendall(payload)
                time.sleep(0.01)
            except (ConnectionResetError, BrokenPipeError):
                return "dropped"
            except socket.timeout:
                return "dropped"

        try:
            sock.recv(4096)
            return "completed"
        except ConnectionResetError:
            return "dropped"
        except socket.timeout:
            return "completed"
    except ConnectionResetError:
        return "dropped"
    except ConnectionRefusedError:
        return "error"
    except socket.timeout:
        return "dropped"
    except OSError as e:
        if e.errno == 104:
            return "dropped"
        return "error"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Generate live ML classification traffic")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=443, help="Target port")
    parser.add_argument("--num-flows", type=int, default=100, help="Total flows (half per class)")
    parser.add_argument("--output", default=None, help="Output CSV path")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-flow timeout (s)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "live_eval_results.csv")

    random.seed(args.seed)

    # Build flow plan: half blocked (encrypted proxy), half normal (HTTPS)
    n_per_class = args.num_flows // 2
    plan = []
    for _ in range(n_per_class):
        plan.append("blocked")
    for _ in range(n_per_class):
        plan.append("normal")
    random.shuffle(plan)

    results = []
    errors = 0

    print(f"Sending {len(plan)} flows to {args.host}:{args.port}...")
    print(f"  {n_per_class} encrypted proxy flows + {n_per_class} normal HTTPS flows")
    start = time.perf_counter()

    for i, cls in enumerate(plan):
        if cls == "blocked":
            outcome = send_encrypted_proxy_flow(args.host, args.port, args.timeout)
        else:
            outcome = send_normal_https_flow(args.host, args.port, args.timeout)

        results.append({
            "index": i,
            "class": cls,
            "outcome": outcome,
        })
        if outcome == "error":
            errors += 1

        if (i + 1) % 10 == 0:
            elapsed = time.perf_counter() - start
            print(f"  {i+1}/{len(plan)} ({elapsed:.1f}s elapsed, {errors} errors)")

    total_time = time.perf_counter() - start

    # Write results
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "class", "outcome"])
        writer.writeheader()
        writer.writerows(results)

    # Compute TPR/TNR
    tp = sum(1 for r in results if r["class"] == "blocked" and r["outcome"] == "dropped")
    fn = sum(1 for r in results if r["class"] == "blocked" and r["outcome"] != "dropped")
    tn = sum(1 for r in results if r["class"] == "normal" and r["outcome"] == "completed")
    fp = sum(1 for r in results if r["class"] == "normal" and r["outcome"] == "dropped")

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    print(f"\n=== Results ===")
    print(f"Total: {len(plan)} flows in {total_time:.1f}s")
    print(f"Errors: {errors}")
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"TPR={tpr:.4f}  TNR={tnr:.4f}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
