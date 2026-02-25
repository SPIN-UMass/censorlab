#!/usr/bin/env python3
"""Generate live traffic for NFQ evaluation of Shadowsocks detection (Table 3).

Sends TCP connections through the NFQ censor -- half with Shadowsocks-like
random-byte payloads (should be dropped), half with normal HTTPS connections
(should be allowed).  Records whether each connection succeeded or was dropped.

Usage:
    python3 generate_traffic.py --host 127.0.0.1 --port 443 --num-requests 1000
"""

import argparse
import csv
import os
import random
import socket
import ssl
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

EXEMPT_LENGTHS = {517, 518, 519, 520, 521, 1460, 1500}

# Domains for normal HTTPS traffic
NORMAL_DOMAINS = [
    "example.com", "httpbin.org", "ifconfig.me", "icanhazip.com",
    "checkip.amazonaws.com",
]


def make_shadowsocks_payload(size=None):
    """Generate random-looking payload mimicking Shadowsocks."""
    if size is None:
        size = random.randint(50, 1400)
    while size in EXEMPT_LENGTHS:
        size = random.randint(50, 1400)
    payload = os.urandom(size)
    # Ensure first 6 bytes are not all printable ASCII
    attempts = 0
    while len(payload) >= 6 and all(0x20 <= b <= 0x7E for b in payload[:6]):
        payload = os.urandom(size)
        attempts += 1
        if attempts > 100:
            payload = bytes([0x01]) + os.urandom(size - 1)
            break
    return payload


def send_encrypted_payload(host, port, timeout=5.0):
    """Send a Shadowsocks-like random payload over raw TCP.

    Returns:
        'completed' -- data sent and response/close received
        'dropped'   -- connection reset or timed out (likely blocked)
        'error'     -- other error
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        payload = make_shadowsocks_payload()
        sock.sendall(payload)

        try:
            data = sock.recv(4096)
            return "completed"
        except ConnectionResetError:
            return "dropped"
        except socket.timeout:
            return "dropped"  # Timeout after send = likely dropped
    except ConnectionResetError:
        return "dropped"
    except ConnectionRefusedError:
        return "error"
    except socket.timeout:
        return "error"
    except OSError as e:
        if e.errno == 104:  # ECONNRESET
            return "dropped"
        return "error"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def send_tls_connection(host, port, sni="example.com", timeout=5.0):
    """Send a normal TLS ClientHello (identifiable protocol fingerprint).

    Returns:
        'completed' -- TLS handshake succeeded or got a response
        'dropped'   -- connection reset or timed out
        'error'     -- other error
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Wrap in TLS -- this sends a proper ClientHello with \x16\x03 prefix
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            ssock = context.wrap_socket(sock, server_hostname=sni)
            ssock.close()
            return "completed"
        except ssl.SSLError:
            return "completed"  # TLS error but connection was not dropped
        except ConnectionResetError:
            return "dropped"
        except socket.timeout:
            return "dropped"
    except ConnectionResetError:
        return "dropped"
    except ConnectionRefusedError:
        return "error"
    except socket.timeout:
        return "error"
    except OSError as e:
        if e.errno == 104:  # ECONNRESET
            return "dropped"
        return "error"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Generate live Shadowsocks evaluation traffic")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=443, help="Target port")
    parser.add_argument("--num-requests", type=int, default=1000, help="Total requests")
    parser.add_argument("--output", default=None, help="Output CSV path")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-request timeout (s)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    if args.output is None:
        args.output = os.path.join(EXPERIMENT_DIR, "results", "live_eval_results.csv")

    random.seed(args.seed)

    # Build request plan: half encrypted (forbidden), half TLS (allowed)
    n_per_class = args.num_requests // 2
    plan = []
    for _ in range(n_per_class):
        plan.append(("forbidden", "shadowsocks"))
    for _ in range(n_per_class):
        sni = random.choice(NORMAL_DOMAINS)
        plan.append(("allowed", sni))
    random.shuffle(plan)

    results = []
    errors = 0

    print(f"Sending {len(plan)} connections to {args.host}:{args.port}...")
    start = time.perf_counter()

    for i, (cls, detail) in enumerate(plan):
        if cls == "forbidden":
            outcome = send_encrypted_payload(args.host, args.port, args.timeout)
        else:
            outcome = send_tls_connection(args.host, args.port, detail, args.timeout)

        results.append({
            "index": i,
            "class": cls,
            "type": detail,
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
        writer = csv.DictWriter(f, fieldnames=["index", "class", "type", "outcome"])
        writer.writeheader()
        writer.writerows(results)

    # Compute TPR/TNR
    tp = sum(1 for r in results if r["class"] == "forbidden" and r["outcome"] == "dropped")
    fn = sum(1 for r in results if r["class"] == "forbidden" and r["outcome"] != "dropped")
    tn = sum(1 for r in results if r["class"] == "allowed" and r["outcome"] == "completed")
    fp = sum(1 for r in results if r["class"] == "allowed" and r["outcome"] == "dropped")

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    print(f"\n=== Results ===")
    print(f"Total: {len(plan)} connections in {total_time:.1f}s")
    print(f"Errors: {errors}")
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"TPR={tpr:.4f}  TNR={tnr:.4f}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
