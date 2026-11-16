#!/usr/bin/env python3
"""probe.py — per-connection latency through the censor.

Opens N sequential TCP connections to the HTTP endpoint, sends one GET and
waits for the full response; records connect time and total time per request.
Writes index,connect_s,total_s,outcome to --output.
"""

import argparse
import csv
import socket
import time


def one(host, port, timeout):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        t1 = time.perf_counter()
        s.sendall(b"GET /probe HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
        buf = b""
        while True:
            chunk = s.recv(65535)
            if not chunk:
                break
            buf += chunk
        t2 = time.perf_counter()
        return t1 - t0, t2 - t0, "ok" if buf.startswith(b"HTTP/1.1 200") else "bad"
    except ConnectionResetError:
        return None, time.perf_counter() - t0, "reset"
    except (socket.timeout, OSError) as e:
        return None, time.perf_counter() - t0, f"error:{type(e).__name__}"
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    rows = []
    for i in range(args.n):
        c, t, outcome = one(args.host, args.port, args.timeout)
        rows.append({"index": i, "connect_s": f"{c:.6f}" if c is not None else "",
                     "total_s": f"{t:.6f}", "outcome": outcome})
    with open(args.output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["index", "connect_s", "total_s", "outcome"])
        w.writeheader()
        w.writerows(rows)
    ok = sorted(float(r["total_s"]) for r in rows if r["outcome"] == "ok")
    if ok:
        print(f"probe: {len(ok)}/{len(rows)} ok, median total {ok[len(ok)//2]*1000:.2f} ms")
    else:
        print(f"probe: 0/{len(rows)} ok")


if __name__ == "__main__":
    main()
