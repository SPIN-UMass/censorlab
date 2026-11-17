#!/usr/bin/env python3
"""Send probe connections with random first-two-packet lengths (client side).

Each probe opens a TCP connection to the probe sink (probe_server.py) and
sends exactly two data segments of random bytes, of lengths len1 and len2
drawn uniformly from [1, --max-len].  The censor (censor.py) evaluates its
model on the second non-empty packet and, if it flags the connection, drops
that packet and everything after it.  The sink never sends payload, so the
two probe segments are the first two non-empty packets the censor sees.

Every probe binds its own source port (--base-port + index), so each probe
is one connection that can be matched unambiguously to the sink's log.

Outcome is measured two ways:
  - client side (what a black-box attacker sees): whether the second segment
    is acknowledged within --wait seconds (tcpi_unacked from TCP_INFO).  The
    first segment must be acknowledged before the second is sent, so the two
    segments never coalesce.
  - server side (the paper's method, "the server records which packets
    arrive"): bytes the sink received, len1 + len2 = allowed, len1 = blocked.
`outcome` is the server-side result; probes where the two disagree, or the
sink saw an unexpected byte count, are reported as "error" so they cannot
silently skew the plot.

Output CSV columns:
    index, len1, len2, src_port, client_outcome, server_bytes, outcome

Usage:
    python3 generate_probes.py --host 172.31.6.20 --port 8888 --n 10000 \
        --server-log results/server_log.csv
"""

import argparse
import csv
import errno
import os
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(SCRIPT_DIR)

# struct tcp_info: 8 bytes of u8 fields, then u32 rto, ato, snd_mss, rcv_mss, unacked
TCPI_UNACKED_OFFSET = 24
TCP_INFO_LEN = 104
# CensorLab listens on 127.0.0.1:25716 (src/ipc.rs), so no probe may bind it
CENSORLAB_IPC_PORT = 25716


def unacked(sock):
    info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, TCP_INFO_LEN)
    return struct.unpack_from("I", info, TCPI_UNACKED_OFFSET)[0]


def wait_acked(sock, deadline):
    """Poll until every sent segment is acknowledged; False at the deadline."""
    while unacked(sock) != 0:
        if time.monotonic() > deadline:
            return False
        time.sleep(0.002)
    return True


def send_probe(host, port, src_port, len1, len2, wait):
    """Returns the client-side outcome: "allowed", "blocked" or "error:<reason>"."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stage = "setup"
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(5.0)
        stage = "bind"
        sock.bind(("0.0.0.0", src_port))
        stage = "connect"
        sock.connect((host, port))
        stage = "send"
        sock.sendall(os.urandom(len1))
        # The first segment is never dropped (the model needs two lengths);
        # waiting for its ACK keeps the two segments separate on the wire.
        if not wait_acked(sock, time.monotonic() + 2.0):
            return "error:first-unacked"
        sock.sendall(os.urandom(len2))
        if wait_acked(sock, time.monotonic() + wait):
            return "allowed"
        return "blocked"
    except OSError as e:
        name = errno.errorcode.get(e.errno, type(e).__name__) if e.errno else type(e).__name__
        return f"error:{stage}:{name}"
    finally:
        sock.close()


def read_server_log(path, client_ip, ports):
    """{src_port: bytes} for this run's probes; None for ports seen twice."""
    seen = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["client_ip"] != client_ip:
                continue
            p = int(row["client_port"])
            if p in ports:
                seen[p] = None if p in seen else int(row["bytes_received"])
    return seen


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True, help="probe sink address (not loopback)")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--n", type=int, default=10000, help="number of probes")
    parser.add_argument("--max-len", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--base-port", type=int, default=10000,
                        help="probe i uses source port base-port + i")
    parser.add_argument("--workers", type=int, default=16, help="concurrent probes")
    parser.add_argument("--wait", type=float, default=0.5,
                        help="seconds to wait for the second segment's ACK")
    parser.add_argument("--server-log", required=True,
                        help="probe_server.py log (shared with the sink)")
    parser.add_argument("--server-log-timeout", type=float, default=60.0)
    parser.add_argument("--output", default=os.path.join(EXPERIMENT_DIR, "results", "probe_results.csv"))
    args = parser.parse_args()

    if args.base_port + args.n > 32768:
        sys.exit("source ports would overlap the ephemeral range; lower --base-port or --n")
    if args.base_port <= CENSORLAB_IPC_PORT < args.base_port + args.n:
        sys.exit(f"source ports would include CensorLab's IPC port {CENSORLAB_IPC_PORT} "
                 "(listening on 127.0.0.1); change --base-port")

    rng = random.Random(args.seed)
    probes = [(i, rng.randint(1, args.max_len), rng.randint(1, args.max_len))
              for i in range(args.n)]

    print(f"Sending {args.n} probes to {args.host}:{args.port} "
          f"(lengths 1-{args.max_len}, {args.workers} concurrent, seed {args.seed})", flush=True)
    start = time.monotonic()
    client = [None] * args.n

    def run(probe):
        i, l1, l2 = probe
        client[i] = send_probe(args.host, args.port, args.base_port + i, l1, l2, args.wait)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for done, _ in enumerate(pool.map(run, probes), 1):
            if done % 1000 == 0:
                print(f"  [{done}/{args.n}] {time.monotonic() - start:.0f}s", flush=True)

    # Find our own address as the sink sees it
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((args.host, args.port))
    client_ip = s.getsockname()[0]
    s.close()

    # Wait for the sink to log every probe (blocked ones end at its idle timeout)
    ports = {args.base_port + i for i in range(args.n)}
    deadline = time.monotonic() + args.server_log_timeout
    while True:
        server = read_server_log(args.server_log, client_ip, ports)
        if len(server) == len(ports) or time.monotonic() > deadline:
            break
        time.sleep(1.0)

    rows = []
    counts = {}
    for i, l1, l2 in probes:
        port = args.base_port + i
        nbytes = server.get(port)
        if nbytes == l1 + l2:
            server_outcome = "allowed"
        elif nbytes == l1:
            server_outcome = "blocked"
        else:
            server_outcome = "error"
        outcome = server_outcome if server_outcome == client[i] else "error"
        counts[outcome] = counts.get(outcome, 0) + 1
        rows.append({
            "index": i, "len1": l1, "len2": l2, "src_port": port,
            "client_outcome": client[i],
            "server_bytes": "" if nbytes is None else nbytes,
            "outcome": outcome,
        })

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    missing = len(ports) - len(server)
    print(f"Done in {time.monotonic() - start:.0f}s: "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
          + (f" ({missing} probes missing from the sink log)" if missing else ""))
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
