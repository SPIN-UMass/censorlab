#!/usr/bin/env python3
"""Probe sink for the model extraction experiment (server side).

Accepts TCP connections, never sends any payload (a server reply would be a
non-empty packet and could become one of the two packets the censor
classifies), and records how many bytes arrived on each connection once it
ends: the client closes it (allowed probes) or it goes idle for
--idle-timeout seconds (the censor dropped the second packet and every
retransmission after it).

Log format (CSV, one line per connection, flushed as written):
    client_ip,client_port,bytes_received

Usage:
    python3 probe_server.py --port 8888 --log results/server_log.csv
"""

import argparse
import socket
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--log", required=True)
    parser.add_argument("--idle-timeout", type=float, default=3.0)
    args = parser.parse_args()

    lock = threading.Lock()
    log = open(args.log, "w", buffering=1)
    log.write("client_ip,client_port,bytes_received\n")

    def handle(conn, addr):
        conn.settimeout(args.idle_timeout)
        received = 0
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                received += len(data)
        except (socket.timeout, OSError):
            pass
        finally:
            conn.close()
        with lock:
            log.write(f"{addr[0]},{addr[1]},{received}\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(1024)
    print(f"probe sink listening on {args.bind}:{args.port}, logging to {args.log}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
