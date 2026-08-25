#!/usr/bin/env python3
"""server.py — all the endpoints the live scenarios need, in one process.

  :8080  HTTP/1.1 server answering every GET with a small 200 response (probe)
  :80    same HTTP server (01: the keyword censors filter port 80)
  :443   TLS-handshake responder: reads a ClientHello, replies with a fixed
         ServerHello record (03, 04); plain TCP sink otherwise
  :53    DNS responder: answers every A query with 93.184.216.34 (02).  An
         injected 10.10.10.10 answer therefore unambiguously signals the censor.

Standard library only, threaded.  Exits on SIGTERM.
"""

import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REAL_ANSWER = "93.184.216.34"


class Quiet(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"<html><body>ok</body></html>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def http_server(port=8080):
    ThreadingHTTPServer(("0.0.0.0", port), Quiet).serve_forever()


def server_hello():
    body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 22, 0x0303, len(hs)) + hs


def tls_responder():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 443))
    srv.listen(256)
    hello = server_hello()

    def handle(conn):
        try:
            conn.settimeout(5)
            data = conn.recv(65535)
            if data:
                conn.sendall(hello)
            try:
                conn.recv(65535)
            except OSError:
                pass
        except OSError:
            pass
        finally:
            conn.close()

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def dns_responder():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    answer_ip = socket.inet_aton(REAL_ANSWER)
    while True:
        data, addr = sock.recvfrom(4096)
        if len(data) < 12:
            continue
        txid = data[:2]
        # walk the first question to find its end
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += data[pos] + 1
        qend = pos + 1 + 4
        if qend > len(data):
            continue
        question = data[12:qend]
        header = txid + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0)
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + answer_ip
        sock.sendto(header + question + rr, addr)


if __name__ == "__main__":
    for fn in (http_server, tls_responder, dns_responder):
        threading.Thread(target=fn, daemon=True).start()
    # Scenario 01 filters port 80 specifically
    threading.Thread(target=http_server, args=(80,), daemon=True).start()
    threading.Event().wait()
