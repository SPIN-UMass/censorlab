#!/usr/bin/env bash
# run_live_eval_docker.sh — Run live evaluations (Table 3) inside Docker
#
# Runs each experiment's run_evaluation.sh inside a Docker container
# with NET_ADMIN capabilities (needed for iptables/NFQUEUE).
#
# Usage:
#   bash experiments/scripts/run_live_eval_docker.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENTS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$EXPERIMENTS_DIR")"

IMAGE="censorlab:latest"

echo "============================================================"
echo "  CensorLab — Live Evaluation Pipeline (Docker)"
echo "============================================================"
echo "Image: $IMAGE"
echo ""

FAILED=()

# ----------------------------------------------------------------
# Experiment 01: HTTP Keyword Filtering
# ----------------------------------------------------------------
echo "=== Experiment 01: HTTP Keyword Filtering ==="
echo "Starting HTTP server and running evaluation..."
docker run --rm \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    -v "$EXPERIMENTS_DIR/01_http_keyword:/experiment" \
    "$IMAGE" bash -c '
        source /dev-env.sh
        # Start a simple HTTP server in the background
        python3 -c "
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading, random, string
class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        words = [chr(random.randint(97,122)) * random.randint(3,8) for _ in range(100)]
        self.send_response(200)
        self.send_header(\"Content-Type\", \"text/plain\")
        self.end_headers()
        self.wfile.write(\" \".join(words).encode())
    def log_message(self, *args): pass
HTTPServer((\"0.0.0.0\", 8080), Handler).serve_forever()
" &
        sleep 1
        TARGET_HOST=127.0.0.1 TARGET_PORT=8080 NUM_REQUESTS=10000 \
            bash /experiment/scripts/run_evaluation.sh
    '
if [ $? -eq 0 ]; then
    echo "  [01] Evaluation complete"
else
    echo "  [01] WARNING: evaluation failed"
    FAILED+=("01_http_keyword")
fi
echo ""

# ----------------------------------------------------------------
# Experiment 02: DNS Injection
# ----------------------------------------------------------------
echo "=== Experiment 02: DNS Injection ==="
echo "Starting DNS resolver and running evaluation..."
docker run --rm \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    -v "$EXPERIMENTS_DIR/02_dns_injection:/experiment" \
    "$IMAGE" bash -c '
        source /dev-env.sh
        # Start a simple DNS server on port 53 that responds with 1.2.3.4
        # (for allowed queries that pass through the censor)
        python3 -c "
import socket, struct
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((\"0.0.0.0\", 53))
while True:
    data, addr = sock.recvfrom(4096)
    # Build a minimal DNS response
    txid = data[:2]
    flags = struct.pack(\">H\", 0x8180)
    qdcount = data[4:6]
    ancount = struct.pack(\">H\", 1)
    nscount = struct.pack(\">H\", 0)
    arcount = struct.pack(\">H\", 0)
    # Find end of question section
    pos = 12
    while pos < len(data) and data[pos] != 0:
        pos += 1 + data[pos]
    pos += 5  # null + qtype + qclass
    question = data[12:pos]
    # Answer: pointer to name, type A, class IN, TTL 60, rdata 1.2.3.4
    answer = struct.pack(\">HHIH4s\", 1, 1, 60, 4, socket.inet_aton(\"1.2.3.4\"))
    answer = b\"\\xc0\\x0c\" + answer
    resp = txid + flags + qdcount + ancount + nscount + arcount + question + answer
    sock.sendto(resp, addr)
" &
        sleep 1
        RESOLVER=127.0.0.1 NUM_QUERIES=500 \
            bash /experiment/scripts/run_evaluation.sh
    '
if [ $? -eq 0 ]; then
    echo "  [02] Evaluation complete"
else
    echo "  [02] WARNING: evaluation failed"
    FAILED+=("02_dns_injection")
fi
echo ""

# ----------------------------------------------------------------
# Experiment 03: TLS SNI Filtering
# ----------------------------------------------------------------
echo "=== Experiment 03: TLS SNI Filtering ==="
echo "Starting TCP listener and running evaluation..."
docker run --rm \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    -v "$EXPERIMENTS_DIR/03_tls_sni:/experiment" \
    "$IMAGE" bash -c '
        source /dev-env.sh
        # Start a simple TCP echo server on port 443
        python3 -c "
import socket, threading
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((\"0.0.0.0\", 443))
server.listen(128)
def handle(conn):
    try:
        data = conn.recv(4096)
        conn.sendall(b\"HTTP/1.0 200 OK\r\n\r\n\")
    except: pass
    finally: conn.close()
while True:
    conn, _ = server.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
" &
        sleep 1
        TARGET_HOST=127.0.0.1 TARGET_PORT=443 NUM_REQUESTS=1000 \
            bash /experiment/scripts/run_evaluation.sh
    '
if [ $? -eq 0 ]; then
    echo "  [03] Evaluation complete"
else
    echo "  [03] WARNING: evaluation failed"
    FAILED+=("03_tls_sni")
fi
echo ""

# ----------------------------------------------------------------
# Experiment 04: Shadowsocks Detection
# ----------------------------------------------------------------
echo "=== Experiment 04: Shadowsocks Detection ==="
echo "Starting TCP listener and running evaluation..."
docker run --rm \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    -v "$EXPERIMENTS_DIR/04_shadowsocks:/experiment" \
    "$IMAGE" bash -c '
        source /dev-env.sh
        # Start a TCP echo server on port 443 (accepts both TLS and raw TCP)
        python3 -c "
import socket, threading
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((\"0.0.0.0\", 443))
server.listen(128)
def handle(conn):
    try:
        data = conn.recv(4096)
        conn.sendall(data[:64] if data else b\"\")
    except: pass
    finally: conn.close()
while True:
    conn, _ = server.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
" &
        sleep 1
        TARGET_HOST=127.0.0.1 TARGET_PORT=443 NUM_REQUESTS=1000 \
            bash /experiment/scripts/run_evaluation.sh
    '
if [ $? -eq 0 ]; then
    echo "  [04] Evaluation complete"
else
    echo "  [04] WARNING: evaluation failed"
    FAILED+=("04_shadowsocks")
fi
echo ""

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo "============================================================"
echo "  Live Evaluation Complete"
echo "============================================================"

for exp in 01_http_keyword 02_dns_injection 03_tls_sni 04_shadowsocks; do
    t3="$EXPERIMENTS_DIR/$exp/results/table3.json"
    if [ -f "$t3" ]; then
        echo "  [OK]   $exp/results/table3.json"
    else
        echo "  [MISS] $exp/results/table3.json"
    fi
done
echo ""

if [ ${#FAILED[@]} -gt 0 ]; then
    echo "Warnings (${#FAILED[@]} experiments had issues):"
    for f in "${FAILED[@]}"; do
        echo "  - $f"
    done
    exit 1
else
    echo "All experiments completed successfully."
fi
