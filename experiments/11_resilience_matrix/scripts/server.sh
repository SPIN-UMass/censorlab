#!/usr/bin/env bash
# server.sh — runs inside the `server` container: an HTTP origin plus the server
# side of each circumvention tool.  Connection parameters the clients need
# (obfs4 certificate) are published to /results.
set -euo pipefail
ME=172.31.0.20
mkdir -p /www /tmp/obfs4 /tmp/snowflake /results
# Origin: files of several sizes so tunnelled flows have realistic shapes
for kb in 1 4 16 64 256 1024; do head -c $((kb * 1024)) /dev/urandom > /www/f_${kb}k; done
( cd /www && python3 -m http.server 8000 --bind 0.0.0.0 >/results/origin.log 2>&1 ) &

# Shadowsocks (AEAD 2022-style cipher widely deployed)
ssserver -s 0.0.0.0:8388 -k censorlab-resilience -m chacha20-ietf-poly1305 >/results/ssserver.log 2>&1 &

# obfs4 via lyrebird in managed-transport server mode; ORPort is the origin.
TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_STATE_LOCATION=/tmp/obfs4 \
TOR_PT_SERVER_TRANSPORTS=obfs4 TOR_PT_SERVER_BINDADDR=obfs4-0.0.0.0:4443 \
TOR_PT_ORPORT=127.0.0.1:8000 TOR_PT_EXIT_ON_STDIN_CLOSE=0 \
    lyrebird >/results/obfs4-server.log 2>&1 &
for i in $(seq 1 30); do [ -f /tmp/obfs4/obfs4_bridgeline.txt ] && break; sleep 1; done
grep -o 'cert=[^ ]*' /tmp/obfs4/obfs4_bridgeline.txt | head -1 > /results/obfs4_cert.txt
echo "obfs4 $(cat /results/obfs4_cert.txt)"

# Snowflake: broker + WebSocket server (ORPort = origin) + one standalone proxy,
# all local; the client rendezvous via the broker over plain HTTP.
cat > /tmp/bridges.jsonl <<JSON
{"displayName":"local","webSocketAddress":"ws://$ME:8443","fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80A72"}
JSON
broker -disable-tls -addr 0.0.0.0:8080 -bridge-list-path /tmp/bridges.jsonl \
       -allowed-relay-pattern "^$ME$" -default-relay-pattern "^$ME$" -disable-geoip -unsafe-logging \
       >/results/snowflake-broker.log 2>&1 &
TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_STATE_LOCATION=/tmp/snowflake \
TOR_PT_SERVER_TRANSPORTS=snowflake TOR_PT_SERVER_BINDADDR=snowflake-0.0.0.0:8443 \
TOR_PT_ORPORT=127.0.0.1:8000 TOR_PT_EXIT_ON_STDIN_CLOSE=0 \
    server -disable-tls -unsafe-logging >/results/snowflake-server.log 2>&1 &
sleep 2
proxy -broker http://127.0.0.1:8080/ -relay ws://$ME:8443 -allow-non-tls-relay \
      -allow-proxying-to-private-addresses -allowed-relay-hostname-pattern "^$ME$" \
      -stun "${STUN:-stun:stun.l.google.com:19302}" -unsafe-logging -capacity 10 \
      >/results/snowflake-proxy.log 2>&1 &

touch /results/server.ready
echo "server ready"
wait
