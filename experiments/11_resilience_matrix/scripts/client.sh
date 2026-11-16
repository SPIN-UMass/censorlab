#!/usr/bin/env bash
# client.sh — runs inside the `client` container: tunnels N HTTP fetches through
# each circumvention tool while tcpdump records the wire traffic.
#
# Output per tool in /results:  <tool>.pcap  <tool>.fetches.csv  <tool>*.log
# Environment: N_FETCHES (default 60; Snowflake uses N_FETCHES/6), TOOLS, STUN
set -euo pipefail
SERVER=172.31.0.20
OUT=/results
N="${N_FETCHES:-60}"
read -r -a TOOLS <<< "${TOOLS:-shadowsocks obfs4 snowflake}"
SIZES=(1 4 16 64 256 1024)
FETCH=/censorlab/experiments/11_resilience_matrix/scripts/socks_fetch.py

for _ in $(seq 1 60); do [ -f $OUT/server.ready ] && break; sleep 1; done
sleep 2

start_capture() {  # tool filter
    tcpdump -i eth0 -nn -U -w "$OUT/$1.pcap" "$2" >/dev/null 2>&1 &
    CAP_PID=$!
    sleep 1
}

stop_capture() {
    sleep 1
    kill -INT "$CAP_PID" 2>/dev/null || true
    wait "$CAP_PID" 2>/dev/null || true
}

# fetch_loop TOOL PROXY_PORT N TARGET_PORT [PT_ARGS]
fetch_loop() {
    local tool="$1" port="$2" n="$3" tport="$4" args="${5:-}"
    echo "index,size_kb,result,bytes,seconds,error" > "$OUT/$tool.fetches.csv"
    for i in $(seq 0 $((n - 1))); do
        kb=${SIZES[$((RANDOM % ${#SIZES[@]}))]}
        if [ -n "$args" ]; then
            res=$(python3 "$FETCH" 127.0.0.1 "$port" $SERVER "$tport" "/f_${kb}k" "$args" 2>&1 || true)
        else
            res=$(python3 "$FETCH" 127.0.0.1 "$port" $SERVER "$tport" "/f_${kb}k" 2>&1 || true)
        fi
        if [[ "$res" == ok* ]]; then
            read -r _ bytes secs <<< "$res"
            echo "$i,$kb,ok,$bytes,$secs," >> "$OUT/$tool.fetches.csv"
        else
            echo "$i,$kb,fail,,,\"${res//\"/}\"" >> "$OUT/$tool.fetches.csv"
        fi
        sleep "0.$((RANDOM % 5))"
    done
    echo "$tool: $(grep -c ',ok,' "$OUT/$tool.fetches.csv" || true) / $n fetches succeeded"
}

pt_port() {  # LOG TRANSPORT -> socks port announced by the PT client
    grep "^CMETHOD $2 " "$1" | sed -E 's/.*:([0-9]+)[[:space:]]*$/\1/'
}

for tool in "${TOOLS[@]}"; do
    echo "== $tool =="
    case "$tool" in
        shadowsocks)
            sslocal -b 127.0.0.1:1080 -s $SERVER:8388 -k censorlab-resilience -m chacha20-ietf-poly1305 \
                >"$OUT/shadowsocks.log" 2>&1 &
            pid=$!
            sleep 2
            start_capture shadowsocks "host $SERVER and tcp port 8388"
            fetch_loop shadowsocks 1080 "$N" 8000
            stop_capture
            kill $pid 2>/dev/null || true
            ;;
        obfs4)
            cert=$(cat $OUT/obfs4_cert.txt)
            mkdir -p /tmp/obfs4c
            TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_STATE_LOCATION=/tmp/obfs4c TOR_PT_CLIENT_TRANSPORTS=obfs4 \
            TOR_PT_EXIT_ON_STDIN_CLOSE=0 lyrebird -enableLogging -logLevel INFO >"$OUT/obfs4.log" 2>&1 &
            pid=$!
            for _ in $(seq 1 20); do grep -q '^CMETHOD obfs4 ' "$OUT/obfs4.log" 2>/dev/null && break; sleep 1; done
            port=$(pt_port "$OUT/obfs4.log" obfs4)
            echo "obfs4 client socks on $port"
            start_capture obfs4 "host $SERVER and tcp port 4443"
            # PT clients take the *bridge* address as the SOCKS target and the
            # bridge parameters as SOCKS username/password (pt-spec §3.5).
            fetch_loop obfs4 "$port" "$N" 4443 "$cert;iat-mode=0"
            stop_capture
            kill $pid 2>/dev/null || true
            cp /tmp/obfs4c/lyrebird.log "$OUT/obfs4-client.log" 2>/dev/null || true
            ;;
        snowflake)
            mkdir -p /tmp/sfc
            TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_STATE_LOCATION=/tmp/sfc TOR_PT_CLIENT_TRANSPORTS=snowflake \
            TOR_PT_EXIT_ON_STDIN_CLOSE=0 \
                client -url http://$SERVER:8080/ -ice "${STUN:-stun:stun.l.google.com:19302}" \
                       -keep-local-addresses -unsafe-logging -max 1 >"$OUT/snowflake.log" 2>&1 &
            pid=$!
            for _ in $(seq 1 20); do grep -q '^CMETHOD snowflake ' "$OUT/snowflake.log" 2>/dev/null && break; sleep 1; done
            port=$(pt_port "$OUT/snowflake.log" snowflake)
            echo "snowflake client socks on $port"
            # Broker rendezvous (HTTP :8080), STUN and WebRTC/DTLS (UDP) — i.e. every
            # packet to the server host that is not one of the other tunnels/origin.
            start_capture snowflake "host $SERVER and not tcp port 8388 and not tcp port 4443 and not tcp port 8000"
            fetch_loop snowflake "$port" $(( N / 6 > 0 ? N / 6 : 1 )) 8443
            stop_capture
            kill $pid 2>/dev/null || true
            ;;
        *)
            echo "unknown tool $tool" >&2
            ;;
    esac
done
echo "== client done =="
