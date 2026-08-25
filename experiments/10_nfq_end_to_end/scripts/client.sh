#!/usr/bin/env bash
# client.sh — runs inside the client container once the path to the server is up.
#
#   1. latency probe   : N sequential HTTP requests through the censor -> latency.csv
#   2. bulk throughput : iperf3 client for IPERF_SECONDS            -> iperf.json
#   3. scenario traffic: the scenario's live generator (if SCENARIO set) -> live_eval_results.csv
#
# Environment: SCENARIO (01_http_keyword|02_dns_injection|03_tls_sni|04_shadowsocks|"")
#              N_REQUESTS (default 200), PROBE_N (default 200), IPERF_SECONDS (default 5)
set -euo pipefail
SERVER=172.30.0.20
OUT=/results
mkdir -p "$OUT"
EXP=/censorlab/experiments

echo "== latency probe =="
python3 "$EXP/10_nfq_end_to_end/scripts/probe.py" --host $SERVER --port 8080 --n "${PROBE_N:-200}" --output "$OUT/latency.csv"

echo "== iperf3 =="
iperf3 -c $SERVER -t "${IPERF_SECONDS:-5}" -J > "$OUT/iperf.json" || echo '{}' > "$OUT/iperf.json"
python3 - "$OUT/iperf.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
try:
    bps = d["end"]["sum_received"]["bits_per_second"]
    print(f"iperf3: {bps/1e6:.1f} Mbit/s received, retransmits {d['end']['sum_sent'].get('retransmits','?')}")
except KeyError:
    print("iperf3: no result")
PY

case "${SCENARIO:-}" in
    01_http_keyword)
        python3 "$EXP/01_http_keyword/scripts/generate_traffic.py" --host $SERVER --port 8080 \
            --num-requests "${N_REQUESTS:-200}" --output "$OUT/live_eval_results.csv" ;;
    02_dns_injection)
        python3 "$EXP/02_dns_injection/scripts/generate_traffic.py" --resolver $SERVER \
            --n "$(( ${N_REQUESTS:-200} / 2 ))" --output "$OUT/live_eval_results.csv" ;;
    03_tls_sni)
        python3 "$EXP/03_tls_sni/scripts/generate_traffic.py" --host $SERVER --port 443 \
            --num-requests "${N_REQUESTS:-200}" --output "$OUT/live_eval_results.csv" ;;
    04_shadowsocks)
        python3 "$EXP/04_shadowsocks/scripts/generate_traffic.py" --host $SERVER --port 443 \
            --num-requests "${N_REQUESTS:-200}" --output "$OUT/live_eval_results.csv" ;;
    "") echo "no scenario traffic requested" ;;
    *)  echo "unknown SCENARIO ${SCENARIO}" >&2; exit 2 ;;
esac
echo "== client done =="
