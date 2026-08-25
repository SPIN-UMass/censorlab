# common.sh — shared definitions for 08_real_traffic scripts (sourced).

DEFAULT_SCENARIOS=(01_http_keyword 02_dns_injection 03_tls_sni 04_shadowsocks 05_ml_classification)

# load_mixes <mixes.conf> — sets MIX_NAMES (ordered) and MIX_PACKETS[name]
load_mixes() {
    MIX_NAMES=()
    declare -g -A MIX_PACKETS=()
    local line lineno=0
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        if [[ "$line" =~ ^([a-z][a-z0-9_]*)=([0-9]+)[[:space:]]*$ ]]; then
            MIX_NAMES+=("${BASH_REMATCH[1]}")
            MIX_PACKETS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
        else
            echo "mixes.conf:$lineno: unrecognized line: $line" >&2
            return 1
        fi
    done < "$1"
}
