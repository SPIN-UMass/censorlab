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
            local name="${BASH_REMATCH[1]}" packets="${BASH_REMATCH[2]}"
            if [[ "$name" =~ _(iscx|combined)$ ]]; then
                echo "mixes.conf:$lineno: mix names may not end in _iscx/_combined (reserved for BACKGROUND)" >&2
                return 1
            fi
            MIX_NAMES+=("$name")
            MIX_PACKETS["$name"]="$packets"
        else
            echo "mixes.conf:$lineno: unrecognized line: $line" >&2
            return 1
        fi
    done < "$1"
}

# Background traffic source, selected with BACKGROUND=ustc|iscx|combined
# (default combined):
#   ustc      USTC-TFC2016 benign captures only — the original study; mix ids,
#             PCAP names and result directories are unchanged (bg90k, ...)
#   iscx      ISCXVPN2016 non-VPN application captures only   (bg90k_iscx, ...)
#   combined  half of each mix's packets from each dataset    (bg90k_combined, ...)
BACKGROUNDS=(ustc iscx combined)
BACKGROUND="${BACKGROUND:-combined}"

# check_background — validate $BACKGROUND
check_background() {
    case "$BACKGROUND" in
        ustc|iscx|combined) ;;
        *) echo "BACKGROUND must be one of: ${BACKGROUNDS[*]} (got '$BACKGROUND')" >&2; return 1 ;;
    esac
}

# mix_id <mix> — name of a mix under $BACKGROUND, used for PCAPs and result dirs
mix_id() {
    if [ "$BACKGROUND" = ustc ]; then
        echo "$1"
    else
        echo "${1}_${BACKGROUND}"
    fi
}
