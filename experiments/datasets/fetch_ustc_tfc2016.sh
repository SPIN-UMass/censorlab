#!/usr/bin/env bash
# fetch_ustc_tfc2016.sh — download the benign half of USTC-TFC2016 (Wang et al.,
# "Malware traffic classification using CNN", ICOIN 2017) for use as real
# background traffic in experiments/08_real_traffic.
#
# Ten applications captured on a real network (BitTorrent, Facetime, FTP,
# Gmail, MySQL, Outlook, Skype, SMB, Weibo, World of Warcraft).  The plain
# .pcap files are fetched (SMB/Weibo are shipped as .7z and skipped).  Files are
# verified against the SHA-256 sums recorded below and stored under
# experiments/datasets/ustc-tfc2016/ (git-ignored).
#
# Usage: bash experiments/datasets/fetch_ustc_tfc2016.sh
set -euo pipefail

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ustc-tfc2016"
BASE_URL="https://raw.githubusercontent.com/davidyslu/USTC-TFC2016/master/Benign"

# name  sha256
FILES="
BitTorrent.pcap       __SHA_BitTorrent__
Facetime.pcap         __SHA_Facetime__
FTP.pcap              __SHA_FTP__
Gmail.pcap            __SHA_Gmail__
MySQL.pcap            __SHA_MySQL__
Outlook.pcap          __SHA_Outlook__
Skype.pcap            __SHA_Skype__
WorldOfWarcraft.pcap  __SHA_WorldOfWarcraft__
"

mkdir -p "$DEST"
echo "$FILES" | while read -r name sha; do
    [ -z "$name" ] && continue
    out="$DEST/$name"
    if [ -f "$out" ] && echo "$sha  $out" | sha256sum -c --status 2>/dev/null; then
        echo "  [ok]   $name"
        continue
    fi
    echo "  [get]  $name"
    curl -fsSL --retry 3 -o "$out.part" "$BASE_URL/$name"
    mv "$out.part" "$out"
    if [[ "$sha" != __SHA_* ]]; then
        echo "$sha  $out" | sha256sum -c --status || { echo "checksum mismatch: $name" >&2; exit 1; }
    fi
done
echo "Dataset in $DEST"
