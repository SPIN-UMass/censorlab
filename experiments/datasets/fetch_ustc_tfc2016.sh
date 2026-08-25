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
BitTorrent.pcap       f4c4c59d460c6748110e6a0288c84a1362d7a3fa8a34b7a5cbe423de9e903deb
Facetime.pcap         b142bd39de652584521c1e5c0fa6d35630b69b27692e187b2b2aa14426bc699e
FTP.pcap              bccef78f0aaf26c3288094511b84b87717afa148bcff9203565d6049c8f3537e
Gmail.pcap            6b10fa77c165de6d621842f9becb158d9630b0c913ddf6df2f943a839b142d17
MySQL.pcap            fa5eda45d90a9c5835d9193d2708cac2a7380722be464bf961efe7b32f861b99
Outlook.pcap          4b6e69fe3c43e5277576491097429cb84b742764c9a1bdf463f0ef6c3377300d
Skype.pcap            30890a6c74f748d224b5fd1504bebc4e4103e5848d2fcb2acd4dc08ca3c2f761
WorldOfWarcraft.pcap  64eede78604b245f9ef842295dd5963884d2c39e1a04f90cd3c5ffadc552d06f
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
