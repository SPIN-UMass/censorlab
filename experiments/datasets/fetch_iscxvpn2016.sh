#!/usr/bin/env bash
# fetch_iscxvpn2016.sh — ingest the non-VPN application captures of ISCXVPN2016
# (UNB CIC "VPN-nonVPN", Draper-Gil et al., ICISSP 2016) as real background
# traffic for experiments/08_real_traffic.
#
# The dataset is distributed by the Canadian Institute for Cybersecurity behind
# a registration form (name, e-mail, organisation), so it cannot be fetched
# non-interactively.  Manual step, once:
#
#   1. Open http://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/ , fill in the
#      form, then "Browse files" -> Dataset/PCAPs/.
#   2. Download the non-VPN archives (NonVPN-PCAPs-01.zip, -02.zip, -03.zip;
#      the VPN-PCAPs-*.zip archives are not used) into
#      $ISCXVPN2016_DIR/archives/  (default below).
#   3. Run this script.  It records the archives' SHA-256 on first sight
#      (archives.sha256) and verifies them on every later run; paste the
#      printed sums into ARCHIVE_SHA256 below and commit to pin them.
#
# One capture per application (APPS below) is extracted, converted from pcapng
# where needed (editcap), re-framed as Ethernet legacy pcap (normalize_pcap.py;
# CensorLab's pcap mode accepts only LINKTYPE_ETHERNET) and truncated to
# ISCX_MAX_PACKETS IP frames, giving $ISCXVPN2016_DIR/pcap/NN_<app>.pcap.
# MANIFEST.tsv records each file's source member, original format and link
# type, frame counts and SHA-256; SHA256SUMS is verified on every run.
#
# Large data lives outside the repository: $ISCXVPN2016_DIR (default
# /mnt/shared/jsheffey/censorlab/datasets/iscxvpn2016).  A symlink
# experiments/datasets/iscxvpn2016 -> $ISCXVPN2016_DIR is (re)created so the
# experiment scripts can use a fixed, git-ignored path.
#
# Usage: bash experiments/datasets/fetch_iscxvpn2016.sh [ARCHIVE.zip ...]
#   (archives default to $ISCXVPN2016_DIR/archives/*.zip)
# Env:   ISCXVPN2016_DIR   dataset location (default: see above)
#        ISCX_MAX_PACKETS  IP frames kept per capture (default 20000)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${ISCXVPN2016_DIR:-/mnt/shared/jsheffey/censorlab/datasets/iscxvpn2016}"
MAX_PACKETS="${ISCX_MAX_PACKETS:-20000}"
LINK="$SCRIPT_DIR/iscxvpn2016"
FORM_URL="http://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/"

[[ "$MAX_PACKETS" =~ ^[1-9][0-9]*$ ]] || { echo "ISCX_MAX_PACKETS must be a positive integer" >&2; exit 1; }

# Pinned archive checksums (archive basename -> sha256).  Empty: trust on first
# use via $DEST/archives.sha256.
declare -A ARCHIVE_SHA256=(
)

# Applications, in background-read order (interleave.py reads captures in
# order, so the order is chosen to alternate traffic classes: a small budget
# still covers streaming, VoIP, chat, e-mail, file transfer and P2P).
# name  extended regex on the lower-cased member basename (VPN captures, whose
# names start with "vpn", are never selected).
APPS="
youtube         ^youtube[0-9]
skype_audio     ^skype_audio
email           ^email
netflix         ^netflix
facebook_chat   ^facebook_?chat
sftp            ^sftp
spotify         ^spotify
hangouts_video  ^hangouts?_video
torrent         ^torrent
icq_chat        ^icq_?chat
ftps            ^ftps
vimeo           ^vimeo
voipbuster      ^voipbuster
aim_chat        ^aim_?chat
skype_video     ^skype_video
facebook_audio  ^facebook_audio
scp             ^scp
gmail_chat      ^gmail_?chat
hangouts_audio  ^hangouts?_audio
skype_file      ^skype_file
facebook_video  ^facebook_video
hangouts_chat   ^hangouts?_chat
skype_chat      ^skype_chat
"

die() { echo "fetch_iscxvpn2016: $*" >&2; exit 1; }

if ! mkdir -p "$DEST/archives" "$DEST/pcap" 2>/dev/null; then
    die "cannot create $DEST (set ISCXVPN2016_DIR to a writable location)"
fi
if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
    die "$LINK exists and is not a symlink; move it away"
fi
ln -sfn "$DEST" "$LINK"

# ---- already ingested? ------------------------------------------------------
config_line="# max_packets=$MAX_PACKETS"
if [ -f "$DEST/MANIFEST.tsv" ] && [ -f "$DEST/SHA256SUMS" ] \
    && [ "$(head -n1 "$DEST/MANIFEST.tsv")" = "$config_line" ] \
    && (cd "$DEST/pcap" && sha256sum -c --status ../SHA256SUMS); then
    echo "  [ok]   ISCXVPN2016: $(wc -l < "$DEST/SHA256SUMS") captures verified"
    echo "Dataset in $DEST"
    exit 0
fi

# ---- archives ---------------------------------------------------------------
ARCHIVES=("$@")
if [ ${#ARCHIVES[@]} -eq 0 ]; then
    shopt -s nullglob
    ARCHIVES=("$DEST"/archives/*.zip)
    shopt -u nullglob
fi
if [ ${#ARCHIVES[@]} -eq 0 ]; then
    cat >&2 <<EOF
fetch_iscxvpn2016: no archives found in $DEST/archives/.

ISCXVPN2016 requires registration and must be downloaded by hand:
  1. open $FORM_URL and submit the form;
  2. "Browse files" -> Dataset/PCAPs/ and download NonVPN-PCAPs-01.zip,
     NonVPN-PCAPs-02.zip and NonVPN-PCAPs-03.zip into $DEST/archives/;
  3. re-run: bash experiments/datasets/fetch_iscxvpn2016.sh
EOF
    exit 1
fi

for t in unzip editcap sha256sum python3; do
    command -v "$t" >/dev/null || die "missing '$t' (use: nix develop .#experiments)"
done

touch "$DEST/archives.sha256"
for a in "${ARCHIVES[@]}"; do
    [ -f "$a" ] || die "no such archive: $a"
    base="$(basename "$a")"
    sum="$(sha256sum "$a" | cut -d' ' -f1)"
    pinned="${ARCHIVE_SHA256[$base]:-}"
    recorded="$(awk -v b="$base" '$2 == b { print $1 }' "$DEST/archives.sha256")"
    if [ -n "$pinned" ] && [ "$sum" != "$pinned" ]; then
        die "checksum mismatch for $base (pinned $pinned, got $sum)"
    elif [ -n "$recorded" ] && [ "$sum" != "$recorded" ]; then
        die "checksum mismatch for $base (recorded $recorded, got $sum)"
    elif [ -z "$pinned" ] && [ -z "$recorded" ]; then
        echo "$sum  $base" >> "$DEST/archives.sha256"
        echo "  [new]  $base  sha256 $sum  (recorded; pin it in ARCHIVE_SHA256)"
    else
        echo "  [ok]   $base"
    fi
done

# ---- select one capture per application -------------------------------------
# Candidate list: "<lower-cased basename>\t<archive>\t<member>", sorted so the
# choice is deterministic.  Members with glob metacharacters or path
# components that are not plain are ignored (unzip treats member arguments as
# patterns).
candidates="$(
    for a in "${ARCHIVES[@]}"; do
        unzip -Z1 "$a" | while IFS= read -r m; do
            b="${m##*/}"
            [[ "$b" =~ ^[A-Za-z0-9._-]+\.(pcap|pcapng)$ ]] || continue
            [[ "$m" =~ ^[A-Za-z0-9._/-]+$ ]] || continue
            lb="${b,,}"
            [[ "$lb" == vpn* ]] && continue
            printf '%s\t%s\t%s\n' "$lb" "$a" "$m"
        done
    done | LC_ALL=C sort
)"
[ -n "$candidates" ] || die "no .pcap/.pcapng members found in the archives"

WORK="$(mktemp -d "$DEST/.work.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
rm -f "$DEST"/pcap/*.pcap
manifest="$WORK/MANIFEST.tsv"
{
    echo "$config_line"
    printf 'file\tapp\tarchive\tmember\tsource_format\tsource_linktype\tframes_read\tip_frames_kept\tsha256\n'
} > "$manifest"

idx=0
missing=()
while read -r app regex; do
    [ -z "$app" ] && continue
    line="$(awk -F'\t' -v re="$regex" '$1 ~ re { print; exit }' <<< "$candidates")"
    if [ -z "$line" ]; then
        missing+=("$app")
        echo "  [miss] $app (no member matching /$regex/)"
        continue
    fi
    IFS=$'\t' read -r _lb archive member <<< "$line"
    idx=$((idx + 1))
    out="$(printf '%02d_%s.pcap' "$idx" "$app")"
    ex="$WORK/extract"
    rm -rf "$ex"; mkdir "$ex"
    unzip -q -j -o "$archive" "$member" -d "$ex" < /dev/null
    src="$ex/${member##*/}"
    magic="$(od -An -N4 -tx1 "$src" | tr -d ' \n')"
    if [ "$magic" = "0a0d0d0a" ]; then
        fmt=pcapng
        editcap -F pcap "$src" "$ex/converted.pcap" < /dev/null \
            || { echo "  [skip] $app: editcap could not convert $member" >&2; idx=$((idx - 1)); missing+=("$app"); continue; }
        legacy="$ex/converted.pcap"
    else
        fmt=pcap
        legacy="$src"
    fi
    if ! stats="$(python3 -I "$SCRIPT_DIR/normalize_pcap.py" "$legacy" "$DEST/pcap/$out" --max-packets "$MAX_PACKETS" < /dev/null)"; then
        echo "  [skip] $app: $member not usable" >&2
        idx=$((idx - 1)); missing+=("$app"); continue
    fi
    IFS=$'\t' read -r linktype n_in n_out <<< "$stats"
    sum="$(sha256sum "$DEST/pcap/$out" | cut -d' ' -f1)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$out" "$app" "$(basename "$archive")" "$member" "$fmt" "$linktype" "$n_in" "$n_out" "$sum" >> "$manifest"
    echo "  [add]  $out  <- $member ($fmt, linktype $linktype, $n_out IP frames)"
    rm -rf "$ex"
done <<< "$APPS"

[ "$idx" -gt 0 ] || die "no usable captures extracted"
mv "$manifest" "$DEST/MANIFEST.tsv"
(cd "$DEST/pcap" && sha256sum -- *.pcap) > "$DEST/SHA256SUMS"
[ ${#missing[@]} -eq 0 ] || echo "  note: no capture for: ${missing[*]}"
echo "Dataset in $DEST ($idx captures, $(du -sh "$DEST/pcap" | cut -f1))"
