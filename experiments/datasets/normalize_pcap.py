#!/usr/bin/env python3
"""normalize_pcap.py — rewrite a legacy pcap as an Ethernet-framed legacy pcap.

Used when ingesting third-party captures (experiments/datasets/
fetch_iscxvpn2016.sh) so that everything under a dataset's pcap/ directory has
exactly one shape: libpcap, LINKTYPE_ETHERNET, IPv4/IPv6 frames only.  That is
what CensorLab's pcap mode accepts, and what interleave.py emits.

Input must already be a *legacy* pcap (convert pcapng first with
`editcap -F pcap`).  Frames are parsed by common/pcaprecords.py, which accepts
only the fixed-layout link types it knows (Ethernet, Linux SLL, raw IP);
any other link type is rejected with exit status 2 rather than guessed at.
Non-IP frames (ARP, LLDP, ...) are dropped.

Prints one tab-separated line: linktype, frames_in, frames_out.

Usage: normalize_pcap.py INPUT OUTPUT [--max-packets N]
"""

import argparse
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "common"))
from pcaprecords import (  # noqa: E402
    LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL, LINKTYPE_RAW,
    PcapFormatError, PcapWriter, iter_records, read_header, to_ethernet,
)

SUPPORTED = {LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_IPV4, LINKTYPE_IPV6}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="stop after writing this many IP frames (default: all)")
    args = ap.parse_args()
    if args.max_packets is not None and args.max_packets <= 0:
        sys.exit("--max-packets must be positive")

    try:
        with open(args.input, "rb") as f:
            _endian, _tick, _snaplen, linktype = read_header(f)
    except PcapFormatError as e:
        print(f"{args.input}: {e}", file=sys.stderr)
        sys.exit(2)
    if linktype not in SUPPORTED:
        print(f"{args.input}: unsupported link type {linktype}", file=sys.stderr)
        sys.exit(2)

    n_in = n_out = 0
    tmp = args.output + ".part"
    with PcapWriter(tmp) as w:
        for ts, frame, lt in iter_records(args.input):
            n_in += 1
            eth = to_ethernet(frame, lt)
            if eth is None:
                continue
            w.write(ts, eth)
            n_out += 1
            if args.max_packets is not None and n_out >= args.max_packets:
                break
    if n_out == 0:
        os.unlink(tmp)
        print(f"{args.input}: no IP frames", file=sys.stderr)
        sys.exit(2)
    os.replace(tmp, args.output)
    print(f"{linktype}\t{n_in}\t{n_out}")


if __name__ == "__main__":
    main()
