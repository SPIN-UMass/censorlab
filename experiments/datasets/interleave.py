#!/usr/bin/env python3
"""interleave.py — mix a labelled scenario PCAP with real background traffic.

Produces a new PCAP in which the scenario's flows are interleaved, in time,
with packets drawn from one or more background captures, plus a labels CSV
for the mixed file.  This is the "background-traffic interleaving" used by
experiments/08_real_traffic (MR4): the censor programs must find the labelled
flows inside realistic traffic instead of a PCAP that contains nothing else.

Method
  * --background may be given more than once; each occurrence is one
    background *source* (e.g. one dataset).  The --background-packets budget
    is split evenly across sources (remainder to the earlier ones), so a
    USTC-TFC2016 + ISCXVPN2016 mix gets half its packets from each.  With a
    single source the behaviour is exactly that of the original tool.
  * Within a source, packets are read from its captures in order (after an
    optional --background-offset) and truncated to the source's share (all if
    --background-packets is omitted).  Non-IP frames are dropped; frames are
    re-framed as Ethernet.
  * Each source's timestamps are rescaled linearly onto the scenario's time
    span so that all sources overlap uniformly; ties go to the scenario
    packet, then to the earlier source.  Relative order *within* each source
    is kept, so every TCP stream stays valid.
  * Background hosts are left unmodified, except that any address colliding
    with a scenario address (or, for the second and later sources, with an
    address of an earlier source) is rewritten into 172.16.0.0/12 (with
    checksums recomputed) so flows from different origins can never merge.
  * Labels are re-indexed to flow ordinals in the mixed file (see
    common/report.py); the original index is kept as `scenario_index`.
    Background flows are unlabelled; the reporting module counts tool
    decisions on them separately ("background_flagged").

Usage
  interleave.py --scenario-pcap 03_tls_sni/pcap/test.pcap \
                --scenario-labels 03_tls_sni/pcap/labels.csv \
                --background datasets/ustc-tfc2016/*.pcap \
                [--background datasets/iscxvpn2016/pcap/*.pcap] \
                --background-packets 90000 \
                --output pcap/03_tls_sni_bg90k.pcap --output-labels pcap/03_tls_sni_bg90k.labels.csv
"""

import argparse
import csv
import heapq
import ipaddress
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "common"))
from pcaprecords import PcapWriter, ip_addresses, iter_records, to_ethernet  # noqa: E402
from report import FlowTable  # noqa: E402


def read_scenario(path):
    pkts = []
    addrs = set()
    for ts, frame, lt in iter_records(path):
        eth = to_ethernet(frame, lt)
        if eth is None:
            eth = frame  # keep non-IP frames (ARP etc.) as they are
        else:
            a = ip_addresses(eth, 1)
            if a:
                addrs.update(a)
        pkts.append((ts, eth))
    return pkts, addrs


def read_background(paths, offset, limit):
    pkts = []
    skipped = 0
    for path in paths:
        for ts, frame, lt in iter_records(path):
            if skipped < offset:
                skipped += 1
                continue
            eth = to_ethernet(frame, lt)
            if eth is None:
                continue
            pkts.append((ts, eth))
            if limit is not None and len(pkts) >= limit:
                return pkts
    return pkts


def addresses(pkts):
    out = set()
    for _ts, frame in pkts:
        a = ip_addresses(frame, 1)
        if a:
            out.update(a)
    return out


def remap_collisions(bg, reserved, pool):
    """Rewrite background addresses that collide with `reserved` addresses.

    `pool` is a shared iterator of replacement addresses (strings);
    replacements that are themselves reserved are skipped.
    """
    colliding = set()
    for _ts, frame in bg:
        a = ip_addresses(frame, 1)
        if a:
            colliding.update(x for x in a if x in reserved)
    if not colliding:
        return bg, {}
    remap = {}
    for a in sorted(colliding):
        new = next(pool)
        while new in reserved:
            new = next(pool)
        remap[a] = new

    from scapy.all import IP, TCP, UDP, Ether  # only needed for checksum recomputation

    out = []
    for ts, frame in bg:
        a = ip_addresses(frame, 1)
        if not a or not (a[0] in remap or a[1] in remap):
            out.append((ts, frame))
            continue
        pkt = Ether(frame)
        ip = pkt.getlayer(IP)
        if ip is None:
            out.append((ts, frame))
            continue
        if ip.src in remap:
            ip.src = remap[ip.src]
        if ip.dst in remap:
            ip.dst = remap[ip.dst]
        del ip.chksum
        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if l4 is not None:
            del l4.chksum
        out.append((ts, bytes(pkt)))
    return out, remap


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario-pcap", required=True)
    ap.add_argument("--scenario-labels", required=True)
    ap.add_argument("--background", nargs="+", action="append", required=True,
                    help="background PCAP file(s) of one source; repeat for several sources")
    ap.add_argument("--background-packets", type=int, default=None,
                    help="total background packets, split evenly across sources (default: all)")
    ap.add_argument("--background-offset", type=int, default=0,
                    help="skip this many packets of each source first")
    ap.add_argument("--output", required=True)
    ap.add_argument("--output-labels", required=True)
    args = ap.parse_args()

    scen, scen_addrs = read_scenario(args.scenario_pcap)
    if not scen:
        sys.exit("empty scenario pcap")
    if args.background_packets is not None and args.background_packets < 0:
        sys.exit("--background-packets must be >= 0")
    sources = args.background
    if args.background_packets is None:
        shares = [None] * len(sources)
    else:
        q, r = divmod(args.background_packets, len(sources))
        shares = [q + (1 if k < r else 0) for k in range(len(sources))]

    s_t0, s_t1 = scen[0][0], scen[-1][0]
    span_s = (s_t1 - s_t0) or 1.0
    reserved = set(scen_addrs)
    pool = (str(h) for h in ipaddress.ip_network("172.16.0.0/12").hosts())
    remap = {}
    streams = []
    for paths, share in zip(sources, shares):
        if share == 0:
            continue
        src = read_background(paths, args.background_offset, share)
        if not src:
            sys.exit(f"no background packets read from {' '.join(paths)}")
        if share is not None and len(src) < share:
            print(f"warning: wanted {share} background packets from {' '.join(paths)}, "
                  f"got {len(src)}", file=sys.stderr)
        src, src_remap = remap_collisions(src, reserved, pool)
        remap.update(src_remap)
        reserved |= addresses(src)
        # Rescale this source's time onto the scenario's span, preserving order.
        b_t0, b_t1 = src[0][0], src[-1][0]
        span_b = (b_t1 - b_t0) or 1.0
        streams.append([(s_t0 + (ts - b_t0) / span_b * span_s, frame) for ts, frame in src])
    if not streams:
        sys.exit("no background packets read")
    # Stable k-way merge of the sources by timestamp (earlier source wins ties).
    bg = [(ts, frame) for ts, _k, _i, frame in heapq.merge(
        *[[(ts, k, i, frame) for i, (ts, frame) in enumerate(s)] for k, s in enumerate(streams)])]

    # Stable two-way merge by timestamp (scenario wins ties).
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    n = 0
    i = j = 0
    with PcapWriter(args.output) as w:
        while i < len(scen) or j < len(bg):
            if j >= len(bg) or (i < len(scen) and scen[i][0] <= bg[j][0]):
                w.write(*scen[i]); i += 1
            else:
                w.write(*bg[j]); j += 1
            n += 1

    # Re-index labels to flow ordinals in the mixed file.
    scen_flows = FlowTable(args.scenario_pcap)
    mixed_flows = FlowTable(args.output)
    ordinal_to_key = {v: k for k, v in scen_flows.key_to_flow.items()}
    with open(args.scenario_labels, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = list(reader)
    idx_col = "index" if "index" in fieldnames else "flow_index"
    out_rows = []
    for row in rows:
        row = dict(row)
        row["scenario_index"] = row[idx_col]
        row[idx_col] = mixed_flows.key_to_flow[ordinal_to_key[int(row[idx_col])]]
        out_rows.append(row)
    out_rows.sort(key=lambda r: int(r[idx_col]))
    with open(args.output_labels, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames + ["scenario_index"])
        w.writeheader()
        w.writerows(out_rows)

    print(f"scenario: {len(scen)} pkts / {scen_flows.num_flows} flows; "
          f"background: {len(bg)} pkts / {mixed_flows.num_flows - scen_flows.num_flows} flows "
          f"({len(remap)} addresses remapped); mixed: {n} pkts -> {args.output}")


if __name__ == "__main__":
    main()
