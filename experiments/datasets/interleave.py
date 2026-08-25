#!/usr/bin/env python3
"""interleave.py — mix a labelled scenario PCAP with real background traffic.

Produces a new PCAP in which the scenario's flows are interleaved, in time,
with packets drawn from one or more background captures, plus a labels CSV
for the mixed file.  This is the "background-traffic interleaving" used by
experiments/08_real_traffic (MR4): the censor programs must find the labelled
flows inside realistic traffic instead of a PCAP that contains nothing else.

Method
  * Background packets are read from the given captures in order and
    truncated to --background-packets (all if omitted).  Non-IP frames are
    dropped.  Link-layer headers are normalized to Ethernet.
  * Background timestamps are rescaled linearly onto the scenario's time span
    so that the two sources overlap uniformly; ties are broken in favour of
    the scenario packet.  Relative packet order *within* each source is kept,
    so every TCP stream stays valid.
  * Background hosts are left unmodified, except that any background address
    colliding with a scenario address is rewritten into 172.16.0.0/12 so that
    background flows can never be confused with labelled flows.
  * Labels are re-indexed to flow ordinals in the mixed file (see
    common/report.py).  Background flows are unlabelled; the reporting module
    counts tool decisions on them separately ("background_flagged").

Usage
  interleave.py --scenario-pcap 03_tls_sni/pcap/test.pcap \
                --scenario-labels 03_tls_sni/pcap/labels.csv \
                --background datasets/ustc-tfc2016/*.pcap \
                --background-packets 90000 --seed 1 \
                --output pcap/03_tls_sni_bg90k.pcap --output-labels pcap/03_tls_sni_bg90k.labels.csv
"""

import argparse
import csv
import ipaddress
import os
import random
import sys

from scapy.all import IP, IPv6, TCP, UDP, Ether, PcapReader, PcapWriter  # noqa: E402
from scapy.layers.l2 import CookedLinux  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "common"))
from report import FlowTable  # noqa: E402

BG_MAC_SRC = "02:bb:00:00:00:01"
BG_MAC_DST = "02:bb:00:00:00:02"


def read_packets(path):
    with PcapReader(path) as r:
        for p in r:
            yield p


def normalize_ethernet(pkt):
    """Return an Ethernet-framed copy of an IP packet, or None if not IP."""
    if pkt.haslayer(Ether):
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return None
        return pkt
    if pkt.haslayer(CookedLinux):
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    elif isinstance(pkt, (IP, IPv6)):
        ip = pkt
    else:
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    eth = Ether(src=BG_MAC_SRC, dst=BG_MAC_DST, type=0x0800 if isinstance(ip, IP) else 0x86DD) / ip
    eth.time = pkt.time
    return eth


def scenario_addresses(packets):
    addrs = set()
    for p in packets:
        ip = p.getlayer(IP) or p.getlayer(IPv6)
        if ip is not None:
            addrs.add(ip.src)
            addrs.add(ip.dst)
    return addrs


def build_remap(bg_packets, forbidden):
    """Map colliding background IPv4 addresses into 172.16.0.0/12."""
    remap = {}
    pool = ipaddress.ip_network("172.16.0.0/12").hosts()
    for p in bg_packets:
        ip = p.getlayer(IP)
        if ip is None:
            continue
        for a in (ip.src, ip.dst):
            if a in forbidden and a not in remap:
                remap[a] = str(next(pool))
    return remap


def apply_remap(pkt, remap):
    ip = pkt.getlayer(IP)
    if ip is None or not remap:
        return pkt
    changed = False
    if ip.src in remap:
        ip.src = remap[ip.src]; changed = True
    if ip.dst in remap:
        ip.dst = remap[ip.dst]; changed = True
    if changed:
        # force checksum recomputation
        del ip.chksum
        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if l4 is not None:
            del l4.chksum
    return pkt


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario-pcap", required=True)
    ap.add_argument("--scenario-labels", required=True)
    ap.add_argument("--background", nargs="+", required=True, help="background PCAP file(s)")
    ap.add_argument("--background-packets", type=int, default=None,
                    help="number of background packets to use (default: all)")
    ap.add_argument("--background-offset", type=int, default=0,
                    help="skip this many background packets first")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--output", required=True)
    ap.add_argument("--output-labels", required=True)
    args = ap.parse_args()
    random.seed(args.seed)

    # --- scenario ---------------------------------------------------------
    scen = list(read_packets(args.scenario_pcap))
    if not scen:
        sys.exit("empty scenario pcap")
    s_t0, s_t1 = float(scen[0].time), float(scen[-1].time)
    scen_addrs = scenario_addresses(scen)

    # --- background -------------------------------------------------------
    bg = []
    skipped = 0
    limit = args.background_packets
    for path in args.background:
        for p in read_packets(path):
            if skipped < args.background_offset:
                skipped += 1
                continue
            q = normalize_ethernet(p)
            if q is None:
                continue
            bg.append(q)
            if limit is not None and len(bg) >= limit:
                break
        if limit is not None and len(bg) >= limit:
            break
    if not bg:
        sys.exit("no background packets read")

    remap = build_remap(bg, scen_addrs)
    for p in bg:
        apply_remap(p, remap)

    # Rescale background time onto the scenario's span, preserving order.
    b_t0, b_t1 = float(bg[0].time), float(bg[-1].time)
    span_b = (b_t1 - b_t0) or 1.0
    span_s = (s_t1 - s_t0) or 1.0
    for p in bg:
        p.time = s_t0 + (float(p.time) - b_t0) / span_b * span_s

    # --- merge (stable two-way merge by timestamp) -------------------------
    merged = []
    i = j = 0
    while i < len(scen) or j < len(bg):
        if j >= len(bg) or (i < len(scen) and float(scen[i].time) <= float(bg[j].time)):
            merged.append(scen[i]); i += 1
        else:
            merged.append(bg[j]); j += 1

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with PcapWriter(args.output, linktype=1, sync=False) as w:
        for p in merged:
            w.write(p)

    # --- labels: re-index scenario flows to mixed-file flow ordinals --------
    scen_flows = FlowTable(args.scenario_pcap)
    mixed_flows = FlowTable(args.output)
    ordinal_to_key = {v: k for k, v in scen_flows.key_to_flow.items()}

    with open(args.scenario_labels, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)
    idx_col = "index" if "index" in fieldnames else "flow_index"
    out_rows = []
    for row in rows:
        key = ordinal_to_key[int(row[idx_col])]
        row = dict(row)
        row["scenario_index"] = row[idx_col]
        row[idx_col] = mixed_flows.key_to_flow[key]
        out_rows.append(row)
    out_rows.sort(key=lambda r: int(r[idx_col]))
    with open(args.output_labels, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fieldnames) + ["scenario_index"])
        w.writeheader()
        w.writerows(out_rows)

    print(f"scenario: {len(scen)} pkts / {scen_flows.num_flows} flows; "
          f"background: {len(bg)} pkts / {mixed_flows.num_flows - scen_flows.num_flows} flows "
          f"({len(remap)} addresses remapped); mixed: {len(merged)} pkts -> {args.output}")


if __name__ == "__main__":
    main()
