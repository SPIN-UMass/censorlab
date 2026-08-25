"""pcapgen.py — shared helpers for building realistic synthetic test PCAPs.

The scenario PCAPs are labelled per *flow*.  Every TCP flow is emitted as a
complete connection — three-way handshake, data segments with consistent
sequence/acknowledgement numbers, and a FIN/ACK teardown — so that stateful
tools (Zeek, Suricata, Snort, OpenGFW) attach their application-layer
analyzers exactly as they would on real traffic.  Flows are written
sequentially in time, so a flow's label index equals its order of first
appearance in the file (the flow ordinal used by common/report.py).
"""

import csv
import os

from scapy.all import IP, TCP, Ether, Raw, UDP, wrpcap

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"

# Inter-packet gap inside a flow and gap between flows (seconds)
INTRA_GAP = 0.0005
INTER_GAP = 0.002


def _eth(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)


def tcp_flow(client_ip, server_ip, sport, dport, client_data, server_data=None,
             t0=0.0, client_isn=1000, server_isn=2000, close=True):
    """Build one complete TCP connection as a list of timestamped packets.

    client_data / server_data: list of bytes segments sent in order, or a
    single bytes object.  Client segments are sent first; each is acknowledged
    by the server, then server segments are sent and acknowledged.  Pass an
    interleaved exchange via `tcp_exchange` instead if ordering matters.
    """
    if isinstance(client_data, (bytes, bytearray)):
        client_data = [bytes(client_data)]
    if server_data is None:
        server_data = []
    elif isinstance(server_data, (bytes, bytearray)):
        server_data = [bytes(server_data)]
    exchange = [("c", d) for d in client_data] + [("s", d) for d in server_data]
    return tcp_exchange(client_ip, server_ip, sport, dport, exchange,
                        t0=t0, client_isn=client_isn, server_isn=server_isn, close=close)


def tcp_exchange(client_ip, server_ip, sport, dport, exchange, t0=0.0,
                 client_isn=1000, server_isn=2000, close=True):
    """Build a TCP connection carrying `exchange` = [("c"|"s", bytes), ...].

    Each data segment is followed by a pure ACK from the peer.
    """
    pkts = []
    t = t0
    c_seq = client_isn
    s_seq = server_isn

    def c2s(flags, payload=b"", seq=None, ack=None):
        nonlocal t
        p = _eth(CLIENT_MAC, SERVER_MAC) / IP(src=client_ip, dst=server_ip) / \
            TCP(sport=sport, dport=dport, flags=flags,
                seq=c_seq if seq is None else seq, ack=s_seq if ack is None else ack)
        if payload:
            p = p / Raw(load=payload)
        p.time = t
        t += INTRA_GAP
        pkts.append(p)

    def s2c(flags, payload=b"", seq=None, ack=None):
        nonlocal t
        p = _eth(SERVER_MAC, CLIENT_MAC) / IP(src=server_ip, dst=client_ip) / \
            TCP(sport=dport, dport=sport, flags=flags,
                seq=s_seq if seq is None else seq, ack=c_seq if ack is None else ack)
        if payload:
            p = p / Raw(load=payload)
        p.time = t
        t += INTRA_GAP
        pkts.append(p)

    # Handshake
    c2s("S", ack=0)
    c_seq += 1
    s2c("SA")
    s_seq += 1
    c2s("A")

    # Data
    for who, data in exchange:
        data = bytes(data)
        if who == "c":
            c2s("PA", data)
            c_seq += len(data)
            s2c("A")
        else:
            s2c("PA", data)
            s_seq += len(data)
            c2s("A")

    # Teardown (client initiates)
    if close:
        c2s("FA")
        c_seq += 1
        s2c("FA")
        s_seq += 1
        c2s("A")

    return pkts


def udp_packet(client_ip, server_ip, sport, dport, payload, t0=0.0):
    p = _eth(CLIENT_MAC, SERVER_MAC) / IP(src=client_ip, dst=server_ip) / \
        UDP(sport=sport, dport=dport) / Raw(load=bytes(payload))
    p.time = t0
    return [p]


def lay_out(flows, t_start=1_700_000_000.0):
    """Assign sequential timestamps to a list of flows (each a packet list).

    Returns (packets, first_packet_index_per_flow).
    """
    packets = []
    firsts = []
    t = t_start
    for flow in flows:
        firsts.append(len(packets))
        base = flow[0].time
        for p in flow:
            p.time = t + (float(p.time) - float(base))
            packets.append(p)
        t = float(packets[-1].time) + INTER_GAP
    return packets, firsts


def write_dataset(flows, labels, pcap_path, labels_path, fieldnames):
    """Write flows to a PCAP and per-flow labels to CSV.

    `labels` is a list of dicts aligned with `flows`; "index" and
    "first_packet_index"/"num_packets" are filled in here.
    """
    packets, firsts = lay_out(flows)
    for i, (lbl, flow) in enumerate(zip(labels, flows)):
        lbl["index"] = i
        lbl["first_packet_index"] = firsts[i]
        lbl["num_packets"] = len(flow)

    os.makedirs(os.path.dirname(os.path.abspath(pcap_path)), exist_ok=True)
    wrpcap(pcap_path, packets)
    os.makedirs(os.path.dirname(os.path.abspath(labels_path)), exist_ok=True)
    out_fields = ["index"] + [f for f in fieldnames if f not in ("index",)] + \
                 ["first_packet_index", "num_packets"]
    with open(labels_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=out_fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(labels)
    return len(packets)
