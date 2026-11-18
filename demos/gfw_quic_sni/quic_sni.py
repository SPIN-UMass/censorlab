# GFW QUIC SNI blocking (PyCL corpus program)
#
# The GFW decrypts QUIC client Initial packets and blocks by SNI.  Compared
# with the generic quic_blocking demo, this one follows the specific behaviour
# Zohaib et al. (USENIX Security 2025) measured:
#
#   * only the first UDP packet of a flow is inspected.  If anything else
#     comes first, the flow is never blocked;
#   * the SNI must be in that one datagram: a ClientHello spread over several
#     Initial packets is not reassembled (so parse_initial, not a reassembler);
#   * only QUIC version 1 is handled;
#   * flows whose source port is not greater than the destination port are
#     ignored, on any destination port;
#   * the Initial itself is delivered.  Afterwards the client's packets are
#     dropped; the server's are not.
#
# Not emulated: the GFW drops everything from the client to the same server
# IP and port, whatever the source port, for 180 s.  That needs a clock, which
# PyCL does not have (see censor.toml); here only the triggering flow is cut.
# Real blocking also lags by up to a few seconds and is probabilistic.
#
# To test:
#   curl --http3-only https://example.org    (works)
#   curl --http3-only https://youtube.com    (times out)
#
# Return values used: "drop"

from quic import parse_initial

# Two of the domains the paper found blocked over QUIC
BLOCKED = [b"youtube.com", b"google.com"]

first = True
client = None    # IP whose packets are dropped once the flow is blocked


def process(packet):
    global first, client
    udp = packet.udp
    if not udp:
        return
    if client is not None:
        if packet.ip.src == client:
            return "drop"
        return
    if not first:
        return
    first = False
    if udp.src <= udp.dst:
        return
    try:
        info = parse_initial(packet.payload)
    except Exception:
        return
    if info.version != 1 or info.sni is None:
        return
    sni = info.sni.lower()
    for domain in BLOCKED:
        if sni == domain or sni.endswith(b"." + domain):
            client = packet.ip.src
            return
