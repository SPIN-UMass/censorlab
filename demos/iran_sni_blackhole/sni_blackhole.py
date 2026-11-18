# Iran's SNI blackholing (PyCL corpus program)
#
# Unlike the GFW, which injects RSTs, Iran's filter "simply 'blackholes' the
# traffic, dropping the offending packet and all future packets from the
# client in the flow" (Bock et al., SIGCOMM 2020).  Packets from the server
# still arrive, so the client just sees its own segments go unacknowledged.
#
#   * the ClientHello must fit in one segment: the filter does not reassemble
#     TCP (SIGCOMM 2020), so this script parses single packets on purpose;
#   * no TCP handshake is needed to trigger it (both papers);
#   * only ports 53, 80 and 443 are monitored, and the blackhole covers the
#     4-tuple for 180 s, restarted by further packets (WOOT 2021, Table I).
#     That timer is the idle timeout in censor.toml.
#
# Iran's HTTP censorship additionally injects a block page; CensorLab cannot
# inject TCP payloads, so only the SNI filter is emulated.
#
# To test:
#   curl https://example.org    (works)
#   curl https://youtube.com    (times out)
#
# Return values used: "drop"

from tls import parse_client_hello

# Illustrative blocklist; SIGCOMM 2020 used youtube.com as its trigger
BLOCKED = [b"youtube.com"]
MONITORED_PORTS = [53, 80, 443]

blackholed = False


def process(packet):
    global blackholed
    tcp = packet.tcp
    if not tcp or packet.direction != 1 or tcp.dst not in MONITORED_PORTS:
        return
    if blackholed:
        return "drop"
    if not packet.payload:
        return
    try:
        names = parse_client_hello(packet.payload).sni_list
    except Exception:
        return  # not a complete ClientHello in this segment
    for name in names:
        name = name.lower()
        for domain in BLOCKED:
            if name == domain or name.endswith(b"." + domain):
                blackholed = True
                return "drop"
