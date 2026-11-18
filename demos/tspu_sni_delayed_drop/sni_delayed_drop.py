# TSPU SNI-II: delayed symmetric drop (PyCL corpus program)
#
# Xue et al. (IMC 2022) found four different reactions of Russia's TSPU to a
# forbidden SNI.  This is the one they call SNI-II, used for a short list of
# "out-registry" domains such as play.google.com, news.google.com and
# nordvpn.com:
#
#   "once a triggering ClientHello is seen, an additional five to eight
#    packets can be delivered from either side, after which symmetric packet
#    drops occur."
#
# So the TLS handshake may even appear to progress before the connection
# stalls in both directions, with no RST.
#
#   * The trigger must be sent by a client on the Russian side (the TSPU
#     decides who the client is from the SYN).
#   * The ClientHello must fit in one packet: the paper notes that TCP
#     segmentation still bypasses the TSPU, so this script parses single
#     packets on purpose.
#   * The state lasts until the connection has been idle for 420 s
#     (censor.toml).
#
# The other reactions: SNI-I rewrites the server's packets into RST/ACKs
# (CensorLab cannot rewrite flags or payload; the tspu_ttl_normalization and
# https_blocking_tls demos use "reset" instead), SNI-III was throttling (see
# the throttling demo) and SNI-IV drops everything including the ClientHello.
#
# To test:
#   curl https://example.org        (works)
#   curl https://play.google.com    (hangs during or just after the handshake)
#
# Return values used: "drop"

from tls import parse_client_hello

BLOCKED = [b"play.google.com", b"news.google.com", b"nordvpn.com"]
# Packets still delivered after the trigger; the paper observed five to eight
GRACE_PACKETS = 5

opened_locally = False   # the SYN came from the client (local) side
remaining = None         # packets left before the drop; None = not triggered


def process(packet):
    global opened_locally, remaining
    tcp = packet.tcp
    if not tcp:
        return
    if tcp.flags.syn and not tcp.flags.ack:
        opened_locally = packet.direction == 1
        return
    if remaining is not None:
        if remaining == 0:
            return "drop"
        remaining -= 1
        return
    if not opened_locally or packet.direction != 1 or tcp.dst != 443 or not packet.payload:
        return
    try:
        names = parse_client_hello(packet.payload).sni_list
    except Exception:
        return
    for name in names:
        name = name.lower()
        for domain in BLOCKED:
            if name == domain or name.endswith(b"." + domain):
                remaining = GRACE_PACKETS
                return
