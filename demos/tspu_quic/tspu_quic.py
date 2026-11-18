# TSPU QUIC blocking (PyCL corpus program)
#
# In March 2022 Russia's TSPU began blocking QUIC outright.  It does not
# decrypt anything (compare quic_blocking and gfw_quic_sni): Xue et al.
# (IMC 2022) found it matches
#
#   * a UDP packet sent from the Russian side to port 443,
#   * with at least 1001 bytes of payload,
#   * whose bytes 1-4 are 00 00 00 01, the QUIC version 1 field.
#
# After such a packet, "all following packets from both sides will be
# dropped", whatever they look like.  Other versions (draft-29, quicping's
# 0xbabababa) and packets coming from the remote side do not trigger it.
# The state lasts until the flow has been idle for 420 s (censor.toml).
#
# To test:
#   curl --http3-only https://example.org    (times out)
#   curl https://example.org                 (works: TCP)
#
# Return values used: "drop"

QUIC_V1 = b"\x00\x00\x00\x01"

blocked = False


def process(packet):
    global blocked
    udp = packet.udp
    if not udp:
        return
    if blocked:
        return "drop"
    if (
        packet.direction == 1
        and udp.dst == 443
        and packet.payload_len >= 1001
        and packet.payload[1:5] == QUIC_V1
    ):
        blocked = True      # the following packets are dropped, not this one
