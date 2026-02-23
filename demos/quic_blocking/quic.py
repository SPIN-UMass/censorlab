from quic import parse_initial

# QUIC SNI blocking demo
# Blocks QUIC connections to example.com by inspecting the QUIC Initial packet.
#
# To test:
#   (works fine)
#   curl --http3 https://google.com
#   (blocked)
#   curl --http3 https://example.com
#
# Note: QUIC Initial packets are encrypted in practice. This demo works with
# unprotected packets or when the censor has derived the Initial keys from the
# Destination Connection ID.
def process(packet):
    udp = packet.udp
    if udp and 443 in [udp.src, udp.dst]:
        try:
            info = parse_initial(packet.payload)
            if info.sni and "example.com" in info.sni:
                return "drop"
        except Exception:
            # Not a QUIC Initial, or encrypted payload
            pass
