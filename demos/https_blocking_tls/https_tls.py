# HTTPS SNI blocking demo using proper TLS ClientHello parsing.
# Blocks TLS connections to example.com by extracting the SNI from the
# TLS ClientHello message.
#
# To test:
#   (works fine)
#   curl https://google.com
#   (blocked)
#   curl https://example.com
#
# packet.tls_client_hello is reassembled by CensorLab from the start of the
# client's TCP stream, so it handles ClientHellos split across TCP segments or
# TLS records. Modern clients split it by default: a post-quantum key share
# (X25519MLKEM768) makes the ClientHello ~1.6 KB, more than one segment.
# It is None until the whole ClientHello has arrived, then set on that packet
# and every later packet of the connection.
#
# This is more robust than the naive byte-matching approach (b"example.com" in payload)
# because it avoids false positives from matching certificate data and validates the
# TLS record structure.
def process(packet):
    hello = packet.tls_client_hello
    if hello and hello.sni and b"example.com" in hello.sni.lower():
        return "reset"
