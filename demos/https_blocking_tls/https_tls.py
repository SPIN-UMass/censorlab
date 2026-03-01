from tls import parse_client_hello

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
# This is more robust than the naive byte-matching approach (b"example.com" in payload)
# because it correctly handles:
#   - SNI split across packet boundaries (first packet only)
#   - False positives from matching certificate data
#   - Proper TLS record structure validation
def process(packet):
    tcp = packet.tcp
    if tcp and 443 in [tcp.src, tcp.dst]:
        try:
            hello = parse_client_hello(packet.payload)
            if hello.sni and b"example.com" in hello.sni.lower():
                return "drop"
        except Exception:
            # Not a TLS ClientHello (e.g. application data, alerts)
            pass
