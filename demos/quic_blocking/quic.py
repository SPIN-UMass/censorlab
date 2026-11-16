from quic import new_reassembler

# QUIC SNI blocking demo
# Blocks QUIC connections to example.com by inspecting the QUIC Initial packet.
#
# To test:
#   (works fine)
#   curl --http3 https://google.com
#   (blocked)
#   curl --http3 https://example.com
#
# QUIC Initial packets are encrypted, but with keys derived from the
# client's Destination Connection ID, so any on-path observer can decrypt
# them (RFC 9001 Section 5.2). The quic module does exactly that, for QUIC
# v1 and v2.
#
# This script runs once per connection, so this reassembler is per-connection
# state: it joins ClientHellos that span several Initial datagrams (as with
# post-quantum key shares).
initials = new_reassembler()

def process(packet):
    udp = packet.udp
    if udp and 443 in [udp.src, udp.dst]:
        try:
            info = initials.feed(packet.payload)
        except Exception:
            # Not a (decryptable) client Initial: server traffic, short
            # header packets, unknown QUIC versions, ...
            return
        if info.sni and b"example.com" in info.sni.lower():
            return "drop"
