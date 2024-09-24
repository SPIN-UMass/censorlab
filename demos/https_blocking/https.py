# To test blocking in this demo, run
# (works just fine)
# curl https://google.com
# (fails)
# curl https://example.com
def process(packet):
    tcp = packet.tcp
    if tcp and 443 in [tcp.src, tcp.dst]:
        # Look for example.com SNI
        if b"example.com" in packet.payload:
            return "drop"
