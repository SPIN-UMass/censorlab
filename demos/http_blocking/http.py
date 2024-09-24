# To test blocking in this demo, run
# (works just fine)
# curl http://google.com
# (fails)
# curl http://example.com
def process(packet):
    tcp = packet.tcp
    if tcp and 80 in [tcp.src, tcp.dst]:
        if b"example" in packet.payload:
            return "drop"
