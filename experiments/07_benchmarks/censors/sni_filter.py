# SNI filter benchmark censor
# Lightweight censor that inspects TLS ClientHello for a blocked SNI.
# Used in Experiment 7 to measure overhead of basic payload inspection.

from tls import parse_client_hello

def process(packet):
    tcp = packet.tcp
    if tcp and 443 in [tcp.src, tcp.dst]:
        try:
            hello = parse_client_hello(packet.payload)
            if hello.sni and "blocked.example.com" in hello.sni:
                return "reset"
        except Exception:
            pass
