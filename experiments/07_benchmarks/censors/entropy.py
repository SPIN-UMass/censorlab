# Entropy-based detection benchmark censor
# Medium-weight censor that checks protocol fingerprints and payload entropy
# to detect and block unrecognized high-entropy traffic (e.g. encrypted proxies).
# Used in Experiment 7 to measure overhead of statistical payload analysis.

PROTOCOL_FINGERPRINTS = [b"\x16\x03", b"GET ", b"POST ", b"HTTP/", b"SSH-"]

def process(packet):
    tcp = packet.tcp
    if not tcp:
        return
    payload = packet.payload
    if not payload:
        return
    for fp in PROTOCOL_FINGERPRINTS:
        if payload[:len(fp)] == fp:
            return
    if packet.payload_entropy > 3.0 and packet.payload_avg_popcount > 3.4:
        return "drop"
