from dns import parse as parse_dns


def process(packet):
    ip = packet.ip
    if "8.8.8.8" in [ip.src, ip.dst]:
        return "drop"
