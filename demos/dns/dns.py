from dns import parse as parse_dns


def process(packet):
    udp = packet.udp
    if udp and udp.uses_port(53):
        dns = parse_dns(packet.payload)
    return
