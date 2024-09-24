from dns import parse as parse_dns


def process(packet):
    udp = packet.udp
    if udp and udp.dst == 53:
        dns = parse_dns(packet.payload)
        for question in dns.questions:
            if "google.com" in question.qname:
                return "drop"
