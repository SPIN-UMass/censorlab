from dns import parse as parse_dns


# To test this demo
# (works fine)
# nslookup yahoo.com
# (fails, timeout)
# nslookup google.com
def process(packet):
    udp = packet.udp
    if udp and udp.dst == 53:
        dns = parse_dns(packet.payload)
        for question in dns.questions:
            if "google.com" in question.qname:
                return "drop"
