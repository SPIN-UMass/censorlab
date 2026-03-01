from dns import parse as parse_dns, craft_response

# Add domains to block here
BLOCKED_DOMAINS = [
    "google.com",
]

# IP address to inject in forged DNS responses
POISON_IP = "10.10.10.10"

# To test this demo:
#   nslookup yahoo.com    (works fine — returns real IP)
#   nslookup google.com   (blocked — returns forged IP 10.10.10.10)
def process(packet):
    udp = packet.udp
    if udp and udp.dst == 53:
        dns = parse_dns(packet.payload)
        for question in dns.questions:
            for domain in BLOCKED_DOMAINS:
                if domain in question.qname:
                    return craft_response(packet.payload, POISON_IP)
