# DNS Response Injection Censor (PyCL)
# Emulates GFW-style DNS poisoning: intercepts DNS queries for forbidden
# domains and returns a forged A record pointing to a sinkhole IP.
#
# When process() returns bytes, CensorLab injects them as a UDP response
# packet while allowing the original query through (racing the real
# resolver, matching GFW behavior).

from dns import parse as parse_dns, craft_response

FORBIDDEN = [
    b"google.com", b"facebook.com", b"twitter.com", b"youtube.com",
    b"wikipedia.org", b"instagram.com", b"whatsapp.com", b"telegram.org",
    b"signal.org", b"reddit.com", b"nytimes.com", b"bbc.com",
    b"reuters.com", b"theguardian.com", b"washingtonpost.com",
    b"amnesty.org", b"hrw.org", b"rsf.org", b"torproject.org",
    b"eff.org", b"vpngate.net", b"psiphon.ca", b"lanternvpn.org",
    b"protonvpn.com", b"mullvad.net", b"github.com", b"medium.com",
    b"blogspot.com", b"wordpress.com", b"tumblr.com", b"dropbox.com",
    b"soundcloud.com", b"vimeo.com", b"twitch.tv", b"discord.com",
]

POISON_IP = "10.10.10.10"

def process(packet):
    udp = packet.udp
    if udp and udp.dst == 53:
        payload = packet.payload
        if payload:
            try:
                dns = parse_dns(payload)
                for q in dns.questions:
                    qname_lower = q.qname.lower().encode()
                    for domain in FORBIDDEN:
                        if domain in qname_lower:
                            return craft_response(payload, POISON_IP)
            except Exception:
                pass
