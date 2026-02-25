# TLS SNI Filtering Censor (PyCL)
# Emulates HTTPS censorship by extracting SNI from TLS ClientHello
# and resetting connections to forbidden domains.
#
# Real-world examples: GFW (China), Iran, Russia all perform SNI-based
# blocking on TLS connections to restricted services.
#
# NOTE: The FORBIDDEN list is embedded here because RustPython
# re-executes top-level code per connection.

from tls import parse_client_hello

FORBIDDEN = [
    b"google.com", b"facebook.com", b"twitter.com", b"youtube.com",
    b"instagram.com", b"whatsapp.com", b"telegram.org", b"signal.org",
    b"wikipedia.org", b"reddit.com", b"discord.com", b"medium.com",
    b"soundcloud.com", b"tumblr.com", b"vimeo.com", b"pinterest.com",
    b"nytimes.com", b"washingtonpost.com", b"bbc.com", b"theguardian.com",
    b"reuters.com", b"amnesty.org", b"hrw.org", b"rsf.org",
    b"torproject.org", b"psiphon.ca", b"lanternvpn.org", b"mullvad.net",
    b"protonvpn.com", b"nordvpn.com", b"expressvpn.com",
    b"github.com", b"gitlab.com", b"stackoverflow.com", b"twitch.tv",
]

def process(packet):
    tcp = packet.tcp
    if tcp and 443 in [tcp.src, tcp.dst]:
        try:
            hello = parse_client_hello(packet.payload)
            if hello.sni:
                sni_lower = hello.sni.lower().encode()
                for domain in FORBIDDEN:
                    if domain in sni_lower:
                        return "reset"
        except Exception:
            pass
