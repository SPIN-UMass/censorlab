# Traffic policing / throttling (PyCL corpus program)
#
# In March 2021 Russia's TSPU throttled Twitter by slowing — not blocking —
# connections whose TLS SNI matched t.co / twimg.com / twitter.com (Xue et al.,
# "Throttling Twitter: an emerging censorship technique in Russia", IMC 2021).
# Throttling is a *policing* action: packets are delivered late rather than
# dropped, so the service degrades without an obvious block page or reset.
#
# This program emulates that behaviour with the Delay action: once a
# connection's ClientHello names a throttled domain, every subsequent packet of
# that connection is held for THROTTLE_DELAY seconds before being re-injected.
# With TCP's congestion control reacting to the added RTT, the effective
# throughput collapses to a few hundred kbit/s, as observed in Russia.
#
# Return values used: ("delay", seconds)
#
# Usage (Tap/NFQ mode; PCAP mode only reports the decision):
#   censorlab -c demos/throttling/censor.toml nfq

from tls import parse_client_hello

THROTTLED = [b"twitter.com", b"t.co", b"twimg.com"]
THROTTLE_DELAY = 0.5   # seconds added to every packet of a throttled connection

throttled = False


def process(packet):
    global throttled
    tcp = packet.tcp
    if not tcp:
        return
    if throttled:
        return ("delay", THROTTLE_DELAY)
    if packet.direction == 1 and tcp.dst == 443 and packet.payload:
        try:
            sni = parse_client_hello(packet.payload).sni.lower()
        except Exception:
            return
        for domain in THROTTLED:
            if sni == domain or sni.endswith(b"." + domain):
                throttled = True
                return ("delay", THROTTLE_DELAY)
