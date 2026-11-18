# GFW censorship of DNS over TCP (PyCL corpus program)
#
# The GFW answers forbidden DNS queries sent over UDP with forged responses
# (see dns_blocking).  Over TCP it cannot race the server that way; instead a
# query for a forbidden name gets the connection torn down with injected RSTs
# (Bock et al., SIGCOMM 2020, measured with unmodified clients querying open
# resolvers outside China).
#
#   * There is no residual censorship for DNS, over UDP or TCP (WOOT 2021):
#     the client may reconnect and ask something else straight away, so only
#     the offending packet is reset here.
#   * RFC 7766 clients retry after a reset, which is why even unreliable
#     evasion strategies work well against this censor (SIGCOMM 2020).
#
# The query has to be in one packet (dns.parse_tcp raises on a partial
# message); whether the GFW reassembles DNS-over-TCP is not reported.
#
# To test:
#   dig +tcp @9.9.9.9 www.facebook.com    (reset)
#   dig +tcp @9.9.9.9 example.org         (works)
#
# Return values used: "reset"

from dns import parse_tcp

# facebook.com is the trigger used in WOOT 2021
BLOCKED = [b"facebook.com"]


def process(packet):
    tcp = packet.tcp
    if not tcp or tcp.dst != 53 or not packet.payload:
        return
    try:
        messages = parse_tcp(packet.payload)
    except Exception:
        return
    for message in messages:
        if not message.query:
            continue
        for question in message.questions:
            name = question.qname.lower()
            for domain in BLOCKED:
                if name == domain or name.endswith(b"." + domain):
                    return "reset"
