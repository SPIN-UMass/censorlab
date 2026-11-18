# Encrypted DNS resolver blocking (PyCL corpus program)
#
# Encrypted DNS (DoT on port 853, DoH on port 443) hides queries from DNS
# injection, but the resolver itself is still named in the TLS SNI.  In
# September 2021 users in Russia reported exactly that being used
# (net4people/bbs #81):
#
#   "Blocking of DoH and DoT is by TCP RST after the TLS ClientHello."
#   "TLS connections to the same IP address with a different SNI do not get
#    RST."
#
# Resolvers named in the reports include dns.google (DoH and DoT),
# doh.opendns.com (DoH) and 1dot1dot1dot1.cloudflare-dns.com (DoT), while
# AdGuard and Quad9 kept working.  Plaintext DNS to 8.8.8.8 timed out; that
# part needs no script and is the [udp.ip_port_blocklist] in censor.toml.
#
# The rule here is SNI-only, on any port.  Like tspu_sni_delayed_drop it looks
# at single packets, since Xue et al. (IMC 2022) found that a ClientHello
# split across segments bypassed the TSPU.
#
# To test:
#   kdig +tls @dns.google example.org     (reset)
#   kdig +tls @dns.quad9.net example.org  (works)
#   dig @8.8.8.8 example.org              (times out)
#
# Return values used: "reset"

from tls import parse_client_hello

BLOCKED_RESOLVERS = [
    b"dns.google",
    b"doh.opendns.com",
    b"1dot1dot1dot1.cloudflare-dns.com",
]

blocked = False


def process(packet):
    global blocked
    if not packet.tcp:
        return
    if blocked:
        return "reset"
    if packet.direction != 1 or not packet.payload:
        return
    try:
        names = parse_client_hello(packet.payload).sni_list
    except Exception:
        return
    if any(name.lower() in BLOCKED_RESOLVERS for name in names):
        blocked = True
        return "reset"
