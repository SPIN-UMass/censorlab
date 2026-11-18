# Turkmenistan's firewall (PyCL corpus program)
#
# Nourin et al. (WWW 2023) measured three filters, all of which
#   * act in both directions (a probe sent into the country triggers them just
#     like one sent out of it), so this script never looks at packet.direction;
#   * act on any port, not only 53/80/443;
#   * match domains against regular expressions, which over-block
#     (a rule like .*\.cyou.* takes out a whole TLD).
#
# DNS    a UDP query for a censored name gets a forged answer of 127.0.0.1
#        (the real query is not dropped).
# HTTP   a censored name in the Host header draws a RST.
# HTTPS  a censored name in the TLS SNI draws a RST.  The ClientHello has to
#        fit in one segment: TCP segmentation evades the filter (Section 6).
#
# HTTP and HTTPS have residual censorship: afterwards any non-RST packet with
# the same (source IP:port, destination IP:port) draws a RST, until 30 s after
# the last injected packet (the idle timeout in censor.toml).
#
# CensorLab's "reset" sends RSTs to both endpoints; the paper reports one
# injected RST per trigger.
#
# To test:
#   nslookup twitter.com 1.1.1.1                          (answers 127.0.0.1)
#   curl -H 'Host: twitter.com' http://example.org:8080/  (reset)
#   curl https://twitter.com                              (reset)
#
# Return values used: bytes (inject), "reset"

from rust import regex
from dns import parse as parse_dns, craft_response
from tls import parse_client_hello

# Illustrative rules in the style the paper recovered
BLOCKED = regex(r"(?i)(^|\.)twitter\.com$|\.cyou")
BLOCKED_HOST_HEADER = regex(
    r"(?i)\r\nHost:[ \t]*([^\r\n]*\.)?twitter\.com[ \t]*\r\n|\r\nHost:[^\r\n]*\.cyou"
)
POISON_IP = "127.0.0.1"

# (source IP, source port) of the packet that triggered the HTTP/HTTPS filter
residual = None


def process(packet):
    global residual
    if packet.udp:
        try:
            dns = parse_dns(packet.payload)
        except Exception:
            return
        if dns.query and any(BLOCKED.is_match(q.qname) for q in dns.questions):
            return craft_response(packet.payload, POISON_IP)
        return

    tcp = packet.tcp
    if not tcp:
        return
    sender = (packet.ip.src, tcp.src)
    if residual == sender:
        if not tcp.flags.rst:
            return "reset"
        return
    if not packet.payload:
        return
    forbidden = BLOCKED_HOST_HEADER.is_match(packet.payload)
    if not forbidden:
        try:
            names = parse_client_hello(packet.payload).sni_list
        except Exception:
            names = []
        forbidden = any(BLOCKED.is_match(name) for name in names)
    if forbidden:
        residual = sender
        return "reset"
