# Iran's protocol filter (PyCL corpus program)
#
# Bock et al. (FOCI 2020) found that, next to its ordinary DPI, Iran runs a
# filter that only lets recognised protocols through on TCP ports 53, 80 and
# 443, for some destination prefixes:
#
#   * it looks at the first two data-carrying packets the client sends;
#   * if either matches the DNS, HTTP or HTTPS fingerprint (any of them, on
#     any of the three ports), the flow is left alone;
#   * otherwise the second packet and the rest of the client's packets are
#     dropped.  Packets from the server are untouched;
#   * the filter does not reassemble TCP segments, and only acts on
#     connections whose client is inside Iran.
#
# The blackhole lasts 60 s and every further packet restarts the timer; that
# part is the idle timeout in censor.toml.
#
# To test (from the client):
#   curl http://104.18.0.1/          (allowed: starts with "GET ")
#   nc 104.18.0.1 80, then type two lines of anything else
#                                    (the second line never arrives)
#
# Return values used: "drop"

from rust import subnet

FILTERED_PORTS = [53, 80, 443]
# The filter only covers some destinations and the paper could not tell why.
# These are the two Cloudflare prefixes it found fully affected.
FILTERED_NETS = [subnet("104.18.0.0/16"), subnet("104.31.82.0/24")]

# PATCH and TRACE are not recognised
HTTP_VERBS = [b"GET ", b"POST ", b"HEAD ", b"CONNECT ", b"OPTIONS ", b"DELETE ", b"PUT "]


def is_dns(p):
    # A DNS-over-UDP header (no TCP length prefix): QR = 0, fewer than 15
    # questions, no answers.  Real DNS-over-TCP therefore never matches.
    return (
        len(p) >= 12
        and p[2] & 0x80 == 0
        and int.from_bytes(p[4:6], "big") < 15
        and p[6:8] == b"\x00\x00"
    )


def is_http(p):
    return len(p) >= 8 and any(p.startswith(verb) for verb in HTTP_VERBS)


def is_tls(p):
    # 5-byte record header plus at least 36 bytes; version 3.1-3.3; the record
    # length must cover exactly the rest of the packet.  Nothing after the
    # header is checked.  (The paper gives the version and length rules; that
    # the first byte must be 0x16, Handshake, is assumed here.)
    return (
        len(p) >= 41
        and p[0] == 0x16
        and p[1] == 3
        and p[2] in (1, 2, 3)
        and int.from_bytes(p[3:5], "big") == len(p) - 5
    )


data_packets = 0     # data-carrying client packets inspected so far
recognised = False   # one of the first two matched a fingerprint
blackholed = False


def process(packet):
    global data_packets, recognised, blackholed
    tcp = packet.tcp
    # Only client -> server packets are inspected or dropped
    if not tcp or packet.direction != 1 or tcp.dst not in FILTERED_PORTS:
        return
    if not any(net.contains(packet.ip.dst) for net in FILTERED_NETS):
        return
    if blackholed:
        return "drop"
    payload = packet.payload
    if recognised or data_packets >= 2 or not payload:
        return
    data_packets += 1
    if is_dns(payload) or is_http(payload) or is_tls(payload):
        recognised = True
    elif data_packets == 2:
        blackholed = True
        return "drop"
