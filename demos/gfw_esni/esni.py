# GFW ESNI blocking (PyCL corpus program)
#
# Since 2020-07-29 the GFW blocks TLS connections whose ClientHello carries the
# encrypted_server_name extension (type 0xffce).  From the measurement report:
#
#   * the extension type alone is the trigger; changing it to another value
#     stops the blocking (ECH's 0xff02-0xff04 were not blocked);
#   * nothing is injected.  The ClientHello itself reaches the server (WOOT
#     2021), then the GFW "drops only client-to-server packets";
#   * a complete TCP handshake is needed first;
#   * it happens on every port and for connections opened in either direction;
#   * sending the ClientHello in two TCP segments evades it, so this script
#     looks at single packets on purpose.
#
# Not emulated: the GFW also drops new connections with the same (client IP,
# server IP, server port) for 120 or 180 s.  That needs a clock, which PyCL
# does not have (see censor.toml); here only the triggering connection is cut.
#
# To test, send a ClientHello with a 0xffce extension; ordinary TLS, with or
# without ECH, is unaffected:
#   curl https://example.org    (works)
#
# Return values used: "drop"

from tls import parse_client_hello

ESNI = 0xFFCE


def extension_types(record):
    """Extension types of a single-record ClientHello.

    Only call this on bytes parse_client_hello() has accepted: it relies on
    every length field being consistent.
    """
    pos = 5 + 4 + 2 + 32                                   # record + handshake headers, version, random
    pos += 1 + record[pos]                                 # session id
    pos += 2 + int.from_bytes(record[pos:pos + 2], "big")  # cipher suites
    pos += 1 + record[pos]                                 # compression methods
    end = pos + 2 + int.from_bytes(record[pos:pos + 2], "big")
    pos += 2
    types = []
    while pos + 4 <= end:
        types.append(int.from_bytes(record[pos:pos + 2], "big"))
        pos += 4 + int.from_bytes(record[pos + 2:pos + 4], "big")
    return types


client = None        # (IP, port) that sent the SYN
handshake = 0        # 1: SYN seen, 2: SYN+ACK seen, 3: client's ACK seen
blocked = False


def process(packet):
    global client, handshake, blocked
    tcp = packet.tcp
    if not tcp:
        return
    sender = (packet.ip.src, tcp.src)
    flags = tcp.flags
    if flags.syn and not flags.ack:
        client, handshake = sender, 1
        return
    if flags.syn and flags.ack and handshake == 1 and sender != client:
        handshake = 2
        return
    if sender != client:
        return                      # server -> client packets are never dropped
    if blocked:
        return "drop"
    if handshake == 2 and flags.ack:
        handshake = 3
    if handshake != 3 or not packet.payload:
        return
    try:
        hello = parse_client_hello(packet.payload)
    except Exception:
        return
    if hello.record_count == 1 and ESNI in extension_types(packet.payload):
        blocked = True              # this packet is still delivered
