# Snowflake DTLS fingerprinting (PyCL corpus program)
#
# Snowflake carries Tor over WebRTC data channels, whose outermost layer is a
# DTLS handshake over UDP.  Snowflake uses the Pion WebRTC library, not a
# browser's, and Russian ISPs twice blocked it by features of Pion's DTLS
# handshake that browsers do not show (Bocovich et al., USENIX Security 2024):
#
#   2021-12  "the presence of a supported_groups extension in the DTLS Server
#            Hello message produced by Pion" (a Pion bug);
#   2022-07  "the server sending a Hello Verify Request message", which Pion
#            did and major browsers did not.
#
# Both only catch connections where the Pion side is the DTLS server, which is
# why neither blocked every Snowflake connection.  (A rule on the contents of
# supported_groups in the ClientHello was seen in between; its details are
# not published, so it is not here.)
#
# The paper describes the fingerprints, not the censor's action; testers saw
# that the DTLS handshake never completed.  Here the matching message and the
# rest of the flow are dropped.
#
# To test: run a Snowflake client older than the corresponding fix through
# CensorLab; browser WebRTC calls keep working.
#
# Return values used: "drop"

HANDSHAKE = 22
HELLO_VERIFY_REQUEST = 3
SERVER_HELLO = 2
SUPPORTED_GROUPS = 10

BLOCK_SERVER_HELLO_GROUPS = True    # the December 2021 rule
BLOCK_HELLO_VERIFY = True           # the July 2022 rule


def dtls_handshake(p):
    """(message type, body) of an unfragmented DTLS handshake record at the
    start of a datagram, else None."""
    # Record: type, version (fe ff = DTLS 1.0, fe fd = DTLS 1.2), epoch 0,
    # sequence number, length.  Handshake: type, length, message sequence,
    # fragment offset, fragment length.
    if len(p) < 25 or p[0] != HANDSHAKE or p[1] != 0xFE or p[3:5] != b"\x00\x00":
        return None
    record_len = int.from_bytes(p[11:13], "big")
    body_len = int.from_bytes(p[14:17], "big")
    fragment_offset = int.from_bytes(p[19:22], "big")
    fragment_len = int.from_bytes(p[22:25], "big")
    if fragment_offset != 0 or fragment_len != body_len or record_len != 12 + body_len:
        return None
    if len(p) < 25 + body_len:
        return None
    return p[13], p[25:25 + body_len]


def server_hello_extensions(body):
    """Extension types of a ServerHello body, [] if it is malformed."""
    try:
        pos = 2 + 32                    # version, random
        pos += 1 + body[pos]            # session id
        pos += 2 + 1                    # cipher suite, compression method
        if pos == len(body):
            return []                   # no extensions
        end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
        if end != len(body):
            return []
        pos += 2
        types = []
        while pos + 4 <= end:
            types.append(int.from_bytes(body[pos:pos + 2], "big"))
            pos += 4 + int.from_bytes(body[pos + 2:pos + 4], "big")
        return types
    except IndexError:
        return []


blocked = False


def process(packet):
    global blocked
    if not packet.udp:
        return
    if blocked:
        return "drop"
    message = dtls_handshake(packet.payload)
    if message is None:
        return
    kind, body = message
    if kind == HELLO_VERIFY_REQUEST and BLOCK_HELLO_VERIFY:
        blocked = True
    elif kind == SERVER_HELLO and BLOCK_SERVER_HELLO_GROUPS:
        blocked = SUPPORTED_GROUPS in server_hello_extensions(body)
    if blocked:
        return "drop"
