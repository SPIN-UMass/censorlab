# Cloudflare ECH blocking (PyCL corpus program)
#
# With Encrypted Client Hello the real server name is encrypted and the
# ClientHello shows only a shared "public name"; for every Cloudflare site
# that is cloudflare-ech.com.  Russia's TSPU blocks exactly that combination
# (net4people/bbs #417).  A ClientHello is blocked if it has both
#
#   1. an SNI of cloudflare-ech.com, and
#   2. an encrypted_client_hello extension (type 0xfe0d).
#
# "Neither of these elements on its own is sufficient": the same SNI without
# ECH passes, and so does ECH (or GREASE ECH) with any other public name.
# The mechanism is "packet dropping on the connection after the signature is
# detected (i.e., not a TCP RST or other overt teardown)".
#
# The reports do not say whether the ClientHello itself gets through; here it
# is dropped along with everything after it, in both directions.  QUIC is
# affected too but not covered: the quic module does not expose the
# ClientHello's extensions.
#
# ClientHelloInfo does not list extension types either, so this script keeps
# the client's first bytes itself, in arrival order, and walks them once
# CensorLab has recognised the ClientHello.  A ClientHello whose segments
# arrive out of order or retransmitted is therefore missed.
#
# To test, use a browser with ECH enabled:
#   a site that is not on Cloudflare     (works)
#   a Cloudflare site with ECH enabled   (hangs)
#
# Return values used: "drop"

ECH = 0xFE0D
ECH_PUBLIC_NAME = b"cloudflare-ech.com"
MAX_BUFFER = 16384


def extension_types(stream):
    """Extension types of the ClientHello at the start of a TLS stream.

    Returns [] if the bytes are not laid out as expected (see above).
    """
    try:
        # Join the handshake records
        msg, pos = b"", 0
        while pos + 5 <= len(stream) and stream[pos] == 22:
            length = int.from_bytes(stream[pos + 3:pos + 5], "big")
            msg += stream[pos + 5:pos + 5 + length]
            pos += 5 + length
        pos = 4 + 2 + 32                                    # handshake header, version, random
        pos += 1 + msg[pos]                                 # session id
        pos += 2 + int.from_bytes(msg[pos:pos + 2], "big")  # cipher suites
        pos += 1 + msg[pos]                                 # compression methods
        end = pos + 2 + int.from_bytes(msg[pos:pos + 2], "big")
        pos += 2
        types = []
        while pos + 4 <= min(end, len(msg)):
            types.append(int.from_bytes(msg[pos:pos + 2], "big"))
            pos += 4 + int.from_bytes(msg[pos + 2:pos + 4], "big")
        return types
    except IndexError:
        return []


stream = b""       # the client's bytes so far, until the ClientHello is complete
decided = False
blocked = False


def process(packet):
    global stream, decided, blocked
    if not packet.tcp:
        return
    if blocked:
        return "drop"
    if decided:
        return
    if packet.direction == 1 and len(stream) < MAX_BUFFER:
        stream += packet.payload
    hello = packet.tls_client_hello
    if hello is None:
        return
    decided = True
    names = [name.lower() for name in hello.sni_list]
    if ECH_PUBLIC_NAME in names and ECH in extension_types(stream):
        blocked = True
        return "drop"
    stream = b""
