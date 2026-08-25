# Shadowsocks/Encrypted Protocol Detection Censor (PyCL)
# Emulates GFW-style heuristics from Wu et al. 2023:
# "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic"
#
# Rules applied to the FIRST client->server data packet of each connection whose
# SYN was observed (Wu et al.: "the first data packet of a TCP connection";
# connections picked up mid-stream are not inspected, as in OpenGFW/the GFW):
# 1. Payload > 0 bytes
# 2. First 6 bytes are NOT printable ASCII (0x20-0x7e)
# 3. No protocol fingerprint (not TLS/HTTP/SSH/etc.)
# 4. Payload length not in exempt set
# 5. Popcount (avg bits per byte) is in [3.4, 4.6]           (Wu et al. Ex1)
# 6. Entropy > 0.375 (normalized 0-1; equivalent to 3.0 on 0-8 scale)
# 7. Fewer than half of the bytes are printable ASCII          (Wu et al. Ex3)
# 8. No run of more than 20 contiguous printable ASCII bytes   (Wu et al. Ex4)
# Rules 7-8 are the exemptions that keep collateral damage on real traffic low
# (without them ~5 % of benign flows in USTC-TFC2016 are flagged; with them <1 %).

from rust import regex

saw_syn = False  # connection start observed (mid-stream flows are never inspected)
checked = False
blocked = False  # once the first data packet fails the checks, the whole connection is blocked

EXEMPT_LENGTHS = {
    517, 518, 519, 520, 521,
    1460, 1500,
}

# Known protocol fingerprints (first bytes)
PROTOCOL_FINGERPRINTS = [
    b"\x16\x03",    # TLS record (handshake)
    b"\x14\x03",    # TLS ChangeCipherSpec
    b"\x15\x03",    # TLS Alert
    b"\x17\x03",    # TLS Application Data
    b"GET ",        # HTTP GET
    b"POST ",       # HTTP POST
    b"HEAD ",       # HTTP HEAD
    b"PUT ",        # HTTP PUT
    b"HTTP/",       # HTTP response
    b"SSH-",        # SSH identification
    b"\x00\x00",    # Often DNS/other
]

def is_printable_ascii(b):
    return 0x20 <= b <= 0x7e

# Every byte that is *not* printable ASCII, as a delete table for bytes.translate
NON_PRINTABLE = bytes(range(0x20)) + bytes(range(0x7F, 0x100))
# A run of more than 20 printable bytes (native regex engine)
PRINTABLE_RUN = regex(r"[\x20-\x7e]{21}")

def process(packet):
    global saw_syn, checked, blocked
    tcp = packet.tcp
    if not tcp:
        return
    # A blocked connection stays blocked: the GFW blackholes the flow, so TCP
    # retransmissions of the first data packet must not slip through.
    if blocked:
        return "drop"
    if tcp.flags.syn and not tcp.flags.ack and packet.direction == 1:
        saw_syn = True
        return
    # Only the client's first data packet of a connection we saw start is inspected
    if not saw_syn or packet.direction != 1:
        return
    payload = packet.payload
    if not payload or len(payload) == 0:
        return
    # Only check first data packet
    if checked:
        return
    checked = True

    # Rule 4: Exempt common lengths
    if len(payload) in EXEMPT_LENGTHS:
        return

    # Rule 3: Check protocol fingerprints
    for fp in PROTOCOL_FINGERPRINTS:
        if payload[:len(fp)] == fp:
            return

    # Rule 2: First 6 bytes must not be printable ASCII
    if len(payload) >= 6:
        if all(is_printable_ascii(b) for b in payload[:6]):
            return

    # Rule 5: Popcount check (avg bits per byte in [3.4, 4.6])
    popcount = packet.payload_avg_popcount
    if popcount < 3.4 or popcount > 4.6:
        return

    # Rule 6: Entropy check (normalized 0-1; 0.375 = 3.0/8.0)
    entropy = packet.payload_entropy
    if entropy < 0.375:
        return

    # Rule 7 (Ex3): exempt if more than half of the bytes are printable
    # (bytes.translate with a delete table counts natively — no per-byte loop)
    if len(payload.translate(None, NON_PRINTABLE)) * 2 > len(payload):
        return

    # Rule 8 (Ex4): exempt if there is a run of more than 20 printable bytes
    if PRINTABLE_RUN.is_match(payload):
        return

    blocked = True
    return "drop"
