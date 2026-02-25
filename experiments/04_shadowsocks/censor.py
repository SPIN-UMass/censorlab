# Shadowsocks/Encrypted Protocol Detection Censor (PyCL)
# Emulates GFW-style heuristics from Wu et al. 2023:
# "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic"
#
# Rules applied to the FIRST data packet of each connection:
# 1. Payload > 0 bytes
# 2. First 6 bytes are NOT printable ASCII (0x20-0x7e)
# 3. No protocol fingerprint (not TLS/HTTP/SSH/etc.)
# 4. Payload length not in exempt set
# 5. Popcount (avg bits per byte) is in [3.4, 4.6]
# 6. Entropy > 0.375 (normalized 0-1; equivalent to 3.0 on 0-8 scale)

checked = False

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

def process(packet):
    global checked
    tcp = packet.tcp
    if not tcp:
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

    return "drop"
