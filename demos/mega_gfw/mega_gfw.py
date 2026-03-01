# =============================================================================
# Mega-GFW: Emulating China's Great Firewall in CensorLab
# =============================================================================
#
# This script combines seven censorship techniques documented in academic
# research on the Chinese Great Firewall (GFW) and similar state-level
# censorship systems. Each technique is labeled with its academic citation.
#
# The GFW is the world's most sophisticated internet censorship apparatus,
# operating at backbone routers across China's international gateways.
# It employs a layered approach: cheap checks (IP blocklist) run first,
# expensive checks (DPI, entropy analysis) run later.
#
# This script is meant as an educational demonstration of how these
# techniques work.
#
# References (in order of technique):
#   [1] Xu et al., "Internet Censorship in China: Where Does the Filtering
#       Occur?" (PAM 2011)
#   [2] Anonymous, "Towards a Comprehensive Picture of the Great Firewall's
#       DNS Censorship" (FOCI 2014)
#   [3] Hoang et al., "How Great is the Great Firewall? Measuring China's
#       DNS Censorship" (USENIX Security 2021)
#   [4] Knockel et al., "Three Researchers, Five Conjectures: An Empirical
#       Analysis of TOM-Skype Censorship and Surveillance" (FOCI 2011)
#   [5] Clayton et al., "Ignoring the Great Firewall of China" (PET 2006)
#   [6] Bock et al., "Exposing and Circumventing China's Censorship of ESNI"
#       (GFW Report, August 2020)
#   [7] Elmenhorst et al., "Web Censorship Measurements of HTTP/3 over QUIC"
#       (IMC 2021)
#   [8] Wu et al., "How the Great Firewall of China Detects and Blocks Fully
#       Encrypted Traffic" (USENIX Security 2023)
#   [9] Alice et al., "How China Detects and Blocks Shadowsocks"
#       (IMC 2020)
#   [10] Dunna et al., "Analyzing China's Blocking of Unpublished Tor Bridges"
#       (FOCI 2018)
#   [11] Zohaib et al., "Exposing and Circumventing SNI-based QUIC Censorship
#       of the Great Firewall of China" (USENIX Security 2025)

from rust import log_info
from dns import parse as parse_dns, craft_response as craft_dns_response
from tls import parse_client_hello
from quic import parse_initial

# =============================================================================
# Blocklists
# =============================================================================
# The GFW uses keyword and domain lists that are updated regularly.
# These are representative examples for demonstration purposes.

BLOCKED_DOMAINS = [
    b"blocked.example.com",
    b"forbidden.test",
    b"sensitive.example.org",
]

BLOCKED_KEYWORDS = [
    b"ultrasurf",
    b"freegate",
    b"falun",
    b"dynaweb",
]

# IP addresses to block (technique 1)
BLOCKED_IPS = [
    "198.51.100.1",
]


# =============================================================================
# Technique 1: IP Blocklist
# =============================================================================
# The GFW maintains blocklists of IP addresses belonging to known
# circumvention services, foreign media, and other "sensitive" destinations.
#
# Reference:
#   - Xu et al., "Internet Censorship in China: Where Does the Filtering
#     Occur?" (PAM 2011)

def check_ip(packet):
    ip = packet.ip
    for blocked in BLOCKED_IPS:
        if blocked in [ip.src, ip.dst]:
            log_info("[IP blocklist] Blocked IP: " + blocked)
            return "drop"
    return None


# =============================================================================
# Technique 2: DNS Query Blocking
# =============================================================================
# The GFW inspects DNS queries traversing international links and injects
# forged responses for blocked domains. It operates on UDP port 53 traffic,
# matching queried domain names against a blocklist. Rather than dropping
# the query, the GFW injects a forged DNS response pointing to a decoy IP,
# racing against the legitimate response.
#
# References:
#   - Anonymous, "Towards a Comprehensive Picture of the Great Firewall's
#     DNS Censorship" (FOCI 2014)
#   - Hoang et al., "How Great is the Great Firewall? Measuring China's
#     DNS Censorship" (USENIX Security 2021)

POISON_IP = "104.18.27.120"

def check_dns(packet):
    udp = packet.udp
    if not udp or udp.dst != 53:
        return None

    try:
        dns = parse_dns(packet.payload)
    except Exception:
        return None

    for question in dns.questions:
        qname = question.qname.lower()
        for blocked in BLOCKED_DOMAINS:
            if blocked in qname:
                log_info("[DNS inject] Injecting forged response for: " + str(qname))
                return craft_dns_response(packet.payload, POISON_IP)
    return None


# =============================================================================
# Technique 3: HTTP Host / Keyword Blocking
# =============================================================================
# The GFW performs deep packet inspection on HTTP traffic, examining both
# the Host header and the request body/URI for sensitive keywords. When a
# match is found, it injects TCP RST packets in both directions.
#
# References:
#   - Knockel et al., "Three Researchers, Five Conjectures: An Empirical
#     Analysis of TOM-Skype Censorship and Surveillance" (FOCI 2011)
#   - Clayton et al., "Ignoring the Great Firewall of China" (PET 2006)

def check_http(packet):
    tcp = packet.tcp
    if not tcp or not tcp.uses_port(80):
        return None
    if packet.payload_len == 0:
        return None

    payload = packet.payload

    # Quick check for HTTP request method (bytes comparison, no decode needed)
    is_http = (b"GET " in payload[:10] or b"POST " in payload[:10] or
               b"HEAD " in payload[:10] or b"PUT " in payload[:10])
    if not is_http:
        return None

    # Check Host header against domain blocklist (byte-level matching)
    for blocked in BLOCKED_DOMAINS:
        if blocked in payload:
            log_info("[HTTP DPI] Blocked domain in HTTP request: " + str(blocked))
            return "reset"

    # Check for sensitive keywords anywhere in the request
    for keyword in BLOCKED_KEYWORDS:
        if keyword in payload:
            log_info("[HTTP DPI] Blocked keyword in HTTP request: " + str(keyword))
            return "reset"

    return None


# =============================================================================
# Technique 4: TLS SNI Filtering
# =============================================================================
# Since ~2019, the GFW inspects the Server Name Indication (SNI) field in
# TLS ClientHello messages. This reveals which domain the client is
# connecting to, even though the rest of the TLS handshake is encrypted.
# The GFW also began blocking Encrypted Client Hello (ECH/ESNI) entirely.
#
# Reference:
#   - Bock et al., "Exposing and Circumventing China's Censorship of ESNI"
#     (GFW Report, August 2020)

def check_tls_sni(packet):
    tcp = packet.tcp
    if not tcp or not tcp.uses_port(443):
        return None
    if packet.payload_len == 0:
        return None

    try:
        hello = parse_client_hello(packet.payload)
    except Exception:
        return None

    if not hello.sni:
        return None

    sni_lower = hello.sni.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in sni_lower:
            log_info("[TLS SNI] Blocked SNI: " + str(sni_lower))
            return "reset"

    return None


# =============================================================================
# Technique 5: QUIC SNI Blocking
# =============================================================================
# As QUIC (HTTP/3) adoption grows, the GFW has extended its SNI filtering
# to QUIC Initial packets. The SNI in QUIC Initial packets is extracted
# from the embedded TLS ClientHello within the CRYPTO frame.
# Some censors also block QUIC entirely by dropping all UDP/443 traffic.
#
# References:
#   - Elmenhorst et al., "Web Censorship Measurements of HTTP/3 over QUIC"
#     (IMC 2021)
#   - Zohaib et al., "Exposing and Circumventing SNI-based QUIC Censorship
#     of the Great Firewall of China" (USENIX Security 2025)

def check_quic_sni(packet):
    udp = packet.udp
    if not udp or not udp.uses_port(443):
        return None
    if packet.payload_len == 0:
        return None

    try:
        info = parse_initial(packet.payload)
    except Exception:
        return None

    if not info.sni:
        return None

    sni_lower = info.sni.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in sni_lower:
            log_info("[QUIC SNI] Blocked SNI: " + str(sni_lower))
            return "drop"

    return None


# =============================================================================
# Technique 6: Fully Encrypted Traffic Detection
# =============================================================================
# In late 2022, the GFW began detecting and blocking "fully encrypted"
# proxy protocols (Shadowsocks, VMess, etc.) that lack identifiable protocol
# fingerprints. The GFW applies five exemption rules (Algorithm 1 in the
# paper); traffic that does NOT match any exemption is blocked:
#   Ex1: Average popcount per byte <= 3.4 or >= 4.6
#   Ex2: First 6+ bytes are printable ASCII [0x20, 0x7e]
#   Ex3: More than 50% of bytes are printable ASCII
#   Ex4: Longest contiguous run of printable ASCII > 20 bytes
#   Ex5: Matches a known protocol fingerprint (TLS or HTTP)
#
# References:
#   - Wu et al., "How the Great Firewall of China Detects and Blocks Fully
#     Encrypted Traffic" (USENIX Security 2023)
#   - Alice et al., "How China Detects and Blocks Shadowsocks" (IMC 2020)

PRINTABLE_ASCII = set(range(0x20, 0x7f))

def _num_beginning_ascii(data):
    """Count printable ASCII bytes at the start of data."""
    for i in range(len(data)):
        if data[i] not in PRINTABLE_ASCII:
            return i
    return len(data)

def _longest_printable_run(data):
    """Find the longest contiguous run of printable ASCII bytes."""
    max_run = 0
    run = 0
    for b in data:
        if b in PRINTABLE_ASCII:
            run += 1
        else:
            if run > max_run:
                max_run = run
            run = 0
    if run > max_run:
        max_run = run
    return max_run

def _frac_printable(data):
    """Return the fraction of bytes that are printable ASCII."""
    count = 0
    for b in data:
        if b in PRINTABLE_ASCII:
            count += 1
    return count / len(data)

def _match_protocol_fingerprint(data):
    """Check for TLS or HTTP protocol fingerprints."""
    # TLS: [\x15-\x17]\x03[\x00-\x0f]
    if len(data) >= 3:
        if data[0] in (0x15, 0x16, 0x17) and data[1] == 0x03 and data[2] in range(0x00, 0x10):
            return "TLS"
    # HTTP: GET, PUT, POST, HEAD followed by space
    if len(data) >= 5:
        if data[0:4] == b"GET " or data[0:4] == b"PUT ":
            return "HTTP"
        if data[0:5] == b"POST " or data[0:5] == b"HEAD ":
            return "HTTP"
    return None

def check_encrypted_traffic(packet):
    tcp = packet.tcp
    if not tcp:
        return None
    if packet.payload_len == 0:
        return None

    # Exempt well-known ports (HTTP/HTTPS are handled by other techniques)
    if tcp.uses_port(443) or tcp.uses_port(80):
        return None

    payload = packet.payload

    # Ex5: Protocol fingerprint exemption (TLS, HTTP)
    proto = _match_protocol_fingerprint(payload)
    if proto:
        return None

    # Ex1: Popcount exemption — average bits set per byte <= 3.4 or >= 4.6
    popcount = packet.payload_avg_popcount
    if popcount <= 3.4 or popcount >= 4.6:
        return None

    # Ex2: First 6+ bytes are printable ASCII [0x20, 0x7e]
    if _num_beginning_ascii(payload) >= 6:
        return None

    # Ex3: More than 50% of bytes are printable ASCII
    if _frac_printable(payload) > 0.5:
        return None

    # Ex4: Longest contiguous run of printable ASCII > 20 bytes
    if _longest_printable_run(payload) > 20:
        return None

    # No exemption matched — traffic looks fully encrypted
    log_info("[Encrypted traffic] Blocked fully encrypted traffic (popcount=" + str(popcount) + ")")
    return "drop"


# =============================================================================
# Technique 7: SSH Protocol Detection
# =============================================================================
# The GFW monitors for SSH connections, particularly to flag potential
# circumvention tunnels. SSH connections begin with a version banner like
# "SSH-2.0-OpenSSH_8.9\r\n" which is trivially detectable via DPI.
# While China doesn't block all SSH, it uses SSH detection to identify and
# probe potential proxy/tunnel endpoints.
#
# Reference:
#   - Dunna et al., "Analyzing China's Blocking of Unpublished Tor Bridges"
#     (FOCI 2018)

def check_ssh(packet):
    tcp = packet.tcp
    if not tcp:
        return None
    if packet.payload_len == 0:
        return None

    if b"SSH-" in packet.payload[:10]:
        log_info("[SSH detection] Blocked SSH connection")
        return "reset"

    return None


# =============================================================================
# Main processing function
# =============================================================================
# The GFW processes packets through a cascade of checks, ordered from
# cheapest to most expensive.

def process(packet):
    # Technique 1: IP blocklist
    result = check_ip(packet)
    if result:
        return result

    # Technique 2: DNS query blocking (UDP/53)
    result = check_dns(packet)
    if result:
        return result

    # Technique 3: HTTP keyword/host blocking (TCP/80)
    result = check_http(packet)
    if result:
        return result

    # Technique 4: TLS SNI filtering (TCP/443)
    result = check_tls_sni(packet)
    if result:
        return result

    # Technique 5: QUIC SNI blocking (UDP/443)
    result = check_quic_sni(packet)
    if result:
        return result

    # Technique 6: Encrypted traffic detection (high entropy heuristic)
    result = check_encrypted_traffic(packet)
    if result:
        return result

    # Technique 7: SSH banner detection
    result = check_ssh(packet)
    if result:
        return result

    # No match — allow the packet through
    return None
