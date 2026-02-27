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
#       (FOCI 2020)
#   [7] Elmenhorst et al., "Web Censorship Measurements of HTTP/3 over QUIC"
#       (IMC 2022)
#   [8] Wu et al., "How the Great Firewall of China Detects and Blocks Fully
#       Encrypted Traffic" (USENIX Security 2023)
#   [9] Dunna et al., "Analyzing China's Blocking of Unpublished Tor Bridges"
#       (FOCI 2018)

from dns import parse as parse_dns
from tls import parse_client_hello
from quic import parse_initial

# =============================================================================
# Blocklists
# =============================================================================
# The GFW uses keyword and domain lists that are updated regularly.
# These are representative examples for demonstration purposes.

BLOCKED_DOMAINS = [
    "blocked.example.com",
    "forbidden.test",
    "sensitive.example.org",
]

# Byte-encoded versions for matching inside raw packet payloads (HTTP DPI)
BLOCKED_DOMAINS_BYTES = [
    b"blocked.example.com",
    b"forbidden.test",
    b"sensitive.example.org",
]

BLOCKED_KEYWORDS = [
    "ultrasurf",
    "freegate",
    "falun",
    "dynaweb",
]

BLOCKED_KEYWORDS_BYTES = [
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
            return "drop"
    return None


# =============================================================================
# Technique 2: DNS Query Blocking
# =============================================================================
# The GFW inspects DNS queries traversing international links and injects
# forged responses for blocked domains. It operates on UDP port 53 traffic,
# matching queried domain names against a blocklist.
#
# References:
#   - Anonymous, "Towards a Comprehensive Picture of the Great Firewall's
#     DNS Censorship" (FOCI 2014)
#   - Hoang et al., "How Great is the Great Firewall? Measuring China's
#     DNS Censorship" (USENIX Security 2021)

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
                return "drop"
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
    for blocked_bytes in BLOCKED_DOMAINS_BYTES:
        if blocked_bytes in payload:
            return "reset"

    # Check for sensitive keywords anywhere in the request
    for keyword_bytes in BLOCKED_KEYWORDS_BYTES:
        if keyword_bytes in payload:
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
#     (FOCI 2020)

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
# Reference:
#   - Elmenhorst et al., "Web Censorship Measurements of HTTP/3 over QUIC"
#     (IMC 2022)

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
            return "drop"

    return None


# =============================================================================
# Technique 6: Fully Encrypted Traffic Detection
# =============================================================================
# In late 2022, the GFW began detecting and blocking "fully encrypted"
# proxy protocols (Shadowsocks, VMess, etc.) that lack identifiable protocol
# fingerprints. The detection heuristic checks:
#   - High Shannon entropy (close to 1.0, indicating random/encrypted data)
#   - No recognizable protocol header (not TLS, HTTP, SSH, etc.)
#   - High average popcount (bits-per-byte near 4.0, consistent with
#     uniformly random bytes)
#
# Reference:
#   - Wu et al., "How the Great Firewall of China Detects and Blocks Fully
#     Encrypted Traffic" (USENIX Security 2023)

def check_encrypted_traffic(packet):
    tcp = packet.tcp
    if not tcp:
        return None
    if packet.payload_len < 64:
        return None

    # Known protocol fingerprints are already handled by earlier checks
    # (DNS, HTTP, TLS, QUIC, SSH). If we reach here, the payload doesn't
    # match any known protocol. Check if it looks fully encrypted.

    # Check entropy + popcount thresholds
    # High entropy (>0.9 on 0-1 scale) combined with high average popcount
    # (>3.4 bits/byte) strongly indicates fully encrypted / random data.
    entropy = packet.payload_entropy
    popcount = packet.payload_avg_popcount
    if entropy > 0.9 and popcount > 3.4:
        return "drop"

    return None


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
#   - (SSH tunneling is a common circumvention method; the GFW actively
#     probes servers detected speaking SSH on non-standard ports)

def check_ssh(packet):
    tcp = packet.tcp
    if not tcp:
        return None
    if packet.payload_len == 0:
        return None

    if b"SSH-" in packet.payload[:10]:
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
