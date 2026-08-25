# TSPU-style TTL normalization (PyCL corpus program)
#
# Desynchronisation tools (GoodbyeDPI, zapret, byedpi, …) defeat naive DPI by
# sending a *fake* TCP segment — carrying a decoy ClientHello — with a TTL
# chosen so that the DPI sees it but the segment expires before it reaches the
# server.  A DPI that trusts the first segment it sees for a sequence range is
# then poisoned and misses the real ClientHello that follows.
#
# Russia's TSPU is reported to defeat this family of evasions by normalizing the
# stream rather than inspecting segments in isolation (Xue et al., IMC'22;
# ntc.party / net4people reports on TSPU behaviour).  This program emulates the
# TTL half of that normalization:
#
#   * remember the TTL of the client's SYN (its true hop distance);
#   * a later client segment whose TTL is implausibly lower than that baseline
#     cannot reach the server — it is a fake.  Rewrite its TTL back to the
#     baseline so that it *does* reach the server (the desync becomes
#     self-defeating: the server now sees the decoy too) and, since the DPI
#     knows it is a fake, do not let it poison inspection;
#   * inspect every genuine client segment as usual (here: SNI filtering).
#
# Return values used: ("rewrite", {"ttl": n})  -> normalized copy is forwarded
#                     "reset"                   -> forbidden SNI
#
# Usage: censorlab -c demos/tspu_ttl_normalization/censor.toml nfq

from tls import parse_client_hello

FORBIDDEN = [b"example.org", b"torproject.org", b"bbc.com"]

# Hops of slack allowed below the SYN's TTL before a segment is considered a
# fake that will expire before the server (route changes are ≤ a few hops).
TTL_TOLERANCE = 8

baseline_ttl = None


def process(packet):
    global baseline_ttl
    tcp = packet.tcp
    if not tcp or packet.direction != 1:
        return  # only client -> server segments matter here

    ttl = packet.ip.ttl
    if tcp.flags.syn:
        baseline_ttl = ttl
        return

    if baseline_ttl is not None and ttl + TTL_TOLERANCE < baseline_ttl:
        # Fake segment: normalize its TTL so it reaches the server, and skip
        # inspection so its decoy payload cannot poison our view of the stream.
        return ("rewrite", {"ttl": baseline_ttl})

    if tcp.dst == 443 and packet.payload:
        try:
            sni = parse_client_hello(packet.payload).sni.lower()
        except Exception:
            return
        for domain in FORBIDDEN:
            if domain in sni:
                return "reset"
