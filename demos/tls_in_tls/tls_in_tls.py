# TLS-in-TLS detector (PyCL corpus program)
#
# Proxies that tunnel traffic inside an ordinary-looking TLS connection
# (Trojan, V2Ray/Xray TLS transports, Shadowsocks TLS plugins, naiveproxy-like
# designs) leak the *shape* of the inner TLS handshake through the outer record
# lengths.  Russian ISPs' TSPU devices were reported in 2023–2024 to throttle or
# reset such "TLS in TLS" connections on this basis (ntc.party threads;
# net4people/bbs issue #129 and follow-ups), which is what motivated
# XTLS-Vision's handshake padding.
#
# Heuristic, evaluated on the outer connection's application-data records
# (content type 0x17), independent of the outer TLS version:
#
#   phase 0  wait for the first client->server record of ClientHello size
#            (200–1500 B).  Smaller client records (TLS 1.3 Finished, pings)
#            and all server records before it are skipped.
#   phase 1  the server must answer with >= 1000 B of records — the inner
#            ServerHello/Certificate flight — within at most 3 records.
#   phase 2  the next client record must be small (< 120 B): the inner
#            Finished / key exchange.  -> match
#
# Any deviation ends tracking for the connection (no match).  Record lengths
# come from TLS record headers, so TCP segmentation does not matter as long as
# the remaining length of a record split across segments is tracked.
#
# Return value used: "reset" on a match.
#
# Usage: censorlab -c demos/tls_in_tls/censor.toml nfq

APP_DATA = 0x17
TLS_TYPES = (0x14, 0x15, 0x16, 0x17)

INNER_CH_MIN, INNER_CH_MAX = 200, 1500
INNER_SERVER_MIN_BYTES = 1000
INNER_SERVER_MAX_RECORDS = 3
INNER_FINISHED_MAX = 120

# Per-connection state (the script is instantiated once per connection).
phase = 0
server_bytes = 0
server_records = 0
remaining = {1: 0, -1: 0}   # bytes of a record still pending per direction
decided = False


def app_records(direction, payload):
    """Yield lengths of the application-data records that start in payload."""
    i = 0
    if remaining[direction] > 0:
        take = min(remaining[direction], len(payload))
        remaining[direction] -= take
        i = take
    while i + 5 <= len(payload):
        ctype = payload[i]
        if ctype not in TLS_TYPES:
            return
        length = (payload[i + 3] << 8) | payload[i + 4]
        if ctype == APP_DATA:
            yield length
        body = min(length, len(payload) - i - 5)
        remaining[direction] = length - body
        i += 5 + body


def step(direction, length):
    """Advance the state machine; return True on a TLS-in-TLS match."""
    global phase, server_bytes, server_records, decided
    if phase == 0:
        if direction == 1 and INNER_CH_MIN <= length <= INNER_CH_MAX:
            phase = 1
            server_bytes = 0
            server_records = 0
        return False
    if phase == 1:
        if direction == -1:
            server_bytes += length
            server_records += 1
            if server_records > INNER_SERVER_MAX_RECORDS and server_bytes < INNER_SERVER_MIN_BYTES:
                decided = True
            return False
        # first client record after the server flight
        decided = True
        return server_bytes >= INNER_SERVER_MIN_BYTES and length < INNER_FINISHED_MAX
    return False


def process(packet):
    tcp = packet.tcp
    if not tcp or decided or not packet.payload:
        return
    direction = packet.direction
    if direction not in (1, -1):
        return
    for length in app_records(direction, packet.payload):
        if step(direction, length):
            return "reset"
        if decided:
            return
