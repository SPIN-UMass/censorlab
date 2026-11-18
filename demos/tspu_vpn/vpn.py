# WireGuard / OpenVPN blocking after the handshake (PyCL corpus program)
#
# On 2023-08-07 users on many Russian ISPs reported that WireGuard and OpenVPN
# to foreign servers stopped working: the tunnel comes up, then no traffic
# flows.  Testers on ntc.party narrowed the rule down to a count of data
# packets after a successful handshake (net4people/bbs #274):
#
#   WireGuard  "Block if there are more than two data packets
#               (message_type = 4), after a successful handshake."
#   OpenVPN    "Block if there are more than 15 packets with data (P_DATA),
#               after a successful handshake."  (TCP and UDP)
#
# Because the handshake completes, the client believes it is connected; the
# data packets beyond the threshold then vanish.
#
# The reports give the thresholds but not how the censor recognises a
# handshake or which direction it drops.  This program assumes:
#   * WireGuard handshake = an initiation (type 1) answered by a response
#     (type 2); types are the first byte, followed by three zero bytes;
#   * OpenVPN handshake = P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7) answered
#     by P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8); the opcode is the top five
#     bits of the first byte (after the 2-byte length prefix over TCP, where
#     only the first OpenVPN packet of each segment is looked at);
#   * once over the threshold, every later packet of the flow is dropped.
# The reports also say the rule was applied to foreign hosting ranges; no
# address filter is applied here.
#
# To test: bring up a WireGuard or OpenVPN tunnel through CensorLab.  The
# handshake succeeds; pings through the tunnel get no reply.
#
# Return values used: "drop"

WG_INITIATION, WG_RESPONSE, WG_DATA = 1, 2, 4
OVPN_RESET_CLIENT, OVPN_RESET_SERVER = 7, 8
OVPN_DATA = (6, 9)          # P_DATA_V1, P_DATA_V2

WG_MAX_DATA = 2
OVPN_MAX_DATA = 15

initiator = None    # IP that sent the first handshake message
protocol = None     # "wireguard" or "openvpn", once the handshake completed
candidate = None    # protocol of the handshake message seen from the initiator
data_packets = 0
blocked = False


def wireguard_type(payload):
    if len(payload) >= 4 and payload[1:4] == b"\x00\x00\x00":
        return payload[0]


def openvpn_opcode(packet):
    payload = packet.payload
    if packet.tcp:
        payload = payload[2:]
    if payload:
        return payload[0] >> 3


def process(packet):
    global initiator, protocol, candidate, data_packets, blocked
    if blocked:
        return "drop"
    if not packet.payload:
        return
    wg = wireguard_type(packet.payload) if packet.udp else None
    ovpn = openvpn_opcode(packet)

    if protocol is None:
        src = packet.ip.src
        if wg == WG_INITIATION:
            initiator, candidate = src, "wireguard"
        elif ovpn == OVPN_RESET_CLIENT:
            initiator, candidate = src, "openvpn"
        elif src != initiator and initiator is not None:
            if candidate == "wireguard" and wg == WG_RESPONSE:
                protocol = candidate
            elif candidate == "openvpn" and ovpn == OVPN_RESET_SERVER:
                protocol = candidate
        return

    if protocol == "wireguard":
        is_data, limit = wg == WG_DATA, WG_MAX_DATA
    else:
        is_data, limit = ovpn in OVPN_DATA, OVPN_MAX_DATA
    if is_data:
        data_packets += 1
        if data_packets > limit:
            blocked = True
            return "drop"
