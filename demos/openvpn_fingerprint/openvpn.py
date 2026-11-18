# OpenVPN opcode fingerprinting (PyCL corpus program)
#
# Every OpenVPN packet starts with an unencrypted byte holding an opcode and a
# key id (over TCP it follows a 2-byte length).  A session opens with
# a client reset, a server reset, then control and ACK packets for the TLS
# handshake, then data packets; the resets never come back once the handshake
# is done.  Xue et al. (USENIX Security 2022) fingerprint that shape instead
# of fixed byte values, so the rule also catches "XOR-scrambled" OpenVPN,
# where each opcode byte is consistently mapped to some other value.
#
# Algorithm 1 of the paper, over the opcode bytes of a flow's first N packets:
#
#   CR, SR = opcode of packet 0, opcode of packet 1
#   for each later opcode:
#       if it is CR or SR and at least 4 different opcodes have been seen:
#           not OpenVPN (a reset after the handshake)
#   OpenVPN if N packets were seen and 4..10 different opcodes occurred
#
# The printed algorithm starts the set of seen opcodes empty at packet 2; its
# comment says a handshake needs at least four opcodes, which only adds up if
# the two resets count, so they are counted here.  N = 100 is the window the
# authors deployed.
#
# The paper's filter only flags a flow for a second, active-probing stage
# (CensorLab cannot send probes).  Here a flagged flow is simply dropped from
# packet N on.  The paper's ACK-size fingerprint is not implemented.
#
# To test: run OpenVPN (UDP or TCP, with or without the XOR patch) through
# CensorLab; the tunnel dies after its first 100 packets.
#
# Return values used: "drop"

N = 100

opcodes = []
blocked = False


def is_openvpn(ops):
    client_reset, server_reset = ops[0], ops[1]
    seen = {client_reset, server_reset}
    for op in ops[2:]:
        if op in (client_reset, server_reset) and len(seen) >= 4:
            return False
        seen.add(op)
    return 4 <= len(seen) <= 10


def process(packet):
    global blocked
    if blocked:
        return "drop"
    payload = packet.payload
    if packet.tcp:
        payload = payload[2:]       # skip the packet length
    if not payload or len(opcodes) >= N:
        return
    opcodes.append(payload[0])
    if len(opcodes) == N and is_openvpn(opcodes):
        blocked = True
        return "drop"
