# WireGuard / OpenVPN blocking after the handshake (CensorLang corpus
# program); see vpn.py.  UDP only: OpenVPN over TCP needs the 2-byte length
# prefix skipped, which the PyCL version does.  Unlike the PyCL version this
# does not check that the handshake reply came from the other endpoint.
#
# reg:b.0 = WireGuard initiation seen     reg:b.1 = WireGuard handshake done
# reg:b.2 = OpenVPN client reset seen     reg:b.3 = OpenVPN handshake done
# reg:i.0 = WireGuard data packets        reg:i.1 = OpenVPN data packets
# reg:b.8 and up = scratch

# 0-2: WireGuard initiation, response, transport data (type byte + 3 zero bytes)
regex "(?s-u)^\x01\x00\x00\x00"
regex "(?s-u)^\x02\x00\x00\x00"
regex "(?s-u)^\x04\x00\x00\x00"
# 3-5: OpenVPN opcode (top 5 bits of the first byte): hard reset client v2 (7),
# hard reset server v2 (8), P_DATA_V1 (6) or P_DATA_V2 (9)
regex "(?s-u)^[\x38-\x3f]"
regex "(?s-u)^[\x40-\x47]"
regex "(?s-u)^[\x30-\x37\x48-\x4f]"

# Not UDP (the field reads 0)
if field:udp.length == 0: RETURN allow

# WireGuard: block once more than two data packets follow a handshake
REGEX 0 -> reg:b.8
if reg:b.8 == True: COPY True -> reg:b.0
REGEX 1 -> reg:b.9
AND reg:b.0, reg:b.9 -> reg:b.10
if reg:b.10 == True: COPY True -> reg:b.1
REGEX 2 -> reg:b.11
AND reg:b.1, reg:b.11 -> reg:b.12
if reg:b.12 == True: ADD reg:i.0, 1 -> reg:i.0
if reg:i.0 > 2: RETURN terminate

# OpenVPN: block once more than 15 data packets follow a handshake
REGEX 3 -> reg:b.8
if reg:b.8 == True: COPY True -> reg:b.2
REGEX 4 -> reg:b.9
AND reg:b.2, reg:b.9 -> reg:b.10
if reg:b.10 == True: COPY True -> reg:b.3
REGEX 5 -> reg:b.11
AND reg:b.3, reg:b.11 -> reg:b.12
if reg:b.12 == True: ADD reg:i.1, 1 -> reg:i.1
if reg:i.1 > 15: RETURN terminate
