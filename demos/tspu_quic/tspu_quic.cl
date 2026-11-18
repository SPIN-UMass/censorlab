# TSPU QUIC blocking (CensorLang corpus program); see tspu_quic.py.
#
# reg:b.0 = this flow has shown the fingerprint; drop everything after it
# reg:b.1 = scratch

# Any first byte, then the QUIC version 1 field
regex "(?s-u)^.\x00\x00\x00\x01"

if reg:b.0 == True: RETURN terminate
# The trigger must come from the local (client) side, go to UDP port 443 ...
if field:direction != 1: RETURN allow
if field:udp.dst != 443: RETURN allow
# ... and carry at least 1001 bytes
if field:transport.payload.len < 1001: RETURN allow
REGEX 0 -> reg:b.1
# The triggering packet itself is delivered
if reg:b.1 == True: COPY True -> reg:b.0
