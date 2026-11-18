# TSPU SNI-II: delayed symmetric drop (CensorLang corpus program); see
# sni_delayed_drop.py.
#
# reg:b.0 = a triggering ClientHello has been seen
# reg:b.1 = scratch
# reg:i.0 = packets seen since the trigger
# reg:i.1 = direction of the SYN (1 = opened from the local side)

regex "(?i)(^|\.)(play\.google\.com|news\.google\.com|nordvpn\.com)$"

# After the trigger, five more packets pass in either direction, then
# everything is dropped (the paper observed five to eight)
if reg:b.0 == True: ADD reg:i.0, 1 -> reg:i.0
if reg:i.0 > 5: RETURN terminate
if reg:b.0 == True: RETURN allow

# Only connections opened by the local client; a bare SYN has no ACK flag
if field:tcp.flag.ack == False: COPY field:direction -> reg:i.1
if reg:i.1 != 1: RETURN allow
if field:tcp.dst != 443: RETURN allow
# The ClientHello must have arrived in one segment and one TLS record:
# segmentation bypasses the TSPU
if field:tls.hello.tcp_segments != 1: RETURN allow
if field:tls.hello.record_count != 1: RETURN allow
REGEX_SNI 0 -> reg:b.1
# The triggering packet itself is delivered
if reg:b.1 == True: COPY True -> reg:b.0
