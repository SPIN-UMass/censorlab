# GFW censorship of DNS over TCP (CensorLang corpus program); see dns_tcp.py.
#
# CensorLang has no DNS parser, so this matches the name's wire encoding
# (length-prefixed labels: \x08facebook\x03com\x00) anywhere in a segment to
# port 53.  Unlike the PyCL version it does not check that the segment is a
# well-formed query.  RETURN reset keeps resetting the rest of the connection,
# which the first RST has ended anyway; new connections are unaffected.
#
# reg:b.0 = scratch

regex "(?i-u)\x08facebook\x03com\x00"

if field:tcp.dst != 53: RETURN allow
REGEX 0 -> reg:b.0
if reg:b.0 == True: RETURN reset
