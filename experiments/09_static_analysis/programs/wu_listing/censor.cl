# Wu et al. Shadowsocks detector exactly as listed in the paper (Section 5.3),
# analysed here so the paper's worked static analysis cites generated numbers.
regex "^(\x16\x03|\x14\x03|\x15\x03|\x17\x03|GET |POST |HEAD |PUT |HTTP/)"
regex "^[\x20-\x7e]{6}"
regex "[\x20-\x7e]{21,}"
if field:transport.payload.avg_popcount <= 3.4: RETURN allow_all
if field:transport.payload.avg_popcount >= 4.6: RETURN allow_all
REGEX 1 -> reg:b.0
if reg:b.0 == True: RETURN allow_all
if field:transport.payload.printable_fraction > 0.5: RETURN allow_all
REGEX 2 -> reg:b.1
if reg:b.1 == True: RETURN allow_all
REGEX 0 -> reg:b.2
if reg:b.2 == True: RETURN allow_all
if field:tcp.payload.len > 0: RETURN terminate
