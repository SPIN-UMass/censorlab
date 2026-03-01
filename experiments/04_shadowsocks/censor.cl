# CensorLang Shadowsocks/encrypted protocol detection
# GFW heuristics from Wu et al. 2023

# Regex 0: Known protocol fingerprints (whitelist)
regex "^(\x16\x03|\x14\x03|\x15\x03|\x17\x03|GET |POST |HEAD |PUT |HTTP/|SSH-|\x00\x00)"
# Regex 1: First 6 bytes are printable ASCII (whitelist — rule 2)
regex "^[\x20-\x7e]{6}"

# Rule 1: Skip packets with no payload
if field:tcp.payload.len == 0: RETURN allow_all
# Rule 4: Exempt common lengths
if field:tcp.payload.len == 517: RETURN allow_all
if field:tcp.payload.len == 518: RETURN allow_all
if field:tcp.payload.len == 519: RETURN allow_all
if field:tcp.payload.len == 520: RETURN allow_all
if field:tcp.payload.len == 521: RETURN allow_all
if field:tcp.payload.len == 1460: RETURN allow_all
if field:tcp.payload.len == 1500: RETURN allow_all
# Rule 3: Allow known protocols (TLS, HTTP, SSH, DNS)
REGEX 0 -> reg:b.0
if reg:b.0 == True: RETURN allow_all
# Rule 2: Allow if first 6 bytes are printable ASCII
REGEX 1 -> reg:b.1
if reg:b.1 == True: RETURN allow_all
# Rule 5: Popcount check (avg bits per byte must be in [3.4, 4.6])
if field:transport.payload.avg_popcount < 3.4: RETURN allow_all
if field:transport.payload.avg_popcount > 4.6: RETURN allow_all
# Rule 6: Block high-entropy traffic (likely fully encrypted)
# Entropy is normalized 0-1; 0.375 = 3.0/8.0
if field:transport.payload.entropy > 0.375: RETURN terminate
