# CensorLang Shadowsocks/encrypted protocol detection
# GFW heuristics from Wu et al. 2023

# Regex 0: Known protocol fingerprints (whitelist)
regex "^(\x16\x03|\x14\x03|\x15\x03|\x17\x03|GET |POST |HEAD |PUT |HTTP/|SSH-|\x00\x00)"
# Regex 1: First 6 bytes are printable ASCII (whitelist — rule 2)
regex "^[\x20-\x7e]{6}"
# Regex 2: a run of more than 20 printable bytes anywhere (Wu et al. Ex4)
regex "[\x20-\x7e]{21}"

# Connection start: the pure SYN (ACK flag clear) identifies the client side;
# remember that we saw it (reg:b.3) and the client's port (reg:i.4).  Flows
# picked up mid-stream are never inspected (Wu et al. inspect the first data
# packet of a connection).
if field:tcp.flag.ack == False: COPY field:tcp.src -> reg:i.4
if field:tcp.flag.ack == False: COPY True -> reg:b.3
if reg:b.3 != True: RETURN allow
# Only segments from the client carry the first data packet
if field:tcp.src != reg:i.4: RETURN allow
# Rule 1: Skip packets with no payload
if field:tcp.payload.len == 0: RETURN allow
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
# Rule 8 (Ex4): exempt payloads with a long printable run
REGEX 2 -> reg:b.2
if reg:b.2 == True: RETURN allow_all
# Rule 7 (Ex3, printable fraction > 50 %) is not applied by this program.
# Rule 5: Popcount check (avg bits per byte must be in [3.4, 4.6])
if field:transport.payload.avg_popcount < 3.4: RETURN allow_all
if field:transport.payload.avg_popcount > 4.6: RETURN allow_all
# Rule 6: Block high-entropy traffic (likely fully encrypted)
# Entropy is normalized 0-1; 0.375 = 3.0/8.0
if field:transport.payload.entropy > 0.375: RETURN terminate
# Wu et al. only inspect the first data packet: once it has passed every
# rule the connection is exempt from further checks.
RETURN allow_all
