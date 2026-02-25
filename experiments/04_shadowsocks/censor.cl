# CensorLang Shadowsocks/encrypted protocol detection
# Simplified GFW heuristics from Wu et al. 2023
# Note: CensorLang lacks popcount and first-byte inspection,
# so this is a simplified version using entropy threshold only.

# Match known protocol fingerprints to whitelist
regex "^(\x16\x03|\x14\x03|\x15\x03|\x17\x03|GET |POST |HEAD |PUT |HTTP/|SSH-)"

# Skip packets with no payload
if field:tcp.payload.len == 0: RETURN allow_all
# Allow known protocols (TLS, HTTP, SSH, etc.)
REGEX 0 -> reg:b.0
if reg:b.0 == True: RETURN allow_all
# Block high-entropy traffic (likely fully encrypted)
# Entropy is normalized 0-1; 0.375 = 3.0/8.0
if field:transport.payload.entropy > 0.375: RETURN terminate
