# CensorLang TLS SNI filtering
# Matches forbidden domain names via regex in TLS ClientHello payload.
# Less robust than PyCL (cannot structurally parse TLS) but functional
# because the SNI appears as a plaintext string in the ClientHello.

regex "(?i)(google\.com|facebook\.com|twitter\.com|youtube\.com|instagram\.com|whatsapp\.com|telegram\.org|signal\.org|wikipedia\.org|reddit\.com|discord\.com|medium\.com|soundcloud\.com|tumblr\.com|vimeo\.com|pinterest\.com|nytimes\.com|washingtonpost\.com|bbc\.com|theguardian\.com|reuters\.com|amnesty\.org|hrw\.org|rsf\.org|torproject\.org|psiphon\.ca|lanternvpn\.org|mullvad\.net|protonvpn\.com|nordvpn\.com|expressvpn\.com|github\.com|gitlab\.com|stackoverflow\.com|twitch\.tv)"

# Only inspect port 443 traffic
if field:tcp.dst != 443: RETURN allow
# Skip packets with no payload
if field:tcp.payload.len == 0: RETURN allow
# Test regex against payload
REGEX 0 -> reg:b.0
if reg:b.0 == True: RETURN reset
