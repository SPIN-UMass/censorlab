# CensorLang DNS query blocking (drop-only)
# CensorLang cannot inject packets, so this drops queries for forbidden domains.
# This is a weaker form of censorship than injection (causes timeout, not poisoning).
#
# NOTE: DNS domain names in wire format use length-prefixed labels
# (e.g., \x06google\x03com\x00) rather than dot notation.
# We match the label text without dots.

regex "(?i)(google|facebook|twitter|youtube|wikipedia|instagram|whatsapp|telegram|signal|reddit|nytimes|bbc|reuters|theguardian|washingtonpost|amnesty|hrw|rsf|torproject|eff|vpngate|psiphon|lanternvpn|protonvpn|mullvad|github|medium|blogspot|wordpress|tumblr|dropbox|soundcloud|vimeo|twitch|discord)"

# Only inspect DNS queries (without this guard the word list would be matched
# against every payload on the wire, including bulk TCP transfers)
if field:udp.dst != 53: RETURN allow
# Test regex against payload (UDP DNS queries)
REGEX 0 -> reg:b.0
if reg:b.0 == True: RETURN terminate
