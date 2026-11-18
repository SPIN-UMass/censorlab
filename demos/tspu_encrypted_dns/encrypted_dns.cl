# Encrypted DNS resolver blocking (CensorLang corpus program); see
# encrypted_dns.py.  Plaintext DNS to 8.8.8.8 is dropped by the
# [udp.ip_port_blocklist] in censor_lang.toml.
#
# reg:b.0 = scratch

regex "(?i)^(dns\.google|doh\.opendns\.com|1dot1dot1dot1\.cloudflare-dns\.com)$"

# Only a ClientHello sent by the local client in one segment and one record
if field:direction != 1: RETURN allow
if field:tls.hello.tcp_segments != 1: RETURN allow
if field:tls.hello.record_count != 1: RETURN allow
REGEX_SNI 0 -> reg:b.0
if reg:b.0 == True: RETURN reset
