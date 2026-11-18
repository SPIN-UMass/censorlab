# GFW keyword censorship of FTP and SMTP (CensorLang corpus program); see
# ftp_smtp.py.  RETURN reset keeps resetting the rest of the connection,
# which the first RST has ended anyway; new connections are unaffected.
#
# reg:b.0, reg:b.1 = scratch

regex "(?i)ultrasurf"
regex "(?i)^(MAIL FROM|RCPT TO):[^\r\n]*xiazai@upup\.info"

# FTP control channel: a sensitive keyword in a command
REGEX 0 -> reg:b.0
if field:tcp.dst != 21: COPY False -> reg:b.0
if reg:b.0 == True: RETURN reset

# SMTP: a forbidden address as sender or recipient
REGEX 1 -> reg:b.1
if field:tcp.dst != 25: COPY False -> reg:b.1
if reg:b.1 == True: RETURN reset
