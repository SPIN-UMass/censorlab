# GFW keyword censorship of FTP and SMTP (PyCL corpus program)
#
# HTTP is not the only plaintext protocol the GFW reads.  Bock et al. triggered
# it over
#
#   FTP   by requesting "files with sensitive keywords as names (e.g.,
#         ultrasurf)" (SIGCOMM 2020);
#   SMTP  with the forbidden address xiazai@upup.info, as the recipient
#         (SIGCOMM 2020) or in MAIL FROM (WOOT 2021).
#
# In both cases the connection is torn down with injected RSTs.  Two things
# differ from the GFW's HTTP censorship:
#
#   * there is no residual censorship: "after the forbidden request on these
#     protocols is censored, the user is free to make a second follow-up
#     request", so only the offending packet is reset here;
#   * the FTP and SMTP boxes do not reassemble TCP segments (shrinking the
#     TCP window so the client splits its request evades them), so this
#     script matches single packets on purpose.
#
# The papers used servers on the protocols' usual ports; whether other ports
# are inspected is not reported, so only 21 and 25 are looked at.
#
# To test:
#   curl ftp://ftp.example.org/ultrasurf.zip              (reset)
#   curl ftp://ftp.example.org/readme.txt                 (works)
#   swaks --server mail.example.org --to xiazai@upup.info (reset)
#
# Return values used: "reset"

from rust import regex

FTP_KEYWORD = regex(r"(?i)ultrasurf")
SMTP_ADDRESS = regex(r"(?i)^(MAIL FROM|RCPT TO):[^\r\n]*xiazai@upup\.info")


def process(packet):
    tcp = packet.tcp
    if not tcp or not packet.payload:
        return
    if tcp.dst == 21 and FTP_KEYWORD.is_match(packet.payload):
        return "reset"
    if tcp.dst == 25 and SMTP_ADDRESS.is_match(packet.payload):
        return "reset"
