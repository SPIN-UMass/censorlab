use dns_parser::Packet as DNSPacket;

/// Parse a buffer as DNS
pub fn parse_dns<'a>(data: &'a [u8]) -> Result<DNSPacket<'a>, dns_parser::Error> {
    DNSPacket::parse(data)
}
