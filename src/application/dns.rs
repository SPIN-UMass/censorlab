use dns_parser::Packet as DNSPacket;

/// Parse a buffer as DNS
pub fn parse_dns(data: &[u8]) -> () {
    let packet = DNSPacket::parse(data);
    println!("{:?}", packet);
}
