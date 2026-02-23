use dns_parser::Packet as DNSPacket;

/// Parse a buffer as DNS
pub fn parse_dns<'a>(data: &'a [u8]) -> Result<DNSPacket<'a>, dns_parser::Error> {
    DNSPacket::parse(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_dns_query() {
        // DNS query for example.com, ID=0x1234, QR=0 (query), 1 question
        let dns_bytes: Vec<u8> = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query, recursion desired
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: example.com, type A, class IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,       // Root label
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];
        let packet = parse_dns(&dns_bytes).unwrap();
        assert_eq!(packet.header.id, 0x1234);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 0);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qname.to_string(), "example.com");
    }

    #[test]
    fn parse_invalid_dns_data() {
        let invalid_bytes: Vec<u8> = vec![0x00, 0x01, 0x02];
        let result = parse_dns(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_dns_data() {
        let empty: Vec<u8> = vec![];
        let result = parse_dns(&empty);
        assert!(result.is_err());
    }
}
