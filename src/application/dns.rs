use dns_parser::Packet as DNSPacket;

/// Parse a buffer as DNS
pub fn parse_dns<'a>(data: &'a [u8]) -> Result<DNSPacket<'a>, dns_parser::Error> {
    DNSPacket::parse(data)
}

/// Craft a DNS response from a query, injecting an A record answer with the given IP.
///
/// Parses the query to extract the ID and question section, then constructs a minimal
/// DNS response with QR=1, RD=1, RA=1, RCODE=0 (no error), and a single A record answer.
///
/// The response uses a name pointer (0xC00C) to reference the question name at offset 12,
/// which is standard DNS compression.
pub fn craft_dns_response(
    query_bytes: &[u8],
    answer_ip: std::net::Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, CraftDnsError> {
    // Minimum DNS header is 12 bytes
    if query_bytes.len() < 12 {
        return Err(CraftDnsError::QueryTooShort);
    }
    // Parse just enough to validate and find the end of the question section
    let parsed = DNSPacket::parse(query_bytes).map_err(CraftDnsError::Parse)?;
    if parsed.questions.is_empty() {
        return Err(CraftDnsError::NoQuestions);
    }
    // Find the end of the question section by scanning labels after the 12-byte header
    let question_end = find_question_end(query_bytes)?;
    // Build the response
    let mut resp = Vec::with_capacity(question_end + 16); // question + answer
    // Copy DNS header (12 bytes)
    resp.extend_from_slice(&query_bytes[..2]); // ID
    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
    resp.push(0x81); // QR=1, RD=1
    resp.push(0x80); // RA=1
    // QDCOUNT = 1
    resp.push(0x00);
    resp.push(0x01);
    // ANCOUNT = 1
    resp.push(0x00);
    resp.push(0x01);
    // NSCOUNT = 0
    resp.push(0x00);
    resp.push(0x00);
    // ARCOUNT = 0
    resp.push(0x00);
    resp.push(0x00);
    // Copy question section verbatim (from byte 12 to question_end)
    resp.extend_from_slice(&query_bytes[12..question_end]);
    // Answer section: name pointer to question (offset 12 = 0x0C)
    resp.push(0xC0);
    resp.push(0x0C);
    // Type A (1)
    resp.push(0x00);
    resp.push(0x01);
    // Class IN (1)
    resp.push(0x00);
    resp.push(0x01);
    // TTL (4 bytes, big-endian)
    resp.extend_from_slice(&ttl.to_be_bytes());
    // RDLENGTH = 4 (IPv4)
    resp.push(0x00);
    resp.push(0x04);
    // RDATA = IPv4 address
    resp.extend_from_slice(&answer_ip.octets());
    Ok(resp)
}

/// Find the byte offset immediately after the first question section in a DNS packet.
fn find_question_end(data: &[u8]) -> Result<usize, CraftDnsError> {
    let mut pos = 12; // Start after DNS header
    // Walk through domain name labels
    loop {
        if pos >= data.len() {
            return Err(CraftDnsError::Truncated);
        }
        let label_len = data[pos] as usize;
        if label_len == 0 {
            pos += 1; // null terminator
            break;
        }
        // Check for compression pointer (top 2 bits set)
        if label_len & 0xC0 == 0xC0 {
            pos += 2; // pointer is 2 bytes
            break;
        }
        pos += 1 + label_len;
    }
    // After the name: QTYPE (2 bytes) + QCLASS (2 bytes)
    pos += 4;
    if pos > data.len() {
        return Err(CraftDnsError::Truncated);
    }
    Ok(pos)
}

#[derive(Debug, thiserror::Error)]
pub enum CraftDnsError {
    #[error("DNS query too short (< 12 bytes)")]
    QueryTooShort,
    #[error("Failed to parse DNS query: {0}")]
    Parse(dns_parser::Error),
    #[error("DNS query has no questions")]
    NoQuestions,
    #[error("DNS query truncated")]
    Truncated,
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
