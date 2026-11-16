//! Strict, self-contained DNS message recognizer (RFC 1035, RFC 3597, RFC 6891).
//!
//! The whole message is recognized before anything is handed to a censor program:
//! header, question section, and every resource record in the answer, authority and
//! additional sections. Anything outside the grammar below is rejected; anything
//! inside it is represented, including record types and classes that this module
//! does not know (RFC 3597). In particular, an unrecognized QTYPE such as HTTPS (65)
//! or SVCB (64) is never a parse failure, so it cannot be used to slip a query past
//! a censor that fails open on parse errors.
//!
//! Grammar enforced for domain names:
//! * a label length byte is `00xxxxxx` (1..=63 bytes of label, any octets) or the root
//!   `0x00`; the extended label types `01`/`10` are rejected;
//! * a compression pointer `11xxxxxx xxxxxxxx` must target an offset past the header
//!   and strictly before the start of the label run that contains it, and must land on
//!   an ordinary non-empty label. Run starts therefore strictly decrease and every hop
//!   consumes at least one label, so decompression terminates in a bounded number of
//!   steps by construction;
//! * the decoded name is at most 255 octets in wire form.
//!
//! Bytes after the last section are not interpreted but are counted in
//! [`Message::trailing_len`], so a script can decide what to do about them.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Size of the fixed DNS header.
pub const HEADER_LEN: usize = 12;
/// Maximum length of a domain name in wire form, including length bytes and root.
pub const MAX_NAME_WIRE_LEN: usize = 255;
/// Maximum length of a single label.
pub const MAX_LABEL_LEN: usize = 63;
/// TYPE value of the EDNS(0) OPT pseudo-RR.
pub const TYPE_OPT: u16 = 41;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("DNS message truncated")]
    Truncated,
    #[error("unsupported DNS label type byte {0:#04x}")]
    BadLabelType(u8),
    #[error("DNS name exceeds {MAX_NAME_WIRE_LEN} octets")]
    NameTooLong,
    #[error("DNS compression pointer at offset {at} to {target} is not strictly backward")]
    PointerNotBackward { at: usize, target: usize },
    #[error("DNS compression pointer at offset {at} targets the header")]
    PointerIntoHeader { at: usize },
    #[error("DNS compression pointer at offset {at} does not target a label")]
    PointerToNonLabel { at: usize },
    #[error("malformed RDATA for record type {rtype}")]
    BadRdata { rtype: u16 },
    #[error("OPT record outside the additional section, with a non-root owner, or repeated")]
    BadOpt,
    #[error("DNS-over-TCP length prefix exceeds available data")]
    TcpFrameTruncated,
}

/// Fixed DNS header (RFC 1035 4.1.1, RFC 2535 AD/CD bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    /// QR bit clear
    pub query: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub response_code: u8,
    pub questions: u16,
    pub answers: u16,
    pub nameservers: u16,
    pub additional: u16,
}

impl Header {
    fn parse(data: &[u8]) -> Result<Self, DnsError> {
        if data.len() < HEADER_LEN {
            return Err(DnsError::Truncated);
        }
        let be = |i: usize| u16::from_be_bytes([data[i], data[i + 1]]);
        let flags = be(2);
        Ok(Header {
            id: be(0),
            query: flags & 0x8000 == 0,
            opcode: ((flags >> 11) & 0x0F) as u8,
            authoritative: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            z: flags & 0x0040 != 0,
            authenticated_data: flags & 0x0020 != 0,
            checking_disabled: flags & 0x0010 != 0,
            response_code: (flags & 0x000F) as u8,
            questions: be(4),
            answers: be(6),
            nameservers: be(8),
            additional: be(10),
        })
    }
}

/// A decompressed domain name: its labels, in order, without the root label.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }
}

/// Presentation format (RFC 1035 5.1) without the trailing dot: labels joined by `.`,
/// with `.` and `\` inside a label escaped by a backslash and octets outside the
/// printable ASCII range written as `\DDD`. This is injective, so a label containing a
/// literal dot can not masquerade as two labels. The root name renders as `""`.
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, label) in self.labels.iter().enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }
            for &b in label {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", b as char)?,
                    0x21..=0x7E => write!(f, "{}", b as char)?,
                    _ => write!(f, "\\{:03}", b)?,
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: Name,
    pub qtype: u16,
    /// Raw QCLASS field, including the mDNS unicast-response bit.
    pub qclass: u16,
}

impl Question {
    /// mDNS "QU" bit (top bit of QCLASS).
    pub fn prefer_unicast(&self) -> bool {
        self.qclass & 0x8000 != 0
    }
    /// QCLASS with the mDNS bit masked off.
    pub fn qclass_value(&self) -> u16 {
        self.qclass & 0x7FFF
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: Name,
    pub rtype: u16,
    /// Raw CLASS field, including the mDNS cache-flush bit.
    pub class: u16,
    /// Raw TTL field.
    pub ttl: u32,
    pub data: RData,
}

impl ResourceRecord {
    /// mDNS cache-flush bit (top bit of CLASS).
    pub fn multicast_unique(&self) -> bool {
        self.class & 0x8000 != 0
    }
    pub fn class_value(&self) -> u16 {
        self.class & 0x7FFF
    }
    /// TTL with values above 2^31-1 treated as zero (RFC 2181 8).
    pub fn ttl_clamped(&self) -> u32 {
        if self.ttl > i32::MAX as u32 {
            0
        } else {
            self.ttl
        }
    }
}

/// Record data. Types not decoded here are kept as opaque octets (RFC 3597).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(Name),
    NS(Name),
    PTR(Name),
    MX {
        preference: u16,
        exchange: Name,
    },
    SOA {
        primary_ns: Name,
        mailbox: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum_ttl: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    TXT(Vec<Vec<u8>>),
    Unknown(Vec<u8>),
}

/// EDNS(0) OPT pseudo-RR (RFC 6891 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
    /// (OPTION-CODE, OPTION-DATA) pairs, in order.
    pub options: Vec<(u16, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub nameservers: Vec<ResourceRecord>,
    /// Additional section, excluding the OPT pseudo-RR.
    pub additional: Vec<ResourceRecord>,
    pub opt: Option<Opt>,
    /// Offset just past the first question, if any.
    pub first_question_end: Option<usize>,
    /// Number of bytes after the last section.
    pub trailing_len: usize,
}

/// Bounds-checked big-endian reader over `data[..limit]`.
fn read_u16(data: &[u8], pos: usize, limit: usize) -> Result<u16, DnsError> {
    if pos.checked_add(2).is_none_or(|e| e > limit) {
        return Err(DnsError::Truncated);
    }
    Ok(u16::from_be_bytes([data[pos], data[pos + 1]]))
}

fn read_u32(data: &[u8], pos: usize, limit: usize) -> Result<u32, DnsError> {
    if pos.checked_add(4).is_none_or(|e| e > limit) {
        return Err(DnsError::Truncated);
    }
    Ok(u32::from_be_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
    ]))
}

/// Parse a (possibly compressed) name starting at `start`. Uncompressed bytes of the
/// name must lie before `limit`. Returns the name and the offset just past its
/// in-place encoding.
fn parse_name(msg: &[u8], start: usize, limit: usize) -> Result<(Name, usize), DnsError> {
    let mut labels = Vec::new();
    let mut pos = start;
    // Region [run_start, limit) currently being read
    let mut run_start = start;
    let mut limit = limit;
    let mut end = None;
    let mut wire_len = 0usize;
    let mut just_jumped = false;
    loop {
        if pos >= limit {
            return Err(DnsError::Truncated);
        }
        let b = msg[pos];
        match b >> 6 {
            0b00 => {
                if b == 0 {
                    if just_jumped {
                        return Err(DnsError::PointerToNonLabel { at: pos });
                    }
                    // Root label; wire_len + 1 <= 255 is maintained below
                    let end = end.unwrap_or(pos + 1);
                    return Ok((Name { labels }, end));
                }
                let len = b as usize;
                debug_assert!(len <= MAX_LABEL_LEN);
                let label_end = pos + 1 + len;
                if label_end > limit {
                    return Err(DnsError::Truncated);
                }
                wire_len += 1 + len;
                // Reserve one octet for the root label
                if wire_len + 1 > MAX_NAME_WIRE_LEN {
                    return Err(DnsError::NameTooLong);
                }
                labels.push(msg[pos + 1..label_end].to_vec());
                pos = label_end;
                just_jumped = false;
            }
            0b11 => {
                if just_jumped {
                    return Err(DnsError::PointerToNonLabel { at: pos });
                }
                let target = (read_u16(msg, pos, limit)? & 0x3FFF) as usize;
                if target < HEADER_LEN {
                    return Err(DnsError::PointerIntoHeader { at: pos });
                }
                if target >= run_start {
                    return Err(DnsError::PointerNotBackward { at: pos, target });
                }
                if end.is_none() {
                    end = Some(pos + 2);
                }
                limit = run_start;
                run_start = target;
                pos = target;
                just_jumped = true;
            }
            _ => return Err(DnsError::BadLabelType(b)),
        }
    }
}

/// Parse a name that must exactly fill `msg[start..end]` (in place).
fn parse_name_exact(msg: &[u8], start: usize, end: usize, rtype: u16) -> Result<Name, DnsError> {
    let (name, after) = parse_name(msg, start, end)?;
    if after != end {
        return Err(DnsError::BadRdata { rtype });
    }
    Ok(name)
}

impl RData {
    fn parse(rtype: u16, msg: &[u8], start: usize, end: usize) -> Result<RData, DnsError> {
        let rd = &msg[start..end];
        let bad = || DnsError::BadRdata { rtype };
        Ok(match rtype {
            1 => RData::A(Ipv4Addr::from(<[u8; 4]>::try_from(rd).map_err(|_| bad())?)),
            28 => RData::AAAA(Ipv6Addr::from(
                <[u8; 16]>::try_from(rd).map_err(|_| bad())?,
            )),
            2 => RData::NS(parse_name_exact(msg, start, end, rtype)?),
            5 => RData::CNAME(parse_name_exact(msg, start, end, rtype)?),
            12 => RData::PTR(parse_name_exact(msg, start, end, rtype)?),
            15 => RData::MX {
                preference: read_u16(msg, start, end).map_err(|_| bad())?,
                exchange: parse_name_exact(msg, start + 2, end, rtype)?,
            },
            6 => {
                let (primary_ns, p) = parse_name(msg, start, end)?;
                let (mailbox, p) = parse_name(msg, p, end)?;
                if end - p != 20 {
                    return Err(bad());
                }
                RData::SOA {
                    primary_ns,
                    mailbox,
                    serial: read_u32(msg, p, end)?,
                    refresh: read_u32(msg, p + 4, end)?,
                    retry: read_u32(msg, p + 8, end)?,
                    expire: read_u32(msg, p + 12, end)?,
                    minimum_ttl: read_u32(msg, p + 16, end)?,
                }
            }
            33 => RData::SRV {
                priority: read_u16(msg, start, end).map_err(|_| bad())?,
                weight: read_u16(msg, start + 2, end).map_err(|_| bad())?,
                port: read_u16(msg, start + 4, end).map_err(|_| bad())?,
                target: parse_name_exact(msg, start + 6, end, rtype)?,
            },
            16 => {
                let mut strings = Vec::new();
                let mut rest = rd;
                while let Some((&len, tail)) = rest.split_first() {
                    let len = len as usize;
                    if tail.len() < len {
                        return Err(bad());
                    }
                    strings.push(tail[..len].to_vec());
                    rest = &tail[len..];
                }
                RData::TXT(strings)
            }
            _ => RData::Unknown(rd.to_vec()),
        })
    }
}

/// Fixed part of a resource record following its owner name.
struct RrFixed {
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata_start: usize,
    rdata_end: usize,
}

fn parse_rr_fixed(msg: &[u8], pos: usize) -> Result<RrFixed, DnsError> {
    let rtype = read_u16(msg, pos, msg.len())?;
    let class = read_u16(msg, pos + 2, msg.len())?;
    let ttl = read_u32(msg, pos + 4, msg.len())?;
    let rdlen = read_u16(msg, pos + 8, msg.len())? as usize;
    let rdata_start = pos + 10;
    let rdata_end = rdata_start + rdlen;
    if rdata_end > msg.len() {
        return Err(DnsError::Truncated);
    }
    Ok(RrFixed {
        rtype,
        class,
        ttl,
        rdata_start,
        rdata_end,
    })
}

fn parse_opt_options(rd: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, DnsError> {
    let mut options = Vec::new();
    let mut pos = 0;
    while pos < rd.len() {
        let bad = |_| DnsError::BadRdata { rtype: TYPE_OPT };
        let code = read_u16(rd, pos, rd.len()).map_err(bad)?;
        let len = read_u16(rd, pos + 2, rd.len()).map_err(bad)? as usize;
        let data_start = pos + 4;
        if data_start + len > rd.len() {
            return Err(DnsError::BadRdata { rtype: TYPE_OPT });
        }
        options.push((code, rd[data_start..data_start + len].to_vec()));
        pos = data_start + len;
    }
    Ok(options)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

/// Parse a full DNS message (as carried in a UDP payload).
pub fn parse_dns(msg: &[u8]) -> Result<Message, DnsError> {
    let header = Header::parse(msg)?;
    let mut pos = HEADER_LEN;

    // Counts are untrusted, so vectors grow only as records are actually parsed
    let mut questions = Vec::new();
    let mut first_question_end = None;
    for _ in 0..header.questions {
        let (qname, p) = parse_name(msg, pos, msg.len())?;
        let qtype = read_u16(msg, p, msg.len())?;
        let qclass = read_u16(msg, p + 2, msg.len())?;
        pos = p + 4;
        first_question_end.get_or_insert(pos);
        questions.push(Question {
            qname,
            qtype,
            qclass,
        });
    }

    let mut answers = Vec::new();
    let mut nameservers = Vec::new();
    let mut additional = Vec::new();
    let mut opt = None;
    let sections = [
        (Section::Answer, header.answers),
        (Section::Authority, header.nameservers),
        (Section::Additional, header.additional),
    ];
    for (section, count) in sections {
        for _ in 0..count {
            let (name, p) = parse_name(msg, pos, msg.len())?;
            let fixed = parse_rr_fixed(msg, p)?;
            pos = fixed.rdata_end;
            if fixed.rtype == TYPE_OPT {
                if section != Section::Additional || !name.labels.is_empty() || opt.is_some() {
                    return Err(DnsError::BadOpt);
                }
                let [extended_rcode, version, f0, f1] = fixed.ttl.to_be_bytes();
                opt = Some(Opt {
                    udp_payload_size: fixed.class,
                    extended_rcode,
                    version,
                    flags: u16::from_be_bytes([f0, f1]),
                    options: parse_opt_options(&msg[fixed.rdata_start..fixed.rdata_end])?,
                });
                continue;
            }
            let rr = ResourceRecord {
                name,
                rtype: fixed.rtype,
                class: fixed.class,
                ttl: fixed.ttl,
                data: RData::parse(fixed.rtype, msg, fixed.rdata_start, fixed.rdata_end)?,
            };
            match section {
                Section::Answer => answers.push(rr),
                Section::Authority => nameservers.push(rr),
                Section::Additional => additional.push(rr),
            }
        }
    }

    Ok(Message {
        header,
        questions,
        answers,
        nameservers,
        additional,
        opt,
        first_question_end,
        trailing_len: msg.len() - pos,
    })
}

/// Parse a DNS-over-TCP payload (RFC 1035 4.2.2, RFC 7766): one or more messages,
/// each preceded by a two-octet length. The payload must consist of complete frames.
pub fn parse_dns_tcp(data: &[u8]) -> Result<Vec<Message>, DnsError> {
    if data.is_empty() {
        return Err(DnsError::Truncated);
    }
    let mut messages = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = read_u16(data, pos, data.len()).map_err(|_| DnsError::TcpFrameTruncated)? as usize;
        let start = pos + 2;
        let end = start + len;
        if end > data.len() {
            return Err(DnsError::TcpFrameTruncated);
        }
        messages.push(parse_dns(&data[start..end])?);
        pos = end;
    }
    Ok(messages)
}

/// Mnemonic for a TYPE/QTYPE value. Names used by earlier CensorLab versions are
/// kept as-is (e.g. `All` for 255); unassigned values use the RFC 3597 `TYPEnnn` form.
pub fn type_name(code: u16) -> String {
    let name = match code {
        1 => "A",
        2 => "NS",
        3 => "MD",
        4 => "MF",
        5 => "CNAME",
        6 => "SOA",
        7 => "MB",
        8 => "MG",
        9 => "MR",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        14 => "MINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        52 => "TLSA",
        64 => "SVCB",
        65 => "HTTPS",
        251 => "IXFR",
        252 => "AXFR",
        253 => "MAILB",
        254 => "MAILA",
        255 => "All",
        257 => "CAA",
        _ => return format!("TYPE{code}"),
    };
    name.to_owned()
}

/// Mnemonic for a CLASS/QCLASS value (without the mDNS top bit).
pub fn class_name(code: u16) -> String {
    let name = match code {
        1 => "IN",
        2 => "CS",
        3 => "CH",
        4 => "HS",
        254 => "NONE",
        255 => "Any",
        _ => return format!("CLASS{code}"),
    };
    name.to_owned()
}

/// Opcode as named by earlier CensorLab versions.
pub fn opcode_name(code: u8) -> String {
    match code {
        0 => "StandardQuery".to_owned(),
        1 => "InverseQuery".to_owned(),
        2 => "ServerStatusRequest".to_owned(),
        x => format!("Reserved({x})"),
    }
}

/// RCODE as named by earlier CensorLab versions.
pub fn rcode_name(code: u8) -> String {
    match code {
        0 => "NoError".to_owned(),
        1 => "FormatError".to_owned(),
        2 => "ServerFailure".to_owned(),
        3 => "NameError".to_owned(),
        4 => "NotImplemented".to_owned(),
        5 => "Refused".to_owned(),
        x => format!("Reserved({x})"),
    }
}

/// Craft a DNS response from a query, injecting an A record answer with the given IP.
///
/// The query is fully parsed first. The response copies the query ID and its first
/// question, sets QR=1, RD=1, RA=1, RCODE=0, and carries a single A record whose
/// owner is a compression pointer (0xC00C) to the question name at offset 12.
pub fn craft_dns_response(
    query_bytes: &[u8],
    answer_ip: Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, CraftDnsError> {
    if query_bytes.len() < HEADER_LEN {
        return Err(CraftDnsError::QueryTooShort);
    }
    let parsed = parse_dns(query_bytes).map_err(CraftDnsError::Parse)?;
    let question_end = parsed.first_question_end.ok_or(CraftDnsError::NoQuestions)?;
    let mut resp = Vec::with_capacity(question_end + 16);
    resp.extend_from_slice(&query_bytes[..2]); // ID
    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
    resp.extend_from_slice(&[0x81, 0x80]);
    // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    // First question, verbatim. Compression pointers in it would have to target the
    // header and are rejected by the parser, so the copy is self-contained.
    resp.extend_from_slice(&query_bytes[HEADER_LEN..question_end]);
    // Answer: owner = pointer to offset 12, TYPE A, CLASS IN, TTL, RDLENGTH 4, RDATA
    resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x04]);
    resp.extend_from_slice(&answer_ip.octets());
    Ok(resp)
}

#[derive(Debug, thiserror::Error)]
pub enum CraftDnsError {
    #[error("DNS query too short (< 12 bytes)")]
    QueryTooShort,
    #[error("Failed to parse DNS query: {0}")]
    Parse(DnsError),
    #[error("DNS query has no questions")]
    NoQuestions,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header with the given counts (ID 0x1234, RD=1).
    fn header(qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00];
        for c in [qd, an, ns, ar] {
            v.extend_from_slice(&c.to_be_bytes());
        }
        v
    }

    fn name(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for label in s.split('.').filter(|l| !l.is_empty()) {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v
    }

    fn query(qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut v = header(1, 0, 0, 0);
        v.extend(name(qname));
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&qclass.to_be_bytes());
        v
    }

    fn rr(owner: &[u8], rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut v = owner.to_vec();
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&class.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    #[test]
    fn parse_valid_dns_query() {
        let packet = parse_dns(&query("example.com", 1, 1)).unwrap();
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.query);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qname.to_string(), "example.com");
        assert_eq!(packet.questions[0].qtype, 1);
        assert_eq!(packet.trailing_len, 0);
    }

    #[test]
    fn parse_invalid_dns_data() {
        assert_eq!(parse_dns(&[0x00, 0x01, 0x02]), Err(DnsError::Truncated));
        assert_eq!(parse_dns(&[]), Err(DnsError::Truncated));
    }

    #[test]
    fn https_and_svcb_queries_parse() {
        for (qtype, mnemonic) in [(65, "HTTPS"), (64, "SVCB")] {
            let packet = parse_dns(&query("www.google.com", qtype, 1)).unwrap();
            assert_eq!(packet.questions[0].qname.to_string(), "www.google.com");
            assert_eq!(packet.questions[0].qtype, qtype);
            assert_eq!(type_name(packet.questions[0].qtype), mnemonic);
        }
    }

    #[test]
    fn unknown_qtype_and_qclass_are_represented() {
        let packet = parse_dns(&query("example.com", 0xFF00, 0x1234)).unwrap();
        let q = &packet.questions[0];
        assert_eq!(q.qtype, 0xFF00);
        assert_eq!(type_name(q.qtype), "TYPE65280");
        assert_eq!(class_name(q.qclass_value()), "CLASS4660");
        assert!(!q.prefer_unicast());
    }

    #[test]
    fn edns_opt_is_parsed_out_of_additional() {
        let mut msg = query("example.com", 65, 1);
        msg[11] = 1; // ARCOUNT
        // OPT: UDP 1232, ext-rcode 0, version 0, DO bit, one cookie option
        let cookie = [0x00, 0x0A, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
        msg.extend(rr(&[0], TYPE_OPT, 1232, 0x0000_8000, &cookie));
        let packet = parse_dns(&msg).unwrap();
        assert!(packet.additional.is_empty());
        let opt = packet.opt.unwrap();
        assert_eq!(opt.udp_payload_size, 1232);
        assert_eq!(opt.version, 0);
        assert_eq!(opt.flags, 0x8000);
        assert_eq!(opt.options, vec![(10, vec![1, 2, 3, 4, 5, 6, 7, 8])]);
    }

    #[test]
    fn misplaced_or_duplicate_opt_rejected() {
        // OPT in the answer section
        let mut msg = header(0, 1, 0, 0);
        msg.extend(rr(&[0], TYPE_OPT, 1232, 0, &[]));
        assert_eq!(parse_dns(&msg), Err(DnsError::BadOpt));
        // Two OPT records
        let mut msg = header(0, 0, 0, 2);
        msg.extend(rr(&[0], TYPE_OPT, 1232, 0, &[]));
        msg.extend(rr(&[0], TYPE_OPT, 1232, 0, &[]));
        assert_eq!(parse_dns(&msg), Err(DnsError::BadOpt));
        // Non-root owner
        let mut msg = header(0, 0, 0, 1);
        msg.extend(rr(&name("a"), TYPE_OPT, 1232, 0, &[]));
        assert_eq!(parse_dns(&msg), Err(DnsError::BadOpt));
        // Option overruns RDATA
        let mut msg = header(0, 0, 0, 1);
        msg.extend(rr(&[0], TYPE_OPT, 1232, 0, &[0, 10, 0, 9, 1]));
        assert_eq!(parse_dns(&msg), Err(DnsError::BadRdata { rtype: TYPE_OPT }));
    }

    #[test]
    fn response_with_compression_and_unknown_rr_types() {
        let mut msg = header(1, 3, 0, 0);
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg.extend(name("www.example.com"));
        msg.extend_from_slice(&[0, 65, 0, 1]);
        // HTTPS answer (opaque RDATA), owner = pointer to question name
        msg.extend(rr(&[0xC0, 12], 65, 1, 300, &[0, 1, 0]));
        // CNAME answer, target = "cdn" + pointer to "example.com" (offset 16)
        msg.extend(rr(&[0xC0, 12], 5, 1, 300, &[3, b'c', b'd', b'n', 0xC0, 16]));
        // A answer
        msg.extend(rr(&[0xC0, 12], 1, 1, 0x8000_0000, &[93, 184, 216, 34]));
        let packet = parse_dns(&msg).unwrap();
        assert!(!packet.header.query);
        assert_eq!(packet.answers.len(), 3);
        assert_eq!(packet.answers[0].name.to_string(), "www.example.com");
        assert_eq!(packet.answers[0].rtype, 65);
        assert_eq!(packet.answers[0].data, RData::Unknown(vec![0, 1, 0]));
        match &packet.answers[1].data {
            RData::CNAME(n) => assert_eq!(n.to_string(), "cdn.example.com"),
            other => panic!("expected CNAME, got {other:?}"),
        }
        assert_eq!(packet.answers[2].data, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(packet.answers[2].ttl_clamped(), 0);
    }

    #[test]
    fn known_type_with_bad_rdata_rejected() {
        let mut msg = header(0, 1, 0, 0);
        msg.extend(rr(&[0], 1, 1, 0, &[1, 2, 3]));
        assert_eq!(parse_dns(&msg), Err(DnsError::BadRdata { rtype: 1 }));
        // CNAME whose name does not fill RDATA exactly
        let mut msg = header(0, 1, 0, 0);
        let mut rd = name("a");
        rd.push(0xFF);
        msg.extend(rr(&[0], 5, 1, 0, &rd));
        assert_eq!(parse_dns(&msg), Err(DnsError::BadRdata { rtype: 5 }));
    }

    #[test]
    fn compression_pointer_loop_rejected() {
        // Question name is a pointer to itself
        let mut msg = header(1, 0, 0, 0);
        msg.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert_eq!(
            parse_dns(&msg),
            Err(DnsError::PointerNotBackward { at: 12, target: 12 })
        );
        // Answer: label then pointer back to its own start (a -> a -> ...)
        let mut msg = header(1, 1, 0, 0);
        msg.extend(name("x"));
        msg.extend_from_slice(&[0, 1, 0, 1]);
        let owner_at = msg.len();
        msg.extend(rr(&[1, b'a', 0xC0, owner_at as u8], 1, 1, 0, &[1, 2, 3, 4]));
        assert_eq!(
            parse_dns(&msg),
            Err(DnsError::PointerNotBackward { at: owner_at + 2, target: owner_at })
        );
        // Closing a cycle between two names needs a forward pointer somewhere
        let mut msg = header(1, 1, 0, 0);
        msg.extend(name("x")); // 12..15
        msg.extend_from_slice(&[0, 1, 0, 1]); // 15..19
        msg.extend(rr(&[1, b'b', 0xC0, 30], 1, 1, 0, &[1, 2, 3, 4]));
        assert!(matches!(
            parse_dns(&msg),
            Err(DnsError::PointerNotBackward { .. })
        ));
    }

    #[test]
    fn forward_pointer_rejected() {
        // Question name points forward into the (later) answer section
        let mut msg = header(1, 1, 0, 0);
        msg.extend_from_slice(&[0xC0, 18, 0, 1, 0, 1]);
        msg.extend(rr(&name("a"), 1, 1, 0, &[1, 2, 3, 4]));
        assert_eq!(
            parse_dns(&msg),
            Err(DnsError::PointerNotBackward { at: 12, target: 18 })
        );
    }

    #[test]
    fn pointer_into_header_or_to_pointer_rejected() {
        let mut msg = header(1, 0, 0, 0);
        msg.extend_from_slice(&[0xC0, 4, 0, 1, 0, 1]);
        assert_eq!(parse_dns(&msg), Err(DnsError::PointerIntoHeader { at: 12 }));
        // Pointer chain: question "a" at 12, answer owner at 19 = ptr->12 is fine,
        // but a second answer whose owner points at that pointer is rejected.
        let mut msg = header(1, 2, 0, 0);
        msg.extend(name("a")); // 12..15
        msg.extend_from_slice(&[0, 1, 0, 1]); // ..19
        msg.extend(rr(&[0xC0, 12], 1, 1, 0, &[1, 2, 3, 4])); // owner at 19
        msg.extend(rr(&[0xC0, 19], 1, 1, 0, &[1, 2, 3, 4]));
        assert_eq!(parse_dns(&msg), Err(DnsError::PointerToNonLabel { at: 19 }));
    }

    #[test]
    fn truncated_messages_rejected() {
        let full = query("www.example.com", 65, 1);
        for len in 0..full.len() {
            assert_eq!(
                parse_dns(&full[..len]),
                Err(DnsError::Truncated),
                "prefix of length {len}"
            );
        }
        // Answer with RDLENGTH past the end
        let mut msg = header(0, 1, 0, 0);
        msg.extend(rr(&[0], 1, 1, 0, &[1, 2, 3, 4]));
        msg.pop();
        assert_eq!(parse_dns(&msg), Err(DnsError::Truncated));
        // QDCOUNT larger than the questions present
        let mut msg = query("a", 1, 1);
        msg[5] = 2;
        assert_eq!(parse_dns(&msg), Err(DnsError::Truncated));
    }

    #[test]
    fn overlong_names_rejected() {
        // 4 labels of 63 = 256 wire octets + root = 257 > 255
        let label = "a".repeat(63);
        let long = [label.as_str(); 4].join(".");
        assert_eq!(parse_dns(&query(&long, 1, 1)), Err(DnsError::NameTooLong));
        // 3 x 63 + 1 x 61 = 64*3 + 62 + 1 root = 255 exactly: accepted
        let ok = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        let packet = parse_dns(&query(&ok, 1, 1)).unwrap();
        assert_eq!(packet.questions[0].qname.labels().len(), 4);
        // One more octet is too long
        let too_long = format!("{label}.{label}.{label}.{}", "a".repeat(62));
        assert_eq!(parse_dns(&query(&too_long, 1, 1)), Err(DnsError::NameTooLong));
        // Overlong via compression: a suffix that is itself near the limit
        let mut msg = header(1, 1, 0, 0);
        msg.extend(name(&ok));
        msg.extend_from_slice(&[0, 1, 0, 1]);
        msg.extend(rr(&[1, b'x', 0xC0, 12], 1, 1, 0, &[1, 2, 3, 4]));
        assert_eq!(parse_dns(&msg), Err(DnsError::NameTooLong));
    }

    #[test]
    fn labels_longer_than_63_rejected() {
        // 0x40 and 0x80 prefixes are extended/reserved label types
        for b in [0x40u8, 0x7F, 0x80, 0xBF] {
            let mut msg = header(1, 0, 0, 0);
            msg.push(b);
            msg.extend(std::iter::repeat_n(b'a', b as usize & 0x3F));
            msg.extend_from_slice(&[0, 0, 1, 0, 1]);
            assert_eq!(parse_dns(&msg), Err(DnsError::BadLabelType(b)));
        }
    }

    #[test]
    fn name_presentation_is_injective() {
        let mut msg = header(1, 0, 0, 0);
        msg.extend_from_slice(&[6, b'g', b'o', b'.', b'o', b'\\', 0xFF, 3, b'c', b'o', b'm', 0]);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        let packet = parse_dns(&msg).unwrap();
        assert_eq!(packet.questions[0].qname.to_string(), "go\\.o\\\\\\255.com");
        assert_eq!(packet.questions[0].qname.labels()[0], b"go.o\\\xFF".to_vec());
    }

    #[test]
    fn trailing_bytes_counted() {
        let mut msg = query("example.com", 1, 1);
        msg.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(parse_dns(&msg).unwrap().trailing_len, 2);
    }

    #[test]
    fn tcp_framing() {
        let q1 = query("example.com", 65, 1);
        let q2 = query("example.org", 1, 1);
        let mut data = Vec::new();
        for q in [&q1, &q2] {
            data.extend_from_slice(&(q.len() as u16).to_be_bytes());
            data.extend_from_slice(q);
        }
        let messages = parse_dns_tcp(&data).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].questions[0].qtype, 65);
        assert_eq!(messages[1].questions[0].qname.to_string(), "example.org");
        // Partial frame
        assert_eq!(
            parse_dns_tcp(&data[..data.len() - 1]),
            Err(DnsError::TcpFrameTruncated)
        );
        assert_eq!(parse_dns_tcp(&data[..1]), Err(DnsError::TcpFrameTruncated));
        assert_eq!(parse_dns_tcp(&[]), Err(DnsError::Truncated));
        // Frame contents must themselves be a valid message
        assert_eq!(parse_dns_tcp(&[0, 3, 1, 2, 3]), Err(DnsError::Truncated));
    }

    #[test]
    fn craft_response_for_https_query() {
        let q = query("www.google.com", 65, 1);
        let resp = craft_dns_response(&q, Ipv4Addr::new(10, 10, 10, 10), 60).unwrap();
        let parsed = parse_dns(&resp).unwrap();
        assert!(!parsed.header.query);
        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.questions[0].qtype, 65);
        assert_eq!(parsed.answers[0].name.to_string(), "www.google.com");
        assert_eq!(parsed.answers[0].data, RData::A(Ipv4Addr::new(10, 10, 10, 10)));
        assert_eq!(parsed.answers[0].ttl, 60);
    }

    #[test]
    fn craft_response_rejects_bad_queries() {
        assert!(matches!(
            craft_dns_response(&[0; 4], Ipv4Addr::LOCALHOST, 1),
            Err(CraftDnsError::QueryTooShort)
        ));
        assert!(matches!(
            craft_dns_response(&header(0, 0, 0, 0), Ipv4Addr::LOCALHOST, 1),
            Err(CraftDnsError::NoQuestions)
        ));
        let mut q = query("a", 1, 1);
        q.pop();
        assert!(matches!(
            craft_dns_response(&q, Ipv4Addr::LOCALHOST, 1),
            Err(CraftDnsError::Parse(DnsError::Truncated))
        ));
    }
}
