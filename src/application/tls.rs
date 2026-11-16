use smoltcp::wire::IpAddress;
use thiserror::Error;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};

/// Errors that can occur when parsing a TLS ClientHello
#[derive(Debug, Error)]
pub enum TlsParseError {
    #[error("Data too short for TLS record")]
    TooShort,
    #[error("TLS record parse failed")]
    ParseFailed,
    #[error("Not a TLS Handshake record")]
    NotHandshake,
    #[error("Not a ClientHello message")]
    NotClientHello,
    #[error("No extensions in ClientHello")]
    NoExtensions,
    #[error("Failed to parse extensions")]
    ExtensionParseFailed,
    #[error("SNI is not valid UTF-8")]
    InvalidUtf8,
}

/// Information extracted from a TLS ClientHello
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    /// TLS version from the ClientHello (legacy: usually 0x0303 for TLS 1.2+)
    pub client_version: u16,
    /// Server Name Indication, if present
    pub sni: Option<String>,
    /// ALPN protocol names, if present
    pub alpn: Vec<String>,
    /// Supported TLS versions from the supported_versions extension
    pub supported_versions: Vec<u16>,
    /// Number of cipher suites offered
    pub cipher_suites_count: usize,
    /// Number of extensions present
    pub extensions_count: usize,
}

/// Parse a TLS ClientHello from a raw TCP payload (TLS record format).
///
/// Expects the data to begin with a TLS record header (content type + version + length).
pub fn parse_client_hello_record(data: &[u8]) -> Result<ClientHelloInfo, TlsParseError> {
    if data.len() < 5 {
        return Err(TlsParseError::TooShort);
    }

    let (_, plaintext) = parse_tls_plaintext(data).map_err(|_| TlsParseError::ParseFailed)?;

    for msg in &plaintext.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            return extract_info_from_client_hello(ch);
        }
    }

    Err(TlsParseError::NotClientHello)
}

/// Parse a TLS ClientHello handshake message (without the TLS record header).
///
/// This is the format found inside QUIC CRYPTO frames. The data should start
/// with the handshake type byte (0x01 for ClientHello).
pub fn parse_client_hello_message(data: &[u8]) -> Result<ClientHelloInfo, TlsParseError> {
    if data.len() < 4 {
        return Err(TlsParseError::TooShort);
    }

    // Wrap the handshake message in a TLS record header so tls-parser can parse it
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(22); // content type: Handshake
    record.extend_from_slice(&[0x03, 0x03]); // version: TLS 1.2
    record.push(((data.len() >> 8) & 0xff) as u8);
    record.push((data.len() & 0xff) as u8);
    record.extend_from_slice(data);

    parse_client_hello_record(&record)
}

/// Most bytes of client stream the assembler will buffer looking for a ClientHello.
///
/// A ClientHello can't exceed one maximum-size TLS record (2^14 bytes) when parsed, so this
/// leaves room for record headers if the client splits it across many small records.
pub const MAX_CLIENT_HELLO_STREAM: usize = 1 << 15;
/// Largest TLS record body allowed by RFC 8446 for plaintext records.
const MAX_RECORD_LEN: usize = 1 << 14;

/// A TCP endpoint
pub type Endpoint = (IpAddress, u16);

/// Reassembles the client's first TLS handshake message from TCP segments.
///
/// One of these lives on each TCP connection. It only ever buffers the start of the
/// client→server byte stream, bounded by [`MAX_CLIENT_HELLO_STREAM`], and frees the buffer as
/// soon as it has either found a ClientHello or decided the stream doesn't start with one.
///
/// Policies:
/// * The client is the sender of the first SYN (without ACK); the stream starts at ISN+1. If the
///   connection was picked up mid-stream (no SYN seen), the first payload-carrying packet anchors
///   the stream instead, which can't handle the first segment arriving out of order.
/// * Segments are placed by sequence number, so duplicates and out-of-order segments within the
///   window are handled.
/// * Where segments overlap with different contents, the first bytes received win.
/// * Later SYNs (e.g. with a different ISN) are ignored.
#[derive(Debug, Default)]
pub struct ClientHelloAssembler {
    state: AssemblerState,
}

#[derive(Debug, Default)]
enum AssemblerState {
    /// Haven't seen the start of the client stream yet
    #[default]
    AwaitStream,
    /// Buffering the client stream, whose first byte has sequence number `base`
    Buffering {
        client: Endpoint,
        base: u32,
        /// Bytes received so far, indexed by offset from `base`
        buf: Vec<u8>,
        /// Which bytes of `buf` have been received
        filled: Vec<bool>,
        /// Length of the contiguous received prefix of `buf`
        contiguous: usize,
        /// Don't rescan until the contiguous prefix is at least this long
        need: usize,
    },
    /// Finished: either the ClientHello, or None if the stream doesn't start with one
    Done(Option<ClientHelloInfo>),
}

impl ClientHelloAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a TCP segment from either direction of the connection
    pub fn observe(&mut self, src: Endpoint, seq: u32, syn: bool, ack: bool, payload: &[u8]) {
        match self.state {
            AssemblerState::AwaitStream => {
                // The SYN consumes one sequence number, so the stream starts after it
                let base = if syn && !ack {
                    seq.wrapping_add(1)
                } else if !syn && !payload.is_empty() {
                    seq
                } else {
                    return;
                };
                self.state = AssemblerState::Buffering {
                    client: src,
                    base,
                    buf: Vec::new(),
                    filled: Vec::new(),
                    contiguous: 0,
                    need: 1,
                };
                // Data on the SYN (TCP Fast Open) is part of the stream
                self.insert(base, payload);
            }
            AssemblerState::Buffering { client, .. } => {
                if src == client && !syn {
                    self.insert(seq, payload);
                }
            }
            AssemblerState::Done(_) => {}
        }
    }

    /// Place a client segment in the buffer and check whether the ClientHello is complete
    fn insert(&mut self, seq: u32, mut payload: &[u8]) {
        let AssemblerState::Buffering {
            base,
            buf,
            filled,
            contiguous,
            need,
            ..
        } = &mut self.state
        else {
            return;
        };
        let mut offset = seq.wrapping_sub(*base);
        // A segment starting before the stream (only possible when picked up mid-stream)
        // contributes whatever part of it lies after the start
        if offset > u32::MAX / 2 {
            let skip = offset.wrapping_neg() as usize;
            if skip >= payload.len() {
                return;
            }
            payload = &payload[skip..];
            offset = 0;
        }
        let offset = offset as usize;
        if payload.is_empty() {
            return;
        }
        // The client has sent more than a ClientHello could need, without completing one
        if offset >= MAX_CLIENT_HELLO_STREAM {
            self.state = AssemblerState::Done(None);
            return;
        }
        let end = (offset + payload.len()).min(MAX_CLIENT_HELLO_STREAM);
        if buf.len() < end {
            buf.resize(end, 0);
            filled.resize(end, false);
        }
        // First bytes received win
        for (i, byte) in (offset..end).zip(payload) {
            if !filled[i] {
                buf[i] = *byte;
                filled[i] = true;
            }
        }
        while *contiguous < filled.len() && filled[*contiguous] {
            *contiguous += 1;
        }
        if *contiguous < *need {
            return;
        }
        match scan_client_hello(&buf[..*contiguous]) {
            Scan::NeedMore(n) if n <= MAX_CLIENT_HELLO_STREAM => *need = n,
            Scan::NeedMore(_) | Scan::NotClientHello => self.state = AssemblerState::Done(None),
            Scan::Found(info) => self.state = AssemblerState::Done(Some(info)),
        }
    }

    /// The reassembled ClientHello, once found
    pub fn client_hello(&self) -> Option<&ClientHelloInfo> {
        match &self.state {
            AssemblerState::Done(info) => info.as_ref(),
            _ => None,
        }
    }

    /// Whether the assembler has stopped looking (found a ClientHello or gave up)
    pub fn is_done(&self) -> bool {
        matches!(self.state, AssemblerState::Done(_))
    }
}

/// Outcome of scanning the start of a client stream for a ClientHello
enum Scan {
    /// Not enough data yet; the stream must be at least this long before rescanning
    NeedMore(usize),
    /// The stream doesn't start with a well-formed ClientHello
    NotClientHello,
    Found(ClientHelloInfo),
}

/// Recognize a ClientHello at the start of a client stream, possibly split over several
/// handshake records
fn scan_client_hello(stream: &[u8]) -> Scan {
    let mut handshake = Vec::new();
    let mut pos = 0;
    loop {
        // Once the handshake header is in, we know how much handshake data to wait for
        if handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return Scan::NotClientHello;
            }
            let len = 4 + u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            // parse_client_hello_message re-wraps the message in a single record
            if len > MAX_RECORD_LEN {
                return Scan::NotClientHello;
            }
            if handshake.len() >= len {
                return match parse_client_hello_message(&handshake[..len]) {
                    Ok(info) => Scan::Found(info),
                    Err(_) => Scan::NotClientHello,
                };
            }
        }
        // Each handshake byte still missing needs at least one more stream byte
        let missing = if handshake.len() >= 4 {
            4 + u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize - handshake.len()
        } else {
            4 - handshake.len()
        };
        // The stream ends partway through the current record
        if pos > stream.len() {
            return Scan::NeedMore(stream.len() + missing);
        }
        // Validate whatever part of the next record header has arrived
        let header = &stream[pos..(pos + 5).min(stream.len())];
        if header.first().is_some_and(|t| *t != 0x16) || header.get(1).is_some_and(|v| *v != 0x03) {
            return Scan::NotClientHello;
        }
        if header.len() < 5 {
            return Scan::NeedMore((pos + 5).max(stream.len() + missing));
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len == 0 || record_len > MAX_RECORD_LEN {
            return Scan::NotClientHello;
        }
        let body = pos + 5;
        handshake.extend_from_slice(&stream[body..(body + record_len).min(stream.len())]);
        pos = body + record_len;
    }
}

/// Extract ClientHelloInfo from a parsed TlsClientHelloContents.
fn extract_info_from_client_hello(
    ch: &tls_parser::TlsClientHelloContents,
) -> Result<ClientHelloInfo, TlsParseError> {
    let client_version = ch.version.0;
    let cipher_suites_count = ch.ciphers.len();

    let mut sni = None;
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();
    let mut extensions_count = 0;

    if let Some(ext_data) = ch.ext {
        let (_, extensions) =
            parse_tls_client_hello_extensions(ext_data).map_err(|_| TlsParseError::ExtensionParseFailed)?;

        extensions_count = extensions.len();

        for ext in &extensions {
            match ext {
                TlsExtension::SNI(sni_list) => {
                    for (sni_type, name_bytes) in sni_list {
                        // SNIType 0 = HostName
                        if sni_type.0 == 0 {
                            sni = Some(
                                std::str::from_utf8(name_bytes)
                                    .map_err(|_| TlsParseError::InvalidUtf8)?
                                    .to_string(),
                            );
                        }
                    }
                }
                TlsExtension::ALPN(protocols) => {
                    for proto in protocols {
                        if let Ok(s) = std::str::from_utf8(proto) {
                            alpn.push(s.to_string());
                        }
                    }
                }
                TlsExtension::SupportedVersions(versions) => {
                    for v in versions {
                        supported_versions.push(v.0);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(ClientHelloInfo {
        client_version,
        sni,
        alpn,
        supported_versions,
        cipher_suites_count,
        extensions_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TLS ClientHello handshake message (no record header).
    fn build_client_hello_message(sni: Option<&str>, alpn: Option<&[&str]>) -> Vec<u8> {
        let mut extensions = Vec::new();

        // SNI extension
        if let Some(name) = sni {
            let sni_bytes = name.as_bytes();
            let sn_entry_len = 1 + 2 + sni_bytes.len();
            let sni_ext_data_len = 2 + sn_entry_len;

            extensions.extend_from_slice(&[0x00, 0x00]); // type: SNI
            extensions.push(((sni_ext_data_len >> 8) & 0xff) as u8);
            extensions.push((sni_ext_data_len & 0xff) as u8);
            extensions.push(((sn_entry_len >> 8) & 0xff) as u8);
            extensions.push((sn_entry_len & 0xff) as u8);
            extensions.push(0x00); // host_name type
            extensions.push(((sni_bytes.len() >> 8) & 0xff) as u8);
            extensions.push((sni_bytes.len() & 0xff) as u8);
            extensions.extend_from_slice(sni_bytes);
        }

        // ALPN extension
        if let Some(protocols) = alpn {
            let mut alpn_list = Vec::new();
            for proto in protocols {
                let pb = proto.as_bytes();
                alpn_list.push(pb.len() as u8);
                alpn_list.extend_from_slice(pb);
            }
            let alpn_data_len = 2 + alpn_list.len();
            extensions.extend_from_slice(&[0x00, 0x10]); // type: ALPN
            extensions.push(((alpn_data_len >> 8) & 0xff) as u8);
            extensions.push((alpn_data_len & 0xff) as u8);
            extensions.push(((alpn_list.len() >> 8) & 0xff) as u8);
            extensions.push((alpn_list.len() & 0xff) as u8);
            extensions.extend_from_slice(&alpn_list);
        }

        // supported_versions extension (TLS 1.3 + TLS 1.2)
        {
            let versions = [0x03, 0x04, 0x03, 0x03];
            let sv_data_len = 1 + versions.len();
            extensions.extend_from_slice(&[0x00, 0x2B]); // type: supported_versions
            extensions.push(((sv_data_len >> 8) & 0xff) as u8);
            extensions.push((sv_data_len & 0xff) as u8);
            extensions.push(versions.len() as u8);
            extensions.extend_from_slice(&versions);
        }

        let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions.len();
        let mut buf = Vec::new();

        buf.push(0x01); // ClientHello
        buf.push(((ch_body_len >> 16) & 0xff) as u8);
        buf.push(((ch_body_len >> 8) & 0xff) as u8);
        buf.push((ch_body_len & 0xff) as u8);
        buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x00); // session_id len
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        buf.extend_from_slice(&[0x01, 0x00]); // compression
        buf.push(((extensions.len() >> 8) & 0xff) as u8);
        buf.push((extensions.len() & 0xff) as u8);
        buf.extend_from_slice(&extensions);

        buf
    }

    /// Wrap a handshake message in a TLS record header.
    fn wrap_in_record(handshake: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(22); // Handshake
        buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        buf.push(((handshake.len() >> 8) & 0xff) as u8);
        buf.push((handshake.len() & 0xff) as u8);
        buf.extend_from_slice(handshake);
        buf
    }

    /// A ClientHello message about as large as one with a post-quantum key share,
    /// using a padding extension to stand in for X25519MLKEM768
    fn build_large_client_hello_message(sni: &str) -> Vec<u8> {
        let mut msg = build_client_hello_message(Some(sni), None);
        let pad = 1500;
        msg.extend_from_slice(&[0x00, 0x15, (pad >> 8) as u8, (pad & 0xff) as u8]);
        msg.extend(std::iter::repeat_n(0u8, pad));
        // Fix up the handshake length and extensions length
        let hs_len = msg.len() - 4;
        msg[1..4].copy_from_slice(&(hs_len as u32).to_be_bytes()[1..]);
        let ext_len = u16::from_be_bytes([msg[45], msg[46]]) as usize + 4 + pad;
        msg[45..47].copy_from_slice(&(ext_len as u16).to_be_bytes());
        msg
    }

    /// Split a handshake message across several TLS records of at most `chunk` bytes
    fn wrap_in_records(handshake: &[u8], chunk: usize) -> Vec<u8> {
        handshake.chunks(chunk).flat_map(wrap_in_record).collect()
    }

    const CLIENT: Endpoint = (IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)), 40000);
    const SERVER: Endpoint = (IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 2)), 443);
    const ISN: u32 = 1000;

    /// Assembler that has seen the client's SYN
    fn after_syn(isn: u32) -> ClientHelloAssembler {
        let mut asm = ClientHelloAssembler::new();
        asm.observe(CLIENT, isn, true, false, &[]);
        asm.observe(SERVER, 5000, true, true, &[]);
        asm
    }

    fn sni(asm: &ClientHelloAssembler) -> Option<&str> {
        asm.client_hello().and_then(|ch| ch.sni.as_deref())
    }

    #[test]
    fn assembler_single_segment() {
        let stream = wrap_in_record(&build_client_hello_message(Some("example.com"), None));
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream);
        assert_eq!(sni(&asm), Some("example.com"));
        assert!(asm.is_done());
    }

    #[test]
    fn assembler_split_across_segments() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        assert!(stream.len() > 1460);
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..1460]);
        assert_eq!(asm.client_hello().map(|_| ()), None);
        assert!(!asm.is_done());
        asm.observe(CLIENT, ISN + 1 + 1460, false, true, &stream[1460..]);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_ignores_server_data() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..1460]);
        asm.observe(SERVER, 5001, false, true, b"not part of the client stream");
        asm.observe(CLIENT, ISN + 1 + 1460, false, true, &stream[1460..]);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_duplicate_segment() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..1460]);
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..1460]);
        asm.observe(CLIENT, ISN + 1 + 1460, false, true, &stream[1460..]);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_out_of_order() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1 + 1460, false, true, &stream[1460..]);
        assert!(!asm.is_done());
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..1460]);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_tiny_segments() {
        let stream = wrap_in_record(&build_client_hello_message(Some("example.com"), None));
        let mut asm = after_syn(ISN);
        for (i, byte) in stream.iter().enumerate() {
            asm.observe(CLIENT, ISN + 1 + i as u32, false, true, std::slice::from_ref(byte));
        }
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_overlap_first_wins() {
        let stream = wrap_in_record(&build_client_hello_message(Some("example.com"), None));
        let sni_at = stream.windows(11).position(|w| w == b"example.com").unwrap();
        let split = sni_at + 4;
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..split]);
        // Retransmission overlapping the first segment, with different bytes in the overlap
        let mut second = stream[sni_at..].to_vec();
        second[..4].copy_from_slice(b"xxxx");
        asm.observe(CLIENT, ISN + 1 + sni_at as u32, false, true, &second);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_split_across_records() {
        let stream = wrap_in_records(&build_large_client_hello_message("example.com"), 100);
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_split_across_records_and_segments() {
        let stream = wrap_in_records(&build_large_client_hello_message("example.com"), 7);
        let mut asm = after_syn(ISN);
        for (i, chunk) in stream.chunks(500).enumerate() {
            asm.observe(CLIENT, ISN + 1 + (i * 500) as u32, false, true, chunk);
        }
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_seq_wraparound() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        let isn = u32::MAX - 100;
        let mut asm = after_syn(isn);
        asm.observe(CLIENT, isn.wrapping_add(1), false, true, &stream[..1460]);
        asm.observe(CLIENT, isn.wrapping_add(1 + 1460), false, true, &stream[1460..]);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_data_on_syn() {
        // TCP Fast Open: the ClientHello rides on the SYN
        let stream = wrap_in_record(&build_client_hello_message(Some("example.com"), None));
        let mut asm = ClientHelloAssembler::new();
        asm.observe(CLIENT, ISN, true, false, &stream);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_mid_stream_without_syn() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        let mut asm = ClientHelloAssembler::new();
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..1460]);
        asm.observe(CLIENT, ISN + 1 + 1460, false, true, &stream[1460..]);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_later_syn_ignored() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream[..1460]);
        asm.observe(CLIENT, 9999, true, false, &[]);
        asm.observe(CLIENT, ISN + 1 + 1460, false, true, &stream[1460..]);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_gives_up_on_non_tls() {
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(asm.is_done());
        assert!(asm.client_hello().is_none());
    }

    #[test]
    fn assembler_gives_up_on_non_client_hello() {
        // A handshake record holding a ServerHello (type 2)
        let mut msg = build_client_hello_message(Some("example.com"), None);
        msg[0] = 0x02;
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &wrap_in_record(&msg)[..20]);
        assert!(asm.is_done());
    }

    #[test]
    fn assembler_gives_up_on_bad_record_header() {
        for header in [
            [0x16, 0x02, 0x00, 0x00, 0x10], // not version 3.x
            [0x16, 0x03, 0x01, 0x00, 0x00], // empty record
            [0x16, 0x03, 0x01, 0x40, 0x01], // record longer than 2^14
        ] {
            let mut asm = after_syn(ISN);
            asm.observe(CLIENT, ISN + 1, false, true, &header);
            assert!(asm.is_done(), "header {:?}", header);
        }
    }

    #[test]
    fn assembler_gives_up_on_oversized_hello() {
        // Handshake header claiming a ClientHello far larger than the buffer cap
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x10, 0x00, 0x00]);
        assert!(asm.is_done());
    }

    #[test]
    fn assembler_gives_up_on_stream_past_window() {
        let stream = wrap_in_record(&build_large_client_hello_message("example.com"));
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1 + 1460, false, true, &stream[1460..]);
        asm.observe(CLIENT, ISN + 1 + MAX_CLIENT_HELLO_STREAM as u32, false, true, b"later data");
        assert!(asm.is_done());
        assert!(asm.client_hello().is_none());
    }

    #[test]
    fn parse_record_extracts_sni() {
        let msg = build_client_hello_message(Some("example.com"), None);
        let record = wrap_in_record(&msg);
        let info = parse_client_hello_record(&record).unwrap();
        assert_eq!(info.sni, Some("example.com".to_string()));
        assert_eq!(info.client_version, 0x0303);
    }

    #[test]
    fn parse_message_extracts_sni() {
        let msg = build_client_hello_message(Some("www.example.org"), None);
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.sni, Some("www.example.org".to_string()));
    }

    #[test]
    fn parse_message_no_sni() {
        let msg = build_client_hello_message(None, None);
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.sni, None);
    }

    #[test]
    fn parse_message_with_alpn() {
        let msg = build_client_hello_message(Some("test.com"), Some(&["h2", "http/1.1"]));
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.sni, Some("test.com".to_string()));
        assert_eq!(info.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn parse_message_supported_versions() {
        let msg = build_client_hello_message(Some("test.com"), None);
        let info = parse_client_hello_message(&msg).unwrap();
        assert!(info.supported_versions.contains(&0x0304)); // TLS 1.3
        assert!(info.supported_versions.contains(&0x0303)); // TLS 1.2
    }

    #[test]
    fn parse_record_not_handshake() {
        // Application data record (content type 23)
        let data = vec![23, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        // tls-parser parses this as a non-handshake record, so we won't find a ClientHello
        let err = parse_client_hello_record(&data).unwrap_err();
        assert!(
            matches!(err, TlsParseError::NotClientHello | TlsParseError::ParseFailed),
            "Expected NotClientHello or ParseFailed, got {:?}",
            err
        );
    }

    #[test]
    fn parse_record_too_short() {
        let err = parse_client_hello_record(&[0x16, 0x03]).unwrap_err();
        assert!(matches!(err, TlsParseError::TooShort));
    }

    #[test]
    fn parse_record_truncated() {
        // Record says 100 bytes but only 5 are present
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05];
        let err = parse_client_hello_record(&data).unwrap_err();
        assert!(matches!(err, TlsParseError::ParseFailed));
    }

    #[test]
    fn cipher_suites_count_tracked() {
        let msg = build_client_hello_message(Some("test.com"), None);
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.cipher_suites_count, 1);
    }

    #[test]
    fn extensions_count_tracked() {
        let msg = build_client_hello_message(Some("test.com"), Some(&["h2"]));
        let info = parse_client_hello_message(&msg).unwrap();
        // SNI + ALPN + supported_versions = 3
        assert_eq!(info.extensions_count, 3);
    }
}
