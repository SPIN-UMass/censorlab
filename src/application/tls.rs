//! TLS ClientHello recognition.
//!
//! The ClientHello grammar (RFC 8446 §4.1.2, RFC 5246 §7.4.1.2) is a nest of
//! length-prefixed vectors with bounded lengths, so it is recognised here by a
//! small hand-written parser that checks every length exactly: a vector must
//! be consumed completely by its contents, and the message must be consumed
//! completely by its fields.  Nothing is extracted from a message until its
//! framing has been fully recognised.
//!
//! Two entry points exist:
//! * [`ClientHelloDefragmenter`] — a streaming state machine over the TLS
//!   record layer.  It accepts the client→server byte stream in arbitrary
//!   chunks, validates each record header, concatenates handshake fragments
//!   across records and yields the ClientHello once complete.  It is used by
//!   the TCP reassembler in [`super::tls_stream`] and by
//!   [`parse_client_hello_record`].
//! * [`parse_client_hello_message`] — a bare handshake message (QUIC CRYPTO
//!   frames carry these without a record header).
//!
//! Extension-level policy (documented here because scripts depend on it):
//! * A known extension (server_name, ALPN, supported_versions) whose body does
//!   not match its grammar contributes nothing and its type is recorded in
//!   [`ClientHelloInfo::malformed_extensions`]; other extensions still parse.
//!   The extension *block* framing, however, must be exact or the whole
//!   ClientHello is rejected (there is no unambiguous way to resynchronise).
//! * Every `host_name` entry from every server_name extension is kept, in
//!   order, in [`ClientHelloInfo::sni_list`].  [`ClientHelloInfo::sni`] is the
//!   first one (OpenSSL, BoringSSL and RFC 6066 all permit at most one; a
//!   hello carrying more is flagged via [`ClientHelloInfo::sni_count`] /
//!   `duplicate_extensions` and robust censors should inspect every entry).
//! * Host names are opaque bytes.  Invalid UTF-8 does not abort the parse; it
//!   sets [`ClientHelloInfo::sni_invalid_utf8`].
use smoltcp::wire::IpAddress;
use thiserror::Error;

/// Maximum TLSPlaintext fragment length (RFC 8446 §5.1).
pub const MAX_RECORD_FRAGMENT: usize = 1 << 14;
/// Length of a TLS record header.
pub const RECORD_HEADER_LEN: usize = 5;
/// Length of a handshake message header (type + u24 length).
pub const HANDSHAKE_HEADER_LEN: usize = 4;

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const SNI_HOST_NAME: u8 = 0;

/// Errors that can occur when recognising a TLS ClientHello
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TlsParseError {
    #[error("Data ends before the ClientHello is complete")]
    Incomplete,
    #[error("Record content type {0} is not Handshake (22)")]
    NotHandshake(u8),
    #[error("Record version {0:#06x} is not a TLS/SSLv3 version")]
    BadRecordVersion(u16),
    #[error("Zero-length handshake record")]
    EmptyRecord,
    #[error("Record length {0} exceeds 2^14")]
    RecordTooLong(usize),
    #[error("Handshake type {0} is not ClientHello (1)")]
    NotClientHello(u8),
    #[error("ClientHello length {0} exceeds the configured limit")]
    TooLarge(usize),
    #[error("Handshake data follows the ClientHello in the same flight")]
    TrailingHandshakeData,
    #[error("Malformed ClientHello: {0}")]
    Malformed(&'static str),
    #[error("Reassembly buffer limit reached before the ClientHello completed")]
    BufferLimit,
}

/// Information extracted from a TLS ClientHello
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// TLS version from the ClientHello (legacy: usually 0x0303 for TLS 1.2+)
    pub client_version: u16,
    /// First `host_name` entry of the server_name extension, as raw bytes.
    pub sni: Option<Vec<u8>>,
    /// Every `host_name` entry, across all server_name extensions, in order.
    pub sni_list: Vec<Vec<u8>>,
    /// True if any `host_name` entry is not valid UTF-8.
    pub sni_invalid_utf8: bool,
    /// ALPN protocol names (raw bytes), across all ALPN extensions, in order.
    pub alpn: Vec<Vec<u8>>,
    /// Supported TLS versions from the supported_versions extension
    pub supported_versions: Vec<u16>,
    /// Number of cipher suites offered
    pub cipher_suites_count: usize,
    /// Number of extensions present
    pub extensions_count: usize,
    /// True if any extension type occurs more than once (forbidden by RFC 8446 §4.2).
    pub duplicate_extensions: bool,
    /// Types of known extensions whose bodies did not match their grammar.
    pub malformed_extensions: Vec<u16>,
    /// Number of TLS records the ClientHello spanned (0 for a bare message).
    pub record_count: usize,
    /// Number of TCP segments that contributed bytes (0 if not TCP-reassembled).
    pub tcp_segments: usize,
}

impl ClientHelloInfo {
    /// The first SNI host name, if present and valid UTF-8.
    pub fn sni_str(&self) -> Option<&str> {
        self.sni.as_deref().and_then(|b| std::str::from_utf8(b).ok())
    }
    /// Number of `host_name` entries.
    pub fn sni_count(&self) -> usize {
        self.sni_list.len()
    }
    /// True if the hello spanned more than one TLS record or TCP segment.
    pub fn reassembled(&self) -> bool {
        self.record_count > 1 || self.tcp_segments > 1
    }
}

/// Minimal cursor over a byte slice; every read is bounds-checked.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    /// A vector with a one-byte length prefix whose length lies in `min..=max`.
    fn vec8(&mut self, min: usize, max: usize) -> Option<&'a [u8]> {
        let len = usize::from(self.u8()?);
        (min..=max).contains(&len).then_some(())?;
        self.take(len)
    }
    /// A vector with a two-byte length prefix whose length lies in `min..=max`.
    fn vec16(&mut self, min: usize, max: usize) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        (min..=max).contains(&len).then_some(())?;
        self.take(len)
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Parse a TLS ClientHello from a raw TCP payload (TLS record format).
///
/// The payload must start with a TLS record header.  The ClientHello may span
/// several handshake records within `data`; bytes after the record that
/// completes it (e.g. a ChangeCipherSpec record) are ignored.
pub fn parse_client_hello_record(data: &[u8]) -> Result<ClientHelloInfo, TlsParseError> {
    match ClientHelloDefragmenter::new(usize::MAX).push(data) {
        DefragStep::NeedMore(_) => Err(TlsParseError::Incomplete),
        DefragStep::Done(result) => result,
    }
}

/// Parse a TLS ClientHello handshake message (without the TLS record header).
///
/// This is the format found inside QUIC CRYPTO frames.  `data` must contain
/// exactly one ClientHello message (type byte, u24 length, body).
pub fn parse_client_hello_message(data: &[u8]) -> Result<ClientHelloInfo, TlsParseError> {
    if data.len() < HANDSHAKE_HEADER_LEN {
        return Err(TlsParseError::Incomplete);
    }
    if data[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(TlsParseError::NotClientHello(data[0]));
    }
    let len = u24(&data[1..4]);
    let body = &data[HANDSHAKE_HEADER_LEN..];
    if body.len() < len {
        return Err(TlsParseError::Incomplete);
    }
    if body.len() > len {
        return Err(TlsParseError::TrailingHandshakeData);
    }
    parse_client_hello_body(body)
}

fn u24(b: &[u8]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

/// Result of feeding bytes to a [`ClientHelloDefragmenter`].
#[derive(Debug)]
pub enum DefragStep {
    /// More stream bytes are needed; continue with the returned state.
    NeedMore(ClientHelloDefragmenter),
    /// Recognition finished, successfully or not.  The state is consumed, so
    /// no further bytes can be fed by construction.
    Done(Result<ClientHelloInfo, TlsParseError>),
}

/// Streaming recogniser for the record layer of a client's first flight.
///
/// Accepts the client→server byte stream in arbitrary chunks.  Every record
/// before the ClientHello completes must be a Handshake record with an
/// SSLv3/TLS record version and a fragment length in `1..=2^14`; the
/// handshake fragments are concatenated into one handshake message, which
/// must be a ClientHello that ends exactly at a record boundary.
#[derive(Debug)]
pub struct ClientHelloDefragmenter {
    /// Bytes of a partially received record header.
    header: [u8; RECORD_HEADER_LEN],
    header_len: usize,
    /// Body bytes still expected for the current record (0 = expecting a header).
    record_remaining: usize,
    /// Concatenated handshake bytes.
    message: Vec<u8>,
    /// Declared ClientHello body length, once its header has been seen.
    declared_len: Option<usize>,
    /// Number of records seen.
    records: usize,
    /// Maximum number of stream bytes the hello may occupy.
    stream_limit: usize,
}

impl ClientHelloDefragmenter {
    /// Create a defragmenter that rejects any ClientHello whose minimal
    /// encoding (one record header + handshake header + body) exceeds
    /// `stream_limit` bytes.
    pub fn new(stream_limit: usize) -> Self {
        Self {
            header: [0; RECORD_HEADER_LEN],
            header_len: 0,
            record_remaining: 0,
            message: Vec::new(),
            declared_len: None,
            records: 0,
            stream_limit,
        }
    }

    /// Feed the next chunk of the stream.
    pub fn push(mut self, mut data: &[u8]) -> DefragStep {
        while !data.is_empty() {
            if self.record_remaining == 0 {
                let n = (RECORD_HEADER_LEN - self.header_len).min(data.len());
                self.header[self.header_len..self.header_len + n].copy_from_slice(&data[..n]);
                self.header_len += n;
                data = &data[n..];
                if self.header_len < RECORD_HEADER_LEN {
                    break;
                }
                self.header_len = 0;
                if let Err(e) = self.start_record() {
                    return DefragStep::Done(Err(e));
                }
            } else {
                let n = self.record_remaining.min(data.len());
                self.message.extend_from_slice(&data[..n]);
                self.record_remaining -= n;
                data = &data[n..];
                if let Err(e) = self.check_message() {
                    return DefragStep::Done(Err(e));
                }
                if let Some(len) = self.declared_len {
                    if self.record_remaining == 0
                        && self.message.len() == HANDSHAKE_HEADER_LEN + len
                    {
                        let result = parse_client_hello_body(&self.message[HANDSHAKE_HEADER_LEN..])
                            .map(|mut info| {
                                info.record_count = self.records;
                                info
                            });
                        return DefragStep::Done(result);
                    }
                }
            }
        }
        DefragStep::NeedMore(self)
    }

    /// Validate a just-completed record header.
    fn start_record(&mut self) -> Result<(), TlsParseError> {
        let [content_type, major, minor, hi, lo] = self.header;
        if content_type != CONTENT_TYPE_HANDSHAKE {
            return Err(TlsParseError::NotHandshake(content_type));
        }
        let version = u16::from_be_bytes([major, minor]);
        if major != 3 || minor > 4 {
            return Err(TlsParseError::BadRecordVersion(version));
        }
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if len == 0 {
            return Err(TlsParseError::EmptyRecord);
        }
        if len > MAX_RECORD_FRAGMENT {
            return Err(TlsParseError::RecordTooLong(len));
        }
        self.records += 1;
        self.record_remaining = len;
        self.check_trailing()
    }

    /// Validate the handshake header once available, and that the current
    /// record does not extend past the end of the ClientHello.
    fn check_message(&mut self) -> Result<(), TlsParseError> {
        if self.declared_len.is_none() && self.message.len() >= HANDSHAKE_HEADER_LEN {
            if self.message[0] != HANDSHAKE_CLIENT_HELLO {
                return Err(TlsParseError::NotClientHello(self.message[0]));
            }
            let len = u24(&self.message[1..4]);
            if len.saturating_add(RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN) > self.stream_limit {
                return Err(TlsParseError::TooLarge(len));
            }
            self.declared_len = Some(len);
        }
        self.check_trailing()
    }

    fn check_trailing(&self) -> Result<(), TlsParseError> {
        match self.declared_len {
            Some(len) if self.message.len() + self.record_remaining > HANDSHAKE_HEADER_LEN + len => {
                Err(TlsParseError::TrailingHandshakeData)
            }
            _ => Ok(()),
        }
    }
}

/// Recognise a ClientHello body (everything after the handshake header).
fn parse_client_hello_body(body: &[u8]) -> Result<ClientHelloInfo, TlsParseError> {
    use TlsParseError::Malformed;
    let mut r = Reader(body);
    let client_version = r.u16().ok_or(Malformed("legacy_version"))?;
    r.take(32).ok_or(Malformed("random"))?;
    r.vec8(0, 32).ok_or(Malformed("legacy_session_id"))?;
    let ciphers = r.vec16(2, 0xfffe).ok_or(Malformed("cipher_suites"))?;
    if ciphers.len() % 2 != 0 {
        return Err(Malformed("cipher_suites"));
    }
    r.vec8(1, 0xff).ok_or(Malformed("legacy_compression_methods"))?;

    let mut info = ClientHelloInfo {
        client_version,
        cipher_suites_count: ciphers.len() / 2,
        ..Default::default()
    };
    // Extensions are optional in TLS 1.2 (absent entirely); if present the
    // block must exactly fill the remainder of the body.
    if r.is_empty() {
        return Ok(info);
    }
    let block = r.vec16(0, 0xffff).ok_or(Malformed("extensions"))?;
    if !r.is_empty() {
        return Err(Malformed("trailing bytes after extensions"));
    }
    // First pass: recognise the extension framing completely.
    let mut exts = Vec::new();
    let mut er = Reader(block);
    while !er.is_empty() {
        let ty = er.u16().ok_or(Malformed("extension header"))?;
        let data = er.vec16(0, 0xffff).ok_or(Malformed("extension length"))?;
        exts.push((ty, data));
    }
    info.extensions_count = exts.len();
    let mut seen = std::collections::HashSet::new();
    for (ty, _) in &exts {
        if !seen.insert(*ty) {
            info.duplicate_extensions = true;
        }
    }
    // Second pass: interpret the extensions we care about.
    for (ty, data) in exts {
        let ok = match ty {
            EXT_SERVER_NAME => parse_server_name(data).map(|names| {
                for name in names {
                    if std::str::from_utf8(&name).is_err() {
                        info.sni_invalid_utf8 = true;
                    }
                    info.sni_list.push(name);
                }
            }),
            EXT_ALPN => parse_alpn(data).map(|protos| info.alpn.extend(protos)),
            EXT_SUPPORTED_VERSIONS => {
                parse_supported_versions(data).map(|v| info.supported_versions.extend(v))
            }
            _ => Some(()),
        };
        if ok.is_none() {
            info.malformed_extensions.push(ty);
        }
    }
    info.sni = info.sni_list.first().cloned();
    Ok(info)
}

/// server_name (RFC 6066 §3): ServerNameList<1..2^16-1> of
/// { NameType name_type; HostName<1..2^16-1> } — only host_name (0) is
/// defined, and an unknown name type cannot be delimited, so it makes the
/// whole extension malformed.
fn parse_server_name(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut r = Reader(data);
    let list = r.vec16(1, 0xffff)?;
    if !r.is_empty() {
        return None;
    }
    let mut lr = Reader(list);
    let mut names = Vec::new();
    while !lr.is_empty() {
        if lr.u8()? != SNI_HOST_NAME {
            return None;
        }
        names.push(lr.vec16(1, 0xffff)?.to_vec());
    }
    Some(names)
}

/// ALPN (RFC 7301 §3.1): ProtocolNameList<2..2^16-1> of ProtocolName<1..2^8-1>.
fn parse_alpn(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut r = Reader(data);
    let list = r.vec16(2, 0xffff)?;
    if !r.is_empty() {
        return None;
    }
    let mut lr = Reader(list);
    let mut protos = Vec::new();
    while !lr.is_empty() {
        protos.push(lr.vec8(1, 0xff)?.to_vec());
    }
    Some(protos)
}

/// supported_versions in a ClientHello (RFC 8446 §4.2.1): ProtocolVersion<2..254>.
fn parse_supported_versions(data: &[u8]) -> Option<Vec<u16>> {
    let mut r = Reader(data);
    let list = r.vec8(2, 254)?;
    if !r.is_empty() || list.len() % 2 != 0 {
        return None;
    }
    Some(
        list.chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect(),
    )
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

    /// Encode a raw extension (type, body).
    fn ext(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut v = ty.to_be_bytes().to_vec();
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// SNI extension body with the given (name_type, name) entries.
    fn sni_body(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (ty, name) in entries {
            list.push(*ty);
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name);
        }
        let mut v = (list.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(&list);
        v
    }

    /// ALPN extension body.
    fn alpn_body(protos: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for p in protos {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        let mut v = (list.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(&list);
        v
    }

    /// Build a ClientHello handshake message from pre-encoded extensions.
    fn hello_with_exts(exts: &[Vec<u8>]) -> Vec<u8> {
        let ext_block: Vec<u8> = exts.concat();
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);
        let mut msg = vec![0x01];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    /// Split a handshake message across several TLS records at the given cut points.
    fn wrap_in_records(handshake: &[u8], cuts: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = 0;
        for &c in cuts.iter().chain(std::iter::once(&handshake.len())) {
            out.extend_from_slice(&wrap_in_record(&handshake[prev..c]));
            prev = c;
        }
        out
    }

    #[test]
    fn invalid_utf8_sni_does_not_abort_other_fields() {
        let msg = hello_with_exts(&[
            ext(0x0000, &sni_body(&[(0, b"ex\xffample.com")])),
            ext(0x0010, &alpn_body(&[b"h2"])),
        ]);
        let info = parse_client_hello_message(&msg).expect("hello must still parse");
        assert_eq!(info.alpn, vec![b"h2".to_vec()]);
        assert!(info.sni_invalid_utf8);
        assert_eq!(info.sni.as_deref(), Some(&b"ex\xffample.com"[..]));
        assert_eq!(info.sni_str(), None);
    }

    #[test]
    fn hello_split_across_two_records() {
        let msg = build_client_hello_message(Some("split.example"), Some(&["h2"]));
        let data = wrap_in_records(&msg, &[10]);
        let info = parse_client_hello_record(&data).expect("two-record hello must parse");
        assert_eq!(info.extensions_count, 3);
    }

    #[test]
    fn message_longer_than_u16_is_not_truncated() {
        // A 65480-byte padding extension pushes the body beyond 0xFFFF.
        let msg = hello_with_exts(&[
            ext(0x0000, &sni_body(&[(0, b"big.example")])),
            ext(0x0015, &vec![0u8; 65480]),
        ]);
        assert!(msg.len() > 0xFFFF);
        let info = parse_client_hello_message(&msg).expect("large hello must parse");
        assert_eq!(info.extensions_count, 2);
    }

    /// A ClientHello message about as large as one with a post-quantum key share,
    /// using a padding extension to stand in for X25519MLKEM768
    fn build_large_client_hello_message(sni: &str) -> Vec<u8> {
        let mut msg = build_client_hello_message(Some(sni), None);
        let pad = 1500;
        msg.extend_from_slice(&[0x00, 0x15, (pad >> 8) as u8, (pad & 0xff) as u8]);
        msg.extend(std::iter::repeat(0u8).take(pad));
        // Fix up the handshake length and extensions length
        let hs_len = msg.len() - 4;
        msg[1..4].copy_from_slice(&(hs_len as u32).to_be_bytes()[1..]);
        let ext_len = u16::from_be_bytes([msg[45], msg[46]]) as usize + 4 + pad;
        msg[45..47].copy_from_slice(&(ext_len as u16).to_be_bytes());
        msg
    }

    /// Split a handshake message across several TLS records of at most `chunk` bytes
    fn wrap_in_record_chunks(handshake: &[u8], chunk: usize) -> Vec<u8> {
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
        asm.client_hello().and_then(|ch| ch.sni_str())
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
        let stream = wrap_in_record_chunks(&build_large_client_hello_message("example.com"), 100);
        let mut asm = after_syn(ISN);
        asm.observe(CLIENT, ISN + 1, false, true, &stream);
        assert_eq!(sni(&asm), Some("example.com"));
    }

    #[test]
    fn assembler_split_across_records_and_segments() {
        let stream = wrap_in_record_chunks(&build_large_client_hello_message("example.com"), 7);
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
        assert_eq!(info.sni_str(), Some("example.com"));
        assert_eq!(info.client_version, 0x0303);
    }

    #[test]
    fn parse_message_extracts_sni() {
        let msg = build_client_hello_message(Some("www.example.org"), None);
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.sni_str(), Some("www.example.org"));
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
        assert_eq!(info.sni_str(), Some("test.com"));
        assert_eq!(info.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
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
        // Application data record (content type 23) before any ClientHello
        let data = vec![23, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let err = parse_client_hello_record(&data).unwrap_err();
        assert_eq!(err, TlsParseError::NotHandshake(23));
    }

    #[test]
    fn parse_record_too_short() {
        let err = parse_client_hello_record(&[0x16, 0x03]).unwrap_err();
        assert_eq!(err, TlsParseError::Incomplete);
    }

    #[test]
    fn parse_record_truncated() {
        // Record says 100 bytes but only 5 are present
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05];
        let err = parse_client_hello_record(&data).unwrap_err();
        assert_eq!(err, TlsParseError::Incomplete);
    }

    #[test]
    fn hello_split_across_three_records_counts_records() {
        let msg = build_client_hello_message(Some("three.example"), Some(&["h2"]));
        let data = wrap_in_records(&msg, &[1, 30]);
        let info = parse_client_hello_record(&data).unwrap();
        assert_eq!(info.sni_str(), Some("three.example"));
        assert_eq!(info.record_count, 3);
        assert!(info.reassembled());
    }

    #[test]
    fn non_handshake_record_between_fragments_rejected() {
        let msg = build_client_hello_message(Some("x.example"), None);
        let mut data = wrap_in_record(&msg[..10]);
        data.extend_from_slice(&[20, 0x03, 0x03, 0x00, 0x01, 0x01]); // ChangeCipherSpec
        data.extend_from_slice(&wrap_in_record(&msg[10..]));
        assert_eq!(
            parse_client_hello_record(&data).unwrap_err(),
            TlsParseError::NotHandshake(20)
        );
    }

    #[test]
    fn record_length_over_2_14_rejected() {
        let data = [0x16, 0x03, 0x01, 0x40, 0x01, 0x01];
        assert_eq!(
            parse_client_hello_record(&data).unwrap_err(),
            TlsParseError::RecordTooLong(0x4001)
        );
    }

    #[test]
    fn empty_record_and_bad_version_rejected() {
        assert_eq!(
            parse_client_hello_record(&[0x16, 0x03, 0x01, 0x00, 0x00]).unwrap_err(),
            TlsParseError::EmptyRecord
        );
        assert_eq!(
            parse_client_hello_record(&[0x16, 0x02, 0x00, 0x00, 0x01, 0x01]).unwrap_err(),
            TlsParseError::BadRecordVersion(0x0200)
        );
    }

    #[test]
    fn trailing_handshake_data_in_record_rejected() {
        let mut msg = build_client_hello_message(Some("x.example"), None);
        msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(
            parse_client_hello_record(&wrap_in_record(&msg)).unwrap_err(),
            TlsParseError::TrailingHandshakeData
        );
    }

    #[test]
    fn records_after_hello_are_ignored() {
        let msg = build_client_hello_message(Some("x.example"), None);
        let mut data = wrap_in_record(&msg);
        data.extend_from_slice(&[20, 0x03, 0x03, 0x00, 0x01, 0x01]);
        assert_eq!(parse_client_hello_record(&data).unwrap().sni_str(), Some("x.example"));
    }

    #[test]
    fn not_client_hello_rejected() {
        let mut msg = build_client_hello_message(Some("x.example"), None);
        msg[0] = 2; // ServerHello
        assert_eq!(
            parse_client_hello_record(&wrap_in_record(&msg)).unwrap_err(),
            TlsParseError::NotClientHello(2)
        );
    }

    #[test]
    fn defragmenter_byte_at_a_time() {
        let msg = build_client_hello_message(Some("bytewise.example"), Some(&["h2"]));
        let data = wrap_in_records(&msg, &[7, 50]);
        let mut d = ClientHelloDefragmenter::new(usize::MAX);
        for (i, b) in data.iter().enumerate() {
            match d.push(std::slice::from_ref(b)) {
                DefragStep::NeedMore(next) => d = next,
                DefragStep::Done(res) => {
                    assert_eq!(i, data.len() - 1, "completed early");
                    assert_eq!(res.unwrap().sni_str(), Some("bytewise.example"));
                    return;
                }
            }
        }
        panic!("never completed");
    }

    #[test]
    fn defragmenter_rejects_declared_length_over_limit() {
        let msg = build_client_hello_message(Some("x.example"), None);
        let d = ClientHelloDefragmenter::new(msg.len() + RECORD_HEADER_LEN - 1);
        match d.push(&wrap_in_record(&msg)[..9]) {
            DefragStep::Done(Err(TlsParseError::TooLarge(_))) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn message_length_must_be_exact() {
        let mut msg = build_client_hello_message(Some("x.example"), None);
        msg.push(0);
        assert_eq!(
            parse_client_hello_message(&msg).unwrap_err(),
            TlsParseError::TrailingHandshakeData
        );
        msg.truncate(msg.len() - 2);
        assert_eq!(parse_client_hello_message(&msg).unwrap_err(), TlsParseError::Incomplete);
    }

    #[test]
    fn body_inner_lengths_must_be_exact() {
        // Extensions length one larger than the remaining body.
        let mut msg = build_client_hello_message(Some("x.example"), None);
        let ext_len_pos = 4 + 2 + 32 + 1 + 4 + 2;
        msg[ext_len_pos + 1] += 1;
        assert!(matches!(
            parse_client_hello_message(&msg).unwrap_err(),
            TlsParseError::Malformed(_)
        ));
    }

    #[test]
    fn multiple_host_names_all_exposed() {
        let msg = hello_with_exts(&[ext(
            0x0000,
            &sni_body(&[(0, b"allowed.example"), (0, b"blocked.example")]),
        )]);
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.sni.as_deref(), Some(&b"allowed.example"[..]));
        assert_eq!(
            info.sni_list,
            vec![b"allowed.example".to_vec(), b"blocked.example".to_vec()]
        );
        assert_eq!(info.sni_count(), 2);
    }

    #[test]
    fn duplicate_sni_extensions_flagged_and_merged() {
        let msg = hello_with_exts(&[
            ext(0x0000, &sni_body(&[(0, b"a.example")])),
            ext(0x0000, &sni_body(&[(0, b"b.example")])),
        ]);
        let info = parse_client_hello_message(&msg).unwrap();
        assert!(info.duplicate_extensions);
        assert_eq!(info.sni_list.len(), 2);
    }

    #[test]
    fn malformed_sni_extension_keeps_other_fields() {
        let msg = hello_with_exts(&[
            ext(0x0000, &sni_body(&[(7, b"weird")])), // unknown name type
            ext(0x0010, &alpn_body(&[b"h2"])),
        ]);
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.sni, None);
        assert_eq!(info.malformed_extensions, vec![0x0000]);
        assert_eq!(info.alpn, vec![b"h2".to_vec()]);
    }

    #[test]
    fn hello_without_extensions_block() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00]);
        let mut msg = vec![1, 0, 0, body.len() as u8];
        msg.extend_from_slice(&body);
        let info = parse_client_hello_message(&msg).unwrap();
        assert_eq!(info.extensions_count, 0);
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
