//! QUIC client Initial parsing with Initial-packet decryption.
//!
//! QUIC Initial packets are protected with keys that are derived from the
//! client-chosen Destination Connection ID and a version-specific salt
//! (RFC 9001 Section 5.2; RFC 9369 Section 3.3 for QUIC v2). Anyone on the
//! path can therefore remove the protection, which is exactly what real-world
//! censors do to read the SNI. This module:
//!
//! 1. Fully parses the long header (fixed bit, version, connection IDs,
//!    token, Length) and validates every length against the datagram.
//! 2. Derives the client Initial keys, removes header protection, decodes
//!    the packet number and AEAD-decrypts (AES-128-GCM) the payload.
//! 3. Walks every frame permitted in an Initial packet (PADDING, PING, ACK,
//!    CRYPTO, CONNECTION_CLOSE) and rejects anything else.
//! 4. Reassembles CRYPTO data by offset and parses the TLS ClientHello once
//!    the whole handshake message is available.
//!
//! Coalesced packets (RFC 9000 Section 12.2) are handled via the Length
//! field. ClientHellos spanning several Initial packets in *different*
//! datagrams (e.g. post-quantum key shares) need per-connection state; use
//! [`ClientInitialReassembler`] for that. [`parse_quic_initial`] is the
//! stateless single-datagram entry point.
//!
//! Only QUIC v1 (RFC 9000) and QUIC v2 (RFC 9369) are understood. Any other
//! version is rejected with [`QuicParseError::UnsupportedVersion`]: the
//! Initial protection of unknown versions is unknown, so we never guess.

use super::tls;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

/// Errors that can occur when parsing a QUIC Initial packet
#[derive(Debug, Error)]
pub enum QuicParseError {
    #[error("Packet too short")]
    TooShort,
    #[error("Not a QUIC long header packet")]
    NotLongHeader,
    #[error("QUIC fixed bit is not set")]
    FixedBitUnset,
    #[error("Unsupported QUIC version: {0:#x}")]
    UnsupportedVersion(u32),
    #[error("Not a QUIC Initial packet (type={0})")]
    NotInitial(u8),
    #[error("Invalid variable-length integer")]
    InvalidVarInt,
    #[error("Connection ID longer than 20 bytes")]
    ConnectionIdTooLong,
    #[error("Length field inconsistent with the datagram")]
    InvalidLength,
    #[error("Initial packet failed to decrypt (not a client Initial or corrupted)")]
    DecryptionFailed,
    #[error("Reserved header bits are set")]
    ReservedBitsSet,
    #[error("Initial packet has an empty payload")]
    EmptyPayload,
    #[error("Frame type {0:#x} is not permitted in an Initial packet")]
    UnexpectedFrame(u8),
    #[error("Truncated or malformed frame")]
    MalformedFrame,
    #[error("CRYPTO data exceeds the 16384-byte limit")]
    CryptoTooLarge,
    #[error("Overlapping CRYPTO data is inconsistent")]
    CryptoInconsistent,
    #[error("CRYPTO stream does not start with a ClientHello")]
    NotClientHello,
    #[error("TLS parse error: {0}")]
    TlsError(#[from] tls::TlsParseError),
}

/// Upper bound on the client Initial CRYPTO stream (the ClientHello).
///
/// This is the TLS maximum plaintext record size; a ClientHello that does not
/// fit is not something we try to reassemble.
pub const MAX_CRYPTO_STREAM: usize = 1 << 14;

/// Maximum connection ID length for QUIC v1 and v2 (RFC 9000 Section 17.2).
const MAX_CID_LEN: usize = 20;
/// AES-128-GCM tag length
const TAG_LEN: usize = 16;
/// Header protection sample length
const SAMPLE_LEN: usize = 16;
/// Largest value representable by a QUIC varint
const VARINT_MAX: u64 = (1 << 62) - 1;

/// A QUIC version whose Initial packet protection we understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    /// QUIC version 1 (RFC 9000 / RFC 9001)
    V1,
    /// QUIC version 2 (RFC 9369)
    V2,
}

/// Long header packet types (RFC 9000 Section 17.2, RFC 9369 Section 3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl QuicVersion {
    /// Map a wire version number to a known version.
    pub fn from_wire(version: u32) -> Option<Self> {
        match version {
            0x0000_0001 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    /// The wire version number.
    pub fn to_wire(self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4,
                0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            Self::V2 => &[
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e,
                0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
            ],
        }
    }

    /// (key, iv, hp) HKDF labels
    fn labels(self) -> (&'static [u8], &'static [u8], &'static [u8]) {
        match self {
            Self::V1 => (b"quic key", b"quic iv", b"quic hp"),
            Self::V2 => (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
        }
    }

    fn packet_type(self, type_bits: u8) -> LongPacketType {
        use LongPacketType::*;
        match (self, type_bits & 0x03) {
            (Self::V1, 0) | (Self::V2, 1) => Initial,
            (Self::V1, 1) | (Self::V2, 2) => ZeroRtt,
            (Self::V1, 2) | (Self::V2, 3) => Handshake,
            _ => Retry,
        }
    }

    fn initial_type_bits(self) -> u8 {
        match self {
            Self::V1 => 0,
            Self::V2 => 1,
        }
    }
}

/// Result of parsing a QUIC Initial packet's crypto payload
#[derive(Debug, Clone)]
pub struct QuicInitialInfo {
    /// QUIC version (e.g. 0x00000001 for QUIC v1)
    pub version: u32,
    /// Destination Connection ID
    pub dcid: Vec<u8>,
    /// Source Connection ID
    pub scid: Vec<u8>,
    /// TLS ClientHello, once the CRYPTO stream holds the complete message.
    /// `None` means the ClientHello is still incomplete (it continues in
    /// another Initial packet).
    pub client_hello: Option<tls::ClientHelloInfo>,
}

impl QuicInitialInfo {
    /// Convenience: get the SNI from the ClientHello, if present.
    pub fn sni(&self) -> Option<&str> {
        self.client_hello.as_ref().and_then(|ch| ch.sni_str())
    }
}

/// Decode a QUIC variable-length integer (RFC 9000, Section 16).
/// Returns (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> Result<(u64, usize), QuicParseError> {
    let first = *data.first().ok_or(QuicParseError::InvalidVarInt)?;
    let length = 1usize << (first >> 6);
    let bytes = data.get(..length).ok_or(QuicParseError::InvalidVarInt)?;
    let value = bytes[1..]
        .iter()
        .fold((first & 0x3f) as u64, |acc, b| (acc << 8) | *b as u64);
    Ok((value, length))
}

/// Encode a QUIC varint using the shortest encoding (or at least `min_len` bytes).
fn encode_varint(value: u64, min_len: usize, out: &mut Vec<u8>) {
    assert!(value <= VARINT_MAX, "varint out of range");
    let len = [1usize, 2, 4, 8]
        .into_iter()
        .find(|&l| l >= min_len && value < (1u64 << (8 * l - 2)))
        .expect("value fits in 8 bytes");
    let prefix = (len.trailing_zeros() as u8) << 6;
    let bytes = value.to_be_bytes();
    out.push(bytes[8 - len] | prefix);
    out.extend_from_slice(&bytes[9 - len..]);
}

/// Bounds-checked reader over a byte slice.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn varint(&mut self) -> Option<u64> {
        let (v, n) = decode_varint(&self.data[self.pos..]).ok()?;
        self.pos += n;
        Some(v)
    }
    /// A varint used as a length that must fit within the remaining data.
    fn varint_len(&mut self) -> Option<usize> {
        let v = self.varint()?;
        usize::try_from(v).ok().filter(|&n| n <= self.remaining())
    }
}

/// A long header packet located within a datagram (header protection still on).
struct LongHeader<'a> {
    version: QuicVersion,
    packet_type: LongPacketType,
    dcid: &'a [u8],
    scid: &'a [u8],
    /// Offset of the (protected) packet number; only meaningful for packets
    /// with a Length field.
    pn_offset: usize,
    /// Total length of this packet within the datagram.
    packet_len: usize,
}

/// Parse a long header packet at the start of `data` and determine its
/// extent. Validates every length field.
fn parse_long_header(data: &[u8]) -> Result<LongHeader<'_>, QuicParseError> {
    let mut r = Reader::new(data);
    let first = r.u8().ok_or(QuicParseError::TooShort)?;
    if first & 0x80 == 0 {
        return Err(QuicParseError::NotLongHeader);
    }
    let version = r.bytes(4).ok_or(QuicParseError::TooShort)?;
    let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);
    // Version negotiation (version 0) and unknown versions: the remainder of
    // the packet is version-specific, so stop here.
    let version = QuicVersion::from_wire(version).ok_or(QuicParseError::UnsupportedVersion(version))?;
    if first & 0x40 == 0 {
        return Err(QuicParseError::FixedBitUnset);
    }
    let packet_type = version.packet_type((first >> 4) & 0x03);

    let dcid_len = r.u8().ok_or(QuicParseError::TooShort)? as usize;
    if dcid_len > MAX_CID_LEN {
        return Err(QuicParseError::ConnectionIdTooLong);
    }
    let dcid = r.bytes(dcid_len).ok_or(QuicParseError::TooShort)?;
    let scid_len = r.u8().ok_or(QuicParseError::TooShort)? as usize;
    if scid_len > MAX_CID_LEN {
        return Err(QuicParseError::ConnectionIdTooLong);
    }
    let scid = r.bytes(scid_len).ok_or(QuicParseError::TooShort)?;

    match packet_type {
        LongPacketType::Retry => {
            // Retry has no Length field and extends to the end of the datagram.
            Ok(LongHeader {
                version,
                packet_type,
                dcid,
                scid,
                pn_offset: r.pos,
                packet_len: data.len(),
            })
        }
        _ => {
            if packet_type == LongPacketType::Initial {
                let token_len = r.varint_len().ok_or(QuicParseError::InvalidLength)?;
                r.bytes(token_len).ok_or(QuicParseError::InvalidLength)?;
            }
            let length = r.varint_len().ok_or(QuicParseError::InvalidLength)?;
            let pn_offset = r.pos;
            Ok(LongHeader {
                version,
                packet_type,
                dcid,
                scid,
                pn_offset,
                packet_len: pn_offset + length,
            })
        }
    }
}

/// Client Initial packet protection keys.
#[derive(Clone)]
struct InitialKeys {
    aead: Aes128Gcm,
    iv: [u8; 12],
    hp: Aes128,
}

/// HKDF-Expand-Label (RFC 8446 Section 7.1) with an empty context.
fn hkdf_expand_label(secret: &[u8], label: &[u8], out: &mut [u8]) {
    let prk = Hkdf::<Sha256>::from_prk(secret).expect("secret is a SHA-256 PRK");
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // empty context
    prk.expand(&info, out).expect("output length is valid for SHA-256");
}

/// Raw client Initial key material: (key, iv, hp)
fn derive_client_initial_secrets(version: QuicVersion, dcid: &[u8]) -> ([u8; 16], [u8; 12], [u8; 16]) {
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&version.initial_salt()[..]), dcid);
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(&initial_secret, b"client in", &mut client_secret);
    let (key_label, iv_label, hp_label) = version.labels();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf_expand_label(&client_secret, key_label, &mut key);
    hkdf_expand_label(&client_secret, iv_label, &mut iv);
    hkdf_expand_label(&client_secret, hp_label, &mut hp);
    (key, iv, hp)
}

impl InitialKeys {
    fn client(version: QuicVersion, dcid: &[u8]) -> Self {
        let (key, iv, hp) = derive_client_initial_secrets(version, dcid);
        Self {
            aead: Aes128Gcm::new(&key.into()),
            iv,
            hp: Aes128::new(&hp.into()),
        }
    }

    fn hp_mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; 16] {
        let mut block = (*sample).into();
        self.hp.encrypt_block(&mut block);
        block.into()
    }

    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (n, p) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
            *n ^= p;
        }
        nonce
    }
}

/// Recover a full packet number (RFC 9000 Appendix A.3).
fn decode_packet_number(largest_pn: Option<u64>, truncated: u64, pn_nbits: u32) -> u64 {
    let expected = largest_pn.map_or(0, |l| l + 1);
    let win = 1u64 << pn_nbits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate.saturating_add(hwin) <= expected && candidate < (1u64 << 62) - win {
        candidate + win
    } else if candidate > expected.saturating_add(hwin) && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

/// Remove protection from an Initial packet. Returns (packet number, plaintext).
fn open_initial(
    keys: &InitialKeys,
    packet: &[u8],
    pn_offset: usize,
    largest_pn: Option<u64>,
) -> Result<(u64, Vec<u8>), QuicParseError> {
    // The sample starts 4 bytes after the packet number offset and the
    // packet must contain it entirely (RFC 9001 Section 5.4.2).
    let sample = packet
        .get(pn_offset + 4..)
        .and_then(|rest| rest.first_chunk::<SAMPLE_LEN>())
        .ok_or(QuicParseError::InvalidLength)?;
    let mask = keys.hp_mask(sample);
    let first = packet[0] ^ (mask[0] & 0x0f);
    let pn_len = (first & 0x03) as usize + 1;

    let mut header = packet[..pn_offset + pn_len].to_vec();
    header[0] = first;
    let mut truncated = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        truncated = (truncated << 8) | header[pn_offset + i] as u64;
    }
    let pn = decode_packet_number(largest_pn, truncated, 8 * pn_len as u32);

    let body = &packet[pn_offset + pn_len..];
    // pn_offset + 4 + 16 <= len guarantees body.len() >= TAG_LEN
    let (ciphertext, tag) = body
        .split_last_chunk::<TAG_LEN>()
        .ok_or(QuicParseError::InvalidLength)?;
    let mut plaintext = ciphertext.to_vec();
    keys.aead
        .decrypt_inout_detached(
            &Nonce::from(keys.nonce(pn)),
            &header,
            plaintext.as_mut_slice().into(),
            &Tag::from(*tag),
        )
        .map_err(|_| QuicParseError::DecryptionFailed)?;

    // Only checked after authentication (RFC 9000 Section 17.2).
    if first & 0x0c != 0 {
        return Err(QuicParseError::ReservedBitsSet);
    }
    Ok((pn, plaintext))
}

/// Walk all frames of a decrypted Initial packet, returning CRYPTO segments
/// as (offset, data).
fn parse_initial_frames(payload: &[u8]) -> Result<Vec<(u64, &[u8])>, QuicParseError> {
    use QuicParseError::MalformedFrame;
    if payload.is_empty() {
        return Err(QuicParseError::EmptyPayload);
    }
    let mut r = Reader::new(payload);
    let mut crypto = Vec::new();
    while let Some(frame_type) = r.u8() {
        // Frame types are varints; every type permitted here is < 0x40 and
        // therefore a single byte. Anything else is not allowed in Initial.
        match frame_type {
            // PADDING, PING
            0x00 | 0x01 => {}
            // ACK, ACK with ECN counts
            0x02 | 0x03 => {
                let _largest = r.varint().ok_or(MalformedFrame)?;
                let _delay = r.varint().ok_or(MalformedFrame)?;
                let range_count = r.varint().ok_or(MalformedFrame)?;
                let _first_range = r.varint().ok_or(MalformedFrame)?;
                // Each range is at least two bytes, so this loop is bounded
                // by the payload length.
                for _ in 0..range_count {
                    let _gap = r.varint().ok_or(MalformedFrame)?;
                    let _len = r.varint().ok_or(MalformedFrame)?;
                }
                if frame_type == 0x03 {
                    for _ in 0..3 {
                        r.varint().ok_or(MalformedFrame)?;
                    }
                }
            }
            // CRYPTO
            0x06 => {
                let offset = r.varint().ok_or(MalformedFrame)?;
                let len = r.varint_len().ok_or(MalformedFrame)?;
                if offset + len as u64 > VARINT_MAX {
                    return Err(MalformedFrame);
                }
                crypto.push((offset, r.bytes(len).ok_or(MalformedFrame)?));
            }
            // CONNECTION_CLOSE (transport)
            0x1c => {
                let _error_code = r.varint().ok_or(MalformedFrame)?;
                let _frame_type = r.varint().ok_or(MalformedFrame)?;
                let reason_len = r.varint_len().ok_or(MalformedFrame)?;
                r.bytes(reason_len).ok_or(MalformedFrame)?;
            }
            other => return Err(QuicParseError::UnexpectedFrame(other)),
        }
    }
    Ok(crypto)
}

/// Reassembly buffer for the Initial CRYPTO stream.
#[derive(Clone, Default)]
struct CryptoStream {
    data: Vec<u8>,
    filled: Vec<bool>,
}

impl CryptoStream {
    fn insert(&mut self, offset: u64, segment: &[u8]) -> Result<(), QuicParseError> {
        let end = offset
            .checked_add(segment.len() as u64)
            .filter(|&e| e <= MAX_CRYPTO_STREAM as u64)
            .ok_or(QuicParseError::CryptoTooLarge)? as usize;
        let start = offset as usize;
        if self.data.len() < end {
            self.data.resize(end, 0);
            self.filled.resize(end, false);
        }
        // Check before writing so that a rejected segment changes nothing.
        let consistent = segment
            .iter()
            .enumerate()
            .all(|(i, b)| !self.filled[start + i] || self.data[start + i] == *b);
        if !consistent {
            return Err(QuicParseError::CryptoInconsistent);
        }
        self.data[start..end].copy_from_slice(segment);
        self.filled[start..end].iter_mut().for_each(|f| *f = true);
        Ok(())
    }

    fn contiguous(&self) -> &[u8] {
        let n = self.filled.iter().position(|f| !f).unwrap_or(self.filled.len());
        &self.data[..n]
    }

    /// The ClientHello, if the full handshake message has arrived.
    fn client_hello(&self) -> Result<Option<tls::ClientHelloInfo>, QuicParseError> {
        let data = self.contiguous();
        let Some(header) = data.get(..4) else {
            return Ok(None);
        };
        if header[0] != 0x01 {
            return Err(QuicParseError::NotClientHello);
        }
        let body_len = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        let total = 4 + body_len;
        if total > MAX_CRYPTO_STREAM {
            return Err(QuicParseError::CryptoTooLarge);
        }
        match data.get(..total) {
            Some(msg) => Ok(Some(tls::parse_client_hello_message(msg)?)),
            None => Ok(None),
        }
    }
}

/// Per-connection state, keyed by (version, original DCID).
#[derive(Clone)]
struct ConnState {
    version: QuicVersion,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    keys: InitialKeys,
    largest_pn: Option<u64>,
    crypto: CryptoStream,
    client_hello: Option<tls::ClientHelloInfo>,
}

impl ConnState {
    fn info(&self) -> QuicInitialInfo {
        QuicInitialInfo {
            version: self.version.to_wire(),
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            client_hello: self.client_hello.clone(),
        }
    }
}

/// Stateful decoder for the client Initial packets of one connection.
///
/// Feed it every client-to-server UDP payload; CRYPTO data is reassembled
/// across Initial packets and datagrams, so ClientHellos that span several
/// packets are recovered. A datagram that fails to parse or decrypt leaves
/// the state untouched. If a successfully decrypted Initial uses a new
/// version or DCID (e.g. after a Retry), reassembly restarts.
#[derive(Clone, Default)]
pub struct ClientInitialReassembler {
    state: Option<ConnState>,
}

impl ClientInitialReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process one UDP datagram payload.
    pub fn feed(&mut self, datagram: &[u8]) -> Result<QuicInitialInfo, QuicParseError> {
        let first = parse_long_header(datagram)?;
        if first.packet_type != LongPacketType::Initial {
            return Err(QuicParseError::NotInitial((datagram[0] >> 4) & 0x03));
        }
        if first.packet_len > datagram.len() {
            return Err(QuicParseError::InvalidLength);
        }
        // Work on a copy so that a failure leaves the committed state intact.
        let mut state = match &self.state {
            Some(s) if s.version == first.version && s.dcid == first.dcid => s.clone(),
            _ => ConnState {
                version: first.version,
                dcid: first.dcid.to_vec(),
                scid: first.scid.to_vec(),
                keys: InitialKeys::client(first.version, first.dcid),
                largest_pn: None,
                crypto: CryptoStream::default(),
                client_hello: None,
            },
        };

        // The first packet must be a decryptable client Initial.
        state.open_and_absorb(&datagram[..first.packet_len], first.pn_offset)?;

        // Coalesced packets (RFC 9000 Section 12.2). Packets we cannot
        // process are ignored, as a receiver would; we stop at the first one
        // whose extent cannot be determined.
        let mut rest = &datagram[first.packet_len..];
        while !rest.is_empty() {
            let Ok(hdr) = parse_long_header(rest) else { break };
            if hdr.packet_len > rest.len() || hdr.version != state.version || hdr.dcid != state.dcid.as_slice() {
                break;
            }
            if hdr.packet_type == LongPacketType::Initial {
                let mut attempt = state.clone();
                if attempt
                    .open_and_absorb(&rest[..hdr.packet_len], hdr.pn_offset)
                    .is_ok()
                {
                    state = attempt;
                }
            }
            rest = &rest[hdr.packet_len..];
        }

        if state.client_hello.is_none() {
            state.client_hello = state.crypto.client_hello()?;
        }
        let info = state.info();
        self.state = Some(state);
        Ok(info)
    }
}

impl ConnState {
    fn open_and_absorb(&mut self, packet: &[u8], pn_offset: usize) -> Result<(), QuicParseError> {
        let (pn, plaintext) = open_initial(&self.keys, packet, pn_offset, self.largest_pn)?;
        for (offset, segment) in parse_initial_frames(&plaintext)? {
            self.crypto.insert(offset, segment)?;
        }
        self.largest_pn = Some(self.largest_pn.map_or(pn, |l| l.max(pn)));
        Ok(())
    }
}

/// Parse a single UDP datagram containing a QUIC client Initial, decrypt it,
/// and extract connection info + TLS ClientHello.
///
/// This is stateless: `client_hello` is `None` if the ClientHello continues
/// in another datagram (use [`ClientInitialReassembler`] for that).
/// Returns an error for anything that is not a well-formed, authenticated
/// client Initial of a supported QUIC version.
pub fn parse_quic_initial(data: &[u8]) -> Result<QuicInitialInfo, QuicParseError> {
    ClientInitialReassembler::new().feed(data)
}

/// Build a protected client Initial packet (the inverse of
/// [`parse_quic_initial`]). Intended for tests and traffic generation.
///
/// `frames` is the plaintext frame payload; it is padded with PADDING frames
/// if needed so that the header protection sample is available.
/// `pn_len` must be in 1..=4 and `pn` must fit in it.
pub fn seal_client_initial(
    version: QuicVersion,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    pn: u64,
    pn_len: usize,
    frames: &[u8],
) -> Vec<u8> {
    assert!((1..=4).contains(&pn_len), "pn_len must be 1..=4");
    assert!(pn < 1u64 << (8 * pn_len), "pn does not fit in pn_len");
    assert!(dcid.len() <= MAX_CID_LEN && scid.len() <= MAX_CID_LEN);
    let mut plaintext = frames.to_vec();
    if pn_len + plaintext.len() < 4 {
        plaintext.resize(4 - pn_len, 0x00);
    }

    let mut header = vec![0xc0 | (version.initial_type_bits() << 4) | (pn_len as u8 - 1)];
    header.extend_from_slice(&version.to_wire().to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(scid);
    encode_varint(token.len() as u64, 1, &mut header);
    header.extend_from_slice(token);
    encode_varint((pn_len + plaintext.len() + TAG_LEN) as u64, 2, &mut header);
    let pn_offset = header.len();
    header.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);

    let keys = InitialKeys::client(version, dcid);
    let tag = keys
        .aead
        .encrypt_inout_detached(
            &Nonce::from(keys.nonce(pn)),
            &header,
            plaintext.as_mut_slice().into(),
        )
        .expect("AES-GCM encryption cannot fail for these sizes");
    let mut packet = header;
    packet.extend_from_slice(&plaintext);
    packet.extend_from_slice(&tag);

    let sample = packet[pn_offset + 4..]
        .first_chunk::<SAMPLE_LEN>()
        .expect("packet contains the header protection sample");
    let mask = keys.hp_mask(sample);
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

/// Build a CRYPTO frame carrying `data` at `offset`.
pub fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
    let mut f = vec![0x06];
    encode_varint(offset, 1, &mut f);
    encode_varint(data.len() as u64, 1, &mut f);
    f.extend_from_slice(data);
    f
}

#[cfg(test)]
#[path = "quic_test_vectors.rs"]
mod test_vectors;

#[cfg(test)]
mod tests {
    use super::test_vectors::*;
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const RFC_DCID: &str = "8394c8f03e515708";

    /// Build a minimal TLS ClientHello handshake message with the given SNI.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        build_client_hello_padded(sni, 0)
    }

    /// ClientHello with an extra opaque extension of `pad` bytes (to mimic
    /// large post-quantum ClientHellos).
    fn build_client_hello_padded(sni: &str, pad: usize) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sn_entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_data_len = 2 + sn_entry_len;
        let pad_ext = if pad > 0 { 4 + pad } else { 0 };
        let ext_total = 4 + sni_ext_data_len + pad_ext;
        let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_total;

        let mut buf = Vec::new();
        buf.push(0x01); // ClientHello
        buf.extend_from_slice(&(ch_body_len as u32).to_be_bytes()[1..]);
        buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x00); // session_id len
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        buf.extend_from_slice(&[0x01, 0x00]); // compression
        buf.extend_from_slice(&(ext_total as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // SNI extension type
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        buf.extend_from_slice(&(sn_entry_len as u16).to_be_bytes());
        buf.push(0x00); // host_name
        buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sni_bytes);
        if pad > 0 {
            buf.extend_from_slice(&[0x00, 0x15]); // padding extension
            buf.extend_from_slice(&(pad as u16).to_be_bytes());
            buf.resize(buf.len() + pad, 0);
        }
        buf
    }

    fn padded(mut frames: Vec<u8>, total: usize) -> Vec<u8> {
        if frames.len() < total {
            frames.resize(total, 0);
        }
        frames
    }

    /// A protected v1 client Initial carrying a ClientHello with `sni`.
    fn build_quic_initial(sni: &str, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let frames = padded(crypto_frame(0, &build_client_hello(sni)), 1162);
        seal_client_initial(QuicVersion::V1, dcid, scid, &[], 0, 1, &frames)
    }

    // ---- RFC test vectors ----

    #[test]
    fn rfc9001_key_derivation() {
        let (key, iv, hp) = derive_client_initial_secrets(QuicVersion::V1, &unhex(RFC_DCID));
        assert_eq!(key.to_vec(), unhex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv.to_vec(), unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp.to_vec(), unhex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn rfc9369_key_derivation() {
        let (key, iv, hp) = derive_client_initial_secrets(QuicVersion::V2, &unhex(RFC_DCID));
        assert_eq!(key.to_vec(), unhex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(iv.to_vec(), unhex("91f73e2351d8fa91660e909f"));
        assert_eq!(hp.to_vec(), unhex("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    #[test]
    fn rfc9001_client_initial_yields_sni() {
        let info = parse_quic_initial(&unhex(V1_CLIENT_INITIAL)).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.dcid, unhex(RFC_DCID));
        assert!(info.scid.is_empty());
        assert_eq!(info.sni(), Some("example.com"));
        assert_eq!(info.client_hello.as_ref().unwrap().alpn, vec![b"alpn".to_vec()]);
    }

    #[test]
    fn rfc9369_v2_client_initial_yields_sni() {
        let info = parse_quic_initial(&unhex(V2_CLIENT_INITIAL)).unwrap();
        assert_eq!(info.version, 0x6b3343cf);
        assert_eq!(info.dcid, unhex(RFC_DCID));
        assert_eq!(info.sni(), Some("example.com"));
    }

    #[test]
    fn seal_reproduces_rfc_vectors() {
        let frames = padded(unhex(V1_CLIENT_CRYPTO_FRAME), 1162);
        let dcid = unhex(RFC_DCID);
        let v1 = seal_client_initial(QuicVersion::V1, &dcid, &[], &[], 2, 4, &frames);
        assert_eq!(v1, unhex(V1_CLIENT_INITIAL));
        let v2 = seal_client_initial(QuicVersion::V2, &dcid, &[], &[], 2, 4, &frames);
        assert_eq!(v2, unhex(V2_CLIENT_INITIAL));
    }

    #[test]
    fn v2_retry_is_not_an_initial() {
        // v2 Retry uses type bits 00, which is Initial in v1.
        let err = parse_quic_initial(&unhex(V2_RETRY)).unwrap_err();
        assert!(matches!(err, QuicParseError::NotInitial(0)), "{err:?}");
    }

    #[test]
    fn v2_server_initial_is_rejected() {
        let err = parse_quic_initial(&unhex(V2_SERVER_INITIAL)).unwrap_err();
        assert!(matches!(err, QuicParseError::DecryptionFailed), "{err:?}");
    }

    #[test]
    fn v1_packet_relabelled_as_v2_is_rejected() {
        let mut pkt = unhex(V1_CLIENT_INITIAL);
        pkt[1..5].copy_from_slice(&0x6b3343cfu32.to_be_bytes());
        // Type bits 00 mean Retry in v2.
        assert!(matches!(
            parse_quic_initial(&pkt).unwrap_err(),
            QuicParseError::NotInitial(0)
        ));
        pkt[0] = (pkt[0] & !0x30) | 0x10;
        assert!(parse_quic_initial(&pkt).is_err());
    }

    #[test]
    fn unknown_version_is_not_guessed() {
        let mut pkt = unhex(V1_CLIENT_INITIAL);
        pkt[1..5].copy_from_slice(&0xff00001du32.to_be_bytes()); // draft-29
        assert!(matches!(
            parse_quic_initial(&pkt).unwrap_err(),
            QuicParseError::UnsupportedVersion(0xff00001d)
        ));
    }

    #[test]
    fn fixed_bit_must_be_set() {
        let mut pkt = unhex(V1_CLIENT_INITIAL);
        pkt[0] &= !0x40;
        assert!(matches!(
            parse_quic_initial(&pkt).unwrap_err(),
            QuicParseError::FixedBitUnset
        ));
    }

    #[test]
    fn every_truncation_is_rejected() {
        let pkt = unhex(V1_CLIENT_INITIAL);
        for len in 0..pkt.len() {
            assert!(parse_quic_initial(&pkt[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn every_single_byte_corruption_is_rejected() {
        let pkt = unhex(V1_CLIENT_INITIAL);
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 0x01;
            assert!(parse_quic_initial(&bad).is_err(), "byte {i}");
        }
    }

    // ---- Header / datagram structure ----

    #[test]
    fn parse_quic_initial_extracts_sni() {
        let pkt = build_quic_initial("example.com", &[0x01, 0x02, 0x03, 0x04], &[0x05]);
        let info = parse_quic_initial(&pkt).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.dcid, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(info.scid, vec![0x05]);
        assert_eq!(info.sni(), Some("example.com"));
    }

    #[test]
    fn parse_quic_initial_long_sni() {
        let pkt = build_quic_initial("very.long.subdomain.example.org", &[0xAA, 0xBB], &[]);
        let info = parse_quic_initial(&pkt).unwrap();
        assert_eq!(info.sni(), Some("very.long.subdomain.example.org"));
        assert_eq!(info.scid, Vec::<u8>::new());
    }

    #[test]
    fn parse_quic_initial_empty_dcid() {
        let pkt = build_quic_initial("test.example.com", &[], &[0x01]);
        let info = parse_quic_initial(&pkt).unwrap();
        assert_eq!(info.dcid, Vec::<u8>::new());
        assert_eq!(info.sni(), Some("test.example.com"));
    }

    #[test]
    fn token_is_skipped() {
        let frames = padded(crypto_frame(0, &build_client_hello("tok.example")), 1100);
        let pkt = seal_client_initial(QuicVersion::V1, &[9; 8], &[], &[0xAB; 70], 0, 2, &frames);
        assert_eq!(parse_quic_initial(&pkt).unwrap().sni(), Some("tok.example"));
    }

    #[test]
    fn oversized_connection_id_is_rejected() {
        let mut data = vec![0xC0, 0, 0, 0, 1, 21];
        data.extend_from_slice(&[0u8; 60]);
        assert!(matches!(
            parse_quic_initial(&data).unwrap_err(),
            QuicParseError::ConnectionIdTooLong
        ));
    }

    #[test]
    fn length_beyond_datagram_is_rejected() {
        let mut pkt = build_quic_initial("example.com", &[1; 8], &[]);
        pkt.truncate(pkt.len() - 1);
        assert!(parse_quic_initial(&pkt).is_err());
    }

    #[test]
    fn trailing_padding_after_packet_is_ignored() {
        let mut pkt = build_quic_initial("example.com", &[1; 8], &[]);
        pkt.extend_from_slice(&[0u8; 50]);
        assert_eq!(parse_quic_initial(&pkt).unwrap().sni(), Some("example.com"));
    }

    #[test]
    fn coalesced_handshake_packet_is_skipped() {
        let dcid = [7u8; 8];
        let mut pkt = build_quic_initial("example.com", &dcid, &[]);
        // v1 Handshake long header with a 20-byte (opaque) body.
        pkt.extend_from_slice(&[0xE0, 0, 0, 0, 1, 8]);
        pkt.extend_from_slice(&dcid);
        pkt.extend_from_slice(&[0, 20]);
        pkt.extend_from_slice(&[0x55; 20]);
        assert_eq!(parse_quic_initial(&pkt).unwrap().sni(), Some("example.com"));
    }

    #[test]
    fn coalesced_initials_split_client_hello() {
        let dcid = [3u8; 8];
        let ch = build_client_hello("split.example");
        let (a, b) = ch.split_at(30);
        let mut dgram = seal_client_initial(QuicVersion::V1, &dcid, &[], &[], 0, 1, &crypto_frame(0, a));
        let second = padded(crypto_frame(a.len() as u64, b), 1000);
        dgram.extend(seal_client_initial(QuicVersion::V1, &dcid, &[], &[], 1, 1, &second));
        assert_eq!(parse_quic_initial(&dgram).unwrap().sni(), Some("split.example"));
    }

    #[test]
    fn reject_short_header() {
        let data = vec![0x40, 0x00, 0x00, 0x01, 0x00];
        let err = parse_quic_initial(&data).unwrap_err();
        assert!(matches!(err, QuicParseError::NotLongHeader));
    }

    #[test]
    fn reject_handshake_packet_type() {
        let data = vec![0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00];
        let err = parse_quic_initial(&data).unwrap_err();
        assert!(matches!(err, QuicParseError::NotInitial(2)));
    }

    #[test]
    fn reject_version_negotiation() {
        let mut data = vec![0xC0];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // version 0
        data.push(0x04);
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        data.push(0x00);
        let err = parse_quic_initial(&data).unwrap_err();
        assert!(matches!(err, QuicParseError::UnsupportedVersion(0)));
    }

    #[test]
    fn reject_empty_data() {
        let err = parse_quic_initial(&[]).unwrap_err();
        assert!(matches!(err, QuicParseError::TooShort));
    }

    #[test]
    fn reject_truncated_header() {
        let data = vec![0xC0, 0x00, 0x00];
        let err = parse_quic_initial(&data).unwrap_err();
        assert!(matches!(err, QuicParseError::TooShort));
    }

    #[test]
    fn unprotected_payload_is_rejected() {
        // The old parser accepted plaintext CRYPTO frames; real Initials
        // are always protected, so plaintext must not authenticate.
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let mut data = vec![0xC0, 0x00, 0x00, 0x00, 0x01, dcid.len() as u8];
        data.extend_from_slice(&dcid);
        data.extend_from_slice(&[0x00, 0x00]);
        let payload = padded([vec![0x00], crypto_frame(0, &build_client_hello("x.com"))].concat(), 60);
        encode_varint(payload.len() as u64, 2, &mut data);
        data.extend_from_slice(&payload);
        assert!(matches!(
            parse_quic_initial(&data).unwrap_err(),
            QuicParseError::DecryptionFailed
        ));
    }

    // ---- Frames ----

    #[test]
    fn chaos_protection_frames_are_walked() {
        // Chrome-style: CRYPTO split out of order, interleaved with PING,
        // PADDING and ACK frames.
        let ch = build_client_hello("chaos.example");
        let mut frames = vec![0x01, 0x00, 0x00];
        frames.extend(crypto_frame(40, &ch[40..]));
        frames.extend([0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00]); // ACK, 1 extra range
        frames.push(0x01);
        frames.extend([0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]); // ACK_ECN
        frames.extend(crypto_frame(0, &ch[..20]));
        frames.extend(crypto_frame(10, &ch[10..40])); // overlap, consistent
        let frames = padded(frames, 1100);
        let pkt = seal_client_initial(QuicVersion::V1, &[5; 8], &[], &[], 0, 1, &frames);
        assert_eq!(parse_quic_initial(&pkt).unwrap().sni(), Some("chaos.example"));
    }

    #[test]
    fn connection_close_frame_is_parsed() {
        let mut frames = vec![0x1c, 0x0a, 0x06, 0x03, b'b', b'a', b'd'];
        frames.extend(crypto_frame(0, &build_client_hello("cc.example")));
        let pkt = seal_client_initial(QuicVersion::V1, &[5; 8], &[], &[], 0, 1, &frames);
        assert_eq!(parse_quic_initial(&pkt).unwrap().sni(), Some("cc.example"));
    }

    #[test]
    fn disallowed_frame_is_rejected() {
        let mut frames = crypto_frame(0, &build_client_hello("s.example"));
        frames.extend([0x08, 0x00, 0x00]); // STREAM frame: not allowed in Initial
        let pkt = seal_client_initial(QuicVersion::V1, &[5; 8], &[], &[], 0, 1, &frames);
        assert!(matches!(
            parse_quic_initial(&pkt).unwrap_err(),
            QuicParseError::UnexpectedFrame(0x08)
        ));
    }

    #[test]
    fn truncated_frames_are_rejected() {
        let cases: &[&[u8]] = &[
            &[0x06, 0x00, 0x10, 0x01],           // CRYPTO length past end
            &[0x02, 0x00, 0x00, 0x05, 0x00],     // ACK claims 5 ranges
            &[0x1c, 0x00, 0x00, 0x20, 0x41],     // reason past end
            &[0x06, 0x40],                       // truncated varint
        ];
        for frames in cases {
            let pkt = seal_client_initial(QuicVersion::V1, &[5; 8], &[], &[], 0, 1, frames);
            assert!(
                matches!(parse_quic_initial(&pkt).unwrap_err(), QuicParseError::MalformedFrame),
                "{frames:?}"
            );
        }
    }

    #[test]
    fn inconsistent_crypto_overlap_is_rejected() {
        let ch = build_client_hello("o.example");
        let mut frames = crypto_frame(0, &ch);
        let mut altered = ch[..10].to_vec();
        altered[5] ^= 0xff;
        frames.extend(crypto_frame(0, &altered));
        let pkt = seal_client_initial(QuicVersion::V1, &[5; 8], &[], &[], 0, 1, &frames);
        assert!(matches!(
            parse_quic_initial(&pkt).unwrap_err(),
            QuicParseError::CryptoInconsistent
        ));
    }

    #[test]
    fn crypto_beyond_limit_is_rejected() {
        let frames = crypto_frame(MAX_CRYPTO_STREAM as u64, &[1]);
        let pkt = seal_client_initial(QuicVersion::V1, &[5; 8], &[], &[], 0, 1, &frames);
        assert!(matches!(
            parse_quic_initial(&pkt).unwrap_err(),
            QuicParseError::CryptoTooLarge
        ));
    }

    #[test]
    fn non_client_hello_crypto_is_rejected() {
        let frames = crypto_frame(0, &[0x02, 0x00, 0x00, 0x01, 0x00]);
        let pkt = seal_client_initial(QuicVersion::V1, &[5; 8], &[], &[], 0, 1, &frames);
        assert!(matches!(
            parse_quic_initial(&pkt).unwrap_err(),
            QuicParseError::NotClientHello
        ));
    }

    // ---- Multi-datagram reassembly ----

    fn two_datagram_client_hello(sni: &str, dcid: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // ~1.8 KB ClientHello, as with X25519MLKEM768 key shares.
        let ch = build_client_hello_padded(sni, 1750);
        let (a, b) = ch.split_at(1100);
        let d1 = seal_client_initial(QuicVersion::V1, dcid, &[], &[], 0, 1, &padded(crypto_frame(0, a), 1162));
        let d2 = seal_client_initial(
            QuicVersion::V1,
            dcid,
            &[],
            &[],
            1,
            1,
            &padded(crypto_frame(a.len() as u64, b), 1162),
        );
        (d1, d2)
    }

    #[test]
    fn reassembler_joins_client_hello_across_datagrams() {
        let (d1, d2) = two_datagram_client_hello("pq.example", &[0x11; 8]);
        // Stateless parsing sees an incomplete ClientHello.
        assert!(parse_quic_initial(&d1).unwrap().client_hello.is_none());
        assert!(parse_quic_initial(&d2).unwrap().client_hello.is_none());

        let mut r = ClientInitialReassembler::new();
        assert!(r.feed(&d1).unwrap().client_hello.is_none());
        assert_eq!(r.feed(&d2).unwrap().sni(), Some("pq.example"));
        // Retransmissions keep reporting it.
        assert_eq!(r.feed(&d1).unwrap().sni(), Some("pq.example"));
    }

    #[test]
    fn reassembler_handles_reordering_and_junk() {
        let (d1, d2) = two_datagram_client_hello("pq.example", &[0x11; 8]);
        let mut r = ClientInitialReassembler::new();
        assert!(r.feed(&d2).unwrap().client_hello.is_none());
        // Garbage and a server Initial in between leave the state intact.
        assert!(r.feed(&[0xC0, 0, 0]).is_err());
        assert!(r.feed(&unhex(V2_SERVER_INITIAL)).is_err());
        let mut corrupted = d1.clone();
        corrupted[100] ^= 1;
        assert!(r.feed(&corrupted).is_err());
        assert_eq!(r.feed(&d1).unwrap().sni(), Some("pq.example"));
    }

    #[test]
    fn reassembler_restarts_on_new_dcid() {
        let (d1, _) = two_datagram_client_hello("old.example", &[0x11; 8]);
        let mut r = ClientInitialReassembler::new();
        r.feed(&d1).unwrap();
        // e.g. after a Retry: new DCID, CRYPTO restarts at offset 0
        let fresh = build_quic_initial("new.example", &[0x22; 8], &[]);
        let info = r.feed(&fresh).unwrap();
        assert_eq!(info.dcid, vec![0x22; 8]);
        assert_eq!(info.sni(), Some("new.example"));
    }

    // ---- Robustness ----

    /// xorshift64* PRNG for deterministic fuzzing
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    #[test]
    fn random_input_never_panics() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let valid = unhex(V1_CLIENT_INITIAL);
        let headers: [&[u8]; 3] = [&[0xC0, 0, 0, 0, 1], &[0xD0, 0x6b, 0x33, 0x43, 0xcf], &[]];
        let mut r = ClientInitialReassembler::new();
        for i in 0..20_000 {
            let len = (rng.next() % 1500) as usize;
            let mut data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let prefix = headers[i % 3];
            if data.len() >= prefix.len() {
                data[..prefix.len()].copy_from_slice(prefix);
            }
            let _ = parse_quic_initial(&data);
            let _ = r.feed(&data);

            // Random multi-byte mutation of a valid packet
            let mut m = valid.clone();
            for _ in 0..1 + rng.next() % 4 {
                let pos = (rng.next() as usize) % m.len();
                m[pos] = rng.next() as u8;
            }
            m.truncate((rng.next() as usize) % (m.len() + 1) + 1);
            let _ = parse_quic_initial(&m);
        }
    }

    #[test]
    fn random_frames_never_panic() {
        // Exercise the frame walker and reassembly on authenticated garbage.
        let mut rng = Rng(42);
        for _ in 0..2_000 {
            let len = 1 + (rng.next() % 64) as usize;
            let frames: Vec<u8> = (0..len)
                .map(|_| match rng.next() % 4 {
                    0 => [0x00, 0x01, 0x02, 0x03, 0x06, 0x1c][(rng.next() % 6) as usize],
                    _ => rng.next() as u8,
                })
                .collect();
            let pkt = seal_client_initial(QuicVersion::V1, &[1; 8], &[], &[], 0, 1, &frames);
            let _ = parse_quic_initial(&pkt);
        }
    }

    // ---- Varints / packet numbers ----

    #[test]
    fn decode_varint_1byte() {
        let (val, len) = decode_varint(&[0x25]).unwrap();
        assert_eq!(val, 37);
        assert_eq!(len, 1);
    }

    #[test]
    fn decode_varint_2byte() {
        let (val, len) = decode_varint(&[0x7b, 0xbd]).unwrap();
        assert_eq!(len, 2);
        assert_eq!(val, 15293);
    }

    #[test]
    fn decode_varint_4byte() {
        let (val, len) = decode_varint(&[0x9d, 0x7f, 0x3e, 0x7d]).unwrap();
        assert_eq!(len, 4);
        assert_eq!(val, 494878333);
    }

    #[test]
    fn decode_varint_8byte() {
        let (val, len) =
            decode_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]).unwrap();
        assert_eq!(len, 8);
        assert_eq!(val, 151288809941952652);
    }

    #[test]
    fn decode_varint_empty() {
        let err = decode_varint(&[]).unwrap_err();
        assert!(matches!(err, QuicParseError::InvalidVarInt));
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, VARINT_MAX] {
            let mut buf = Vec::new();
            encode_varint(v, 1, &mut buf);
            assert_eq!(decode_varint(&buf).unwrap(), (v, buf.len()));
        }
    }

    #[test]
    fn packet_number_decoding_rfc9000_example() {
        // RFC 9000 Appendix A.3
        assert_eq!(decode_packet_number(Some(0xa82f30ea), 0x9b32, 16), 0xa82f9b32);
        assert_eq!(decode_packet_number(None, 2, 32), 2);
    }
}
