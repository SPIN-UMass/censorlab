use super::tls;
use thiserror::Error;

/// Errors that can occur when parsing a QUIC Initial packet
#[derive(Debug, Error)]
pub enum QuicParseError {
    #[error("Packet too short")]
    TooShort,
    #[error("Not a QUIC long header packet")]
    NotLongHeader,
    #[error("Unsupported QUIC version: {0:#x}")]
    UnsupportedVersion(u32),
    #[error("Not a QUIC Initial packet (type={0})")]
    NotInitial(u8),
    #[error("Invalid variable-length integer")]
    InvalidVarInt,
    #[error("TLS parse error: {0}")]
    TlsError(#[from] tls::TlsParseError),
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
    /// TLS ClientHello info extracted from the CRYPTO frame, if found
    pub client_hello: Option<tls::ClientHelloInfo>,
}

impl QuicInitialInfo {
    /// Convenience: get the SNI from the ClientHello, if present.
    pub fn sni(&self) -> Option<&str> {
        self.client_hello.as_ref().and_then(|ch| ch.sni.as_deref())
    }
}

/// Decode a QUIC variable-length integer (RFC 9000, Section 16).
/// Returns (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> Result<(u64, usize), QuicParseError> {
    if data.is_empty() {
        return Err(QuicParseError::InvalidVarInt);
    }
    let prefix = data[0] >> 6;
    let length = 1usize << prefix;
    if data.len() < length {
        return Err(QuicParseError::InvalidVarInt);
    }
    let mut value = (data[0] as u64) & 0x3f;
    for i in 1..length {
        value = (value << 8) | (data[i] as u64);
    }
    Ok((value, length))
}

/// Parse a QUIC Initial packet and extract connection info + TLS ClientHello.
///
/// This handles the *unencrypted* portion of a QUIC Initial packet.
/// In a real QUIC Initial, the payload after the header is encrypted with
/// Initial keys derived from the DCID. For censorship purposes, many censors
/// inspect the raw bytes looking for patterns, or derive the Initial keys to
/// decrypt. This parser:
///
/// - Parses the QUIC long header (version, DCID, SCID, token, length)
/// - Attempts to find a CRYPTO frame in the payload (works for unprotected
///   test fixtures or pre-decrypted packets)
/// - Extracts TLS ClientHello info (SNI, ALPN, supported versions) if found
///
/// For encrypted payloads, `client_hello` will be `None`.
pub fn parse_quic_initial(data: &[u8]) -> Result<QuicInitialInfo, QuicParseError> {
    if data.is_empty() {
        return Err(QuicParseError::TooShort);
    }

    // Check long header bit (bit 7 of first byte must be 1)
    if data[0] & 0x80 == 0 {
        return Err(QuicParseError::NotLongHeader);
    }

    // Packet type is bits 4-5
    let packet_type = (data[0] & 0x30) >> 4;

    // Initial = 0x00
    if packet_type != 0x00 {
        return Err(QuicParseError::NotInitial(packet_type));
    }

    if data.len() < 5 {
        return Err(QuicParseError::TooShort);
    }

    // Version (4 bytes)
    let version = ((data[1] as u32) << 24)
        | ((data[2] as u32) << 16)
        | ((data[3] as u32) << 8)
        | (data[4] as u32);

    // Version 0 = version negotiation, not an Initial
    if version == 0 {
        return Err(QuicParseError::UnsupportedVersion(0));
    }

    let mut pos = 5;

    // DCID length (1 byte) + DCID
    if pos >= data.len() {
        return Err(QuicParseError::TooShort);
    }
    let dcid_len = data[pos] as usize;
    pos += 1;
    if pos + dcid_len > data.len() {
        return Err(QuicParseError::TooShort);
    }
    let dcid = data[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    // SCID length (1 byte) + SCID
    if pos >= data.len() {
        return Err(QuicParseError::TooShort);
    }
    let scid_len = data[pos] as usize;
    pos += 1;
    if pos + scid_len > data.len() {
        return Err(QuicParseError::TooShort);
    }
    let scid = data[pos..pos + scid_len].to_vec();
    pos += scid_len;

    // Token length (variable-length integer) + token
    if pos >= data.len() {
        return Err(QuicParseError::TooShort);
    }
    let (token_len, token_varint_size) = decode_varint(&data[pos..])?;
    pos += token_varint_size;
    pos += token_len as usize;

    // Packet length (variable-length integer)
    if pos >= data.len() {
        return Err(QuicParseError::TooShort);
    }
    let (_pkt_len, pkt_len_varint_size) = decode_varint(&data[pos..])?;
    pos += pkt_len_varint_size;

    // The remaining bytes are the protected payload.
    // Try to find a CRYPTO frame and extract TLS ClientHello.
    let client_hello = extract_client_hello_from_payload(&data[pos..]);

    Ok(QuicInitialInfo {
        version,
        dcid,
        scid,
        client_hello,
    })
}

/// Attempt to extract a TLS ClientHello by scanning the payload for a CRYPTO frame.
///
/// QUIC CRYPTO frame format:
///   - type: 0x06 (1 byte)
///   - offset: variable-length integer
///   - length: variable-length integer
///   - data: TLS handshake bytes
fn extract_client_hello_from_payload(payload: &[u8]) -> Option<tls::ClientHelloInfo> {
    if payload.is_empty() {
        return None;
    }

    // After the packet number (which we can't reliably determine the length of
    // without decryption), try scanning with different PN length assumptions (1-4 bytes).
    for pn_len in 1..=4 {
        if pn_len >= payload.len() {
            continue;
        }
        if let Some(info) = try_parse_crypto_frame(&payload[pn_len..]) {
            return Some(info);
        }
    }

    None
}

/// Try to parse a CRYPTO frame at the start of the given data and extract ClientHello.
fn try_parse_crypto_frame(data: &[u8]) -> Option<tls::ClientHelloInfo> {
    if data.is_empty() {
        return None;
    }

    let mut pos = 0;

    // Walk through frames
    while pos < data.len() {
        let frame_type = data[pos];

        // PADDING frame (type 0x00) — skip
        if frame_type == 0x00 {
            pos += 1;
            continue;
        }

        // CRYPTO frame (type 0x06)
        if frame_type == 0x06 {
            pos += 1;
            // offset (varint)
            let (_, offset_size) = decode_varint(data.get(pos..)?).ok()?;
            pos += offset_size;
            // length (varint)
            let (crypto_len, len_size) = decode_varint(data.get(pos..)?).ok()?;
            pos += len_size;
            let crypto_data = data.get(pos..pos + crypto_len as usize)?;
            // The CRYPTO frame data is a raw TLS handshake message (no record header)
            return tls::parse_client_hello_message(crypto_data).ok();
        }

        // Unknown frame type — can't continue parsing
        break;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello handshake message with the given SNI.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sn_entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_data_len = 2 + sn_entry_len;
        let ext_total = 4 + sni_ext_data_len;
        let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_total;

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

        buf.push(((ext_total >> 8) & 0xff) as u8);
        buf.push((ext_total & 0xff) as u8);
        buf.extend_from_slice(&[0x00, 0x00]); // SNI extension type
        buf.push(((sni_ext_data_len >> 8) & 0xff) as u8);
        buf.push((sni_ext_data_len & 0xff) as u8);
        buf.push(((sn_entry_len >> 8) & 0xff) as u8);
        buf.push((sn_entry_len & 0xff) as u8);
        buf.push(0x00); // host_name
        buf.push(((sni_bytes.len() >> 8) & 0xff) as u8);
        buf.push((sni_bytes.len() & 0xff) as u8);
        buf.extend_from_slice(sni_bytes);

        buf
    }

    /// Build a minimal QUIC Initial packet wrapping a TLS ClientHello with SNI.
    /// The payload is NOT encrypted (suitable for testing).
    fn build_quic_initial(sni: &str, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let ch = build_client_hello(sni);

        // CRYPTO frame
        let mut crypto_frame = Vec::new();
        crypto_frame.push(0x06); // CRYPTO frame type
        crypto_frame.push(0x00); // offset = 0
        if ch.len() < 64 {
            crypto_frame.push(ch.len() as u8);
        } else {
            let len = ch.len() as u16;
            crypto_frame.push(0x40 | ((len >> 8) as u8));
            crypto_frame.push((len & 0xff) as u8);
        }
        crypto_frame.extend_from_slice(&ch);

        // Packet number (1 byte)
        let pn = vec![0x00u8];
        let payload = [pn.as_slice(), crypto_frame.as_slice()].concat();

        // QUIC long header
        let mut buf = Vec::new();
        buf.push(0xC0); // Initial long header
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
        buf.push(dcid.len() as u8);
        buf.extend_from_slice(dcid);
        buf.push(scid.len() as u8);
        buf.extend_from_slice(scid);
        buf.push(0x00); // token length: 0
        if payload.len() < 64 {
            buf.push(payload.len() as u8);
        } else {
            let len = payload.len() as u16;
            buf.push(0x40 | ((len >> 8) as u8));
            buf.push((len & 0xff) as u8);
        }
        buf.extend_from_slice(&payload);

        buf
    }

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
    fn encrypted_payload_returns_no_client_hello() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let mut data = vec![0xC0];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.push(dcid.len() as u8);
        data.extend_from_slice(&dcid);
        data.push(0x00); // scid len = 0
        data.push(0x00); // token len = 0
        let fake_payload = vec![0xAB; 50];
        data.push(fake_payload.len() as u8);
        data.extend_from_slice(&fake_payload);

        let info = parse_quic_initial(&data).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.dcid, dcid.to_vec());
        assert!(info.client_hello.is_none());
    }

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
    fn decode_varint_empty() {
        let err = decode_varint(&[]).unwrap_err();
        assert!(matches!(err, QuicParseError::InvalidVarInt));
    }
}
