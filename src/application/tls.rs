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
