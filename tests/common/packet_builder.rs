/// Builds raw Ethernet frames wrapping IPv4 + TCP/UDP packets.
///
/// The Ethernet header is 14 bytes:
///   dst_mac(6) + src_mac(6) + ethertype(2)
///
/// Reuses the same IP/TCP/UDP construction patterns from `src/program/packet.rs`
/// unit tests, with the addition of the Ethernet framing.

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // skip checksum field
        }
        let word = (header[i] as u32) << 8
            | if i + 1 < header.len() {
                header[i + 1] as u32
            } else {
                0
            };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

// ---------------------------------------------------------------------------
// Ethernet framing
// ---------------------------------------------------------------------------

fn ethernet_wrap(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    frame.push((ethertype >> 8) as u8);
    frame.push(ethertype as u8);
    frame.extend_from_slice(payload);
    frame
}

// ---------------------------------------------------------------------------
// IPv4 + TCP
// ---------------------------------------------------------------------------

fn build_ipv4_tcp_raw(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len;
    let mut buf = vec![0u8; total_len];

    // IPv4 header (20 bytes)
    buf[0] = 0x45;
    buf[2] = (total_len >> 8) as u8;
    buf[3] = total_len as u8;
    buf[8] = 64; // TTL
    buf[9] = 6; // TCP
    buf[12..16].copy_from_slice(&src_ip);
    buf[16..20].copy_from_slice(&dst_ip);
    let ck = ipv4_checksum(&buf[..20]);
    buf[10] = (ck >> 8) as u8;
    buf[11] = ck as u8;

    // TCP header (20 bytes)
    let tcp = &mut buf[20..];
    tcp[0] = (src_port >> 8) as u8;
    tcp[1] = src_port as u8;
    tcp[2] = (dst_port >> 8) as u8;
    tcp[3] = dst_port as u8;
    // seq
    tcp[4] = (seq >> 24) as u8;
    tcp[5] = (seq >> 16) as u8;
    tcp[6] = (seq >> 8) as u8;
    tcp[7] = seq as u8;
    // ack
    tcp[8] = (ack >> 24) as u8;
    tcp[9] = (ack >> 16) as u8;
    tcp[10] = (ack >> 8) as u8;
    tcp[11] = ack as u8;
    tcp[12] = 5 << 4; // data offset = 5
    tcp[13] = tcp_flags;
    tcp[14] = 0xFF; // window high
    tcp[15] = 0xFF; // window low
    tcp[20..20 + payload.len()].copy_from_slice(payload);

    buf
}

/// TCP flag constants
pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_PSH_ACK: u8 = 0x18;

/// Build an Ethernet frame containing an IPv4/TCP packet.
pub fn tcp_frame(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let ip_pkt = build_ipv4_tcp_raw(src_ip, dst_ip, src_port, dst_port, tcp_flags, seq, ack, payload);
    ethernet_wrap(0x0800, &ip_pkt)
}

// ---------------------------------------------------------------------------
// IPv4 + UDP
// ---------------------------------------------------------------------------

fn build_ipv4_udp_raw(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut buf = vec![0u8; total_len];

    // IPv4 header
    buf[0] = 0x45;
    buf[2] = (total_len >> 8) as u8;
    buf[3] = total_len as u8;
    buf[8] = 64;
    buf[9] = 17; // UDP
    buf[12..16].copy_from_slice(&src_ip);
    buf[16..20].copy_from_slice(&dst_ip);
    let ck = ipv4_checksum(&buf[..20]);
    buf[10] = (ck >> 8) as u8;
    buf[11] = ck as u8;

    // UDP header
    let udp = &mut buf[20..];
    udp[0] = (src_port >> 8) as u8;
    udp[1] = src_port as u8;
    udp[2] = (dst_port >> 8) as u8;
    udp[3] = dst_port as u8;
    udp[4] = (udp_len >> 8) as u8;
    udp[5] = udp_len as u8;
    udp[8..8 + payload.len()].copy_from_slice(payload);

    buf
}

/// Build an Ethernet frame containing an IPv4/UDP packet.
pub fn udp_frame(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_pkt = build_ipv4_udp_raw(src_ip, dst_ip, src_port, dst_port, payload);
    ethernet_wrap(0x0800, &ip_pkt)
}

// ---------------------------------------------------------------------------
// Application-layer payload builders
// ---------------------------------------------------------------------------

/// Build a DNS query payload for `domain`.
///
/// Constructs a minimal DNS query (QR=0, OPCODE=0, 1 question, type A, class IN).
pub fn dns_query(domain: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header (12 bytes)
    buf.extend_from_slice(&[0x00, 0x01]); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // QNAME
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label

    // QTYPE = A (1), QCLASS = IN (1)
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x01]);

    buf
}

/// Build an HTTP GET request payload.
pub fn http_get(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")
        .into_bytes()
}

/// Build a TLS ClientHello record (with record header) containing the given SNI.
///
/// This produces a full TLS record suitable as a TCP payload.
pub fn tls_client_hello_record(sni: &str) -> Vec<u8> {
    let msg = tls_client_hello_message(sni);
    let mut record = Vec::with_capacity(5 + msg.len());
    record.push(22); // content type: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    record.push(((msg.len() >> 8) & 0xff) as u8);
    record.push((msg.len() & 0xff) as u8);
    record.extend_from_slice(&msg);
    record
}

/// Build a TLS ClientHello handshake message (without record header).
fn tls_client_hello_message(sni: &str) -> Vec<u8> {
    let mut extensions = Vec::new();

    // SNI extension
    let sni_bytes = sni.as_bytes();
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

/// Build a QUIC Initial packet (unencrypted) wrapping a TLS ClientHello with the given SNI.
///
/// The payload is NOT encrypted — suitable for testing the QUIC parser.
pub fn quic_initial_packet(sni: &str) -> Vec<u8> {
    let ch = tls_client_hello_message(sni);

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

    let dcid: &[u8] = &[0x01, 0x02, 0x03, 0x04];
    let scid: &[u8] = &[];

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
