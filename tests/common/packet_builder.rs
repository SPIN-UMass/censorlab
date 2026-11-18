//! Builds raw Ethernet frames wrapping IPv4 + TCP/UDP packets.
//!
//! The Ethernet header is 14 bytes:
//!   dst_mac(6) + src_mac(6) + ethertype(2)
//!
//! Reuses the same IP/TCP/UDP construction patterns from `src/program/packet.rs`
//! unit tests, with the addition of the Ethernet framing.

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
#[allow(dead_code)]
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
#[allow(dead_code)]
pub const TCP_RST: u8 = 0x04;
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
    dns_query_typed(domain, 1, false)
}

/// Build a DNS query payload with an arbitrary QTYPE (class IN), optionally
/// carrying an EDNS(0) OPT pseudo-RR in the additional section, as browsers do.
pub fn dns_query_typed(domain: &str, qtype: u16, edns: bool) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header (12 bytes)
    buf.extend_from_slice(&[0x00, 0x01]); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    buf.extend_from_slice(&[0x00, u8::from(edns)]); // ARCOUNT

    // QNAME
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label

    // QTYPE, QCLASS = IN (1)
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]);

    if edns {
        // OPT RR: root owner, TYPE=41, CLASS=UDP size 1232, TTL=0 (ext-rcode,
        // version, flags), RDLENGTH=0
        buf.push(0x00);
        buf.extend_from_slice(&41u16.to_be_bytes());
        buf.extend_from_slice(&1232u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&[0x00, 0x00]);
    }

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
    tls_client_hello_record_padded(sni, 0)
}

/// Build a TLS ClientHello record with a padding extension of `padding` bytes.
///
/// With ~1500 bytes of padding this is the size of a ClientHello carrying a post-quantum
/// key share, which no longer fits in a single TCP segment.
pub fn tls_client_hello_record_padded(sni: &str, padding: usize) -> Vec<u8> {
    tls_client_hello_record_with_extensions(sni, padding, &[])
}

/// Build a TLS ClientHello record that also carries the given `(type, data)`
/// extensions after SNI and supported_versions (e.g. ESNI `0xffce`, ECH `0xfe0d`).
pub fn tls_client_hello_record_with_extensions(
    sni: &str,
    padding: usize,
    extra: &[(u16, &[u8])],
) -> Vec<u8> {
    let msg = tls_client_hello_message(sni, padding, extra);
    let mut record = Vec::with_capacity(5 + msg.len());
    record.push(22); // content type: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    record.push(((msg.len() >> 8) & 0xff) as u8);
    record.push((msg.len() & 0xff) as u8);
    record.extend_from_slice(&msg);
    record
}

/// Build a TLS ClientHello handshake message (without record header).
fn tls_client_hello_message(sni: &str, padding: usize, extra: &[(u16, &[u8])]) -> Vec<u8> {
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

    // caller-supplied extensions
    for (ty, data) in extra {
        extensions.extend_from_slice(&ty.to_be_bytes());
        extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(data);
    }

    // padding extension
    if padding > 0 {
        extensions.extend_from_slice(&[0x00, 0x15]);
        extensions.push(((padding >> 8) & 0xff) as u8);
        extensions.push((padding & 0xff) as u8);
        extensions.extend(std::iter::repeat_n(0u8, padding));
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

/// Build an SSH version banner payload (e.g. "SSH-2.0-OpenSSH_8.9\r\n").
pub fn ssh_banner() -> Vec<u8> {
    b"SSH-2.0-OpenSSH_8.9\r\n".to_vec()
}

/// Build a deterministic high-entropy payload of the given length.
///
/// For lengths <= 256, produces a permutation of byte values using a
/// linear congruential map `(i * 167 + 89) mod 256`, guaranteeing
/// maximum Shannon entropy (each byte value appears exactly once).
/// For longer payloads, the pattern repeats with different offsets.
/// Average popcount is ~4.0 (half of 8 bits).
pub fn high_entropy_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i.wrapping_mul(167).wrapping_add(89)) & 0xFF) as u8)
        .collect()
}

/// QUIC client Initial DCID used by the fixtures below.
const QUIC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// Seal one protected (RFC 9001) QUIC v1 client Initial whose frames are
/// `frames`, padded to the 1162-byte payload real clients use.
fn sealed_initial(pn: u64, mut frames: Vec<u8>) -> Vec<u8> {
    use censorlab::application::quic::{seal_client_initial, QuicVersion};
    frames.resize(frames.len().max(1162), 0x00); // PADDING frames
    seal_client_initial(QuicVersion::V1, &QUIC_DCID, &[], &[], pn, 1, &frames)
}

/// Build a protected QUIC v1 client Initial carrying a TLS ClientHello with
/// the given SNI, encrypted with the Initial keys derived from its DCID
/// exactly as a real client would.
pub fn quic_initial_packet(sni: &str) -> Vec<u8> {
    use censorlab::application::quic::crypto_frame;
    sealed_initial(0, crypto_frame(0, &tls_client_hello_message(sni, 0, &[])))
}

/// Two protected client Initial datagrams of one connection whose
/// ClientHello (with the given SNI) is split between them, like large
/// post-quantum ClientHellos. Neither datagram alone contains the full SNI.
pub fn quic_initial_split_datagrams(sni: &str) -> (Vec<u8>, Vec<u8>) {
    use censorlab::application::quic::crypto_frame;
    let ch = tls_client_hello_message(sni, 0, &[]);
    // Split inside the SNI value.
    let sni_pos = ch
        .windows(sni.len())
        .position(|w| w == sni.as_bytes())
        .expect("SNI is in the ClientHello");
    let split = sni_pos + sni.len() / 2;
    let first = sealed_initial(0, crypto_frame(0, &ch[..split]));
    let second = sealed_initial(1, crypto_frame(split as u64, &ch[split..]));
    (first, second)
}

// ---------------------------------------------------------------------------
// Arbitrary IP payloads (ICMP, unknown protocols, IPv6 extension headers)
// ---------------------------------------------------------------------------

/// Build an Ethernet frame containing an IPv4 packet with an arbitrary protocol
/// number and raw (already-encoded) payload.
pub fn ipv4_raw_frame(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[2] = (total_len >> 8) as u8;
    buf[3] = total_len as u8;
    buf[8] = 64;
    buf[9] = protocol;
    buf[12..16].copy_from_slice(&src_ip);
    buf[16..20].copy_from_slice(&dst_ip);
    let ck = ipv4_checksum(&buf[..20]);
    buf[10] = (ck >> 8) as u8;
    buf[11] = ck as u8;
    buf[20..].copy_from_slice(payload);
    ethernet_wrap(0x0800, &buf)
}

/// Build an Ethernet frame containing an IPv6 packet whose fixed header has the
/// given next-header value, followed by `payload` verbatim (which may begin with
/// extension headers).
pub fn ipv6_raw_frame(src_ip: [u8; 16], dst_ip: [u8; 16], next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 40 + payload.len()];
    buf[0] = 0x60;
    buf[4] = (payload.len() >> 8) as u8;
    buf[5] = payload.len() as u8;
    buf[6] = next_header;
    buf[7] = 64;
    buf[8..24].copy_from_slice(&src_ip);
    buf[24..40].copy_from_slice(&dst_ip);
    buf[40..].copy_from_slice(payload);
    ethernet_wrap(0x86DD, &buf)
}

/// A minimal ICMP/ICMPv6 echo request (type 8 or 128, code 0, no data).
/// The checksum is left zero; CensorLab does not verify it.
pub fn icmp_echo(icmp_type: u8) -> Vec<u8> {
    vec![icmp_type, 0, 0, 0, 0, 1, 0, 1]
}

/// A raw 20-byte TCP header (no checksum), for embedding with [`ipv6_raw_frame`].
pub fn raw_tcp_header(src_port: u16, dst_port: u16, flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14] = 0xFF;
    tcp[15] = 0xFF;
    tcp
}

/// Overwrite the IPv4 TTL of an Ethernet-framed IPv4 packet and fix the
/// header checksum.  Used to emulate low-TTL "fake" segments.
pub fn set_ipv4_ttl(frame: &mut [u8], ttl: u8) {
    let ip = &mut frame[14..];
    ip[8] = ttl;
    ip[10] = 0;
    ip[11] = 0;
    let ck = ipv4_checksum(&ip[..20]);
    ip[10] = (ck >> 8) as u8;
    ip[11] = ck as u8;
}

/// Build an Ethernet frame containing one IPv4 fragment: `payload` sits at byte
/// `offset` (a multiple of 8) of the original packet's payload.
pub fn ipv4_fragment_frame(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    ident: u16,
    offset: u16,
    more: bool,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[2] = (total_len >> 8) as u8;
    buf[3] = total_len as u8;
    buf[4..6].copy_from_slice(&ident.to_be_bytes());
    let flags_offset = (u16::from(more) << 13) | (offset / 8);
    buf[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    buf[8] = ttl;
    buf[9] = 17;
    buf[12..16].copy_from_slice(&src_ip);
    buf[16..20].copy_from_slice(&dst_ip);
    let ck = ipv4_checksum(&buf[..20]);
    buf[10] = (ck >> 8) as u8;
    buf[11] = ck as u8;
    buf[20..].copy_from_slice(payload);
    ethernet_wrap(0x0800, &buf)
}
