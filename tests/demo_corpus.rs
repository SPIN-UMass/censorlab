//! PCAP-mode tests for the demos that emulate specific documented censors
//! (`gfw_*`, `iran_*`, `tspu_*`, `turkmenistan`, `openvpn_fingerprint`,
//! `snowflake_dtls`).
//!
//! Each test builds synthetic traffic, runs the shipped demo config through
//! the real binary, and checks the complete list of actions: the flows the
//! demo must act on, and similar flows it must leave alone. Demos that ship a
//! CensorLang version are run under both configs.

// Test packet builders mirror wire formats: many header-field arguments and
// byte-by-byte pushes are clearer than the alternatives here.
#![allow(clippy::too_many_arguments, clippy::vec_init_then_push)]

// Not every builder is used by every test crate.
#[allow(dead_code)]
mod common;

use common::packet_builder::{
    dns_query, http_get, quic_initial_packet, quic_initial_split_datagrams, tcp_frame,
    tls_client_hello_record, tls_client_hello_record_with_extensions, udp_frame, TCP_ACK,
    TCP_PSH_ACK, TCP_SYN,
};
use common::pcap_builder::PcapBuilder;
use common::runner::{run_pcap_with_config, RunResult};
use std::path::PathBuf;
use tempfile::TempDir;

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [93, 184, 216, 34];

const PYCL: &str = "censor.toml";
const CENSORLANG: &str = "censor_lang.toml";

/// See `frame_idx` in pcap_integration.rs: the first frame is packet_index 2.
const FIRST_FRAME_INDEX: usize = 2;

/// Frames with capture timestamps. Each pushed frame is one second after the
/// previous one unless `wait` is called in between.
#[derive(Default)]
struct Capture {
    now: u32,
    frames: Vec<(u32, Vec<u8>)>,
}

impl Capture {
    /// Append a frame and return its index.
    fn push(&mut self, frame: Vec<u8>) -> usize {
        self.now += 1;
        self.frames.push((self.now, frame));
        self.frames.len() - 1
    }

    /// Append frames and return the index of the last one.
    fn extend(&mut self, frames: Vec<Vec<u8>>) -> usize {
        for frame in frames {
            self.push(frame);
        }
        self.frames.len() - 1
    }

    /// Let `secs` seconds pass before the next frame.
    fn wait(&mut self, secs: u32) {
        self.now += secs;
    }

    /// Run `demos/<demo>/<config>` over the capture and return every action
    /// as (frame index, kind), in order.
    fn run(&self, demo: &str, config: &str) -> Vec<(usize, &'static str)> {
        let tmp = TempDir::new().unwrap();
        let pcap_path = tmp.path().join("test.pcap");
        let mut b = PcapBuilder::new();
        for (ts, frame) in &self.frames {
            b = b.add_frame_at(*ts, frame);
        }
        b.write_to(&pcap_path);
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("demos")
            .join(demo)
            .join(config);
        let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");
        assert_eq!(result.exit_code, 0, "{demo}/{config} stderr: {}", result.stderr);
        assert_clean(demo, config, &result);
        result
            .action_lines
            .iter()
            .map(|l| (l.packet_index - FIRST_FRAME_INDEX, kind(&l.action)))
            .collect()
    }
}

/// A demo must not rely on `on_script_error`: no script exception may occur.
fn assert_clean(demo: &str, config: &str, result: &RunResult) {
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        !combined.contains("raised") && !combined.contains("Traceback") && !combined.contains("Error processing"),
        "{demo}/{config} logged a script error:\n{combined}"
    );
}

fn kind(action: &str) -> &'static str {
    for k in ["Drop", "Reset", "Inject", "Delay", "Rewrite", "Ignore"] {
        if action.contains(k) {
            return k;
        }
    }
    panic!("unexpected action {action:?}");
}

fn all(kind: &'static str, frames: &[usize]) -> Vec<(usize, &'static str)> {
    frames.iter().map(|&f| (f, kind)).collect()
}

/// One TCP connection; tracks sequence numbers so segments are contiguous.
struct Flow {
    client: [u8; 4],
    server: [u8; 4],
    cport: u16,
    sport: u16,
    cseq: u32,
    sseq: u32,
}

impl Flow {
    /// A connection from `client:cport` to `server:sport`.
    fn new(client: [u8; 4], cport: u16, server: [u8; 4], sport: u16) -> Self {
        Self { client, server, cport, sport, cseq: 1000, sseq: 5000 }
    }

    /// SYN, SYN+ACK, ACK.
    fn handshake(&mut self) -> Vec<Vec<u8>> {
        let syn = tcp_frame(self.client, self.server, self.cport, self.sport, TCP_SYN, self.cseq, 0, &[]);
        self.cseq += 1;
        let synack = tcp_frame(
            self.server,
            self.client,
            self.sport,
            self.cport,
            TCP_SYN | TCP_ACK,
            self.sseq,
            self.cseq,
            &[],
        );
        self.sseq += 1;
        vec![syn, synack, self.client(&[])]
    }

    /// A segment from the client (a bare ACK if `payload` is empty).
    fn client(&mut self, payload: &[u8]) -> Vec<u8> {
        let flags = if payload.is_empty() { TCP_ACK } else { TCP_PSH_ACK };
        let frame =
            tcp_frame(self.client, self.server, self.cport, self.sport, flags, self.cseq, self.sseq, payload);
        self.cseq += payload.len() as u32;
        frame
    }

    /// A segment from the server.
    fn server(&mut self, payload: &[u8]) -> Vec<u8> {
        let flags = if payload.is_empty() { TCP_ACK } else { TCP_PSH_ACK };
        let frame =
            tcp_frame(self.server, self.client, self.sport, self.cport, flags, self.sseq, self.cseq, payload);
        self.sseq += payload.len() as u32;
        frame
    }

    /// Handshake followed by one client data segment.
    fn open_with(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = self.handshake();
        frames.push(self.client(payload));
        frames
    }
}

/// A ClientHello too large for one segment, as its two segments' payloads.
fn split_hello(sni: &str, extra: &[(u16, &[u8])]) -> (Vec<u8>, Vec<u8>) {
    let hello = tls_client_hello_record_with_extensions(sni, 1500, extra);
    assert!(hello.len() > 1460);
    let (first, second) = hello.split_at(1460);
    (first.to_vec(), second.to_vec())
}

// ==========================================================================
// iran_protocol_filter
// ==========================================================================

#[test]
fn test_demo_iran_protocol_filter() {
    const FILTERED: [u8; 4] = [104, 18, 0, 1];
    let mut cap = Capture::default();
    let mut dropped = Vec::new();

    // A: an HTTP request split so that neither of the first two data packets
    // looks like a known protocol. The second packet onwards is dropped,
    // the server's packets are not.
    let mut a = Flow::new(CLIENT, 50000, FILTERED, 80);
    cap.extend(a.open_with(b"G"));
    dropped.push(cap.push(a.client(b"ET / HTTP/1.1\r\nHost: example.org\r\n\r\n")));
    cap.push(a.server(b"HTTP/1.1 400 Bad Request\r\n\r\n"));
    dropped.push(cap.push(a.client(b"more")));
    // 60 s without a packet: the blackhole is lifted
    cap.wait(61);
    cap.push(a.client(b"later"));

    // B: a normal GET, then anything
    let mut b = Flow::new(CLIENT, 50001, FILTERED, 80);
    cap.extend(b.open_with(&http_get("example.org", "/")));
    cap.push(b.client(&[0x00, 0x01, 0x02, 0x03]));

    // C: the same split request to an address the filter does not cover
    let mut c = Flow::new(CLIENT, 50002, SERVER, 80);
    cap.extend(c.open_with(b"G"));
    cap.push(c.client(b"ET / HTTP/1.1\r\nHost: example.org\r\n\r\n"));
    cap.push(c.client(b"more"));

    // D: an unmonitored port
    let mut d = Flow::new(CLIENT, 50003, FILTERED, 8080);
    cap.extend(d.open_with(b"hello"));
    cap.push(d.client(b"world"));
    cap.push(d.client(b"again"));

    // E: the second data packet is a TLS ClientHello: recognised
    let mut e = Flow::new(CLIENT, 50004, FILTERED, 443);
    cap.extend(e.open_with(b"junk"));
    cap.push(e.client(&tls_client_hello_record("example.org")));
    cap.push(e.client(b"junk"));

    // F: a DNS-over-UDP style header on port 53 is recognised ...
    let mut f = Flow::new(CLIENT, 50005, FILTERED, 53);
    cap.extend(f.open_with(&dns_query("example.org")));
    cap.push(f.client(b"junk"));

    // G: ... but real DNS-over-TCP (2-byte length prefix) is not, so a second
    // query on the same connection is dropped (the bug the paper points out)
    let query = dns_query("example.org");
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend(&query);
    let mut g = Flow::new(CLIENT, 50006, FILTERED, 53);
    cap.extend(g.open_with(&framed));
    dropped.push(cap.push(g.client(&framed)));

    assert_eq!(cap.run("iran_protocol_filter", PYCL), all("Drop", &dropped));
}

// ==========================================================================
// iran_sni_blackhole
// ==========================================================================

#[test]
fn test_demo_iran_sni_blackhole() {
    let mut cap = Capture::default();
    let mut dropped = Vec::new();

    // A: forbidden SNI: the ClientHello and the client's later packets are
    // dropped, the server's are not
    let mut a = Flow::new(CLIENT, 50000, SERVER, 443);
    dropped.push(cap.extend(a.open_with(&tls_client_hello_record("youtube.com"))));
    dropped.push(cap.push(a.client(&[])));
    cap.push(a.server(b"late reply"));
    dropped.push(cap.push(a.client(b"retry")));
    // 180 s without a packet: the blackhole is lifted
    cap.wait(181);
    cap.push(a.client(b"later"));

    // B: allowed SNI
    let mut b = Flow::new(CLIENT, 50001, SERVER, 443);
    cap.extend(b.open_with(&tls_client_hello_record("example.org")));
    cap.push(b.client(b"data"));

    // C: forbidden SNI on a port that is not monitored
    let mut c = Flow::new(CLIENT, 50002, SERVER, 8443);
    cap.extend(c.open_with(&tls_client_hello_record("youtube.com")));
    cap.push(c.client(b"data"));

    // D: forbidden SNI split across two segments: no reassembly
    let (first, second) = split_hello("youtube.com", &[]);
    let mut d = Flow::new(CLIENT, 50003, SERVER, 443);
    cap.extend(d.open_with(&first));
    cap.push(d.client(&second));
    cap.push(d.client(b"data"));

    // E: no handshake needed, and subdomains match
    let mut e = Flow::new(CLIENT, 50004, SERVER, 443);
    dropped.push(cap.push(e.client(&tls_client_hello_record("www.youtube.com"))));

    assert_eq!(cap.run("iran_sni_blackhole", PYCL), all("Drop", &dropped));
}

// ==========================================================================
// turkmenistan
// ==========================================================================

#[test]
fn test_demo_turkmenistan() {
    const OUTSIDE: [u8; 4] = [8, 8, 4, 4];
    let mut cap = Capture::default();
    let mut expected = Vec::new();

    // DNS: forged answers in both directions and on any port
    expected.push((cap.push(udp_frame(CLIENT, OUTSIDE, 40000, 53, &dns_query("twitter.com"))), "Inject"));
    expected.push((cap.push(udp_frame(OUTSIDE, CLIENT, 40001, 53, &dns_query("www.twitter.com"))), "Inject"));
    expected.push((cap.push(udp_frame(CLIENT, OUTSIDE, 40002, 5353, &dns_query("abc.cyou"))), "Inject"));
    cap.push(udp_frame(CLIENT, OUTSIDE, 40003, 53, &dns_query("example.org")));
    cap.push(udp_frame(CLIENT, OUTSIDE, 40004, 53, &dns_query("nottwitter.com")));

    // HTTP on a non-standard port: RST, then a RST for every later packet
    // with the same source and destination, until 30 s of silence
    let mut h = Flow::new(CLIENT, 50000, SERVER, 8080);
    expected.push((cap.extend(h.open_with(&http_get("twitter.com", "/"))), "Reset"));
    expected.push((cap.push(h.client(&[])), "Reset"));
    cap.push(h.server(b"reply"));
    expected.push((cap.push(h.client(b"again")), "Reset"));
    cap.wait(31);
    cap.push(h.client(b"later"));

    // HTTP from outside to a server inside
    let mut i = Flow::new(OUTSIDE, 50001, CLIENT, 80);
    expected.push((cap.extend(i.open_with(&http_get("www.twitter.com", "/"))), "Reset"));

    // HTTPS
    let mut t = Flow::new(CLIENT, 50002, SERVER, 443);
    expected.push((cap.extend(t.open_with(&tls_client_hello_record("twitter.com"))), "Reset"));

    // Similar traffic that is not censored
    let mut ok1 = Flow::new(CLIENT, 50003, SERVER, 80);
    cap.extend(ok1.open_with(&http_get("example.org", "/twitter.com")));
    let mut ok2 = Flow::new(CLIENT, 50004, SERVER, 80);
    cap.extend(ok2.open_with(&http_get("nottwitter.com", "/")));
    let mut ok3 = Flow::new(CLIENT, 50005, SERVER, 443);
    cap.extend(ok3.open_with(&tls_client_hello_record("nottwitter.com")));
    // A ClientHello split across segments evades the filter
    let (first, second) = split_hello("twitter.com", &[]);
    let mut ok4 = Flow::new(CLIENT, 50006, SERVER, 443);
    cap.extend(ok4.open_with(&first));
    cap.push(ok4.client(&second));

    assert_eq!(cap.run("turkmenistan", PYCL), expected);
}

// ==========================================================================
// gfw_esni
// ==========================================================================

const ESNI: (u16, &[u8]) = (0xffce, &[0x13; 64]);
const ECH: (u16, &[u8]) = (0xfe0d, &[0x42; 64]);

#[test]
fn test_demo_gfw_esni() {
    let esni_hello = tls_client_hello_record_with_extensions("example.org", 0, &[ESNI]);
    let mut cap = Capture::default();
    let mut dropped = Vec::new();

    // A: the ESNI ClientHello is delivered; afterwards the client's packets
    // are dropped and the server's are not
    let mut a = Flow::new(CLIENT, 50000, SERVER, 443);
    cap.extend(a.open_with(&esni_hello));
    cap.push(a.server(b"ServerHello"));
    dropped.push(cap.push(a.client(&[])));
    dropped.push(cap.push(a.client(b"Finished")));

    // B: an ordinary ClientHello
    let mut b = Flow::new(CLIENT, 50001, SERVER, 443);
    cap.extend(b.open_with(&tls_client_hello_record("example.org")));
    cap.push(b.client(b"data"));

    // C: ECH is a different extension and is not blocked
    let mut c = Flow::new(CLIENT, 50002, SERVER, 443);
    cap.extend(c.open_with(&tls_client_hello_record_with_extensions("example.org", 0, &[ECH])));
    cap.push(c.client(b"data"));

    // D: no TCP handshake, no blocking
    let mut d = Flow::new(CLIENT, 50003, SERVER, 443);
    cap.push(d.client(&esni_hello));
    cap.push(d.client(b"data"));

    // E: any port
    let mut e = Flow::new(CLIENT, 50004, SERVER, 8443);
    cap.extend(e.open_with(&esni_hello));
    dropped.push(cap.push(e.client(b"data")));

    // F: connections opened from outside trigger it too
    let mut f = Flow::new(SERVER, 50005, CLIENT, 443);
    cap.extend(f.open_with(&esni_hello));
    cap.push(f.server(b"ServerHello"));
    dropped.push(cap.push(f.client(b"data")));

    // G: an ESNI ClientHello split across segments is not recognised
    let (first, second) = split_hello("example.org", &[ESNI]);
    let mut g = Flow::new(CLIENT, 50006, SERVER, 443);
    cap.extend(g.open_with(&first));
    cap.push(g.client(&second));
    cap.push(g.client(b"data"));

    assert_eq!(cap.run("gfw_esni", PYCL), all("Drop", &dropped));
}

// ==========================================================================
// gfw_quic_sni
// ==========================================================================

#[test]
fn test_demo_gfw_quic_sni() {
    let blocked = quic_initial_packet("youtube.com");
    let mut cap = Capture::default();
    let mut dropped = Vec::new();

    // A: the Initial is delivered, then client -> server packets are dropped
    cap.push(udp_frame(CLIENT, SERVER, 50000, 443, &blocked));
    dropped.push(cap.push(udp_frame(CLIENT, SERVER, 50000, 443, &[0x40; 64])));
    cap.push(udp_frame(SERVER, CLIENT, 443, 50000, &[0x40; 64]));
    dropped.push(cap.push(udp_frame(CLIENT, SERVER, 50000, 443, &[0x40; 64])));

    // B: an SNI that is not on the list
    cap.push(udp_frame(CLIENT, SERVER, 50001, 443, &quic_initial_packet("example.org")));
    cap.push(udp_frame(CLIENT, SERVER, 50001, 443, &[0x40; 64]));

    // C: source port not greater than the destination port
    cap.push(udp_frame(CLIENT, SERVER, 400, 443, &blocked));
    cap.push(udp_frame(CLIENT, SERVER, 400, 443, &[0x40; 64]));

    // D: the Initial is not the first packet of the flow
    cap.push(udp_frame(CLIENT, SERVER, 50002, 443, &[0x40; 64]));
    cap.push(udp_frame(CLIENT, SERVER, 50002, 443, &blocked));
    cap.push(udp_frame(CLIENT, SERVER, 50002, 443, &[0x40; 64]));

    // E: the ClientHello spans two Initial datagrams: not reassembled
    let (first, second) = quic_initial_split_datagrams("youtube.com");
    cap.push(udp_frame(CLIENT, SERVER, 50003, 443, &first));
    cap.push(udp_frame(CLIENT, SERVER, 50003, 443, &second));
    cap.push(udp_frame(CLIENT, SERVER, 50003, 443, &[0x40; 64]));

    // F: any destination port, and subdomains match
    cap.push(udp_frame(CLIENT, SERVER, 50004, 8443, &quic_initial_packet("www.youtube.com")));
    dropped.push(cap.push(udp_frame(CLIENT, SERVER, 50004, 8443, &[0x40; 64])));

    assert_eq!(cap.run("gfw_quic_sni", PYCL), all("Drop", &dropped));
}

// ==========================================================================
// tspu_quic (PyCL and CensorLang)
// ==========================================================================

#[test]
fn test_demo_tspu_quic() {
    let initial = quic_initial_packet("example.org");
    assert!(initial.len() >= 1001 && initial[1..5] == [0, 0, 0, 1]);
    // Version 1 but shorter than 1001 bytes
    let mut short = vec![0u8; 1000];
    short[..5].copy_from_slice(&[0xc0, 0, 0, 0, 1]);
    // Long enough, but QUIC draft-29
    let mut draft29 = vec![0u8; 1200];
    draft29[..5].copy_from_slice(&[0xc0, 0xff, 0, 0, 0x1d]);

    let mut cap = Capture::default();
    let mut dropped = Vec::new();

    // A: the fingerprint; everything after it is dropped, in both directions
    cap.push(udp_frame(CLIENT, SERVER, 50000, 443, &initial));
    dropped.push(cap.push(udp_frame(SERVER, CLIENT, 443, 50000, &[0x40; 64])));
    dropped.push(cap.push(udp_frame(CLIENT, SERVER, 50000, 443, &[0x40; 64])));

    // B: too short
    cap.push(udp_frame(CLIENT, SERVER, 50001, 443, &short));
    cap.push(udp_frame(CLIENT, SERVER, 50001, 443, &short));

    // C: another QUIC version
    cap.push(udp_frame(CLIENT, SERVER, 50002, 443, &draft29));
    cap.push(udp_frame(CLIENT, SERVER, 50002, 443, &draft29));

    // D: not port 443
    cap.push(udp_frame(CLIENT, SERVER, 50003, 8443, &initial));
    cap.push(udp_frame(CLIENT, SERVER, 50003, 8443, &initial));

    // E: sent from the remote side
    cap.push(udp_frame(SERVER, CLIENT, 50004, 443, &initial));
    cap.push(udp_frame(CLIENT, SERVER, 443, 50004, &[0x40; 64]));

    for config in [PYCL, CENSORLANG] {
        assert_eq!(cap.run("tspu_quic", config), all("Drop", &dropped), "{config}");
    }
}

// ==========================================================================
// tspu_sni_delayed_drop (PyCL and CensorLang)
// ==========================================================================

/// Eight more packets, alternating server and client; returns their indices.
fn eight_more(cap: &mut Capture, flow: &mut Flow) -> Vec<usize> {
    (0..8)
        .map(|i| {
            let frame = if i % 2 == 0 { flow.server(b"s") } else { flow.client(b"c") };
            cap.push(frame)
        })
        .collect()
}

#[test]
fn test_demo_tspu_sni_delayed_drop() {
    let mut cap = Capture::default();

    // A: forbidden SNI: five more packets pass, then both directions drop
    let mut a = Flow::new(CLIENT, 50000, SERVER, 443);
    cap.extend(a.open_with(&tls_client_hello_record("play.google.com")));
    let after = eight_more(&mut cap, &mut a);
    let dropped = after[5..].to_vec();

    // B: allowed SNI
    let mut b = Flow::new(CLIENT, 50001, SERVER, 443);
    cap.extend(b.open_with(&tls_client_hello_record("example.org")));
    eight_more(&mut cap, &mut b);

    // C: the connection was opened from the remote side
    let mut c = Flow::new(SERVER, 50002, CLIENT, 443);
    cap.extend(c.open_with(&tls_client_hello_record("play.google.com")));
    eight_more(&mut cap, &mut c);

    // D: the ClientHello is split across two segments
    let (first, second) = split_hello("nordvpn.com", &[]);
    let mut d = Flow::new(CLIENT, 50003, SERVER, 443);
    cap.extend(d.open_with(&first));
    cap.push(d.client(&second));
    eight_more(&mut cap, &mut d);

    for config in [PYCL, CENSORLANG] {
        assert_eq!(cap.run("tspu_sni_delayed_drop", config), all("Drop", &dropped), "{config}");
    }
}

// ==========================================================================
// tspu_vpn (PyCL; CensorLang for the UDP cases)
// ==========================================================================

/// A WireGuard message: type, three reserved zero bytes, then `len - 4` bytes.
fn wireguard(kind: u8, len: usize) -> Vec<u8> {
    let mut p = vec![0xAB; len];
    p[..4].copy_from_slice(&[kind, 0, 0, 0]);
    p
}

/// An OpenVPN packet with the given opcode (key id 0) and `len` bytes in all.
fn openvpn(opcode: u8, len: usize) -> Vec<u8> {
    let mut p = vec![0xCD; len];
    p[0] = opcode << 3;
    p
}

/// An OpenVPN packet as sent over TCP: 2-byte length, then the packet.
fn openvpn_tcp(opcode: u8, len: usize) -> Vec<u8> {
    let mut p = (len as u16).to_be_bytes().to_vec();
    p.extend(openvpn(opcode, len));
    p
}

const OVPN_RESET_CLIENT: u8 = 7;
const OVPN_RESET_SERVER: u8 = 8;
const OVPN_CONTROL: u8 = 4;
const OVPN_ACK: u8 = 5;
const OVPN_DATA_V2: u8 = 9;

#[test]
fn test_demo_tspu_vpn() {
    let mut cap = Capture::default();
    let mut dropped_udp = Vec::new();
    let mut dropped_tcp = Vec::new();

    // A: WireGuard: handshake, two data packets pass, the third and
    // everything after it is dropped
    cap.push(udp_frame(CLIENT, SERVER, 40000, 51820, &wireguard(1, 148)));
    cap.push(udp_frame(SERVER, CLIENT, 51820, 40000, &wireguard(2, 92)));
    cap.push(udp_frame(CLIENT, SERVER, 40000, 51820, &wireguard(4, 96)));
    cap.push(udp_frame(SERVER, CLIENT, 51820, 40000, &wireguard(4, 96)));
    dropped_udp.push(cap.push(udp_frame(CLIENT, SERVER, 40000, 51820, &wireguard(4, 96))));
    dropped_udp.push(cap.push(udp_frame(SERVER, CLIENT, 51820, 40000, &wireguard(4, 96))));
    dropped_udp.push(cap.push(udp_frame(CLIENT, SERVER, 40000, 51820, &wireguard(1, 148))));

    // B: data-shaped packets without a handshake
    for _ in 0..4 {
        cap.push(udp_frame(CLIENT, SERVER, 40001, 51820, &wireguard(4, 96)));
    }

    // C: OpenVPN over UDP: resets, some control traffic, 15 data packets
    // pass, the 16th and everything after it is dropped
    cap.push(udp_frame(CLIENT, SERVER, 40002, 1194, &openvpn(OVPN_RESET_CLIENT, 14)));
    cap.push(udp_frame(SERVER, CLIENT, 1194, 40002, &openvpn(OVPN_RESET_SERVER, 26)));
    cap.push(udp_frame(CLIENT, SERVER, 40002, 1194, &openvpn(OVPN_ACK, 22)));
    cap.push(udp_frame(CLIENT, SERVER, 40002, 1194, &openvpn(OVPN_CONTROL, 300)));
    cap.push(udp_frame(SERVER, CLIENT, 1194, 40002, &openvpn(OVPN_CONTROL, 1200)));
    for i in 0..17 {
        let frame = if i % 2 == 0 {
            udp_frame(CLIENT, SERVER, 40002, 1194, &openvpn(OVPN_DATA_V2, 120))
        } else {
            udp_frame(SERVER, CLIENT, 1194, 40002, &openvpn(OVPN_DATA_V2, 120))
        };
        let index = cap.push(frame);
        if i >= 15 {
            dropped_udp.push(index);
        }
    }

    // D: OpenVPN over TCP (PyCL version only)
    let mut d = Flow::new(CLIENT, 40003, SERVER, 443);
    cap.extend(d.open_with(&openvpn_tcp(OVPN_RESET_CLIENT, 14)));
    cap.push(d.server(&openvpn_tcp(OVPN_RESET_SERVER, 26)));
    for i in 0..16 {
        let index = cap.push(d.client(&openvpn_tcp(OVPN_DATA_V2, 120)));
        if i >= 15 {
            dropped_tcp.push(index);
        }
    }

    // E: unrelated UDP
    cap.push(udp_frame(CLIENT, SERVER, 40004, 53, &dns_query("example.org")));

    let mut dropped_all = dropped_udp.clone();
    dropped_all.extend(&dropped_tcp);
    assert_eq!(cap.run("tspu_vpn", PYCL), all("Drop", &dropped_all));
    assert_eq!(cap.run("tspu_vpn", CENSORLANG), all("Drop", &dropped_udp));
}

// ==========================================================================
// openvpn_fingerprint
// ==========================================================================

/// `total` UDP packets of one flow whose first bytes are `first_byte(i)`,
/// alternating direction; returns their indices.
fn udp_flow(cap: &mut Capture, cport: u16, total: usize, first_byte: impl Fn(usize) -> u8) -> Vec<usize> {
    (0..total)
        .map(|i| {
            let mut payload = vec![0xCD; 64];
            payload[0] = first_byte(i);
            let frame = if i % 2 == 0 {
                udp_frame(CLIENT, SERVER, cport, 1194, &payload)
            } else {
                udp_frame(SERVER, CLIENT, 1194, cport, &payload)
            };
            cap.push(frame)
        })
        .collect()
}

/// Opcode byte of packet `i` of an OpenVPN session: client reset, server
/// reset, a handshake of ACK and control packets, then data.
fn openvpn_session(i: usize) -> u8 {
    let opcode = match i {
        0 => OVPN_RESET_CLIENT,
        1 => OVPN_RESET_SERVER,
        2..=11 if i % 2 == 0 => OVPN_ACK,
        2..=11 => OVPN_CONTROL,
        _ => OVPN_DATA_V2,
    };
    opcode << 3
}

#[test]
fn test_demo_openvpn_fingerprint() {
    let mut cap = Capture::default();

    // A: an OpenVPN session is dropped from its 100th packet on
    let a = udp_flow(&mut cap, 40000, 105, openvpn_session);
    let mut dropped = a[99..].to_vec();

    // B: the same session XOR-scrambled: each opcode byte maps to another value
    let b = udp_flow(&mut cap, 40001, 105, |i| openvpn_session(i) ^ 0x5a);
    dropped.extend(&b[99..]);

    // C: far more than 10 different first bytes
    udp_flow(&mut cap, 40002, 105, |i| (i * 7) as u8);
    // D: a single first byte
    udp_flow(&mut cap, 40003, 105, |_| 0x17);
    // E: a "client reset" reappears after the handshake
    udp_flow(&mut cap, 40004, 105, |i| if i == 50 { OVPN_RESET_CLIENT << 3 } else { openvpn_session(i) });
    // F: fewer than 100 packets
    udp_flow(&mut cap, 40005, 60, openvpn_session);

    // G: OpenVPN over TCP: the opcode follows a 2-byte length
    let mut g = Flow::new(CLIENT, 40006, SERVER, 443);
    cap.extend(g.handshake());
    for i in 0..102 {
        let mut payload = vec![0x00, 0x40];
        payload.extend(vec![openvpn_session(i); 64]);
        let frame = if i % 2 == 0 { g.client(&payload) } else { g.server(&payload) };
        let index = cap.push(frame);
        if i >= 99 {
            dropped.push(index);
        }
    }

    assert_eq!(cap.run("openvpn_fingerprint", PYCL), all("Drop", &dropped));
}

// ==========================================================================
// gfw_ftp_smtp (PyCL and CensorLang)
// ==========================================================================

#[test]
fn test_demo_gfw_ftp_smtp() {
    let mut cap = Capture::default();
    let mut reset = Vec::new();

    // A: FTP request for a file with a sensitive name
    let mut a = Flow::new(CLIENT, 50000, SERVER, 21);
    cap.extend(a.open_with(b"USER anonymous\r\n"));
    reset.push(cap.push(a.client(b"RETR ultrasurf.zip\r\n")));

    // B: no residual censorship: a new connection works straight away
    let mut b = Flow::new(CLIENT, 50001, SERVER, 21);
    cap.extend(b.open_with(b"USER anonymous\r\n"));
    cap.push(b.client(b"RETR readme.txt\r\n"));

    // C: the keyword split across two segments is not seen
    let mut c = Flow::new(CLIENT, 50002, SERVER, 21);
    cap.extend(c.open_with(b"RETR ultra"));
    cap.push(c.client(b"surf.zip\r\n"));

    // D, E: SMTP with the forbidden address as sender or recipient
    let mut d = Flow::new(CLIENT, 50003, SERVER, 25);
    cap.extend(d.open_with(b"EHLO client.example\r\n"));
    reset.push(cap.push(d.client(b"MAIL FROM:<xiazai@upup.info>\r\n")));
    let mut e = Flow::new(CLIENT, 50004, SERVER, 25);
    cap.extend(e.open_with(b"MAIL FROM:<alice@example.org>\r\n"));
    reset.push(cap.push(e.client(b"RCPT TO:<xiazai@upup.info>\r\n")));

    // F: other addresses
    let mut f = Flow::new(CLIENT, 50005, SERVER, 25);
    cap.extend(f.open_with(b"MAIL FROM:<alice@example.org>\r\n"));
    cap.push(f.client(b"RCPT TO:<bob@example.org>\r\n"));

    // G, H: the same strings on other ports
    let mut g = Flow::new(CLIENT, 50006, SERVER, 8021);
    cap.extend(g.open_with(b"RETR ultrasurf.zip\r\n"));
    let mut h = Flow::new(CLIENT, 50007, SERVER, 587);
    cap.extend(h.open_with(b"MAIL FROM:<xiazai@upup.info>\r\n"));

    for config in [PYCL, CENSORLANG] {
        assert_eq!(cap.run("gfw_ftp_smtp", config), all("Reset", &reset), "{config}");
    }
}

// ==========================================================================
// gfw_dns_tcp (PyCL and CensorLang)
// ==========================================================================

/// A DNS query as sent over TCP: 2-byte length, then the message.
fn dns_query_tcp(name: &str) -> Vec<u8> {
    let query = dns_query(name);
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend(&query);
    framed
}

#[test]
fn test_demo_gfw_dns_tcp() {
    let mut cap = Capture::default();
    let mut reset = Vec::new();

    // A: forbidden name
    let mut a = Flow::new(CLIENT, 50000, [9, 9, 9, 9], 53);
    reset.push(cap.extend(a.open_with(&dns_query_tcp("www.facebook.com"))));

    // B: no residual censorship: the next connection to the same resolver works
    let mut b = Flow::new(CLIENT, 50001, [9, 9, 9, 9], 53);
    cap.extend(b.open_with(&dns_query_tcp("example.org")));

    // C: a different name that merely ends the same way
    let mut c = Flow::new(CLIENT, 50002, [9, 9, 9, 9], 53);
    cap.extend(c.open_with(&dns_query_tcp("notfacebook.com")));

    // D: not port 53
    let mut d = Flow::new(CLIENT, 50003, [9, 9, 9, 9], 5353);
    cap.extend(d.open_with(&dns_query_tcp("www.facebook.com")));

    // E: UDP queries are another mechanism (see dns_blocking)
    cap.push(udp_frame(CLIENT, [9, 9, 9, 9], 40000, 53, &dns_query("www.facebook.com")));

    for config in [PYCL, CENSORLANG] {
        assert_eq!(cap.run("gfw_dns_tcp", config), all("Reset", &reset), "{config}");
    }
}

// ==========================================================================
// tspu_ech
// ==========================================================================

#[test]
fn test_demo_tspu_ech() {
    let mut cap = Capture::default();
    let mut dropped = Vec::new();

    // A: cloudflare-ech.com with an ECH extension: dropped from the
    // ClientHello on, in both directions
    let mut a = Flow::new(CLIENT, 50000, SERVER, 443);
    dropped.push(cap.extend(a.open_with(&tls_client_hello_record_with_extensions(
        "cloudflare-ech.com",
        0,
        &[ECH],
    ))));
    dropped.push(cap.push(a.server(b"ServerHello")));
    dropped.push(cap.push(a.client(b"retransmission")));

    // B: the same SNI without ECH
    let mut b = Flow::new(CLIENT, 50001, SERVER, 443);
    cap.extend(b.open_with(&tls_client_hello_record("cloudflare-ech.com")));
    cap.push(b.server(b"ServerHello"));

    // C: ECH with another public name
    let mut c = Flow::new(CLIENT, 50002, SERVER, 443);
    cap.extend(c.open_with(&tls_client_hello_record_with_extensions("public.example.org", 0, &[ECH])));
    cap.push(c.server(b"ServerHello"));

    // D: a large (post-quantum sized) ClientHello in two segments is caught
    // when its second segment arrives
    let (first, second) = split_hello("cloudflare-ech.com", &[ECH]);
    let mut d = Flow::new(CLIENT, 50003, SERVER, 443);
    cap.extend(d.open_with(&first));
    dropped.push(cap.push(d.client(&second)));
    dropped.push(cap.push(d.server(b"ServerHello")));

    // E: the same large ClientHello without ECH
    let (first, second) = split_hello("cloudflare-ech.com", &[]);
    let mut e = Flow::new(CLIENT, 50004, SERVER, 443);
    cap.extend(e.open_with(&first));
    cap.push(e.client(&second));
    cap.push(e.server(b"ServerHello"));

    assert_eq!(cap.run("tspu_ech", PYCL), all("Drop", &dropped));
}

// ==========================================================================
// tspu_encrypted_dns (PyCL and CensorLang)
// ==========================================================================

#[test]
fn test_demo_tspu_encrypted_dns() {
    const GOOGLE_DNS: [u8; 4] = [8, 8, 8, 8];
    const QUAD9: [u8; 4] = [9, 9, 9, 9];
    let mut cap = Capture::default();
    let mut expected = Vec::new();

    // A: DoT to dns.google: RST at the ClientHello and for whatever follows
    let mut a = Flow::new(CLIENT, 50000, GOOGLE_DNS, 853);
    expected.push((cap.extend(a.open_with(&tls_client_hello_record("dns.google"))), "Reset"));
    expected.push((cap.push(a.client(b"retransmission")), "Reset"));

    // B, C: DoH to OpenDNS (names are case-insensitive), DoT to Cloudflare
    let mut b = Flow::new(CLIENT, 50001, [146, 112, 41, 2], 443);
    expected.push((cap.extend(b.open_with(&tls_client_hello_record("DoH.OpenDNS.com"))), "Reset"));
    let mut c = Flow::new(CLIENT, 50002, [1, 1, 1, 1], 853);
    expected.push((
        cap.extend(c.open_with(&tls_client_hello_record("1dot1dot1dot1.cloudflare-dns.com"))),
        "Reset",
    ));

    // D: same address as A, different SNI
    let mut d = Flow::new(CLIENT, 50003, GOOGLE_DNS, 443);
    cap.extend(d.open_with(&tls_client_hello_record("example.org")));
    cap.push(d.client(b"data"));

    // E: a resolver that was not blocked
    let mut e = Flow::new(CLIENT, 50004, QUAD9, 853);
    cap.extend(e.open_with(&tls_client_hello_record("dns.quad9.net")));

    // F: a blocked name split across segments is not seen
    let (first, second) = split_hello("dns.google", &[]);
    let mut f = Flow::new(CLIENT, 50005, GOOGLE_DNS, 853);
    cap.extend(f.open_with(&first));
    cap.push(f.client(&second));

    // G: plaintext DNS to 8.8.8.8 is dropped (config list), other resolvers are not
    expected.push((cap.push(udp_frame(CLIENT, GOOGLE_DNS, 40000, 53, &dns_query("example.org"))), "Drop"));
    expected.push((cap.push(udp_frame(GOOGLE_DNS, CLIENT, 53, 40000, &dns_query("example.org"))), "Drop"));
    cap.push(udp_frame(CLIENT, QUAD9, 40001, 53, &dns_query("example.org")));

    for config in [PYCL, CENSORLANG] {
        assert_eq!(cap.run("tspu_encrypted_dns", config), expected, "{config}");
    }
}

// ==========================================================================
// snowflake_dtls
// ==========================================================================

/// A DTLS 1.2 record holding one unfragmented handshake message.
fn dtls_handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let len24 = &(body.len() as u32).to_be_bytes()[1..];
    let mut p = vec![22, 0xfe, 0xfd]; // handshake, DTLS 1.2
    p.extend([0, 0]); // epoch
    p.extend([0, 0, 0, 0, 0, 0]); // sequence number
    p.extend(((12 + body.len()) as u16).to_be_bytes());
    p.push(kind);
    p.extend(len24);
    p.extend([0, 0]); // message sequence
    p.extend([0, 0, 0]); // fragment offset
    p.extend(len24); // fragment length
    p.extend(body);
    p
}

/// A DTLS ServerHello body with the given extensions.
fn dtls_server_hello(extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = vec![0xfe, 0xfd];
    body.extend([0x11; 32]); // random
    body.push(0); // session id
    body.extend([0xc0, 0x2b]); // cipher suite
    body.push(0); // compression method
    if !extensions.is_empty() {
        let mut block = Vec::new();
        for (ty, data) in extensions {
            block.extend(ty.to_be_bytes());
            block.extend((data.len() as u16).to_be_bytes());
            block.extend(*data);
        }
        body.extend((block.len() as u16).to_be_bytes());
        body.extend(block);
    }
    body
}

#[test]
fn test_demo_snowflake_dtls() {
    const CLIENT_HELLO: u8 = 1;
    const SERVER_HELLO: u8 = 2;
    const HELLO_VERIFY_REQUEST: u8 = 3;
    const RENEGOTIATION_INFO: (u16, &[u8]) = (0xff01, &[0]);
    const EXTENDED_MASTER_SECRET: (u16, &[u8]) = (0x0017, &[]);
    const SUPPORTED_GROUPS: (u16, &[u8]) = (0x000a, &[0, 2, 0, 0x1d]);

    let client_hello = dtls_handshake(CLIENT_HELLO, &[0x22; 120]);
    let mut cap = Capture::default();
    let mut dropped = Vec::new();

    // A: ServerHello with supported_groups (Pion, December 2021 rule)
    cap.push(udp_frame(CLIENT, SERVER, 40000, 50000, &client_hello));
    let pion = dtls_server_hello(&[RENEGOTIATION_INFO, EXTENDED_MASTER_SECRET, SUPPORTED_GROUPS]);
    dropped.push(cap.push(udp_frame(SERVER, CLIENT, 50000, 40000, &dtls_handshake(SERVER_HELLO, &pion))));
    dropped.push(cap.push(udp_frame(CLIENT, SERVER, 40000, 50000, &client_hello)));

    // B: ServerHello without it (browser-like)
    cap.push(udp_frame(CLIENT, SERVER, 40001, 50000, &client_hello));
    let browser = dtls_server_hello(&[RENEGOTIATION_INFO, EXTENDED_MASTER_SECRET]);
    cap.push(udp_frame(SERVER, CLIENT, 50000, 40001, &dtls_handshake(SERVER_HELLO, &browser)));
    cap.push(udp_frame(CLIENT, SERVER, 40001, 50000, &[23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]));

    // C: ServerHello with no extensions at all
    cap.push(udp_frame(CLIENT, SERVER, 40002, 50000, &client_hello));
    cap.push(udp_frame(SERVER, CLIENT, 50000, 40002, &dtls_handshake(SERVER_HELLO, &dtls_server_hello(&[]))));

    // D: HelloVerifyRequest (Pion, July 2022 rule); here the DTLS server is
    // the local peer
    cap.push(udp_frame(SERVER, CLIENT, 50000, 40003, &client_hello));
    let mut verify = vec![0xfe, 0xff, 20];
    verify.extend([0x33; 20]);
    dropped.push(cap.push(udp_frame(CLIENT, SERVER, 40003, 50000, &dtls_handshake(HELLO_VERIFY_REQUEST, &verify))));
    dropped.push(cap.push(udp_frame(SERVER, CLIENT, 50000, 40003, &client_hello)));

    // E: unrelated UDP
    cap.push(udp_frame(CLIENT, SERVER, 40004, 53, &dns_query("example.org")));

    assert_eq!(cap.run("snowflake_dtls", PYCL), all("Drop", &dropped));
}

// Every demo directory with a CensorLang version is exercised above.
#[test]
fn every_censorlang_demo_has_a_test() {
    let tested = ["tspu_quic", "tspu_sni_delayed_drop", "tspu_vpn", "gfw_ftp_smtp", "gfw_dns_tcp", "tspu_encrypted_dns"];
    let demos = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("demos");
    for entry in std::fs::read_dir(demos).unwrap().flatten() {
        if entry.path().join(CENSORLANG).is_file() {
            let name = entry.file_name().into_string().unwrap();
            assert!(tested.contains(&name.as_str()), "demos/{name} has a CensorLang version but no test");
        }
    }
}
