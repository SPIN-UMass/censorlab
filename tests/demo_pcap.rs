//! PCAP-mode integration tests for demos not covered by `pcap_integration.rs`:
//! `https_blocking`, `shadowsocks_gfw`, `shadowsocks_poisoned` and `print`.
//!
//! Each test synthesizes traffic with the shared builders and asserts that the
//! demo's intended action fires on matching traffic and not on benign traffic.

// Test packet builders mirror wire formats: many header-field arguments and
// byte-by-byte pushes are clearer than the alternatives here.
#![allow(clippy::too_many_arguments, clippy::vec_init_then_push)]

// Not every builder is used by every test crate.
#[allow(dead_code)]
mod common;

use common::packet_builder::{
    dns_query, high_entropy_payload, http_get, tcp_frame, tls_client_hello_record, udp_frame,
    TCP_ACK, TCP_PSH_ACK, TCP_SYN,
};
use common::pcap_builder::PcapBuilder;
use common::runner::{run_pcap_with_config, RunResult};
use std::path::PathBuf;
use tempfile::TempDir;

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [93, 184, 216, 34];

fn demo_config(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("demos")
        .join(name)
        .join("censor.toml")
}

/// See `frame_idx` in pcap_integration.rs: the first frame is packet_index 2.
fn frame_idx(n: usize) -> usize {
    n + 2
}

/// Write `frames` to a pcap and run the named demo over it.
fn run_demo(demo: &str, frames: &[Vec<u8>]) -> RunResult {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    let mut b = PcapBuilder::new();
    for f in frames {
        b = b.add_frame(f);
    }
    b.write_to(&pcap_path);
    let result = run_pcap_with_config(&demo_config(demo), &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result
}

/// Frame indices (0-based) that received an action containing `needle`.
fn frames_with(result: &RunResult, needle: &str) -> Vec<usize> {
    result
        .action_lines
        .iter()
        .filter(|l| l.action.contains(needle))
        .map(|l| l.packet_index - 2)
        .collect()
}

/// A client-initiated TCP flow: 3-way handshake followed by one data segment
/// from the client.  Returns 4 frames.
fn tcp_flow(server: [u8; 4], cport: u16, sport: u16, payload: &[u8]) -> Vec<Vec<u8>> {
    vec![
        tcp_frame(CLIENT, server, cport, sport, TCP_SYN, 100, 0, &[]),
        tcp_frame(server, CLIENT, sport, cport, TCP_SYN | TCP_ACK, 200, 101, &[]),
        tcp_frame(CLIENT, server, cport, sport, TCP_ACK, 101, 201, &[]),
        tcp_frame(CLIENT, server, cport, sport, TCP_PSH_ACK, 101, 201, payload),
    ]
}

// ==========================================================================
// https_blocking: drop port-443 segments whose payload mentions example.com
// ==========================================================================

#[test]
fn test_demo_https_blocking() {
    let mut frames = Vec::new();
    // Flow A (frames 0-3): ClientHello for example.com -> data segment dropped
    frames.extend(tcp_flow(SERVER, 50000, 443, &tls_client_hello_record("example.com")));
    // Flow B (frames 4-7): ClientHello for google.com -> untouched
    frames.extend(tcp_flow([142, 250, 80, 46], 50001, 443, &tls_client_hello_record("google.com")));
    // Flow C (frames 8-11): plaintext HTTP to example.com on port 80 -> untouched
    // (the demo only inspects port 443)
    frames.extend(tcp_flow(SERVER, 50002, 80, &http_get("example.com", "/")));

    let result = run_demo("https_blocking", &frames);
    assert_eq!(
        frames_with(&result, "Drop"),
        vec![3],
        "only the example.com ClientHello should be dropped: {:?}\n{}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines.len(), 1, "{:?}", result.action_lines);
}

// ==========================================================================
// shadowsocks_gfw: Wu et al. (USENIX Sec '23) fully-encrypted-traffic rules
// ==========================================================================

/// Bytes that are non-printable and have exactly 4 set bits, so they keep
/// the average popcount inside the GFW's (3.4, 4.6) window.
const NONPRINT_POP4: [u8; 4] = [0x0F, 0xF0, 0x87, 0x99];

fn nonprintable(len: usize) -> Vec<u8> {
    (0..len).map(|i| NONPRINT_POP4[i % 4]).collect()
}

#[test]
fn test_demo_shadowsocks_gfw_blocks_random_looking_traffic() {
    // 256 bytes, one of each value: popcount exactly 4.0, ~37% printable,
    // first byte printable but the second is not.
    let random = high_entropy_payload(256);
    let frames = tcp_flow(SERVER, 50000, 8388, &random);

    let result = run_demo("shadowsocks_gfw", &frames);
    assert_eq!(
        frames_with(&result, "Drop"),
        vec![3],
        "the handshake must pass and the random-looking segment must be dropped: {:?}\n{}",
        result.action_lines,
        result.stdout
    );
}

#[test]
fn test_demo_shadowsocks_gfw_exemptions() {
    let random = high_entropy_payload(256);

    // Ex1: average popcount outside (3.4, 4.6)
    let low_popcount = vec![0x01u8; 256];
    // Ex2: first six bytes printable ('U' = 0x55 has popcount 4)
    let mut printable_prefix = b"UUUUUUUU".to_vec();
    printable_prefix.extend(nonprintable(200));
    // Ex3: more than half the bytes printable
    let mostly_printable = http_get("example.com", "/some/fairly/long/path?with=query");
    // Ex4: a run of more than 20 contiguous printable bytes
    let mut printable_run = nonprintable(4);
    printable_run.extend(std::iter::repeat_n(b'U', 25));
    printable_run.extend(nonprintable(100));
    // Port exemption in the demo: 80 and 443 are never blocked
    let web = random.clone();

    let mut frames = Vec::new();
    frames.extend(tcp_flow(SERVER, 50001, 8388, &low_popcount));
    frames.extend(tcp_flow(SERVER, 50002, 8388, &printable_prefix));
    frames.extend(tcp_flow(SERVER, 50003, 8388, &mostly_printable));
    frames.extend(tcp_flow(SERVER, 50004, 8388, &printable_run));
    frames.extend(tcp_flow(SERVER, 50005, 443, &web));

    let result = run_demo("shadowsocks_gfw", &frames);
    assert!(
        result.action_lines.is_empty(),
        "exempt traffic must not be blocked (flow k = frames 4k..4k+3; \
         0=popcount, 1=printable prefix, 2=mostly printable, 3=printable run, 4=port 443): {:?}\n{}",
        result.action_lines,
        result.stdout
    );
}

// ==========================================================================
// shadowsocks_poisoned: IP blocklist + ONNX classifier after 30 packets
// ==========================================================================

#[test]
fn test_demo_shadowsocks_poisoned_ip_blocklist() {
    let blocked = [192, 168, 31, 1];
    let mut frames = Vec::new();
    frames.extend(tcp_flow(blocked, 50000, 8388, b"hello"));
    frames.extend(tcp_flow(SERVER, 50001, 8388, b"hello"));

    let result = run_demo("shadowsocks_poisoned", &frames);
    let reset = frames_with(&result, "Reset");
    assert!(
        reset.contains(&0) && reset.iter().all(|&f| f < 4),
        "traffic to 192.168.31.1 must be reset and nothing else: {:?}\n{}",
        result.action_lines,
        result.stdout
    );
}

#[test]
fn test_demo_shadowsocks_poisoned_model_runs() {
    // A 40-packet flow, so the script evaluates the model at packet 30.
    let mut frames = tcp_flow(SERVER, 50000, 8388, &high_entropy_payload(256));
    for i in 0..36u32 {
        let (src, dst, sp, dp) = if i % 2 == 0 {
            (CLIENT, SERVER, 50000, 8388)
        } else {
            (SERVER, CLIENT, 8388, 50000)
        };
        frames.push(tcp_frame(src, dst, sp, dp, TCP_PSH_ACK, 1000 + i, 1000, &high_entropy_payload(256)));
    }
    let result = run_demo("shadowsocks_poisoned", &frames);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        !combined.contains("ERROR") && !combined.contains("Traceback"),
        "model evaluation must not error:\n{combined}"
    );
    // The model is only consulted at packet 30, so nothing before it can fire.
    assert!(
        result.action_lines.iter().all(|l| l.packet_index >= frame_idx(29)),
        "{:?}",
        result.action_lines
    );
}

// ==========================================================================
// print: logs every packet, never acts
// ==========================================================================

#[test]
fn test_demo_print_logs_without_acting() {
    let mut frames = tcp_flow(SERVER, 50000, 80, &http_get("example.com", "/"));
    frames.push(udp_frame(CLIENT, [8, 8, 8, 8], 45000, 53, &dns_query("example.com")));

    let result = run_demo("print", &frames);
    assert!(result.action_lines.is_empty(), "{:?}", result.action_lines);
    let logged = result.stdout.lines().filter(|l| l.contains("INFO")).count();
    assert!(
        logged >= frames.len(),
        "expected one INFO log line per packet, got {logged}:\n{}",
        result.stdout
    );
}
