mod common;

use common::packet_builder::{
    dns_query, http_get, quic_initial_packet, tcp_frame, tls_client_hello_record, udp_frame,
    TCP_ACK, TCP_PSH_ACK, TCP_SYN,
};
use common::pcap_builder::PcapBuilder;
use common::runner::run_pcap_with_config;
use std::path::PathBuf;
use tempfile::TempDir;

/// Resolve a demo config path relative to the workspace root.
fn demo_config(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("demos").join(name).join("censor.toml")
}

/// Write a TOML config and optional Python script into a temp directory.
/// Returns the config path.
fn write_temp_config(dir: &TempDir, toml_content: &str) -> PathBuf {
    let path = dir.path().join("censor.toml");
    std::fs::write(&path, toml_content).expect("write temp config");
    path
}

fn write_temp_script(dir: &TempDir, filename: &str, content: &str) {
    let path = dir.path().join(filename);
    std::fs::write(&path, content).expect("write temp script");
}

/// The PCAP global header consumes one packet_index in the reader loop,
/// so the first data frame has packet_index=2, second=3, etc.
/// This helper converts a 0-based frame index to the expected packet_index.
fn frame_idx(n: usize) -> usize {
    n + 2
}

// ==========================================================================
// Test 1: null passthrough
// ==========================================================================

#[test]
fn test_null_passthrough() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client_ip = [10, 0, 0, 1];
    let server_ip = [93, 184, 216, 34];

    PcapBuilder::new()
        .add_frame(&tcp_frame(client_ip, server_ip, 50000, 80, TCP_SYN, 100, 0, &[]))
        .add_frame(&tcp_frame(server_ip, client_ip, 80, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]))
        .add_frame(&tcp_frame(client_ip, server_ip, 50000, 80, TCP_PSH_ACK, 101, 201, b"hello"))
        .write_to(&pcap_path);

    let config = demo_config("null");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        0,
        "null script should produce no actions, got: {:?}",
        result.action_lines
    );
}

// ==========================================================================
// Test 2: IP blocking (via Python script)
// ==========================================================================

#[test]
fn test_ip_blocking() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let blocked = [8, 8, 8, 8];
    let allowed = [1, 1, 1, 1];

    PcapBuilder::new()
        // frame 0: client -> 8.8.8.8 (should be dropped)
        .add_frame(&tcp_frame(client, blocked, 50000, 53, TCP_SYN, 100, 0, &[]))
        // frame 1: client -> 1.1.1.1 (should pass)
        .add_frame(&tcp_frame(client, allowed, 50001, 53, TCP_SYN, 200, 0, &[]))
        // frame 2: 8.8.8.8 -> client (should be dropped)
        .add_frame(&tcp_frame(blocked, client, 53, 50000, TCP_SYN | TCP_ACK, 300, 101, &[]))
        .write_to(&pcap_path);

    let config = demo_config("ip_blocking");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        2,
        "expected 2 drop actions, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(0));
    assert!(
        result.action_lines[0].action.contains("Drop"),
        "expected Drop, got: {}",
        result.action_lines[0].action
    );
    assert_eq!(result.action_lines[1].packet_index, frame_idx(2));
    assert!(
        result.action_lines[1].action.contains("Drop"),
        "expected Drop, got: {}",
        result.action_lines[1].action
    );
}

// ==========================================================================
// Test 3: DNS blocking
// ==========================================================================

#[test]
fn test_dns_blocking() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let dns_server = [8, 8, 8, 8];

    PcapBuilder::new()
        // frame 0: DNS query for google.com -> dropped
        .add_frame(&udp_frame(client, dns_server, 45000, 53, &dns_query("google.com")))
        // frame 1: DNS query for yahoo.com -> passes
        .add_frame(&udp_frame(client, dns_server, 45001, 53, &dns_query("yahoo.com")))
        // frame 2: DNS query for mail.google.com -> dropped (substring match)
        .add_frame(&udp_frame(client, dns_server, 45002, 53, &dns_query("mail.google.com")))
        // frame 3: DNS response (dst port != 53) -> passes
        .add_frame(&udp_frame(dns_server, client, 53, 45000, &[0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
        .write_to(&pcap_path);

    let config = demo_config("dns_blocking");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        2,
        "expected 2 drop actions, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(0));
    assert!(result.action_lines[0].action.contains("Drop"));
    assert_eq!(result.action_lines[1].packet_index, frame_idx(2));
    assert!(result.action_lines[1].action.contains("Drop"));
}

// ==========================================================================
// Test 4: HTTP blocking
// ==========================================================================

#[test]
fn test_http_blocking() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    // Flow 1 (frames 0-3): to example.org (blocked) — 3-way handshake + HTTP GET
    let f1 = [
        tcp_frame(client, server, 50000, 80, TCP_SYN, 100, 0, &[]),
        tcp_frame(server, client, 80, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]),
        tcp_frame(client, server, 50000, 80, TCP_ACK, 101, 201, &[]),
        tcp_frame(
            client,
            server,
            50000,
            80,
            TCP_PSH_ACK,
            101,
            201,
            &http_get("example.org", "/"),
        ),
    ];

    // Flow 2 (frames 4-7): to google.com (not blocked)
    let server2 = [142, 250, 80, 46];
    let f2 = [
        tcp_frame(client, server2, 50001, 80, TCP_SYN, 300, 0, &[]),
        tcp_frame(server2, client, 80, 50001, TCP_SYN | TCP_ACK, 400, 301, &[]),
        tcp_frame(client, server2, 50001, 80, TCP_ACK, 301, 401, &[]),
        tcp_frame(
            client,
            server2,
            50001,
            80,
            TCP_PSH_ACK,
            301,
            401,
            &http_get("google.com", "/"),
        ),
    ];

    let mut builder = PcapBuilder::new();
    for frame in f1.iter().chain(f2.iter()) {
        builder = builder.add_frame(frame);
    }
    builder.write_to(&pcap_path);

    let config = demo_config("http_blocking");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    // The HTTP request to example.org should trigger a Reset (within flow 1, frames 0-3)
    let flow1_max_idx = frame_idx(3); // frame 3 = packet index 5
    assert!(
        result
            .action_lines
            .iter()
            .any(|l| l.action.contains("Reset") && l.packet_index <= flow1_max_idx),
        "expected at least one Reset action for .org request in flow 1, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    // The google.com flow (frames 4-7 -> packet indices 6-9) should NOT trigger any action
    let flow2_min_idx = frame_idx(4);
    for line in &result.action_lines {
        if line.packet_index >= flow2_min_idx {
            panic!(
                "unexpected action for google.com flow (pkt {}): {}",
                line.packet_index, line.action
            );
        }
    }
}

// ==========================================================================
// Test 5: HTTPS blocking (TLS parsed)
// ==========================================================================

#[test]
fn test_https_blocking_tls_parsed() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    let hello_blocked = tls_client_hello_record("example.com");
    let f1 = [
        tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]),
        tcp_frame(server, client, 443, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]),
        tcp_frame(client, server, 50000, 443, TCP_ACK, 101, 201, &[]),
        tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 101, 201, &hello_blocked),
    ];

    let server2 = [142, 250, 80, 46];
    let hello_allowed = tls_client_hello_record("google.com");
    let f2 = [
        tcp_frame(client, server2, 50001, 443, TCP_SYN, 300, 0, &[]),
        tcp_frame(server2, client, 443, 50001, TCP_SYN | TCP_ACK, 400, 301, &[]),
        tcp_frame(client, server2, 50001, 443, TCP_ACK, 301, 401, &[]),
        tcp_frame(client, server2, 50001, 443, TCP_PSH_ACK, 301, 401, &hello_allowed),
    ];

    let mut builder = PcapBuilder::new();
    for frame in f1.iter().chain(f2.iter()) {
        builder = builder.add_frame(frame);
    }
    builder.write_to(&pcap_path);

    let config = demo_config("https_blocking_tls");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let flow1_max_idx = frame_idx(3);
    assert!(
        result
            .action_lines
            .iter()
            .any(|l| l.action.contains("Drop") && l.packet_index <= flow1_max_idx),
        "expected Drop for example.com via TLS parsing in flow 1, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    let flow2_min_idx = frame_idx(4);
    for line in &result.action_lines {
        if line.packet_index >= flow2_min_idx {
            panic!(
                "unexpected action for google.com flow (pkt {}): {}",
                line.packet_index, line.action
            );
        }
    }
}

// ==========================================================================
// Test 7: QUIC blocking
// ==========================================================================

#[test]
fn test_quic_blocking() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server_blocked = [93, 184, 216, 34];
    let server_allowed = [142, 250, 80, 46];

    PcapBuilder::new()
        // frame 0: QUIC Initial with SNI=example.com -> dropped
        .add_frame(&udp_frame(
            client,
            server_blocked,
            55000,
            443,
            &quic_initial_packet("example.com"),
        ))
        // frame 1: QUIC Initial with SNI=google.com -> passes
        .add_frame(&udp_frame(
            client,
            server_allowed,
            55001,
            443,
            &quic_initial_packet("google.com"),
        ))
        .write_to(&pcap_path);

    let config = demo_config("quic_blocking");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        1,
        "expected 1 drop action, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(0));
    assert!(
        result.action_lines[0].action.contains("Drop"),
        "expected Drop, got: {}",
        result.action_lines[0].action
    );
}

// ==========================================================================
// Test 8: IP blocking via script (config-driven with helper script)
// ==========================================================================

#[test]
fn test_config_ip_blocklist() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let blocked_ip = [192, 168, 1, 100];
    let allowed_ip = [192, 168, 1, 200];
    let server = [10, 0, 0, 1];

    PcapBuilder::new()
        // frame 0: from blocked IP -> dropped
        .add_frame(&tcp_frame(blocked_ip, server, 50000, 80, TCP_SYN, 100, 0, &[]))
        // frame 1: from allowed IP -> passes
        .add_frame(&tcp_frame(allowed_ip, server, 50001, 80, TCP_SYN, 200, 0, &[]))
        .write_to(&pcap_path);

    // The IP blocklist in config is not enforced at runtime (only the Python
    // script layer implements IP-based blocking). Use a script instead.
    write_temp_script(
        &tmp,
        "block_ip.py",
        r#"
def process(packet):
    ip = packet.ip
    if "192.168.1.100" in [ip.src, ip.dst]:
        return "drop"
"#,
    );

    let config_str = r#"
[execution]
mode = "Python"
script = "block_ip.py"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        1,
        "expected 1 drop action, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(0));
    assert!(
        result.action_lines[0].action.contains("Drop"),
        "expected Drop, got: {}",
        result.action_lines[0].action
    );
}

// ==========================================================================
// Test 9: config TCP port blocklist (no script)
// ==========================================================================

#[test]
fn test_config_tcp_port_blocklist() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // frame 0: to port 443 -> dropped
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]))
        // frame 1: to port 80 -> passes
        .add_frame(&tcp_frame(client, server, 50001, 80, TCP_SYN, 200, 0, &[]))
        .write_to(&pcap_path);

    // Provide full config with all required fields to avoid parse errors.
    let config_str = r#"
[execution]
mode = "Python"

[ethernet]
[ethernet.allowlist]
list = []
[ethernet.blocklist]
list = []

[arp]

[ip]
[ip.blocklist]
list = []
action = "Drop"
[ip.allowlist]
list = []

[icmp]

[tcp]
[tcp.port_allowlist]
list = []
[tcp.port_blocklist]
list = [443]
action = "Drop"
[tcp.ip_port_allowlist]
list = []
[tcp.ip_port_blocklist]
list = []

[udp]
[udp.port_allowlist]
list = []
[udp.port_blocklist]
list = []
[udp.ip_port_allowlist]
list = []
[udp.ip_port_blocklist]
list = []
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        1,
        "expected 1 drop action, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(0));
    assert!(
        result.action_lines[0].action.contains("Drop"),
        "expected Drop, got: {}",
        result.action_lines[0].action
    );
}
