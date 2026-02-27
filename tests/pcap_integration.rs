mod common;

use common::packet_builder::{
    dns_query, high_entropy_payload, http_get, quic_initial_packet, ssh_banner, tcp_frame,
    tls_client_hello_record, udp_frame, TCP_ACK, TCP_PSH_ACK, TCP_SYN,
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
// Test 8: IP blocking via config-level blocklist (no Python script)
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

    let config_str = r#"
[execution]
mode = "Python"

[ip.blocklist]
list = ["192.168.1.100"]
action = "Drop"
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
// Test 8b: Config-level UDP port blocklist
// ==========================================================================

#[test]
fn test_config_udp_port_blocklist() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [8, 8, 8, 8];

    PcapBuilder::new()
        // frame 0: UDP to port 53 -> dropped
        .add_frame(&udp_frame(client, server, 45000, 53, &dns_query("example.com")))
        // frame 1: UDP to port 443 -> passes
        .add_frame(&udp_frame(client, server, 45001, 443, &[0x00; 20]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[udp]
ip_port_allowlist = { list = [] }

[udp.port_blocklist]
list = [53]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        1,
        "expected 1 drop action for UDP/53, got: {:?}\nstdout: {}",
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
// Test 8c: Config-level TCP ip:port blocklist
// ==========================================================================

#[test]
fn test_config_tcp_ip_port_blocklist() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let blocked_server = [93, 184, 216, 34];
    let allowed_server = [93, 184, 216, 35];

    PcapBuilder::new()
        // frame 0: TCP to blocked_server:80 -> dropped
        .add_frame(&tcp_frame(client, blocked_server, 50000, 80, TCP_SYN, 100, 0, &[]))
        // frame 1: TCP to allowed_server:80 -> passes
        .add_frame(&tcp_frame(client, allowed_server, 50001, 80, TCP_SYN, 200, 0, &[]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = [] }

[tcp.ip_port_blocklist]
list = ["93.184.216.34:80"]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        1,
        "expected 1 drop action for TCP 93.184.216.34:80, got: {:?}\nstdout: {}",
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
// Test 8d: Config-level UDP ip:port blocklist
// ==========================================================================

#[test]
fn test_config_udp_ip_port_blocklist() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let blocked_dns = [8, 8, 8, 8];
    let allowed_dns = [1, 1, 1, 1];

    PcapBuilder::new()
        // frame 0: UDP to 8.8.8.8:53 -> dropped
        .add_frame(&udp_frame(client, blocked_dns, 45000, 53, &dns_query("example.com")))
        // frame 1: UDP to 1.1.1.1:53 -> passes
        .add_frame(&udp_frame(client, allowed_dns, 45001, 53, &dns_query("example.com")))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[udp]
ip_port_allowlist = { list = [] }

[udp.ip_port_blocklist]
list = ["8.8.8.8:53"]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        1,
        "expected 1 drop action for UDP 8.8.8.8:53, got: {:?}\nstdout: {}",
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
// Test 8e: TCP port blocklist does NOT affect UDP traffic
// ==========================================================================

#[test]
fn test_tcp_port_list_does_not_affect_udp() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // frame 0: TCP to port 443 -> dropped by TCP blocklist
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]))
        // frame 1: UDP to port 443 -> should NOT be affected by TCP blocklist
        .add_frame(&udp_frame(client, server, 55000, 443, &[0x00; 20]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = [] }

[tcp.port_blocklist]
list = [443]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    // Only 1 action: TCP/443 dropped. UDP/443 should pass through.
    assert_eq!(
        result.action_lines.len(),
        1,
        "expected exactly 1 drop action (TCP only), got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(0));
    assert!(
        result.action_lines[0].action.contains("Drop"),
        "expected Drop for TCP/443, got: {}",
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

// ==========================================================================
// Test 10: Mega-GFW combined censorship
// ==========================================================================
// Validates all 7 censorship techniques from the mega_gfw demo in a single
// test using 12 distinct network flows.

#[test]
fn test_mega_gfw_combined_censorship() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    // -----------------------------------------------------------------------
    // IP addresses used across flows
    // -----------------------------------------------------------------------
    let client = [10, 0, 0, 1];
    let dns_server = [8, 8, 8, 8];
    let http_server = [93, 184, 216, 34];
    let http_server2 = [93, 184, 216, 35];
    let tls_server = [142, 250, 80, 46];
    let tls_server2 = [142, 250, 80, 47];
    let quic_server = [172, 217, 14, 99];
    let quic_server2 = [172, 217, 14, 100];
    let ssh_server = [203, 0, 113, 10];
    let proxy_server = [203, 0, 113, 20];
    let proxy_server2 = [203, 0, 113, 21];
    let blocked_ip = [198, 51, 100, 1]; // in censor.toml ip.blocklist

    let mut builder = PcapBuilder::new();

    // -----------------------------------------------------------------------
    // Flow 1 (frame 0): DNS query for blocked.example.com -> DROP
    // "Testing DNS query to blocked.example.com - the GFW should drop this."
    // -----------------------------------------------------------------------
    builder = builder.add_frame(&udp_frame(
        client, dns_server, 45000, 53,
        &dns_query("blocked.example.com"),
    ));

    // -----------------------------------------------------------------------
    // Flow 2 (frame 1): DNS query for safe.example.com -> ALLOW
    // "Testing DNS query to safe.example.com - should sail through."
    // -----------------------------------------------------------------------
    builder = builder.add_frame(&udp_frame(
        client, dns_server, 45001, 53,
        &dns_query("safe.example.com"),
    ));

    // -----------------------------------------------------------------------
    // Flow 3 (frames 2-5): HTTP GET Host: blocked.example.com -> RESET
    // "Testing HTTP request to blocked.example.com - the GFW should reset this."
    // -----------------------------------------------------------------------
    builder = builder
        .add_frame(&tcp_frame(client, http_server, 50000, 80, TCP_SYN, 100, 0, &[]))
        .add_frame(&tcp_frame(http_server, client, 80, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]))
        .add_frame(&tcp_frame(client, http_server, 50000, 80, TCP_ACK, 101, 201, &[]))
        .add_frame(&tcp_frame(
            client, http_server, 50000, 80, TCP_PSH_ACK, 101, 201,
            &http_get("blocked.example.com", "/"),
        ));

    // -----------------------------------------------------------------------
    // Flow 4 (frames 6-9): HTTP GET Host: allowed.example.com -> ALLOW
    // "Testing HTTP request to allowed.example.com - should pass fine."
    // -----------------------------------------------------------------------
    builder = builder
        .add_frame(&tcp_frame(client, http_server2, 50001, 80, TCP_SYN, 300, 0, &[]))
        .add_frame(&tcp_frame(http_server2, client, 80, 50001, TCP_SYN | TCP_ACK, 400, 301, &[]))
        .add_frame(&tcp_frame(client, http_server2, 50001, 80, TCP_ACK, 301, 401, &[]))
        .add_frame(&tcp_frame(
            client, http_server2, 50001, 80, TCP_PSH_ACK, 301, 401,
            &http_get("allowed.example.com", "/"),
        ));

    // -----------------------------------------------------------------------
    // Flow 5 (frames 10-13): TLS ClientHello SNI=blocked.example.com -> RESET
    // "Testing HTTPS to blocked.example.com - the GFW should reset the handshake."
    // -----------------------------------------------------------------------
    let hello_blocked = tls_client_hello_record("blocked.example.com");
    builder = builder
        .add_frame(&tcp_frame(client, tls_server, 50002, 443, TCP_SYN, 500, 0, &[]))
        .add_frame(&tcp_frame(tls_server, client, 443, 50002, TCP_SYN | TCP_ACK, 600, 501, &[]))
        .add_frame(&tcp_frame(client, tls_server, 50002, 443, TCP_ACK, 501, 601, &[]))
        .add_frame(&tcp_frame(
            client, tls_server, 50002, 443, TCP_PSH_ACK, 501, 601,
            &hello_blocked,
        ));

    // -----------------------------------------------------------------------
    // Flow 6 (frames 14-17): TLS ClientHello SNI=allowed.example.com -> ALLOW
    // "Testing HTTPS to allowed.example.com - should complete normally."
    // -----------------------------------------------------------------------
    let hello_allowed = tls_client_hello_record("allowed.example.com");
    builder = builder
        .add_frame(&tcp_frame(client, tls_server2, 50003, 443, TCP_SYN, 700, 0, &[]))
        .add_frame(&tcp_frame(tls_server2, client, 443, 50003, TCP_SYN | TCP_ACK, 800, 701, &[]))
        .add_frame(&tcp_frame(client, tls_server2, 50003, 443, TCP_ACK, 701, 801, &[]))
        .add_frame(&tcp_frame(
            client, tls_server2, 50003, 443, TCP_PSH_ACK, 701, 801,
            &hello_allowed,
        ));

    // -----------------------------------------------------------------------
    // Flow 7 (frame 18): QUIC Initial SNI=blocked.example.com -> DROP
    // "Testing QUIC to blocked.example.com - the GFW should drop this."
    // -----------------------------------------------------------------------
    builder = builder.add_frame(&udp_frame(
        client, quic_server, 55000, 443,
        &quic_initial_packet("blocked.example.com"),
    ));

    // -----------------------------------------------------------------------
    // Flow 8 (frame 19): QUIC Initial SNI=allowed.example.com -> ALLOW
    // "Testing QUIC to allowed.example.com - should pass through."
    // -----------------------------------------------------------------------
    builder = builder.add_frame(&udp_frame(
        client, quic_server2, 55001, 443,
        &quic_initial_packet("allowed.example.com"),
    ));

    // -----------------------------------------------------------------------
    // Flow 9 (frames 20-23): SSH banner on port 22 -> RESET
    // "Testing SSH connection - the GFW should reset on seeing the banner."
    // -----------------------------------------------------------------------
    builder = builder
        .add_frame(&tcp_frame(client, ssh_server, 50004, 22, TCP_SYN, 900, 0, &[]))
        .add_frame(&tcp_frame(ssh_server, client, 22, 50004, TCP_SYN | TCP_ACK, 1000, 901, &[]))
        .add_frame(&tcp_frame(client, ssh_server, 50004, 22, TCP_ACK, 901, 1001, &[]))
        .add_frame(&tcp_frame(
            client, ssh_server, 50004, 22, TCP_PSH_ACK, 901, 1001,
            &ssh_banner(),
        ));

    // -----------------------------------------------------------------------
    // Flow 10 (frames 24-27): High-entropy random payload on port 8388 -> DROP
    // "Testing encrypted proxy traffic - the GFW should detect and drop this."
    // -----------------------------------------------------------------------
    let encrypted_payload = high_entropy_payload(256);
    builder = builder
        .add_frame(&tcp_frame(client, proxy_server, 50005, 8388, TCP_SYN, 1100, 0, &[]))
        .add_frame(&tcp_frame(proxy_server, client, 8388, 50005, TCP_SYN | TCP_ACK, 1200, 1101, &[]))
        .add_frame(&tcp_frame(client, proxy_server, 50005, 8388, TCP_ACK, 1101, 1201, &[]))
        .add_frame(&tcp_frame(
            client, proxy_server, 50005, 8388, TCP_PSH_ACK, 1101, 1201,
            &encrypted_payload,
        ));

    // -----------------------------------------------------------------------
    // Flow 11 (frames 28-31): Normal ASCII text on port 8388 -> ALLOW
    // "Testing normal text on the same port - should pass, it's not encrypted."
    // -----------------------------------------------------------------------
    let normal_payload = b"Hello, this is a perfectly normal ASCII text message that should not trigger any entropy-based detection. It contains regular English words and punctuation.";
    builder = builder
        .add_frame(&tcp_frame(client, proxy_server2, 50006, 8388, TCP_SYN, 1300, 0, &[]))
        .add_frame(&tcp_frame(proxy_server2, client, 8388, 50006, TCP_SYN | TCP_ACK, 1400, 1301, &[]))
        .add_frame(&tcp_frame(client, proxy_server2, 50006, 8388, TCP_ACK, 1301, 1401, &[]))
        .add_frame(&tcp_frame(
            client, proxy_server2, 50006, 8388, TCP_PSH_ACK, 1301, 1401,
            normal_payload,
        ));

    // -----------------------------------------------------------------------
    // Flow 12 (frame 32): Packet from blocked IP 198.51.100.1 -> DROP (config)
    // "Testing config-level IP blocklist - should be dropped before script runs."
    // -----------------------------------------------------------------------
    builder = builder.add_frame(&tcp_frame(
        blocked_ip, client, 50007, 80, TCP_SYN, 1500, 0, &[],
    ));

    builder.write_to(&pcap_path);

    // -----------------------------------------------------------------------
    // Run censorlab
    // -----------------------------------------------------------------------
    let config = demo_config("mega_gfw");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "censorlab failed:\nstderr: {}", result.stderr);

    // Print all actions for debugging
    println!("=== Mega-GFW Test Results ===");
    println!("stdout:\n{}", result.stdout);
    if !result.stderr.is_empty() {
        println!("stderr:\n{}", result.stderr);
    }
    println!("Parsed action lines:");
    for line in &result.action_lines {
        println!("  packet_index={}: {}", line.packet_index, line.action);
    }

    // -----------------------------------------------------------------------
    // Assertions
    // -----------------------------------------------------------------------

    // Flow 1: DNS blocked.example.com -> Drop (frame 0)
    assert!(
        result.action_lines.iter().any(|l| l.packet_index == frame_idx(0) && l.action.contains("Drop")),
        "Flow 1: expected Drop for DNS query to blocked.example.com (frame 0)"
    );

    // Flow 2: DNS safe.example.com -> no action (frame 1)
    assert!(
        !result.action_lines.iter().any(|l| l.packet_index == frame_idx(1)),
        "Flow 2: DNS query to safe.example.com should produce no action (frame 1)"
    );

    // Flow 3: HTTP blocked.example.com -> Reset (frames 2-5)
    assert!(
        result.action_lines.iter().any(|l| {
            l.packet_index >= frame_idx(2) && l.packet_index <= frame_idx(5)
                && l.action.contains("Reset")
        }),
        "Flow 3: expected Reset for HTTP to blocked.example.com (frames 2-5)"
    );

    // Flow 4: HTTP allowed.example.com -> no action (frames 6-9)
    assert!(
        !result.action_lines.iter().any(|l| {
            l.packet_index >= frame_idx(6) && l.packet_index <= frame_idx(9)
        }),
        "Flow 4: HTTP to allowed.example.com should produce no action (frames 6-9)"
    );

    // Flow 5: TLS SNI blocked.example.com -> Reset (frames 10-13)
    assert!(
        result.action_lines.iter().any(|l| {
            l.packet_index >= frame_idx(10) && l.packet_index <= frame_idx(13)
                && l.action.contains("Reset")
        }),
        "Flow 5: expected Reset for TLS SNI blocked.example.com (frames 10-13)"
    );

    // Flow 6: TLS SNI allowed.example.com -> no action (frames 14-17)
    assert!(
        !result.action_lines.iter().any(|l| {
            l.packet_index >= frame_idx(14) && l.packet_index <= frame_idx(17)
        }),
        "Flow 6: TLS SNI allowed.example.com should produce no action (frames 14-17)"
    );

    // Flow 7: QUIC blocked.example.com -> Drop (frame 18)
    assert!(
        result.action_lines.iter().any(|l| l.packet_index == frame_idx(18) && l.action.contains("Drop")),
        "Flow 7: expected Drop for QUIC SNI blocked.example.com (frame 18)"
    );

    // Flow 8: QUIC allowed.example.com -> no action (frame 19)
    assert!(
        !result.action_lines.iter().any(|l| l.packet_index == frame_idx(19)),
        "Flow 8: QUIC SNI allowed.example.com should produce no action (frame 19)"
    );

    // Flow 9: SSH banner -> Reset (frames 20-23)
    assert!(
        result.action_lines.iter().any(|l| {
            l.packet_index >= frame_idx(20) && l.packet_index <= frame_idx(23)
                && l.action.contains("Reset")
        }),
        "Flow 9: expected Reset for SSH banner (frames 20-23)"
    );

    // Flow 10: High-entropy payload -> Drop (frames 24-27)
    assert!(
        result.action_lines.iter().any(|l| {
            l.packet_index >= frame_idx(24) && l.packet_index <= frame_idx(27)
                && l.action.contains("Drop")
        }),
        "Flow 10: expected Drop for high-entropy payload (frames 24-27)"
    );

    // Flow 11: Normal ASCII on port 8388 -> no action (frames 28-31)
    assert!(
        !result.action_lines.iter().any(|l| {
            l.packet_index >= frame_idx(28) && l.packet_index <= frame_idx(31)
        }),
        "Flow 11: normal ASCII text should produce no action (frames 28-31)"
    );

    // Flow 12: Blocked IP 198.51.100.1 -> Drop (frame 32, config-level)
    assert!(
        result.action_lines.iter().any(|l| l.packet_index == frame_idx(32) && l.action.contains("Drop")),
        "Flow 12: expected Drop for blocked IP 198.51.100.1 (frame 32)"
    );

    println!("=== All 12 flows validated successfully! ===");
}
