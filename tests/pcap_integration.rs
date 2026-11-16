// Test packet builders mirror wire formats: many header-field arguments and
// byte-by-byte pushes are clearer than the alternatives here.
#![allow(clippy::too_many_arguments, clippy::vec_init_then_push)]

mod common;

use common::packet_builder::{
    dns_query, high_entropy_payload, http_get, icmp_echo, ipv4_raw_frame, ipv6_raw_frame,
    quic_initial_packet, raw_tcp_header, ssh_banner, tcp_frame, tls_client_hello_record,
    tls_client_hello_record_padded, udp_frame, TCP_ACK, TCP_PSH_ACK, TCP_SYN,
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
        "expected 2 inject actions, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(0));
    assert!(result.action_lines[0].action.contains("Inject"));
    assert_eq!(result.action_lines[1].packet_index, frame_idx(2));
    assert!(result.action_lines[1].action.contains("Inject"));
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
            .any(|l| l.action.contains("Reset") && l.packet_index <= flow1_max_idx),
        "expected Reset for example.com via TLS parsing in flow 1, got: {:?}\nstdout: {}",
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
// Test 5b: HTTPS blocking with a ClientHello split across TCP segments
// ==========================================================================

/// Client sends a post-quantum-sized ClientHello in two segments: 1460 bytes, then the rest
fn split_hello_flow(
    client: [u8; 4],
    server: [u8; 4],
    port: u16,
    isn: u32,
    sni: &str,
    out_of_order: bool,
) -> Vec<Vec<u8>> {
    let hello = tls_client_hello_record_padded(sni, 1500);
    assert!(hello.len() > 1460);
    let (first, second) = hello.split_at(1460);
    let seg1 = tcp_frame(client, server, port, 443, TCP_ACK, isn + 1, 1001, first);
    let seg2 = tcp_frame(client, server, port, 443, TCP_PSH_ACK, isn + 1 + 1460, 1001, second);
    let mut frames = vec![
        tcp_frame(client, server, port, 443, TCP_SYN, isn, 0, &[]),
        tcp_frame(server, client, 443, port, TCP_SYN | TCP_ACK, 1000, isn + 1, &[]),
        tcp_frame(client, server, port, 443, TCP_ACK, isn + 1, 1001, &[]),
    ];
    if out_of_order {
        frames.extend([seg2, seg1]);
    } else {
        frames.extend([seg1, seg2]);
    }
    frames
}

fn check_split_hello_blocking(out_of_order: bool) {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let f1 = split_hello_flow(client, [93, 184, 216, 34], 50000, 100, "example.com", out_of_order);
    let f2 = split_hello_flow(client, [142, 250, 80, 46], 50001, 300, "google.com", out_of_order);

    let mut builder = PcapBuilder::new();
    for frame in f1.iter().chain(f2.iter()) {
        builder = builder.add_frame(frame);
    }
    builder.write_to(&pcap_path);

    let config = demo_config("https_blocking_tls");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    // The ClientHello completes on the last segment of flow 1
    assert!(
        result
            .action_lines
            .iter()
            .any(|l| l.action.contains("Reset") && l.packet_index == frame_idx(4)),
        "expected Reset when the split ClientHello for example.com completes, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    for line in &result.action_lines {
        if line.packet_index >= frame_idx(f1.len()) {
            panic!(
                "unexpected action for google.com flow (pkt {}): {}",
                line.packet_index, line.action
            );
        }
    }
}

#[test]
fn test_https_blocking_tls_split_client_hello() {
    check_split_hello_blocking(false);
}

#[test]
fn test_https_blocking_tls_split_client_hello_out_of_order() {
    check_split_hello_blocking(true);
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
// Test 8a: IP blocking via config-level CIDR subnet blocklist
// ==========================================================================

#[test]
fn test_config_ip_subnet_blocklist() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];

    PcapBuilder::new()
        // frame 0: first address of 198.51.100.0/24 -> dropped
        .add_frame(&tcp_frame(client, [198, 51, 100, 0], 50000, 80, TCP_SYN, 100, 0, &[]))
        // frame 1: just below the subnet -> passes
        .add_frame(&tcp_frame(client, [198, 51, 99, 255], 50001, 80, TCP_SYN, 200, 0, &[]))
        // frame 2: last address of the subnet -> dropped
        .add_frame(&tcp_frame(client, [198, 51, 100, 255], 50002, 80, TCP_SYN, 300, 0, &[]))
        // frame 3: just above the subnet -> passes
        .add_frame(&tcp_frame(client, [198, 51, 101, 0], 50003, 80, TCP_SYN, 400, 0, &[]))
        // frame 4: single-address entry in the same list -> dropped
        .add_frame(&tcp_frame(client, [203, 0, 113, 7], 50004, 80, TCP_SYN, 500, 0, &[]))
        // frame 5: neighbour of the single address -> passes
        .add_frame(&tcp_frame(client, [203, 0, 113, 8], 50005, 80, TCP_SYN, 600, 0, &[]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[ip.blocklist]
list = ["198.51.100.0/24", "203.0.113.7", "2001:db8::/32"]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let dropped: Vec<usize> = result
        .action_lines
        .iter()
        .filter(|l| l.action.contains("Drop"))
        .map(|l| l.packet_index)
        .collect();
    assert_eq!(
        dropped,
        vec![frame_idx(0), frame_idx(2), frame_idx(4)],
        "unexpected drops: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
}

// ==========================================================================
// Test 8a': Config-level TCP ip:port blocklist with a subnet
// ==========================================================================

#[test]
fn test_config_tcp_ip_port_subnet_blocklist() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];

    PcapBuilder::new()
        // frame 0: in subnet, matching port -> dropped
        .add_frame(&tcp_frame(client, [93, 184, 7, 9], 50000, 443, TCP_SYN, 100, 0, &[]))
        // frame 1: in subnet, other port -> passes
        .add_frame(&tcp_frame(client, [93, 184, 7, 9], 50001, 80, TCP_SYN, 200, 0, &[]))
        // frame 2: outside subnet, matching port -> passes
        .add_frame(&tcp_frame(client, [93, 185, 0, 1], 50002, 443, TCP_SYN, 300, 0, &[]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = [] }

[tcp.ip_port_blocklist]
list = ["93.184.0.0/16:443"]
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
    assert!(result.action_lines[0].action.contains("Drop"));
}

// ==========================================================================
// Test 8a''': Python subnet helpers (rust.subnet / rust.ip_in)
// ==========================================================================

#[test]
fn test_python_subnet_helpers() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];

    PcapBuilder::new()
        // frame 0: dst in 198.51.100.0/24 (precompiled subnet) -> dropped
        .add_frame(&tcp_frame(client, [198, 51, 100, 9], 50000, 80, TCP_SYN, 100, 0, &[]))
        // frame 1: dst outside both subnets -> passes
        .add_frame(&tcp_frame(client, [198, 51, 101, 9], 50001, 80, TCP_SYN, 200, 0, &[]))
        // frame 2: dst in 203.0.113.0/28 (ip_in) -> dropped
        .add_frame(&tcp_frame(client, [203, 0, 113, 15], 50002, 80, TCP_SYN, 300, 0, &[]))
        // frame 3: dst just past the /28 -> passes
        .add_frame(&tcp_frame(client, [203, 0, 113, 16], 50003, 80, TCP_SYN, 400, 0, &[]))
        .write_to(&pcap_path);

    write_temp_script(
        &tmp,
        "censor.py",
        r#"from rust import subnet, ip_in

BLOCKED = subnet("198.51.100.0/24")

# Invalid subnets raise ValueError instead of matching nothing
for bad in ["10.0.0.1/8", "10.0.0.0/33", "nonsense"]:
    try:
        subnet(bad)
        raise Exception("accepted " + bad)
    except ValueError:
        pass
try:
    BLOCKED.contains("not-an-ip")
    raise Exception("accepted bad address")
except ValueError:
    pass
assert not BLOCKED.contains("::1")
assert subnet("2001:db8::/32").contains("2001:db8::1")
assert str(BLOCKED) == "198.51.100.0/24"

def process(packet):
    if BLOCKED.contains(packet.ip.dst):
        return "drop"
    if ip_in(packet.ip.dst, "203.0.113.0/28"):
        return "drop"
"#,
    );
    let config_str = r#"
[execution]
mode = "Python"
script = "censor.py"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let dropped: Vec<usize> = result
        .action_lines
        .iter()
        .filter(|l| l.action.contains("Drop"))
        .map(|l| l.packet_index)
        .collect();
    assert_eq!(
        dropped,
        vec![frame_idx(0), frame_idx(2)],
        "unexpected drops: {:?}\nstdout: {}\nstderr: {}",
        result.action_lines,
        result.stdout,
        result.stderr
    );
}

// ==========================================================================
// Test 8a'''': CensorLang subnet directive + DST_IN
// ==========================================================================

#[test]
fn test_censorlang_subnet_membership() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];

    PcapBuilder::new()
        // frame 0: dst in 198.51.100.0/24 -> terminated
        .add_frame(&tcp_frame(client, [198, 51, 100, 5], 50000, 80, TCP_SYN, 100, 0, &[]))
        // frame 1: dst outside -> passes
        .add_frame(&tcp_frame(client, [198, 51, 101, 5], 50001, 80, TCP_SYN, 200, 0, &[]))
        .write_to(&pcap_path);

    let cl_script = "subnet \"198.51.100.0/24\"\nDST_IN 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate\n";
    let config_str = r#"
[execution]
mode = "CensorLang"
script = "censor.cl"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    write_temp_script(&tmp, "censor.cl", cl_script);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let dropped: Vec<usize> = result
        .action_lines
        .iter()
        .filter(|l| l.action.contains("Drop"))
        .map(|l| l.packet_index)
        .collect();
    assert_eq!(
        dropped,
        vec![frame_idx(0)],
        "unexpected drops: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
}

// ==========================================================================
// Test 8a'': Invalid CIDR in config is rejected at load time
// ==========================================================================

#[test]
fn test_config_invalid_cidr_rejected() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    PcapBuilder::new()
        .add_frame(&tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 50000, 80, TCP_SYN, 100, 0, &[]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[ip.blocklist]
list = ["198.51.100.1/24"]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");
    assert_ne!(result.exit_code, 0, "config with host bits set should fail to load");
    assert!(
        result.stderr.contains("host bits"),
        "error should mention host bits, stderr: {}",
        result.stderr
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

    // Flow 1: DNS blocked.example.com -> Inject (forged response) (frame 0)
    assert!(
        result.action_lines.iter().any(|l| l.packet_index == frame_idx(0) && l.action.contains("Inject")),
        "Flow 1: expected Inject for DNS query to blocked.example.com (frame 0)"
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

// ==========================================================================
// Test: Per-host state in PyCL (Python)
// ==========================================================================

#[test]
fn test_python_per_host_state_counters() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    // Two different clients sending to same server
    let client_a = [10, 0, 0, 1];
    let client_b = [10, 0, 0, 2];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // Connection 1 from client_a (frames 0-2)
        .add_frame(&tcp_frame(client_a, server, 50000, 80, TCP_SYN, 100, 0, &[]))
        .add_frame(&tcp_frame(server, client_a, 80, 50000, TCP_ACK, 200, 101, &[]))
        .add_frame(&tcp_frame(client_a, server, 50000, 80, TCP_PSH_ACK, 101, 201, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        // Connection 2 from client_a (frames 3-5)
        .add_frame(&tcp_frame(client_a, server, 50001, 80, TCP_SYN, 300, 0, &[]))
        .add_frame(&tcp_frame(server, client_a, 80, 50001, TCP_ACK, 400, 301, &[]))
        .add_frame(&tcp_frame(client_a, server, 50001, 80, TCP_PSH_ACK, 301, 401, b"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        // Connection 3 from client_a (frames 6-7) — should be blocked (3rd connection)
        .add_frame(&tcp_frame(client_a, server, 50002, 80, TCP_SYN, 500, 0, &[]))
        .add_frame(&tcp_frame(client_a, server, 50002, 80, TCP_PSH_ACK, 501, 601, b"GET /blocked HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        // Connection from client_b (frames 8-9) — different host, should NOT be blocked
        .add_frame(&tcp_frame(client_b, server, 50000, 80, TCP_SYN, 700, 0, &[]))
        .add_frame(&tcp_frame(client_b, server, 50000, 80, TCP_PSH_ACK, 701, 801, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        .write_to(&pcap_path);

    // Python script that drops all traffic from a host once they exceed 2 connections
    let script = r#"
def process(packet):
    if host.num_connections > 2:
        return "drop"
"#;
    let config_str = r#"
[execution]
mode = "Python"
script = "censor.py"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    write_temp_script(&tmp, "censor.py", script);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);

    // Frames 0-5 (first 2 connections from client_a): no action
    for i in 0..6 {
        assert!(
            !result.action_lines.iter().any(|l| l.packet_index == frame_idx(i)),
            "frame {i} should not be dropped (first 2 connections from client_a)"
        );
    }

    // Frames 6-7 (3rd connection from client_a): should be dropped
    for i in 6..8 {
        assert!(
            result.action_lines.iter().any(|l| l.packet_index == frame_idx(i) && l.action.contains("Drop")),
            "frame {i} should be dropped (3rd connection from client_a, host.num_connections > 2)"
        );
    }

    // Frames 8-9 (client_b): no action (different host, only 1 connection)
    for i in 8..10 {
        assert!(
            !result.action_lines.iter().any(|l| l.packet_index == frame_idx(i)),
            "frame {i} should not be dropped (client_b only has 1 connection)"
        );
    }
}

// ==========================================================================
// Test: Per-host persistent state dict in PyCL (Python)
// ==========================================================================

#[test]
fn test_python_per_host_persistent_state() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // Connection 1: high-entropy payload triggers flagging (frames 0-1)
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]))
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 101, 201, &high_entropy_payload(256)))
        // Connection 2: any data from same host should be dropped (frames 2-3)
        .add_frame(&tcp_frame(client, server, 50001, 80, TCP_SYN, 300, 0, &[]))
        .add_frame(&tcp_frame(client, server, 50001, 80, TCP_PSH_ACK, 301, 401, b"normal data"))
        .write_to(&pcap_path);

    // Python script that demonstrates residual censorship via host.state
    let script = r#"
def process(packet):
    if host.state.get("blocked"):
        return "drop"
    if packet.payload_len > 0 and packet.payload_entropy > 0.9:
        host.state["blocked"] = True
        return "drop"
"#;
    let config_str = r#"
[execution]
mode = "Python"
script = "censor.py"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    write_temp_script(&tmp, "censor.py", script);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);

    // Frame 0 (SYN): no payload, no action
    assert!(
        !result.action_lines.iter().any(|l| l.packet_index == frame_idx(0)),
        "SYN should not trigger action"
    );

    // Frame 1 (high-entropy data): dropped + host flagged
    assert!(
        result.action_lines.iter().any(|l| l.packet_index == frame_idx(1) && l.action.contains("Drop")),
        "high-entropy payload should be dropped"
    );

    // Frame 3 (normal data on new connection): dropped because host.state["blocked"] persists
    assert!(
        result.action_lines.iter().any(|l| l.packet_index == frame_idx(3) && l.action.contains("Drop")),
        "second connection should be dropped via persistent host.state (residual censorship)"
    );
}

// ==========================================================================
// Test: Per-host state in CensorLang
// ==========================================================================

#[test]
fn test_censorlang_per_host_fields() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client_a = [10, 0, 0, 1];
    let client_b = [10, 0, 0, 2];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // Connection 1 from client_a (frames 0-1)
        .add_frame(&tcp_frame(client_a, server, 50000, 80, TCP_SYN, 100, 0, &[]))
        .add_frame(&tcp_frame(client_a, server, 50000, 80, TCP_PSH_ACK, 101, 201, b"hello"))
        // Connection 2 from client_a (frames 2-3)
        .add_frame(&tcp_frame(client_a, server, 50001, 80, TCP_SYN, 300, 0, &[]))
        .add_frame(&tcp_frame(client_a, server, 50001, 80, TCP_PSH_ACK, 301, 401, b"world"))
        // Connection 3 from client_a (frames 4-5) — exceeds threshold
        .add_frame(&tcp_frame(client_a, server, 50002, 80, TCP_SYN, 500, 0, &[]))
        .add_frame(&tcp_frame(client_a, server, 50002, 80, TCP_PSH_ACK, 501, 601, b"blocked"))
        // Connection from client_b (frames 6-7) — different host, fine
        .add_frame(&tcp_frame(client_b, server, 50000, 80, TCP_SYN, 700, 0, &[]))
        .add_frame(&tcp_frame(client_b, server, 50000, 80, TCP_PSH_ACK, 701, 801, b"ok"))
        .write_to(&pcap_path);

    // CensorLang program that terminates hosts with >2 connections
    let cl_script = "if field:host.num_connections > 2 : RETURN terminate\n";
    let config_str = r#"
[execution]
mode = "CensorLang"
script = "censor.cl"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    write_temp_script(&tmp, "censor.cl", cl_script);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);

    // Frames 0-3 (first 2 connections from client_a): no action
    for i in 0..4 {
        assert!(
            !result.action_lines.iter().any(|l| l.packet_index == frame_idx(i)),
            "frame {i} should not be terminated (first 2 connections from client_a)"
        );
    }

    // Frames 4-5 (3rd connection from client_a): terminated
    for i in 4..6 {
        assert!(
            result.action_lines.iter().any(|l| l.packet_index == frame_idx(i) && l.action.contains("Drop")),
            "frame {i} should be terminated (3rd connection from client_a, host.num_connections > 2)"
        );
    }

    // Frames 6-7 (client_b): no action
    for i in 6..8 {
        assert!(
            !result.action_lines.iter().any(|l| l.packet_index == frame_idx(i)),
            "frame {i} should not be terminated (client_b only has 1 connection)"
        );
    }
}

// ==========================================================================
// Test: CensorLang host registers (persist across connections from same IP)
// ==========================================================================

#[test]
fn test_censorlang_host_registers() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let client_b = [10, 0, 0, 2];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // Connection 1 from client: high-entropy payload triggers flag (frames 0-1)
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]))
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 101, 201, &high_entropy_payload(256)))
        // Connection 2 from client: normal data, but host is flagged (frames 2-3)
        .add_frame(&tcp_frame(client, server, 50001, 80, TCP_SYN, 300, 0, &[]))
        .add_frame(&tcp_frame(client, server, 50001, 80, TCP_PSH_ACK, 301, 401, b"normal data"))
        // Connection from client_b: not flagged (frames 4-5)
        .add_frame(&tcp_frame(client_b, server, 50000, 80, TCP_SYN, 500, 0, &[]))
        .add_frame(&tcp_frame(client_b, server, 50000, 80, TCP_PSH_ACK, 501, 601, b"hello"))
        .write_to(&pcap_path);

    // CensorLang program:
    // 1. If hreg:b.0 is set, terminate (residual censorship)
    // 2. If entropy > 7.0, set hreg:b.0 and terminate
    let cl_script = "\
if hreg:b.0 == True : RETURN terminate
if field:transport.payload.entropy > 0.9 : COPY True -> hreg:b.0
if field:transport.payload.entropy > 0.9 : RETURN terminate
";
    let config_str = r#"
[execution]
mode = "CensorLang"
script = "censor.cl"

[execution.program]
num_registers = 16

[execution.env]
field_default_on_error = true
"#;
    let config_path = write_temp_config(&tmp, config_str);
    write_temp_script(&tmp, "censor.cl", cl_script);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);

    // Frame 0 (SYN, no payload): no action
    assert!(
        !result.action_lines.iter().any(|l| l.packet_index == frame_idx(0)),
        "SYN should not trigger action"
    );

    // Frame 1 (high-entropy data): dropped + host flagged via hreg:b.0
    assert!(
        result.action_lines.iter().any(|l| l.packet_index == frame_idx(1) && l.action.contains("Drop")),
        "high-entropy payload should be dropped"
    );

    // Frames 2-3 (second connection from same client): should be dropped because hreg:b.0 persists
    for i in 2..4 {
        assert!(
            result.action_lines.iter().any(|l| l.packet_index == frame_idx(i) && l.action.contains("Drop")),
            "frame {i} should be dropped via residual host register censorship"
        );
    }

    // Frames 4-5 (client_b): no action (different host, hreg:b.0 not set)
    for i in 4..6 {
        assert!(
            !result.action_lines.iter().any(|l| l.packet_index == frame_idx(i)),
            "frame {i} should not be dropped (client_b has no flag)"
        );
    }
}

// ==========================================================================
// PyCL structured return values: ("rewrite", {...}) and ("delay", seconds)
// ==========================================================================

#[test]
fn test_python_rewrite_and_delay_actions() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    // Frame 0: a normal segment (TTL 64) -> must be delayed by the script.
    // Frame 1: a low-TTL "fake" segment (TTL 3), the kind of packet used by
    //          desync tools against DPI -> must be rewritten to TTL 64.
    let normal = tcp_frame(client, server, 50000, 80, TCP_PSH_ACK, 101, 201, b"hello");
    let mut fake = tcp_frame(client, server, 50000, 80, TCP_PSH_ACK, 101, 201, b"fake!");
    common::packet_builder::set_ipv4_ttl(&mut fake, 3);

    PcapBuilder::new()
        .add_frame(&normal)
        .add_frame(&fake)
        .write_to(&pcap_path);

    let script = r#"
def process(packet):
    if packet.ip.ttl < 10:
        return ("rewrite", {"ttl": 64})
    return ("delay", 0.25)
"#;
    write_temp_script(&tmp, "censor.py", script);
    let config = write_temp_config(
        &tmp,
        r#"
[execution]
mode = "Python"
script = "censor.py"
"#,
    );

    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);

    let delayed = result
        .action_lines
        .iter()
        .find(|l| l.packet_index == frame_idx(0))
        .unwrap_or_else(|| panic!("no action for frame 0: {:?}\n{}", result.action_lines, result.stdout));
    assert!(
        delayed.action.contains("Delay"),
        "frame 0 should be delayed, got {}",
        delayed.action
    );

    let rewritten = result
        .action_lines
        .iter()
        .find(|l| l.packet_index == frame_idx(1))
        .unwrap_or_else(|| panic!("no action for frame 1: {:?}\n{}", result.action_lines, result.stdout));
    assert!(
        rewritten.action.contains("Rewrite") && rewritten.action.contains("ttl: Some(64)"),
        "frame 1 should be rewritten to TTL 64, got {}",
        rewritten.action
    );
}

// ==========================================================================
// Corpus programs added for the revision: TSPU TTL normalization, TLS-in-TLS
// ==========================================================================

/// A TLS application-data record (type 0x17) with `len` bytes of opaque body.
fn tls_app_record(len: usize) -> Vec<u8> {
    let mut r = vec![0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
    r.extend(std::iter::repeat_n(0xAA, len));
    r
}

#[test]
fn test_demo_tspu_ttl_normalization() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    // Handshake (TTL 64 baseline), then a low-TTL fake ClientHello with a decoy
    // SNI, then the real ClientHello for a forbidden domain.
    let mut fake = tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 101, 201,
                             &tls_client_hello_record("www.example.com"));
    common::packet_builder::set_ipv4_ttl(&mut fake, 3);
    let frames = [
        tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]),
        tcp_frame(server, client, 443, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]),
        tcp_frame(client, server, 50000, 443, TCP_ACK, 101, 201, &[]),
        fake,
        tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 101, 201,
                  &tls_client_hello_record("www.example.org")),
    ];
    let mut b = PcapBuilder::new();
    for f in &frames {
        b = b.add_frame(f);
    }
    b.write_to(&pcap_path);

    let result = run_pcap_with_config(&demo_config("tspu_ttl_normalization"), &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let act = |n: usize| result.action_lines.iter().find(|l| l.packet_index == frame_idx(n)).map(|l| l.action.clone());
    assert!(act(3).is_some_and(|a| a.contains("Rewrite") && a.contains("ttl: Some(64)")),
            "fake segment should be TTL-normalized: {:?}\n{}", result.action_lines, result.stdout);
    assert!(act(4).is_some_and(|a| a.contains("Reset")),
            "real forbidden ClientHello should be reset: {:?}", result.action_lines);
    assert!(act(0).is_none() && act(1).is_none() && act(2).is_none(), "handshake must pass");
}

#[test]
fn test_demo_tls_in_tls() {
    let tmp = TempDir::new().unwrap();
    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    // Outer connection carrying an inner TLS handshake: 350 B client record
    // (inner ClientHello), 1400 + 900 B server records (inner ServerHello +
    // Certificate), 74 B client record (inner Finished).
    let tunnel = [
        tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]),
        tcp_frame(server, client, 443, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]),
        tcp_frame(client, server, 50000, 443, TCP_ACK, 101, 201, &[]),
        tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 101, 201, &tls_client_hello_record("cdn.example.net")),
        tcp_frame(server, client, 443, 50000, TCP_PSH_ACK, 201, 400, &tls_app_record(2000)),
        tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 400, 2206, &tls_app_record(60)),   // outer Finished (1.3)
        tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 465, 2206, &tls_app_record(350)),  // inner ClientHello
        tcp_frame(server, client, 443, 50000, TCP_PSH_ACK, 2206, 820, &tls_app_record(1400)), // inner ServerHello+Cert
        tcp_frame(server, client, 443, 50000, TCP_PSH_ACK, 3611, 820, &tls_app_record(900)),
        tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 820, 4516, &tls_app_record(74)),   // inner Finished
    ];
    // Plain HTTPS: same outer handshake, then request/response/request.
    let https = [
        tcp_frame(client, server, 50001, 443, TCP_SYN, 100, 0, &[]),
        tcp_frame(server, client, 443, 50001, TCP_SYN | TCP_ACK, 200, 101, &[]),
        tcp_frame(client, server, 50001, 443, TCP_ACK, 101, 201, &[]),
        tcp_frame(client, server, 50001, 443, TCP_PSH_ACK, 101, 201, &tls_client_hello_record("www.example.net")),
        tcp_frame(server, client, 443, 50001, TCP_PSH_ACK, 201, 400, &tls_app_record(2000)),
        tcp_frame(client, server, 50001, 443, TCP_PSH_ACK, 400, 2206, &tls_app_record(60)),
        tcp_frame(client, server, 50001, 443, TCP_PSH_ACK, 465, 2206, &tls_app_record(350)),  // GET
        tcp_frame(server, client, 443, 50001, TCP_PSH_ACK, 2206, 820, &tls_app_record(1400)), // response
        tcp_frame(server, client, 443, 50001, TCP_PSH_ACK, 3611, 820, &tls_app_record(900)),
        tcp_frame(client, server, 50001, 443, TCP_PSH_ACK, 820, 4516, &tls_app_record(310)),  // next GET
    ];

    let pcap_path = tmp.path().join("test.pcap");
    let mut b = PcapBuilder::new();
    for f in tunnel.iter().chain(https.iter()) {
        b = b.add_frame(f);
    }
    b.write_to(&pcap_path);

    let result = run_pcap_with_config(&demo_config("tls_in_tls"), &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let resets: Vec<usize> = result.action_lines.iter()
        .filter(|l| l.action.contains("Reset")).map(|l| l.packet_index).collect();
    assert_eq!(resets, vec![frame_idx(9)],
               "only the tunnel's inner Finished should trigger a reset: {:?}\n{}", result.action_lines, result.stdout);
}

#[test]
fn test_demo_throttling_delays_matching_connection() {
    let tmp = TempDir::new().unwrap();
    let client = [10, 0, 0, 1];
    let server = [104, 244, 42, 1];
    let frames = [
        tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]),
        tcp_frame(server, client, 443, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]),
        tcp_frame(client, server, 50000, 443, TCP_ACK, 101, 201, &[]),
        tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 101, 201, &tls_client_hello_record("abs.twimg.com")),
        tcp_frame(server, client, 443, 50000, TCP_PSH_ACK, 201, 400, &tls_app_record(1200)),
        tcp_frame(client, server, 50000, 443, TCP_ACK, 400, 1406, &[]),
    ];
    let pcap_path = tmp.path().join("test.pcap");
    let mut b = PcapBuilder::new();
    for f in &frames {
        b = b.add_frame(f);
    }
    b.write_to(&pcap_path);

    let result = run_pcap_with_config(&demo_config("throttling"), &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let delayed: Vec<usize> = result.action_lines.iter()
        .filter(|l| l.action.contains("Delay")).map(|l| l.packet_index).collect();
    assert_eq!(delayed, vec![frame_idx(3), frame_idx(4), frame_idx(5)],
               "ClientHello and every later packet must be delayed: {:?}", result.action_lines);
}

// ==========================================================================
// CensorLang must see the packet direction (it was only set for PyCL)
// ==========================================================================

#[test]
fn test_censorlang_direction_field() {
    let tmp = TempDir::new().unwrap();
    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];
    let frames = [
        tcp_frame(client, server, 50000, 80, TCP_SYN, 100, 0, &[]),                      // client -> wan
        tcp_frame(server, client, 80, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]),          // wan -> client
        tcp_frame(client, server, 50000, 80, TCP_PSH_ACK, 101, 201, b"GET / HTTP/1.1\r\n\r\n"),
        tcp_frame(server, client, 80, 50000, TCP_PSH_ACK, 201, 120, b"HTTP/1.1 200 OK\r\n\r\n"),
    ];
    let pcap_path = tmp.path().join("test.pcap");
    let mut b = PcapBuilder::new();
    for f in &frames {
        b = b.add_frame(f);
    }
    b.write_to(&pcap_path);

    write_temp_script(&tmp, "censor.cl", "if field:direction == -1: RETURN terminate\nRETURN allow\n");
    let config = write_temp_config(&tmp, "[execution]\nmode = \"CensorLang\"\nscript = \"censor.cl\"\n");
    let result = run_pcap_with_config(&config, &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let dropped: Vec<usize> = result.action_lines.iter()
        .filter(|l| l.action.contains("Drop")).map(|l| l.packet_index).collect();
    // frame 1 is the first wan -> client packet; `terminate` then drops the rest
    // of the connection (frames 2, 3).  Frame 0 (client -> wan) must pass.
    assert_eq!(dropped, vec![frame_idx(1), frame_idx(2), frame_idx(3)],
               "the connection must be terminated at the first wan->client packet: {:?}\n{}",
               result.action_lines, result.stdout);
}

// ===========================================================================
// Exit status: a censor run that fails must exit nonzero so harnesses notice.
// ===========================================================================
#[test]
fn test_pcap_missing_file_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("does_not_exist.pcap");
    let result = run_pcap_with_config(&demo_config("null"), &missing, "10.0.0.1");
    assert_ne!(result.exit_code, 0,
               "pcap mode on a nonexistent file must fail\nstdout: {}\nstderr: {}",
               result.stdout, result.stderr);
}

// ==========================================================================
// Allowlists accept a packet if either endpoint is listed
// ==========================================================================

#[test]
fn test_config_tcp_port_allowlist_matches_either_endpoint() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // frame 0: ephemeral client port -> 443 (allowlisted) -> passes
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_SYN, 100, 0, &[]))
        // frame 1: reply 443 -> ephemeral port -> passes
        .add_frame(&tcp_frame(server, client, 443, 50000, TCP_SYN | TCP_ACK, 200, 101, &[]))
        // frame 2: ephemeral client port -> 80 (not allowlisted) -> dropped
        .add_frame(&tcp_frame(client, server, 50001, 80, TCP_SYN, 300, 0, &[]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = [] }

[tcp.port_allowlist]
list = [443]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        result.action_lines.len(),
        1,
        "only the port-80 SYN should be dropped, got: {:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines[0].packet_index, frame_idx(2));
    assert!(result.action_lines[0].action.contains("Drop"));
}

// ==========================================================================
// IP-layer rules apply regardless of the transport protocol
// ==========================================================================

const V6_CLIENT: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const V6_SERVER: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// IPv6 next-header values
const HOP_BY_HOP: u8 = 0;
const ICMPV6: u8 = 58;
const TCP: u8 = 6;

/// An 8-byte hop-by-hop options header (PadN) followed by `inner`.
fn hop_by_hop(next: u8, inner: &[u8]) -> Vec<u8> {
    let mut v = vec![next, 0, 1, 4, 0, 0, 0, 0];
    v.extend_from_slice(inner);
    v
}

/// Indices of frames that produced an action containing `needle`.
fn frames_with(result: &common::runner::RunResult, needle: &str) -> Vec<usize> {
    result
        .action_lines
        .iter()
        .filter(|l| l.action.contains(needle))
        .map(|l| l.packet_index)
        .collect()
}

#[test]
fn test_ip_blocklist_applies_to_non_tcp_udp() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let blocked = [8, 8, 8, 8];
    let allowed = [1, 1, 1, 1];

    PcapBuilder::new()
        // frame 0: ICMP echo to blocked IP
        .add_frame(&ipv4_raw_frame(client, blocked, 1, &icmp_echo(8)))
        // frame 1: GRE to blocked IP
        .add_frame(&ipv4_raw_frame(client, blocked, 47, &[0; 8]))
        // frame 2: truncated TCP header to blocked IP
        .add_frame(&ipv4_raw_frame(client, blocked, 6, &[0; 4]))
        // frame 3: ICMPv6 behind a hop-by-hop header from a blocked IPv6 address
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, HOP_BY_HOP, &hop_by_hop(ICMPV6, &icmp_echo(128))))
        // frame 4: ICMP echo to an allowed IP -> passes
        .add_frame(&ipv4_raw_frame(client, allowed, 1, &icmp_echo(8)))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[ip.blocklist]
list = ["8.8.8.8", "2001:db8::2"]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        frames_with(&result, "Drop"),
        vec![frame_idx(0), frame_idx(1), frame_idx(2), frame_idx(3)],
        "{:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines.len(), 4, "{:?}", result.action_lines);
}

#[test]
fn test_icmp_action_covers_icmpv4_and_icmpv6() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [8, 8, 8, 8];

    PcapBuilder::new()
        // frame 0: ICMPv4 echo
        .add_frame(&ipv4_raw_frame(client, server, 1, &icmp_echo(8)))
        // frame 1: ICMPv6 echo
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, ICMPV6, &icmp_echo(128)))
        // frame 2: ICMPv6 behind a hop-by-hop header (e.g. MLD)
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, HOP_BY_HOP, &hop_by_hop(ICMPV6, &icmp_echo(128))))
        // frame 3: truncated ICMPv4 header: still ICMP
        .add_frame(&ipv4_raw_frame(client, server, 1, &[8, 0]))
        // frame 4: GRE is not ICMP -> ip.unknown (default: continue)
        .add_frame(&ipv4_raw_frame(client, server, 47, &[0; 8]))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[icmp]
action = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        frames_with(&result, "Drop"),
        vec![frame_idx(0), frame_idx(1), frame_idx(2), frame_idx(3)],
        "{:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines.len(), 4, "{:?}", result.action_lines);
}

#[test]
fn test_ip_unknown_applies_to_unknown_protocols_only() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [8, 8, 8, 8];

    PcapBuilder::new()
        // frame 0: GRE -> unknown
        .add_frame(&ipv4_raw_frame(client, server, 47, &[0; 8]))
        // frame 1: ICMP -> icmp.action (default: continue)
        .add_frame(&ipv4_raw_frame(client, server, 1, &icmp_echo(8)))
        // frame 2: TCP behind a hop-by-hop header is TCP, not unknown
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, HOP_BY_HOP,
                                   &hop_by_hop(TCP, &raw_tcp_header(50000, 80, TCP_SYN, 1, 0))))
        // frame 3: GRE over IPv6 behind a hop-by-hop header -> unknown
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, HOP_BY_HOP, &hop_by_hop(47, &[0; 8])))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[ip]
unknown = "Drop"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        frames_with(&result, "Drop"),
        vec![frame_idx(0), frame_idx(3)],
        "{:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines.len(), 2, "{:?}", result.action_lines);
}

#[test]
fn test_tcp_port_blocklist_sees_through_ipv6_extension_headers() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    PcapBuilder::new()
        // frame 0: TCP SYN to port 443 behind a hop-by-hop header -> dropped
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, HOP_BY_HOP,
                                   &hop_by_hop(TCP, &raw_tcp_header(50000, 443, TCP_SYN, 1, 0))))
        // frame 1: TCP SYN to port 80 behind a hop-by-hop header -> passes
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, HOP_BY_HOP,
                                   &hop_by_hop(TCP, &raw_tcp_header(50001, 80, TCP_SYN, 1, 0))))
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
    let result = run_pcap_with_config(&config_path, &pcap_path, "2001:db8::1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(
        frames_with(&result, "Drop"),
        vec![frame_idx(0)],
        "{:?}\nstdout: {}",
        result.action_lines,
        result.stdout
    );
    assert_eq!(result.action_lines.len(), 1, "{:?}", result.action_lines);
}

// ==========================================================================
// List-derived Resets must target the triggering connection
// ==========================================================================

#[test]
fn test_tcp_port_blocklist_reset_is_populated() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let server = [93, 184, 216, 34];

    PcapBuilder::new()
        // frame 0: data segment to port 443 -> Reset for this connection
        .add_frame(&tcp_frame(client, server, 50000, 443, TCP_PSH_ACK, 1000, 2000, b"hello"))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = [] }

[tcp.port_blocklist]
list = [443]
action = "Reset"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(result.action_lines.len(), 1, "{:?}", result.action_lines);
    let action = &result.action_lines[0].action;
    for needle in [
        "Reset",
        "src: Address([10, 0, 0, 1])",
        "dst: Address([93, 184, 216, 34])",
        "src_port: 50000",
        "dst_port: 443",
        "seq: SeqNumber(1000)",
        "ack: SeqNumber(2000)",
        "is_ack: true",
    ] {
        assert!(action.contains(needle), "expected {needle:?} in {action}");
    }
}

#[test]
fn test_ip_blocklist_reset_resets_tcp_and_drops_other_traffic() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");

    let client = [10, 0, 0, 1];
    let blocked = [8, 8, 8, 8];

    PcapBuilder::new()
        // frame 0: TCP to a blocked IP -> populated Reset
        .add_frame(&tcp_frame(client, blocked, 50000, 80, TCP_PSH_ACK, 1000, 2000, b"hi"))
        // frame 1: ICMP to a blocked IP -> no connection to reset, so Drop
        .add_frame(&ipv4_raw_frame(client, blocked, 1, &icmp_echo(8)))
        // frame 2: UDP to a blocked IP -> Drop
        .add_frame(&udp_frame(client, blocked, 50001, 53, &[0; 4]))
        // frame 3: truncated TCP header to a blocked IP -> Drop
        .add_frame(&ipv4_raw_frame(client, blocked, 6, &[0; 4]))
        // frame 4: TCP over IPv6 behind a hop-by-hop header -> populated Reset
        .add_frame(&ipv6_raw_frame(V6_CLIENT, V6_SERVER, HOP_BY_HOP,
                                   &hop_by_hop(TCP, &raw_tcp_header(50002, 443, TCP_SYN, 7, 0))))
        .write_to(&pcap_path);

    let config_str = r#"
[execution]
mode = "Python"

[ip.blocklist]
list = ["8.8.8.8", "2001:db8::2"]
action = "Reset"
"#;
    let config_path = write_temp_config(&tmp, config_str);
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(result.action_lines.len(), 5, "{:?}", result.action_lines);
    let reset = &result.action_lines[0].action;
    for needle in ["Reset", "src_port: 50000", "dst_port: 80", "seq: SeqNumber(1000)"] {
        assert!(reset.contains(needle), "expected {needle:?} in {reset}");
    }
    let reset_v6 = &result.action_lines[4].action;
    for needle in ["Reset", "src_port: 50002", "dst_port: 443", "seq: SeqNumber(7)"] {
        assert!(reset_v6.contains(needle), "expected {needle:?} in {reset_v6}");
    }
    assert_eq!(
        frames_with(&result, "Drop"),
        vec![frame_idx(1), frame_idx(2), frame_idx(3)],
        "{:?}",
        result.action_lines
    );
}
