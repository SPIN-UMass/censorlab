//! Connection-tracking lifecycle tests (PCAP mode).
//!
//! These exercise teardown of per-connection state (FIN/RST, idle timeout,
//! table size caps) and bounding of per-host state.
mod common;

use common::packet_builder::{
    tcp_frame, tls_client_hello_record, udp_frame, TCP_ACK, TCP_FIN, TCP_PSH_ACK, TCP_RST, TCP_SYN,
};
use common::pcap_builder::PcapBuilder;
use common::runner::{run_pcap_with_config, RunResult};
use tempfile::TempDir;

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [93, 184, 216, 34];

/// Per-connection packet counter. The counter lives in the connection's
/// script scope, so it restarts at 0 whenever a fresh connection is tracked.
/// Drops any payload-carrying packet once the connection has seen `limit`
/// packets.
fn counting_script(limit: usize) -> String {
    format!(
        r#"
n = 0
def process(packet):
    global n
    n += 1
    if n >= {limit} and packet.payload_len > 0:
        return "drop"
"#
    )
}

/// Write `script` and a config (with `extra` appended) to `tmp`, run the
/// pcap and return the result.
fn run(tmp: &TempDir, pcap: PcapBuilder, script: &str, extra: &str) -> RunResult {
    let pcap_path = tmp.path().join("test.pcap");
    pcap.write_to(&pcap_path);
    std::fs::write(tmp.path().join("censor.py"), script).unwrap();
    let config = format!(
        "[execution]\nmode = \"Python\"\nscript = \"censor.py\"\n{extra}"
    );
    let config_path = tmp.path().join("censor.toml");
    std::fs::write(&config_path, config).unwrap();
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result
}

fn dropped(result: &RunResult) -> Vec<usize> {
    result
        .action_lines
        .iter()
        .filter(|l| l.action.contains("Drop"))
        // The pcap global header consumes packet_index 1, so frame n is n + 2
        .map(|l| l.packet_index - 2)
        .collect()
}

/// A full TCP handshake + one data packet on (CLIENT:sport, SERVER:80).
fn handshake_and_data(b: PcapBuilder, sport: u16, isn: u32) -> PcapBuilder {
    b.add_frame(&tcp_frame(CLIENT, SERVER, sport, 80, TCP_SYN, isn, 0, &[]))
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, sport, TCP_SYN | TCP_ACK, 9000, isn + 1, &[]))
        .add_frame(&tcp_frame(CLIENT, SERVER, sport, 80, TCP_PSH_ACK, isn + 1, 9001, b"hello"))
}

#[test]
fn tcp_port_reuse_after_fin_starts_fresh_connection() {
    let tmp = TempDir::new().unwrap();
    let b = handshake_and_data(PcapBuilder::new(), 50000, 100)
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_FIN | TCP_ACK, 106, 9001, &[]))
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50000, TCP_FIN | TCP_ACK, 9001, 107, &[]))
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_ACK, 107, 9002, &[]));
    // Same 5-tuple, new connection
    let b = handshake_and_data(b, 50000, 5000);
    let result = run(&tmp, b, &counting_script(4), "");
    assert_eq!(
        dropped(&result),
        Vec::<usize>::new(),
        "a new SYN after FIN/FIN must start a fresh connection (init re-run): {:?}",
        result.action_lines
    );
}

#[test]
fn tcp_port_reuse_after_rst_starts_fresh_connection() {
    let tmp = TempDir::new().unwrap();
    let b = handshake_and_data(PcapBuilder::new(), 50000, 100)
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50000, TCP_RST, 9001, 0, &[]));
    let b = handshake_and_data(b, 50000, 5000);
    let result = run(&tmp, b, &counting_script(4), "");
    assert_eq!(dropped(&result), Vec::<usize>::new(), "{:?}", result.action_lines);
}

#[test]
fn packets_after_close_stay_in_the_closed_connection() {
    // The final ACK (and stray retransmissions) after FIN/FIN or RST must not
    // be tracked as a brand-new connection.
    let tmp = TempDir::new().unwrap();
    let b = handshake_and_data(PcapBuilder::new(), 50000, 100)
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_FIN | TCP_ACK, 106, 9001, &[]))
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50000, TCP_FIN | TCP_ACK, 9001, 107, &[]))
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_ACK, 107, 9002, &[]))
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_PSH_ACK, 101, 9001, b"retx"));
    let script = r#"
def process(packet):
    if host.num_connections > 1:
        return "drop"
"#;
    let result = run(&tmp, b, script, "");
    assert_eq!(dropped(&result), Vec::<usize>::new(), "{:?}", result.action_lines);
}

#[test]
fn script_sees_fin_and_rst_packets() {
    let tmp = TempDir::new().unwrap();
    let b = handshake_and_data(PcapBuilder::new(), 50000, 100)
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_FIN | TCP_ACK, 106, 9001, &[]))
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50000, TCP_FIN | TCP_ACK, 9001, 107, &[]));
    let b = handshake_and_data(b, 50001, 100)
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50001, TCP_RST, 9001, 0, &[]));
    let script = r#"
def process(packet):
    if packet.tcp.flags.fin or packet.tcp.flags.rst:
        return "drop"
"#;
    let result = run(&tmp, b, script, "");
    assert_eq!(dropped(&result), vec![3, 4, 8], "{:?}", result.action_lines);
}

#[test]
fn udp_idle_timeout_starts_fresh_connection() {
    let tmp = TempDir::new().unwrap();
    let b = PcapBuilder::new()
        .add_frame_at(0, &udp_frame(CLIENT, SERVER, 40000, 53, b"one"))
        .add_frame_at(1000, &udp_frame(CLIENT, SERVER, 40000, 53, b"two"));
    let result = run(&tmp, b, &counting_script(2), "");
    assert_eq!(
        dropped(&result),
        Vec::<usize>::new(),
        "UDP flow idle for 1000s must be forgotten by default: {:?}",
        result.action_lines
    );
}

#[test]
fn udp_idle_timeout_is_configurable() {
    let tmp = TempDir::new().unwrap();
    let b = PcapBuilder::new()
        .add_frame_at(0, &udp_frame(CLIENT, SERVER, 40000, 53, b"one"))
        .add_frame_at(1000, &udp_frame(CLIENT, SERVER, 40000, 53, b"two"));
    let result = run(&tmp, b, &counting_script(2), "[conntrack]\nudp_idle_timeout = 5000\n");
    assert_eq!(dropped(&result), vec![1], "{:?}", result.action_lines);
}

#[test]
fn tcp_idle_timeout_starts_fresh_connection() {
    let tmp = TempDir::new().unwrap();
    let b = PcapBuilder::new()
        .add_frame_at(0, &tcp_frame(CLIENT, SERVER, 50000, 80, TCP_SYN, 100, 0, &[]))
        .add_frame_at(1, &tcp_frame(CLIENT, SERVER, 50000, 80, TCP_PSH_ACK, 101, 1, b"a"))
        .add_frame_at(100_000, &tcp_frame(CLIENT, SERVER, 50000, 80, TCP_PSH_ACK, 102, 1, b"b"));
    let result = run(&tmp, b, &counting_script(3), "");
    assert_eq!(dropped(&result), Vec::<usize>::new(), "{:?}", result.action_lines);
}

#[test]
fn max_connections_evicts_least_recently_seen() {
    let tmp = TempDir::new().unwrap();
    let b = PcapBuilder::new()
        .add_frame(&udp_frame(CLIENT, SERVER, 40000, 53, b"a1"))
        .add_frame(&udp_frame(CLIENT, SERVER, 40001, 53, b"b1"))
        .add_frame(&udp_frame(CLIENT, SERVER, 40000, 53, b"a2"));
    let result = run(&tmp, b, &counting_script(2), "[conntrack]\nmax_connections = 1\n");
    assert_eq!(
        dropped(&result),
        Vec::<usize>::new(),
        "flow A must have been evicted by flow B: {:?}",
        result.action_lines
    );
    // Sanity: without the cap, flow A is remembered
    let tmp = TempDir::new().unwrap();
    let b = PcapBuilder::new()
        .add_frame(&udp_frame(CLIENT, SERVER, 40000, 53, b"a1"))
        .add_frame(&udp_frame(CLIENT, SERVER, 40001, 53, b"b1"))
        .add_frame(&udp_frame(CLIENT, SERVER, 40000, 53, b"a2"));
    let result = run(&tmp, b, &counting_script(2), "");
    assert_eq!(dropped(&result), vec![2], "{:?}", result.action_lines);
}

#[test]
fn max_hosts_evicts_least_recently_seen_host_state() {
    let other: [u8; 4] = [10, 0, 0, 2];
    let script = r#"
def process(packet):
    if host.state.get("seen"):
        return "drop"
    host.state["seen"] = True
"#;
    let frames = |b: PcapBuilder| {
        b.add_frame(&udp_frame(CLIENT, SERVER, 40000, 53, b"x"))
            .add_frame(&udp_frame(other, SERVER, 40000, 53, b"x"))
            .add_frame(&udp_frame(CLIENT, SERVER, 40001, 53, b"x"))
    };
    let tmp = TempDir::new().unwrap();
    let result = run(&tmp, frames(PcapBuilder::new()), script, "[conntrack]\nmax_hosts = 2\n");
    assert_eq!(
        dropped(&result),
        Vec::<usize>::new(),
        "CLIENT's host state must have been evicted: {:?}",
        result.action_lines
    );
    // Sanity: without the cap, host state persists across connections
    let tmp = TempDir::new().unwrap();
    let result = run(&tmp, frames(PcapBuilder::new()), script, "");
    assert_eq!(dropped(&result), vec![2], "{:?}", result.action_lines);
}

#[test]
fn tls_client_hello_does_not_leak_across_port_reuse() {
    let tmp = TempDir::new().unwrap();
    let hello = tls_client_hello_record("first.example");
    let hello_end = 101 + hello.len() as u32;
    // Connection 1 completes a ClientHello, then closes with FIN/FIN/ACK
    let b = PcapBuilder::new()
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_SYN, 100, 0, &[]))
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50000, TCP_SYN | TCP_ACK, 9000, 101, &[]))
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_PSH_ACK, 101, 9001, &hello))
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_FIN | TCP_ACK, hello_end, 9001, &[]))
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50000, TCP_FIN | TCP_ACK, 9001, hello_end + 1, &[]))
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_ACK, hello_end + 1, 9002, &[]));
    // Connection 2 on the same 5-tuple sends plain (non-TLS) data
    let b = handshake_and_data(b, 50000, 5000);
    let script = r#"
def process(packet):
    if packet.tls_client_hello is not None:
        return "drop"
"#;
    let result = run(&tmp, b, script, "");
    assert_eq!(
        dropped(&result),
        // Frames 2-5 are connection 1 from the ClientHello on; 6-8 are connection 2
        vec![2, 3, 4, 5],
        "connection 2 must not see connection 1's ClientHello: {:?}",
        result.action_lines
    );
}

#[test]
fn censorlang_port_reuse_after_fin_starts_fresh_connection() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    // 6 packets on the first connection, 3 on the second
    let b = handshake_and_data(PcapBuilder::new(), 50000, 100)
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_FIN | TCP_ACK, 106, 9001, &[]))
        .add_frame(&tcp_frame(SERVER, CLIENT, 80, 50000, TCP_FIN | TCP_ACK, 9001, 107, &[]))
        .add_frame(&tcp_frame(CLIENT, SERVER, 50000, 80, TCP_ACK, 107, 9002, &[]));
    handshake_and_data(b, 50000, 5000).write_to(&pcap_path);
    std::fs::write(
        tmp.path().join("censor.cl"),
        "if field:env.num_packets > 6: RETURN terminate\nRETURN allow\n",
    )
    .unwrap();
    let config_path = tmp.path().join("censor.toml");
    std::fs::write(
        &config_path,
        "[execution]\nmode = \"CensorLang\"\nscript = \"censor.cl\"\n",
    )
    .unwrap();
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(dropped(&result), Vec::<usize>::new(), "{:?}", result.action_lines);
}

#[test]
fn invalid_conntrack_config_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let pcap_path = tmp.path().join("test.pcap");
    PcapBuilder::new()
        .add_frame(&udp_frame(CLIENT, SERVER, 40000, 53, b"x"))
        .write_to(&pcap_path);
    std::fs::write(tmp.path().join("censor.py"), "def process(packet):\n    pass\n").unwrap();
    let config_path = tmp.path().join("censor.toml");
    std::fs::write(
        &config_path,
        "[execution]\nmode = \"Python\"\nscript = \"censor.py\"\n[conntrack]\nmax_connections = 0\n",
    )
    .unwrap();
    let result = run_pcap_with_config(&config_path, &pcap_path, "10.0.0.1");
    assert_ne!(result.exit_code, 0, "max_connections = 0 must be rejected");
}
