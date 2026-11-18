//! The PyCL module cache (`[execution] python_module_cache`) must be
//! invisible: every shipped censor script gives byte-identical output with
//! the cache on and off, and scripts whose module body is not pure fall back
//! to running it per connection.

// Test packet builders mirror wire formats: many header-field arguments and
// byte-by-byte pushes are clearer than the alternatives here.
#![allow(clippy::too_many_arguments, clippy::vec_init_then_push)]

// Not every builder is used by every test crate.
#[allow(dead_code)]
mod common;

use common::packet_builder::{
    dns_query, high_entropy_payload, http_get, quic_initial_packet, ssh_banner, tcp_frame,
    tls_client_hello_record, udp_frame, TCP_ACK, TCP_FIN, TCP_PSH_ACK, TCP_SYN,
};
use common::pcap_builder::PcapBuilder;
use common::runner::run_pcap_with_config;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const CLIENT: [u8; 4] = [10, 0, 0, 1];

const CACHED: &str = "module environment cached";
const FALLBACK: &str = "module body runs for every connection";

/// A TCP connection: handshake, the client's payloads alternating with
/// server replies of `reply_len` bytes, then FINs
fn tcp_flow(
    frames: &mut Vec<Vec<u8>>,
    server: [u8; 4],
    sport: u16,
    dport: u16,
    payloads: &[Vec<u8>],
    reply_len: usize,
) {
    let (mut c, mut s) = (1000u32, 5000u32);
    frames.push(tcp_frame(CLIENT, server, sport, dport, TCP_SYN, c, 0, &[]));
    frames.push(tcp_frame(server, CLIENT, dport, sport, TCP_SYN | TCP_ACK, s, c + 1, &[]));
    c += 1;
    s += 1;
    frames.push(tcp_frame(CLIENT, server, sport, dport, TCP_ACK, c, s, &[]));
    for payload in payloads {
        frames.push(tcp_frame(CLIENT, server, sport, dport, TCP_PSH_ACK, c, s, payload));
        c += payload.len() as u32;
        let reply = vec![0x17; reply_len];
        frames.push(tcp_frame(server, CLIENT, dport, sport, TCP_PSH_ACK, s, c, &reply));
        s += reply_len as u32;
    }
    frames.push(tcp_frame(CLIENT, server, sport, dport, TCP_FIN | TCP_ACK, c, s, &[]));
    frames.push(tcp_frame(server, CLIENT, dport, sport, TCP_FIN | TCP_ACK, s, c + 1, &[]));
}

/// Traffic that exercises every shipped script: blocked and allowed HTTP,
/// DNS, TLS, QUIC and SSH, fully encrypted flows and long flows (ML window
/// scripts), each kind on two connections so per-connection state is tested
fn traffic() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for round in 0..2u16 {
        let port = |n: u16| 40000 + round * 100 + n;
        tcp_flow(&mut frames, [93, 184, 216, 34], port(1), 80,
            &[http_get("example.com", "/falun"), http_get("example.com", "/ok")], 300);
        tcp_flow(&mut frames, [93, 184, 216, 35], port(2), 80,
            &[http_get("example.org", "/index.html")], 1200);
        tcp_flow(&mut frames, [142, 250, 0, 1], port(3), 443,
            &[tls_client_hello_record("www.google.com")], 1400);
        tcp_flow(&mut frames, [151, 101, 0, 1], port(4), 443,
            &[tls_client_hello_record("example.net")], 1400);
        tcp_flow(&mut frames, [104, 18, 27, 120], port(5), 443,
            &[tls_client_hello_record("twitter.com")], 900);
        for (n, sni) in ["www.example.com", "blocked.example.com", "torproject.org"].iter().enumerate() {
            tcp_flow(&mut frames, [192, 0, 2, 10 + n as u8], port(10 + n as u16), 443,
                &[tls_client_hello_record(sni), high_entropy_payload(400)], 1400);
        }
        tcp_flow(&mut frames, [203, 0, 113, 7], port(6), 8388,
            &[high_entropy_payload(300), high_entropy_payload(700)], 500);
        tcp_flow(&mut frames, [203, 0, 113, 8], port(7), 22, &[ssh_banner()], 40);
        // Long flows of varying sizes, for windowed and ML scripts
        let long: Vec<Vec<u8>> = (0..14).map(|i| high_entropy_payload(50 + 97 * i)).collect();
        tcp_flow(&mut frames, [198, 51, 100, 9], port(8), 443, &long, 1300);
        let long: Vec<Vec<u8>> = (0..12).map(|i| vec![b'a' + i as u8; 20 + 40 * i]).collect();
        tcp_flow(&mut frames, [198, 51, 100, 10], port(9), 8080, &long, 64);
        for (n, domain) in ["google.com", "example.com", "www.facebook.com"].iter().enumerate() {
            let sport = port(20 + n as u16);
            frames.push(udp_frame(CLIENT, [8, 8, 8, 8], sport, 53, &dns_query(domain)));
            frames.push(udp_frame([8, 8, 8, 8], CLIENT, 53, sport, &dns_query(domain)));
        }
        for (n, sni) in ["www.youtube.com", "example.com"].iter().enumerate() {
            let sport = port(30 + n as u16);
            frames.push(udp_frame(CLIENT, [142, 250, 0, 2], sport, 443, &quic_initial_packet(sni)));
            frames.push(udp_frame([142, 250, 0, 2], CLIENT, 443, sport, &high_entropy_payload(1200)));
        }
    }
    frames
}

/// `config` with its relative paths made absolute and `python_module_cache`
/// set, written to `out`
fn write_config(config: &Path, cache: bool, out: &Path) {
    let dir = config.parent().unwrap();
    let mut text = String::new();
    for line in std::fs::read_to_string(config).unwrap().lines() {
        let trimmed = line.trim_start();
        let path_value = ["script", "path"].iter().find_map(|key| {
            trimmed
                .strip_prefix(key)
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix('='))
                .map(str::trim)
                .and_then(|value| value.strip_prefix('"')?.strip_suffix('"'))
                .map(|value| (key, value))
        });
        match path_value {
            Some((key, value)) => {
                text.push_str(&format!("{key} = {:?}\n", dir.join(value).display().to_string()));
            }
            None => {
                text.push_str(line);
                text.push('\n');
            }
        }
        if trimmed == "[execution]" {
            text.push_str(&format!("python_module_cache = {cache}\n"));
        }
    }
    std::fs::write(out, text).unwrap();
}

/// stdout without log timestamps, the timing line, the cache log line and
/// delay deadlines (wall-clock instants)
fn normalized(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| !line.starts_with("Pcap mode took"))
        .filter(|line| !line.contains(CACHED) && !line.contains(FALLBACK))
        .map(|line| match line.find("Z\u{1b}[0m") {
            // "<dim>2026-..Z<reset> rest"
            Some(end) if line.starts_with('\u{1b}') => &line[end + 1..],
            _ => line,
        })
        .map(|line| match line.find("Delay(Instant {") {
            Some(start) => format!("{}Delay(..)", &line[..start]),
            None => line.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every shipped PyCL config (demos and experiments)
fn shipped_configs() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut configs = Vec::new();
    for pattern_dir in ["demos", "experiments"] {
        for entry in std::fs::read_dir(root.join(pattern_dir)).unwrap() {
            let dir = entry.unwrap().path();
            configs.push(dir.join("censor.toml"));
        }
    }
    let benchmarks = root.join("experiments/07_benchmarks/censors");
    for entry in std::fs::read_dir(&benchmarks).unwrap() {
        configs.push(entry.unwrap().path());
    }
    configs.retain(|config| {
        config.extension().is_some_and(|ext| ext == "toml")
            && std::fs::read_to_string(config).is_ok_and(|text| {
                text.lines().any(|line| line.trim_start().starts_with("script"))
                    && !text.lines().any(|line| {
                        line.replace(' ', "") == "mode=\"CensorLang\""
                    })
            })
    });
    configs.sort();
    configs
}

#[test]
fn shipped_scripts_behave_identically_with_and_without_the_cache() {
    let tmp = TempDir::new().unwrap();
    let pcap = tmp.path().join("traffic.pcap");
    let mut builder = PcapBuilder::new();
    for frame in traffic() {
        builder = builder.add_frame(&frame);
    }
    builder.write_to(&pcap);

    let configs = shipped_configs();
    assert!(configs.len() >= 20, "found only {configs:?}");
    let mut cached = Vec::new();
    let mut silent = Vec::new();
    for config in &configs {
        let mut outputs = Vec::new();
        for cache in [true, false] {
            let path = tmp.path().join(format!("censor_{cache}.toml"));
            write_config(config, cache, &path);
            let result = run_pcap_with_config(&path, &pcap, "10.0.0.1");
            assert_eq!(result.exit_code, 0, "{}: {}", config.display(), result.stderr);
            if cache && result.stdout.contains(CACHED) {
                cached.push(config.clone());
            }
            if cache && result.action_lines.is_empty() {
                silent.push(config.clone());
            }
            outputs.push(result.stdout);
        }
        assert_eq!(
            normalized(&outputs[0]),
            normalized(&outputs[1]),
            "{}: output differs with the module cache",
            config.display()
        );
    }
    // The traffic must make most scripts decide something
    assert!(silent.len() * 3 < configs.len(), "no decisions from {silent:?}");
    // The cache must actually be in use for (nearly) all of them; only the
    // QUIC demo, which builds a reassembler at module level, falls back
    let fallback: Vec<_> = configs.iter().filter(|c| !cached.contains(c)).collect();
    assert_eq!(
        fallback,
        vec![&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("demos/quic_blocking/censor.toml")],
    );
}

/// A module body that reads the first packet (or has side effects) is not
/// cacheable: it still runs per connection, with the same result as before
#[test]
fn impure_module_bodies_fall_back() {
    let tmp = TempDir::new().unwrap();
    let pcap = tmp.path().join("traffic.pcap");
    let mut builder = PcapBuilder::new();
    for frame in traffic() {
        builder = builder.add_frame(&frame);
    }
    builder.write_to(&pcap);
    for (script, reason) in [
        (
            // Rebinds the per-packet global, which a helper then reads
            "packet = None\n\
             def first_byte():\n    return packet.payload[:1] if packet is not None else b''\n\
             def process(p):\n    if first_byte() == b'G':\n        return 'drop'\n",
            "module level uses `packet`",
        ),
        (
            "from rust import log_info\nlog_info('module body ran')\n\
             def process(packet):\n    pass\n",
            "module level calls `log_info`",
        ),
        (
            "print('module body ran')\ndef process(packet):\n    return 'drop'\n",
            "module level calls `print`",
        ),
    ] {
        std::fs::write(tmp.path().join("censor.py"), script).unwrap();
        let mut outputs = Vec::new();
        for cache in [true, false] {
            let config = tmp.path().join(format!("censor_{cache}.toml"));
            std::fs::write(
                &config,
                format!(
                    "[execution]\nmode = \"Python\"\nscript = \"censor.py\"\n\
                     python_module_cache = {cache}\n"
                ),
            )
            .unwrap();
            let result = run_pcap_with_config(&config, &pcap, "10.0.0.1");
            assert_eq!(result.exit_code, 0, "{}", result.stderr);
            if cache {
                assert!(
                    result.stdout.contains(FALLBACK) && result.stdout.contains(reason),
                    "expected a fallback because {reason:?}:\n{}",
                    result.stdout
                );
            }
            outputs.push(result.stdout);
        }
        assert_eq!(normalized(&outputs[0]), normalized(&outputs[1]), "{script}");
        assert!(!outputs[1].is_empty());
    }
}
