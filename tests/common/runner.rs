use std::path::Path;
use std::process::Command;

/// A parsed action line from censorlab PCAP-mode output.
#[derive(Debug)]
pub struct ActionLine {
    pub packet_index: usize,
    pub action: String,
}

/// Result of running censorlab in PCAP mode.
#[derive(Debug)]
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub action_lines: Vec<ActionLine>,
}

/// Run the `censorlab` binary in PCAP mode.
///
/// # Arguments
/// * `config_path` – path to `censor.toml`
/// * `pcap_path`   – path to the `.pcap` file
/// * `client_ip`   – the IP address considered the "client"
pub fn run_pcap_with_config(config_path: &Path, pcap_path: &Path, client_ip: &str) -> RunResult {
    let bin = env!("CARGO_BIN_EXE_censorlab");

    let output = Command::new(bin)
        .arg("-c")
        .arg(config_path)
        .arg("pcap")
        .arg(pcap_path)
        .arg(client_ip)
        .output()
        .expect("failed to execute censorlab binary");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let action_lines = parse_action_lines(&stdout);

    RunResult {
        exit_code,
        stdout,
        stderr,
        action_lines,
    }
}

/// Parse action lines from stdout.
///
/// censorlab PCAP mode prints lines like:
///   `1: Ok(Drop)`
///   `2: Ok(Reset { ... })`
///   `Pcap mode took 123us to process the file`
///
/// We extract lines matching `"{index}: {action}"`.
fn parse_action_lines(stdout: &str) -> Vec<ActionLine> {
    let mut lines = Vec::new();
    for line in stdout.lines() {
        // Skip the timing line
        if line.starts_with("Pcap mode took") {
            continue;
        }
        // Try to parse "{index}: {rest}"
        if let Some((idx_str, rest)) = line.split_once(": ") {
            if let Ok(packet_index) = idx_str.trim().parse::<usize>() {
                lines.push(ActionLine {
                    packet_index,
                    action: rest.to_string(),
                });
            }
        }
    }
    lines
}
