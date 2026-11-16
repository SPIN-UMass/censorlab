use super::{Action, Censor, ClientAddrs};

use clap::Parser;
use ort::Error as OrtError;
use pcap_parser::pcapng::Block;
use pcap_parser::{PcapBlockOwned, PcapError};
use smoltcp::wire::IpAddress;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the pcap to analyze
    pub pcap_path: PathBuf,
    /// Ip address(es) considered the "client" (comma-separated, e.g.
    /// `10.0.0.1,2001:db8::1` to give both an IPv4 and an IPv6 client address)
    ///
    /// Without 2 interfaces, we don't know how to determine the direction of traffic
    /// We need to arbitrarily choose a "client ip" that is used to calculate direction
    /// Anything coming to this IP is wan->cient. Anything from this IP is client->wan
    #[clap(value_delimiter = ',', required = true)]
    pub client_ip: Vec<IpAddr>,
}
/// Context for the pcap censor
pub struct Context {
    pub client: ClientAddrs,
}

impl Censor {
    pub fn run_pcap(mut self, args: Args) -> Result<(), PcapModeError> {
        // Total timer includes file I/O (for cross-tool comparisons)
        let start_total = Instant::now();
        // Open the pcap
        let pcap_file = File::open(args.pcap_path)?;
        let mut pcap_reader = pcap_parser::create_reader(usize::from(u16::MAX), pcap_file)
            .map_err(|err| err.to_string())
            .map_err(PcapModeError::Pcap)?;
        // Processing timer excludes file I/O (for CensorLab-only benchmarks)
        let start_processing = Instant::now();
        // Create our context. This will basically never change
        let mut context = Context {
            client: ClientAddrs::new(args.client_ip.iter().map(|ip| IpAddress::from(*ip))),
        };
        // Connection-tracking timeouts follow capture time, not wall-clock time
        self.transport_state.use_packet_clock();
        // Legacy pcap: whether record timestamps are in ns rather than us
        let mut legacy_nanos = false;
        // PCAP-NG: (resolution in units/sec, offset in seconds) per interface id
        let mut interfaces: Vec<(u64, i64)> = Vec::new();
        let mut packet_index = 0;
        loop {
            // IPC is intentionally not supported in PCAP mode: PCAP processes
            // static capture files, so live model updates and shutdown signals
            // don't apply.
            let (size, block) = match pcap_reader.next() {
                Ok(d) => d,
                Err(PcapError::Incomplete(_)) => {
                    pcap_reader
                        .refill()
                        .map_err(|err| err.to_string())
                        .map_err(PcapModeError::Pcap)?;
                    continue;
                }
                Err(PcapError::Eof) => break,
                Err(err) => {
                    return Err(PcapModeError::Pcap(err.to_string()));
                }
            };
            packet_index += 1;
            let (timestamp, data) = match block {
                PcapBlockOwned::Legacy(block) => (
                    Some(legacy_ts_micros(block.ts_sec, block.ts_usec, legacy_nanos)),
                    block.data,
                ),
                PcapBlockOwned::LegacyHeader(header) => {
                    legacy_nanos = header.is_nanosecond_precision();
                    pcap_reader.consume(size);
                    continue;
                }
                PcapBlockOwned::NG(block) => match block {
                    Block::EnhancedPacket(pkt) => {
                        // Packets on an undescribed interface carry no usable time
                        let ts = usize::try_from(pkt.if_id)
                            .ok()
                            .and_then(|id| interfaces.get(id))
                            .map(|&(resolution, offset)| {
                                ng_ts_micros(pkt.ts_high, pkt.ts_low, resolution, offset)
                            });
                        (ts, pkt.data)
                    }
                    // Simple packet blocks have no timestamp
                    Block::SimplePacket(pkt) => (None, pkt.data),
                    Block::SectionHeader(_) => {
                        // Interface ids are scoped to a section
                        interfaces.clear();
                        pcap_reader.consume(size);
                        continue;
                    }
                    Block::InterfaceDescription(idb) => {
                        // An invalid resolution falls back to the default (microseconds)
                        let resolution = idb.ts_resolution().unwrap_or(1_000_000);
                        interfaces.push((resolution, idb.ts_offset()));
                        pcap_reader.consume(size);
                        continue;
                    }
                    _ => {
                        pcap_reader.consume(size);
                        continue;
                    }
                },
            };
            let data = data.to_vec();
            if let Some(timestamp) = timestamp {
                self.transport_state.set_packet_time(timestamp);
            }
            let mut context = (&mut context).into();
            let action = self.process_frame(&data, &mut context);
            match action {
                Ok(Action::None) => {}
                Ok(Action::Ignore) => {}
                action => println!("{}: {:?}", packet_index, action),
            }
            pcap_reader.consume(size);
        }
        println!(
            "Pcap mode took {}us to process the file ({}us including I/O)",
            start_processing.elapsed().as_micros(),
            start_total.elapsed().as_micros()
        );
        Ok(())
    }
}
/// Legacy pcap record timestamp in microseconds
fn legacy_ts_micros(ts_sec: u32, ts_frac: u32, nanos: bool) -> u64 {
    let frac_micros = if nanos { ts_frac / 1000 } else { ts_frac };
    u64::from(ts_sec) * 1_000_000 + u64::from(frac_micros)
}

/// PCAP-NG enhanced packet timestamp in microseconds, given the interface's
/// resolution (units per second, non-zero) and offset (seconds). Saturates to
/// the range of `u64`.
fn ng_ts_micros(ts_high: u32, ts_low: u32, resolution: u64, offset: i64) -> u64 {
    let ts = (u128::from(ts_high) << 32) | u128::from(ts_low);
    let resolution = u128::from(resolution.max(1));
    let secs = i128::try_from(ts / resolution).unwrap_or(i128::MAX).saturating_add(offset.into());
    let frac_micros = (ts % resolution) * 1_000_000 / resolution;
    let micros = secs
        .saturating_mul(1_000_000)
        .saturating_add(frac_micros as i128);
    u64::try_from(micros.max(0)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_timestamps() {
        assert_eq!(legacy_ts_micros(2, 500, false), 2_000_500);
        assert_eq!(legacy_ts_micros(2, 500_000, true), 2_000_500);
    }

    #[test]
    fn ng_timestamps() {
        // Default resolution: microseconds
        assert_eq!(ng_ts_micros(0, 3_000_001, 1_000_000, 0), 3_000_001);
        // Nanoseconds, with a 64-bit timestamp
        let ns: u64 = 5_000_000_000_123_456;
        assert_eq!(
            ng_ts_micros((ns >> 32) as u32, ns as u32, 1_000_000_000, 0),
            5_000_000_000_123
        );
        // Offset in seconds, positive and negative
        assert_eq!(ng_ts_micros(0, 1_000_000, 1_000_000, 10), 11_000_000);
        assert_eq!(ng_ts_micros(0, 1_000_000, 1_000_000, -10), 0);
    }
}

/// Error running in wire mode
#[derive(Debug, Error)]
pub enum PcapModeError {
    #[error("Error opening pcap")]
    Open(#[from] io::Error),
    #[error("Error reading pcap block")]
    Pcap(String),
    #[error("Error updating model")]
    Ort(#[from] OrtError),
}

#[cfg(test)]
mod args_tests {
    use super::*;

    #[test]
    fn client_ip_accepts_v4_and_v6() {
        let args = Args::try_parse_from(["pcap", "x.pcap", "10.0.0.1,2001:db8::1"]).unwrap();
        assert_eq!(
            args.client_ip,
            vec!["10.0.0.1".parse::<IpAddr>().unwrap(), "2001:db8::1".parse().unwrap()]
        );
        // A single address keeps working
        let args = Args::try_parse_from(["pcap", "x.pcap", "10.0.0.1"]).unwrap();
        assert_eq!(args.client_ip.len(), 1);
        // ... and one is required
        assert!(Args::try_parse_from(["pcap", "x.pcap"]).is_err());
    }
}
