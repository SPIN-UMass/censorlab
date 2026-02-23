use crate::program::env::ProgramCensor;
use crate::program::packet::Packet;
use pcap_parser::pcapng::Block as PcapNGBlock;
use pcap_parser::{PcapBlockOwned, PcapError};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum PcapLoadError {
    #[error("Failed to open PCAP file: {0}")]
    FileOpen(#[from] std::io::Error),
    #[error("Invalid PCAP format: {0}")]
    InvalidFormat(String),
}

pub struct Pcap {
    pub packets: Vec<Packet>,
    num_connections: usize,
}

impl Pcap {
    /// Loads a PCAP
    pub fn load(path: PathBuf, num_connections: Option<usize>) -> Result<Self, PcapLoadError> {
        // Log the call
        if let Some(num_connections) = num_connections {
            debug!("Loading up to {num_connections} connections worth of pcaps from {path:?}");
        } else {
            debug!("Loading all packets from {path:?}");
        }
        // Load the pcap
        let pcap = load_pcap(&path, num_connections, false)?;
        debug!(
            "Loaded {} connections ({} packets) from {path:?}",
            pcap.num_connections,
            pcap.packets.len()
        );
        // Return it!
        Ok(pcap)
    }
}
pub fn load_pcap<P: AsRef<Path>>(
    path: P,
    num_connections: Option<usize>,
    only_first_data_packet: bool,
) -> Result<Pcap, PcapLoadError> {
    let file = File::open(&path).map(BufReader::new)?;
    // Create a pcap reader
    let mut reader = pcap_parser::create_reader(u16::MAX.into(), file)
        .map_err(|e| PcapLoadError::InvalidFormat(format!("{:?}", e)))?;
    // This buffer will store packets
    let mut packets = num_connections
        .map(Vec::with_capacity)
        .unwrap_or_else(Vec::new);
    // Instantiate an empty program environment that will be used for aggregating connections
    // For pcap loading, this is used to make sure we only load a certain number of connections
    let mut env = ProgramCensor::new(&Default::default(), &Default::default());
    // Metadata about how timestamps are stored in a pcapng file
    let mut if_ts = None;
    // Read packets from the reader
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                // Handle the block
                use PcapBlockOwned::*;
                use PcapNGBlock::*;
                // PCAP-NG block padding: reader.consume(offset) handles block alignment;
                // any trailing padding in block.data is harmless since IP total_len
                // constrains packet parsing boundaries.
                let (timestamp, block_data) = match block {
                    Legacy(block) => (
                        Some(f64::from(block.ts_sec) + f64::from(block.ts_usec) / 1_000_000.0),
                        Some(block.data),
                    ),
                    LegacyHeader(_) => (None, None),
                    NG(SimplePacket(block)) => (None, Some(block.data)),
                    NG(EnhancedPacket(block)) => {
                        let ts = if let Some((resol, offset)) = if_ts {
                            Some(block.decode_ts_f64(resol, offset))
                        } else {
                            None
                        };
                        (ts, Some(block.data))
                    }
                    NG(InterfaceDescription(if_description)) => {
                        if_ts = if_description
                            .ts_resolution()
                            .map(|if_tsresol| (if_tsresol, if_description.ts_offset()));
                        (None, None)
                    }
                    NG(_) => (None, None),
                };
                // Parse the data as a packet
                if let Some(block_data) = block_data {
                    let packet = match Packet::from_ts_bytes(timestamp, block_data, 0.into()) {
                        Ok(packet) => packet,
                        Err(err) => {
                            debug!("Skipping packet (len={}): {:?}", block_data.len(), err);
                            reader.consume(offset);
                            continue;
                        }
                    };
                    // If we're being told to only grab the first data block, do some extra
                    // stuff
                    let mut had_first_data_block = None;
                    if only_first_data_packet {
                        had_first_data_block =
                            Some(env.connection_has_received_first_data_packet(&packet));
                    }
                    // Process the packet
                    env.process(&packet);
                    // Store the packet
                    if !only_first_data_packet {
                        packets.push(packet);
                    }
                    // If we're being told to only grab the first data block, do some extra
                    // stuff
                    else if let Some(had_first_data_block) = had_first_data_block {
                        if !had_first_data_block
                            && env.connection_has_received_first_data_packet(&packet)
                        {
                            packets.push(packet);
                        }
                    }
                    // Check if it's time to stop
                    if let Some(num_connections) = num_connections {
                        if env.num_finished_tcp >= num_connections {
                            debug!("Sufficient connections have been collected");
                            break;
                        }
                    }
                }
                // Consume the data from the pcap
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_needed)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(e) => return Err(PcapLoadError::InvalidFormat(format!("{:?}", e))),
        }
    }
    // Strip out all packets not related to a finished connection
    packets.retain(|packet| env.connection_is_finished(packet));
    // At the end of this we have our packets
    Ok(Pcap {
        packets,
        num_connections: env.num_finished_tcp,
    })
}
