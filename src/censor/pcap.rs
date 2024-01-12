use super::{Action, Censor};

use clap::Parser;
use onnxruntime::OrtError;
use pcap_parser::pcapng::Block;
use pcap_parser::{PcapBlockOwned, PcapError};
use smoltcp::wire::IpAddress;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the pcap to analyze
    pub pcap_path: PathBuf,
    /// Ip address considered the "client"
    ///
    /// Without 2 interfaces, we don't know how to determine the direction of traffic
    /// We need to arbitrarily choose a "client ip" that is used to calculate direction
    /// Anything coming to this IP is wan->cient. Anything from this IP is client->wan
    pub client_ip: IpAddr,
}
/// Context for the pcap censor
pub struct Context {
    pub client_ip: IpAddress,
}

impl Censor {
    pub fn run_pcap(mut self, args: Args) -> Result<(), PcapModeError> {
        // Start the timer
        let start = SystemTime::now();
        // Open the pcap
        let pcap_file = File::open(args.pcap_path)?;
        let mut pcap_reader = pcap_parser::create_reader(usize::from(u16::MAX), pcap_file)
            .map_err(|err| err.to_string())
            .map_err(PcapModeError::Pcap)?;
        // Create our context. This will basically never change
        let mut context = Context {
            client_ip: args.client_ip.into(),
        };
        let mut packet_index = 0;
        loop {
            // TODO: handle ipcs in pcap mode
            // Need some kind of trigger to wait for it
            let (size, block) = match pcap_reader.next() {
                Ok(d) => d,
                Err(PcapError::Incomplete) => {
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
            let data = match block {
                PcapBlockOwned::Legacy(block) => block.data,
                PcapBlockOwned::LegacyHeader(_) => {
                    pcap_reader.consume(size);
                    continue;
                }
                PcapBlockOwned::NG(block) => match block {
                    Block::EnhancedPacket(pkt) => pkt.data,
                    Block::SimplePacket(pkt) => pkt.data,
                    _ => {
                        pcap_reader.consume(size);
                        continue;
                    }
                },
            }
            .to_vec();
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
            "Pcap mode took {}us to process the file",
            start.elapsed().unwrap().as_micros()
        );
        Ok(())
    }
}
/// Error running in wire mode
#[derive(Debug, Error)]
pub enum PcapModeError {
    #[error("Error opening pcap")]
    Open(#[from] io::Error),
    #[error("Error reading pcap block")]
    Pcap(String),
    //#[error("Error handling IPC")]
    //Ipc(#[from] crate::censor::HandleIpcError),
    #[error("Error updating model")]
    Ort(#[from] OrtError),
    #[error("todo add error when tis is implemented")]
    Todo,
}
