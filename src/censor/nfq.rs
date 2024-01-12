use super::{Action, Censor};
use crate::arp::ArpCache;
use crate::censor::{HandleIpcError, IpPair};
use crate::watermark::Delayer;
use clap::Parser;
use get_if_addrs::IfAddr;
use mac_address::MacAddressError;
use nfq::{Queue, Verdict};
use onnxruntime::OrtError;
use procfs::ProcError;
use smoltcp::phy::{Device, Medium, RawSocket, TxToken};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::time::Instant;
use smoltcp::wire::{Error as SmoltcpError, EthernetAddress, IpAddress, TcpSeqNumber};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{debug, error, info, trace};

//const DEFAULT_TABLE: &str = "filter";
//const IN_CHAIN: &str = "INPUT";
//const OUT_CHAIN: &str = "OUTPUT";

#[derive(Debug, Parser)]
pub struct Args {
    /// Ip address considered the "client"
    ///
    /// Without 2 interfaces, we don't know how to determine the direction of traffic
    /// We need to arbitrarily choose a "client ip" that is used to calculate direction
    /// Anything coming to this IP is wan->cient. Anything from this IP is client->wan
    pub client_ip: IpAddr,
    /// what to do with traffic that doesn't have a direction
    /// by default we have to ignore it because the model relies on direction info
    #[clap(long, default_value = "ignore")]
    pub no_dir_action: Action,
    /// Which queue number to use
    #[clap(short, long, default_value_t = 0)]
    pub queue_num: u16,
    /// Interface to send packets to (defaults to first interface that can send AF_INET packets
    pub interface: Option<String>,
    /// Number of times to send a reset
    /// TODO: move this to the config file
    #[clap(long, default_value_t = 5)]
    pub reset_repeat: usize,
}
/// Context for the pcap censor
pub struct Context {
    pub client_ip: IpAddress,
    pub no_dir_action: Action,
    /// Module for delaying packets
    pub delayer: Delayer,
}

impl Censor {
    pub async fn run_nfq(mut self, mut args: Args) -> Result<(), NfqModeError> {
        // Initialize an arp cache. This is used for resolving IPs to arp
        let mut arp_cache = ArpCache::default();
        // Get the interface if it doesn't exist
        let interface_name = match args.interface.take() {
            Some(interface) => interface,
            None => {
                let mut found_interface = None;
                for system_if in get_if_addrs::get_if_addrs().map_err(NfqModeError::Interface)? {
                    // Store any useful cache info
                    if let IfAddr::V4(ref ipv4) = system_if.addr {
                        if let Some(mac) = mac_address::mac_address_by_name(&system_if.name)? {
                            arp_cache.insert(ipv4.ip.into(), EthernetAddress(mac.bytes()));
                        }
                    }
                    // This simply uses the first non-loopback interface. Theoretically it would be
                    // good to filter this on client ip, however, censorlab might be operating as a
                    // tap on an interface for which it doesn't even have an IP address!
                    if !system_if.is_loopback() {
                        found_interface = Some(system_if.name);
                    }
                }
                let interface = found_interface.ok_or(NfqModeError::NoInterfaceFound)?;
                debug!("Interface not specified: using {interface}");
                interface
            }
        };
        // Get the mac of our interface
        let _client_mac = mac_address::mac_address_by_name(&interface_name)?
            .ok_or(NfqModeError::InterfaceHasNoMac)?
            .bytes();
        // We need a default route
        let mut default_route_ip = None;
        // Load up the list of routes
        for route in procfs::net::route().map_err(NfqModeError::OpenRoutes)? {
            if route.destination == Ipv4Addr::new(0, 0, 0, 0) && route.iface == interface_name {
                default_route_ip = Some(route.gateway);
                break;
            }
        }
        let default_route_ip = default_route_ip.ok_or(NfqModeError::DefaultRouteNotFound)?;
        // Scan the arp table for the mac for our default route ip
        let mut default_route_mac = None;
        for arp_entry in procfs::net::arp().map_err(NfqModeError::OpenArp)? {
            if arp_entry.ip_address == default_route_ip && arp_entry.device == interface_name {
                default_route_mac = arp_entry.hw_address;
            }
        }
        // Open the interface as an IP raw socket
        trace!("Opening raw socket for {}", interface_name);
        let mut interface =
            RawSocket::new(&interface_name, Medium::Ip).map_err(NfqModeError::RawSocketOpen)?;
        info!("Opened raw socket for {}", interface_name);
        // TODO: Initialize a firewall rule to forward packets to nfqueue
        // TODO: false means no ipv6
        //let iptables = iptables::new(false).map_err(NfqModeError::IpTables)?;
        //TODO: configurable parameters
        // Create our context. This will basically never change
        let mut context = Context {
            client_ip: args.client_ip.into(),
            no_dir_action: args.no_dir_action,
            delayer: Delayer::new(interface_name),
        };
        {
            let mut context = (&mut context).into();
            trace!("Opening netfilter queue");
            let mut queue = Queue::open().map_err(NfqModeError::NfqOpen)?;
            queue.set_nonblocking(true);
            queue.bind(args.queue_num).map_err(NfqModeError::NfqBind)?;
            info!("Opened netfilter queue");
            info!("Starting packet loop");
            let mut packet_num = 0;
            loop {
                // Handle any incoming ipc requests
                match self.handle_ipc() {
                    Ok(()) => {}
                    Err(HandleIpcError::Shutdown) => break,
                    Err(err) => return Err(err.into()),
                }
                // Handle packets on the queue
                match queue.recv() {
                    Ok(mut msg) => {
                        let action = self.process_frame_payload(
                            msg.get_hw_protocol().into(),
                            msg.get_payload(),
                            &mut context,
                        );
                        let action = match action {
                            Ok(action) => action,
                            Err(err) => {
                                error!("Error processing packet: {:?}", err);
                                Action::None
                            }
                        };
                        if !matches!(action, Action::None | Action::Ignore) {
                            info!("Censorship event on packet {packet_num}: {action:?}");
                        }
                        packet_num += 1;
                        match action {
                            Action::None | Action::Ignore => {
                                trace!("Forwarding packet normally");
                                msg.set_verdict(Verdict::Accept);
                                queue.verdict(msg).map_err(NfqModeError::Nfq)?;
                            }
                            Action::Drop => {
                                trace!("Dropping packet");
                                msg.set_verdict(Verdict::Drop);
                                queue.verdict(msg).map_err(NfqModeError::Nfq)?;
                            }
                            Action::Reset {
                                src_mac: _,
                                dst_mac: _,
                                ips,
                                ipid,
                                src_port,
                                dst_port,
                                seq,
                                ack,
                                payload_len,
                            } => {
                                // Time for misery
                                let mut src_mac = [0; 6];
                                let mut dst_mac = [0; 6];
                                if let IpPair::V4 { src, dst } = ips {
                                    // Resolve src mac addr
                                    if let Some(mac) =
                                        arp_cache.resolve(src).map_err(NfqModeError::OpenArp)?
                                    {
                                        src_mac = mac.0;
                                    } else if IpAddress::from(src)
                                        != IpAddress::from(args.client_ip)
                                    {
                                        if let Some(mac) = default_route_mac {
                                            src_mac = mac;
                                        }
                                    }
                                    // Resolve dst mac addr
                                    if let Some(mac) =
                                        arp_cache.resolve(dst).map_err(NfqModeError::OpenArp)?
                                    {
                                        dst_mac = mac.0;
                                    } else if IpAddress::from(dst)
                                        != IpAddress::from(args.client_ip)
                                    {
                                        if let Some(mac) = default_route_mac {
                                            dst_mac = mac;
                                        }
                                    }
                                }
                                trace!("Sending bidirectional reset for {:?}<->{:?}, ips={:?}, ports={},{}, seq={},ack={}", src_mac, dst_mac, ips, src_port, dst_port, seq, ack);
                                // Send resets, then accept the packet
                                let (client_reset, server_reset) = self.craft_resets(
                                    src_mac,
                                    dst_mac,
                                    ips,
                                    ipid,
                                    src_port,
                                    dst_port,
                                    seq,
                                    ack,
                                    payload_len,
                                )?;
                                // Send the resets
                                for _ in 0..args.reset_repeat {
                                    if let Some(tx_token) =
                                        interface.transmit(SmoltcpInstant::from_micros_const(0))
                                    {
                                        tx_token.consume(client_reset.len(), |tx_buf| {
                                            tx_buf.copy_from_slice(&client_reset);
                                            Ok::<(), SmoltcpError>(())
                                        })?;
                                    }
                                    if let Some(tx_token) =
                                        interface.transmit(Instant::from_micros_const(0))
                                    {
                                        tx_token.consume(server_reset.len(), |tx_buf| {
                                            tx_buf.copy_from_slice(&server_reset);
                                            Ok::<(), SmoltcpError>(())
                                        })?;
                                    }
                                }
                                // Accept the packet
                                msg.set_verdict(Verdict::Accept);
                                queue.verdict(msg).map_err(NfqModeError::Nfq)?;
                            }
                            Action::Delay(_) => {
                                // Drop the original packet
                                msg.set_verdict(Verdict::Drop);
                                queue.verdict(msg).map_err(NfqModeError::Nfq)?;
                            }
                        };
                    }
                    Err(err) => match err.kind() {
                        io::ErrorKind::WouldBlock => {}
                        _ => return Err(NfqModeError::Nfq(err)),
                    },
                }
            }
            queue.unbind(0).map_err(NfqModeError::Nfq)?;
        }
        // We know the context is our nfq
        context.delayer.delay_thread.abort();
        if let Err(err) = context.delayer.delay_thread.await {
            if !err.is_cancelled() {
                Err(err)?
            }
        }
        Ok(())
    }
    fn craft_resets(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        ips: IpPair,
        ipid: Option<u16>,
        src_port: u16,
        dst_port: u16,
        ack: TcpSeqNumber,
        seq: TcpSeqNumber,
        payload_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), smoltcp::wire::Error> {
        // Construct the client reset
        let client_reset = crate::transport::construct_reset(
            EthernetAddress(dst_mac),
            EthernetAddress(src_mac),
            ips.swap(),
            ipid,
            // src port
            dst_port,
            // dst port
            src_port,
            // ack
            seq + payload_len,
            // seq
            ack,
        )?;
        // Construct the server reset
        let server_reset = crate::transport::construct_reset(
            EthernetAddress(src_mac),
            EthernetAddress(dst_mac),
            ips,
            ipid,
            src_port, // src port
            dst_port, // dst port
            ack,      // ack
            seq,      // seq
        )?;

        Ok((client_reset, server_reset))
    }
}

/// Error running in wire mode
#[derive(Debug, Error)]
pub enum NfqModeError {
    #[error("Error setting up iptables: {0}")]
    IpTables(Box<dyn std::error::Error>),
    #[error("Error listing interfaces: {0}")]
    Interface(io::Error),
    #[error("Failed to find a suitable interface")]
    NoInterfaceFound,
    #[error("Failed to find MAC address of our chosen interface: {0}")]
    MacAddressNotFound(#[from] MacAddressError),
    #[error("Interface has no MAC address")]
    InterfaceHasNoMac,
    #[error("Failed to open routing table: {0}")]
    OpenRoutes(ProcError),
    #[error("Failed to find ip for default route (0.0.0.0)")]
    DefaultRouteNotFound,
    #[error("Failed to open ARP table")]
    OpenArp(ProcError),
    #[error("Failed to find arp entry (containing MAC) for default route")]
    NoArpEntryForDefaultRoute,
    #[error("Failed to open raw IP socket on interface: {0}")]
    RawSocketOpen(io::Error),
    #[error("Error opening nfqueue: {0}")]
    NfqOpen(io::Error),
    #[error("Error binding nfqueue: {0}")]
    NfqBind(io::Error),
    #[error("Error interacting with nfqueue: {0}")]
    Nfq(io::Error),
    #[error("Error handling IPC: {0}")]
    Ipc(#[from] crate::censor::HandleIpcError),
    #[error("Error updating model: {0}")]
    Ort(#[from] OrtError),
    #[error("Error doing processing: {0}")]
    Process(#[from] smoltcp::wire::Error),
    #[error("Error joining watermark thread :{0}")]
    ThreadJoin(#[from] JoinError),
}

// TODO: automatically insert and remove firewall rule for nfq
