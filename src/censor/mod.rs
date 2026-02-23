mod filter;
mod nfq;
mod pcap;
#[cfg(feature = "wire")]
mod wire;

use crate::censor::filter::{AllowBlockList, AllowList, BlockList, RecommendList};
use crate::censor::nfq::NfqModeError;
use crate::censor::pcap::PcapModeError;
#[cfg(feature = "wire")]
use crate::censor::wire::WireError;
use crate::config::ethernet::MACAddress;
use crate::config::Config;
use crate::ipc::{ipc_thread, ModelThreadError};
use crate::model::onnx::ModelLoadError;
use crate::model::ModelThreadMessage;
use crate::program::packet::Packet;
use crate::transport::{TransportState, TransportStateInitError};
use bitvec::prelude::*;
#[cfg(feature = "wire")]
use core::ops::{Index, IndexMut};
use ort::Error as OrtError;
use serde::{de, Deserialize, Deserializer};
#[cfg(feature = "wire")]
use smoltcp::phy::RawSocket;
#[cfg(feature = "wire")]
use smoltcp::phy::Device;
use smoltcp::wire::Error as SmoltcpError;
use smoltcp::wire::{
    ArpPacket, EthernetAddress, EthernetFrame, EthernetProtocol as EtherType, Icmpv4Packet,
    Icmpv6Packet, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpSeqNumber,
};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
#[cfg(feature = "wire")]
use std::slice::SliceIndex;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::Instant;
use thiserror::Error;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinError;
use tracing::{debug, error, info_span, warn};

/// Used for fast access to a list of every port for examples such as udp port filtering
pub type PortVec = BitArr!(for 65536, in u64, Msb0);

/// Arguments to the censor are stored here
pub mod args {
    use clap::Parser;
    /// Censorlab is a framework for simulating censors
    #[derive(Debug, Parser)]
    pub enum SubCmd {
        #[cfg(feature = "wire")]
        /// In this mode, the censor acts as an intermediary between 2 interfaces, typically a WAN
        /// and client.
        /// It is capable of dropping and modifying packets
        Wire {
            #[clap(flatten)]
            args: super::wire::Args,
        },
        /// In this mode, the censor will read packets from a pcap, logging actions it *would* have
        /// taken if it received these packets in tap mode.
        Pcap {
            #[clap(flatten)]
            args: super::pcap::Args,
        },
        /// In this mode, the censor will read packets from the netfilter packet queue
        /// taken if it received these packets in tap mode.
        Nfq {
            #[clap(flatten)]
            args: super::nfq::Args,
        },
    }
}

/// Censor acts as a censoring adversary capable of making decisions based on received packets and
/// its internal state
pub struct Censor {
    // Ethernet
    /// MAC allow/blocklist
    ethernet_list: AllowBlockList<HashSet<EthernetAddress>>,
    /// What to do with ethernet packets with unknown ethertype
    ethernet_unknown: Action,
    // ARP stuff
    /// Config for arp
    arp: crate::config::arp::Config,
    // IP
    /// IPv4 allow/blocklist
    ipv4_list: AllowBlockList<HashSet<Ipv4Address>>,
    /// IPv6 allow/blocklist
    ipv6_list: AllowBlockList<HashSet<Ipv6Address>>,
    /// What to do with ip packets with unknown type
    ip_unknown: Action,
    // ICMP
    /// What to do with ICMP packets
    icmp: crate::config::icmp::Config,
    // TCP
    /// TCP allow/blocklist for ports
    tcp_port_list: AllowBlockList<PortVec>,
    /// TCP allow/blocklist for ip-port pairs
    tcp_ip_port_list: AllowBlockList<HashSet<crate::config::IpPort>>,
    // UDP
    /// UDP allow/blocklist for ports.
    /// Loaded from config but not yet used in process_transport (see TODO.md).
    #[allow(dead_code)]
    udp_port_list: AllowBlockList<PortVec>,
    /// UDP allow/blocklist for ip-port pairs
    udp_ip_port_list: AllowBlockList<HashSet<crate::config::IpPort>>,
    // Reset
    /// Number of times to repeat TCP RST packets
    reset_repeat: usize,
    // IPC
    /// Port to listen for model changes on
    ipc_port: u16,
    /// Control channel
    sender: UnboundedSender<crate::ipc::Message>,
    receiver: UnboundedReceiver<crate::ipc::Message>,
    // State
    /// Manager for per-connection environments
    transport_state: TransportState,
}

#[derive(Debug, Error)]
pub enum CensorInitError {
    #[error("Error initializing tcp state tracker: {0}")]
    TransportStateInit(#[from] TransportStateInitError),
    #[error("Error loading censorship model: {0}")]
    LoadModel(#[from] ModelLoadError),
    #[error("Error sending censorship model to {0} aggregator: {1:?}")]
    SendCensorshipModel(crate::ipc::ModelScope, SendError<crate::ipc::Message>),
}
/// Error running the censor
#[derive(Debug, Error)]
pub enum CensorError {
    #[cfg(feature = "wire")]
    #[error("Error running censor in wire mode: {0}")]
    Wire(#[from] WireError),
    #[error("Error running censor in pcap mode: {0}")]
    Pcap(#[from] PcapModeError),
    #[error("Error running censor in nfq mode: {0}")]
    Nfq(#[from] NfqModeError),
    #[error("Error joining the IPC thread: {0}")]
    IpcJoin(#[from] JoinError),
    #[error("Error in the IPC thread {0}")]
    Ipc(#[from] ModelThreadError),
}
/// Context for the censor
/// This allows the main censor program to pass information related to its operation
/// For example, the wire censor is aware of traffic direction and can give that without having to
/// calculate it, while the tap censor cannot
enum Context<'a> {
    #[cfg(feature = "wire")]
    Wire(&'a wire::Context),
    Pcap(&'a pcap::Context),
    Nfq(&'a nfq::Context),
}

#[cfg(feature = "wire")]
impl<'a> From<&'a mut wire::Context> for Context<'a> {
    fn from(ctx: &'a mut wire::Context) -> Self {
        Context::Wire(ctx)
    }
}
impl<'a> From<&'a mut pcap::Context> for Context<'a> {
    fn from(ctx: &'a mut pcap::Context) -> Self {
        Context::Pcap(ctx)
    }
}
impl<'a> From<&'a mut nfq::Context> for Context<'a> {
    fn from(ctx: &'a mut nfq::Context) -> Self {
        Context::Nfq(ctx)
    }
}

impl Censor {
    /// Initializes common censor state using the common arguments
    ///
    /// # Arguments
    /// * `args` - Common censor arguments
    pub fn new(
        ipc_port: u16,
        config: Config,
        tcp_decision_log_path: Option<PathBuf>,
        model_sender: mpsc::SyncSender<ModelThreadMessage>,
    ) -> Result<Self, CensorInitError> {
        // Destructure config to move each field independently (avoids cloning models)
        let Config {
            execution,
            ethernet,
            arp,
            ip,
            icmp,
            tcp,
            udp,
            models,
        } = config;

        // Convert MAC allow/blocklist into hashsets
        let ethernet_allowlist =
            AllowList::from(ethernet.allowlist.map(MACAddress::into).set());
        let ethernet_blocklist =
            BlockList::from(ethernet.blocklist.map(MACAddress::into).set());
        // Combine into allow-blocklist
        let ethernet_list = AllowBlockList::new(ethernet_allowlist, ethernet_blocklist);

        // Split IP lists out into ipv4 and ipv6
        let ipv4_filter = |ip| {
            if let IpAddr::V4(ipv4) = ip {
                Some(ipv4.into())
            } else {
                None
            }
        };
        let ipv6_filter = |ip| {
            if let IpAddr::V6(ipv6) = ip {
                Some(ipv6.into())
            } else {
                None
            }
        };
        // Perform filtering (ipv4)
        let ipv4_allowlist = AllowList::from(ip.allowlist.filter_map(ipv4_filter).set());
        let ipv4_blocklist = BlockList::from(ip.blocklist.filter_map(ipv4_filter).set());
        // Combine allow and blocklist
        let ipv4_list = AllowBlockList::new(ipv4_allowlist, ipv4_blocklist);
        // Perform filtering (ipv6)
        let ipv6_allowlist = AllowList::from(ip.allowlist.filter_map(ipv6_filter).set());
        let ipv6_blocklist = BlockList::from(ip.blocklist.filter_map(ipv6_filter).set());
        // Combine allow and blocklist
        let ipv6_list = AllowBlockList::new(ipv6_allowlist, ipv6_blocklist);

        // Initialize bitvec for tcp port lists
        let tcp_port_allowlist = AllowList::from(tcp.port_allowlist.bit_vec());
        let tcp_port_blocklist = BlockList::from(tcp.port_blocklist.bit_vec());
        // Combine into 1 thing
        let tcp_port_list = AllowBlockList::new(tcp_port_allowlist, tcp_port_blocklist);
        // Initialize hashmaps for tcp ip-port lists
        let tcp_ip_port_allowlist = AllowList::from(tcp.ip_port_allowlist.set());
        let tcp_ip_port_blocklist = BlockList::from(tcp.ip_port_blocklist.set());
        // Combine into 1 thing
        let tcp_ip_port_list = AllowBlockList::new(tcp_ip_port_allowlist, tcp_ip_port_blocklist);

        // Initialize bitvec for udp port lists
        let udp_port_allowlist = AllowList::from(udp.port_allowlist.bit_vec());
        let udp_port_blocklist = BlockList::from(udp.port_blocklist.bit_vec());
        // Combine into 1 thing
        let udp_port_list = AllowBlockList::new(udp_port_allowlist, udp_port_blocklist);
        // Initialize hashmaps for udp ip-port lists
        let udp_ip_port_allowlist = AllowList::from(udp.ip_port_allowlist.set());
        let udp_ip_port_blocklist = BlockList::from(udp.ip_port_blocklist.set());
        // Combine into 1 thing
        let udp_ip_port_list = AllowBlockList::new(udp_ip_port_allowlist, udp_ip_port_blocklist);

        // Construct a control channel
        let (sender, receiver) = unbounded_channel();
        // Save reset_repeat before moving execution config
        let reset_repeat = execution.reset_repeat;
        // Start up our tcp state
        let transport_state = TransportState::new(
            models,
            tcp_decision_log_path,
            execution,
            model_sender,
        )?;
        // Construct the censor object
        Ok(Censor {
            // Ethernet
            ethernet_list,
            ethernet_unknown: ethernet.unknown,
            // Arp
            arp,
            // IP
            ipv4_list,
            ipv6_list,
            ip_unknown: ip.unknown,
            // ICMP
            icmp,
            // TCP
            tcp_port_list,
            tcp_ip_port_list,
            // UDP
            udp_port_list,
            udp_ip_port_list,
            // Reset
            reset_repeat,
            //IPC
            ipc_port,
            sender,
            receiver,
            // State
            transport_state,
        })
    }
    /// Handle any IPC messages
    pub fn handle_ipc(&mut self) -> Result<(), HandleIpcError> {
        while let Ok(message) = self.receiver.try_recv() {
            match message {
                crate::ipc::Message::UpdateModel {
                    scope: _,
                    onnx_data: _,
                    metadata: _,
                } => {
                    /*info!("Updating model");
                    let session = self
                        .onnx_env
                        .new_session_builder()?
                        .with_optimization_level(GraphOptimizationLevel::Basic)?
                        .with_number_threads(1)?
                        .with_model_from_memory(onnx_data)?;
                    let float_input = session
                        .inputs
                        .iter()
                        .find(|input| input.name == "float_input")
                        .unwrap();
                    assert_eq!(
                        &float_input.dimensions,
                        &[Some(1), Some(metadata.features.len().try_into().unwrap())]
                    );
                    let (prob_index, probability_output) = session
                        .outputs
                        .iter()
                        .enumerate()
                        .find(|(_, output)| output.name == "probabilities")
                        .unwrap();
                    assert_eq!(
                        &probability_output.dimensions,
                        &[Some(1), Some(metadata.labels.len().try_into().unwrap())]
                    );
                    let model = Model {
                        session,
                        metadata,
                        prob_index,
                    };
                    match scope {
                        crate::ipc::ModelScope::Tcp => self.transport_state.update_model(model),
                        _ => {}
                    }*/
                }
                crate::ipc::Message::Shutdown => return Err(HandleIpcError::Shutdown),
            }
        }
        Ok(())
    }
    /// Run the censor
    pub async fn run(self, cmd: args::SubCmd) -> Result<(), CensorError> {
        // Hand the sender to our thread
        let sender = self.sender.clone();
        // First store whether the subcommand is pcap
        let threads = if matches!(&cmd, &args::SubCmd::Pcap { .. }) {
            None
        } else {
            // Start a thread that receives ipc messages
            let ipc_thread = tokio::task::spawn(ipc_thread(self.ipc_port, sender.clone()));
            // Start a second thread that handles interrupts
            let sigint_thread = tokio::task::spawn(signal_handler_thread(sender.clone()));
            Some((ipc_thread, sigint_thread))
        };
        // Run the subcommand
        // Don't immediately throw the error because we want to let the ipc thread die
        let cmd_result = self.run_subcmd(cmd).await;
        if let Some((ipc_thread, sigint_thread)) = threads {
            // If command resulted in an error, kill the ipc thread
            debug!("killing the IPC thread");
            ipc_thread.abort();
            debug!("killing the SIGINT thread");
            sigint_thread.abort();
            debug!("Waiting for the IPC thread to die");
            // Join the IPC thread
            match ipc_thread.await {
                Ok(ipc_thread_result) => ipc_thread_result?,
                Err(err) => {
                    if !err.is_cancelled() {
                        Err(err)?
                    }
                }
            }
            // Join the signal thread
            if let Err(err) = sigint_thread.await {
                if !err.is_cancelled() {
                    Err(err)?
                }
            }
        }
        cmd_result
    }
    /// Run the subcommand, without common threads that need to be initialized
    async fn run_subcmd(self, cmd: args::SubCmd) -> Result<(), CensorError> {
        // Run the subcommand
        match cmd {
            #[cfg(feature = "wire")]
            args::SubCmd::Wire { args } => self.run_wire(args)?,
            args::SubCmd::Pcap { args } => self.run_pcap(args)?,
            args::SubCmd::Nfq { args } => self.run_nfq(args).await?,
        };
        Ok(())
    }
    fn process_frame_payload<T: AsRef<[u8]>>(
        &mut self,
        ethertype: EtherType,
        payload: T,
        censor_ctx: &mut Context,
    ) -> Result<Action, SmoltcpError> {
        coz::progress!("process_frame_payload");
        // For non-IP ethertypes, skip full packet parsing
        let action = match ethertype {
            EtherType::Arp => return self.process_arp(&payload),
            EtherType::Unknown(_) => return Ok(self.ethernet_unknown),
            // IP packets need full parsing for transport-layer processing
            EtherType::Ipv4 | EtherType::Ipv6 => {
                match Packet::from_ts_bytes(None, payload.as_ref(), ethertype) {
                    Ok(packet) => match ethertype {
                        EtherType::Ipv4 => self.process_ipv4(&payload, censor_ctx, packet),
                        EtherType::Ipv6 => self.process_ipv6(&payload, censor_ctx, packet),
                        _ => unreachable!(),
                    },
                    // Unparseable packets are expected (e.g. truncated frames) and
                    // should not block traffic.
                    Err(err) => {
                        warn!("Error parsing packet, allowing through: {:?}", err);
                        return Ok(Default::default());
                    }
                }
            }
        };
        // Handle the delayer if relevant
        match action? {
            Action::Delay(instant) => {
                if let Context::Nfq(nfq::Context { delayer, .. }) = censor_ctx {
                    delayer
                        .delay_packet(payload.as_ref().to_vec(), instant)
                        .unwrap();
                    // We consider the packet "dropped" here
                    Ok(Action::Drop)
                } else {
                    // If we couldnt delay the packet, just pass it
                    Ok(Action::None)
                }
            }
            // Return any other actions
            action => Ok(action),
        }
    }
    /// Processes the raw packet based on its metadata and our internal state
    ///
    /// # Parameters
    /// * `data` - Raw packet data in bytes
    fn process_frame<T: AsRef<[u8]>>(
        &mut self,
        data: T,
        censor_ctx: &mut Context,
    ) -> Result<Action, SmoltcpError> {
        // Parse packet as ethernet
        let frame = EthernetFrame::new_checked(data.as_ref())?;
        // Pull out metadata before we borrow the payload
        let src_addr = frame.src_addr();
        let dst_addr = frame.dst_addr();
        let ethertype = frame.ethertype();
        // Borrow payload
        let payload = frame.payload();
        // Process the allow/blocklists
        match self.ethernet_list.recommend_either(&src_addr, &dst_addr) {
            // If the list didn't make a decision or said to continue, then continue
            Some(Action::None) | None => Ok(self
                .process_frame_payload(ethertype, payload, censor_ctx)?
                .add_mac(frame.src_addr().0, frame.dst_addr().0)),
            // Reset is not valid for Ethernet layer (see TODO.md: make unrepresentable)
            Some(Action::Reset { .. }) => {
                warn!("Reset is not a valid action for ethernet allow/blocklist. Dropping instead");
                Ok(Action::Drop)
            }
            // Other actions are returned immediately without further processing
            Some(action) => Ok(action),
        }
    }
    /// Processes an IPv4 packet based on its metadata and our internal state
    ///
    /// # Parameters
    /// * `data` - Raw ipv4 payload (unchecked)
    fn process_ipv4<T: AsRef<[u8]>>(
        &mut self,
        data: T,
        censor_ctx: &mut Context,
        packet: Packet,
    ) -> Result<Action, SmoltcpError> {
        // Just make sure the packet is indeed ipv4
        let ipv4_packet = Ipv4Packet::new_checked(data.as_ref())?;
        // Figure out our direction
        let direction = match censor_ctx {
            // For wire mode we always know the direction
            #[cfg(feature = "wire")]
            Context::Wire(ctx) => ctx.direction,
            // For pcap/nfq mode we infer it using a client IP
            Context::Pcap(pcap::Context { client_ip })
            | Context::Nfq(nfq::Context { client_ip, .. }) => {
                if let IpAddress::Ipv4(client_ip) = client_ip {
                    if ipv4_packet.src_addr() == *client_ip {
                        Direction::ClientToWan
                    } else if ipv4_packet.dst_addr() == *client_ip {
                        Direction::WanToClient
                    } else {
                        Direction::Unknown
                    }
                } else {
                    Direction::Unknown
                }
            }
        };
        // Process the remainder using the generic IP handler
        let result = self.process_ip(
            IpPair::V4 {
                src: ipv4_packet.src_addr(),
                dst: ipv4_packet.dst_addr(),
            },
            Some(ipv4_packet.ident()),
            ipv4_packet.next_header(),
            direction,
            ipv4_packet.payload(),
            packet,
        );
        result.map(|action| action.add_ipid(ipv4_packet.ident()))
    }
    /// Processes an IPv6 packet based on its metadata and our internal state
    ///
    /// # Parameters
    /// * `data` - Raw ipv6 payload (unchecked)
    fn process_ipv6<T: AsRef<[u8]>>(
        &mut self,
        data: T,
        censor_ctx: &mut Context,
        packet: Packet,
    ) -> Result<Action, SmoltcpError> {
        // Just make sure the packet is indeed ipv6
        let ipv6_packet = Ipv6Packet::new_checked(data.as_ref())?;
        // Figure out our direction
        let direction = match censor_ctx {
            // For wire mode we always know the direction
            #[cfg(feature = "wire")]
            Context::Wire(ctx) => ctx.direction,
            // For pcap/nfq mode we infer it using a client IP
            Context::Pcap(pcap::Context { client_ip })
            | Context::Nfq(nfq::Context { client_ip, .. }) => {
                if let IpAddress::Ipv6(client_ip) = *client_ip {
                    if ipv6_packet.src_addr() == client_ip {
                        Direction::ClientToWan
                    } else if ipv6_packet.dst_addr() == client_ip {
                        Direction::WanToClient
                    } else {
                        Direction::Unknown
                    }
                } else {
                    Direction::Unknown
                }
            }
        };
        // Process the remainder using the generic IP handler
        self.process_ip(
            IpPair::V6 {
                src: ipv6_packet.src_addr(),
                dst: ipv6_packet.dst_addr(),
            },
            None,
            ipv6_packet.next_header(),
            direction,
            ipv6_packet.payload(),
            packet,
        )
    }
    /// Generic IP processing function that simplifies some of the logic and avoids exponential
    /// branching
    ///
    /// # Parameters
    /// * `ip_src` - source ip
    /// * `ip_dst` - destination ip
    /// * `next_header` -  protocol of the underlying packet
    /// * `direction` - which direction this packet was processed in
    /// * `data` - payload of ip packet
    /// * `reset` - Whether we should issue a reset if tcp
    /// * `swap` - Whether we should swap src and dst fields
    fn process_ip<T: AsRef<[u8]>>(
        &mut self,
        ips: IpPair,
        _ipid: Option<u16>,
        next_header: IpProtocol,
        direction: Direction,
        data: T,
        packet: Packet,
    ) -> Result<Action, SmoltcpError> {
        // Enrich logging
        let span = info_span!(
            "ip",
            direction = tracing::field::display(direction),
            src = tracing::field::display(ips.src()),
            dst = tracing::field::display(ips.dst())
        );
        let _enter = span.enter();
        // Dispatch processing based on protocol
        match next_header {
            IpProtocol::Tcp | IpProtocol::Udp => {
                self.process_transport(ips, data.as_ref(), direction, packet)
            }
            IpProtocol::Icmp => self.process_icmp(ips, direction, data.as_ref()),
            other => {
                debug!(
                    "Encountered packet with unknown IP protocol {}. Performing {} action",
                    other, self.ip_unknown
                );
                Ok(self.ip_unknown)
            }
        }
    }
    /// Processes the arp packet based on its metadata and our internal state
    ///
    /// # Parameters
    /// * `data` - Raw ethernet payload (unchecked)
    fn process_arp<T: AsRef<[u8]>>(&mut self, data: T) -> Result<Action, SmoltcpError> {
        // Just make sure the packet is indeed arp
        let _arp_packet = ArpPacket::new_checked(data)?;
        // Do what we are supposed to for arp
        Ok(self.arp.action)
    }
    /// Processes an ICMP packet based on its metadata nad our internal state
    ///
    /// # Parameters
    /// * `data` - Raw payload of an IP packet
    fn process_icmp<T: AsRef<[u8]>>(
        &mut self,
        ips: IpPair,
        _direction: Direction,
        data: T,
    ) -> Result<Action, SmoltcpError> {
        match ips {
            IpPair::V4 { .. } => {
                let _icmp_packet = Icmpv4Packet::new_checked(data)?;
            }
            IpPair::V6 { .. } => {
                let _icmp_packet = Icmpv6Packet::new_checked(data)?;
            }
        }
        Ok(self.icmp.action)
    }
    /// Processes the transport-layer  packet based on its metadata and our internal state
    ///
    /// # Parameters
    /// * `src_ip` - Source IP address from the encapsulating IP payload
    /// * `dst_ip` - Destination IP address from the encapsulating IP payload
    /// * `data` - Raw transport-layer payload from an ip frame
    fn process_transport<T: AsRef<[u8]>>(
        &mut self,
        ips: IpPair,
        _data: T,
        direction: Direction,
        packet: Packet,
    ) -> Result<Action, SmoltcpError> {
        // First, process using the port list
        match self
            .tcp_port_list
            .recommend_either(&packet.transport.src, &packet.transport.dst)
        {
            // If we pass the whitelist, process our packet normally
            Some(Action::None) | None => self.transport_state.process(ips, direction, packet),
            // Any other action must return immediately
            Some(action) => Ok(action),
        }
    }
}
impl fmt::Display for Censor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Censor Parameters:")?;

        // Ethernet
        let eth_allow = self.ethernet_list.allow.store.len();
        let eth_block = self.ethernet_list.block.store.len();
        if eth_allow > 0 || eth_block > 0 {
            writeln!(f, "  Ethernet: {eth_allow} allowed, {eth_block} blocked")?;
        }
        writeln!(f, "  Ethernet unknown ethertype: {}", self.ethernet_unknown)?;

        // IP
        let ipv4_allow = self.ipv4_list.allow.store.len();
        let ipv4_block = self.ipv4_list.block.store.len();
        let ipv6_allow = self.ipv6_list.allow.store.len();
        let ipv6_block = self.ipv6_list.block.store.len();
        if ipv4_allow > 0 || ipv4_block > 0 {
            writeln!(f, "  IPv4: {ipv4_allow} allowed, {ipv4_block} blocked")?;
        }
        if ipv6_allow > 0 || ipv6_block > 0 {
            writeln!(f, "  IPv6: {ipv6_allow} allowed, {ipv6_block} blocked")?;
        }
        writeln!(f, "  IP unknown protocol: {}", self.ip_unknown)?;

        // ICMP
        writeln!(f, "  ICMP: {}", self.icmp.action)?;

        // TCP
        let tcp_ip_port_allow = self.tcp_ip_port_list.allow.store.len();
        let tcp_ip_port_block = self.tcp_ip_port_list.block.store.len();
        if tcp_ip_port_allow > 0 || tcp_ip_port_block > 0 {
            writeln!(f, "  TCP ip:port: {tcp_ip_port_allow} allowed, {tcp_ip_port_block} blocked")?;
        }

        // UDP
        let udp_ip_port_allow = self.udp_ip_port_list.allow.store.len();
        let udp_ip_port_block = self.udp_ip_port_list.block.store.len();
        if udp_ip_port_allow > 0 || udp_ip_port_block > 0 {
            writeln!(f, "  UDP ip:port: {udp_ip_port_allow} allowed, {udp_ip_port_block} blocked")?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub enum IpPair {
    V4 { src: Ipv4Address, dst: Ipv4Address },
    V6 { src: Ipv6Address, dst: Ipv6Address },
}
impl IpPair {
    pub fn src(&self) -> IpAddress {
        match self {
            IpPair::V4 { src, .. } => (*src).into(),
            IpPair::V6 { src, .. } => (*src).into(),
        }
    }
    pub fn dst(&self) -> IpAddress {
        match self {
            IpPair::V4 { dst, .. } => (*dst).into(),
            IpPair::V6 { dst, .. } => (*dst).into(),
        }
    }
    pub fn swap(&self) -> Self {
        match self {
            IpPair::V4 { src, dst } => IpPair::V4 {
                src: *dst,
                dst: *src,
            },
            IpPair::V6 { src, dst } => IpPair::V6 {
                src: *dst,
                dst: *src,
            },
        }
    }
}

/// Result of reading a packet then sending it, incorporating special cases
// this is basically just an option. should we convert it?
pub enum ForwardFramesResult {
    /// Some frames were successfully forwarded
    Success,
    /// A frame was successfully read, but failed to send, and we reached our max number of tries
    /// Contains the size of the failed frame
    TxFull(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    WanToClient,
    ClientToWan,
    Unknown,
}
impl Direction {
    /// Direction-to-sign mapping used for numeric conversion (e.g. ML features).
    ///
    /// Convention: WanToClient = -1, Unknown = 0, ClientToWan = 1.
    /// This matches the sign convention used in paper experiments and training data.
    /// If a different mapping is needed, these constants can be adjusted here.
    pub const NEGATIVE_ONE: Direction = Direction::WanToClient;
    /// Which direction should be converted to 0
    pub const ZERO: Direction = Direction::Unknown;
    /// Which direction should be converted to 1
    pub const ONE: Direction = Direction::ClientToWan;
}
impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Direction::WanToClient => "wan->client",
            Direction::ClientToWan => "client->wan",
            Direction::Unknown => "unknown",
        })
    }
}
impl From<Direction> for f64 {
    fn from(dir: Direction) -> Self {
        match dir {
            Direction::NEGATIVE_ONE => -1.0,
            Direction::ZERO => 0.0,
            Direction::ONE => 1.0,
        }
    }
}

#[cfg(feature = "wire")]
pub struct RetryBuffer {
    buf: Vec<u8>,
    size: Option<usize>,
}

#[cfg(feature = "wire")]
impl RetryBuffer {
    fn for_interface(interface: &RawSocket) -> Self {
        // Get iface MTU
        let mtu = interface.capabilities().max_transmission_unit;
        // Create an MTU size buffer
        Self {
            buf: vec![0; mtu],
            size: None,
        }
    }
    fn get_data(&self) -> Option<&[u8]> {
        self.size.map(|size| &self.buf[..size])
    }
    fn clear(&mut self) {
        self.size = None;
    }
}

#[cfg(feature = "wire")]
impl<T> Index<T> for RetryBuffer
where
    T: SliceIndex<[u8]>,
{
    type Output = <T as SliceIndex<[u8]>>::Output;
    fn index(&self, index: T) -> &Self::Output {
        self.buf.index(index)
    }
}
#[cfg(feature = "wire")]
impl<T> IndexMut<T> for RetryBuffer
where
    T: SliceIndex<[u8]>,
{
    fn index_mut(&mut self, index: T) -> &mut Self::Output {
        self.buf.index_mut(index)
    }
}

/// An action taken by the censor
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Default)]
pub enum Action {
    /// Continue to process the packet.
    /// If there is no more processing to be done, Wire mode and nfq mode will forward the packet
    #[default]
    None,
    /// Send a RST in both directions
    Reset {
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        ips: IpPair,
        ipid: Option<u16>,
        src_port: u16,
        dst_port: u16,
        seq: TcpSeqNumber,
        ack: TcpSeqNumber,
        is_ack: bool,
        payload_len: usize,
    },
    /// Ignore  the packet immediately without further processing
    /// In wire mode this does a forward, in tap mode this ignores the packet
    Ignore,
    /// Drop the packet immediately without further processing
    /// Only allowed in wire mode
    Drop,
    /// Delay the packet until the given time
    Delay(Instant),
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Less)
    }
}

impl Action {
    pub fn is_reset(&self) -> bool {
        matches!(self, Action::Reset { .. })
    }
    pub fn enrich(
        self,
        ips: IpPair,
        src_port: u16,
        dst_port: u16,
        ack: TcpSeqNumber,
        seq: TcpSeqNumber,
        payload_len: usize,
    ) -> Self {
        if let Action::Reset {
            src_mac,
            dst_mac,
            ipid,
            is_ack,
            ..
        } = self
        {
            Action::Reset {
                src_mac,
                dst_mac,
                ips,
                ipid,
                src_port,
                dst_port,
                seq,
                ack,
                payload_len,
                is_ack,
            }
        } else {
            self
        }
    }
    pub fn add_mac(self, src_mac: [u8; 6], dst_mac: [u8; 6]) -> Self {
        if let Action::Reset {
            ips,
            ipid,
            src_port,
            dst_port,
            seq,
            ack,
            payload_len,
            is_ack,
            ..
        } = self
        {
            Action::Reset {
                src_mac,
                dst_mac,
                ips,
                ipid,
                src_port,
                dst_port,
                seq,
                ack,
                payload_len,
                is_ack,
            }
        } else {
            self
        }
    }
    pub fn add_ipid(self, ipid: u16) -> Self {
        if let Action::Reset {
            src_mac,
            dst_mac,
            ips,
            src_port,
            dst_port,
            seq,
            ack,
            payload_len,
            is_ack,
            ..
        } = self
        {
            Action::Reset {
                src_mac,
                dst_mac,
                ips,
                ipid: Some(ipid),
                src_port,
                dst_port,
                seq,
                ack,
                payload_len,
                is_ack,
            }
        } else {
            self
        }
    }
}

#[derive(Debug, Error)]
#[error("Invalid action: {0}")]
pub struct ActionFromStrError(String);

impl FromStr for Action {
    type Err = ActionFromStrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "none" => Ok(Action::None),
            "ignore" => Ok(Action::Ignore),
            "drop" => Ok(Action::Drop),
            "reset" => Ok(Action::Reset {
                src_mac: [0; 6],
                dst_mac: [0; 6],
                ips: IpPair::V4 {
                    src: Ipv4Address::UNSPECIFIED,
                    dst: Ipv4Address::UNSPECIFIED,
                },
                ipid: None,
                src_port: 0,
                dst_port: 0,
                ack: TcpSeqNumber(0),
                seq: TcpSeqNumber(0),
                payload_len: 0,
                is_ack: false,
            }),
            _other => Err(ActionFromStrError(s.to_owned())),
        }
    }
}
impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}
impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Action::None => "continue processing",
            Action::Ignore => "ignore without processing",
            Action::Drop => "drop without processing",
            Action::Reset { .. } => {
                "process up to before packet aggregation then send a RST packet to both sides"
            }
            Action::Delay(_instant) => "delay the packet",
        })
    }
}

#[derive(Debug, Error)]
pub enum HandleIpcError {
    #[error("Ipc indicated shutdown")]
    Shutdown,
    #[error("Error building model")]
    Ort(#[from] OrtError),
}

async fn signal_handler_thread(
    sender: UnboundedSender<crate::ipc::Message>,
) -> Result<(), SignalHandlerThreadError> {
    // Handle signals
    let mut signal_handler = signal(SignalKind::interrupt())?;
    loop {
        if let Some(()) = signal_handler.recv().await {
            error!("Received SIGINT. shutting down");
            sender.send(crate::ipc::Message::Shutdown)?;
        } else {
            break;
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SignalHandlerThreadError {
    #[error("Error setting up signal handler: {0}")]
    Init(#[from] io::Error),
    #[error("Error sending shutdown to ipc")]
    Ipc(#[from] SendError<crate::ipc::Message>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::List;
    use std::collections::HashSet;
    use std::str::FromStr;

    // --- Action FromStr tests ---

    #[test]
    fn action_from_str_none() {
        let action = Action::from_str("none").unwrap();
        assert_eq!(action, Action::None);
    }

    #[test]
    fn action_from_str_ignore() {
        let action = Action::from_str("ignore").unwrap();
        assert_eq!(action, Action::Ignore);
    }

    #[test]
    fn action_from_str_drop() {
        let action = Action::from_str("drop").unwrap();
        assert_eq!(action, Action::Drop);
    }

    #[test]
    fn action_from_str_reset() {
        let action = Action::from_str("reset").unwrap();
        assert!(action.is_reset());
    }

    #[test]
    fn action_from_str_case_insensitive() {
        let action = Action::from_str("NONE").unwrap();
        assert_eq!(action, Action::None);
        let action = Action::from_str("Drop").unwrap();
        assert_eq!(action, Action::Drop);
    }

    #[test]
    fn action_from_str_invalid() {
        let result = Action::from_str("invalid_action");
        assert!(result.is_err());
    }

    // --- Action Display tests ---

    #[test]
    fn action_display_none() {
        assert_eq!(format!("{}", Action::None), "continue processing");
    }

    #[test]
    fn action_display_ignore() {
        assert_eq!(
            format!("{}", Action::Ignore),
            "ignore without processing"
        );
    }

    #[test]
    fn action_display_drop() {
        assert_eq!(format!("{}", Action::Drop), "drop without processing");
    }

    #[test]
    fn action_display_reset() {
        let action = Action::from_str("reset").unwrap();
        let display = format!("{}", action);
        assert!(display.contains("RST"));
    }

    // --- Direction tests ---

    #[test]
    fn direction_to_f64_wan_to_client() {
        let val: f64 = Direction::WanToClient.into();
        assert_eq!(val, -1.0);
    }

    #[test]
    fn direction_to_f64_client_to_wan() {
        let val: f64 = Direction::ClientToWan.into();
        assert_eq!(val, 1.0);
    }

    #[test]
    fn direction_to_f64_unknown() {
        let val: f64 = Direction::Unknown.into();
        assert_eq!(val, 0.0);
    }

    #[test]
    fn direction_display_wan_to_client() {
        assert_eq!(format!("{}", Direction::WanToClient), "wan->client");
    }

    #[test]
    fn direction_display_client_to_wan() {
        assert_eq!(format!("{}", Direction::ClientToWan), "client->wan");
    }

    #[test]
    fn direction_display_unknown() {
        assert_eq!(format!("{}", Direction::Unknown), "unknown");
    }

    // --- BlockList tests ---

    #[test]
    fn blocklist_recommend_item_in_list() {
        let store: HashSet<u16> = vec![80, 443].into_iter().collect();
        let blocklist = BlockList {
            store,
            in_blocklist: Action::Drop,
        };
        assert_eq!(blocklist.recommend(&80), Some(Action::Drop));
        assert_eq!(blocklist.recommend(&443), Some(Action::Drop));
    }

    #[test]
    fn blocklist_recommend_item_not_in_list() {
        let store: HashSet<u16> = vec![80, 443].into_iter().collect();
        let blocklist = BlockList {
            store,
            in_blocklist: Action::Drop,
        };
        assert_eq!(blocklist.recommend(&22), None);
    }

    // --- AllowList tests ---

    #[test]
    fn allowlist_recommend_item_in_list() {
        let store: HashSet<u16> = vec![80, 443].into_iter().collect();
        let list = List {
            list: store,
            action: Action::Drop,
        };
        let allowlist = AllowList::from(list);
        // Item in allowlist => no action (allowed)
        assert_eq!(allowlist.recommend(&80), None);
    }

    #[test]
    fn allowlist_recommend_item_not_in_list() {
        let store: HashSet<u16> = vec![80, 443].into_iter().collect();
        let list = List {
            list: store,
            action: Action::Drop,
        };
        let allowlist = AllowList::from(list);
        // Item NOT in allowlist => action taken
        assert_eq!(allowlist.recommend(&22), Some(Action::Drop));
    }

    // --- AllowBlockList tests ---

    #[test]
    fn allowblocklist_blocklist_takes_priority() {
        // Blocklist blocks port 80
        let block_store: HashSet<u16> = vec![80].into_iter().collect();
        let blocklist = BlockList {
            store: block_store,
            in_blocklist: Action::Drop,
        };
        // Allowlist allows port 80 (but blocklist should win)
        let allow_store: HashSet<u16> = vec![80, 443].into_iter().collect();
        let allow_list = List {
            list: allow_store,
            action: Action::Ignore,
        };
        let allowlist = AllowList::from(allow_list);
        let abl = AllowBlockList::new(allowlist, blocklist);
        // Port 80 is in blocklist => Drop
        assert_eq!(abl.recommend(&80), Some(Action::Drop));
    }

    #[test]
    fn allowblocklist_allowlist_checked_when_not_blocked() {
        let block_store: HashSet<u16> = vec![80].into_iter().collect();
        let blocklist = BlockList {
            store: block_store,
            in_blocklist: Action::Drop,
        };
        let allow_store: HashSet<u16> = vec![443].into_iter().collect();
        let allow_list = List {
            list: allow_store,
            action: Action::Ignore,
        };
        let allowlist = AllowList::from(allow_list);
        let abl = AllowBlockList::new(allowlist, blocklist);
        // Port 443 is allowed (in allowlist, not in blocklist) => None
        assert_eq!(abl.recommend(&443), None);
        // Port 22 is not in allowlist and not in blocklist => Ignore (allowlist action)
        assert_eq!(abl.recommend(&22), Some(Action::Ignore));
    }
}
