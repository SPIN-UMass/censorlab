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
use crate::config::{Config, IpNetPort};
use crate::ipc::{ipc_thread, ModelThreadError};
use crate::model::onnx::ModelLoadError;
use crate::model::Models;
use crate::program::packet::{IpLayer, Packet};
use crate::transport::{TransportState, TransportStateInitError};
use bitvec::prelude::*;
use ort::Error as OrtError;
use serde::{de, Deserialize, Deserializer};
use smoltcp::wire::Error as SmoltcpError;
use smoltcp::wire::{
    ArpPacket, EthernetAddress, EthernetFrame, EthernetProtocol as EtherType,
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpSeqNumber,
};
use std::collections::HashSet;
use std::fmt;
use std::io;
use crate::subnet::IpNet;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;
use thiserror::Error;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinError;
use crate::packet_log::{debug, error, warn};

/// Used for fast access to a list of every port for examples such as udp port filtering
pub type PortVec = BitArr!(for 65536, in u64, Msb0);

/// Arguments to the censor are stored here
pub mod args {
    use clap::Parser;
    use std::path::PathBuf;
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
        /// Statically analyse a CensorLang program: per-connection/per-host memory
        /// and worst-case per-packet operation counts.  No traffic is processed.
        Analyze {
            /// Path to the CensorLang program (.cl)
            program: PathBuf,
            /// Emit JSON instead of a human-readable report
            #[clap(long)]
            json: bool,
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
    ipv4_list: AllowBlockList<crate::subnet::Ipv4Set>,
    /// IPv6 allow/blocklist
    ipv6_list: AllowBlockList<crate::subnet::Ipv6Set>,
    /// What to do with ip packets with unknown type
    ip_unknown: Action,
    // ICMP
    /// What to do with ICMP packets
    icmp: crate::config::icmp::Config,
    // TCP
    /// TCP allow/blocklist for ports
    tcp_port_list: AllowBlockList<PortVec>,
    /// TCP allow/blocklist for ip-port pairs
    tcp_ip_port_list: AllowBlockList<crate::subnet::IpPortSet>,
    // UDP
    /// UDP allow/blocklist for ports
    udp_port_list: AllowBlockList<PortVec>,
    /// UDP allow/blocklist for ip-port pairs
    udp_ip_port_list: AllowBlockList<crate::subnet::IpPortSet>,
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
        loaded_models: Models,
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
            conntrack,
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
            if let IpNet::V4(ipv4) = ip {
                Some(ipv4)
            } else {
                None
            }
        };
        let ipv6_filter = |ip| {
            if let IpNet::V6(ipv6) = ip {
                Some(ipv6)
            } else {
                None
            }
        };
        // Perform filtering (ipv4)
        let ipv4_allowlist = AllowList::from(ip.allowlist.filter_map(ipv4_filter).collect());
        let ipv4_blocklist = BlockList::from(ip.blocklist.filter_map(ipv4_filter).collect());
        // Combine allow and blocklist
        let ipv4_list = AllowBlockList::new(ipv4_allowlist, ipv4_blocklist);
        // Perform filtering (ipv6)
        let ipv6_allowlist = AllowList::from(ip.allowlist.filter_map(ipv6_filter).collect());
        let ipv6_blocklist = BlockList::from(ip.blocklist.filter_map(ipv6_filter).collect());
        // Combine allow and blocklist
        let ipv6_list = AllowBlockList::new(ipv6_allowlist, ipv6_blocklist);

        // Initialize bitvec for tcp port lists
        let tcp_port_allowlist = AllowList::from(tcp.port_allowlist.bit_vec());
        let tcp_port_blocklist = BlockList::from(tcp.port_blocklist.bit_vec());
        // Combine into 1 thing
        let tcp_port_list = AllowBlockList::new(tcp_port_allowlist, tcp_port_blocklist);
        // Initialize subnet sets for tcp ip-port lists
        let tcp_ip_port_allowlist = AllowList::from(tcp.ip_port_allowlist.map(IpNetPort::into_pair).collect());
        let tcp_ip_port_blocklist = BlockList::from(tcp.ip_port_blocklist.map(IpNetPort::into_pair).collect());
        // Combine into 1 thing
        let tcp_ip_port_list = AllowBlockList::new(tcp_ip_port_allowlist, tcp_ip_port_blocklist);

        // Initialize bitvec for udp port lists
        let udp_port_allowlist = AllowList::from(udp.port_allowlist.bit_vec());
        let udp_port_blocklist = BlockList::from(udp.port_blocklist.bit_vec());
        // Combine into 1 thing
        let udp_port_list = AllowBlockList::new(udp_port_allowlist, udp_port_blocklist);
        // Initialize subnet sets for udp ip-port lists
        let udp_ip_port_allowlist = AllowList::from(udp.ip_port_allowlist.map(IpNetPort::into_pair).collect());
        let udp_ip_port_blocklist = BlockList::from(udp.ip_port_blocklist.map(IpNetPort::into_pair).collect());
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
            conntrack,
            loaded_models,
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
            // Handled in the binary before a Censor is constructed
            args::SubCmd::Analyze { .. } => {}
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
        let action = match ethertype {
            EtherType::Arp => return self.process_arp(&payload),
            EtherType::Unknown(_) => return Ok(self.ethernet_unknown.clone()),
            EtherType::Ipv4 => self.process_ipv4(&payload, censor_ctx),
            EtherType::Ipv6 => self.process_ipv6(&payload, censor_ctx),
        };
        // Mode-specific actions (e.g. Delay) are carried out by each mode's packet loop
        action
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
    ) -> Result<Action, SmoltcpError> {
        // Without a well-formed IP header there are no addresses to apply rules to.
        // Such packets are expected (e.g. truncated frames) and should not block traffic.
        let ipv4_packet = match Ipv4Packet::new_checked(data.as_ref()) {
            Ok(ipv4_packet) => ipv4_packet,
            Err(err) => {
                warn!("Error parsing IPv4 header, allowing through: {:?}", err);
                return Ok(Action::None);
            }
        };
        let ips = IpPair::V4 {
            src: ipv4_packet.src_addr(),
            dst: ipv4_packet.dst_addr(),
        };
        let ip_layer = IpLayer::from_ipv4(&ipv4_packet);
        // Check config-level IP allow/blocklist
        match self
            .ipv4_list
            .recommend_either(&ipv4_packet.src_addr(), &ipv4_packet.dst_addr())
        {
            Some(Action::None) | None => {}
            Some(Action::Reset { .. }) => {
                return Ok(reset_or_drop_ip(ips, Some(&ip_layer)).add_ipid(ipv4_packet.ident()));
            }
            Some(action) => return Ok(action),
        }
        // Figure out our direction
        let direction = match censor_ctx {
            // For wire mode we always know the direction
            #[cfg(feature = "wire")]
            Context::Wire(ctx) => ctx.direction,
            // For pcap/nfq mode we infer it using a client IP
            Context::Pcap(pcap::Context { client })
            | Context::Nfq(nfq::Context { client, .. }) => client.direction(
                ipv4_packet.src_addr().into(),
                ipv4_packet.dst_addr().into(),
            ),
        };
        // Process the remainder using the generic IP handler
        let result = self.process_ip(ips, direction, ip_layer);
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
    ) -> Result<Action, SmoltcpError> {
        // Without a well-formed IP header there are no addresses to apply rules to.
        // Such packets are expected (e.g. truncated frames) and should not block traffic.
        let ipv6_packet = match Ipv6Packet::new_checked(data.as_ref()) {
            Ok(ipv6_packet) => ipv6_packet,
            Err(err) => {
                warn!("Error parsing IPv6 header, allowing through: {:?}", err);
                return Ok(Action::None);
            }
        };
        let ips = IpPair::V6 {
            src: ipv6_packet.src_addr(),
            dst: ipv6_packet.dst_addr(),
        };
        // Find the upper-layer protocol behind any extension headers
        let ip_layer = IpLayer::from_ipv6(&ipv6_packet);
        // Check config-level IP allow/blocklist
        match self
            .ipv6_list
            .recommend_either(&ipv6_packet.src_addr(), &ipv6_packet.dst_addr())
        {
            Some(Action::None) | None => {}
            Some(Action::Reset { .. }) => {
                return Ok(reset_or_drop_ip(ips, ip_layer.as_ref().ok()));
            }
            Some(action) => return Ok(action),
        }
        // Figure out our direction
        let direction = match censor_ctx {
            // For wire mode we always know the direction
            #[cfg(feature = "wire")]
            Context::Wire(ctx) => ctx.direction,
            // For pcap/nfq mode we infer it using a client IP
            Context::Pcap(pcap::Context { client })
            | Context::Nfq(nfq::Context { client, .. }) => client.direction(
                ipv6_packet.src_addr().into(),
                ipv6_packet.dst_addr().into(),
            ),
        };
        match ip_layer {
            // Process the remainder using the generic IP handler
            Ok(ip_layer) => self.process_ip(ips, direction, ip_layer),
            // A broken extension-header chain hides the upper-layer protocol
            Err(err) => {
                debug!(
                    "Could not determine upper-layer protocol ({}). Performing {} action",
                    err, self.ip_unknown
                );
                Ok(without_reset(self.ip_unknown.clone()))
            }
        }
    }
    /// Generic IP processing function that simplifies some of the logic and avoids exponential
    /// branching. Called only after the IP-layer allow/blocklists have passed.
    ///
    /// # Parameters
    /// * `ips` - source and destination ip
    /// * `direction` - which direction this packet was processed in
    /// * `ip_layer` - the recognized IP layer, including the upper-layer protocol and payload
    fn process_ip(
        &mut self,
        ips: IpPair,
        direction: Direction,
        ip_layer: IpLayer,
    ) -> Result<Action, SmoltcpError> {
        // Attribute log events to this packet (an `ip{...}` span, see packet_log)
        let _packet = crate::packet_log::enter(direction, ips);
        // Dispatch processing based on protocol
        match (ip_layer.protocol, ips) {
            (IpProtocol::Tcp | IpProtocol::Udp, _) => {
                match Packet::from_ip_layer(None, &ip_layer) {
                    Ok(packet) => self.process_transport(ips, direction, packet),
                    // The IP-layer rules have already passed. Without a transport header
                    // (truncated/malformed, or a non-first fragment) there are no ports
                    // to match and no connection to track, so let the packet through.
                    Err(err) => {
                        warn!(
                            "Error parsing {} header, allowing through: {}",
                            ip_layer.protocol, err
                        );
                        Ok(Action::None)
                    }
                }
            }
            (IpProtocol::Icmp, IpPair::V4 { .. }) | (IpProtocol::Icmpv6, IpPair::V6 { .. }) => {
                Ok(self.icmp.action.clone())
            }
            (other, _) => {
                debug!(
                    "Encountered packet with unknown IP protocol {}. Performing {} action",
                    other, self.ip_unknown
                );
                // Never TCP, so there is no connection to reset
                Ok(without_reset(self.ip_unknown.clone()))
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
        Ok(self.arp.action.clone())
    }
    /// Processes the transport-layer  packet based on its metadata and our internal state
    ///
    /// # Parameters
    /// * `ips` - Source and destination IP addresses from the encapsulating IP packet
    /// * `direction` - which direction this packet was processed in
    /// * `packet` - The parsed TCP/UDP packet
    fn process_transport(
        &mut self,
        ips: IpPair,
        direction: Direction,
        packet: Packet,
    ) -> Result<Action, SmoltcpError> {
        let is_tcp = matches!(
            packet.transport.extra,
            crate::program::packet::TransportMetadataExtra::Tcp(_)
        );

        if is_tcp {
            // TCP port allow/blocklist
            match self
                .tcp_port_list
                .recommend_either(&packet.transport.src, &packet.transport.dst)
            {
                Some(Action::None) | None => {}
                Some(action) => return Ok(for_connection(action, ips, &packet)),
            }
            // TCP ip:port allow/blocklist
            let src_ipport = crate::config::IpPort(ips.src_std(), packet.transport.src);
            let dst_ipport = crate::config::IpPort(ips.dst_std(), packet.transport.dst);
            match self
                .tcp_ip_port_list
                .recommend_either(&src_ipport, &dst_ipport)
            {
                Some(Action::None) | None => {}
                Some(action) => return Ok(for_connection(action, ips, &packet)),
            }
        } else {
            // UDP port allow/blocklist
            match self
                .udp_port_list
                .recommend_either(&packet.transport.src, &packet.transport.dst)
            {
                Some(Action::None) | None => {}
                Some(action) => return Ok(for_connection(action, ips, &packet)),
            }
            // UDP ip:port allow/blocklist
            let src_ipport = crate::config::IpPort(ips.src_std(), packet.transport.src);
            let dst_ipport = crate::config::IpPort(ips.dst_std(), packet.transport.dst);
            match self
                .udp_ip_port_list
                .recommend_either(&src_ipport, &dst_ipport)
            {
                Some(Action::None) | None => {}
                Some(action) => return Ok(for_connection(action, ips, &packet)),
            }
        }

        self.transport_state.process(ips, direction, packet)
    }
}

/// Resolve a config-list action against the packet that triggered it: a Reset becomes a
/// RST for that packet's TCP connection (or Drop for UDP, which has none to reset).
fn for_connection(action: Action, ips: IpPair, packet: &Packet) -> Action {
    if action.is_reset() {
        crate::transport::reset_or_drop(ips, &packet.transport, packet.payload.len())
    } else {
        action
    }
}

/// Resolve an IP-rule Reset: a RST for the TCP connection the packet belongs to, or Drop
/// when it is not well-formed TCP (other protocols, fragments, truncated headers, or an
/// unparseable IPv6 extension-header chain, passed as `None`).
fn reset_or_drop_ip(ips: IpPair, ip_layer: Option<&IpLayer>) -> Action {
    ip_layer
        .filter(|ip_layer| ip_layer.protocol == IpProtocol::Tcp)
        .and_then(|ip_layer| Packet::from_ip_layer(None, ip_layer).ok())
        .map(|packet| crate::transport::reset_or_drop(ips, &packet.transport, packet.payload.len()))
        .unwrap_or(Action::Drop)
}

/// Replace a Reset with Drop for traffic that can never be TCP.
fn without_reset(action: Action) -> Action {
    if action.is_reset() {
        Action::Drop
    } else {
        action
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
    pub fn src_std(&self) -> std::net::IpAddr {
        match self {
            IpPair::V4 { src, .. } => std::net::IpAddr::V4(*src),
            IpPair::V6 { src, .. } => std::net::IpAddr::V6(*src),
        }
    }
    pub fn dst_std(&self) -> std::net::IpAddr {
        match self {
            IpPair::V4 { dst, .. } => std::net::IpAddr::V4(*dst),
            IpPair::V6 { dst, .. } => std::net::IpAddr::V6(*dst),
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

/// The set of addresses considered to be "the client" when inferring traffic
/// direction in NFQ/PCAP mode.  Holding a set (rather than a single address)
/// lets IPv4 and IPv6 traffic both get a direction, and covers hosts with
/// several addresses per family (e.g. IPv6 temporary addresses).
#[derive(Clone, Debug, Default)]
pub struct ClientAddrs(Vec<IpAddress>);

impl ClientAddrs {
    pub fn new(addrs: impl IntoIterator<Item = IpAddress>) -> Self {
        let mut v: Vec<IpAddress> = Vec::new();
        for addr in addrs {
            if !v.contains(&addr) {
                v.push(addr);
            }
        }
        Self(v)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains(&self, addr: IpAddress) -> bool {
        self.0.contains(&addr)
    }
    /// Direction of a packet `src -> dst` relative to the client.
    pub fn direction(&self, src: IpAddress, dst: IpAddress) -> Direction {
        if self.contains(src) {
            Direction::ClientToWan
        } else if self.contains(dst) {
            Direction::WanToClient
        } else {
            Direction::Unknown
        }
    }
}

impl fmt::Display for ClientAddrs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, addr) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{addr}")?;
        }
        Ok(())
    }
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

/// An action taken by the censor
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Default)]
pub enum Action {
    /// Continue to process the packet.
    /// If there is no more processing to be done, Wire mode and nfq mode will forward the packet
    #[default]
    None,
    /// Send a RST in both directions
    ///
    /// Addresses, ports and sequence numbers describe the triggering segment; build
    /// it with [`crate::transport::reset_for`].
    Reset {
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        ips: IpPair,
        ipid: Option<u16>,
        src_port: u16,
        dst_port: u16,
        /// SEG.SEQ of the triggering segment
        seq: TcpSeqNumber,
        /// SEG.ACK of the triggering segment (meaningful only if `is_ack`)
        ack: TcpSeqNumber,
        /// Whether the triggering segment had the ACK flag set
        is_ack: bool,
        /// SEG.LEN of the triggering segment: payload bytes plus one each for SYN and FIN
        seg_len: usize,
    },
    /// Inject a UDP packet (e.g. forged DNS response) while allowing the original through
    Inject {
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        ips: IpPair,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    },
    /// Ignore  the packet immediately without further processing
    /// In wire mode this does a forward, in tap mode this ignores the packet
    Ignore,
    /// Drop the packet immediately without further processing
    /// Only allowed in wire mode
    Drop,
    /// Delay the packet until the given time
    Delay(Instant),
    /// Forward a mutated copy of the packet (normalization, e.g. TSPU-style TTL
    /// rewriting).  The mutation is structured and applied by the engine, which
    /// recomputes checksums; censor programs never hand back raw packet bytes.
    Rewrite(Rewrite),
}

/// A structured packet mutation applied by the [`Action::Rewrite`] action.
///
/// Only named, bounded fields are supported so that the rewritten packet is
/// correct by construction: the engine re-validates the header it edits and
/// fixes the IPv4 header checksum itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd)]
pub struct Rewrite {
    /// New IPv4 TTL / IPv6 hop limit.
    pub ttl: Option<u8>,
}

impl Rewrite {
    /// Apply the mutation in place to an IP packet (no link-layer header).
    /// Returns `false` (leaving the buffer untouched) if the packet is not a
    /// well-formed IPv4/IPv6 header.
    pub fn apply_ip(&self, packet: &mut [u8]) -> bool {
        match packet.first().map(|b| b >> 4) {
            Some(4) => {
                let mut ip = match Ipv4Packet::new_checked(packet) {
                    Ok(ip) => ip,
                    Err(_) => return false,
                };
                if let Some(ttl) = self.ttl {
                    ip.set_hop_limit(ttl);
                }
                ip.fill_checksum();
                true
            }
            Some(6) => {
                let mut ip = match Ipv6Packet::new_checked(packet) {
                    Ok(ip) => ip,
                    Err(_) => return false,
                };
                if let Some(ttl) = self.ttl {
                    ip.set_hop_limit(ttl);
                }
                true
            }
            _ => false,
        }
    }

    /// Apply the mutation in place to an Ethernet frame carrying IPv4/IPv6.
    pub fn apply_ethernet(&self, frame: &mut [u8]) -> bool {
        let mut eth = match EthernetFrame::new_checked(frame) {
            Ok(eth) => eth,
            Err(_) => return false,
        };
        match eth.ethertype() {
            EtherType::Ipv4 | EtherType::Ipv6 => self.apply_ip(eth.payload_mut()),
            _ => false,
        }
    }
}

impl Action {
    pub fn is_reset(&self) -> bool {
        matches!(self, Action::Reset { .. })
    }
    pub fn is_inject(&self) -> bool {
        matches!(self, Action::Inject { .. })
    }
    pub fn add_mac(self, src_mac: [u8; 6], dst_mac: [u8; 6]) -> Self {
        match self {
            Action::Reset {
                ips,
                ipid,
                src_port,
                dst_port,
                seq,
                ack,
                seg_len,
                is_ack,
                ..
            } => Action::Reset {
                src_mac,
                dst_mac,
                ips,
                ipid,
                src_port,
                dst_port,
                seq,
                ack,
                seg_len,
                is_ack,
            },
            // Inject already carries its own MAC addresses
            other => other,
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
            seg_len,
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
                seg_len,
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
                seg_len: 0,
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
            Action::Inject { .. } => "inject a forged UDP response packet",
            Action::Delay(_instant) => "delay the packet",
            Action::Rewrite(_) => "forward a rewritten copy of the packet",
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

#[cfg(test)]
mod rewrite_tests {
    use super::*;

    /// Minimal IPv4/TCP packet (20-byte header, no payload) with a valid checksum.
    fn ipv4_packet(ttl: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        buf[0] = 0x45;
        buf[3] = 40;
        buf[8] = ttl;
        buf[9] = 6;
        buf[12..16].copy_from_slice(&[10, 0, 0, 1]);
        buf[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.fill_checksum();
        buf
    }

    #[test]
    fn rewrite_sets_ipv4_ttl_and_fixes_checksum() {
        let mut pkt = ipv4_packet(3);
        assert!(Rewrite { ttl: Some(64) }.apply_ip(&mut pkt));
        let ip = Ipv4Packet::new_checked(&pkt[..]).unwrap();
        assert_eq!(ip.hop_limit(), 64);
        assert!(ip.verify_checksum(), "header checksum must be recomputed");
    }

    #[test]
    fn rewrite_sets_ipv6_hop_limit() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[7] = 2;
        assert!(Rewrite { ttl: Some(64) }.apply_ip(&mut pkt));
        assert_eq!(Ipv6Packet::new_checked(&pkt[..]).unwrap().hop_limit(), 64);
    }

    #[test]
    fn rewrite_rejects_garbage() {
        let mut pkt = vec![0xffu8; 3];
        let before = pkt.clone();
        assert!(!Rewrite { ttl: Some(64) }.apply_ip(&mut pkt));
        assert_eq!(pkt, before);
    }

    #[test]
    fn rewrite_applies_through_ethernet() {
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08; // IPv4
        frame.extend(ipv4_packet(1));
        assert!(Rewrite { ttl: Some(64) }.apply_ethernet(&mut frame));
        assert_eq!(Ipv4Packet::new_checked(&frame[14..]).unwrap().hop_limit(), 64);
    }
}

#[cfg(test)]
mod client_addrs_tests {
    use super::*;

    fn v4(a: u8) -> IpAddress {
        Ipv4Address::new(10, 0, 0, a).into()
    }
    fn v6(a: u16) -> IpAddress {
        Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, a).into()
    }

    #[test]
    fn direction_for_both_address_families() {
        let client = ClientAddrs::new([v4(1), v6(1)]);
        assert_eq!(client.direction(v4(1), v4(2)), Direction::ClientToWan);
        assert_eq!(client.direction(v4(2), v4(1)), Direction::WanToClient);
        assert_eq!(client.direction(v6(1), v6(2)), Direction::ClientToWan);
        assert_eq!(client.direction(v6(2), v6(1)), Direction::WanToClient);
        assert_eq!(client.direction(v6(2), v6(3)), Direction::Unknown);
        assert_eq!(client.direction(v4(2), v4(3)), Direction::Unknown);
    }

    #[test]
    fn multiple_addresses_per_family() {
        // e.g. a host with a stable and a temporary (privacy) IPv6 address
        let client = ClientAddrs::new([v6(1), v6(9)]);
        assert_eq!(client.direction(v6(9), v6(2)), Direction::ClientToWan);
        assert_eq!(client.direction(v6(2), v6(1)), Direction::WanToClient);
        assert_eq!(client.direction(v4(1), v4(2)), Direction::Unknown);
    }

    #[test]
    fn empty_is_always_unknown() {
        let client = ClientAddrs::default();
        assert!(client.is_empty());
        assert_eq!(client.direction(v4(1), v4(2)), Direction::Unknown);
    }
}
