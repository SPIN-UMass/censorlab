use super::{Action, Censor};
use crate::arp::ArpCache;
use crate::censor::{HandleIpcError, IpPair};
use crate::delay::DelayQueue;
use clap::Parser;
use mac_address::MacAddressError;
use nfq::{Message, Queue, Verdict};
use ort::Error as OrtError;
use procfs::ProcError;
use smoltcp::phy::{Device, Medium, RawSocket, TxToken};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::time::Instant;
use smoltcp::wire::{Error as SmoltcpError, EthernetAddress, IpAddress, TcpSeqNumber};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant as StdInstant;
use thiserror::Error;
use tracing::{error, info, trace, warn};

/// Default IPTables table
const IPTABLES_TABLE_DEFAULT: &str = "raw";
/// Default IPTable chain for inbound packets
const IPTABLES_CHAIN_IN_DEFAULT: &str = "PREROUTING";
/// Default IPTable chain for outbound packets
const IPTABLES_CHAIN_OUT_DEFAULT: &str = "OUTPUT";
/// Comment string to use to identify any rules previously placed by censorlab
const IPTABLES_COMMENT: &str = "CENSORLAB NFQ TAP";

#[derive(Debug, Parser)]
pub struct Args {
    /// Ip address considered the "client"
    ///
    /// Without 2 interfaces, we don't know how to determine the direction of traffic
    /// We need to arbitrarily choose a "client ip" that is used to calculate direction
    /// Anything coming to this IP is wan->cient. Anything from this IP is client->wan
    #[clap(long)]
    pub client_ip: Option<IpAddr>,
    /// what to do with traffic that doesn't have a direction
    /// by default we have to ignore it because the model relies on direction info
    #[clap(long, default_value = "ignore")]
    pub no_dir_action: Action,
    /// IPTables arguments
    #[clap(flatten)]
    pub iptables: IpTablesArgs,
    /// Interface to send packets to (defaults to first interface that can send AF_INET packets
    pub interface: Option<String>,
}
/// IPTables data
#[derive(Clone, Debug, Parser)]
pub struct IpTablesArgs {
    /// The IPTables table to intercept at
    #[clap(long = "iptables-table", default_value = IPTABLES_TABLE_DEFAULT)]
    pub table: String,
    /// The IPTables chain to use for inbound packets
    #[clap(long = "iptables-chain-in", default_value = IPTABLES_CHAIN_IN_DEFAULT)]
    pub chain_in: String,
    /// The IPTables chain to use for outbound packets
    #[clap(long = "iptables-chain-out", default_value = IPTABLES_CHAIN_OUT_DEFAULT)]
    pub chain_out: String,
    /// Which NFQUEUE queue number for inbound packets
    #[clap(long, default_value_t = 0)]
    pub queue_num_in: u16,
    /// Which NFQUEUE queue number for outbound packets
    #[clap(long, default_value_t = 1)]
    pub queue_num_out: u16,
    /// Force iptables rule insertion even if conflicting NFQUEUE rules are found
    #[clap(long = "force-iptables")]
    pub force: bool,
}
impl IpTablesArgs {
    fn rule_inbound(&self) -> IpTablesRule {
        IpTablesRule {
            table: self.table.clone(),
            chain: self.chain_in.clone(),
            queue_num: self.queue_num_in,
        }
    }
    fn rule_outbound(&self) -> IpTablesRule {
        IpTablesRule {
            table: self.table.clone(),
            chain: self.chain_out.clone(),
            queue_num: self.queue_num_out,
        }
    }
}

#[derive(Clone, Debug)]
pub struct IpTablesRule {
    /// The IPTables table to intercept at
    pub table: String,
    /// The IPTables chain to use
    pub chain: String,
    /// Which NFQUEUE queue number
    pub queue_num: u16,
}

impl fmt::Display for IpTablesRule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "-t {} -A {} {}",
            self.table,
            self.chain,
            self.rule_string()
        )
    }
}
impl IpTablesRule {
    /// Produce iptables rule from the given arguments
    fn rule_string(&self) -> String {
        format!(
            "-j NFQUEUE --queue-num {} -m comment --comment \"{}\"",
            self.queue_num, IPTABLES_COMMENT
        )
    }
    /// Activate the IPTables rule
    ///
    /// NOTE: upon dropping the object produced by this function
    /// its Drop implementation will attempt to remove the rule
    fn activate(&self, is_ipv6: bool, force: bool) -> Result<IpTablesRuleActivated, IpTablesError> {
        // Get a handle on iptables using the given ipv6 preferences
        let iptables = iptables::new(is_ipv6)?;
        // Start with sanity checks: does the chain exist?
        if !iptables.chain_exists(&self.table, &self.chain)? {
            return Err(IpTablesError::IpTablesChainDoesNotExist);
        }
        // NOTE: Because NFQUEUE is a virtual target and not a table
        // we do not need to check for its existence
        // however, it may not exist. On Linux, the xt_NFQUEUE module determines this
        // It may be helpful to pre-check for this

        // After verifying iptables and our desired table/chain exist
        // We can start looking at rules
        // Get the string for the rule
        let rule = &(self.rule_string());
        // Delete any instances of the current rule we plan to add,
        // just for sanity sake
        if iptables.exists(&self.table, &self.chain, rule)? {
            warn!(
                "Found a previous instance of the rule ({self}). Deleting it and all duplicates."
            );
            iptables.delete_all(&self.table, &self.chain, rule)?;
        }
        // Scan for other NFQUEUE rules using the same queue number that
        // don't belong to CensorLab (identified by our comment marker)
        let queue_num_str = format!("--queue-num {}", self.queue_num);
        let mut conflicting_rules = false;
        for existing_rule in iptables.list(&self.table, &self.chain)? {
            if existing_rule.contains(&queue_num_str) && !existing_rule.contains(IPTABLES_COMMENT) {
                if force {
                    warn!("Found potentially conflicting rule: ({existing_rule}), continuing due to --force-iptables");
                } else {
                    error!("Found potentially conflicting rule: ({existing_rule}). Use --force-iptables to override");
                    conflicting_rules = true;
                }
            }
        }
        if conflicting_rules {
            return Err(IpTablesError::IpTablesConflictingRule);
        }
        // Finally, add the NFQ rule
        warn!(
            "Adding the rule: ({self}). \
               This will affect all network connectivity. \
               If you rely on SSH or other networked utilities to \
               access this system, please exercise caution"
        );
        iptables.append_unique(&self.table, &self.chain, rule)?;

        // Wrap as an activated rule, caching the rule string for drop
        Ok(IpTablesRuleActivated {
            rule_string: self.rule_string(),
            rule: self.clone(),
            iptables,
        })
    }
}
#[derive(Debug, thiserror::Error)]
pub enum IpTablesError {
    #[error("Error interfacing with IPTables: {0}")]
    IpTables(#[from] Box<dyn std::error::Error>),
    #[error("Chain does not exist in the given table")]
    IpTablesChainDoesNotExist,
    #[error("Conflicting rules found in iptables. Will not proceed for safety.")]
    IpTablesConflictingRule,
}
/// Activated iptables rule
///
/// This struct is created after a rule has been inserted into iptables
/// Upon drop, it will attempt to remove itself
struct IpTablesRuleActivated {
    /// The rule that has been activated
    rule: IpTablesRule,
    /// Cached rule string for use in drop
    rule_string: String,
    /// The iptables handle (may be different for ipv6 vs ipv4
    iptables: iptables::IPTables,
}

impl Drop for IpTablesRuleActivated {
    /// This function is responsible for removing the
    /// rule from iptables upon drop
    fn drop(&mut self) {
        let rule = &self.rule_string;
        // Log what is happening
        info!(
            "The iptables({}) rule ({}) will now be removed, including any duplicates.",
            self.iptables.cmd, rule
        );
        // Remove the rule
        // drop cannot return an error so this function must be infallible
        if let Err(err) = self
            .iptables
            .delete_all(&self.rule.table, &self.rule.chain, rule)
        {
            error!("Error removing the rule: {err}. Please manually inspect iptables({}), particularly the {} table in the {} chain.", self.iptables.cmd, self.rule.table, self.rule.chain);
        }
    }
}
/// Context for the NFQ censor, providing network identity.
pub struct Context {
    /// Stored for potential future use in RST packet construction.
    #[allow(dead_code)]
    pub client_mac: EthernetAddress,
    pub client_ip: IpAddress,
    /// Stored for potential future use in direction-less traffic handling.
    #[allow(dead_code)]
    pub no_dir_action: Action,
}

/// Which netfilter queue a held message came from (its verdict must go back there).
#[derive(Clone, Copy)]
enum QueueSide {
    In,
    Out,
}

impl Censor {
    /// Run the censor in NFQ mode
    pub async fn run_nfq(mut self, mut args: Args) -> Result<(), NfqModeError> {
        // Here, we need to resolve 3 things
        // 1. the network interface to use
        // 2. the MAC of that interface
        // 3. the IP of that interface
        // We want to get these, so store them if we stumble upon them
        let mut client_addrs = None;

        // Start by looking for the default route
        // This has the secondary effect of finding the default interface if not given
        let mut default_route_ip = None;
        // Load up the list of routes
        for route in procfs::net::route().map_err(NfqModeError::OpenRoutes)? {
            // If a specific interface was requested, prioritize that
            if args.interface.as_ref() == Some(&route.iface) ||
                // If a specific interface is not requested, look for a default route
                route.destination == Ipv4Addr::new(0, 0, 0, 0)
            {
                args.interface = Some(route.iface);
                default_route_ip = Some(route.gateway);
                break;
            }
        }
        // Default route IP and interface name should be definitive at this point
        let default_route_ip = default_route_ip.ok_or(NfqModeError::DefaultRouteNotFound)?;
        let interface_name = args.interface.ok_or(NfqModeError::NoInterfaceFound)?;
        // Scan the arp table for the mac for our default route ip
        let mut default_route_mac = None;
        for arp_entry in procfs::net::arp().map_err(NfqModeError::OpenArp)? {
            if arp_entry.ip_address == default_route_ip && arp_entry.device == interface_name {
                default_route_mac = arp_entry.hw_address;
            }
        }

        // Initialize an arp cache. This is used for resolving IPs to arp
        let mut arp_cache = ArpCache::default();
        // Iterate over interfaces, and store the client mac/ip for our preferred interface
        for system_if in if_addrs::get_if_addrs().map_err(NfqModeError::Interface)? {
            // Skip loopback
            if system_if.is_loopback() {
                continue;
            }
            // Get the mac address of the interface
            if let Some(mac) = mac_address::mac_address_by_name(&system_if.name)? {
                let mac = EthernetAddress(mac.bytes());
                // Store that info in the arp cache
                arp_cache.insert(system_if.ip().into(), mac);
                // Store the addresses if they are the same
                if interface_name == system_if.name && client_addrs.is_none() {
                    client_addrs = Some((mac, system_if.ip().into()));
                }
            }
        }
        // At this point, client mac and ip should be definite
        let (client_mac, own_ip) = client_addrs.ok_or(NfqModeError::InterfaceHasNoMac)?;
        // Direction is computed relative to `--client-ip` when given (censor in
        // the path between a client and the WAN); otherwise relative to our own
        // address (censor running on the client host itself).
        let client_ip: IpAddress = match args.client_ip {
            Some(ip) => ip.into(),
            None => own_ip,
        };
        if args.client_ip.is_some() {
            info!("Computing traffic direction relative to client {client_ip}");
        }

        // Open the interface as an IP raw socket
        trace!("Opening raw socket for {}", interface_name);
        let mut interface = RawSocket::new(&interface_name, Medium::Ethernet)
            .map_err(NfqModeError::RawSocketOpen)?;
        info!("Opened raw socket for {}", interface_name);
        // Create our NFQ context
        let mut context_nfq = Context {
            client_mac,
            client_ip,
            no_dir_action: args.no_dir_action.clone(),
        };
        // Convert context to generic
        let mut context = (&mut context_nfq).into();
        // Start accessing the netfilter queue
        trace!("Opening netfilter queues");
        let mut queue_in = Queue::open().map_err(NfqModeError::NfqOpen)?;
        queue_in.set_nonblocking(true);
        queue_in
            .bind(args.iptables.queue_num_in)
            .map_err(NfqModeError::NfqBind)?;
        let mut queue_out = Queue::open().map_err(NfqModeError::NfqOpen)?;
        queue_out.set_nonblocking(true);
        queue_out
            .bind(args.iptables.queue_num_out)
            .map_err(NfqModeError::NfqBind)?;
        info!("Opened netfilter queues");
        // Create inbound and outbound iptables rules
        let rule_in = args.iptables.rule_inbound();
        let rule_out = args.iptables.rule_outbound();
        // Activate the iptables rules for both IPv4 and IPv6.
        // NOTE: In this section, iptables rules are initialized that will
        //       disrupt connectivity of the system, until we begin processing packets.
        // Upon drop (e.g. if this function has an error) the rules will be removed.
        // At least one of IPv4/IPv6 must succeed per direction.
        let force = args.iptables.force;
        // Activate rules; at least one of IPv4/IPv6 must succeed per direction.
        // Keep activated rules alive so their Drop impls clean up on exit.
        let rule_in_ipv4 = rule_in.activate(false, force);
        let rule_in_ipv6 = rule_in.activate(true, force);
        match (&rule_in_ipv4, &rule_in_ipv6) {
            (Err(_), Err(e)) => return Err(NfqModeError::IpTables(IpTablesError::IpTables(e.to_string().into()))),
            (Err(e), _) => warn!("Could not activate inbound IPv4 iptables rule: {e}"),
            (_, Err(e)) => warn!("Could not activate inbound IPv6 iptables rule: {e}"),
            _ => {}
        }
        let rule_out_ipv4 = rule_out.activate(false, force);
        let rule_out_ipv6 = rule_out.activate(true, force);
        match (&rule_out_ipv4, &rule_out_ipv6) {
            (Err(_), Err(e)) => return Err(NfqModeError::IpTables(IpTablesError::IpTables(e.to_string().into()))),
            (Err(e), _) => warn!("Could not activate outbound IPv4 iptables rule: {e}"),
            (_, Err(e)) => warn!("Could not activate outbound IPv6 iptables rule: {e}"),
            _ => {}
        }
        // Start processing packets
        info!("Starting packet loop");
        let mut packet_num = 0;
        // Packets held by the delay action. We keep the NFQ message itself and
        // only issue its Accept verdict once the deadline passes, so the kernel
        // resumes the packet exactly where it was intercepted (correct
        // direction, routing and link layer) without us re-crafting it.
        let mut delayed: DelayQueue<(QueueSide, Message)> = DelayQueue::new();
        loop {
            // Handle any incoming ipc requests
            match self.handle_ipc() {
                Ok(()) => {}
                Err(HandleIpcError::Shutdown) => break,
                Err(err) => return Err(err.into()),
            }
            // Release delayed packets whose deadline has passed
            let now = StdInstant::now();
            while let Some((side, mut msg)) = delayed.pop_due(now) {
                trace!("Releasing delayed packet");
                msg.set_verdict(Verdict::Accept);
                let queue = match side {
                    QueueSide::In => &mut queue_in,
                    QueueSide::Out => &mut queue_out,
                };
                queue.verdict(msg).map_err(NfqModeError::Nfq)?;
            }
            // Handle each queue
            for (side, queue) in [
                (QueueSide::In, &mut queue_in),
                (QueueSide::Out, &mut queue_out),
            ] {
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
                                is_ack,
                                payload_len,
                            } => {
                                // Time for misery
                                let mut src_mac = [0; 6];
                                let mut dst_mac = [0; 6];
                                if let IpPair::V4 { src, dst } = ips {
                                    // Resolve src mac addr
                                    if let Some(mac) = arp_cache
                                        .resolve(src.into())
                                        .map_err(NfqModeError::OpenArp)?
                                    {
                                        src_mac = mac.0;
                                    } else if IpAddress::from(src) != client_ip {
                                        if let Some(mac) = default_route_mac {
                                            src_mac = mac;
                                        }
                                    }
                                    // Resolve dst mac addr
                                    if let Some(mac) = arp_cache
                                        .resolve(dst.into())
                                        .map_err(NfqModeError::OpenArp)?
                                    {
                                        dst_mac = mac.0;
                                    } else if IpAddress::from(dst) != client_ip {
                                        if let Some(mac) = default_route_mac {
                                            dst_mac = mac;
                                        }
                                    }
                                }
                                trace!("Sending bidirectional reset for {:?}<->{:?}, ips={:?}, ports={},{}, seq={},ack={}", src_mac, dst_mac, ips, src_port, dst_port, seq, ack);
                                // Send resets, then accept the packet
                                let (client_reset, server_reset) = Self::craft_resets(
                                    client_mac.0,
                                    src_mac,
                                    dst_mac,
                                    ips,
                                    ipid,
                                    src_port,
                                    dst_port,
                                    ack,
                                    seq,
                                    payload_len,
                                    is_ack,
                                )?;
                                // Send the resets
                                for _ in 0..self.reset_repeat {
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
                            Action::Inject {
                                src_mac: _,
                                dst_mac: _,
                                ips: inject_ips,
                                src_port: inject_src_port,
                                dst_port: inject_dst_port,
                                payload: inject_payload,
                            } => {
                                // Resolve MAC addresses for the injection packet
                                let mut inj_src_mac = [0u8; 6];
                                let mut inj_dst_mac = [0u8; 6];
                                if let IpPair::V4 { src, dst } = inject_ips {
                                    if let Some(mac) = arp_cache
                                        .resolve(src.into())
                                        .map_err(NfqModeError::OpenArp)?
                                    {
                                        inj_src_mac = mac.0;
                                    } else if IpAddress::from(src) != client_ip {
                                        if let Some(mac) = default_route_mac {
                                            inj_src_mac = mac;
                                        }
                                    }
                                    if let Some(mac) = arp_cache
                                        .resolve(dst.into())
                                        .map_err(NfqModeError::OpenArp)?
                                    {
                                        inj_dst_mac = mac.0;
                                    } else if IpAddress::from(dst) != client_ip {
                                        if let Some(mac) = default_route_mac {
                                            inj_dst_mac = mac;
                                        }
                                    }
                                }
                                // Construct and send the injection packet
                                // Ethernet source is always our own MAC (see craft_resets)
                                let _ = inj_src_mac;
                                let inject_packet = crate::transport::construct_udp_inject(
                                    client_mac,
                                    EthernetAddress(inj_dst_mac),
                                    inject_ips,
                                    inject_src_port,
                                    inject_dst_port,
                                    &inject_payload,
                                )?;
                                if let Some(tx_token) =
                                    interface.transmit(SmoltcpInstant::from_micros_const(0))
                                {
                                    tx_token.consume(inject_packet.len(), |tx_buf| {
                                        tx_buf.copy_from_slice(&inject_packet);
                                        Ok::<(), SmoltcpError>(())
                                    })?;
                                }
                                // Accept the original packet (race the real server, like GFW)
                                msg.set_verdict(Verdict::Accept);
                                queue.verdict(msg).map_err(NfqModeError::Nfq)?;
                            }
                            Action::Delay(until) => {
                                // Hold the packet; its verdict is issued once `until` passes
                                trace!("Delaying packet");
                                delayed.push(until, (side, msg));
                            }
                            Action::Rewrite(rewrite) => {
                                // Forward a mutated copy of the packet
                                let mut payload = msg.get_payload().to_vec();
                                if rewrite.apply_ip(&mut payload) {
                                    msg.set_payload(payload);
                                } else {
                                    warn!("Rewrite action on unparseable packet: forwarding unchanged");
                                }
                                msg.set_verdict(Verdict::Accept);
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
        }
        // Release any still-held packets rather than letting the kernel drop them on unbind
        while let Some((side, mut msg)) = delayed.pop_any() {
            msg.set_verdict(Verdict::Accept);
            let queue = match side {
                QueueSide::In => &mut queue_in,
                QueueSide::Out => &mut queue_out,
            };
            if let Err(err) = queue.verdict(msg) {
                warn!("Failed to release delayed packet on shutdown: {err}");
            }
        }
        // We initialized firewall rules after binding the queue, so we drop them
        // before the queue is unbound
        drop(rule_in_ipv4);
        drop(rule_in_ipv6);
        drop(rule_out_ipv4);
        drop(rule_out_ipv6);
        // Unbind the queue
        queue_in
            .unbind(args.iptables.queue_num_in)
            .map_err(NfqModeError::Nfq)?;
        queue_out
            .unbind(args.iptables.queue_num_out)
            .map_err(NfqModeError::Nfq)?;
        Ok(())
    }
    /// Build the two RST frames for an intercepted segment `src -> dst`.
    ///
    /// Both frames leave *our* interface, so their Ethernet source is our own
    /// MAC (`own_mac`); only the IP/TCP layers impersonate the peers.  Spoofing
    /// the peers' MACs at layer 2 poisons the FDB of any learning bridge we are
    /// attached to (it would move the peer's MAC onto our port) and stalls the
    /// very connections we are trying to reset.  `src_host_mac`/`dst_host_mac`
    /// are the next-hop MACs for the original source and destination.
    fn craft_resets(
        own_mac: [u8; 6],
        src_host_mac: [u8; 6],
        dst_host_mac: [u8; 6],
        ips: IpPair,
        ipid: Option<u16>,
        src_port: u16,
        dst_port: u16,
        ack: TcpSeqNumber,
        seq: TcpSeqNumber,
        payload_len: usize,
        is_ack: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), smoltcp::wire::Error> {
        // Intercepted packet goes src -> dst with seq and ack fields.
        // For a RST to be accepted, its seq must be within the recipient's receive window.
        //
        // Reset to packet source (client_reset with swapped IPs):
        // - seq should be what the source expects to receive = intercepted ack
        // - ack can acknowledge what they sent = intercepted seq + payload_len
        let client_reset = crate::transport::construct_reset(
            EthernetAddress(own_mac),
            EthernetAddress(src_host_mac),
            ips.swap(),
            ipid,
            dst_port, // src port (swapped)
            src_port, // dst port (swapped)
            // ack: acknowledge what they sent
            if is_ack {
                seq + payload_len
            } else {
                TcpSeqNumber(0)
            },
            // seq: what they expect to receive = their ack value
            ack,
        )?;
        // Reset to packet destination (server_reset with original IPs):
        // - seq should be what the dest expects = intercepted seq + payload_len
        //   (since the original packet is accepted, dest will have processed it)
        // - ack = 0 is fine for RST
        let server_reset = crate::transport::construct_reset(
            EthernetAddress(own_mac),
            EthernetAddress(dst_host_mac),
            ips,
            ipid,
            src_port,          // src port
            dst_port,          // dst port
            TcpSeqNumber(0),   // ack
            seq + payload_len, // seq: what they expect after receiving the packet
        )?;

        Ok((client_reset, server_reset))
    }
}

/// Error running in wire mode
#[derive(Debug, Error)]
pub enum NfqModeError {
    #[error("Error interfacing with IPTables: {0}")]
    IpTables(IpTablesError),
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
}

#[cfg(test)]
mod reset_frame_tests {
    use super::*;
    use smoltcp::wire::{EthernetFrame, Ipv4Address};

    #[test]
    fn resets_use_our_mac_as_ethernet_source() {
        let own = [0x02, 0xCE, 0x00, 0x00, 0x00, 0x01];
        let client = [0xAA, 0x00, 0x00, 0x00, 0x00, 0x01];
        let server = [0xBB, 0x00, 0x00, 0x00, 0x00, 0x02];
        let ips = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        let (to_client, to_server) = Censor::craft_resets(own, client, server, ips, Some(1), 40000, 443,
                          TcpSeqNumber(2000), TcpSeqNumber(1000), 100, true)
            .unwrap();
        let f1 = EthernetFrame::new_checked(&to_client[..]).unwrap();
        let f2 = EthernetFrame::new_checked(&to_server[..]).unwrap();
        assert_eq!(f1.src_addr(), EthernetAddress(own));
        assert_eq!(f1.dst_addr(), EthernetAddress(client));
        assert_eq!(f2.src_addr(), EthernetAddress(own));
        assert_eq!(f2.dst_addr(), EthernetAddress(server));
    }
}
