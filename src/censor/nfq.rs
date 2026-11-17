use super::{Action, Censor, Rewrite};
use crate::censor::{ClientAddrs, HandleIpcError, IpPair};
use crate::delay::DelayQueue;
use crate::fragment::{Fragment, Normalizer, Outcome};
use crate::inject::{InjectError, RawIpInjector};
use crate::route;
use clap::Parser;
use nfq::{Message, Queue, Verdict};
use ort::Error as OrtError;
use procfs::ProcError;
use smoltcp::wire::{EthernetAddress, EthernetFrame, IpAddress, TcpSeqNumber};
use std::fmt;
use std::io;
use std::net::IpAddr;
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
    ///
    /// May be repeated or comma-separated (e.g. `--client-ip 10.0.0.2,2001:db8::2`)
    /// so both IPv4 and IPv6 traffic get a direction.  Defaults to every address
    /// of the chosen interface (censor running on the client host itself).
    #[clap(long, value_delimiter = ',')]
    pub client_ip: Vec<IpAddr>,
    /// what to do with traffic that doesn't have a direction
    /// by default we have to ignore it because the model relies on direction info
    #[clap(long, default_value = "ignore")]
    pub no_dir_action: Action,
    /// IPTables arguments
    #[clap(flatten)]
    pub iptables: IpTablesArgs,
    /// Interface whose addresses are the default client addresses (defaults to the
    /// interface of the lowest-metric IPv4 default route, else the IPv6 one).
    /// Injected packets are routed by the kernel, not sent on this interface.
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
            // Packets we inject ourselves carry INJECT_MARK and must not be
            // queued back to us
            "-m mark ! --mark {:#x} -j NFQUEUE --queue-num {} -m comment --comment \"{}\"",
            crate::inject::INJECT_MARK, self.queue_num, IPTABLES_COMMENT
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
    pub client: ClientAddrs,
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

/// Strip the Ethernet header from a frame built by `construct_reset` /
/// `construct_udp_inject`, leaving the IP packet that is injected.
fn l3_payload(frame: &[u8]) -> Option<&[u8]> {
    EthernetFrame::new_checked(frame).ok().map(|f| f.payload())
}

/// Inject a frame's IP packet, logging (not propagating) failures: a failed
/// injection must not stop the censor (fail-open, like packet processing).
fn inject_frame(injector: &RawIpInjector, frame: &[u8]) {
    let result = match l3_payload(frame) {
        Some(packet) => injector.send(packet),
        None => Err(InjectError::Malformed),
    };
    if let Err(err) = result {
        warn!("Failed to inject packet: {err}");
    }
}

impl Censor {
    /// Run the censor in NFQ mode
    pub async fn run_nfq(mut self, args: Args) -> Result<(), NfqModeError> {
        // Pick the interface: the requested one, else that of the default route
        let v4_defaults =
            route::ipv4_default_routes(&procfs::net::route().map_err(NfqModeError::OpenRoutes)?);
        let v6_defaults = match std::fs::read_to_string("/proc/net/ipv6_route") {
            Ok(contents) => route::ipv6_default_routes(&contents)?,
            // IPv6 disabled
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(NfqModeError::OpenIpv6Routes(err)),
        };
        let interface_name =
            route::select_interface(args.interface.as_deref(), &v4_defaults, &v6_defaults)?;
        info!("Using interface {interface_name}");

        // Every address of the chosen interface (IPv4 and IPv6)
        let own_addrs: Vec<IpAddress> = if_addrs::get_if_addrs()
            .map_err(NfqModeError::Interface)?
            .into_iter()
            .filter(|system_if| system_if.name == interface_name)
            .map(|system_if| system_if.ip().into())
            .collect();
        if own_addrs.is_empty() {
            return Err(NfqModeError::InterfaceHasNoAddress(interface_name));
        }
        // Direction is computed relative to `--client-ip` when given (censor in
        // the path between a client and the WAN); otherwise relative to every
        // address of our interface (censor running on the client host itself).
        let client = if args.client_ip.is_empty() {
            ClientAddrs::new(own_addrs)
        } else {
            ClientAddrs::new(args.client_ip.iter().map(|ip| IpAddress::from(*ip)))
        };
        info!("Computing traffic direction relative to client address(es): {client}");

        // Injected packets go through raw IP sockets so the kernel does
        // routing and ARP/neighbour discovery (see crate::inject)
        let ifindex = match std::ffi::CString::new(interface_name.clone()) {
            // SAFETY: name is a valid NUL-terminated string for the call
            Ok(name) => unsafe { libc::if_nametoindex(name.as_ptr()) },
            Err(_) => 0,
        };
        let injector = RawIpInjector::new(ifindex).map_err(NfqModeError::RawSocketOpen)?;
        // Create our NFQ context
        let mut context_nfq = Context {
            client,
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
        // Fragments held by `[ip.fragments] mode = "Buffer"`. Like delayed packets,
        // the NFQ messages themselves are held until their verdict is known. This
        // only sees fragments the kernel has not already reassembled: with
        // connection tracking loaded, netfilter defragments before queueing.
        let mut fragments: Option<Normalizer<(QueueSide, Message)>> = self.fragments.map(Normalizer::new);
        let mut fragment_verdicts: Outcome<(QueueSide, Message)> = Outcome::default();
        let start = StdInstant::now();
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
            // Issue the verdicts of buffered fragments: complete packets are
            // released with the first fragment's TTL, discarded ones dropped
            if let Some(fragments) = &mut fragments {
                fragment_verdicts.drop.extend(fragments.expire(start.elapsed()));
            }
            for released in fragment_verdicts.forward.drain(..) {
                let (side, mut msg) = released.item;
                if released.ttl.is_some() {
                    let mut payload = msg.get_payload().to_vec();
                    if (Rewrite { ttl: released.ttl }).apply_ip(&mut payload) {
                        msg.set_payload(payload);
                    }
                }
                msg.set_verdict(Verdict::Accept);
                let queue = match side {
                    QueueSide::In => &mut queue_in,
                    QueueSide::Out => &mut queue_out,
                };
                queue.verdict(msg).map_err(NfqModeError::Nfq)?;
            }
            for (side, mut msg) in fragment_verdicts.drop.drain(..) {
                trace!("Dropping buffered fragment");
                msg.set_verdict(Verdict::Drop);
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
                                // Fragments are held until their packet is complete
                                let fragment = fragments
                                    .as_mut()
                                    .and_then(|fragments| Some((fragments, Fragment::parse(msg.get_payload())?)));
                                match fragment {
                                    Some((fragments, fragment)) => {
                                        trace!("Buffering fragment");
                                        let outcome = fragments.push(start.elapsed(), fragment, (side, msg));
                                        fragment_verdicts.forward.extend(outcome.forward);
                                        fragment_verdicts.drop.extend(outcome.drop);
                                    }
                                    None => {
                                        trace!("Forwarding packet normally");
                                        msg.set_verdict(Verdict::Accept);
                                        queue.verdict(msg).map_err(NfqModeError::Nfq)?;
                                    }
                                }
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
                                seg_len,
                            } => {
                                trace!("Sending bidirectional reset for ips={:?}, ports={},{}, seq={},ack={}", ips, src_port, dst_port, seq, ack);
                                // The kernel does layer 2 for injected packets, so the
                                // Ethernet addresses of the crafted frames are unused
                                let (client_reset, server_reset) = Self::craft_resets(
                                    [0; 6],
                                    [0; 6],
                                    [0; 6],
                                    ips,
                                    ipid,
                                    src_port,
                                    dst_port,
                                    ack,
                                    seq,
                                    seg_len,
                                    is_ack,
                                )?;
                                // Send the resets
                                for _ in 0..self.reset_repeat {
                                    inject_frame(&injector, &client_reset);
                                    inject_frame(&injector, &server_reset);
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
                                // Construct and send the injection packet (the kernel
                                // does layer 2, see crate::inject)
                                let inject_packet = crate::transport::construct_udp_inject(
                                    EthernetAddress([0; 6]),
                                    EthernetAddress([0; 6]),
                                    inject_ips,
                                    inject_src_port,
                                    inject_dst_port,
                                    &inject_payload,
                                )?;
                                inject_frame(&injector, &inject_packet);
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
        // The same goes for buffered fragments and any verdicts not yet issued
        let held_fragments = fragments.iter_mut().flat_map(|fragments| fragments.drain());
        let pending = std::mem::take(&mut fragment_verdicts);
        for (side, mut msg) in held_fragments
            .chain(pending.forward.into_iter().map(|released| released.item))
            .chain(pending.drop)
        {
            msg.set_verdict(Verdict::Accept);
            let queue = match side {
                QueueSide::In => &mut queue_in,
                QueueSide::Out => &mut queue_out,
            };
            if let Err(err) = queue.verdict(msg) {
                warn!("Failed to release buffered fragment on shutdown: {err}");
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
    pub(super) fn craft_resets(
        own_mac: [u8; 6],
        src_host_mac: [u8; 6],
        dst_host_mac: [u8; 6],
        ips: IpPair,
        ipid: Option<u16>,
        src_port: u16,
        dst_port: u16,
        ack: TcpSeqNumber,
        seq: TcpSeqNumber,
        seg_len: usize,
        is_ack: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), smoltcp::wire::Error> {
        // The intercepted segment goes src -> dst with SEG.SEQ = `seq`, SEG.ACK = `ack`
        // (valid only if `is_ack`) and SEG.LEN = `seg_len` (payload + SYN + FIN).
        // A RST is accepted only if its seq is in the recipient's receive window.
        let next_seq = seq + seg_len;
        // Reset to packet source (swapped IPs), per RFC 9293 section 3.10.7.1:
        // - if the segment had an ACK, the source expects to receive SEG.ACK next;
        // - otherwise (e.g. a SYN, sender in SYN-SENT) there is no usable seq, so
        //   <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>, whose ACK makes it acceptable.
        // In both cases the RST acknowledges everything the source sent.
        let client_reset = crate::transport::construct_reset(
            EthernetAddress(own_mac),
            EthernetAddress(src_host_mac),
            ips.swap(),
            ipid,
            dst_port, // src port (swapped)
            src_port, // dst port (swapped)
            Some(next_seq),
            if is_ack { ack } else { TcpSeqNumber(0) },
        )?;
        // Reset to packet destination (original IPs): the original segment is
        // accepted, so the destination next expects SEG.SEQ + SEG.LEN. We know nothing
        // the destination sent, so this is a bare RST with no ACK.
        let server_reset = crate::transport::construct_reset(
            EthernetAddress(own_mac),
            EthernetAddress(dst_host_mac),
            ips,
            ipid,
            src_port,
            dst_port,
            None,
            next_seq,
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
    #[error("Interface {0} does not exist or has no IP address")]
    InterfaceHasNoAddress(String),
    #[error("Failed to choose an interface: {0}")]
    SelectInterface(#[from] route::SelectInterfaceError),
    #[error("Failed to open routing table: {0}")]
    OpenRoutes(ProcError),
    #[error("Failed to open IPv6 routing table: {0}")]
    OpenIpv6Routes(io::Error),
    #[error("Failed to parse IPv6 routing table: {0}")]
    Ipv6Routes(#[from] route::Ipv6RouteParseError),
    #[error("Failed to open raw IP sockets for injection: {0}")]
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

    /// (seq, ack, ACK flag, RST flag) of a crafted IPv4 reset frame.
    fn tcp_fields(frame: &[u8]) -> (TcpSeqNumber, TcpSeqNumber, bool, bool) {
        use smoltcp::wire::{Ipv4Packet, TcpPacket};
        let eth = EthernetFrame::new_checked(frame).unwrap();
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        (tcp.seq_number(), tcp.ack_number(), tcp.ack(), tcp.rst())
    }

    fn resets(seq: i32, ack: i32, seg_len: usize, is_ack: bool) -> (Vec<u8>, Vec<u8>) {
        let ips = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        Censor::craft_resets([2; 6], [3; 6], [4; 6], ips, None, 40000, 443,
                             TcpSeqNumber(ack), TcpSeqNumber(seq), seg_len, is_ack)
            .unwrap()
    }

    #[test]
    fn resets_for_data_segment_land_in_both_windows() {
        // Client sent 100 bytes at seq 1000, acknowledging the server up to 5000
        let (to_client, to_server) = resets(1000, 5000, 100, true);
        // To the sender: <SEQ=SEG.ACK>, acknowledging what it sent
        assert_eq!(tcp_fields(&to_client), (TcpSeqNumber(5000), TcpSeqNumber(1100), true, true));
        // To the receiver: the next sequence number it expects from the sender
        let (seq, _, ack_flag, rst) = tcp_fields(&to_server);
        assert_eq!((seq, ack_flag, rst), (TcpSeqNumber(1100), false, true));
    }

    #[test]
    fn resets_for_syn_follow_rfc793() {
        // A SYN has no ACK and occupies one sequence number
        let (to_client, to_server) = resets(7000, 0, 1, false);
        // To a SYN-SENT client: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        assert_eq!(tcp_fields(&to_client), (TcpSeqNumber(0), TcpSeqNumber(7001), true, true));
        // To the server, which has seen the SYN and expects ISS+1
        let (seq, _, ack_flag, rst) = tcp_fields(&to_server);
        assert_eq!((seq, ack_flag, rst), (TcpSeqNumber(7001), false, true));
    }
}

#[cfg(test)]
mod args_tests {
    use super::*;

    #[test]
    fn client_ip_repeated_or_comma_separated() {
        let a = Args::try_parse_from([
            "nfq",
            "--client-ip",
            "10.0.0.2",
            "--client-ip",
            "2001:db8::2",
        ])
        .unwrap();
        let b = Args::try_parse_from(["nfq", "--client-ip", "10.0.0.2,2001:db8::2"]).unwrap();
        assert_eq!(a.client_ip, b.client_ip);
        assert_eq!(a.client_ip.len(), 2);
        assert!(Args::try_parse_from(["nfq"]).unwrap().client_ip.is_empty());
    }

    #[test]
    fn nfqueue_rule_skips_our_injected_packets() {
        let rule = IpTablesRule {
            table: "raw".into(),
            chain: "OUTPUT".into(),
            queue_num: 1,
        };
        let s = rule.rule_string();
        assert!(
            s.contains(&format!("-m mark ! --mark {:#x}", crate::inject::INJECT_MARK)),
            "{s}"
        );
        // The match must come before the jump target
        assert!(s.find("--mark").unwrap() < s.find("-j NFQUEUE").unwrap());
    }

    #[test]
    fn resets_are_valid_ip_packets_after_stripping_l2() {
        let ips = IpPair::V6 {
            src: smoltcp::wire::Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            dst: smoltcp::wire::Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        };
        let (to_client, to_server) = Censor::craft_resets(
            [0; 6], [0; 6], [0; 6], ips, None, 40000, 443,
            TcpSeqNumber(2000), TcpSeqNumber(1000), 100, true,
        )
        .unwrap();
        assert_eq!(
            crate::inject::ip_destination(l3_payload(&to_client).unwrap()),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            crate::inject::ip_destination(l3_payload(&to_server).unwrap()),
            Some("2001:db8::2".parse().unwrap())
        );
    }
}
