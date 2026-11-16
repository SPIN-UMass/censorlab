use super::{Censor, Direction, HandleIpcError, IpPair};
use crate::censor::Action;
use crate::sys::{set_promiscuous_mode, PromiscuousModeError};
use clap::Parser;
use smoltcp::phy::{Medium, RawSocket};
use smoltcp::wire::{
    Error as SmoltcpError, EthernetAddress, EthernetFrame, EthernetProtocol,
    Ipv4Packet, Ipv6Packet,
};
use std::collections::VecDeque;
use std::io;
use std::os::unix::io::AsRawFd;
use thiserror::Error;
use tracing::{debug, info, span, warn, Level};

/// How long to block waiting for frames before re-checking IPC (shutdown)
const POLL_TIMEOUT_MS: libc::c_int = 100;
/// Receive buffer size; large enough for any frame the kernel hands us
const RECV_BUF_LEN: usize = 65536;
/// Maximum number of frames queued per interface while its TX buffer is full
const MAX_QUEUED_FRAMES: usize = 1024;
/// `sll_pkttype` of frames sent by this host (linux/if_packet.h; not in libc)
const PACKET_OUTGOING: u8 = 4;

/// Args to wire mode
#[derive(Debug, Parser)]
pub struct Args {
    /// WAN interface name
    pub wan_interface: String,
    /// Client interface name
    pub client_interface: String,
    /// How many packets to process at most from the WAN interface before polling the client
    /// interface
    #[clap(long, default_value_t = 1)]
    pub wan_packets: usize,
    /// How many packets to process at most from the client interface before polling the WAN
    /// interface
    #[clap(long, default_value_t = 1)]
    pub client_packets: usize,
}

/// Error running in wire mode
#[derive(Debug, Error)]
pub enum WireError {
    #[error("failed to open WAN interface: {0}")]
    WanIfaceInit(io::Error),
    #[error("failed to open client interface: {0}")]
    ClientIfaceInit(io::Error),
    #[error("failed to enable promiscuous mode on {0}: {1}")]
    Promiscuous(String, PromiscuousModeError),
    #[error("error waiting for frames: {0}")]
    Poll(io::Error),
    #[error("error receiving a frame on {0}: {1}")]
    Recv(String, io::Error),
    #[error("error handling IPC: {0}")]
    Ipc(#[from] HandleIpcError),
}

/// Context for the wire censor
pub struct Context {
    pub direction: Direction,
}

/// Which interface an emitted frame leaves through, relative to the
/// interface the triggering frame arrived on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Out {
    /// Out of the other interface (towards the frame's destination)
    Forward,
    /// Back out of the ingress interface (towards the frame's source)
    Back,
}

/// A frame to emit
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Emit {
    /// The received frame, unchanged
    Original,
    /// A frame we built (RST, injected response, rewritten copy)
    Frame(Vec<u8>),
}

/// IP addresses of an Ethernet frame carrying IPv4/IPv6
fn frame_ips(frame: &EthernetFrame<&[u8]>) -> Option<IpPair> {
    match frame.ethertype() {
        EthernetProtocol::Ipv4 => Ipv4Packet::new_checked(frame.payload())
            .ok()
            .map(|ip| IpPair::V4 {
                src: ip.src_addr(),
                dst: ip.dst_addr(),
            }),
        EthernetProtocol::Ipv6 => Ipv6Packet::new_checked(frame.payload())
            .ok()
            .map(|ip| IpPair::V6 {
                src: ip.src_addr(),
                dst: ip.dst_addr(),
            }),
        _ => None,
    }
}

fn set_eth_addrs(frame: &mut [u8], src: EthernetAddress, dst: EthernetAddress) {
    let mut eth = EthernetFrame::new_unchecked(frame);
    eth.set_src_addr(src);
    eth.set_dst_addr(dst);
}

/// Decide what to emit for a received frame given the censor's verdict.
///
/// Wire mode is a transparent bridge, so crafted frames impersonate the
/// endpoints at layer 2 too: a frame sent back towards the source uses the
/// observed frame's MACs swapped, one sent onwards uses them as observed.
///
/// Processing errors fail open (forward + warn), consistent with NFQ mode.
pub(super) fn plan_frame(
    verdict: Result<Action, SmoltcpError>,
    frame: &[u8],
    reset_repeat: usize,
) -> Vec<(Out, Emit)> {
    let action = match verdict {
        Ok(action) => action,
        Err(err) => {
            warn!("Error processing frame, forwarding it: {err}");
            return vec![(Out::Forward, Emit::Original)];
        }
    };
    match action {
        Action::None | Action::Ignore | Action::Delay(_) => vec![(Out::Forward, Emit::Original)],
        Action::Drop => Vec::new(),
        Action::Rewrite(rewrite) => {
            let mut copy = frame.to_vec();
            if rewrite.apply_ethernet(&mut copy) {
                vec![(Out::Forward, Emit::Frame(copy))]
            } else {
                warn!("Rewrite action on unparseable frame: forwarding unchanged");
                vec![(Out::Forward, Emit::Original)]
            }
        }
        Action::Reset {
            ips,
            ipid,
            src_port,
            dst_port,
            seq,
            ack,
            is_ack,
            seg_len,
            ..
        } => {
            // Forward the triggering segment first so the destination's
            // expected sequence number matches the RST's (as in NFQ mode,
            // where the segment is accepted)
            let mut plan = vec![(Out::Forward, Emit::Original)];
            let Ok(eth) = EthernetFrame::new_checked(frame) else {
                warn!("Reset requested for an unparseable frame: forwarding only");
                return plan;
            };
            let (src_mac, dst_mac) = (eth.src_addr(), eth.dst_addr());
            match Censor::craft_resets(
                [0; 6],
                src_mac.0,
                dst_mac.0,
                ips,
                ipid,
                src_port,
                dst_port,
                ack,
                seq,
                seg_len,
                is_ack,
            ) {
                Ok((mut to_source, mut to_dest)) => {
                    set_eth_addrs(&mut to_source, dst_mac, src_mac);
                    set_eth_addrs(&mut to_dest, src_mac, dst_mac);
                    for _ in 0..reset_repeat {
                        plan.push((Out::Back, Emit::Frame(to_source.clone())));
                        plan.push((Out::Forward, Emit::Frame(to_dest.clone())));
                    }
                }
                Err(err) => warn!("Failed to build RST frames: {err}"),
            }
            plan
        }
        Action::Inject {
            ips,
            src_port,
            dst_port,
            payload,
            ..
        } => {
            let mut plan = Vec::with_capacity(2);
            let observed = EthernetFrame::new_checked(frame)
                .ok()
                .and_then(|eth| frame_ips(&eth).map(|ips| (eth.src_addr(), eth.dst_addr(), ips)));
            match observed {
                Some((src_mac, dst_mac, observed_ips)) => {
                    // Usually a forged response to the source of the frame
                    let route = if ips.dst() == observed_ips.src() {
                        Some((Out::Back, dst_mac, src_mac))
                    } else if ips.dst() == observed_ips.dst() {
                        Some((Out::Forward, src_mac, dst_mac))
                    } else {
                        None
                    };
                    match route {
                        Some((out, eth_src, eth_dst)) => match crate::transport::construct_udp_inject(
                            eth_src, eth_dst, ips, src_port, dst_port, &payload,
                        ) {
                            // Emit the forged packet first so it wins the race
                            Ok(packet) => plan.push((out, Emit::Frame(packet))),
                            Err(err) => warn!("Failed to build injected packet: {err}"),
                        },
                        None => warn!(
                            "Injected packet to {} matches neither endpoint of the frame: not injecting",
                            ips.dst()
                        ),
                    }
                }
                None => warn!("Inject requested for an unparseable frame: not injecting"),
            }
            plan.push((Out::Forward, Emit::Original));
            plan
        }
    }
}

/// One side of the bridge
#[derive(Clone, Copy, Debug)]
enum Side {
    Wan = 0,
    Client = 1,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Side::Wan => Side::Client,
            Side::Client => Side::Wan,
        }
    }
    /// Direction of a frame received on this side
    fn ingress_direction(self) -> Direction {
        match self {
            Side::Wan => Direction::WanToClient,
            Side::Client => Direction::ClientToWan,
        }
    }
}

/// A bridged interface: a promiscuous AF_PACKET socket plus a queue of
/// frames waiting for TX space.  Promiscuous membership is tied to the
/// socket and is released by the kernel when the socket is closed.
struct Port {
    name: String,
    socket: RawSocket,
    queue: VecDeque<Vec<u8>>,
}

fn is_tx_full(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::ENOBUFS)
}

impl Port {
    fn open(name: &str) -> Result<Self, io::Error> {
        Ok(Self {
            name: name.to_owned(),
            socket: RawSocket::new(name, Medium::Ethernet)?,
            queue: VecDeque::new(),
        })
    }

    /// Receive one frame without blocking.  Frames this host itself sent
    /// out of the interface are skipped (they are not bridge traffic).
    fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            // SAFETY: zeroed sockaddr_ll is a valid value
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: buf and addr are valid for the lengths passed
            let n = unsafe {
                libc::recvfrom(
                    self.socket.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                    &mut addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                return match err.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(err),
                };
            }
            let n = n as usize;
            if addr.sll_pkttype == PACKET_OUTGOING {
                continue;
            }
            if n > buf.len() {
                warn!(iface = %self.name, len = n, "Dropping oversized frame (disable GRO/LRO on bridged interfaces)");
                continue;
            }
            return Ok(Some(n));
        }
    }

    fn try_send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: frame is valid for its length
        let n = unsafe {
            libc::send(
                self.socket.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Send a frame, queueing it if the TX buffer is full.  Frames are never
    /// reordered: while anything is queued, new frames go to the queue.
    fn send(&mut self, frame: &[u8]) {
        if self.queue.is_empty() {
            match self.try_send(frame) {
                Ok(()) => return,
                Err(err) if is_tx_full(&err) => {}
                Err(err) => {
                    warn!(iface = %self.name, "Failed to send frame, dropping it: {err}");
                    return;
                }
            }
        }
        if self.queue.len() >= MAX_QUEUED_FRAMES {
            warn!(iface = %self.name, "TX queue full, dropping frame");
            return;
        }
        debug!(iface = %self.name, "TX buffer full, queueing frame");
        self.queue.push_back(frame.to_vec());
    }

    /// Send as many queued frames as the TX buffer accepts
    fn flush(&mut self) {
        while let Some(frame) = self.queue.front() {
            match self.try_send(frame) {
                Ok(()) => {}
                Err(err) if is_tx_full(&err) => return,
                Err(err) => warn!(iface = %self.name, "Failed to send queued frame, dropping it: {err}"),
            }
            self.queue.pop_front();
        }
    }
}

/// Block until a port is readable (or writable while it has queued frames),
/// or the timeout elapses.
fn wait(ports: &[Port; 2]) -> io::Result<()> {
    let mut fds = ports.each_ref().map(|port| libc::pollfd {
        fd: port.socket.as_raw_fd(),
        events: libc::POLLIN | if port.queue.is_empty() { 0 } else { libc::POLLOUT },
        revents: 0,
    });
    // SAFETY: fds is a valid array of the given length
    let res = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_TIMEOUT_MS) };
    if res < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Ok(())
}

impl Censor {
    /// Run the censor in wire mode
    pub fn run_wire(mut self, args: Args) -> Result<(), WireError> {
        let mut ports = [
            Port::open(&args.wan_interface).map_err(WireError::WanIfaceInit)?,
            Port::open(&args.client_interface).map_err(WireError::ClientIfaceInit)?,
        ];
        // A bridge must see every frame, not just those for its own MAC
        for port in &ports {
            set_promiscuous_mode(&port.name, &port.socket)
                .map_err(|err| WireError::Promiscuous(port.name.clone(), err))?;
        }
        let budgets = [args.wan_packets.max(1), args.client_packets.max(1)];
        let mut buf = vec![0u8; RECV_BUF_LEN];
        info!("Bridging {} <-> {}", args.wan_interface, args.client_interface);
        loop {
            // Handle IPC (model updates, shutdown on SIGINT)
            match self.handle_ipc() {
                Ok(()) => {}
                Err(HandleIpcError::Shutdown) => {
                    info!("Shutting down wire mode");
                    break;
                }
                Err(err) => return Err(err.into()),
            }
            for port in &mut ports {
                port.flush();
            }
            wait(&ports).map_err(WireError::Poll)?;
            for ingress in [Side::Wan, Side::Client] {
                let direction = ingress.ingress_direction();
                let span = span!(Level::TRACE, "forwarding frame", direction = %direction);
                let _span = span.enter();
                for _ in 0..budgets[ingress as usize] {
                    let port = &ports[ingress as usize];
                    let Some(len) = port
                        .recv(&mut buf)
                        .map_err(|err| WireError::Recv(port.name.clone(), err))?
                    else {
                        break;
                    };
                    let frame = &buf[..len];
                    let mut context = Context { direction };
                    let verdict = self.process_frame(frame, &mut (&mut context).into());
                    for (out, emit) in plan_frame(verdict, frame, self.reset_repeat) {
                        let egress = match out {
                            Out::Forward => ingress.other(),
                            Out::Back => ingress,
                        };
                        let bytes = match &emit {
                            Emit::Original => frame,
                            Emit::Frame(bytes) => bytes,
                        };
                        ports[egress as usize].send(bytes);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::censor::Rewrite;
    use crate::transport::{construct_reset, construct_udp_inject};
    use smoltcp::wire::{Ipv4Address, TcpPacket, TcpSeqNumber};

    const CLIENT_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
    const GW_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);

    fn client_to_server() -> IpPair {
        IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(93, 184, 216, 34),
        }
    }

    /// A client -> server TCP frame as seen on the client interface
    fn tcp_frame() -> Vec<u8> {
        construct_reset(
            CLIENT_MAC,
            GW_MAC,
            client_to_server(),
            None,
            40000,
            443,
            Some(TcpSeqNumber(2000)),
            TcpSeqNumber(1000),
        )
        .unwrap()
    }

    /// A client -> resolver DNS query frame
    fn dns_query() -> Vec<u8> {
        construct_udp_inject(CLIENT_MAC, GW_MAC, client_to_server(), 5353, 53, b"query").unwrap()
    }

    fn parse(frame: &[u8]) -> (EthernetAddress, EthernetAddress, IpPair) {
        let eth = EthernetFrame::new_checked(frame).unwrap();
        (eth.src_addr(), eth.dst_addr(), frame_ips(&eth).unwrap())
    }

    #[test]
    fn processing_error_fails_open() {
        let plan = plan_frame(Err(SmoltcpError), &[0u8; 3], 1);
        assert_eq!(plan, vec![(Out::Forward, Emit::Original)]);
    }

    #[test]
    fn allow_forwards_and_drop_does_not() {
        let f = tcp_frame();
        for action in [Action::None, Action::Ignore] {
            assert_eq!(plan_frame(Ok(action), &f, 1), vec![(Out::Forward, Emit::Original)]);
        }
        assert!(plan_frame(Ok(Action::Drop), &f, 1).is_empty());
    }

    #[test]
    fn reset_injects_rsts_both_ways_with_bridge_macs() {
        let f = tcp_frame();
        let action = Action::Reset {
            src_mac: CLIENT_MAC.0,
            dst_mac: GW_MAC.0,
            ips: client_to_server(),
            ipid: None,
            src_port: 40000,
            dst_port: 443,
            seq: TcpSeqNumber(1000),
            ack: TcpSeqNumber(2000),
            is_ack: true,
            seg_len: 0,
        };
        let plan = plan_frame(Ok(action), &f, 2);
        // original, then 2 x (to source, to destination)
        assert_eq!(plan.len(), 5);
        assert_eq!(plan[0], (Out::Forward, Emit::Original));
        for pair in plan[1..].chunks(2) {
            let (Out::Back, Emit::Frame(to_src)) = &pair[0] else {
                panic!("expected RST back to source: {:?}", pair[0])
            };
            let (src, dst, ips) = parse(to_src);
            assert_eq!((src, dst), (GW_MAC, CLIENT_MAC));
            assert_eq!(ips, client_to_server().swap());

            let (Out::Forward, Emit::Frame(to_dst)) = &pair[1] else {
                panic!("expected RST to destination: {:?}", pair[1])
            };
            let (src, dst, ips) = parse(to_dst);
            assert_eq!((src, dst), (CLIENT_MAC, GW_MAC));
            assert_eq!(ips, client_to_server());
            let eth = EthernetFrame::new_checked(&to_dst[..]).unwrap();
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            assert!(TcpPacket::new_checked(ip.payload()).unwrap().rst());
        }
    }

    #[test]
    fn inject_sends_forged_response_back_then_forwards() {
        let f = dns_query();
        let action = Action::Inject {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ips: client_to_server().swap(),
            src_port: 53,
            dst_port: 5353,
            payload: b"forged".to_vec(),
        };
        let plan = plan_frame(Ok(action), &f, 1);
        assert_eq!(plan.len(), 2);
        let (Out::Back, Emit::Frame(resp)) = &plan[0] else {
            panic!("expected forged response first: {:?}", plan[0])
        };
        let (src, dst, ips) = parse(resp);
        assert_eq!((src, dst), (GW_MAC, CLIENT_MAC));
        assert_eq!(ips, client_to_server().swap());
        assert_eq!(plan[1], (Out::Forward, Emit::Original));
    }

    #[test]
    fn inject_to_unrelated_host_is_not_sent() {
        let f = dns_query();
        let action = Action::Inject {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ips: IpPair::V4 {
                src: Ipv4Address::new(1, 1, 1, 1),
                dst: Ipv4Address::new(2, 2, 2, 2),
            },
            src_port: 53,
            dst_port: 5353,
            payload: b"forged".to_vec(),
        };
        assert_eq!(plan_frame(Ok(action), &f, 1), vec![(Out::Forward, Emit::Original)]);
    }

    #[test]
    fn rewrite_forwards_modified_copy() {
        let f = tcp_frame();
        let plan = plan_frame(Ok(Action::Rewrite(Rewrite { ttl: Some(7) })), &f, 1);
        let [(Out::Forward, Emit::Frame(copy))] = &plan[..] else {
            panic!("expected one rewritten frame: {plan:?}")
        };
        let eth = EthernetFrame::new_checked(&copy[..]).unwrap();
        assert_eq!(Ipv4Packet::new_checked(eth.payload()).unwrap().hop_limit(), 7);
    }

    #[test]
    fn ingress_side_sets_direction() {
        assert_eq!(Side::Wan.ingress_direction(), Direction::WanToClient);
        assert_eq!(Side::Client.ingress_direction(), Direction::ClientToWan);
        assert!(matches!(Side::Wan.other(), Side::Client));
    }
}
