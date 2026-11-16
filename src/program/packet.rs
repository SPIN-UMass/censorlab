use rustpython_vm::pymodule;
use smoltcp::wire::{
    EthernetProtocol, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpPacket, TcpSeqNumber, UdpPacket,
};

#[derive(Clone, Debug)]
pub struct Packet {
    /// Timestamp of the packet
    pub timestamp: Option<f64>,
    /// Internet-layer metadata
    pub ip: IpMetadata,
    /// Direction
    pub direction: i8,
    /// Transport-layer metadata
    pub transport: TransportMetadata,
    /// Transport-layer payload.
    ///
    /// Allocated once via `.to_vec()` from a borrowed capture buffer during parsing.
    /// Not cloned in production code paths; the Python accessor copies into PyBytes
    /// which is unavoidable regardless of the backing type (Vec, Rc, or Arc).
    /// Using `Rc<[u8]>` was considered but provides no benefit since Packet is never
    /// cloned in production and the Python VM requires owned bytes.
    pub payload: Vec<u8>,
    /// The connection's TLS ClientHello, once reassembled from the client's first segments.
    ///
    /// Set by connection tracking on the packet that completes it and every packet after.
    pub tls_client_hello: Option<crate::application::tls::ClientHelloInfo>,
}
impl Packet {
    /// Record the traffic direction relative to the configured client.
    pub fn set_direction(&mut self, direction: crate::censor::Direction) {
        use crate::censor::Direction::*;
        self.direction = match direction {
            ClientToWan => 1,
            WanToClient => -1,
            Unknown => 0,
        };
    }
    pub fn from_ts_bytes(
        timestamp: Option<f64>,
        data: &[u8],
        ethertype: EthernetProtocol,
    ) -> Result<Packet, ParsePacketError> {
        let ip_layer = IpLayer::parse(data, ethertype)?;
        Packet::from_ip_layer(timestamp, &ip_layer)
    }
    /// Parse the transport layer of an already-recognized IP packet.
    ///
    /// Fails for anything other than a TCP/UDP packet whose transport header is present
    /// and well-formed.
    pub fn from_ip_layer(
        timestamp: Option<f64>,
        ip_layer: &IpLayer,
    ) -> Result<Packet, ParsePacketError> {
        let ip_metadata = ip_layer.metadata.clone();
        let payload = ip_layer.payload;
        if matches!(ip_layer.protocol, IpProtocol::Tcp | IpProtocol::Udp)
            && !ip_layer.has_upper_header
        {
            return Err(ParsePacketError::NonFirstFragment);
        }
        // Extract transport-layer metadata
        let (transport_metadata, payload) = {
            use IpProtocol::*;
            match ip_layer.protocol {
                Tcp => {
                    let tcp_packet =
                        TcpPacket::new_checked(payload).map_err(ParsePacketError::Tcp)?;
                    let metadata = TransportMetadata::from(&tcp_packet);
                    (metadata, tcp_packet.payload().to_vec())
                }
                Udp => {
                    let udp_packet =
                        UdpPacket::new_checked(payload).map_err(ParsePacketError::Udp)?;
                    let metadata = TransportMetadata::from(&udp_packet);
                    (metadata, udp_packet.payload().to_vec())
                }
                unknown => {
                    return Err(ParsePacketError::UnknownTransport(unknown));
                }
            }
        };
        // Put together the packet
        let packet = Packet {
            timestamp,
            ip: ip_metadata,
            direction: 0,
            transport: transport_metadata,
            payload,
            tls_client_hello: None,
        };
        Ok(packet)
    }
    pub fn connection_identifier(&self) -> ConnectionIdentifier {
        ConnectionIdentifier::new(self.ip.src(), self.ip.dst(), &self.transport)
    }
    pub fn transport_proto(&self) -> TransportProtocol {
        self.transport.extra.protocol()
    }
    pub fn payload_entropy(&self) -> f64 {
        shannon_entropy(&self.payload)
    }
    /// Average number of set bits per payload byte; 0.0 for an empty payload
    /// (like the entropy), never NaN.
    pub fn payload_average_popcount(&self) -> f64 {
        if self.payload.is_empty() {
            return 0.0;
        }
        let ones: u64 = self.payload.iter().map(|b| u64::from(b.count_ones())).sum();
        ones as f64 / self.payload.len() as f64
    }
    /// Fraction of payload bytes that are printable ASCII (0x20..=0x7e);
    /// Wu et al.'s Ex3 exemption.  0.0 for an empty payload, never NaN.
    pub fn payload_printable_fraction(&self) -> f64 {
        if self.payload.is_empty() {
            return 0.0;
        }
        let printable = self.payload.iter().filter(|b| (0x20..=0x7e).contains(*b)).count();
        printable as f64 / self.payload.len() as f64
    }
}

/// The internet layer of a packet, fully recognized down to the upper-layer protocol.
///
/// For IPv6, the extension-header chain (hop-by-hop, routing, destination options,
/// fragment, AH) is walked so that `protocol` is the real upper-layer protocol and
/// `payload` starts at its header.
#[derive(Clone, Debug)]
pub struct IpLayer<'a> {
    /// Fixed-header metadata. `next_header` holds the upper-layer protocol.
    pub metadata: IpMetadata,
    /// Upper-layer protocol (after any IPv6 extension headers)
    pub protocol: IpProtocol,
    /// Upper-layer payload
    pub payload: &'a [u8],
    /// Whether `payload` begins with the upper-layer header. False for non-first
    /// fragments, whose payload is a slice from the middle of the upper-layer packet.
    pub has_upper_header: bool,
}
impl<'a> IpLayer<'a> {
    /// Recognize an IPv4/IPv6 packet (without link-layer header).
    pub fn parse(data: &'a [u8], ethertype: EthernetProtocol) -> Result<Self, ParsePacketError> {
        match ethertype {
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_checked(data).map_err(ParsePacketError::IPv4)?;
                Ok(Self::from_ipv4(&ipv4_packet))
            }
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new_checked(data).map_err(ParsePacketError::IPv6)?;
                Self::from_ipv6(&ipv6_packet)
            }
            unknown => Err(ParsePacketError::UnknownInternet(unknown)),
        }
    }
    /// Recognize the upper layer of a checked IPv4 packet.
    pub fn from_ipv4(ipv4_packet: &Ipv4Packet<&'a [u8]>) -> Self {
        IpLayer {
            metadata: IpMetadata::from(ipv4_packet),
            protocol: ipv4_packet.next_header(),
            payload: ipv4_packet.payload(),
            has_upper_header: ipv4_packet.frag_offset() == 0,
        }
    }
    /// Recognize the upper layer of a checked IPv6 packet by walking its extension headers.
    pub fn from_ipv6(ipv6_packet: &Ipv6Packet<&'a [u8]>) -> Result<Self, ParsePacketError> {
        let mut metadata = IpMetadata::from(ipv6_packet);
        let (protocol, payload, has_upper_header) =
            walk_ipv6_extension_headers(ipv6_packet.next_header(), ipv6_packet.payload())?;
        metadata.next_header = protocol;
        Ok(IpLayer {
            metadata,
            protocol,
            payload,
            has_upper_header,
        })
    }
}

/// Walk an IPv6 extension-header chain starting at `next` with `data` being the payload
/// of the fixed header.
///
/// Returns the upper-layer protocol, its payload, and whether that payload begins with
/// the upper-layer header (false for non-first fragments: per RFC 8200 everything after
/// the Fragment header is fragmentable, so it is absent from those fragments).
/// Every header consumes at least 8 bytes, so the walk is bounded by the packet length.
fn walk_ipv6_extension_headers(
    mut next: IpProtocol,
    mut data: &[u8],
) -> Result<(IpProtocol, &[u8], bool), ParsePacketError> {
    use smoltcp::wire::{Error as WireError, Ipv6ExtHeader};
    loop {
        let len = match next {
            // Length in 8-octet units, not including the first 8 octets (RFC 8200 4.3-4.6)
            IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                let header =
                    Ipv6ExtHeader::new_checked(data).map_err(ParsePacketError::Ipv6ExtHeader)?;
                next = header.next_header();
                8 + usize::from(header.header_len()) * 8
            }
            // Fixed 8 bytes (RFC 8200 4.5)
            IpProtocol::Ipv6Frag => {
                if data.len() < 8 {
                    return Err(ParsePacketError::Ipv6ExtHeader(WireError));
                }
                let frag_next = IpProtocol::from(data[0]);
                let frag_offset = u16::from_be_bytes([data[2], data[3]]) >> 3;
                if frag_offset != 0 {
                    return Ok((frag_next, &data[8..], false));
                }
                // First fragment: the rest of the chain and the upper-layer header follow
                next = frag_next;
                8
            }
            // Length in 4-octet units, minus 2 (RFC 4302 2.2)
            IpProtocol::IpSecAh => {
                if data.len() < 8 {
                    return Err(ParsePacketError::Ipv6ExtHeader(WireError));
                }
                next = IpProtocol::from(data[0]);
                (usize::from(data[1]) + 2) * 4
            }
            upper => return Ok((upper, data, true)),
        };
        data = data
            .get(len..)
            .ok_or(ParsePacketError::Ipv6ExtHeader(WireError))?;
    }
}

#[derive(Clone, Debug)]
pub struct IpMetadata {
    /// Header length
    /// u8 on ip4, usize on ip6
    pub header_len: usize,
    /// Total length
    /// u16 on ip4, usize on ip6
    pub total_len: usize,
    /// TTL
    pub hop_limit: u8,
    /// Protocol of the traffic in the payload    
    pub next_header: IpProtocol,
    /// Fields specific to the IP version
    pub version: IpVersionMetadata,
}
#[derive(Clone, Debug)]
pub enum IpVersionMetadata {
    V4 {
        src: Ipv4Address,
        dst: Ipv4Address,
        dscp: u8,
        ecn: u8,
        ident: u16,
        dont_frag: bool,
        more_frags: bool,
        frag_offset: u16,
        checksum: u16,
    },
    V6 {
        src: Ipv6Address,
        dst: Ipv6Address,
        traffic_class: u8,
        flow_label: u32,
        payload_len: u16,
    },
}
impl IpMetadata {
    fn src(&self) -> IpAddress {
        use IpVersionMetadata::*;
        match self.version {
            V4 { src, .. } => src.into(),
            V6 { src, .. } => src.into(),
        }
    }
    fn dst(&self) -> IpAddress {
        use IpVersionMetadata::*;
        match self.version {
            V4 { dst, .. } => dst.into(),
            V6 { dst, .. } => dst.into(),
        }
    }
}
impl<T: AsRef<[u8]>> From<&Ipv4Packet<T>> for IpMetadata {
    fn from(packet: &Ipv4Packet<T>) -> Self {
        IpMetadata {
            header_len: packet.header_len().into(),
            total_len: packet.total_len().into(),
            hop_limit: packet.hop_limit(),
            next_header: packet.next_header(),
            version: IpVersionMetadata::V4 {
                src: packet.src_addr(),
                dst: packet.dst_addr(),
                dscp: packet.dscp(),
                ecn: packet.ecn(),
                ident: packet.ident(),
                dont_frag: packet.dont_frag(),
                more_frags: packet.more_frags(),
                frag_offset: packet.frag_offset(),
                checksum: packet.checksum(),
            },
        }
    }
}
impl<T: AsRef<[u8]>> From<&Ipv6Packet<T>> for IpMetadata {
    fn from(packet: &Ipv6Packet<T>) -> Self {
        IpMetadata {
            header_len: packet.header_len(),
            total_len: packet.total_len(),
            hop_limit: packet.hop_limit(),
            next_header: packet.next_header(),
            version: IpVersionMetadata::V6 {
                src: packet.src_addr(),
                dst: packet.dst_addr(),
                traffic_class: packet.traffic_class(),
                flow_label: packet.flow_label(),
                payload_len: packet.payload_len(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TransportMetadata {
    pub src: u16,
    pub dst: u16,
    pub extra: TransportMetadataExtra,
}
impl<T: AsRef<[u8]>> From<&TcpPacket<T>> for TransportMetadata {
    fn from(packet: &TcpPacket<T>) -> Self {
        TransportMetadata {
            src: packet.src_port(),
            dst: packet.dst_port(),
            extra: TransportMetadataExtra::from(packet),
        }
    }
}
impl<T: AsRef<[u8]>> From<&UdpPacket<T>> for TransportMetadata {
    fn from(packet: &UdpPacket<T>) -> Self {
        TransportMetadata {
            src: packet.src_port(),
            dst: packet.dst_port(),
            extra: TransportMetadataExtra::from(packet),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum TransportMetadataExtra {
    Tcp(TcpMetadata),
    Udp(UdpMetadata),
}
impl TransportMetadataExtra {
    fn protocol(&self) -> TransportProtocol {
        match self {
            TransportMetadataExtra::Tcp(_) => TransportProtocol::Tcp,
            TransportMetadataExtra::Udp(_) => TransportProtocol::Udp,
        }
    }
}
impl<T: AsRef<[u8]>> From<&TcpPacket<T>> for TransportMetadataExtra {
    fn from(packet: &TcpPacket<T>) -> Self {
        TransportMetadataExtra::Tcp(TcpMetadata {
            seq: packet.seq_number(),
            ack: packet.ack_number(),
            header_len: packet.header_len(),
            urgent_at: packet.urgent_at(),
            window_len: packet.window_len(),
            flags: TcpFlags {
                fin: packet.fin(),
                syn: packet.syn(),
                rst: packet.rst(),
                psh: packet.psh(),
                ack: packet.ack(),
                urg: packet.urg(),
                ece: packet.ece(),
                cwr: packet.cwr(),
                ns: packet.ns(),
            },
        })
    }
}
impl<T: AsRef<[u8]>> From<&UdpPacket<T>> for TransportMetadataExtra {
    fn from(packet: &UdpPacket<T>) -> Self {
        TransportMetadataExtra::Udp(UdpMetadata {
            length: packet.len(),
            checksum: packet.checksum(),
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub struct TcpMetadata {
    pub seq: TcpSeqNumber,
    pub ack: TcpSeqNumber,
    pub header_len: u8,
    pub urgent_at: u16,
    pub window_len: u16,
    pub flags: TcpFlags,
}
impl TcpMetadata {
    /// Sequence number as the unsigned 32-bit value carried on the wire
    /// (smoltcp stores it as an `i32` for wrapping comparisons)
    pub fn seq_number(&self) -> u32 {
        self.seq.0 as u32
    }
    /// Acknowledgement number as the unsigned 32-bit value carried on the wire
    pub fn ack_number(&self) -> u32 {
        self.ack.0 as u32
    }
}
#[derive(Clone, Copy, Debug)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct UdpMetadata {
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ConnectionIdentifier {
    ips: (IpAddress, IpAddress),
    pub transport_proto: TransportProtocol,
    ports: (u16, u16),
}
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}
impl ConnectionIdentifier {
    fn new(src_ip: IpAddress, dst_ip: IpAddress, transport_metadata: &TransportMetadata) -> Self {
        ConnectionIdentifier {
            ips: (src_ip, dst_ip),
            transport_proto: transport_metadata.extra.protocol(),
            ports: (transport_metadata.src, transport_metadata.dst),
        }
    }
    pub fn direction(&self, other: &Self) -> Option<Direction> {
        let (src_ip, dst_ip) = self.ips;
        let (src_port, dst_port) = self.ports;
        let (other_src_ip, other_dst_ip) = other.ips;
        let (other_src_port, other_dst_port) = other.ports;
        if src_ip == other_src_ip
            && dst_ip == other_dst_ip
            && src_port == other_src_port
            && dst_port == other_dst_port
        {
            Some(Direction::FromInitiator)
        } else if src_ip == other_dst_ip
            && dst_ip == other_src_ip
            && src_port == other_dst_port
            && dst_port == other_src_port
        {
            Some(Direction::ToInitiator)
        } else {
            None
        }
    }

    pub fn order_by_port(&self) -> Self {
        // Extract fields
        let (src_ip, dst_ip) = self.ips;
        let (src_port, dst_port) = self.ports;
        // Swap ips and ports (in order of port)
        let (ips, ports) = if src_port < dst_port {
            ((src_ip, dst_ip), (src_port, dst_port))
        } else {
            ((dst_ip, src_ip), (dst_port, src_port))
        };
        // Construct the identifier
        ConnectionIdentifier {
            ips,
            transport_proto: self.transport_proto.clone(),
            ports,
        }
    }
}

/// Direction of the packet
#[derive(Debug)]
pub enum Direction {
    FromInitiator,
    ToInitiator,
}

#[derive(Debug, thiserror::Error)]
pub enum ParsePacketError {
    #[error("Error parsing packet as ethernet: {0}")]
    Ethernet(smoltcp::wire::Error),
    #[error("Error parsing packet as IPv4: {0}")]
    IPv4(smoltcp::wire::Error),
    #[error("Error parsing packet as IPv6: {0}")]
    IPv6(smoltcp::wire::Error),
    #[error("Unknown internet layer: {0}")]
    UnknownInternet(EthernetProtocol),
    #[error("Error parsing packet as Tcp: {0}")]
    Tcp(smoltcp::wire::Error),
    #[error("Error parsing packet as Udp: {0}")]
    Udp(smoltcp::wire::Error),
    #[error("Unknown transport layer: {0}")]
    UnknownTransport(IpProtocol),
    #[error("Malformed IPv6 extension header chain: {0}")]
    Ipv6ExtHeader(smoltcp::wire::Error),
    #[error("Non-first fragment carries no transport header")]
    NonFirstFragment,
}

/// Shannon entropy of a bytestream
/// Scaled from 0-8 to 0-1
pub fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq_list = [0u16; 256];
    for byte in data {
        freq_list[*byte as usize] += 1;
    }

    let len = data.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    -freq_list
        .into_iter()
        .filter(|f| *f != 0)
        .map(|count| (count as f64 / len) * (count as f64 / len).log2())
        .sum::<f64>()
        / 8.0
}

#[pymodule]
pub mod rust_packet {
    use super::{
        IpMetadata as RustIpPacket, IpVersionMetadata, Packet as RustPacket,
        TcpFlags as TcpFlagsRust, TcpMetadata, TransportMetadataExtra, UdpMetadata,
    };
    use crate::censor::Direction;
    use crate::model::{ModelThreadError, ModelThreadMessage};
    use regex::bytes::Regex as RustRegex;
    use rustpython_vm::convert::ToPyObject;
    use rustpython_vm::{
        builtins::PyBytesRef, builtins::PyList, builtins::PyListRef,
        convert::IntoPyException, pyclass, PyObjectRef, PyPayload, PyResult,
        VirtualMachine,
    };
    use tracing;

    use crate::subnet::IpNet;
    use std::io;
    use std::net::IpAddr;
    use std::sync::mpsc;

    #[pyattr]
    #[pyclass(module = "rust", name = "Packet")]
    #[derive(Debug, PyPayload)]
    pub struct Packet(RustPacket);

    impl From<RustPacket> for Packet {
        fn from(packet: RustPacket) -> Self {
            Self(packet)
        }
    }
    impl Packet {
        pub fn set_direction(&mut self, direction: Direction) {
            self.0.direction = match direction {
                Direction::ClientToWan => 1,
                Direction::WanToClient => -1,
                Direction::Unknown => 0,
            };
        }
    }

    #[pyclass]
    // pygetset with &self only generates getters (no setter without explicit #[pygetset(setter)]).
    // Accessor objects clone metadata (IpMetadata, TcpMetadata, UdpMetadata) which are small
    // stack-allocated structs — Rc would add overhead, not remove it.
    impl Packet {
        #[pygetset]
        fn timestamp(&self) -> Option<f64> {
            self.0.timestamp
        }
        #[pygetset]
        fn direction(&self) -> i8 {
            self.0.direction
        }
        #[pygetset]
        fn ip(&self) -> IpPacket {
            IpPacket(self.0.ip.clone())
        }
        #[pygetset]
        fn tcp(&self) -> Option<TcpPacket> {
            if let TransportMetadataExtra::Tcp(ref metadata) = self.0.transport.extra {
                Some(TcpPacket {
                    src: self.0.transport.src,
                    dst: self.0.transport.dst,
                    data: *metadata,
                })
            } else {
                None
            }
        }
        #[pygetset]
        fn udp(&self) -> Option<UdpPacket> {
            if let TransportMetadataExtra::Udp(ref metadata) = self.0.transport.extra {
                Some(UdpPacket {
                    src: self.0.transport.src,
                    dst: self.0.transport.dst,
                    data: *metadata,
                })
            } else {
                None
            }
        }
        #[pygetset]
        fn payload(&self) -> Vec<u8> {
            self.0.payload.clone()
        }
        #[pygetset]
        fn payload_len(&self) -> usize {
            self.0.payload.len()
        }
        #[pygetset]
        fn payload_entropy(&self) -> f64 {
            self.0.payload_entropy()
        }
        #[pygetset]
        fn payload_avg_popcount(&self) -> f64 {
            self.0.payload_average_popcount()
        }
        #[pygetset]
        fn payload_printable_fraction(&self) -> f64 {
            self.0.payload_printable_fraction()
        }
        /// The connection's TLS ClientHello once it has been fully received, even if it was
        /// split across several TCP segments or TLS records, otherwise None
        #[pygetset]
        fn tls_client_hello(&self) -> Option<super::rust_tls::ClientHelloInfo> {
            self.0.tls_client_hello.clone().map(Into::into)
        }
        #[pymethod]
        fn __str__(&self) -> String {
            format!("{:?}", self)
        }
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "IpPacket")]
    #[derive(Debug, PyPayload)]
    pub struct IpPacket(pub RustIpPacket);
    #[pyclass]
    impl IpPacket {
        #[pygetset]
        fn src(&self) -> String {
            self.0.src().to_string()
        }
        #[pygetset]
        fn dst(&self) -> String {
            self.0.dst().to_string()
        }
        #[pygetset]
        fn header_len(&self) -> usize {
            self.0.header_len
        }
        #[pygetset]
        fn total_len(&self) -> usize {
            self.0.total_len
        }
        #[pygetset]
        fn ttl(&self) -> u8 {
            self.0.hop_limit
        }
        #[pygetset]
        fn next_header(&self) -> u8 {
            u8::from(self.0.next_header)
        }
        #[pygetset]
        fn version(&self) -> u8 {
            match self.0.version {
                IpVersionMetadata::V4 { .. } => 4,
                IpVersionMetadata::V6 { .. } => 6,
            }
        }
        // IPv4-specific fields
        #[pygetset]
        fn dscp(&self) -> Option<u8> {
            match self.0.version {
                IpVersionMetadata::V4 { dscp, .. } => Some(dscp),
                _ => None,
            }
        }
        #[pygetset]
        fn ecn(&self) -> Option<u8> {
            match self.0.version {
                IpVersionMetadata::V4 { ecn, .. } => Some(ecn),
                _ => None,
            }
        }
        #[pygetset]
        fn ident(&self) -> Option<u16> {
            match self.0.version {
                IpVersionMetadata::V4 { ident, .. } => Some(ident),
                _ => None,
            }
        }
        #[pygetset]
        fn dont_frag(&self) -> Option<bool> {
            match self.0.version {
                IpVersionMetadata::V4 { dont_frag, .. } => Some(dont_frag),
                _ => None,
            }
        }
        #[pygetset]
        fn more_frags(&self) -> Option<bool> {
            match self.0.version {
                IpVersionMetadata::V4 { more_frags, .. } => Some(more_frags),
                _ => None,
            }
        }
        #[pygetset]
        fn frag_offset(&self) -> Option<u16> {
            match self.0.version {
                IpVersionMetadata::V4 { frag_offset, .. } => Some(frag_offset),
                _ => None,
            }
        }
        #[pygetset]
        fn checksum(&self) -> Option<u16> {
            match self.0.version {
                IpVersionMetadata::V4 { checksum, .. } => Some(checksum),
                _ => None,
            }
        }
        // IPv6-specific fields
        #[pygetset]
        fn traffic_class(&self) -> Option<u8> {
            match self.0.version {
                IpVersionMetadata::V6 { traffic_class, .. } => Some(traffic_class),
                _ => None,
            }
        }
        #[pygetset]
        fn flow_label(&self) -> Option<u32> {
            match self.0.version {
                IpVersionMetadata::V6 { flow_label, .. } => Some(flow_label),
                _ => None,
            }
        }
        #[pygetset]
        fn payload_len(&self) -> Option<u16> {
            match self.0.version {
                IpVersionMetadata::V6 { payload_len, .. } => Some(payload_len),
                _ => None,
            }
        }
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "TcpPacket")]
    #[derive(Debug, PyPayload)]
    pub struct TcpPacket {
        pub src: u16,
        pub dst: u16,
        pub data: TcpMetadata,
    }
    #[pyclass]
    impl TcpPacket {
        #[pygetset]
        fn src(&self) -> u16 {
            self.src
        }
        #[pygetset]
        fn dst(&self) -> u16 {
            self.dst
        }
        #[pymethod]
        fn uses_port(&self, port: u16) -> bool {
            self.src == port || self.dst == port
        }
        #[pygetset]
        fn seq(&self) -> u32 {
            self.data.seq_number()
        }
        #[pygetset]
        fn ack(&self) -> u32 {
            self.data.ack_number()
        }
        #[pygetset]
        fn header_len(&self) -> u8 {
            self.data.header_len
        }
        #[pygetset]
        fn urgent_at(&self) -> u16 {
            self.data.urgent_at
        }
        #[pygetset]
        fn window_len(&self) -> u16 {
            self.data.window_len
        }
        #[pygetset]
        fn flags(&self) -> TcpFlags {
            TcpFlags(self.data.flags)
        }
    }
    #[pyattr]
    #[pyclass(module = "rust", name = "TcpFlags")]
    #[derive(Debug, PyPayload)]
    pub struct TcpFlags(pub TcpFlagsRust);
    #[pyclass]
    impl TcpFlags {
        #[pygetset]
        fn fin(&self) -> bool {
            self.0.fin
        }
        #[pygetset]
        fn syn(&self) -> bool {
            self.0.syn
        }
        #[pygetset]
        fn rst(&self) -> bool {
            self.0.rst
        }
        #[pygetset]
        fn psh(&self) -> bool {
            self.0.psh
        }
        #[pygetset]
        fn ack(&self) -> bool {
            self.0.ack
        }
        #[pygetset]
        fn urg(&self) -> bool {
            self.0.urg
        }
        #[pygetset]
        fn ece(&self) -> bool {
            self.0.ece
        }
        #[pygetset]
        fn cwr(&self) -> bool {
            self.0.cwr
        }
        #[pygetset]
        fn ns(&self) -> bool {
            self.0.ns
        }
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "UdpPacket")]
    #[derive(Debug, PyPayload)]
    pub struct UdpPacket {
        pub src: u16,
        pub dst: u16,
        pub data: UdpMetadata,
    }
    #[pyclass]
    impl UdpPacket {
        #[pygetset]
        fn src(&self) -> u16 {
            self.src
        }
        #[pygetset]
        fn dst(&self) -> u16 {
            self.dst
        }
        #[pymethod]
        fn uses_port(&self, port: u16) -> bool {
            self.src == port || self.dst == port
        }
        #[pygetset]
        fn length(&self) -> u16 {
            self.data.length
        }
        #[pygetset]
        fn checksum(&self) -> u16 {
            self.data.checksum
        }
    }
    #[pyfunction]
    fn regex(s: String, vm: &VirtualMachine) -> PyResult<Regex> {
        // An invalid pattern is the script's fault: raise, don't panic the process
        let inner = RustRegex::new(&s)
            .map_err(|err| vm.new_value_error(format!("invalid regex {s:?}: {err}")))?;
        Ok(Regex { inner })
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "Regex")]
    #[derive(Debug, PyPayload)]
    struct Regex {
        inner: RustRegex,
    }
    #[pyclass]
    impl Regex {
        #[pymethod]
        fn is_match(&self, bytes: PyBytesRef) -> bool {
            self.inner.is_match(bytes.as_ref())
        }
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "Model")]
    #[derive(Debug, PyPayload)]
    pub struct Model {
        sender: mpsc::SyncSender<ModelThreadMessage>,
    }
    impl Model {
        pub fn new(sender: mpsc::SyncSender<ModelThreadMessage>) -> Self {
            Self { sender }
        }
    }
    #[pyclass]
    impl Model {
        #[pymethod]
        fn evaluate(
            &self,
            name: String,
            data: Vec<f32>,
            vm: &VirtualMachine,
        ) -> PyResult<PyListRef> {
            // A fresh reply channel per request: we hold no sender for it, so
            // if the model thread dies, recv() sees the disconnect and errors
            // instead of blocking forever
            let (response_channel, return_recv) = mpsc::sync_channel::<Result<Vec<f64>, ModelThreadError>>(1);
            // Send the data over the channel, along with a return address
            self.sender
                .send(ModelThreadMessage::Request {
                    name,
                    data,
                    response_channel,
                })
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
            // Receive a new value
            let out = return_recv
                .recv()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
            // Parse the result into python values
            let out: Vec<PyObjectRef> = out.into_iter().map(|f| f.to_pyobject(vm)).collect();
            Ok(PyList::new_ref(out, &vm.ctx))
        }
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "Host")]
    #[derive(Debug, PyPayload)]
    pub struct Host {
        num_connections: u32,
        num_packets: u32,
        state: PyObjectRef,
    }
    impl Host {
        pub fn new(num_connections: u32, num_packets: u32, state: PyObjectRef) -> Self {
            Self {
                num_connections,
                num_packets,
                state,
            }
        }
    }
    #[pyclass]
    impl Host {
        #[pygetset]
        fn num_connections(&self) -> u32 {
            self.num_connections
        }
        #[pygetset]
        fn num_packets(&self) -> u32 {
            self.num_packets
        }
        #[pygetset]
        fn state(&self) -> PyObjectRef {
            self.state.clone()
        }
    }

    fn parse_subnet(cidr: &str, vm: &VirtualMachine) -> PyResult<IpNet> {
        cidr.parse().map_err(|e| vm.new_value_error(format!("{e}")))
    }
    fn parse_addr(addr: &str, vm: &VirtualMachine) -> PyResult<IpAddr> {
        addr.parse()
            .map_err(|_| vm.new_value_error(format!("invalid IP address {addr:?}")))
    }

    /// Compile a CIDR subnet (e.g. "10.0.0.0/8", "2001:db8::/32", or a bare address).
    /// Raises ValueError on malformed input or host bits set.
    #[pyfunction]
    fn subnet(cidr: String, vm: &VirtualMachine) -> PyResult<Subnet> {
        parse_subnet(&cidr, vm).map(|inner| Subnet { inner })
    }

    /// Whether `addr` lies in the CIDR subnet `cidr`. Parses `cidr` on every call;
    /// prefer a module-level `subnet(...)` object in per-packet code.
    #[pyfunction]
    fn ip_in(addr: String, cidr: String, vm: &VirtualMachine) -> PyResult<bool> {
        let net = parse_subnet(&cidr, vm)?;
        Ok(net.contains(parse_addr(&addr, vm)?))
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "Subnet")]
    #[derive(Debug, PyPayload)]
    struct Subnet {
        inner: IpNet,
    }
    #[pyclass]
    impl Subnet {
        /// Whether `addr` (an address string such as packet.ip.src) is in this subnet.
        /// Addresses of the other IP family never match. Raises ValueError on a malformed address.
        #[pymethod]
        fn contains(&self, addr: String, vm: &VirtualMachine) -> PyResult<bool> {
            Ok(self.inner.contains(parse_addr(&addr, vm)?))
        }
        #[pymethod]
        fn __str__(&self) -> String {
            self.inner.to_string()
        }
    }

    #[pyfunction]
    fn log_info(msg: String) {
        tracing::info!("{}", msg);
    }

    #[pyfunction]
    fn log_error(msg: String) {
        tracing::error!("{}", msg);
    }

    #[pyfunction]
    fn log_warn(msg: String) {
        tracing::warn!("{}", msg);
    }

    #[pyfunction]
    fn log_debug(msg: String) {
        tracing::debug!("{}", msg);
    }
}

#[pymodule]
pub mod rust_dns {
    use crate::application::dns;
    use rustpython_vm::convert::ToPyObject;
    use rustpython_vm::{
        builtins::PyBytesRef, builtins::PyTuple, convert::IntoPyException,
        pyclass, PyObjectRef, PyPayload, PyResult, VirtualMachine,
    };
    use std::io;
    use std::net::Ipv4Addr;

    fn to_pyerr(err: impl std::error::Error + Send + Sync + 'static, vm: &VirtualMachine) -> rustpython_vm::builtins::PyBaseExceptionRef {
        io::Error::other(err).into_pyexception(vm)
    }

    /// Craft a DNS response from a query, returning raw bytes suitable for injection.
    ///
    /// Usage from Python: `dns.craft_response(packet.payload, "10.10.10.10")`
    /// or with TTL: `dns.craft_response(packet.payload, "10.10.10.10", 300)`
    #[pyfunction(name = "craft_response")]
    fn craft_response(
        query_bytes: PyBytesRef,
        answer_ip: String,
        ttl: rustpython_vm::function::OptionalArg<u32>,
        vm: &VirtualMachine,
    ) -> PyResult<rustpython_vm::builtins::PyBytes> {
        let ip: Ipv4Addr = answer_ip.parse().map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid IPv4 address: {err}"))
                .into_pyexception(vm)
        })?;
        let ttl = ttl.unwrap_or(300);
        let response = dns::craft_dns_response(query_bytes.as_ref(), ip, ttl)
            .map_err(|err| to_pyerr(err, vm))?;
        Ok(rustpython_vm::builtins::PyBytes::from(response))
    }

    /// Parse a DNS message carried directly in a UDP payload.
    #[pyfunction]
    fn parse(bytes: PyBytesRef, vm: &VirtualMachine) -> PyResult<DnsPacket> {
        let msg = dns::parse_dns(bytes.as_ref()).map_err(|err| to_pyerr(err, vm))?;
        Ok(DnsPacket::from(msg))
    }

    /// Parse a DNS-over-TCP payload: one or more 2-byte-length-prefixed messages.
    /// Returns a list of DnsPacket. Raises if any frame is incomplete or invalid.
    #[pyfunction]
    fn parse_tcp(bytes: PyBytesRef, vm: &VirtualMachine) -> PyResult<Vec<PyObjectRef>> {
        let msgs = dns::parse_dns_tcp(bytes.as_ref()).map_err(|err| to_pyerr(err, vm))?;
        Ok(msgs
            .into_iter()
            .map(|m| DnsPacket::from(m).to_pyobject(vm))
            .collect())
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "DnsPacket")]
    #[derive(Debug, PyPayload)]
    pub struct DnsPacket {
        header: dns::Header,
        questions: Vec<Question>,
        answers: Vec<ResourceRecord>,
        nameservers: Vec<ResourceRecord>,
        additional: Vec<ResourceRecord>,
        opt: Option<Record>,
        trailing_len: usize,
    }
    impl From<dns::Message> for DnsPacket {
        fn from(m: dns::Message) -> Self {
            let rrs = |v: Vec<dns::ResourceRecord>| v.into_iter().map(ResourceRecord::from).collect();
            DnsPacket {
                header: m.header,
                questions: m.questions.into_iter().map(Question::from).collect(),
                answers: rrs(m.answers),
                nameservers: rrs(m.nameservers),
                additional: rrs(m.additional),
                opt: m.opt.map(Record::from),
                trailing_len: m.trailing_len,
            }
        }
    }
    #[pyclass]
    impl DnsPacket {
        #[pygetset]
        fn id(&self) -> u16 {
            self.header.id
        }
        #[pygetset]
        fn query(&self) -> bool {
            self.header.query
        }
        #[pygetset]
        fn opcode(&self) -> String {
            dns::opcode_name(self.header.opcode)
        }
        #[pygetset]
        fn authoritative(&self) -> bool {
            self.header.authoritative
        }
        #[pygetset]
        fn truncated(&self) -> bool {
            self.header.truncated
        }
        #[pygetset]
        fn recursion_desired(&self) -> bool {
            self.header.recursion_desired
        }
        #[pygetset]
        fn recursion_available(&self) -> bool {
            self.header.recursion_available
        }
        #[pygetset]
        fn authenticated_data(&self) -> bool {
            self.header.authenticated_data
        }
        #[pygetset]
        fn checking_disabled(&self) -> bool {
            self.header.checking_disabled
        }
        #[pygetset]
        fn response_code(&self) -> String {
            dns::rcode_name(self.header.response_code)
        }
        /// Number of bytes after the last section (not interpreted)
        #[pygetset]
        fn trailing_len(&self) -> usize {
            self.trailing_len
        }

        #[pygetset]
        fn questions(&self, vm: &VirtualMachine) -> Vec<PyObjectRef> {
            self.questions
                .iter()
                .cloned()
                .map(|q| q.to_pyobject(vm))
                .collect()
        }
        #[pygetset]
        fn answers(&self, vm: &VirtualMachine) -> Vec<PyObjectRef> {
            self.answers
                .iter()
                .cloned()
                .map(|q| q.to_pyobject(vm))
                .collect()
        }
        #[pygetset]
        fn nameservers(&self, vm: &VirtualMachine) -> Vec<PyObjectRef> {
            self.nameservers
                .iter()
                .cloned()
                .map(|q| q.to_pyobject(vm))
                .collect()
        }
        #[pygetset]
        fn additional(&self, vm: &VirtualMachine) -> Vec<PyObjectRef> {
            self.additional
                .iter()
                .cloned()
                .map(|q| q.to_pyobject(vm))
                .collect()
        }
        #[pygetset]
        fn opt(&self) -> Option<Record> {
            self.opt.clone()
        }
    }

    fn labels_to_py(name: &dns::Name, vm: &VirtualMachine) -> PyObjectRef {
        let labels: Vec<PyObjectRef> = name
            .labels()
            .iter()
            .map(|l| vm.ctx.new_bytes(l.clone()).into())
            .collect();
        vm.ctx.new_list(labels).into()
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "Question")]
    #[derive(Clone, Debug, PyPayload)]
    struct Question {
        inner: dns::Question,
    }
    #[pyclass]
    impl Question {
        /// Name in presentation format (labels joined by '.', with '.', '\\' and
        /// non-printable octets inside labels backslash-escaped), as bytes
        #[pygetset]
        fn qname(&self) -> rustpython_vm::builtins::PyBytes {
            rustpython_vm::builtins::PyBytes::from(self.inner.qname.to_string().into_bytes())
        }
        /// Raw labels of the name, as a list of bytes
        #[pygetset]
        fn labels(&self, vm: &VirtualMachine) -> PyObjectRef {
            labels_to_py(&self.inner.qname, vm)
        }
        #[pygetset]
        fn prefer_unicast(&self) -> bool {
            self.inner.prefer_unicast()
        }
        /// Mnemonic, e.g. "A", "HTTPS", or "TYPE65280" for unassigned values
        #[pygetset]
        fn qtype(&self) -> String {
            dns::type_name(self.inner.qtype)
        }
        #[pygetset]
        fn qtype_code(&self) -> u16 {
            self.inner.qtype
        }
        /// Mnemonic, e.g. "IN", or "CLASS1234" for unassigned values
        #[pygetset]
        fn qclass(&self) -> String {
            dns::class_name(self.inner.qclass_value())
        }
        /// QCLASS without the mDNS unicast-response bit
        #[pygetset]
        fn qclass_code(&self) -> u16 {
            self.inner.qclass_value()
        }
    }
    impl From<dns::Question> for Question {
        fn from(inner: dns::Question) -> Self {
            Self { inner }
        }
    }

    #[pyattr]
    #[pyclass(module = "rust", name = "ResourceRecord")]
    #[derive(Clone, Debug, PyPayload)]
    struct ResourceRecord {
        inner: dns::ResourceRecord,
    }
    #[pyclass]
    impl ResourceRecord {
        #[pygetset]
        fn name(&self) -> String {
            self.inner.name.to_string()
        }
        #[pygetset]
        fn labels(&self, vm: &VirtualMachine) -> PyObjectRef {
            labels_to_py(&self.inner.name, vm)
        }
        #[pygetset]
        fn multicast_unique(&self) -> bool {
            self.inner.multicast_unique()
        }
        #[pygetset]
        fn rtype(&self) -> String {
            dns::type_name(self.inner.rtype)
        }
        #[pygetset]
        fn rtype_code(&self) -> u16 {
            self.inner.rtype
        }
        #[pygetset]
        fn cls(&self) -> String {
            dns::class_name(self.inner.class_value())
        }
        #[pygetset]
        fn cls_code(&self) -> u16 {
            self.inner.class_value()
        }
        #[pygetset]
        fn ttl(&self) -> u32 {
            self.inner.ttl_clamped()
        }
        /// Tuple whose first element names the variant, e.g. ("A", "1.2.3.4"),
        /// or ("UNKNOWN", type_code, rdata_bytes) for types not decoded
        #[pygetset]
        fn data(&self, vm: &VirtualMachine) -> PyObjectRef {
            rdata_to_py(self.inner.rtype, &self.inner.data, vm)
        }
    }
    impl From<dns::ResourceRecord> for ResourceRecord {
        fn from(inner: dns::ResourceRecord) -> Self {
            Self { inner }
        }
    }

    fn rdata_to_py(rtype: u16, data: &dns::RData, vm: &VirtualMachine) -> PyObjectRef {
        use dns::RData::*;
        match data {
            A(a) => ("A", a.to_string()).to_pyobject(vm),
            AAAA(aaaa) => ("AAAA", aaaa.to_string()).to_pyobject(vm),
            CNAME(cname) => ("CNAME", cname.to_string()).to_pyobject(vm),
            MX {
                preference,
                exchange,
            } => ("MX", *preference, exchange.to_string()).to_pyobject(vm),
            NS(ns) => ("NS", ns.to_string()).to_pyobject(vm),
            PTR(ptr) => ("PTR", ptr.to_string()).to_pyobject(vm),
            SOA {
                primary_ns,
                mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum_ttl,
            } => PyTuple::new_ref(
                vec![
                    "SOA".to_pyobject(vm),
                    primary_ns.to_string().to_pyobject(vm),
                    mailbox.to_string().to_pyobject(vm),
                    serial.to_pyobject(vm),
                    refresh.to_pyobject(vm),
                    retry.to_pyobject(vm),
                    expire.to_pyobject(vm),
                    minimum_ttl.to_pyobject(vm),
                ],
                &vm.ctx,
            )
            .into(),
            SRV {
                priority,
                weight,
                port,
                target,
            } => ("SRV", *priority, *weight, *port, target.to_string()).to_pyobject(vm),
            TXT(txt) => {
                let entries: Vec<PyObjectRef> = txt
                    .iter()
                    .map(|entry| vm.ctx.new_bytes(entry.clone()).into())
                    .collect();
                let list = vm.ctx.new_list(entries);
                ("TXT", list).to_pyobject(vm)
            }
            Unknown(raw) => {
                let raw: PyObjectRef = vm.ctx.new_bytes(raw.clone()).into();
                ("UNKNOWN", rtype, raw).to_pyobject(vm)
            }
        }
    }

    /// EDNS(0) OPT pseudo-record
    #[pyattr]
    #[pyclass(module = "rust", name = "Record")]
    #[derive(Clone, Debug, PyPayload)]
    struct Record {
        inner: dns::Opt,
    }
    #[pyclass]
    impl Record {
        /// Requestor's UDP payload size
        #[pygetset]
        fn udp(&self) -> u16 {
            self.inner.udp_payload_size
        }
        #[pygetset]
        fn extrcode(&self) -> u8 {
            self.inner.extended_rcode
        }
        #[pygetset]
        fn version(&self) -> u8 {
            self.inner.version
        }
        #[pygetset]
        fn flags(&self) -> u16 {
            self.inner.flags
        }
        /// List of (option_code, option_bytes)
        #[pygetset]
        fn options(&self, vm: &VirtualMachine) -> PyObjectRef {
            let opts: Vec<PyObjectRef> = self
                .inner
                .options
                .iter()
                .map(|(code, data)| {
                    let data: PyObjectRef = vm.ctx.new_bytes(data.clone()).into();
                    (*code, data).to_pyobject(vm)
                })
                .collect();
            vm.ctx.new_list(opts).into()
        }
    }
    impl From<dns::Opt> for Record {
        fn from(inner: dns::Opt) -> Self {
            Self { inner }
        }
    }
}

#[pymodule]
pub mod rust_tls {
    use crate::application::tls;
    use rustpython_vm::{
        builtins::PyBytesRef, convert::IntoPyException, pyclass, PyObjectRef, PyPayload, PyResult,
        VirtualMachine,
    };
    use std::io;

    /// Parse a TLS ClientHello from a raw TCP payload (TLS record format).
    #[pyfunction]
    fn parse_client_hello(bytes: PyBytesRef, vm: &VirtualMachine) -> PyResult<ClientHelloInfo> {
        let bytes = bytes.as_ref();
        let info = tls::parse_client_hello_record(bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
        Ok(ClientHelloInfo { inner: info })
    }

    /// Parse a TLS ClientHello handshake message (without TLS record header).
    #[pyfunction]
    fn parse_client_hello_message(
        bytes: PyBytesRef,
        vm: &VirtualMachine,
    ) -> PyResult<ClientHelloInfo> {
        let bytes = bytes.as_ref();
        let info = tls::parse_client_hello_message(bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
        Ok(ClientHelloInfo { inner: info })
    }

    #[pyattr]
    #[pyclass(module = "tls", name = "ClientHelloInfo")]
    #[derive(Debug, PyPayload)]
    pub struct ClientHelloInfo {
        inner: tls::ClientHelloInfo,
    }
    impl From<tls::ClientHelloInfo> for ClientHelloInfo {
        fn from(inner: tls::ClientHelloInfo) -> Self {
            Self { inner }
        }
    }
    #[pyclass]
    impl ClientHelloInfo {
        /// Server Name Indication, or None
        #[pygetset]
        fn sni(&self) -> Option<rustpython_vm::builtins::PyBytes> {
            self.inner.sni.as_ref().map(|s| rustpython_vm::builtins::PyBytes::from(s.as_bytes().to_vec()))
        }

        /// ALPN protocol names
        #[pygetset]
        fn alpn(&self, vm: &VirtualMachine) -> PyObjectRef {
            let list: Vec<PyObjectRef> = self
                .inner
                .alpn
                .iter()
                .map(|s| vm.new_pyobj(s.clone()))
                .collect();
            vm.new_pyobj(list)
        }

        /// Legacy TLS version from the ClientHello (e.g. 0x0303)
        #[pygetset]
        fn client_version(&self) -> u16 {
            self.inner.client_version
        }

        /// Supported TLS versions from the extension
        #[pygetset]
        fn supported_versions(&self, vm: &VirtualMachine) -> PyObjectRef {
            let list: Vec<PyObjectRef> = self
                .inner
                .supported_versions
                .iter()
                .map(|v| vm.new_pyobj(*v))
                .collect();
            vm.new_pyobj(list)
        }

        /// Number of cipher suites offered
        #[pygetset]
        fn cipher_suites_count(&self) -> usize {
            self.inner.cipher_suites_count
        }

        /// Number of extensions present
        #[pygetset]
        fn extensions_count(&self) -> usize {
            self.inner.extensions_count
        }
    }
}

#[pymodule]
pub mod rust_quic {
    use crate::application::quic;
    use rustpython_vm::{
        builtins::PyBytesRef, convert::IntoPyException, pyclass, PyObjectRef, PyPayload, PyResult,
        VirtualMachine,
    };
    use std::io;

    /// Parse a QUIC Initial packet from raw UDP payload.
    #[pyfunction]
    fn parse_initial(bytes: PyBytesRef, vm: &VirtualMachine) -> PyResult<QuicInitialInfo> {
        let bytes = bytes.as_ref();
        let info = quic::parse_quic_initial(bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
        Ok(QuicInitialInfo { inner: info })
    }

    #[pyattr]
    #[pyclass(module = "quic", name = "QuicInitialInfo")]
    #[derive(Debug, PyPayload)]
    pub struct QuicInitialInfo {
        inner: quic::QuicInitialInfo,
    }
    #[pyclass]
    impl QuicInitialInfo {
        /// QUIC version number
        #[pygetset]
        fn version(&self) -> u32 {
            self.inner.version
        }

        /// Destination Connection ID as bytes
        #[pygetset]
        fn dcid(&self, vm: &VirtualMachine) -> PyObjectRef {
            vm.new_pyobj(self.inner.dcid.clone())
        }

        /// Source Connection ID as bytes
        #[pygetset]
        fn scid(&self, vm: &VirtualMachine) -> PyObjectRef {
            vm.new_pyobj(self.inner.scid.clone())
        }

        /// SNI from the TLS ClientHello, if found
        #[pygetset]
        fn sni(&self) -> Option<rustpython_vm::builtins::PyBytes> {
            self.inner.sni().map(|s| rustpython_vm::builtins::PyBytes::from(s.as_bytes().to_vec()))
        }

        /// ALPN protocols from the TLS ClientHello, if found
        #[pygetset]
        fn alpn(&self, vm: &VirtualMachine) -> PyObjectRef {
            let list: Vec<PyObjectRef> = self
                .inner
                .client_hello
                .as_ref()
                .map(|ch| ch.alpn.iter().map(|s| vm.new_pyobj(s.clone())).collect())
                .unwrap_or_default();
            vm.new_pyobj(list)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid IPv4+TCP packet as raw bytes.
    /// Returns the raw IP-layer bytes (no ethernet frame).
    fn build_ipv4_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        // TCP header: 20 bytes minimum (data offset = 5)
        let tcp_len = 20 + payload.len();
        let total_len = 20 + tcp_len; // IP header (20) + TCP + payload
        let mut buf = vec![0u8; total_len];

        // IPv4 header (20 bytes)
        buf[0] = 0x45; // version=4, IHL=5
        buf[2] = (total_len >> 8) as u8;
        buf[3] = total_len as u8;
        buf[8] = 64; // TTL
        buf[9] = 6; // Protocol = TCP
        buf[12..16].copy_from_slice(&src_ip);
        buf[16..20].copy_from_slice(&dst_ip);

        // IPv4 checksum
        let checksum = ipv4_checksum(&buf[..20]);
        buf[10] = (checksum >> 8) as u8;
        buf[11] = checksum as u8;

        // TCP header (20 bytes at offset 20)
        let tcp = &mut buf[20..];
        tcp[0] = (src_port >> 8) as u8;
        tcp[1] = src_port as u8;
        tcp[2] = (dst_port >> 8) as u8;
        tcp[3] = dst_port as u8;
        tcp[12] = 5 << 4; // data offset = 5 (20 bytes)
        // Copy payload
        tcp[20..20 + payload.len()].copy_from_slice(payload);

        buf
    }

    /// Helper: build a minimal valid IPv4+UDP packet as raw bytes.
    fn build_ipv4_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut buf = vec![0u8; total_len];

        // IPv4 header
        buf[0] = 0x45;
        buf[2] = (total_len >> 8) as u8;
        buf[3] = total_len as u8;
        buf[8] = 64;
        buf[9] = 17; // Protocol = UDP
        buf[12..16].copy_from_slice(&src_ip);
        buf[16..20].copy_from_slice(&dst_ip);

        let checksum = ipv4_checksum(&buf[..20]);
        buf[10] = (checksum >> 8) as u8;
        buf[11] = checksum as u8;

        // UDP header (8 bytes at offset 20)
        let udp = &mut buf[20..];
        udp[0] = (src_port >> 8) as u8;
        udp[1] = src_port as u8;
        udp[2] = (dst_port >> 8) as u8;
        udp[3] = dst_port as u8;
        udp[4] = (udp_len >> 8) as u8;
        udp[5] = udp_len as u8;
        // Copy payload
        udp[8..8 + payload.len()].copy_from_slice(payload);

        buf
    }

    /// Helper: build a minimal valid IPv6+TCP packet as raw bytes.
    fn build_ipv6_tcp_packet(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let total_len = 40 + tcp_len; // IPv6 header (40) + TCP + payload
        let mut buf = vec![0u8; total_len];

        // IPv6 header (40 bytes)
        buf[0] = 0x60; // version=6
        buf[4] = (tcp_len >> 8) as u8;
        buf[5] = tcp_len as u8; // payload length
        buf[6] = 6; // next header = TCP
        buf[7] = 64; // hop limit
        buf[8..24].copy_from_slice(&src_ip);
        buf[24..40].copy_from_slice(&dst_ip);

        // TCP header (20 bytes at offset 40)
        let tcp = &mut buf[40..];
        tcp[0] = (src_port >> 8) as u8;
        tcp[1] = src_port as u8;
        tcp[2] = (dst_port >> 8) as u8;
        tcp[3] = dst_port as u8;
        tcp[12] = 5 << 4;
        tcp[20..20 + payload.len()].copy_from_slice(payload);

        buf
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..header.len()).step_by(2) {
            if i == 10 {
                continue; // skip checksum field
            }
            let word = (header[i] as u32) << 8
                | if i + 1 < header.len() {
                    header[i + 1] as u32
                } else {
                    0
                };
            sum += word;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    // ---- Packet parsing tests ----

    #[test]
    fn parse_ipv4_tcp_packet() {
        let raw = build_ipv4_tcp_packet(
            [192, 168, 1, 1],
            [10, 0, 0, 1],
            12345,
            80,
            b"GET / HTTP/1.1\r\n",
        );
        let packet = Packet::from_ts_bytes(Some(1.0), &raw, EthernetProtocol::Ipv4).unwrap();
        assert_eq!(packet.timestamp, Some(1.0));
        assert_eq!(packet.ip.hop_limit, 64);
        assert_eq!(packet.ip.next_header, IpProtocol::Tcp);
        assert_eq!(packet.transport.src, 12345);
        assert_eq!(packet.transport.dst, 80);
        assert_eq!(packet.payload, b"GET / HTTP/1.1\r\n");
        assert!(matches!(
            packet.ip.version,
            IpVersionMetadata::V4 { .. }
        ));
        if let IpVersionMetadata::V4 { src, dst, .. } = packet.ip.version {
            assert_eq!(src, Ipv4Address::new(192, 168, 1, 1));
            assert_eq!(dst, Ipv4Address::new(10, 0, 0, 1));
        }
    }

    #[test]
    fn parse_ipv4_udp_packet() {
        let raw = build_ipv4_udp_packet(
            [8, 8, 8, 8],
            [192, 168, 1, 100],
            53,
            45000,
            b"\x00\x01\x02\x03",
        );
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4).unwrap();
        assert_eq!(packet.timestamp, None);
        assert_eq!(packet.transport.src, 53);
        assert_eq!(packet.transport.dst, 45000);
        assert_eq!(packet.payload, b"\x00\x01\x02\x03");
        assert!(matches!(
            packet.transport.extra,
            TransportMetadataExtra::Udp(_)
        ));
    }

    #[test]
    fn parse_ipv6_tcp_packet() {
        let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let raw = build_ipv6_tcp_packet(src_ip, dst_ip, 443, 50000, b"hello");
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv6).unwrap();
        assert_eq!(packet.ip.hop_limit, 64);
        assert_eq!(packet.transport.src, 443);
        assert_eq!(packet.transport.dst, 50000);
        assert_eq!(packet.payload, b"hello");
        assert!(matches!(
            packet.ip.version,
            IpVersionMetadata::V6 { .. }
        ));
    }

    #[test]
    fn parse_unknown_ethertype_fails() {
        let raw = vec![0u8; 40];
        let result = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Unknown(0x9999));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParsePacketError::UnknownInternet(_)
        ));
    }

    #[test]
    fn parse_truncated_ipv4_fails() {
        let raw = vec![0x45, 0x00]; // Too short
        let result = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_transport_fails() {
        // IPv4 packet with protocol = GRE (47), not TCP/UDP
        let mut buf = vec![0u8; 40];
        buf[0] = 0x45;
        buf[2] = 0;
        buf[3] = 40;
        buf[8] = 64;
        buf[9] = 47; // GRE
        buf[12..16].copy_from_slice(&[10, 0, 0, 1]);
        buf[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let checksum = ipv4_checksum(&buf[..20]);
        buf[10] = (checksum >> 8) as u8;
        buf[11] = checksum as u8;

        let result = Packet::from_ts_bytes(None, &buf, EthernetProtocol::Ipv4);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParsePacketError::UnknownTransport(_)
        ));
    }

    // ---- Entropy tests ----

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_single_byte() {
        // All same bytes: zero entropy
        assert_eq!(shannon_entropy(&[0xAA; 100]), 0.0);
    }

    #[test]
    fn entropy_two_values() {
        // Equal distribution of two values → entropy = 1 bit / 8 = 0.125
        let data: Vec<u8> = (0..200).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
        let e = shannon_entropy(&data);
        assert!((e - 0.125).abs() < 0.001, "entropy was {e}");
    }

    #[test]
    fn entropy_uniform() {
        // All 256 byte values equally: maximum entropy = 1.0
        let data: Vec<u8> = (0..=255).cycle().take(256 * 4).collect();
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.001, "entropy was {e}");
    }

    #[test]
    fn entropy_high_for_random_like() {
        // Pseudo-random-ish data should have high entropy
        let data: Vec<u8> = (0..1000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let e = shannon_entropy(&data);
        assert!(e > 0.8, "entropy was {e}");
    }

    // ---- Popcount tests ----

    #[test]
    fn popcount_all_zeros() {
        let p = Packet {
            timestamp: None,
            tls_client_hello: None,
            ip: IpMetadata {
                header_len: 20,
                total_len: 40,
                hop_limit: 64,
                next_header: IpProtocol::Tcp,
                version: IpVersionMetadata::V4 {
                    src: Ipv4Address::new(0, 0, 0, 0),
                    dst: Ipv4Address::new(0, 0, 0, 0),
                    dscp: 0, ecn: 0, ident: 0,
                    dont_frag: false, more_frags: false,
                    frag_offset: 0, checksum: 0,
                },
            },
            direction: 0,
            transport: TransportMetadata {
                src: 0,
                dst: 0,
                extra: TransportMetadataExtra::Tcp(TcpMetadata {
                    seq: TcpSeqNumber(0),
                    ack: TcpSeqNumber(0),
                    header_len: 20,
                    flags: TcpFlags {
                        fin: false, syn: false, rst: false, psh: false,
                        ack: false, urg: false, ece: false, cwr: false, ns: false,
                    },
                    window_len: 0,
                    urgent_at: 0,
                }),
            },
            payload: vec![0x00; 10],
        };
        assert_eq!(p.payload_average_popcount(), 0.0);
    }

    #[test]
    fn popcount_all_ones() {
        let p = Packet {
            timestamp: None,
            tls_client_hello: None,
            ip: IpMetadata {
                header_len: 20,
                total_len: 40,
                hop_limit: 64,
                next_header: IpProtocol::Tcp,
                version: IpVersionMetadata::V4 {
                    src: Ipv4Address::new(0, 0, 0, 0),
                    dst: Ipv4Address::new(0, 0, 0, 0),
                    dscp: 0, ecn: 0, ident: 0,
                    dont_frag: false, more_frags: false,
                    frag_offset: 0, checksum: 0,
                },
            },
            direction: 0,
            transport: TransportMetadata {
                src: 0,
                dst: 0,
                extra: TransportMetadataExtra::Tcp(TcpMetadata {
                    seq: TcpSeqNumber(0),
                    ack: TcpSeqNumber(0),
                    header_len: 20,
                    flags: TcpFlags {
                        fin: false, syn: false, rst: false, psh: false,
                        ack: false, urg: false, ece: false, cwr: false, ns: false,
                    },
                    window_len: 0,
                    urgent_at: 0,
                }),
            },
            payload: vec![0xFF; 10],
        };
        assert_eq!(p.payload_average_popcount(), 8.0);
    }

    // ---- ConnectionIdentifier tests ----

    #[test]
    fn connection_identifier_basic() {
        let raw = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"");
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4).unwrap();
        let id = packet.connection_identifier();
        assert_eq!(id.transport_proto, TransportProtocol::Tcp);
    }

    #[test]
    fn connection_identifier_direction_same() {
        let raw1 = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"hello");
        let raw2 = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"world");
        let p1 = Packet::from_ts_bytes(None, &raw1, EthernetProtocol::Ipv4).unwrap();
        let p2 = Packet::from_ts_bytes(None, &raw2, EthernetProtocol::Ipv4).unwrap();
        let id1 = p1.connection_identifier();
        let id2 = p2.connection_identifier();
        assert!(matches!(
            id1.direction(&id2),
            Some(Direction::FromInitiator)
        ));
    }

    #[test]
    fn connection_identifier_direction_reverse() {
        let raw1 = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"");
        let raw2 = build_ipv4_tcp_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, b"");
        let p1 = Packet::from_ts_bytes(None, &raw1, EthernetProtocol::Ipv4).unwrap();
        let p2 = Packet::from_ts_bytes(None, &raw2, EthernetProtocol::Ipv4).unwrap();
        let id1 = p1.connection_identifier();
        let id2 = p2.connection_identifier();
        assert!(matches!(
            id1.direction(&id2),
            Some(Direction::ToInitiator)
        ));
    }

    #[test]
    fn connection_identifier_direction_unrelated() {
        let raw1 = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"");
        let raw2 = build_ipv4_tcp_packet([172, 16, 0, 1], [172, 16, 0, 2], 5555, 443, b"");
        let p1 = Packet::from_ts_bytes(None, &raw1, EthernetProtocol::Ipv4).unwrap();
        let p2 = Packet::from_ts_bytes(None, &raw2, EthernetProtocol::Ipv4).unwrap();
        let id1 = p1.connection_identifier();
        let id2 = p2.connection_identifier();
        assert!(id1.direction(&id2).is_none());
    }

    #[test]
    fn connection_identifier_order_by_port() {
        let raw = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 80, 1234, b"");
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4).unwrap();
        let id = packet.connection_identifier();
        let ordered = id.order_by_port();
        assert_eq!(ordered.ports, (80, 1234));
    }

    // ---- TransportMetadata fields ----

    #[test]
    fn tcp_metadata_fields() {
        let raw = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 8080, 443, b"data");
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4).unwrap();
        assert!(matches!(
            packet.transport.extra,
            TransportMetadataExtra::Tcp(TcpMetadata { header_len: 20, .. })
        ));
        assert_eq!(packet.transport.extra.protocol(), TransportProtocol::Tcp);
    }

    #[test]
    fn udp_metadata_fields() {
        let raw = build_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 53, 12345, b"query");
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4).unwrap();
        if let TransportMetadataExtra::Udp(udp) = packet.transport.extra {
            assert_eq!(udp.length, 8 + 5); // header + payload
        } else {
            panic!("expected UDP metadata");
        }
    }

    // ---- IpMetadata accessors ----

    #[test]
    fn ip_metadata_v4_fields() {
        let raw = build_ipv4_tcp_packet([192, 168, 0, 1], [192, 168, 0, 2], 1000, 2000, b"");
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4).unwrap();
        assert_eq!(packet.ip.header_len, 20);
        assert_eq!(packet.ip.hop_limit, 64);
        if let IpVersionMetadata::V4 { src, dst, .. } = packet.ip.version {
            assert_eq!(src, Ipv4Address::new(192, 168, 0, 1));
            assert_eq!(dst, Ipv4Address::new(192, 168, 0, 2));
        } else {
            panic!("expected IPv4");
        }
    }

    #[test]
    fn ip_metadata_v6_fields() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let raw = build_ipv6_tcp_packet(src, dst, 443, 50000, b"");
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv6).unwrap();
        assert_eq!(packet.ip.header_len, 40);
        if let IpVersionMetadata::V6 {
            src: s, dst: d, ..
        } = packet.ip.version
        {
            assert_eq!(s, Ipv6Address::from_bytes(&src));
            assert_eq!(d, Ipv6Address::from_bytes(&dst));
        } else {
            panic!("expected IPv6");
        }
    }

    // ---- Copy trait tests ----

    #[test]
    fn transport_metadata_is_copy() {
        let tm = TransportMetadata {
            src: 80,
            dst: 443,
            extra: TransportMetadataExtra::Tcp(TcpMetadata {
                seq: TcpSeqNumber(100),
                ack: TcpSeqNumber(200),
                header_len: 20,
                flags: TcpFlags {
                    fin: false, syn: true, rst: false, psh: false,
                    ack: false, urg: false, ece: false, cwr: false, ns: false,
                },
                window_len: 65535,
                urgent_at: 0,
            }),
        };
        let tm2 = tm; // Copy, not move
        assert_eq!(tm.src, tm2.src);
        assert_eq!(tm.dst, tm2.dst);
    }

    #[test]
    fn tcp_seq_ack_are_unsigned() {
        let md = TcpMetadata {
            seq: TcpSeqNumber(-1),
            ack: TcpSeqNumber(i32::MIN),
            header_len: 20,
            flags: TcpFlags {
                fin: false, syn: false, rst: false, psh: false,
                ack: true, urg: false, ece: false, cwr: false, ns: false,
            },
            window_len: 0,
            urgent_at: 0,
        };
        assert_eq!(md.seq_number(), u32::MAX);
        assert_eq!(md.ack_number(), 1u32 << 31);
    }

    // ---- IP layer recognition (IPv6 extension headers, fragments) ----

    const V6_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const V6_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// Insert `ext` (a chain of extension headers whose first next-header byte must be
    /// patched in by the caller) between the IPv6 fixed header and its payload.
    fn insert_ipv6_ext(mut raw: Vec<u8>, first_ext: u8, ext: &[u8]) -> Vec<u8> {
        raw[6] = first_ext;
        let payload_len = u16::from_be_bytes([raw[4], raw[5]]) as usize + ext.len();
        raw[4] = (payload_len >> 8) as u8;
        raw[5] = payload_len as u8;
        raw.splice(40..40, ext.iter().copied());
        raw
    }

    #[test]
    fn parse_ipv6_tcp_behind_extension_headers() {
        let raw = build_ipv6_tcp_packet(V6_SRC, V6_DST, 50000, 443, b"hi");
        // Hop-by-hop (8 bytes, PadN) -> Destination options (16 bytes) -> Routing (8) -> TCP
        let mut ext = vec![60, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&[43, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        ext.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        let raw = insert_ipv6_ext(raw, 0, &ext);
        let packet = Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv6).unwrap();
        assert_eq!(packet.ip.next_header, IpProtocol::Tcp);
        assert_eq!(packet.transport.src, 50000);
        assert_eq!(packet.transport.dst, 443);
        assert_eq!(packet.payload, b"hi");
    }

    #[test]
    fn parse_ipv6_first_fragment_reaches_tcp() {
        let raw = build_ipv6_tcp_packet(V6_SRC, V6_DST, 50000, 443, b"hi");
        // Fragment header: next=TCP, offset 0, M=1
        let raw = insert_ipv6_ext(raw, 44, &[6, 0, 0, 1, 0, 0, 0, 7]);
        let layer = IpLayer::parse(&raw, EthernetProtocol::Ipv6).unwrap();
        assert_eq!(layer.protocol, IpProtocol::Tcp);
        assert!(layer.has_upper_header);
        let packet = Packet::from_ip_layer(None, &layer).unwrap();
        assert_eq!(packet.transport.dst, 443);
    }

    #[test]
    fn parse_ipv6_non_first_fragment_has_no_upper_header() {
        let raw = build_ipv6_tcp_packet(V6_SRC, V6_DST, 50000, 443, b"hi");
        // Fragment header: next=TCP, offset 1 (8 bytes)
        let raw = insert_ipv6_ext(raw, 44, &[6, 0, 0, 8, 0, 0, 0, 7]);
        let layer = IpLayer::parse(&raw, EthernetProtocol::Ipv6).unwrap();
        assert_eq!(layer.protocol, IpProtocol::Tcp);
        assert!(!layer.has_upper_header);
        assert!(matches!(
            Packet::from_ip_layer(None, &layer),
            Err(ParsePacketError::NonFirstFragment)
        ));
    }

    #[test]
    fn parse_ipv6_truncated_extension_header_fails() {
        let raw = build_ipv6_tcp_packet(V6_SRC, V6_DST, 50000, 443, b"");
        // Hop-by-hop claims 8 * (1 + 200) bytes, far beyond the packet
        let raw = insert_ipv6_ext(raw, 0, &[6, 200, 1, 4, 0, 0, 0, 0]);
        assert!(matches!(
            IpLayer::parse(&raw, EthernetProtocol::Ipv6),
            Err(ParsePacketError::Ipv6ExtHeader(_))
        ));
    }

    #[test]
    fn parse_ipv6_icmpv6() {
        let mut raw = build_ipv6_tcp_packet(V6_SRC, V6_DST, 0, 0, b"");
        raw[6] = 58; // ICMPv6
        let layer = IpLayer::parse(&raw, EthernetProtocol::Ipv6).unwrap();
        assert_eq!(layer.protocol, IpProtocol::Icmpv6);
        assert!(matches!(
            Packet::from_ip_layer(None, &layer),
            Err(ParsePacketError::UnknownTransport(IpProtocol::Icmpv6))
        ));
    }

    #[test]
    fn parse_ipv4_non_first_fragment_has_no_upper_header() {
        let mut raw = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, b"hi");
        // fragment offset = 1 (8 bytes)
        raw[6] = 0;
        raw[7] = 1;
        raw[10] = 0;
        raw[11] = 0;
        let ck = ipv4_checksum(&raw[..20]);
        raw[10] = (ck >> 8) as u8;
        raw[11] = ck as u8;
        let layer = IpLayer::parse(&raw, EthernetProtocol::Ipv4).unwrap();
        assert_eq!(layer.protocol, IpProtocol::Tcp);
        assert!(!layer.has_upper_header);
        assert!(matches!(
            Packet::from_ts_bytes(None, &raw, EthernetProtocol::Ipv4),
            Err(ParsePacketError::NonFirstFragment)
        ));
    }
}
