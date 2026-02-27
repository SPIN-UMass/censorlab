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
}
impl Packet {
    pub fn from_ts_bytes(
        timestamp: Option<f64>,
        data: &[u8],
        ethertype: EthernetProtocol,
    ) -> Result<Packet, ParsePacketError> {
        // Dependent parsing on the payload
        // Extract IP metadata before parsing the next layer
        let (ip_metadata, payload) = {
            use EthernetProtocol::*;
            match ethertype {
                Ipv4 => {
                    let ipv4_packet =
                        Ipv4Packet::new_checked(data).map_err(ParsePacketError::IPv4)?;
                    let metadata = IpMetadata::from(&ipv4_packet);
                    (metadata, ipv4_packet.payload())
                }
                Ipv6 => {
                    let ipv6_packet =
                        Ipv6Packet::new_checked(data).map_err(ParsePacketError::IPv6)?;
                    let metadata = IpMetadata::from(&ipv6_packet);
                    (metadata, ipv6_packet.payload())
                }
                unknown => {
                    return Err(ParsePacketError::UnknownInternet(unknown));
                }
            }
        };
        // Extract transport-layer metadata
        let (transport_metadata, payload) = {
            use IpProtocol::*;
            match ip_metadata.next_header {
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
    pub fn payload_average_popcount(&self) -> f64 {
        let mut ones: u32 = 0;
        let len: u32 = self.payload.len().try_into().unwrap();
        for byte in &self.payload {
            ones += byte.count_ones();
        }
        f64::from(ones) / f64::from(len)
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
    
    use std::io;
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
                    data: metadata.clone(),
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
                    data: metadata.clone(),
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
        fn seq(&self) -> i32 {
            self.data.seq.0
        }
        #[pygetset]
        fn ack(&self) -> i32 {
            self.data.ack.0
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
            TcpFlags(self.data.flags.clone())
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
    fn regex(s: String, _vm: &VirtualMachine) -> Regex {
        let inner = RustRegex::new(&s).unwrap();
        Regex { inner }
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
        return_recv: mpsc::Receiver<Result<Vec<f64>, ModelThreadError>>,
        return_sender: mpsc::SyncSender<Result<Vec<f64>, ModelThreadError>>,
    }
    impl Model {
        pub fn new(sender: mpsc::SyncSender<ModelThreadMessage>) -> Self {
            let (return_sender, return_recv) = mpsc::sync_channel(1);
            Self {
                sender,
                return_recv,
                return_sender,
            }
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
            // Clone the return channel
            let response_channel = self.return_sender.clone();
            // Send the data over the channel, along with a return address
            self.sender
                .send(ModelThreadMessage::Request {
                    name,
                    data,
                    response_channel,
                })
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
            // Receive a new value
            let out = self
                .return_recv
                .recv()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
            // Parse the result into python values
            let out: Vec<PyObjectRef> = out.into_iter().map(|f| f.to_pyobject(vm)).collect();
            Ok(PyList::new_ref(out, &vm.ctx))
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
    use dns_parser::{Class, Header, QueryClass, QueryType};
    use rustpython_vm::convert::ToPyObject;
    use rustpython_vm::{
        builtins::PyBytesRef, builtins::PyTuple, convert::IntoPyException,
        pyclass, PyObjectRef, PyPayload, PyResult, VirtualMachine,
    };
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
        Ok(rustpython_vm::builtins::PyBytes::from(response))
    }

    #[pyfunction]
    fn parse(bytes: PyBytesRef, vm: &VirtualMachine) -> PyResult<DnsPacket> {
        let bytes = bytes.as_ref();
        // Parse packet as dns
        let dns = dns::parse_dns(bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err).into_pyexception(vm))?;
        Ok(DnsPacket {
            header: dns.header,
            questions: dns.questions.into_iter().map(Question::from).collect(),
            answers: dns.answers.into_iter().map(ResourceRecord::from).collect(),
            nameservers: dns
                .nameservers
                .into_iter()
                .map(ResourceRecord::from)
                .collect(),
            additional: dns
                .additional
                .into_iter()
                .map(ResourceRecord::from)
                .collect(),
            opt: dns.opt.map(|o| Record::from(o)),
        })
    }
    #[pyattr]
    #[pyclass(module = "rust", name = "DnsPacket")]
    #[derive(Debug, PyPayload)]
    pub struct DnsPacket {
        header: Header,
        questions: Vec<Question>,
        answers: Vec<ResourceRecord>,
        nameservers: Vec<ResourceRecord>,
        additional: Vec<ResourceRecord>,
        opt: Option<Record>,
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
            format!("{:?}", self.header.opcode)
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
            self.header.response_code.to_string()
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

    #[pyattr]
    #[pyclass(module = "rust", name = "Question")]
    #[derive(Clone, Debug, PyPayload)]
    struct Question {
        qname: String,
        prefer_unicast: bool,
        qtype: QueryType,
        qclass: QueryClass,
    }
    #[pyclass]
    impl Question {
        #[pygetset]
        fn qname(&self) -> String {
            self.qname.clone()
        }
        #[pygetset]
        fn prefer_unicast(&self) -> bool {
            self.prefer_unicast
        }
        #[pygetset]
        fn qtype(&self) -> String {
            format!("{:?}", self.qtype)
        }
        #[pygetset]
        fn qclass(&self) -> String {
            format!("{:?}", self.qclass)
        }
    }
    impl<'a> From<dns_parser::Question<'a>> for Question {
        fn from(q: dns_parser::Question<'a>) -> Self {
            Self {
                qname: q.qname.to_string(),
                prefer_unicast: q.prefer_unicast,
                qtype: q.qtype,
                qclass: q.qclass,
            }
        }
    }
    #[pyattr]
    #[pyclass(module = "rust", name = "ResourceRecord")]
    #[derive(Clone, Debug, PyPayload)]
    struct ResourceRecord {
        name: String,
        multicast_unique: bool,
        cls: Class,
        ttl: u32,
        data: RData,
    }
    #[pyclass]
    impl ResourceRecord {
        #[pygetset]
        fn name(&self) -> String {
            self.name.clone()
        }
        #[pygetset]
        fn multicast_unique(&self) -> bool {
            self.multicast_unique
        }
        #[pygetset]
        fn cls(&self) -> String {
            format!("{:?}", self.cls)
        }
        #[pygetset]
        fn ttl(&self) -> u32 {
            self.ttl
        }
        #[pygetset]
        fn data(&self, vm: &VirtualMachine) -> PyObjectRef {
            self.data.to_pyobject(vm)
        }
    }
    impl<'a> From<dns_parser::ResourceRecord<'a>> for ResourceRecord {
        fn from(r: dns_parser::ResourceRecord<'a>) -> Self {
            Self {
                name: r.name.to_string(),
                multicast_unique: r.multicast_unique,

                cls: r.cls,
                ttl: r.ttl,
                data: RData::from(r.data),
            }
        }
    }

    #[derive(Clone, Debug)]
    enum RData {
        A(Ipv4Addr),
        AAAA(Ipv6Addr),
        CNAME(String),
        MX {
            preference: u16,
            exchange: String,
        },
        NS(String),
        PTR(String),
        SOA {
            primary_ns: String,
            mailbox: String,
            serial: u32,
            refresh: u32,
            retry: u32,
            expire: u32,
            minimum_ttl: u32,
        },
        SRV {
            priority: u16,
            weight: u16,
            port: u16,
            target: String,
        },
        TXT(Vec<Vec<u8>>),
        Unknown,
    }
    impl ToPyObject for &RData {
        fn to_pyobject(self, vm: &VirtualMachine) -> PyObjectRef {
            use RData::*;
            match self {
                A(a) => ("A", a.to_string()).to_pyobject(vm),
                AAAA(aaaa) => ("AAAA", aaaa.to_string()).to_pyobject(vm),
                CNAME(cname) => ("CNAME", cname).to_pyobject(vm),
                MX {
                    preference,
                    exchange,
                } => ("MX", *preference, exchange).to_pyobject(vm),
                NS(ns) => ("NS", ns).to_pyobject(vm),
                PTR(ptr) => ("PTR", ptr).to_pyobject(vm),
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
                        primary_ns.to_pyobject(vm),
                        mailbox.to_pyobject(vm),
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
                } => ("SRV", *priority, *weight, *port, target).to_pyobject(vm),
                TXT(txt) => {
                    let entries: Vec<PyObjectRef> = txt
                        .iter()
                        .map(|entry| vm.ctx.new_bytes(entry.clone()).into())
                        .collect();
                    let list = vm.ctx.new_list(entries);
                    ("TXT", list).to_pyobject(vm)
                }
                Unknown => ("UNKNOWN",).to_pyobject(vm),
            }
        }
    }
    impl<'a> From<dns_parser::RData<'a>> for RData {
        fn from(r: dns_parser::RData<'a>) -> Self {
            use dns_parser::RData::*;
            match r {
                A(a) => RData::A(a.0),
                AAAA(aaaa) => RData::AAAA(aaaa.0),
                CNAME(cname) => RData::CNAME(cname.0.to_string()),
                MX(mx) => RData::MX {
                    preference: mx.preference,
                    exchange: mx.exchange.to_string(),
                },
                NS(ns) => RData::NS(ns.to_string()),
                PTR(ptr) => RData::PTR(ptr.0.to_string()),
                SOA(soa) => RData::SOA {
                    primary_ns: soa.primary_ns.to_string(),
                    mailbox: soa.mailbox.to_string(),
                    serial: soa.serial,
                    refresh: soa.refresh,
                    retry: soa.retry,
                    expire: soa.expire,
                    minimum_ttl: soa.minimum_ttl,
                },
                SRV(srv) => RData::SRV {
                    priority: srv.priority,
                    weight: srv.weight,
                    port: srv.port,
                    target: srv.target.to_string(),
                },
                TXT(recs) => RData::TXT(recs.iter().map(|rec| rec.to_vec()).collect()),
                Unknown(_) => RData::Unknown,
            }
        }
    }
    /// DNS OPT record — fields stored for future Python accessor exposure via `#[pygetset]`.
    #[pyattr]
    #[pyclass(module = "rust", name = "Record")]
    #[derive(Clone, Debug, PyPayload)]
    #[allow(dead_code)]
    struct Record {
        pub udp: u16,
        pub extrcode: u8,
        pub version: u8,
        pub flags: u16,
        pub data: RData,
    }
    #[pyclass]
    impl Record {}
    impl<'a> From<dns_parser::rdata::opt::Record<'a>> for Record {
        fn from(r: dns_parser::rdata::opt::Record<'a>) -> Self {
            Record {
                udp: r.udp,
                extrcode: r.extrcode,
                version: r.version,
                flags: r.flags,
                data: RData::from(r.data),
            }
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
    #[pyclass]
    impl ClientHelloInfo {
        /// Server Name Indication, or None
        #[pygetset]
        fn sni(&self) -> Option<String> {
            self.inner.sni.clone()
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
        fn sni(&self) -> Option<String> {
            self.inner.sni().map(|s| s.to_string())
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
}
