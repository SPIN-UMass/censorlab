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
    /// Transport-layer payload
    // TODO: modify this to be a reference and then we can have zero copy
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

#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct TcpMetadata {
    pub seq: TcpSeqNumber,
    pub ack: TcpSeqNumber,
    pub header_len: u8,
    pub urgent_at: u16,
    pub window_len: u16,
    pub flags: TcpFlags,
}
#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
        IpMetadata as RustIpPacket, Packet as RustPacket, TcpFlags as TcpFlagsRust, TcpMetadata,
        TransportMetadataExtra, UdpMetadata,
    };
    use crate::censor::Direction;
    use crate::model::{ModelThreadError, ModelThreadMessage};
    use regex::bytes::Regex as RustRegex;
    use rustpython_vm::convert::ToPyObject;
    use rustpython_vm::{
        builtins::PyBytesRef, builtins::PyList, builtins::PyListRef, builtins::PyStrRef,
        convert::IntoPyException, convert::ToPyResult, pyclass, PyObjectRef, PyPayload, PyResult,
        VirtualMachine,
    };
    use std::collections::HashMap;
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
    //TODO: the accessors here use pygetset. not sure about set, bit nervous about it
    //TODO: replace the clones by having these objects contain an RC
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
        //TODO: next header
        //TODO: fields specific to ip version
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
        // TODO: flags
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
}

#[pymodule]
pub mod rust_dns {
    use crate::application::dns;
    use rustpython_vm::builtins::PyBytesRef;
    use rustpython_vm::VirtualMachine;

    #[pyfunction]
    fn parse(bytes: PyBytesRef, _vm: &VirtualMachine) -> i32 {
        dns::parse_dns(bytes.as_ref());
        0
    }
}
