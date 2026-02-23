use crate::censor::{Action, Direction, IpPair};
use crate::model::ModelThreadMessage;
use crate::program::config::Config as ProgramConfig;
use crate::program::env::ProgramEnv;
use crate::program::packet::rust_dns;
use crate::program::packet::rust_quic;
use crate::program::packet::rust_tls;
use crate::program::packet::rust_packet::{self, Model as PythonModel, Packet as PythonPacket};
use crate::program::packet::TransportMetadataExtra;
use crate::program::packet::{Packet, TransportProtocol};
use crate::program::program::{Action as ProgramAction, Program, ProgramLoadError};
use ort::Error as OrtError;
use rustpython_vm::builtins::{PyBaseExceptionRef, PyCode};
use rustpython_vm::convert::ToPyObject;
use rustpython_vm::scope::Scope;
use rustpython_vm::{self as vm, PyRef, Settings};
use serde::Deserialize;
use smoltcp::wire::Error as SmoltcpError;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, TcpSeqNumber,
};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use thiserror::Error;
use tracing::error;

/// Connection key is an identifier that will always resolve to the same value for a connection
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionKey {
    /// Lower (by sorting) IP addr
    addr_low: IpAddress,
    /// Higher (by sorting) IP addr
    addr_high: IpAddress,
    /// Lower (by sorting IP) port
    port_low: u16,
    /// Higher (by sorting IP) port
    port_high: u16,
    /// Protocol
    proto: TransportProtocol,
}
impl ConnectionKey {
    /// Constructor for a connection key
    pub fn new(ips: IpPair, port_1: u16, port_2: u16, proto: TransportProtocol) -> Self {
        // Extract IPs
        let ip_1 = ips.src();
        let ip_2 = ips.dst();
        // Place values based on sorting IPs
        // Sort by IP to ensure symmetric keys (port sort alternative benchmarked in TODO.md)
        let (addr_low, addr_high, port_low, port_high) = if ip_1 <= ip_2 {
            (ip_1, ip_2, port_1, port_2)
        } else {
            (ip_2, ip_1, port_2, port_1)
        };
        // Construct the key
        Self {
            addr_low,
            addr_high,
            port_low,
            port_high,
            proto,
        }
    }
}

/// Aggregate object used to manage state for many different connections
pub struct TransportState {
    /// Internal tracker for connections
    connections: HashMap<ConnectionKey, ConnectionInfo>,
    /// Execution mode
    execution_mode: ExecutionMode,
    /// Interpreter used for executing all python code
    vm: vm::Interpreter,
    /// Code that is run by interpreter on the first packet
    code: PyRef<PyCode>,
    /// Code that is run by interpreter on each packet
    process: PyRef<PyCode>,
    /// Sender used to make requests of the model executor
    model_sender: mpsc::SyncSender<ModelThreadMessage>,
    /// CensorLang program (when in CensorLang mode)
    censorlang_program: Option<Program>,
    /// CensorLang program config
    censorlang_config: ProgramConfig,
}

#[derive(Debug)]
pub struct ConnectionInfo {
    env: ExecutionEnvironment,
    is_first: bool,
}

#[derive(Debug, Error)]
pub enum TransportStateInitError {
    #[error("Failed to initialize Python environment: {0:?}")]
    PythonInit(PyBaseExceptionRef),
    #[error("Failed to do something with ONNX: {0}")]
    OnnxError(#[from] OrtError),
    #[error("Could not find input named float_input with dimensions 1xN for model {name}")]
    CouldNotFindModelInput { name: String },
    #[error("Could not find output named probabilities with dimensions 1xN for model {name}")]
    CouldNotFindModelOutput { name: String },
    #[error("Failed to load script: {0}")]
    ReadScript(io::Error),
    #[error("Failed to load program: {0}")]
    ProgramLoad(#[from] ProgramLoadError),
    #[error("Failed to load model file: {0}")]
    ModelLoad(io::Error),
}

// Consts related to variables
const PACKET: &str = "packet";
const PROCESS: &str = "process";
const MODEL: &str = "model";

#[derive(Debug, Default, Deserialize, Clone, Copy)]
pub enum ExecutionMode {
    #[default]
    Python,
    CensorLang,
}

/// Execution environment
#[derive(Debug)]
pub enum ExecutionEnvironment {
    Python { scope: Scope },
    CensorLang { env: ProgramEnv },
}

impl TransportState {
    pub fn new(
        _model_config: HashMap<String, crate::config::model::Model>,
        _decision_log_path: Option<PathBuf>,
        execution_config: crate::config::execution::Config,
        model_sender: mpsc::SyncSender<ModelThreadMessage>,
    ) -> Result<Self, TransportStateInitError> {
        // Initialize interpreter settings
        let mut settings: Settings = Default::default();
        //settings.isolated = true;
        // Don't have the python subprograms implement sigint
        settings.install_signal_handlers = false;
        settings.hash_seed = Some(execution_config.hash_seed);
        // Want to make sure nothing is passed
        settings.argv = Vec::new();
        // settings.stdio_unbuffered = true;
        // -OO optimization
        settings.optimize = 2;
        // Initialize the interpreter
        let vm = vm::Interpreter::with_init(settings, |vm| {
            // Import the native rust module used to define the packet interface
            vm.add_native_module("rust".to_owned(), Box::new(rust_packet::make_module));
            // Import the native rust module used for dns parsing
            vm.add_native_module("dns".to_owned(), Box::new(rust_dns::make_module));
            // Import the native rust module used for TLS ClientHello parsing
            vm.add_native_module("tls".to_owned(), Box::new(rust_tls::make_module));
            // Import the native rust module used for QUIC Initial parsing
            vm.add_native_module("quic".to_owned(), Box::new(rust_quic::make_module));
        });
        let (code, process) = if let Some(ref script_path) = execution_config.script {
            let source = std::fs::read_to_string(script_path)
                .map_err(TransportStateInitError::ReadScript)?;
            // Do some initialization tasks, eventually returning the compiled code object
            vm.enter(move |vm| {
                // Import the native module so types work
                vm.import("rust", 0)?;
                let source = &source;
                // Compile the given source code
                let code = vm
                    .compile(source, vm::compiler::Mode::Exec, "<embedded>".to_owned())
                    .map_err(|err| vm.new_syntax_error(&err, Some(source)))?;
                let process_source = "process(packet)";
                let process = vm
                    .compile(
                        process_source,
                        vm::compiler::Mode::Exec,
                        "<embedded>".to_owned(),
                    )
                    .map_err(|err| vm.new_syntax_error(&err, Some(process_source)))?;
                Ok((code, process))
            })
            .map_err(TransportStateInitError::PythonInit)?
        } else {
            vm.enter(move |vm| {
                // Import the native module so types work
                vm.import("rust", 0)?;
                let source = "";
                // Compile the given source code
                let code = vm
                    .compile(source, vm::compiler::Mode::Exec, "<embedded>".to_owned())
                    .map_err(|err| vm.new_syntax_error(&err, Some(source)))?;
                let process_source = "";
                let process = vm
                    .compile(
                        process_source,
                        vm::compiler::Mode::Exec,
                        "<embedded>".to_owned(),
                    )
                    .map_err(|err| vm.new_syntax_error(&err, Some(process_source)))?;
                Ok((code, process))
            })
            .map_err(TransportStateInitError::PythonInit)?
        };
        // Load CensorLang program if in CensorLang mode
        let censorlang_program = match execution_config.mode {
            ExecutionMode::CensorLang => {
                if let Some(ref script_path) = execution_config.script {
                    Some(
                        Program::load(script_path.clone())?,
                    )
                } else {
                    Some(Program::default())
                }
            }
            ExecutionMode::Python => None,
        };
        // Construct the overall connection manager
        Ok(TransportState {
            connections: HashMap::new(),
            execution_mode: execution_config.mode,
            vm,
            code,
            process,
            model_sender,
            censorlang_program,
            censorlang_config: ProgramConfig::default(),
        })
    }
    /// Processes the tcp packet based on its metadata and our internal state
    ///
    /// # Parameters
    /// * `src_ip` - Source IP address from the encapsulating IP payload
    /// * `dst_ip` - Destination IP address from the encapsulating IP payload
    /// * `data` - TCP Payload from an ip frame
    pub fn process(
        &mut self,
        ips: IpPair,
        direction: Direction,
        packet: Packet,
    ) -> Result<Action, SmoltcpError> {
        // Make a connection key
        let key = ConnectionKey::new(
            ips,
            packet.transport.src,
            packet.transport.dst,
            packet.transport_proto(),
        );
        let new_key = key.clone();
        // Get a reference to the tracker's packet list
        let ConnectionInfo { is_first, env } =
            self.connections.entry(new_key).or_insert_with(|| {
                // Initialize the per-connection state
                ConnectionInfo {
                    env: match self.execution_mode {
                        ExecutionMode::Python => {
                            // New connection means we should initialize a new Python scope
                            let scope = self
                                .vm
                                .enter(|vm| {
                                    // Initialize the scope
                                    let scope = vm.new_scope_with_builtins();
                                    // Return the scope
                                    Ok::<Scope, PyBaseExceptionRef>(scope)
                                })
                                .unwrap();
                            ExecutionEnvironment::Python { scope }
                        }
                        ExecutionMode::CensorLang => {
                            let env = ProgramEnv::new(
                                packet.connection_identifier(),
                                &self.censorlang_config,
                            );
                            ExecutionEnvironment::CensorLang { env }
                        }
                    },
                    is_first: true,
                }
            });
        // Copy of is_first for the execution
        let is_first_cl = *is_first;
        // If the connection is set up for a Python environment, use that
        let action = match env {
            ExecutionEnvironment::Python { scope } => {
                // Copy the code references
                let code = self.code.clone();
                let _process = self.process.clone();
                // Create a python-objectified version of the Packet struct
                let transport = packet.transport;
                let len = packet.payload.len();
                let mut packet = PythonPacket::from(packet);
                packet.set_direction(direction);
                let sender = self.model_sender.clone();
                // Run a function using the per-connection scope
                match self.vm.enter(move |vm| {
                    // Add in the current packet as an object
                    let pkt = packet.to_pyobject(vm);
                    scope.locals.set_item(PACKET, pkt, vm)?;
                    // Execute our censor program initialization
                    if is_first_cl {
                        if let Err(err) = vm.run_code_obj(code, scope.clone()) {
                            error!("Error initializing environment: {:?}", err);
                            vm.print_exception(err);
                            return Ok(Action::None);
                        }
                        let model = PythonModel::new(sender);
                        let model = model.to_pyobject(vm);
                        scope.locals.set_item(MODEL, model, vm)?;
                    }
                    // Run the per-packet code
                    let action = if let Ok(process_function) = scope.locals.get_item(PROCESS, vm) {
                        if let Some(process_callable) = process_function.to_callable() {
                            if let Ok(pkt) = scope.locals.get_item(PACKET, vm) {
                                match process_callable.invoke((pkt,), vm) {
                                    Ok(result) => match result.try_into_value(vm) {
                                        Ok(s) => {
                                            let s: String = s;
                                            match s.to_lowercase().as_str() {
                                                "reset" => {
                                                    if let TransportMetadataExtra::Tcp(
                                                        tcp_metadata,
                                                    ) = transport.extra
                                                    {
                                                        Action::Reset {
                                                            src_mac: [0; 6],
                                                            dst_mac: [0; 6],
                                                            ips,
                                                            ipid: None,
                                                            src_port: transport.src,
                                                            dst_port: transport.dst,
                                                            seq: tcp_metadata.seq,
                                                            ack: tcp_metadata.ack,
                                                            payload_len: len,
                                                            is_ack: tcp_metadata.flags.ack,
                                                        }
                                                    } else {
                                                        Action::Drop
                                                    }
                                                }
                                                "drop" => Action::Drop,
                                                "allow" => Action::None,
                                                other => {
                                                    if other.starts_with("inject") {
                                                        let _data = other
                                                            .split_ascii_whitespace()
                                                            .skip(1)
                                                            .next();
                                                        Action::None
                                                    } else {
                                                        error!(
                                                            "Unrecognized action: {}. allowing",
                                                            other
                                                        );
                                                        Action::None
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => Action::None,
                                    },
                                    Err(err) => {
                                        error!("Error calling processing function: {:?}", err);
                                        vm.print_exception(err);
                                        Action::None
                                    }
                                }
                            } else {
                                Action::None
                            }
                        } else {
                            Action::None
                        }
                    } else {
                        Action::None
                    };
                    //let result = vm.run_code_obj(process, scope.clone())?;
                    // Finally, return that everything went fine
                    Ok::<_, PyBaseExceptionRef>(action)
                }) {
                    Ok(action) => action,
                    Err(err) => {
                        self.vm.enter(|vm| vm.print_exception(err));
                        Action::None
                    }
                }
            }
            ExecutionEnvironment::CensorLang { env } => {
                // Get the program (should always exist in CensorLang mode)
                if let Some(ref program) = self.censorlang_program {
                    let field_default_on_error = self.censorlang_config.env.field_default_on_error;
                    let program_action = env.process(&packet, program, field_default_on_error);
                    // Convert program::Action to censor::Action
                    match program_action {
                        ProgramAction::Allow => Action::None,
                        ProgramAction::AllowAll => Action::Ignore,
                        ProgramAction::TerminateAll => Action::Drop,
                    }
                } else {
                    Action::None
                }
            }
        };
        if *is_first {
            *is_first = false;
        }
        Ok(action)
    }
}

const ETH_HEADER_LEN: u8 = 14;
const IPV4_HEADER_LEN: u8 = 20;
const IPV6_HEADER_LEN: u8 = 40;
const TCP_HEADER_LEN: u8 = 20;

pub fn construct_reset(
    src_mac: EthernetAddress,
    dst_mac: EthernetAddress,
    ips: IpPair,
    ipid: Option<u16>,
    src_port: u16,
    dst_port: u16,
    ack: TcpSeqNumber,
    seq: TcpSeqNumber,
) -> Result<Vec<u8>, SmoltcpError> {
    let total_length = ETH_HEADER_LEN
        + match ips {
            IpPair::V4 { .. } => IPV4_HEADER_LEN,
            IpPair::V6 { .. } => IPV6_HEADER_LEN,
        }
        + TCP_HEADER_LEN;
    let mut reset_packet = vec![0; total_length.into()];
    let mut eth_packet = EthernetFrame::new_unchecked(&mut reset_packet);
    eth_packet.set_src_addr(src_mac);
    eth_packet.set_dst_addr(dst_mac);
    match ips {
        IpPair::V4 { src, dst } => {
            eth_packet.set_ethertype(EthernetProtocol::Ipv4);
            //ttl
            eth_packet.payload_mut()[8] = 0x40;
            let mut ip_packet = Ipv4Packet::new_unchecked(eth_packet.payload_mut());
            // Set the length to the length of a TCP header
            ip_packet.set_total_len((IPV4_HEADER_LEN + TCP_HEADER_LEN).into());
            ip_packet.set_version(4);
            ip_packet.set_header_len(IPV4_HEADER_LEN);
            ip_packet.set_dscp(0x20);
            if let Some(ipid) = ipid {
                ip_packet.set_ident(ipid);
            }
            // Make sure the length is good
            ip_packet.check_len()?;
            // Store the source and dst ip addresess
            ip_packet.set_src_addr(src);
            ip_packet.set_dst_addr(dst);
            ip_packet.set_next_header(IpProtocol::Tcp);
            // Calculate the checksum
            ip_packet.fill_checksum();
            fill_reset(ip_packet.payload_mut(), ips, src_port, dst_port, ack, seq)?;
        }
        IpPair::V6 { src, dst } => {
            eth_packet.set_ethertype(EthernetProtocol::Ipv6);
            let mut ip_packet = Ipv6Packet::new_unchecked(eth_packet.payload_mut());
            // Set the length to the length of a TCP header
            ip_packet.set_payload_len(TCP_HEADER_LEN.into());
            ip_packet.set_version(6);
            // Make sure the length is good
            ip_packet.check_len()?;
            // Store the source and dst ip addresess
            ip_packet.set_src_addr(src);
            ip_packet.set_dst_addr(dst);
            ip_packet.set_next_header(IpProtocol::Tcp);
            fill_reset(ip_packet.payload_mut(), ips, src_port, dst_port, ack, seq)?;
        }
    };
    Ok(reset_packet)
}

fn fill_reset(
    ip_payload: &mut [u8],
    ips: IpPair,
    src_port: u16,
    dst_port: u16,
    ack: TcpSeqNumber,
    seq: TcpSeqNumber,
) -> Result<(), SmoltcpError> {
    let mut tcp_packet = TcpPacket::new_unchecked(ip_payload);
    tcp_packet.set_header_len(TCP_HEADER_LEN);
    tcp_packet.check_len()?;
    tcp_packet.set_src_port(src_port);
    tcp_packet.set_dst_port(dst_port);
    tcp_packet.set_ack_number(ack);
    tcp_packet.set_seq_number(seq);
    tcp_packet.clear_flags();
    tcp_packet.set_ack(true);
    tcp_packet.set_rst(true);
    tcp_packet.fill_checksum(&ips.src(), &ips.dst());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv6Address, TcpSeqNumber};

    // --- ConnectionKey tests ---

    #[test]
    fn connection_key_symmetric() {
        let ips_fwd = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        let ips_rev = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 2),
            dst: Ipv4Address::new(10, 0, 0, 1),
        };
        let key_fwd = ConnectionKey::new(ips_fwd, 1234, 80, TransportProtocol::Tcp);
        let key_rev = ConnectionKey::new(ips_rev, 80, 1234, TransportProtocol::Tcp);
        assert_eq!(key_fwd, key_rev);
    }

    #[test]
    fn connection_key_different_ips() {
        let ips_a = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        let ips_b = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 3),
        };
        let key_a = ConnectionKey::new(ips_a, 1234, 80, TransportProtocol::Tcp);
        let key_b = ConnectionKey::new(ips_b, 1234, 80, TransportProtocol::Tcp);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn connection_key_different_ports() {
        let ips = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        let key_a = ConnectionKey::new(ips.clone(), 1234, 80, TransportProtocol::Tcp);
        let key_b = ConnectionKey::new(ips, 1234, 443, TransportProtocol::Tcp);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn connection_key_different_proto() {
        let ips = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        let key_tcp = ConnectionKey::new(ips.clone(), 1234, 80, TransportProtocol::Tcp);
        let key_udp = ConnectionKey::new(ips, 1234, 80, TransportProtocol::Udp);
        assert_ne!(key_tcp, key_udp);
    }

    // --- construct_reset tests ---

    #[test]
    fn construct_reset_ipv4_produces_valid_packet() {
        let src_mac = EthernetAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let ips = IpPair::V4 {
            src: Ipv4Address::new(192, 168, 1, 1),
            dst: Ipv4Address::new(10, 0, 0, 1),
        };
        let result = construct_reset(
            src_mac,
            dst_mac,
            ips,
            Some(0x1234),
            12345,
            80,
            TcpSeqNumber(1000),
            TcpSeqNumber(2000),
        );
        let pkt = result.unwrap();
        // Total length = 14 (eth) + 20 (ipv4) + 20 (tcp) = 54
        assert_eq!(pkt.len(), 54);
        // Verify Ethernet frame
        let eth = EthernetFrame::new_unchecked(&pkt);
        assert_eq!(eth.src_addr(), src_mac);
        assert_eq!(eth.dst_addr(), dst_mac);
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        // Verify IP packet
        let ip = Ipv4Packet::new_unchecked(eth.payload());
        assert_eq!(ip.next_header(), IpProtocol::Tcp);
        assert_eq!(ip.src_addr(), Ipv4Address::new(192, 168, 1, 1));
        assert_eq!(ip.dst_addr(), Ipv4Address::new(10, 0, 0, 1));
        assert_eq!(ip.ident(), 0x1234);
        // Verify TCP packet
        let tcp = TcpPacket::new_unchecked(ip.payload());
        assert_eq!(tcp.src_port(), 12345);
        assert_eq!(tcp.dst_port(), 80);
        assert!(tcp.rst());
        assert!(tcp.ack());
        assert_eq!(tcp.ack_number(), TcpSeqNumber(1000));
        assert_eq!(tcp.seq_number(), TcpSeqNumber(2000));
    }

    #[test]
    fn construct_reset_ipv6_produces_valid_packet() {
        let src_mac = EthernetAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let ips = IpPair::V6 {
            src: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            dst: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        };
        let result = construct_reset(
            src_mac,
            dst_mac,
            ips,
            None,
            443,
            50000,
            TcpSeqNumber(500),
            TcpSeqNumber(600),
        );
        let pkt = result.unwrap();
        // Total length = 14 (eth) + 40 (ipv6) + 20 (tcp) = 74
        assert_eq!(pkt.len(), 74);
        // Verify Ethernet frame
        let eth = EthernetFrame::new_unchecked(&pkt);
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);
        // Verify IP packet
        let ip = Ipv6Packet::new_unchecked(eth.payload());
        assert_eq!(ip.next_header(), IpProtocol::Tcp);
        assert_eq!(ip.src_addr(), Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(ip.dst_addr(), Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        // Verify TCP packet
        let tcp = TcpPacket::new_unchecked(ip.payload());
        assert_eq!(tcp.src_port(), 443);
        assert_eq!(tcp.dst_port(), 50000);
        assert!(tcp.rst());
        assert!(tcp.ack());
    }
}
