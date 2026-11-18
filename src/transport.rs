use crate::application::tls_stream::ClientHelloTracker;
use crate::censor::{Action, Direction, IpPair};
use crate::config::conntrack::Config as ConntrackConfig;
use crate::expiring_map::{ExpiringMap, Handle};
use crate::model::Models;
use crate::program::check::ModelSignatures;
use crate::program::config::Config as ProgramConfig;
use crate::program::env::{ProgramEnv, Registers};
use crate::program::packet::rust_dns;
use crate::program::packet::rust_quic;
use crate::program::packet::rust_tls;
use crate::program::packet::rust_packet::{self, Host as PythonHost, Model as PythonModel, Packet as PythonPacket};
use crate::program::packet::TransportMetadataExtra;
use crate::program::packet::{Packet, TransportProtocol};
use crate::program::program::{Action as ProgramAction, Program, ProgramLoadError};
use ort::Error as OrtError;
use rustpython_vm::builtins::{PyBaseExceptionRef, PyCode, PyStrInterned};
use rustpython_vm::convert::ToPyObject;
use rustpython_vm::scope::Scope;
use rustpython_vm::{self as vm, PyObjectRef, PyRef, Settings};
use serde::Deserialize;
use smoltcp::wire::Error as SmoltcpError;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, TcpSeqNumber, UdpPacket,
};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use thiserror::Error;
use crate::packet_log::error;

/// Connection key is an identifier that will always resolve to the same value for a connection
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionKey {
    /// IP addr of the lower (by sorting (IP, port)) endpoint
    addr_low: IpAddress,
    /// IP addr of the higher (by sorting (IP, port)) endpoint
    addr_high: IpAddress,
    /// Port belonging to `addr_low`
    port_low: u16,
    /// Port belonging to `addr_high`
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
        // Place values based on sorting (IP, port) endpoints so both directions
        // map to the same key. Sorting by IP alone is ambiguous when both
        // endpoints share an IP (loopback / same host), so ports break ties.
        let (addr_low, addr_high, port_low, port_high) = if (ip_1, port_1) <= (ip_2, port_2) {
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
    /// Whether (`ip`, `port`) is the `addr_low`/`port_low` endpoint of this key
    fn is_low_endpoint(&self, ip: IpAddress, port: u16) -> bool {
        self.addr_low == ip && self.port_low == port
    }
}

/// Per-host state shared across all connections from the same IP
#[derive(Debug)]
pub struct HostState {
    /// Number of connections whose first tracked packet came from this host
    pub num_connections: u32,
    /// Total number of packets seen from this host across all connections
    pub num_packets: u32,
    /// Host-level registers for CensorLang programs
    pub registers: Registers,
    /// Persistent Python dict exposed as `host.state` / `dst_host.state`
    /// (created lazily in Python mode)
    py_state: Option<PyObjectRef>,
}

/// Packet time, in microseconds
type Micros = u64;
const MICROS_PER_SEC: u64 = 1_000_000;

/// Source of "now" for connection-tracking timeouts
#[derive(Debug)]
enum Clock {
    /// Live modes: time elapsed since the tracker was created
    Monotonic(std::time::Instant),
    /// PCAP mode: the latest capture timestamp seen so far
    Packet(Micros),
}

/// Minimal TCP lifecycle: enough to know when a connection has ended so that
/// a later SYN on the same 5-tuple starts a fresh connection
#[derive(Clone, Copy, Debug, Default)]
struct TcpLifecycle {
    /// FIN seen from the `addr_low`/`port_low` endpoint
    fin_low: bool,
    /// FIN seen from the `addr_high`/`port_high` endpoint
    fin_high: bool,
    /// RST seen from either endpoint
    rst: bool,
}
impl TcpLifecycle {
    fn closed(&self) -> bool {
        self.rst || (self.fin_low && self.fin_high)
    }
}

/// Aggregate object used to manage state for many different connections
///
/// # State lifetime
/// Connection and host state is bounded (see [`crate::config::conntrack`]):
/// * A TCP connection is *closed* once a RST, or a FIN from both endpoints,
///   has been processed. Packets that follow (final ACKs, retransmissions)
///   still go to the same per-connection script state. A SYN without ACK on
///   a closed connection starts a fresh one (script initialization re-runs).
///   Closed connections are forgotten after `tcp_closed_timeout`.
/// * Open TCP connections and UDP flows are forgotten after
///   `tcp_idle_timeout` / `udp_idle_timeout` seconds without packets; a later
///   packet on the same 5-tuple starts a fresh connection.
/// * At most `max_connections` connections are tracked; beyond that the one
///   closest to expiring is evicted.
/// * Per-host state (counters, CensorLang host registers and the Python
///   `host.state`/`dst_host.state` dicts) is kept for every IP that sends or
///   receives traffic, for at most `max_hosts` hosts (least recently seen
///   evicted first) and, if `host_idle_timeout` is set, until the host has
///   been idle that long. An evicted host starts again from empty state.
pub struct TransportState {
    /// Internal tracker for connections
    connections: ExpiringMap<ConnectionKey, ConnectionInfo>,
    /// Per-host state keyed by IP
    hosts: ExpiringMap<IpAddress, HostState>,
    /// Limits on tracked state
    conntrack: ConntrackConfig,
    /// Time source for timeouts
    clock: Clock,
    /// Execution mode
    execution_mode: ExecutionMode,
    /// Interpreter used for executing all python code
    vm: vm::Interpreter,
    /// Compiled censor script, run once per connection on its first packet
    /// (None in CensorLang mode or when no Python script is configured)
    code: Option<PyRef<PyCode>>,
    /// What to do with a packet when the censor script fails
    on_script_error: ScriptErrorPolicy,
    /// The configured models, for scripts and programs to run
    loaded_models: Models,
    /// CensorLang program (when in CensorLang mode)
    censorlang_program: Option<Program>,
    /// CensorLang program config
    censorlang_config: ProgramConfig,
    /// Interned names of the per-packet script globals
    py_names: PyNames,
}

#[derive(Debug)]
pub struct ConnectionInfo {
    env: ExecutionEnvironment,
    is_first: bool,
    /// Reassembles the client's TLS ClientHello (see application::tls_stream)
    tls_hello: ClientHelloTracker,
    /// Only meaningful for TCP
    tcp: TcpLifecycle,
    /// The connection's client: the sender of the first packet seen on it
    /// (the SYN sender for TCP connections observed from the start).
    /// CensorLang host registers (`hreg`) are this host's.
    client_ip: IpAddress,
}

#[derive(Debug, Error)]
pub enum TransportStateInitError {
    #[error("Invalid censor script {}:\n{msg}", path.display())]
    InvalidScript { path: PathBuf, msg: String },
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
const HOST: &str = "host";
const DST_HOST: &str = "dst_host";

/// Interned (hash-cached) names of the globals set for every packet
#[derive(Clone, Copy)]
struct PyNames {
    packet: &'static PyStrInterned,
    host: &'static PyStrInterned,
    dst_host: &'static PyStrInterned,
}
impl PyNames {
    fn new(vm: &vm::VirtualMachine) -> Self {
        Self {
            packet: vm.ctx.intern_str(PACKET),
            host: vm.ctx.intern_str(HOST),
            dst_host: vm.ctx.intern_str(DST_HOST),
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone, Copy)]
pub enum ExecutionMode {
    #[default]
    Python,
    CensorLang,
}

/// What to do with a packet when the Python censor script fails on it
/// (`process()` raised, or the script failed to initialize for its connection).
/// Every such failure is logged either way.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum ScriptErrorPolicy {
    /// Fail open: let the packet through
    #[default]
    Allow,
    /// Fail closed: drop the packet
    Drop,
}
impl ScriptErrorPolicy {
    fn action(self) -> Action {
        match self {
            ScriptErrorPolicy::Allow => Action::None,
            ScriptErrorPolicy::Drop => Action::Drop,
        }
    }
}

/// Execution environment
#[derive(Debug)]
pub enum ExecutionEnvironment {
    Python { scope: Scope, state: PythonConnState },
    CensorLang { env: ProgramEnv },
}

/// Lifecycle of one connection's Python script environment
#[derive(Debug)]
pub enum PythonConnState {
    /// The module body has not run for this connection yet
    Uninitialized,
    /// The module body ran; this is the script's callable `process`
    Ready(PyObjectRef),
    /// The module body raised or left no callable `process` (already logged)
    Failed,
}

/// Human-readable connection label for log messages
struct ConnectionLabel {
    proto: TransportProtocol,
    ips: IpPair,
    src_port: u16,
    dst_port: u16,
}
impl ConnectionLabel {
    fn of(ips: IpPair, packet: &Packet) -> Self {
        Self {
            proto: packet.transport_proto(),
            ips,
            src_port: packet.transport.src,
            dst_port: packet.transport.dst,
        }
    }
}
impl std::fmt::Display for ConnectionLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} {}:{} -> {}:{}",
            self.proto,
            self.ips.src(),
            self.src_port,
            self.ips.dst(),
            self.dst_port
        )
    }
}

/// Render a Python exception (with traceback) as a string for logging
fn format_exception(vm: &vm::VirtualMachine, exc: &PyBaseExceptionRef) -> String {
    let mut out = String::new();
    if vm.write_exception(&mut out, exc).is_err() {
        out = format!("{exc:?}");
    }
    out.trim_end().to_owned()
}

/// Run the censor script's module body in `scope` (with `model` defined) and
/// return its `process` function, which must exist and be callable.
fn init_python_scope(
    vm: &vm::VirtualMachine,
    code: PyRef<PyCode>,
    scope: &Scope,
    loaded_models: Models,
) -> Result<PyObjectRef, String> {
    let model = PythonModel::new(loaded_models).to_pyobject(vm);
    scope
        .globals
        .set_item(MODEL, model, vm)
        .map_err(|err| format_exception(vm, &err))?;
    vm.run_code_obj(code, scope.clone())
        .map_err(|err| format_exception(vm, &err))?;
    let process = scope
        .globals
        .get_item_opt(PROCESS, vm)
        .map_err(|err| format_exception(vm, &err))?
        .ok_or_else(|| "script does not define a `process(packet)` function".to_owned())?;
    if !process.is_callable() {
        return Err(format!(
            "`process` must be callable, but it is a {}",
            process.class().name()
        ));
    }
    Ok(process)
}

/// Build the Reset action for the TCP connection a packet belongs to.
///
/// This is the only place a Reset is populated from a packet, so every source of a
/// Reset (scripts, CensorLang, config lists) targets the same connection the same way.
/// Returns `None` for non-TCP packets, which have no connection to reset.
pub fn reset_for(
    ips: IpPair,
    transport: &crate::program::packet::TransportMetadata,
    payload_len: usize,
) -> Option<Action> {
    let TransportMetadataExtra::Tcp(tcp) = transport.extra else {
        return None;
    };
    // SYN and FIN each occupy one sequence number (RFC 9293 section 3.4)
    let seg_len = payload_len + usize::from(tcp.flags.syn) + usize::from(tcp.flags.fin);
    Some(Action::Reset {
        src_mac: [0; 6],
        dst_mac: [0; 6],
        ips,
        ipid: None,
        src_port: transport.src,
        dst_port: transport.dst,
        seq: tcp.seq,
        ack: tcp.ack,
        seg_len,
        is_ack: tcp.flags.ack,
    })
}

/// [`reset_for`], falling back to Drop for traffic that has no TCP connection to reset.
pub fn reset_or_drop(
    ips: IpPair,
    transport: &crate::program::packet::TransportMetadata,
    payload_len: usize,
) -> Action {
    reset_for(ips, transport, payload_len).unwrap_or(Action::Drop)
}

/// Recognize the value returned by a PyCL `process()` call and map it to an
/// engine [`Action`].
///
/// The accepted grammar is deliberately small and fully checked before any
/// action is built:
///
/// ```text
/// None                         -> continue (Action::None)
/// "allow" | "drop" | "reset"   -> the named action
/// bytes                        -> inject these bytes as a UDP response
/// ("delay",   seconds: number) -> hold the packet for `seconds` (NFQ; wire forwards)
/// ("rewrite", {"ttl": int})    -> forward a copy with the IP TTL/hop limit set
/// ```
///
/// Anything else is logged and treated as `allow`.
fn action_from_python(
    result: PyObjectRef,
    vm: &vm::VirtualMachine,
    ips: IpPair,
    transport: &crate::program::packet::TransportMetadata,
    payload_len: usize,
) -> Action {
    use rustpython_vm::builtins::{PyBytes, PyDict, PyFloat, PyInt, PyStr, PyTuple};

    if vm.is_none(&result) {
        return Action::None;
    }
    if let Some(s) = result.payload::<PyStr>() {
        return match s.as_str().to_lowercase().as_str() {
            "reset" => reset_or_drop(ips, transport, payload_len),
            "drop" => Action::Drop,
            "allow" => Action::None,
            other => {
                error!("Unrecognized action: {}. allowing", other);
                Action::None
            }
        };
    }
    if let Some(bytes_obj) = result.payload::<PyBytes>() {
        // Bytes returned -> injection
        return Action::Inject {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ips: ips.swap(),
            src_port: transport.dst,
            dst_port: transport.src,
            payload: bytes_obj.as_ref().to_vec(),
        };
    }
    if let Some(tuple) = result.payload::<PyTuple>() {
        let items = tuple.as_slice();
        let kind = items
            .first()
            .and_then(|k| k.payload::<PyStr>())
            .map(|k| k.as_str().to_lowercase());
        match (kind.as_deref(), items.get(1)) {
            (Some("delay"), Some(arg)) if items.len() == 2 => {
                let seconds = if let Some(f) = arg.payload::<PyFloat>() {
                    Some(f.to_f64())
                } else {
                    arg.payload::<PyInt>().and_then(|i| i.try_to_primitive::<i64>(vm).ok()).map(|i| i as f64)
                };
                match seconds {
                    Some(s) if s.is_finite() && s >= 0.0 => {
                        return Action::Delay(std::time::Instant::now() + std::time::Duration::from_secs_f64(s));
                    }
                    _ => error!("(\"delay\", seconds): seconds must be a non-negative number. allowing"),
                }
                return Action::None;
            }
            (Some("rewrite"), Some(arg)) if items.len() == 2 => {
                if let Some(dict) = arg.payload::<PyDict>() {
                    let mut rewrite = crate::censor::Rewrite::default();
                    let mut ok = true;
                    for (key, value) in dict {
                        let key = key.payload::<PyStr>().map(|k| k.as_str().to_owned());
                        match key.as_deref() {
                            Some("ttl") => {
                                match value.payload::<PyInt>().and_then(|i| i.try_to_primitive::<u8>(vm).ok()) {
                                    Some(ttl) => rewrite.ttl = Some(ttl),
                                    None => {
                                        error!("(\"rewrite\", {{\"ttl\": v}}): ttl must be an int in 0..=255. allowing");
                                        ok = false;
                                    }
                                }
                            }
                            other => {
                                error!("(\"rewrite\", {{...}}): unknown field {:?}. allowing", other);
                                ok = false;
                            }
                        }
                    }
                    if ok {
                        return Action::Rewrite(rewrite);
                    }
                } else {
                    error!("(\"rewrite\", spec): spec must be a dict. allowing");
                }
                return Action::None;
            }
            _ => {
                error!("Unrecognized action tuple {:?}. allowing", tuple);
                return Action::None;
            }
        }
    }
    error!("Unrecognized return value from process(): {:?}. allowing", result);
    Action::None
}

/// The only modules a censor script may import: CensorLab's native modules
const ALLOWED_IMPORTS: &[&str] = &["rust", "dns", "tls", "quic"];

/// Native stdlib modules the interpreter itself imports while initializing
/// (stdio, importlib, codecs). They are not importable by scripts.
const INTERPRETER_INIT_MODULES: &[&str] = &[
    "_typing", "_signal", "_ast", "_io", "_thread", "_warnings", "_weakref", "_imp", "_codecs",
];

/// `builtins.__import__` replacement: only absolute imports of
/// [`ALLOWED_IMPORTS`] reach the real import machinery.
fn sandboxed_import(args: vm::function::FuncArgs, vm: &vm::VirtualMachine) -> vm::PyResult {
    use rustpython_vm::builtins::PyStr;
    let name = args.args.first().and_then(|n| n.payload::<PyStr>()).map(|n| n.as_str().to_owned());
    // __import__(name, globals=None, locals=None, fromlist=(), level=0)
    let level = args
        .args
        .get(4)
        .or_else(|| args.kwargs.get("level"))
        .map(|level| level.try_to_value::<usize>(vm))
        .transpose()?
        .unwrap_or(0);
    match name {
        Some(name) if level == 0 && ALLOWED_IMPORTS.contains(&name.as_str()) => {
            vm.import_func.call(args, vm)
        }
        name => {
            let shown = name.unwrap_or_else(|| "<non-string>".to_owned());
            Err(vm.new_import_error(
                format!(
                    "censor scripts may only import {}; '{shown}' is not available",
                    ALLOWED_IMPORTS.join(", ")
                ),
                vm.ctx.new_str(shown),
            ))
        }
    }
}

/// Build the RustPython interpreter that censor scripts run in.
///
/// Scripts run inside the censor process, which holds CAP_NET_ADMIN/CAP_NET_RAW,
/// so the interpreter is restricted to what censor scripts need:
/// - Only the native modules required to initialize the interpreter are
///   registered, plus CensorLab's own `rust`, `dns`, `tls` and `quic`; there is
///   no `posix`/`os`, `time`, `pwd`, ... and no filesystem import path.
/// - `__import__` only admits [`ALLOWED_IMPORTS`], and `sys.modules` is
///   emptied of the interpreter's own modules so they can't be re-imported
///   from the cache.
/// - `open` is removed from builtins.
///
/// This is a Python-level restriction, not an OS-level sandbox: objects that
/// exist in the interpreter (e.g. `_io` classes reachable through
/// `object.__subclasses__()`) are still reachable by introspection.
pub(crate) fn new_python_interpreter(hash_seed: u32) -> vm::Interpreter {
    // Initialize interpreter settings
    let mut settings: Settings = Default::default();
    // Ignore PYTHON* environment variables and user site-packages
    settings.isolated = true;
    settings.ignore_environment = true;
    // No filesystem-based imports (also keeps importlib from loading posix)
    settings.allow_external_library = false;
    settings.path_list = Vec::new();
    // Don't have the python subprograms implement sigint
    settings.install_signal_handlers = false;
    settings.hash_seed = Some(hash_seed);
    // Want to make sure nothing is passed
    settings.argv = Vec::new();
    // settings.stdio_unbuffered = true;
    // -OO optimization
    settings.optimize = 2;
    // Initialize the interpreter
    let interpreter = vm::Interpreter::with_init(settings, |vm| {
        // Register only the native modules the interpreter needs to start
        vm::common::rc::PyRc::get_mut(&mut vm.state)
            .expect("interpreter state is not shared during initialization")
            .module_inits
            .retain(|name, _| INTERPRETER_INIT_MODULES.contains(&name.as_ref()));
        // Import the native rust module used to define the packet interface
        vm.add_native_module("rust".to_owned(), Box::new(rust_packet::make_module));
        // Import the native rust module used for dns parsing
        vm.add_native_module("dns".to_owned(), Box::new(rust_dns::make_module));
        // Import the native rust module used for TLS ClientHello parsing
        vm.add_native_module("tls".to_owned(), Box::new(rust_tls::make_module));
        // Import the native rust module used for QUIC Initial parsing
        vm.add_native_module("quic".to_owned(), Box::new(rust_quic::make_module));
    });
    interpreter
        .enter(|vm| {
            // Gate imports
            let import = vm.new_function("__import__", sandboxed_import);
            vm.builtins.set_attr("__import__", import, vm)?;
            // Drop the interpreter's own modules from the import cache, which
            // `import x` consults before calling __import__
            vm.sys_module.set_attr("modules", vm.ctx.new_dict(), vm)?;
            // No file access
            vm.builtins.dict().del_item("open", vm)?;
            Ok::<_, PyBaseExceptionRef>(())
        })
        .unwrap_or_else(|err| {
            interpreter.enter(|vm| vm.print_exception(err));
            panic!("failed to restrict the censor-script interpreter");
        });
    interpreter
}

impl TransportState {
    pub fn new(
        model_config: HashMap<String, crate::config::model::Model>,
        _decision_log_path: Option<PathBuf>,
        execution_config: crate::config::execution::Config,
        conntrack: ConntrackConfig,
        loaded_models: Models,
    ) -> Result<Self, TransportStateInitError> {
        let vm = new_python_interpreter(execution_config.hash_seed);
        let py_names = vm.enter(PyNames::new);
        // Only compile the script as Python if we're in Python mode
        let python_script = match execution_config.mode {
            ExecutionMode::Python => execution_config.script.as_ref(),
            ExecutionMode::CensorLang => None,
        };
        let code = if let Some(script_path) = python_script {
            let source = std::fs::read_to_string(script_path)
                .map_err(TransportStateInitError::ReadScript)?;
            let filename = script_path.display().to_string();
            // Compile the script, then validate it once up front by running its
            // module body in a throwaway scope: a broken script (exception in
            // the module body, no callable `process`) fails here, at startup,
            // instead of silently on every connection.
            let validated = vm.enter(|vm| {
                // Import the native modules so their types (Model, Packet,
                // ClientHello, ...) are initialized before we construct any of them
                vm.import("rust", 0).map_err(|err| format_exception(vm, &err))?;
                vm.import("tls", 0).map_err(|err| format_exception(vm, &err))?;
                let code = vm
                    .compile(&source, vm::compiler::Mode::Exec, filename)
                    .map_err(|err| format_exception(vm, &vm.new_syntax_error(&err, Some(&source))))?;
                let scope = vm.new_scope_with_builtins();
                init_python_scope(vm, code.clone(), &scope, loaded_models.clone())?;
                Ok::<_, String>(code)
            });
            Some(validated.map_err(|msg| TransportStateInitError::InvalidScript {
                path: script_path.clone(),
                msg,
            })?)
        } else {
            None
        };
        // Load CensorLang program if in CensorLang mode
        let censorlang_program = match execution_config.mode {
            ExecutionMode::CensorLang => {
                if let Some(ref script_path) = execution_config.script {
                    // Models the program may reference.  Their input lengths
                    // are not passed in, so indices are bounded by
                    // check::MAX_MODEL_INPUTS.
                    let models: ModelSignatures =
                        model_config.keys().map(|name| (name.clone(), None)).collect();
                    // Rejects (at startup) any program that is malformed or
                    // exceeds the configured limits
                    Some(Program::load(
                        script_path.clone(),
                        &execution_config.censorlang,
                        Some(&models),
                    )?)
                } else {
                    Some(Program::default())
                }
            }
            ExecutionMode::Python => None,
        };
        // Construct the overall connection manager
        Ok(TransportState {
            connections: ExpiringMap::new(),
            hosts: ExpiringMap::new(),
            conntrack,
            clock: Clock::Monotonic(std::time::Instant::now()),
            execution_mode: execution_config.mode,
            vm,
            code,
            on_script_error: execution_config.on_script_error,
            loaded_models,
            censorlang_program,
            censorlang_config: execution_config.censorlang,
            py_names,
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
        mut packet: Packet,
    ) -> Result<Action, SmoltcpError> {
        if self.code.is_some() {
            // The script (including `__del__` on teardown) may write to
            // stdout: queued PCAP decisions go first (see crate::output)
            let _ = crate::output::flush();
        }
        // The packet's time is the connection-tracking clock's: capture time
        // in PCAP mode, seconds since startup in the live modes.
        packet.timestamp = Some(self.now() as f64 / 1e6);
        // Record the direction on the packet itself so that every execution
        // environment (PyCL and CensorLang) sees the same `direction` field.
        packet.set_direction(direction);
        // Make a connection key
        let key = ConnectionKey::new(
            ips,
            packet.transport.src,
            packet.transport.dst,
            packet.transport_proto(),
        );
        let now = self.now();
        // Forget idle state first so this packet never lands in a timed-out connection
        self.expire(now);
        let src_port = packet.transport.src;
        let tcp_flags = match packet.transport.extra {
            TransportMetadataExtra::Tcp(tcp_metadata) => Some(tcp_metadata.flags),
            _ => None,
        };
        // A bare SYN on a closed TCP connection is a new connection reusing the 5-tuple
        let is_bare_syn = tcp_flags.is_some_and(|flags| flags.syn && !flags.ack);
        // The connection is looked up once; its handle stays valid until the
        // eviction pass at the end
        let mut conn = self.connections.find(&key);
        if is_bare_syn
            && conn.is_some_and(|conn| {
                self.connections.get_at(conn).is_some_and(|c| c.tcp.closed())
            })
        {
            if let Some((_, old)) = conn.and_then(|conn| self.connections.remove_at(conn)) {
                self.teardown(vec![old.env], Vec::new());
            }
            conn = None;
        }
        let conn = match conn {
            Some(conn) => conn,
            None => {
                // Initialize the per-connection state
                let env = match self.execution_mode {
                    ExecutionMode::Python => {
                        // New connection means we should initialize a new Python scope
                        let scope = self.vm.enter(|vm| vm.new_scope_with_builtins());
                        ExecutionEnvironment::Python {
                            scope,
                            state: PythonConnState::Uninitialized,
                        }
                    }
                    ExecutionMode::CensorLang => {
                        let env = ProgramEnv::new(
                            packet.connection_identifier(),
                            &self.censorlang_config,
                        );
                        ExecutionEnvironment::CensorLang { env }
                    }
                };
                let info = ConnectionInfo {
                    env,
                    is_first: true,
                    tcp: TcpLifecycle::default(),
                    client_ip: ips.src(),
                    tls_hello: ClientHelloTracker::new(),
                };
                // The real deadline is set once the packet has been processed
                self.connections.insert_handle(key.clone(), info, now).0
            }
        };
        // Track the TLS ClientHello across segments; the result rides on the packet.
        // The tracker lives in ConnectionInfo, so it is reset along with the rest of
        // the connection state on 5-tuple reuse or expiry.
        let info = self
            .connections
            .get_mut_at(conn)
            .expect("connection was inserted above");
        packet.tls = info.tls_hello.observe_packet(&packet);
        // Copy of is_first for the execution
        let is_first_cl = info.is_first;
        let client_ip = info.client_ip;

        // Update per-host state for the source IP
        let src_ip = ips.src();
        let dst_ip = ips.dst();
        let src_host = self.touch_host(src_ip, now);
        let (host_num_connections, host_num_packets) = {
            let host = self.hosts.get_mut_at(src_host).expect("host was touched");
            host.num_packets += 1;
            if is_first_cl {
                host.num_connections += 1;
            }
            (host.num_connections, host.num_packets)
        };
        // Get dst host counters (don't increment -- dst didn't send this packet)
        let dst_host = self.touch_host(dst_ip, now);
        let (dst_host_num_connections, dst_host_num_packets) = {
            let dst_host = self.hosts.get_at(dst_host).expect("host was touched");
            (dst_host.num_connections, dst_host.num_packets)
        };
        // Per-host persistent Python dicts
        let host_dicts = match self.execution_mode {
            ExecutionMode::Python => {
                Some((self.host_py_state(src_host), self.host_py_state(dst_host)))
            }
            ExecutionMode::CensorLang => None,
        };
        // The connection's client is one of this packet's endpoints
        let client_host = if client_ip == src_ip {
            Some(src_host)
        } else if client_ip == dst_ip {
            Some(dst_host)
        } else {
            self.hosts.find(&client_ip)
        };

        let ConnectionInfo { env, .. } = self
            .connections
            .get_mut_at(conn)
            .expect("connection was inserted above");
        // If the connection is set up for a Python environment, use that
        let action = match env {
            // Python mode without a script: nothing to run
            ExecutionEnvironment::Python { .. } if self.code.is_none() => Action::None,
            ExecutionEnvironment::Python { scope, state } => {
                let on_script_error = self.on_script_error;
                let conn = ConnectionLabel::of(ips, &packet);
                let conn_ref = &conn;
                // Create a python-objectified version of the Packet struct
                let transport = packet.transport;
                let len = packet.payload.len();
                let mut packet = PythonPacket::from(packet);
                packet.set_direction(direction);
                let names = self.py_names;
                let (code, models) = (&self.code, &self.loaded_models);
                // Per-host persistent user state dicts (always present in Python mode)
                let (host_dict, dst_host_dict) =
                    host_dicts.expect("host dicts are created in Python mode");
                // Run a function using the per-connection scope
                match self.vm.enter(move |vm| {
                    // Build host object with counters + persistent state dict
                    let host = PythonHost::new(
                        host_num_connections,
                        host_num_packets,
                        host_dict,
                    );
                    let dst_host = PythonHost::new(
                        dst_host_num_connections,
                        dst_host_num_packets,
                        dst_host_dict,
                    );
                    scope
                        .locals
                        .set_item(names.host, host.to_pyobject(vm), vm)?;
                    scope
                        .locals
                        .set_item(names.dst_host, dst_host.to_pyobject(vm), vm)?;
                    // Add in the current packet as an object
                    let pkt = packet.to_pyobject(vm);
                    scope.locals.set_item(names.packet, pkt.clone(), vm)?;
                    // On the connection's first packet, run the module body and
                    // look up `process`.  A failure is logged here, once; the
                    // connection then gets the script-error policy on every packet.
                    let initialized_now = matches!(state, PythonConnState::Uninitialized);
                    if initialized_now {
                        let code = code.clone().expect("checked above");
                        *state = match init_python_scope(vm, code, scope, models.clone()) {
                            Ok(process) => PythonConnState::Ready(process),
                            Err(msg) => {
                                error!(
                                    "{conn_ref}: censor script failed to initialize; applying \
                                     on_script_error = {on_script_error:?} to the whole connection:\n{msg}"
                                );
                                PythonConnState::Failed
                            }
                        };
                    }
                    // Run the per-packet code
                    let action = match state {
                        PythonConnState::Ready(process) => {
                            // The module body may have rebound `packet`
                            let pkt = if initialized_now {
                                scope.locals.get_item(names.packet, vm)?
                            } else {
                                pkt
                            };
                            match process.call((pkt,), vm) {
                                Ok(result) => action_from_python(result, vm, ips, &transport, len),
                                Err(err) => {
                                    error!(
                                        "{conn_ref}: process() raised; applying on_script_error = \
                                         {on_script_error:?}:\n{}",
                                        format_exception(vm, &err)
                                    );
                                    on_script_error.action()
                                }
                            }
                        }
                        PythonConnState::Failed => on_script_error.action(),
                        PythonConnState::Uninitialized => unreachable!("initialized above"),
                    };
                    // Finally, return that everything went fine
                    Ok::<_, PyBaseExceptionRef>(action)
                }) {
                    Ok(action) => action,
                    Err(err) => {
                        let msg = self.vm.enter(|vm| format_exception(vm, &err));
                        error!(
                            "{conn}: failed to set up the Python environment for this packet; \
                             applying on_script_error = {on_script_error:?}:\n{msg}"
                        );
                        on_script_error.action()
                    }
                }
            }
            ExecutionEnvironment::CensorLang { env } => {
                // Get the program (should always exist in CensorLang mode)
                if let Some(ref program) = self.censorlang_program {
                    let field_default_on_error = self.censorlang_config.env.field_default_on_error;
                    // Host registers are keyed on the connection's client, so both
                    // directions of a connection share one bank (the counters
                    // above stay keyed on the packet's sender, like PyCL's `host`).
                    // Both endpoints' host states were touched above.
                    let host = client_host
                        .and_then(|client_host| self.hosts.get_mut_at(client_host))
                        .expect("both endpoint hosts were touched above");
                    let program_action = env.process(
                        &packet,
                        program,
                        field_default_on_error,
                        host_num_connections,
                        host_num_packets,
                        dst_host_num_connections,
                        dst_host_num_packets,
                        &mut host.registers,
                        Some(&self.loaded_models),
                    );
                    // Convert program::Action to censor::Action
                    match program_action {
                        ProgramAction::Allow => Action::None,
                        ProgramAction::AllowAll => Action::Ignore,
                        ProgramAction::TerminateAll => Action::Drop,
                        ProgramAction::ResetAll => {
                            reset_or_drop(ips, &packet.transport, packet.payload.len())
                        }
                    }
                } else {
                    Action::None
                }
            }
        };
        // Update the connection lifecycle now that the script has seen this packet
        let info = self
            .connections
            .get_mut_at(conn)
            .expect("connection is only removed below");
        info.is_first = false;
        if let Some(flags) = tcp_flags {
            if flags.rst {
                info.tcp.rst = true;
            }
            if flags.fin {
                if key.is_low_endpoint(src_ip, src_port) {
                    info.tcp.fin_low = true;
                } else {
                    info.tcp.fin_high = true;
                }
            }
        }
        let timeout = match key.proto {
            TransportProtocol::Tcp if info.tcp.closed() => self.conntrack.tcp_closed_timeout,
            TransportProtocol::Tcp => self.conntrack.tcp_idle_timeout,
            TransportProtocol::Udp => self.conntrack.udp_idle_timeout,
        };
        self.connections
            .set_deadline_at(conn, now.saturating_add(timeout.get().saturating_mul(MICROS_PER_SEC)));
        self.enforce_limits();
        Ok(action)
    }

    /// Use capture timestamps (see [`Self::set_packet_time`]) instead of a
    /// monotonic clock for timeouts. Used in PCAP mode.
    pub fn use_packet_clock(&mut self) {
        self.clock = Clock::Packet(0);
    }

    /// Advance the packet clock to `micros` (microseconds since the epoch).
    /// Time never moves backwards, so out-of-order timestamps are ignored.
    /// Has no effect unless [`Self::use_packet_clock`] was called.
    pub fn set_packet_time(&mut self, micros: u64) {
        if let Clock::Packet(now) = &mut self.clock {
            *now = (*now).max(micros);
        }
    }

    fn now(&self) -> Micros {
        match &self.clock {
            Clock::Monotonic(start) => start.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
            Clock::Packet(now) => *now,
        }
    }

    /// Deadline for a host's state if it is last seen at `now`. Without an
    /// idle timeout the deadline is just `now`, which orders hosts by recency
    fn host_deadline(&self, now: Micros) -> Micros {
        match self.conntrack.host_idle_timeout {
            Some(timeout) => now.saturating_add(timeout.get().saturating_mul(MICROS_PER_SEC)),
            None => now,
        }
    }

    /// Get (creating if needed) the state for host `ip` and mark it as seen at
    /// `now`. The handle stays valid until the next eviction pass.
    fn touch_host(&mut self, ip: IpAddress, now: Micros) -> Handle {
        let deadline = self.host_deadline(now);
        if let Some(host) = self.hosts.find(&ip) {
            self.hosts.set_deadline_at(host, deadline);
            return host;
        }
        let config = &self.censorlang_config;
        let host = HostState {
            num_connections: 0,
            num_packets: 0,
            registers: Registers::new(
                config.program.num_registers.into(),
                config.env.relax_register_types,
            ),
            py_state: None,
        };
        self.hosts.insert_handle(ip, host, deadline).0
    }

    /// Get (creating if needed) the persistent Python dict for a tracked host
    fn host_py_state(&mut self, host: Handle) -> PyObjectRef {
        let host = self.hosts.get_mut_at(host).expect("host was touched");
        host.py_state
            .get_or_insert_with(|| self.vm.enter(|vm| vm.ctx.new_dict().to_pyobject(vm)))
            .clone()
    }

    /// Forget connections and hosts whose idle timeout has passed
    fn expire(&mut self, now: Micros) {
        let mut envs = Vec::new();
        while let Some((_, info)) = self.connections.pop_expired(now) {
            envs.push(info.env);
        }
        let mut hosts = Vec::new();
        if self.conntrack.host_idle_timeout.is_some() {
            while let Some((_, host)) = self.hosts.pop_expired(now) {
                hosts.push(host);
            }
        }
        self.teardown(envs, hosts);
    }

    /// Evict state until the configured size caps are respected
    fn enforce_limits(&mut self) {
        let mut envs = Vec::new();
        while self.connections.len() > self.conntrack.max_connections.get() {
            match self.connections.pop_first() {
                Some((_, info)) => envs.push(info.env),
                None => break,
            }
        }
        let mut hosts = Vec::new();
        while self.hosts.len() > self.conntrack.max_hosts.get() {
            match self.hosts.pop_first() {
                Some((_, host)) => hosts.push(host),
                None => break,
            }
        }
        self.teardown(envs, hosts);
    }

    /// Release removed connection and host state
    ///
    /// Python objects are released inside the interpreter so `__del__` can
    /// run. A connection's scope is cleared first: functions defined by the
    /// script reference the scope's globals, forming a cycle that reference
    /// counting alone would never free.
    fn teardown(&self, envs: Vec<ExecutionEnvironment>, hosts: Vec<HostState>) {
        let has_python = envs
            .iter()
            .any(|env| matches!(env, ExecutionEnvironment::Python { .. }))
            || hosts.iter().any(|host| host.py_state.is_some());
        if !has_python {
            return;
        }
        self.vm.enter(|_vm| {
            for env in envs {
                if let ExecutionEnvironment::Python { scope, .. } = env {
                    scope.globals.clear();
                }
            }
            drop(hosts);
        });
    }
}

const ETH_HEADER_LEN: u8 = 14;
const IPV4_HEADER_LEN: u8 = 20;
const IPV6_HEADER_LEN: u8 = 40;
const TCP_HEADER_LEN: u8 = 20;
const UDP_HEADER_LEN: u8 = 8;
/// IPv6 hop limit for injected packets (matches the IPv4 TTL of 64; a zero
/// hop limit is discarded by the first router).
const INJECTED_HOP_LIMIT: u8 = 64;

/// Build an Ethernet/IP/TCP RST frame. With `ack: Some(n)` the RST carries the ACK
/// flag and acknowledgment number `n`; with `None` it is a bare RST.
pub fn construct_reset(
    src_mac: EthernetAddress,
    dst_mac: EthernetAddress,
    ips: IpPair,
    ipid: Option<u16>,
    src_port: u16,
    dst_port: u16,
    ack: Option<TcpSeqNumber>,
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
            ip_packet.set_hop_limit(INJECTED_HOP_LIMIT);
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
    ack: Option<TcpSeqNumber>,
    seq: TcpSeqNumber,
) -> Result<(), SmoltcpError> {
    let mut tcp_packet = TcpPacket::new_unchecked(ip_payload);
    tcp_packet.set_header_len(TCP_HEADER_LEN);
    tcp_packet.check_len()?;
    tcp_packet.set_src_port(src_port);
    tcp_packet.set_dst_port(dst_port);
    tcp_packet.set_ack_number(ack.unwrap_or(TcpSeqNumber(0)));
    tcp_packet.set_seq_number(seq);
    tcp_packet.clear_flags();
    tcp_packet.set_ack(ack.is_some());
    tcp_packet.set_rst(true);
    tcp_packet.fill_checksum(&ips.src(), &ips.dst());
    Ok(())
}

/// Construct a UDP injection packet with Ethernet/IP/UDP headers wrapping the given payload.
///
/// Used for injecting forged responses (e.g. DNS poisoning) while the original packet
/// is allowed through (racing the real server, similar to GFW behavior).
pub fn construct_udp_inject(
    src_mac: EthernetAddress,
    dst_mac: EthernetAddress,
    ips: IpPair,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, SmoltcpError> {
    let ip_header_len: u8 = match ips {
        IpPair::V4 { .. } => IPV4_HEADER_LEN,
        IpPair::V6 { .. } => IPV6_HEADER_LEN,
    };
    let udp_total_len = UDP_HEADER_LEN as usize + payload.len();
    let total_length = ETH_HEADER_LEN as usize + ip_header_len as usize + udp_total_len;
    let mut packet_buf = vec![0u8; total_length];
    let mut eth_packet = EthernetFrame::new_unchecked(&mut packet_buf);
    eth_packet.set_src_addr(src_mac);
    eth_packet.set_dst_addr(dst_mac);
    match ips {
        IpPair::V4 { src, dst } => {
            eth_packet.set_ethertype(EthernetProtocol::Ipv4);
            // TTL
            eth_packet.payload_mut()[8] = 0x40;
            let mut ip_packet = Ipv4Packet::new_unchecked(eth_packet.payload_mut());
            ip_packet.set_total_len((IPV4_HEADER_LEN as u16) + (udp_total_len as u16));
            ip_packet.set_version(4);
            ip_packet.set_header_len(IPV4_HEADER_LEN);
            ip_packet.check_len()?;
            ip_packet.set_src_addr(src);
            ip_packet.set_dst_addr(dst);
            ip_packet.set_next_header(IpProtocol::Udp);
            ip_packet.fill_checksum();
            fill_udp(ip_packet.payload_mut(), ips, src_port, dst_port, payload)?;
        }
        IpPair::V6 { src, dst } => {
            eth_packet.set_ethertype(EthernetProtocol::Ipv6);
            let mut ip_packet = Ipv6Packet::new_unchecked(eth_packet.payload_mut());
            ip_packet.set_payload_len(udp_total_len as u16);
            ip_packet.set_version(6);
            ip_packet.set_hop_limit(INJECTED_HOP_LIMIT);
            ip_packet.check_len()?;
            ip_packet.set_src_addr(src);
            ip_packet.set_dst_addr(dst);
            ip_packet.set_next_header(IpProtocol::Udp);
            fill_udp(ip_packet.payload_mut(), ips, src_port, dst_port, payload)?;
        }
    };
    Ok(packet_buf)
}

fn fill_udp(
    ip_payload: &mut [u8],
    ips: IpPair,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<(), SmoltcpError> {
    let udp_total_len = UDP_HEADER_LEN as u16 + payload.len() as u16;
    let mut udp_packet = UdpPacket::new_unchecked(ip_payload);
    udp_packet.set_src_port(src_port);
    udp_packet.set_dst_port(dst_port);
    udp_packet.set_len(udp_total_len);
    // Copy payload into the UDP packet
    udp_packet.payload_mut()[..payload.len()].copy_from_slice(payload);
    udp_packet.fill_checksum(&ips.src(), &ips.dst());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv6Address, TcpSeqNumber};

    // --- Python environment tests ---

    /// Run `source` in a fresh censor-script interpreter and return the
    /// value of the global `result` (which the source must set to a bool).
    fn run_python_bool(source: &str) -> bool {
        let interp = new_python_interpreter(1337);
        interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();
            if let Err(err) = vm.run_code_string(scope.clone(), source, "<test>".to_owned()) {
                vm.print_exception(err);
                panic!("test script raised");
            }
            let result = scope.globals.get_item("result", vm).expect("result not set");
            result.try_to_bool(vm).expect("result not a bool")
        })
    }

    #[test]
    fn python_invalid_regex_raises_value_error() {
        assert!(run_python_bool(
            "from rust import regex\n\
             try:\n    regex('(')\n    result = False\n\
             except ValueError:\n    result = True\n"
        ));
    }

    #[test]
    fn python_model_evaluate_raises_on_model_error() {
        let interp = new_python_interpreter(1337);
        let raised = interp.enter(|vm| {
            vm.import("rust", 0).unwrap();
            let scope = vm.new_scope_with_builtins();
            // No models are configured, so the request fails
            let model = PythonModel::new(Models::default()).to_pyobject(vm);
            scope.globals.set_item(MODEL, model, vm).unwrap();
            vm.run_code_string(scope, "model.evaluate('m', [1.0])", "<test>".to_owned())
                .is_err()
        });
        assert!(raised, "model.evaluate() should raise when the model fails");
    }

    #[test]
    fn python_valid_regex_matches() {
        assert!(run_python_bool(
            "from rust import regex\nresult = regex('^ab+c').is_match(b'abbbc')\n"
        ));
    }

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
    fn connection_key_symmetric_same_ip() {
        // Loopback / same-host traffic: both endpoints share an IP, so the
        // ports must decide the ordering.
        let ips = IpPair::V4 {
            src: Ipv4Address::new(127, 0, 0, 1),
            dst: Ipv4Address::new(127, 0, 0, 1),
        };
        let key_fwd = ConnectionKey::new(ips, 50000, 80, TransportProtocol::Tcp);
        let key_rev = ConnectionKey::new(ips, 80, 50000, TransportProtocol::Tcp);
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
        let key_a = ConnectionKey::new(ips, 1234, 80, TransportProtocol::Tcp);
        let key_b = ConnectionKey::new(ips, 1234, 443, TransportProtocol::Tcp);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn connection_key_different_proto() {
        let ips = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        let key_tcp = ConnectionKey::new(ips, 1234, 80, TransportProtocol::Tcp);
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
            Some(TcpSeqNumber(1000)),
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
            Some(TcpSeqNumber(500)),
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

    #[test]
    fn construct_reset_without_ack_clears_ack_flag() {
        let ips = IpPair::V4 {
            src: Ipv4Address::new(192, 168, 1, 1),
            dst: Ipv4Address::new(10, 0, 0, 1),
        };
        let pkt = construct_reset(EthernetAddress([0; 6]), EthernetAddress([0; 6]), ips, None,
                                  1, 2, None, TcpSeqNumber(42)).unwrap();
        let eth = EthernetFrame::new_unchecked(&pkt);
        let ip = Ipv4Packet::new_unchecked(eth.payload());
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.rst());
        assert!(!tcp.ack());
        assert_eq!(tcp.ack_number(), TcpSeqNumber(0));
        assert_eq!(tcp.seq_number(), TcpSeqNumber(42));
        assert!(tcp.verify_checksum(&ips.src(), &ips.dst()));
    }

    // --- reset_for tests ---

    fn tcp_transport(syn: bool, fin: bool, ack: bool) -> crate::program::packet::TransportMetadata {
        use crate::program::packet::{TcpFlags, TcpMetadata, TransportMetadata};
        TransportMetadata {
            src: 40000,
            dst: 443,
            extra: TransportMetadataExtra::Tcp(TcpMetadata {
                seq: TcpSeqNumber(1000),
                ack: TcpSeqNumber(2000),
                header_len: 20,
                urgent_at: 0,
                window_len: 0,
                flags: TcpFlags {
                    fin, syn, rst: false, psh: false, ack, urg: false, ece: false, cwr: false, ns: false,
                },
            }),
        }
    }

    fn seg_len_of(action: Option<Action>) -> usize {
        match action {
            Some(Action::Reset { seg_len, .. }) => seg_len,
            other => panic!("expected Reset, got {other:?}"),
        }
    }

    #[test]
    fn reset_for_counts_syn_and_fin_in_segment_length() {
        let ips = IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        };
        assert_eq!(seg_len_of(reset_for(ips, &tcp_transport(false, false, true), 5)), 5);
        assert_eq!(seg_len_of(reset_for(ips, &tcp_transport(true, false, false), 0)), 1);
        assert_eq!(seg_len_of(reset_for(ips, &tcp_transport(false, true, true), 5)), 6);
        assert_eq!(seg_len_of(reset_for(ips, &tcp_transport(true, true, false), 3)), 5);
    }

    // --- IPv6 hop limit (a zeroed hop limit is discarded by the first router) ---

    fn v6_pair() -> IpPair {
        IpPair::V6 {
            src: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            dst: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        }
    }

    #[test]
    fn construct_reset_ipv6_sets_hop_limit() {
        let pkt = construct_reset(
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
            v6_pair(),
            None,
            443,
            50000,
            Some(TcpSeqNumber(2)),
            TcpSeqNumber(1),
        )
        .unwrap();
        let eth = EthernetFrame::new_checked(&pkt[..]).unwrap();
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.hop_limit(), 64);
    }

    #[test]
    fn construct_udp_inject_ipv6_sets_hop_limit() {
        let pkt = construct_udp_inject(
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
            v6_pair(),
            53,
            40000,
            b"forged",
        )
        .unwrap();
        let eth = EthernetFrame::new_checked(&pkt[..]).unwrap();
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.hop_limit(), 64);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
    }
}
