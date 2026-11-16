use crate::censor::{Action, PortVec};
use crate::subnet::IpNet;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::Hash;
use std::io;
use std::path::Path;
use thiserror::Error;

/// Censorlab config
#[derive(Default, Deserialize)]
pub struct Config {
    /// Execution environment (defaults to Python mode with no script, so a
    /// config may consist of allow/blocklists only)
    #[serde(default)]
    pub execution: execution::Config,
    /// Behaviors for ethernet layer
    #[serde(default)]
    pub ethernet: ethernet::Config,
    /// Behaviors for ARP
    #[serde(default)]
    pub arp: arp::Config,
    /// Behaviors for IP layer
    #[serde(default)]
    pub ip: ip::Config,
    /// Behaviors for ICMP
    #[serde(default)]
    pub icmp: icmp::Config,
    /// Behaviors for TCP layer
    #[serde(default)]
    pub tcp: tcp::Config,
    /// Behaviors for UDP layer
    #[serde(default)]
    pub udp: udp::Config,
    /// Connection/host state tracking limits
    #[serde(default)]
    pub conntrack: conntrack::Config,
    /// Model store
    #[serde(default)]
    pub models: HashMap<String, model::Model>,
}
#[derive(Debug, Error)]
/// Error loading config
pub enum ConfigLoadError {
    #[error("Failed to read config file")]
    Read(#[from] io::Error),
    #[error("Config path doesnt have a parent")]
    NoParent,
    #[error("Failed to parse config file")]
    Parse(#[from] toml::de::Error),
    #[error("Invalid config: {0}")]
    Validation(String),
}
impl Config {
    /// Load the config from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigLoadError> {
        // Parent
        let parent = path.as_ref().parent().ok_or(ConfigLoadError::NoParent)?;
        // Read the file
        let data = fs::read_to_string(&path)?;
        // Parse as config
        let mut config: Self = toml::from_str(&data)?;
        // Modify paths (scripts and model paths are relative to config)
        if let Some(ref mut script_path) = config.execution.script {
            *script_path = parent.join(&script_path)
        }
        for (_, model) in config.models.iter_mut() {
            model.path = parent.join(&model.path);
        }
        // Validate the config
        config.validate()?;
        Ok(config)
    }
    /// Validate config invariants that can't be enforced at the type level.
    fn validate(&self) -> Result<(), ConfigLoadError> {
        // Reset tears down a TCP connection; reject it where no TCP traffic can match
        if self.ethernet.unknown.is_reset() {
            return Err(ConfigLoadError::Validation(
                "\"Reset\" is not a valid action for ethernet.unknown (only valid for TCP)".into(),
            ));
        }
        if self.ethernet.allowlist.action.is_reset() {
            return Err(ConfigLoadError::Validation(
                "\"Reset\" is not a valid action for ethernet.allowlist (only valid for TCP)".into(),
            ));
        }
        if self.ethernet.blocklist.action.is_reset() {
            return Err(ConfigLoadError::Validation(
                "\"Reset\" is not a valid action for ethernet.blocklist (only valid for TCP)".into(),
            ));
        }
        if self.arp.action.is_reset() {
            return Err(ConfigLoadError::Validation(
                "\"Reset\" is not a valid action for ARP (only valid for TCP)".into(),
            ));
        }
        if self.icmp.action.is_reset() {
            return Err(ConfigLoadError::Validation(
                "\"Reset\" is not a valid action for ICMP (only valid for TCP)".into(),
            ));
        }
        // UDP lists only ever match UDP traffic, so a Reset there could never send a RST.
        // (IP lists may Reset: TCP traffic gets a RST and anything else is dropped.)
        for (name, action) in [
            ("udp.port_allowlist", &self.udp.port_allowlist.action),
            ("udp.port_blocklist", &self.udp.port_blocklist.action),
            ("udp.ip_port_allowlist", &self.udp.ip_port_allowlist.action),
            ("udp.ip_port_blocklist", &self.udp.ip_port_blocklist.action),
        ] {
            if action.is_reset() {
                return Err(ConfigLoadError::Validation(format!(
                    "\"Reset\" is not a valid action for {name} (only valid for TCP)"
                )));
            }
        }
        Ok(())
    }
}

/// Common pattern
/// Used for both allowlist and blocklist
#[derive(Debug, Default, Deserialize)]
pub struct List<T> {
    /// List of values to allow/block (empty if omitted)
    #[serde(default)]
    pub list: T,
    /// Action to taken if a value is/isn't in the list
    #[serde(default)]
    pub action: Action,
}
impl<S, T> List<S>
where
    S: IntoIterator<Item = T>,
{
    pub fn map<B, F>(self, f: F) -> List<Vec<B>>
    where
        F: FnMut(T) -> B,
    {
        List {
            list: self.list.into_iter().map(f).collect(),
            action: self.action,
        }
    }
    pub fn filter_map<B, F>(&self, f: F) -> List<Vec<B>>
    where
        F: FnMut(T) -> Option<B>,
        S: Clone,
    {
        List {
            list: self.list.clone().into_iter().filter_map(f).collect(),
            action: self.action.clone(),
        }
    }
    /// Collect the list into an arbitrary store (e.g. a subnet range set)
    pub fn collect<C>(self) -> List<C>
    where
        C: FromIterator<T>,
    {
        List {
            list: self.list.into_iter().collect(),
            action: self.action,
        }
    }
    pub fn set(self) -> List<HashSet<T>>
    where
        T: Eq + PartialEq + Hash,
    {
        List {
            list: self.list.into_iter().collect(),
            action: self.action,
        }
    }
}
impl<S> List<S>
where
    S: IntoIterator<Item = u16>,
{
    pub fn bit_vec(self) -> List<PortVec> {
        let mut port_vec = PortVec::ZERO;
        for port in self.list {
            port_vec.set(usize::from(port), true);
        }
        List {
            list: port_vec,
            action: self.action.clone(),
        }
    }
}

/// Config related to the execution environment
pub mod execution {
    use super::Deserialize;
    use crate::transport::ExecutionMode;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    /// Config related to the execution environment
    pub struct Config {
        #[serde(default)]
        /// Which mode to use: Python or CensorLang
        pub mode: ExecutionMode,
        /// Path to a script to use as the default censor script
        ///
        /// RELATIVE to censor.toml
        pub script: Option<PathBuf>,
        /// Hash seed for Python VM reproducibility (default: 1337)
        #[serde(default = "default_hash_seed")]
        pub hash_seed: u32,
        /// Number of times to repeat sending a TCP RST packet (default: 5)
        #[serde(default = "default_reset_repeat")]
        pub reset_repeat: usize,
    }

    // Hand-written so Config::default() (used when no config file is given, or
    // when [execution] is omitted) agrees with the serde field defaults below.
    impl Default for Config {
        fn default() -> Self {
            Self {
                mode: ExecutionMode::default(),
                script: None,
                hash_seed: default_hash_seed(),
                reset_repeat: default_reset_repeat(),
            }
        }
    }

    fn default_hash_seed() -> u32 {
        1337
    }
    fn default_reset_repeat() -> usize {
        5
    }
}
pub mod ethernet {
    use super::{Action, Deserialize, List};
    use smoltcp::wire::EthernetAddress;

    #[derive(Default, Deserialize)]
    /// Config related to ethernet handling
    pub struct Config {
        #[serde(default)]
        /// What to do
        pub unknown: Action,
        /// Allowlist of mac addresses
        #[serde(default)]
        pub allowlist: List<Vec<MACAddress>>,
        /// Blocklist of mac addresses
        #[serde(default)]
        pub blocklist: List<Vec<MACAddress>>,
    }

    // Unfortunately we need to define a wrapper type
    pub struct MACAddress(EthernetAddress);
    impl<'de> Deserialize<'de> for MACAddress {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            s.parse()
                .map(MACAddress)
                .map_err(|_| serde::de::Error::custom("Failed to parse MAC address"))
        }
    }
    impl From<MACAddress> for EthernetAddress {
        fn from(mac: MACAddress) -> Self {
            mac.0
        }
    }
}
/// Config related to ARP  handling
pub mod arp {
    use super::{Action, Deserialize};

    #[derive(Default, Deserialize)]
    /// Config related to ARP  handling
    pub struct Config {
        #[serde(default)]
        /// What to do with ARP traffic
        pub action: Action,
    }
}

/// Config related to IP  handling
pub mod ip {
    use super::{Action, Deserialize, List};
    use crate::subnet::IpNet;

    #[derive(Default, Deserialize)]
    /// Config related to IP handling
    ///
    /// A `Reset` action here sends a RST for the matching packet's TCP connection, and
    /// drops any matching packet that is not well-formed TCP (so `unknown`, which never
    /// sees TCP, treats `Reset` as `Drop`).
    pub struct Config {
        /// Allowlist of IP addresses and/or CIDR subnets
        #[serde(default)]
        pub allowlist: List<Vec<IpNet>>,
        /// Blocklist of IP addresses and/or CIDR subnets
        #[serde(default)]
        pub blocklist: List<Vec<IpNet>>,
        /// What to do if we run into an unknown next-protocol-header field
        #[serde(default)]
        pub unknown: Action,
    }
}

/// Config related to ICMP  handling
pub mod icmp {
    use super::Action;
    use serde::Deserialize;

    /// Config related to ICMP handling
    #[derive(Default, Deserialize)]
    pub struct Config {
        /// What to do with ICMP traffic
        #[serde(default)]
        pub action: Action,
    }
}

/// A concrete IP address + port pair (the lookup key for ip:port lists).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IpPort(pub std::net::IpAddr, pub u16);

impl std::fmt::Display for IpPort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

/// A subnet + port pair as written in config ip:port lists.
///
/// Grammar (regular; recognized in full before use):
///
/// ```text
/// pair := v4net ":" port | "[" v6net "]" ":" port
/// port := "0" | [1-9] [0-9]*            (at most 65535)
/// ```
///
/// where `v4net`/`v6net` follow [`IpNet`]'s syntax (`addr` or `addr/prefix`).
/// IPv6 must be bracketed and IPv4 must not, so the port separator is unambiguous.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IpNetPort(pub IpNet, pub u16);

impl IpNetPort {
    /// Split into (subnet, port)
    pub fn into_pair(self) -> (IpNet, u16) {
        (self.0, self.1)
    }
}

impl std::fmt::Display for IpNetPort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            IpNet::V4(_) => write!(f, "{}:{}", self.0, self.1),
            IpNet::V6(_) => write!(f, "[{}]:{}", self.0, self.1),
        }
    }
}

/// Parse a strictly-formatted decimal port: "0" or [1-9][0-9]* with value <= 65535
fn parse_port(s: &str) -> Option<u16> {
    let well_formed = match s.as_bytes() {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.len() <= 4 && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if well_formed {
        s.parse().ok()
    } else {
        None
    }
}

impl std::str::FromStr for IpNetPort {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (net_str, port_str, want_v6) = if let Some(rest) = s.strip_prefix('[') {
            let (net, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("invalid ip:port pair (missing ']'): {s}"))?;
            let port = after
                .strip_prefix(':')
                .ok_or_else(|| format!("invalid ip:port pair (expected ':' after ']'): {s}"))?;
            (net, port, true)
        } else {
            let (net, port) = s
                .split_once(':')
                .ok_or_else(|| format!("invalid ip:port pair (missing ':'): {s}"))?;
            (net, port, false)
        };
        let net: IpNet = net_str.parse().map_err(|e| format!("{e}"))?;
        match (net, want_v6) {
            (IpNet::V4(_), false) | (IpNet::V6(_), true) => {}
            (IpNet::V4(_), true) => return Err(format!("IPv4 address must not be bracketed: {s}")),
            (IpNet::V6(_), false) => return Err(format!("IPv6 address must be bracketed: {s}")),
        }
        let port = parse_port(port_str)
            .ok_or_else(|| format!("invalid port (expected decimal 0-65535) in ip:port pair: {s}"))?;
        Ok(IpNetPort(net, port))
    }
}

impl<'de> Deserialize<'de> for IpNetPort {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Config related to TCP  handling
pub mod tcp {
    use super::{IpNetPort, List};
    use serde::Deserialize;

    #[derive(Default, Deserialize)]
    /// Config related to TCP  handling
    pub struct Config {
        #[serde(default)]
        /// Allowlist of ports
        pub port_allowlist: List<Vec<u16>>,
        #[serde(default)]
        /// Blocklist of ports
        pub port_blocklist: List<Vec<u16>>,
        #[serde(default)]
        /// Allowlist of ip-port pairs
        pub ip_port_allowlist: List<Vec<IpNetPort>>,
        #[serde(default)]
        /// Blocklist of ip-port pairs
        pub ip_port_blocklist: List<Vec<IpNetPort>>,
    }
}

/// Config related to UDP  handling
pub mod udp {
    use super::{IpNetPort, List};
    use serde::Deserialize;

    #[derive(Default, Deserialize)]
    /// Config related to UDP  handling
    pub struct Config {
        #[serde(default)]
        /// Allowlist of ports
        pub port_allowlist: List<Vec<u16>>,
        #[serde(default)]
        /// Blocklist of ports
        pub port_blocklist: List<Vec<u16>>,
        #[serde(default)]
        /// Allowlist of ip-port pairs
        pub ip_port_allowlist: List<Vec<IpNetPort>>,
        #[serde(default)]
        /// Blocklist of ip-port pairs
        pub ip_port_blocklist: List<Vec<IpNetPort>>,
    }
}

/// Config related to connection and host state tracking
///
/// All timeouts are in seconds of packet time (capture timestamps in PCAP
/// mode, a monotonic clock in live modes). Zero is rejected for every value.
pub mod conntrack {
    use serde::Deserialize;
    use std::num::{NonZeroU64, NonZeroUsize};

    #[derive(Clone, Debug, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    /// Config related to connection and host state tracking
    pub struct Config {
        /// Forget an open TCP connection after this many idle seconds (default: 3600)
        pub tcp_idle_timeout: NonZeroU64,
        /// Forget a TCP connection this many idle seconds after it was closed
        /// by RST or FIN in both directions (default: 60)
        pub tcp_closed_timeout: NonZeroU64,
        /// Forget a UDP flow after this many idle seconds (default: 120)
        pub udp_idle_timeout: NonZeroU64,
        /// Maximum number of tracked TCP+UDP connections. When exceeded, the
        /// connection closest to expiring is evicted (default: 65536)
        pub max_connections: NonZeroUsize,
        /// Maximum number of hosts with per-host state (counters, registers,
        /// `host.state`). When exceeded, the least recently seen host is
        /// evicted (default: 65536)
        pub max_hosts: NonZeroUsize,
        /// Forget a host's state after this many seconds without traffic
        /// from or to it (default: unset, i.e. only `max_hosts` applies)
        pub host_idle_timeout: Option<NonZeroU64>,
    }
    impl Default for Config {
        fn default() -> Self {
            Self {
                tcp_idle_timeout: NonZeroU64::new(3600).unwrap(),
                tcp_closed_timeout: NonZeroU64::new(60).unwrap(),
                udp_idle_timeout: NonZeroU64::new(120).unwrap(),
                max_connections: NonZeroUsize::new(65536).unwrap(),
                max_hosts: NonZeroUsize::new(65536).unwrap(),
                host_idle_timeout: None,
            }
        }
    }
}

/// Config related to the model store
pub mod model {
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Clone, Deserialize)]
    /// Config related to a model in the model store
    pub struct Model {
        /// Path to the model's ONNX file
        pub path: PathBuf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::censor::Action;

    #[test]
    fn deserialize_minimal_config() {
        let toml_str = r#"
[execution]
mode = "Python"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.models.is_empty());
    }

    #[test]
    fn deserialize_with_ip_blocklist() {
        let toml_str = r#"
[execution]
mode = "Python"

[ip.blocklist]
list = ["192.168.1.1"]
action = "Drop"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.ip.blocklist.list.len(), 1);
        assert_eq!(config.ip.blocklist.action, Action::Drop);
    }

    #[test]
    fn deserialize_with_tcp_port_lists() {
        let toml_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = [] }

[tcp.port_blocklist]
list = [80, 443]
action = "Reset"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.tcp.port_blocklist.list.len(), 2);
        assert!(config.tcp.port_blocklist.list.contains(&80));
        assert!(config.tcp.port_blocklist.list.contains(&443));
    }

    /// Helper to deserialize an Action from a TOML value string
    fn action_from_toml(s: &str) -> Action {
        #[derive(Deserialize)]
        struct Wrapper {
            action: Action,
        }
        let toml_str = format!("action = \"{}\"", s);
        let w: Wrapper = toml::from_str(&toml_str).unwrap();
        w.action
    }

    #[test]
    fn action_deserialize_none() {
        let action = action_from_toml("none");
        assert_eq!(action, Action::None);
    }

    #[test]
    fn action_deserialize_ignore() {
        let action = action_from_toml("ignore");
        assert_eq!(action, Action::Ignore);
    }

    #[test]
    fn action_deserialize_drop() {
        let action = action_from_toml("drop");
        assert_eq!(action, Action::Drop);
    }

    #[test]
    fn action_deserialize_reset() {
        let action = action_from_toml("reset");
        assert!(matches!(action, Action::Reset { .. }));
    }

    #[test]
    fn default_config() {
        let toml_str = r#"
[execution]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.ip.blocklist.action, Action::None);
        assert!(config.ip.blocklist.list.is_empty());
        assert!(config.tcp.port_blocklist.list.is_empty());
        assert!(config.models.is_empty());
    }

    #[test]
    fn tcp_udp_sections_without_ip_port_allowlist() {
        let toml_str = r#"
[execution]
mode = "Python"

[tcp.port_blocklist]
list = [80]
action = "Drop"

[udp.port_blocklist]
list = [53]
action = "Drop"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.tcp.ip_port_allowlist.list.is_empty());
        assert_eq!(config.tcp.ip_port_allowlist.action, Action::None);
        assert!(config.udp.ip_port_allowlist.list.is_empty());
        assert_eq!(config.udp.ip_port_allowlist.action, Action::None);
    }

    #[test]
    fn list_block_without_list_key_defaults_to_empty() {
        let toml_str = r#"
[ip.allowlist]
action = "Drop"

[tcp.port_blocklist]
action = "Reset"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.ip.allowlist.list.is_empty());
        assert_eq!(config.ip.allowlist.action, Action::Drop);
        assert!(config.tcp.port_blocklist.list.is_empty());
    }

    #[test]
    fn config_without_execution_section_uses_execution_defaults() {
        let toml_str = r#"
[ip.blocklist]
list = ["192.168.1.1"]
action = "Drop"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(matches!(config.execution.mode, crate::transport::ExecutionMode::Python));
        assert!(config.execution.script.is_none());
        assert_eq!(config.execution.hash_seed, 1337);
        assert_eq!(config.execution.reset_repeat, 5);
    }

    #[test]
    fn default_config_matches_empty_execution_section() {
        // Config::default() is used when no -c is given; it must agree with
        // what an empty [execution] table deserializes to.
        let parsed: Config = toml::from_str("[execution]\n").unwrap();
        let default = Config::default();
        assert_eq!(default.execution.hash_seed, parsed.execution.hash_seed);
        assert_eq!(default.execution.reset_repeat, parsed.execution.reset_repeat);
    }

    #[test]
    fn list_map_operation() {
        let list: List<Vec<u16>> = List {
            list: vec![1, 2, 3],
            action: Action::Drop,
        };
        let mapped = list.map(|x| x * 2);
        assert_eq!(mapped.list, vec![2, 4, 6]);
        assert_eq!(mapped.action, Action::Drop);
    }

    #[test]
    fn list_set_operation() {
        let list: List<Vec<u16>> = List {
            list: vec![80, 443, 80],
            action: Action::Ignore,
        };
        let set_list = list.set();
        assert_eq!(set_list.list.len(), 2);
        assert!(set_list.list.contains(&80));
        assert!(set_list.list.contains(&443));
        assert_eq!(set_list.action, Action::Ignore);
    }

    #[test]
    fn list_bit_vec_for_ports() {
        let list: List<Vec<u16>> = List {
            list: vec![80, 443, 8080],
            action: Action::Drop,
        };
        let bv = list.bit_vec();
        assert!(*bv.list.get(80).unwrap());
        assert!(*bv.list.get(443).unwrap());
        assert!(*bv.list.get(8080).unwrap());
        assert!(!*bv.list.get(22).unwrap());
        assert_eq!(bv.action, Action::Drop);
    }

    #[test]
    fn validate_rejects_reset_on_ethernet_blocklist() {
        let toml_str = r#"
[execution]
mode = "Python"

[ethernet.blocklist]
list = []
action = "Reset"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("ethernet.blocklist"), "Error should mention ethernet.blocklist: {err_msg}");
    }

    #[test]
    fn validate_rejects_reset_on_arp() {
        let toml_str = r#"
[execution]
mode = "Python"

[arp]
action = "Reset"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_allows_reset_on_tcp() {
        let toml_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = [] }

[tcp.port_blocklist]
list = [80]
action = "Reset"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_reset_on_every_udp_list() {
        for list in ["port_allowlist", "port_blocklist", "ip_port_allowlist", "ip_port_blocklist"] {
            let toml_str = format!(
                r#"
[execution]
mode = "Python"

[udp]
ip_port_allowlist = {{ list = [] }}

[udp.{list}]
list = []
action = "Reset"
"#
            )
            .replace("ip_port_allowlist = { list = [] }\n\n[udp.ip_port_allowlist]", "[udp.ip_port_allowlist]");
            let config: Config = toml::from_str(&toml_str).unwrap();
            let err = config.validate().expect_err(list).to_string();
            assert!(err.contains(&format!("udp.{list}")), "{list}: {err}");
        }
    }

    #[test]
    fn validate_allows_reset_on_ip_lists() {
        // TCP traffic matching an IP rule gets a real RST; anything else is dropped.
        let toml_str = r#"
[execution]
mode = "Python"

[ip]
unknown = "Reset"

[ip.blocklist]
list = ["192.0.2.1"]
action = "Reset"

[ip.allowlist]
list = ["192.0.2.2"]
action = "Reset"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn ip_port_deserialize_ipv4() {
        #[derive(Deserialize)]
        struct W {
            pair: super::IpNetPort,
        }
        let w: W = toml::from_str("pair = \"192.168.1.1:80\"").unwrap();
        assert_eq!(w.pair.0, IpNet::from(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(w.pair.1, 80);
    }

    #[test]
    fn ip_port_deserialize_ipv6() {
        #[derive(Deserialize)]
        struct W {
            pair: super::IpNetPort,
        }
        let w: W = toml::from_str("pair = \"[::1]:443\"").unwrap();
        assert_eq!(w.pair.0, IpNet::from(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
        assert_eq!(w.pair.1, 443);
    }

    #[test]
    fn ip_port_deserialize_invalid() {
        #[derive(Deserialize)]
        #[allow(dead_code)] // only checks that deserialization fails
        struct W {
            #[allow(dead_code)]
            pair: super::IpNetPort,
        }
        assert!(toml::from_str::<W>("pair = \"not-an-ip\"").is_err());
        assert!(toml::from_str::<W>("pair = \"192.168.1.1\"").is_err()); // missing port
    }

    #[test]
    fn conntrack_defaults() {
        let config: Config = toml::from_str("[execution]\n").unwrap();
        let ct = config.conntrack;
        assert_eq!(ct.tcp_idle_timeout.get(), 3600);
        assert_eq!(ct.tcp_closed_timeout.get(), 60);
        assert_eq!(ct.udp_idle_timeout.get(), 120);
        assert_eq!(ct.max_connections.get(), 65536);
        assert_eq!(ct.max_hosts.get(), 65536);
        assert!(ct.host_idle_timeout.is_none());
    }

    #[test]
    fn conntrack_overrides_and_rejects_invalid() {
        let config: Config = toml::from_str(
            "[execution]\n[conntrack]\nudp_idle_timeout = 30\nmax_hosts = 10\nhost_idle_timeout = 600\n",
        )
        .unwrap();
        assert_eq!(config.conntrack.udp_idle_timeout.get(), 30);
        assert_eq!(config.conntrack.max_hosts.get(), 10);
        assert_eq!(config.conntrack.host_idle_timeout.map(|t| t.get()), Some(600));
        // Defaults still apply to unspecified keys
        assert_eq!(config.conntrack.tcp_idle_timeout.get(), 3600);
        // Zero, negative and unknown keys are rejected
        assert!(toml::from_str::<Config>("[execution]\n[conntrack]\nmax_connections = 0\n").is_err());
        assert!(toml::from_str::<Config>("[execution]\n[conntrack]\ntcp_idle_timeout = -1\n").is_err());
        assert!(toml::from_str::<Config>("[execution]\n[conntrack]\nmax_conections = 5\n").is_err());
    }

    #[test]
    fn deserialize_tcp_ip_port_list() {
        let toml_str = r#"
[execution]
mode = "Python"

[tcp]
ip_port_allowlist = { list = ["10.0.0.1:80", "10.0.0.2:443"] }
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.tcp.ip_port_allowlist.list.len(), 2);
        assert_eq!(config.tcp.ip_port_allowlist.list[0].1, 80);
        assert_eq!(config.tcp.ip_port_allowlist.list[1].1, 443);
    }

    #[test]
    fn deserialize_ip_lists_with_subnets() {
        let toml_str = r#"
[execution]
mode = "Python"

[ip.blocklist]
list = ["10.0.0.0/8", "192.168.1.1", "2001:db8::/32", "::1"]
action = "Drop"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let list: Vec<String> = config.ip.blocklist.list.iter().map(|n| n.to_string()).collect();
        assert_eq!(list, ["10.0.0.0/8", "192.168.1.1/32", "2001:db8::/32", "::1/128"]);
    }

    #[test]
    fn invalid_cidr_rejected_at_config_load() {
        for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/129", "10.0.0.0/8x", "10.0.0.0/"] {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("censor.toml");
            std::fs::write(
                &path,
                format!("[execution]\nmode = \"Python\"\n[ip.blocklist]\nlist = [\"{bad}\"]\n"),
            )
            .unwrap();
            assert!(
                matches!(Config::load(&path), Err(ConfigLoadError::Parse(_))),
                "config with {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn ip_port_deserialize_subnets() {
        #[derive(Deserialize)]
        struct W {
            pair: super::IpNetPort,
        }
        let w: W = toml::from_str("pair = \"10.0.0.0/8:80\"").unwrap();
        assert_eq!(w.pair.0.to_string(), "10.0.0.0/8");
        assert_eq!(w.pair.1, 80);
        let w: W = toml::from_str("pair = \"[2001:db8::/32]:443\"").unwrap();
        assert_eq!(w.pair.0.to_string(), "2001:db8::/32");
        assert_eq!(w.pair.1, 443);
        let w: W = toml::from_str("pair = \"1.2.3.4:53\"").unwrap();
        assert_eq!(w.pair.0.to_string(), "1.2.3.4/32");
    }

    #[test]
    fn ip_port_deserialize_rejects_malformed() {
        #[derive(Deserialize)]
        struct W {
            #[allow(dead_code)]
            pair: super::IpNetPort,
        }
        for bad in [
            "10.0.0.1/8:80",       // host bits
            "10.0.0.0/33:80",      // prefix too long
            "[2001:db8::/129]:80", // prefix too long
            "::1:80",              // IPv6 must be bracketed
            "[::1]x80",            // missing ':' after ']'
            "[::1]:",              // empty port
            "1.2.3.4:+80",         // signed port
            "1.2.3.4:080",         // leading zero
            "1.2.3.4:65536",       // port out of range
            "[1.2.3.4]:80",        // IPv4 must not be bracketed
            "1.2.3.4:80:80",
            "1.2.3.4",             // missing port
        ] {
            assert!(toml::from_str::<W>(&format!("pair = \"{bad}\"")).is_err(), "accepted {bad:?}");
        }
    }
}
