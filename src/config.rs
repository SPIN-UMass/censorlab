use crate::censor::{Action, PortVec};
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
    /// Execution environment
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
        // Reset is only valid at the transport layer (TCP); reject it for ethernet/ARP/IP/ICMP
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
        Ok(())
    }
}

/// Common pattern
/// Used for both allowlist and blocklist
#[derive(Debug, Default, Deserialize)]
pub struct List<T> {
    /// List of values to allow/block
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

    #[derive(Default, Deserialize)]
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
    use std::net::IpAddr;

    #[derive(Default, Deserialize)]
    /// Config related to IP handling
    pub struct Config {
        /// Allowlist of IP addresses
        #[serde(default)]
        pub allowlist: List<Vec<IpAddr>>,
        /// Blocklist of IP addresses
        #[serde(default)]
        pub blocklist: List<Vec<IpAddr>>,
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

/// An IP address + port pair that deserializes from "ip:port" strings.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IpPort(pub std::net::IpAddr, pub u16);

impl std::fmt::Display for IpPort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

impl<'de> Deserialize<'de> for IpPort {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Support both "ip:port" and "[ipv6]:port"
        let (ip_str, port_str) = if s.starts_with('[') {
            // IPv6: "[::1]:80"
            let bracket_end = s.find(']').ok_or_else(|| {
                serde::de::Error::custom(format!("invalid ip:port pair (missing ']'): {s}"))
            })?;
            let ip_part = &s[1..bracket_end];
            let port_part = s.get(bracket_end + 2..).ok_or_else(|| {
                serde::de::Error::custom(format!("invalid ip:port pair (missing port after ']:'): {s}"))
            })?;
            (ip_part, port_part)
        } else {
            // IPv4: "1.2.3.4:80"
            let colon = s.rfind(':').ok_or_else(|| {
                serde::de::Error::custom(format!("invalid ip:port pair (missing ':'): {s}"))
            })?;
            (&s[..colon], &s[colon + 1..])
        };
        let ip: std::net::IpAddr = ip_str.parse().map_err(serde::de::Error::custom)?;
        let port: u16 = port_str.parse().map_err(serde::de::Error::custom)?;
        Ok(IpPort(ip, port))
    }
}

/// Config related to TCP  handling
pub mod tcp {
    use super::{IpPort, List};
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
        /// Allowlist of ip-port pairs
        pub ip_port_allowlist: List<Vec<IpPort>>,
        #[serde(default)]
        /// Blocklist of ip-port pairs
        pub ip_port_blocklist: List<Vec<IpPort>>,
    }
}

/// Config related to UDP  handling
pub mod udp {
    use super::{IpPort, List};
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
        /// Allowlist of ip-port pairs
        pub ip_port_allowlist: List<Vec<IpPort>>,
        #[serde(default)]
        /// Blocklist of ip-port pairs
        pub ip_port_blocklist: List<Vec<IpPort>>,
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
        assert_eq!(*bv.list.get(80).unwrap(), true);
        assert_eq!(*bv.list.get(443).unwrap(), true);
        assert_eq!(*bv.list.get(8080).unwrap(), true);
        assert_eq!(*bv.list.get(22).unwrap(), false);
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
    fn ip_port_deserialize_ipv4() {
        #[derive(Deserialize)]
        struct W {
            pair: super::IpPort,
        }
        let w: W = toml::from_str("pair = \"192.168.1.1:80\"").unwrap();
        assert_eq!(w.pair.0, std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(w.pair.1, 80);
    }

    #[test]
    fn ip_port_deserialize_ipv6() {
        #[derive(Deserialize)]
        struct W {
            pair: super::IpPort,
        }
        let w: W = toml::from_str("pair = \"[::1]:443\"").unwrap();
        assert_eq!(w.pair.0, std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert_eq!(w.pair.1, 443);
    }

    #[test]
    fn ip_port_deserialize_invalid() {
        #[derive(Deserialize)]
        struct W {
            pair: super::IpPort,
        }
        assert!(toml::from_str::<W>("pair = \"not-an-ip\"").is_err());
        assert!(toml::from_str::<W>("pair = \"192.168.1.1\"").is_err()); // missing port
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
}
