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
        Ok(config)
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
            action: self.action,
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

/// Config related to TCP  handling
pub mod tcp {
    use super::List;
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
        // TODO: have these auto deserialize into (IpAddr, u16)
        pub ip_port_allowlist: List<Vec<String>>,
        #[serde(default)]
        /// Blocklist of ip-port pairs
        // TODO: have these auto deserialize into (IpAddr, u16)
        pub ip_port_blocklist: List<Vec<String>>,
    }
}

/// Config related to UDP  handling
pub mod udp {
    use super::List;
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
        // TODO: have these auto deserialize into (IpAddr, u16)
        pub ip_port_allowlist: List<Vec<String>>,
        #[serde(default)]
        /// Blocklist of ip-port pairs
        // TODO: have these auto deserialize into (IpAddr, u16)
        pub ip_port_blocklist: List<Vec<String>>,
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
