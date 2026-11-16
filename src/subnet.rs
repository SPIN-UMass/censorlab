//! CIDR subnets and efficient subnet-set membership.
//!
//! Accepted syntax (a regular language, recognized in full before use):
//!
//! ```text
//! net    := addr | addr "/" prefix
//! prefix := "0" | [1-9] [0-9]*          (at most 32 for IPv4, 128 for IPv6)
//! ```
//!
//! `addr` is parsed with the standard library parsers, which reject leading
//! zeros, whitespace and other ambiguous forms. A bare address is a host
//! route (`/32` or `/128`).
//!
//! Host bits set after the prefix (e.g. `10.0.0.1/8`) are **rejected** rather
//! than silently masked: such an entry is almost always a typo for either a
//! single host or a different prefix, and silently widening it to a whole
//! network would change which traffic a censor blocks without any visible
//! signal in the experiment results.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use thiserror::Error;

/// Error parsing a CIDR subnet
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParseIpNetError {
    #[error("invalid IP address in subnet {0:?}")]
    Address(String),
    #[error("invalid prefix length in subnet {0:?} (expected decimal 0-{1})")]
    Prefix(String, u8),
    #[error("subnet {0:?} has host bits set (did you mean {1}?)")]
    HostBits(String, String),
}

/// An IPv4 network. Invariant: no bits set beyond `prefix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Net {
    addr: u32,
    prefix: u8,
}
/// An IPv6 network. Invariant: no bits set beyond `prefix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv6Net {
    addr: u128,
    prefix: u8,
}
/// An IPv4 or IPv6 network
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpNet {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

macro_rules! net_impl {
    ($net:ident, $int:ty, $std:ty, $bits:expr) => {
        impl $net {
            /// Construct a network, rejecting host bits and oversize prefixes
            pub fn new(addr: $std, prefix: u8) -> Option<Self> {
                if prefix > $bits {
                    return None;
                }
                let addr = <$int>::from(addr);
                if addr & !Self::mask(prefix) != 0 {
                    return None;
                }
                Some(Self { addr, prefix })
            }
            fn mask(prefix: u8) -> $int {
                // checked_shl handles prefix 0 (shift by full width)
                (<$int>::MAX).checked_shl(u32::from($bits - prefix)).unwrap_or(0)
            }
            /// Network address
            pub fn network(&self) -> $std {
                <$std>::from(self.addr)
            }
            /// Prefix length
            pub fn prefix(&self) -> u8 {
                self.prefix
            }
            /// First and last address (inclusive) as integers
            pub fn range(&self) -> ($int, $int) {
                (self.addr, self.addr | !Self::mask(self.prefix))
            }
            /// Whether `addr` lies inside this network
            pub fn contains(&self, addr: $std) -> bool {
                <$int>::from(addr) & Self::mask(self.prefix) == self.addr
            }
        }
        impl fmt::Display for $net {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}/{}", self.network(), self.prefix)
            }
        }
    };
}
net_impl!(Ipv4Net, u32, Ipv4Addr, 32u8);
net_impl!(Ipv6Net, u128, Ipv6Addr, 128u8);

impl IpNet {
    /// Whether `addr` lies inside this network. Addresses of the other family never match.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpNet::V4(net), IpAddr::V4(a)) => net.contains(a),
            (IpNet::V6(net), IpAddr::V6(a)) => net.contains(a),
            _ => false,
        }
    }
}
impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpNet::V4(n) => n.fmt(f),
            IpNet::V6(n) => n.fmt(f),
        }
    }
}
impl From<IpAddr> for IpNet {
    /// A single address as a host network
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => IpNet::V4(Ipv4Net { addr: a.into(), prefix: 32 }),
            IpAddr::V6(a) => IpNet::V6(Ipv6Net { addr: a.into(), prefix: 128 }),
        }
    }
}

/// Parse a strictly-formatted decimal prefix: "0" or [1-9][0-9]* with value <= max
fn parse_prefix(s: &str, max: u8) -> Option<u8> {
    let bytes = s.as_bytes();
    let well_formed = match bytes {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.len() <= 2 && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if !well_formed {
        return None;
    }
    s.parse::<u8>().ok().filter(|p| *p <= max)
}

impl FromStr for IpNet {
    type Err = ParseIpNetError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| ParseIpNetError::Address(s.to_string()))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_str {
            None => max,
            Some(p) => parse_prefix(p, max).ok_or_else(|| ParseIpNetError::Prefix(s.to_string(), max))?,
        };
        let net = match addr {
            IpAddr::V4(a) => Ipv4Net::new(a, prefix).map(IpNet::V4),
            IpAddr::V6(a) => Ipv6Net::new(a, prefix).map(IpNet::V6),
        };
        net.ok_or_else(|| {
            let suggestion = match addr {
                IpAddr::V4(a) => Ipv4Net { addr: u32::from(a) & Ipv4Net::mask(prefix), prefix }.to_string(),
                IpAddr::V6(a) => Ipv6Net { addr: u128::from(a) & Ipv6Net::mask(prefix), prefix }.to_string(),
            };
            ParseIpNetError::HostBits(s.to_string(), suggestion)
        })
    }
}
impl<'de> serde::Deserialize<'de> for IpNet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A set of disjoint, sorted, inclusive integer ranges with O(log n) lookup
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet<T> {
    ranges: Vec<(T, T)>,
    /// Number of entries the set was built from (for display)
    entries: usize,
}
impl<T: Ord + Copy> RangeSet<T> {
    /// Whether `value` lies in any range
    pub fn contains_value(&self, value: T) -> bool {
        // Index of the first range starting after value; the candidate is the one before it
        let idx = self.ranges.partition_point(|(start, _)| *start <= value);
        idx > 0 && value <= self.ranges[idx - 1].1
    }
    /// Number of configured entries (not merged ranges)
    pub fn len(&self) -> usize {
        self.entries
    }
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}
impl<T: Ord + Copy> FromIterator<(T, T)> for RangeSet<T> {
    fn from_iter<I: IntoIterator<Item = (T, T)>>(iter: I) -> Self {
        let mut input: Vec<(T, T)> = iter.into_iter().collect();
        let entries = input.len();
        input.sort_unstable();
        let mut ranges: Vec<(T, T)> = Vec::with_capacity(input.len());
        for (start, end) in input {
            match ranges.last_mut() {
                // Overlapping (CIDR ranges either nest or are disjoint)
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => ranges.push((start, end)),
            }
        }
        Self { ranges, entries }
    }
}

/// Set of IPv4 subnets
pub type Ipv4Set = RangeSet<u32>;
/// Set of IPv6 subnets
pub type Ipv6Set = RangeSet<u128>;

impl Ipv4Set {
    pub fn from_nets<I: IntoIterator<Item = Ipv4Net>>(nets: I) -> Self {
        nets.into_iter().map(|n| n.range()).collect()
    }
    pub fn contains_addr(&self, addr: Ipv4Addr) -> bool {
        self.contains_value(addr.into())
    }
}
impl Ipv6Set {
    pub fn from_nets<I: IntoIterator<Item = Ipv6Net>>(nets: I) -> Self {
        nets.into_iter().map(|n| n.range()).collect()
    }
    pub fn contains_addr(&self, addr: Ipv6Addr) -> bool {
        self.contains_value(addr.into())
    }
}

/// Mixed-family subnet set
#[derive(Clone, Debug, Default)]
pub struct IpSet {
    pub v4: Ipv4Set,
    pub v6: Ipv6Set,
}
impl IpSet {
    pub fn contains_addr(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => self.v4.contains_addr(a),
            IpAddr::V6(a) => self.v6.contains_addr(a),
        }
    }
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl FromIterator<IpNet> for IpSet {
    fn from_iter<I: IntoIterator<Item = IpNet>>(iter: I) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for net in iter {
            match net {
                IpNet::V4(n) => v4.push(n),
                IpNet::V6(n) => v6.push(n),
            }
        }
        IpSet {
            v4: Ipv4Set::from_nets(v4),
            v6: Ipv6Set::from_nets(v6),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }
    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }
    fn set(entries: &[&str]) -> IpSet {
        entries.iter().map(|s| net(s)).collect()
    }

    #[test]
    fn parse_valid() {
        assert_eq!(net("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(net("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert_eq!(net("1.2.3.4/32").to_string(), "1.2.3.4/32");
        assert_eq!(net("1.2.3.4").to_string(), "1.2.3.4/32");
        assert_eq!(net("2001:db8::/32").to_string(), "2001:db8::/32");
        assert_eq!(net("::/0").to_string(), "::/0");
        assert_eq!(net("::1").to_string(), "::1/128");
        assert_eq!(net("::1/128").to_string(), "::1/128");
    }

    #[test]
    fn parse_rejects_garbage() {
        for bad in [
            "", "/", "/8", "10.0.0.0/", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/+8",
            "10.0.0.0/08", "10.0.0.0/8/8", "10.0.0.0/8 ", " 10.0.0.0/8", "10.0.0/8",
            "010.0.0.0/8", "10.0.0.0/8a", "10.0.0.0/1000", "2001:db8::/129",
            "2001:db8::/0032", "[2001:db8::]/32", "hello", "10.0.0.0/ 8", "10.0.0.0/256",
        ] {
            assert!(bad.parse::<IpNet>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parse_rejects_host_bits() {
        let err = "10.0.0.1/8".parse::<IpNet>().unwrap_err();
        assert_eq!(err, ParseIpNetError::HostBits("10.0.0.1/8".into(), "10.0.0.0/8".into()));
        assert!("1.0.0.0/0".parse::<IpNet>().is_err());
        assert!("2001:db8::1/32".parse::<IpNet>().is_err());
        assert!("::1/0".parse::<IpNet>().is_err());
    }

    #[test]
    fn v4_hits_misses_and_boundaries() {
        let s = set(&["10.0.0.0/8", "192.168.1.0/24"]);
        assert!(s.contains_addr(v4("10.0.0.0").into()));
        assert!(s.contains_addr(v4("10.255.255.255").into()));
        assert!(!s.contains_addr(v4("9.255.255.255").into()));
        assert!(!s.contains_addr(v4("11.0.0.0").into()));
        assert!(s.contains_addr(v4("192.168.1.0").into()));
        assert!(s.contains_addr(v4("192.168.1.255").into()));
        assert!(!s.contains_addr(v4("192.168.0.255").into()));
        assert!(!s.contains_addr(v4("192.168.2.0").into()));
    }

    #[test]
    fn v4_slash_zero_and_slash_32() {
        let all = set(&["0.0.0.0/0"]);
        assert!(all.contains_addr(v4("0.0.0.0").into()));
        assert!(all.contains_addr(v4("255.255.255.255").into()));
        assert!(!all.contains_addr(v6("::").into()));
        let host = set(&["1.2.3.4/32"]);
        assert!(host.contains_addr(v4("1.2.3.4").into()));
        assert!(!host.contains_addr(v4("1.2.3.5").into()));
        assert!(!host.contains_addr(v4("1.2.3.3").into()));
    }

    #[test]
    fn v6_hits_misses_and_boundaries() {
        let s = set(&["2001:db8::/32", "::1"]);
        assert!(s.contains_addr(v6("2001:db8::").into()));
        assert!(s.contains_addr(v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").into()));
        assert!(!s.contains_addr(v6("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff").into()));
        assert!(!s.contains_addr(v6("2001:db9::").into()));
        assert!(s.contains_addr(v6("::1").into()));
        assert!(!s.contains_addr(v6("::2").into()));
        // IPv4 never matches an IPv6 set
        assert!(!s.contains_addr(v4("0.0.0.1").into()));
    }

    #[test]
    fn v6_slash_zero_and_slash_128() {
        let all = set(&["::/0"]);
        assert!(all.contains_addr(v6("::").into()));
        assert!(all.contains_addr(v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").into()));
        assert!(!all.contains_addr(v4("1.1.1.1").into()));
        let host = set(&["2001:db8::5/128"]);
        assert!(host.contains_addr(v6("2001:db8::5").into()));
        assert!(!host.contains_addr(v6("2001:db8::4").into()));
        assert!(!host.contains_addr(v6("2001:db8::6").into()));
    }

    #[test]
    fn mixed_and_overlapping_entries() {
        let s = set(&["10.1.2.3", "10.0.0.0/8", "10.1.0.0/16", "8.8.8.8", "2001:db8::/48"]);
        assert_eq!(s.len(), 5);
        // Nested ranges merge
        assert_eq!(s.v4.ranges.len(), 2);
        assert!(s.contains_addr(v4("8.8.8.8").into()));
        assert!(!s.contains_addr(v4("8.8.8.9").into()));
        assert!(s.contains_addr(v4("10.200.0.1").into()));
        assert!(s.contains_addr(v6("2001:db8:0:ffff::1").into()));
        assert!(!s.contains_addr(v6("2001:db8:1::").into()));
    }

    #[test]
    fn empty_set_contains_nothing() {
        let s = IpSet::default();
        assert!(!s.contains_addr(v4("0.0.0.0").into()));
        assert!(!s.contains_addr(v6("::").into()));
        assert!(s.is_empty());
    }

    #[test]
    fn ipnet_contains() {
        assert!(net("10.0.0.0/8").contains(v4("10.9.9.9").into()));
        assert!(!net("10.0.0.0/8").contains(v4("11.0.0.0").into()));
        assert!(!net("10.0.0.0/8").contains(v6("::a00:0").into()));
    }
}
