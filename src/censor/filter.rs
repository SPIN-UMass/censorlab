//! Allow/blocklist filtering infrastructure.
//!
//! Provides generic `AllowList`, `BlockList`, and `AllowBlockList` types
//! used for MAC, IP, port, and ip-port filtering throughout the censor.

use super::{Action, PortVec};
use crate::config::{IpPort, List};
use crate::subnet::{IpPortSet, Ipv4Set, Ipv6Set};
use smoltcp::wire::{Ipv4Address, Ipv6Address};
use std::collections::HashSet;
use std::hash::Hash;

/// Used to abstract over different kinds of store (hashset, bit vec)
pub trait Contains<T> {
    fn contains(&self, value: &T) -> bool;
}
impl<T> Contains<T> for HashSet<T>
where
    T: Eq + Hash,
{
    fn contains(&self, value: &T) -> bool {
        HashSet::contains(self, value)
    }
}
impl Contains<u16> for PortVec {
    fn contains(&self, value: &u16) -> bool {
        self.get(usize::from(*value)).as_deref() == Some(&true)
    }
}
impl Contains<Ipv4Address> for Ipv4Set {
    fn contains(&self, value: &Ipv4Address) -> bool {
        self.contains_value(u32::from(*value))
    }
}
impl Contains<Ipv6Address> for Ipv6Set {
    fn contains(&self, value: &Ipv6Address) -> bool {
        self.contains_value(u128::from(*value))
    }
}
impl Contains<IpPort> for IpPortSet {
    fn contains(&self, value: &IpPort) -> bool {
        self.contains_pair(value.0, value.1)
    }
}

/// Trait that can be shared between both an allow and blocklist
pub trait RecommendList<T, Store>
where
    Store: Contains<T>,
{
    /// Recommends an action based on some value
    fn recommend(&self, value: &T) -> Option<Action>;
    /// Recommends an action for the two endpoints of a packet (source and destination).
    ///
    /// The default implementation returns the first decisive recommendation, which is the
    /// correct semantics for a blocklist (a hit on either endpoint blocks). Allowlists must
    /// override it: a packet is allowed if *either* endpoint is listed.
    fn recommend_either(&self, val_1: &T, val_2: &T) -> Option<Action> {
        match self.recommend(val_1) {
            Some(Action::None) | None => self.recommend(val_2),
            Some(action) => Some(action),
        }
    }
}

/// A blocklist
pub struct BlockList<Store> {
    pub store: Store,
    pub in_blocklist: Action,
}
impl<Store> From<List<Store>> for BlockList<Store> {
    fn from(list: List<Store>) -> Self {
        Self {
            store: list.list,
            in_blocklist: list.action,
        }
    }
}
impl<T, Store> RecommendList<T, Store> for BlockList<Store>
where
    Store: Contains<T>,
{
    fn recommend(&self, value: &T) -> Option<Action> {
        if self.store.contains(value) {
            Some(self.in_blocklist.clone())
        } else {
            None
        }
    }
}
/// An allowlist
pub struct AllowList<Store> {
    pub(crate) store: Store,
    not_in_allowlist: Action,
}
impl<Store> From<List<Store>> for AllowList<Store> {
    fn from(list: List<Store>) -> Self {
        Self {
            store: list.list,
            not_in_allowlist: list.action,
        }
    }
}
impl<T, Store> RecommendList<T, Store> for AllowList<Store>
where
    Store: Contains<T>,
{
    fn recommend(&self, value: &T) -> Option<Action> {
        if self.store.contains(value) {
            None
        } else {
            Some(self.not_in_allowlist.clone())
        }
    }
    /// A packet passes the allowlist if either of its endpoints is listed.
    /// (Requiring both would reject e.g. every connection from an ephemeral client port.)
    fn recommend_either(&self, val_1: &T, val_2: &T) -> Option<Action> {
        if self.store.contains(val_1) || self.store.contains(val_2) {
            None
        } else {
            Some(self.not_in_allowlist.clone())
        }
    }
}
/// Combined allow+blocklist that performs each in order
pub struct AllowBlockList<T> {
    /// Allowlist
    pub(crate) allow: AllowList<T>,
    /// Blocklist
    pub(crate) block: BlockList<T>,
}
impl<T> AllowBlockList<T> {
    /// Constructor
    pub fn new(allow: AllowList<T>, block: BlockList<T>) -> Self {
        Self { allow, block }
    }
}
impl<T, Store> RecommendList<T, Store> for AllowBlockList<Store>
where
    Store: Contains<T>,
{
    /// Check both allow and blocklist and perform actions
    fn recommend(&self, value: &T) -> Option<Action> {
        // First check the blocklist
        match self.block.recommend(value) {
            Some(Action::None) | None => self.allow.recommend(value),
            Some(action) => Some(action),
        }
    }
    /// A blocklist hit on either endpoint wins; otherwise the packet must pass the
    /// allowlist on at least one endpoint.
    fn recommend_either(&self, val_1: &T, val_2: &T) -> Option<Action> {
        match self.block.recommend_either(val_1, val_2) {
            Some(Action::None) | None => self.allow.recommend_either(val_1, val_2),
            Some(action) => Some(action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(ports: &[u16], action: Action) -> AllowList<HashSet<u16>> {
        AllowList::from(List {
            list: ports.iter().copied().collect(),
            action,
        })
    }
    fn block(ports: &[u16], action: Action) -> BlockList<HashSet<u16>> {
        BlockList::from(List {
            list: ports.iter().copied().collect(),
            action,
        })
    }

    #[test]
    fn allowlist_either_allows_when_only_second_endpoint_listed() {
        // Client ephemeral port 50000 -> server 443; only 443 is allowlisted
        let list = allow(&[443], Action::Drop);
        assert_eq!(list.recommend_either(&50000, &443), None);
        assert_eq!(list.recommend_either(&443, &50000), None);
    }

    #[test]
    fn allowlist_either_rejects_when_neither_endpoint_listed() {
        let list = allow(&[443], Action::Drop);
        assert_eq!(list.recommend_either(&50000, &80), Some(Action::Drop));
    }

    #[test]
    fn empty_allowlist_with_default_action_continues() {
        // The default (empty list, action None) must not restrict anything
        let list = allow(&[], Action::None);
        assert_eq!(list.recommend_either(&1, &2), Some(Action::None));
    }

    #[test]
    fn empty_allowlist_with_action_applies_to_everything() {
        let list = allow(&[], Action::Drop);
        assert_eq!(list.recommend_either(&1, &2), Some(Action::Drop));
    }

    #[test]
    fn blocklist_either_hits_on_either_endpoint() {
        let list = block(&[80], Action::Drop);
        assert_eq!(list.recommend_either(&80, &50000), Some(Action::Drop));
        assert_eq!(list.recommend_either(&50000, &80), Some(Action::Drop));
        assert_eq!(list.recommend_either(&50000, &443), None);
    }

    #[test]
    fn allowblocklist_either_blocklist_wins_over_allowlist_on_other_endpoint() {
        // 443 is allowlisted, but the other endpoint is blocklisted
        let list = AllowBlockList::new(allow(&[443], Action::Drop), block(&[6666], Action::Ignore));
        assert_eq!(list.recommend_either(&443, &6666), Some(Action::Ignore));
        assert_eq!(list.recommend_either(&6666, &443), Some(Action::Ignore));
    }

    #[test]
    fn allowblocklist_either_allows_when_either_endpoint_allowlisted() {
        let list = AllowBlockList::new(allow(&[443], Action::Drop), block(&[80], Action::Drop));
        assert_eq!(list.recommend_either(&50000, &443), None);
        assert_eq!(list.recommend_either(&50000, &22), Some(Action::Drop));
        assert_eq!(list.recommend_either(&50000, &80), Some(Action::Drop));
    }
}

#[cfg(test)]
mod subnet_tests {
    use super::*;
    use crate::config::IpNetPort;
    use crate::subnet::IpNet;

    fn nets(entries: &[&str]) -> Vec<IpNet> {
        entries.iter().map(|s| s.parse().unwrap()).collect()
    }
    fn v4_set(entries: &[&str]) -> Ipv4Set {
        nets(entries)
            .into_iter()
            .filter_map(|n| match n {
                IpNet::V4(n) => Some(n),
                _ => None,
            })
            .collect()
    }
    fn v6_set(entries: &[&str]) -> Ipv6Set {
        nets(entries)
            .into_iter()
            .filter_map(|n| match n {
                IpNet::V6(n) => Some(n),
                _ => None,
            })
            .collect()
    }
    fn ip_port_set(entries: &[&str]) -> IpPortSet {
        #[derive(serde::Deserialize)]
        struct W {
            p: IpNetPort,
        }
        entries
            .iter()
            .map(|s| toml::from_str::<W>(&format!("p = \"{s}\"")).unwrap().p.into_pair())
            .collect()
    }

    #[test]
    fn ipv4_set_blocklist_with_subnet() {
        let list = BlockList { store: v4_set(&["10.0.0.0/8", "1.1.1.1"]), in_blocklist: Action::Drop };
        assert_eq!(list.recommend(&Ipv4Address::new(10, 20, 30, 40)), Some(Action::Drop));
        assert_eq!(list.recommend(&Ipv4Address::new(1, 1, 1, 1)), Some(Action::Drop));
        assert_eq!(list.recommend(&Ipv4Address::new(1, 1, 1, 2)), None);
        assert_eq!(list.recommend(&Ipv4Address::new(11, 0, 0, 0)), None);
    }

    #[test]
    fn ipv6_set_allowlist_with_subnet() {
        let allow = AllowList::from(List { list: v6_set(&["2001:db8::/32"]), action: Action::Drop });
        let inside: Ipv6Address = "2001:db8:1::1".parse::<std::net::Ipv6Addr>().unwrap();
        let outside: Ipv6Address = "2001:db9::1".parse::<std::net::Ipv6Addr>().unwrap();
        assert_eq!(allow.recommend(&inside), None);
        assert_eq!(allow.recommend(&outside), Some(Action::Drop));
    }

    #[test]
    fn ip_port_set_matches_subnet_and_port() {
        let set = ip_port_set(&["10.0.0.0/8:80", "[2001:db8::/32]:443", "1.2.3.4:53"]);
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(set.contains(&IpPort(ip("10.1.2.3"), 80)));
        assert!(!set.contains(&IpPort(ip("10.1.2.3"), 81)));
        assert!(!set.contains(&IpPort(ip("11.0.0.0"), 80)));
        assert!(set.contains(&IpPort(ip("2001:db8::9"), 443)));
        assert!(!set.contains(&IpPort(ip("2001:db8::9"), 80)));
        assert!(set.contains(&IpPort(ip("1.2.3.4"), 53)));
        assert!(!set.contains(&IpPort(ip("1.2.3.5"), 53)));
        assert_eq!(set.len(), 3);
    }
}
