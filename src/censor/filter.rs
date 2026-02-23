//! Allow/blocklist filtering infrastructure.
//!
//! Provides generic `AllowList`, `BlockList`, and `AllowBlockList` types
//! used for MAC, IP, port, and ip-port filtering throughout the censor.

use super::{Action, PortVec};
use crate::config::List;
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

/// Trait that can be shared between both an allow and blocklist
pub trait RecommendList<T, Store>
where
    Store: Contains<T>,
{
    /// Recommends an action based on some value
    fn recommend(&self, value: &T) -> Option<Action>;
    /// Recommends an action for 2 different values
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
            Some(self.in_blocklist)
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
            Some(self.not_in_allowlist)
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
}
