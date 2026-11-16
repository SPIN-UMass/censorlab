//! A hash map whose entries are additionally ordered by a per-entry deadline.
//!
//! Used to bound connection-tracking state: entries can be expired in
//! deadline order (idle timeouts) and, when a size cap is hit, the entry with
//! the earliest deadline can be evicted. Entries with equal deadlines are
//! ordered by when their deadline was last set, so using "time last seen" as
//! the deadline gives plain LRU ordering.
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

#[derive(Debug)]
struct Entry<V> {
    /// Key into `ExpiringMap::order`
    order_key: (u64, u64),
    value: V,
}

#[derive(Debug)]
pub struct ExpiringMap<K, V> {
    entries: HashMap<K, Entry<V>>,
    /// (deadline, sequence number) -> key
    order: BTreeMap<(u64, u64), K>,
    /// Monotonic counter used to break deadline ties by recency
    next_seq: u64,
}

impl<K: Clone + Eq + Hash, V> Default for ExpiringMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone + Eq + Hash, V> ExpiringMap<K, V> {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|e| &e.value)
    }
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|e| &mut e.value)
    }
    /// The deadline currently associated with `key`
    pub fn deadline(&self, key: &K) -> Option<u64> {
        self.entries.get(key).map(|e| e.order_key.0)
    }
    fn next_order_key(&mut self, deadline: u64) -> (u64, u64) {
        let seq = self.next_seq;
        self.next_seq += 1;
        (deadline, seq)
    }
    /// Insert (or replace) `key`, returning the previous value if any
    pub fn insert(&mut self, key: K, value: V, deadline: u64) -> Option<V> {
        let old = self.remove(&key);
        let order_key = self.next_order_key(deadline);
        self.order.insert(order_key, key.clone());
        self.entries.insert(key, Entry { order_key, value });
        old
    }
    /// Update the deadline of an existing entry. Returns false if `key` is absent.
    pub fn set_deadline(&mut self, key: &K, deadline: u64) -> bool {
        let order_key = self.next_order_key(deadline);
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        let k = self
            .order
            .remove(&entry.order_key)
            .expect("ExpiringMap order index out of sync");
        entry.order_key = order_key;
        self.order.insert(order_key, k);
        true
    }
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let entry = self.entries.remove(key)?;
        self.order.remove(&entry.order_key);
        Some(entry.value)
    }
    /// Remove the entry with the earliest deadline (ties: least recently updated)
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        let (_, key) = self.order.pop_first()?;
        let entry = self
            .entries
            .remove(&key)
            .expect("ExpiringMap order index out of sync");
        Some((key, entry.value))
    }
    /// Remove the entry with the earliest deadline if that deadline is `<= now`
    pub fn pop_expired(&mut self, now: u64) -> Option<(K, V)> {
        match self.order.first_key_value() {
            Some(((deadline, _), _)) if *deadline <= now => self.pop_first(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_remove() {
        let mut m = ExpiringMap::new();
        assert!(m.insert("a", 1, 10).is_none());
        assert_eq!(m.get(&"a"), Some(&1));
        assert_eq!(m.insert("a", 2, 20), Some(1));
        assert_eq!(m.len(), 1);
        assert_eq!(m.deadline(&"a"), Some(20));
        assert_eq!(m.remove(&"a"), Some(2));
        assert!(m.is_empty());
        assert!(m.pop_first().is_none());
    }

    #[test]
    fn pop_first_orders_by_deadline_then_recency() {
        let mut m = ExpiringMap::new();
        m.insert("late", (), 30);
        m.insert("a", (), 10);
        m.insert("b", (), 10);
        // Touching "a" with the same deadline makes it more recent than "b"
        assert!(m.set_deadline(&"a", 10));
        assert_eq!(m.pop_first().map(|(k, _)| k), Some("b"));
        assert_eq!(m.pop_first().map(|(k, _)| k), Some("a"));
        assert_eq!(m.pop_first().map(|(k, _)| k), Some("late"));
        assert!(m.pop_first().is_none());
    }

    #[test]
    fn pop_expired_respects_now() {
        let mut m = ExpiringMap::new();
        m.insert("a", (), 10);
        m.insert("b", (), 20);
        assert!(m.pop_expired(9).is_none());
        assert_eq!(m.pop_expired(10).map(|(k, _)| k), Some("a"));
        assert!(m.pop_expired(19).is_none());
        assert!(m.set_deadline(&"b", 5));
        assert_eq!(m.pop_expired(19).map(|(k, _)| k), Some("b"));
        assert!(!m.set_deadline(&"b", 5));
    }
}
