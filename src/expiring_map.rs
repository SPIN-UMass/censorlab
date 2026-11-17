//! A hash map whose entries are additionally ordered by a per-entry deadline.
//!
//! Used to bound connection-tracking state: entries can be expired in
//! deadline order (idle timeouts) and, when a size cap is hit, the entry with
//! the earliest deadline can be evicted. Entries with equal deadlines are
//! ordered by when their deadline was last set, so using "time last seen" as
//! the deadline gives plain LRU ordering.
//!
//! # Representation
//! Every entry has an order key `(deadline, seq)`, where `seq` increases with
//! every insert or deadline update, and entries leave in order-key order.
//! Connection tracking updates a deadline on every packet, always to "now plus
//! one of a few timeouts" with a clock that never goes back, so the order keys
//! set with any one timeout only grow. Entries are therefore kept in a few
//! *runs*: doubly-linked lists, each sorted by order key. A new order key is
//! appended to a run whose last deadline is not later than its own (its `seq`
//! is the largest yet, so the run stays sorted); the earliest entry overall is
//! the earliest run head. An order key that fits no run (deadlines that move
//! backwards, or more distinct timeouts than runs) goes to an ordered
//! overflow index instead, so the order is exact for any sequence of
//! deadlines; only the cost depends on them.
//!
//! Lookups by key go through a hash index; [`Handle`]s address an entry
//! directly so that a caller touching the same entry several times hashes its
//! key once.
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

/// Maximum number of sorted runs (see the module docs)
const MAX_RUNS: usize = 8;
/// Placeholder link / run index
const NIL: usize = usize::MAX;

/// Order key: (deadline, sequence number)
type OrderKey = (u64, u64);

/// Refers to one entry of an [`ExpiringMap`] until that entry is removed.
/// Using it after that yields `None` (it is never mistaken for a later entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    slot: usize,
    generation: u64,
}

#[derive(Debug)]
struct Node<K, V> {
    key: K,
    value: V,
    order: OrderKey,
    /// Index of the run holding this entry, or NIL for the overflow index
    run: usize,
    prev: usize,
    next: usize,
}

#[derive(Debug)]
struct Slot<K, V> {
    /// Bumped whenever the slot is vacated, invalidating its handles
    generation: u64,
    node: Option<Node<K, V>>,
}

/// A doubly-linked list of entries sorted by order key
#[derive(Debug)]
struct Run {
    head: usize,
    tail: usize,
    /// Order key of `head` (meaningless when empty)
    head_order: OrderKey,
    /// Deadline of `tail` (meaningless when empty)
    tail_deadline: u64,
}
impl Run {
    fn is_empty(&self) -> bool {
        self.head == NIL
    }
}

#[derive(Debug)]
pub struct ExpiringMap<K, V> {
    index: HashMap<K, usize>,
    slots: Vec<Slot<K, V>>,
    /// Vacant slots
    free: Vec<usize>,
    runs: Vec<Run>,
    /// Order keys that fit no run
    overflow: BTreeMap<OrderKey, usize>,
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
            index: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            runs: Vec::new(),
            overflow: BTreeMap::new(),
            next_seq: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.index.len()
    }
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
    /// Handle of the entry for `key`, if present
    pub fn find(&self, key: &K) -> Option<Handle> {
        self.index.get(key).map(|&slot| Handle {
            slot,
            generation: self.slots[slot].generation,
        })
    }
    pub fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }
    pub fn get(&self, key: &K) -> Option<&V> {
        self.find(key).and_then(|handle| self.get_at(handle))
    }
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.find(key).and_then(|handle| self.get_mut_at(handle))
    }
    fn node(&self, handle: Handle) -> Option<&Node<K, V>> {
        self.slots
            .get(handle.slot)
            .filter(|slot| slot.generation == handle.generation)
            .and_then(|slot| slot.node.as_ref())
    }
    pub fn get_at(&self, handle: Handle) -> Option<&V> {
        self.node(handle).map(|node| &node.value)
    }
    pub fn get_mut_at(&mut self, handle: Handle) -> Option<&mut V> {
        self.slots
            .get_mut(handle.slot)
            .filter(|slot| slot.generation == handle.generation)
            .and_then(|slot| slot.node.as_mut())
            .map(|node| &mut node.value)
    }
    /// The deadline currently associated with `key`
    pub fn deadline(&self, key: &K) -> Option<u64> {
        self.find(key)
            .and_then(|handle| self.node(handle))
            .map(|node| node.order.0)
    }
    fn next_order_key(&mut self, deadline: u64) -> OrderKey {
        let seq = self.next_seq;
        self.next_seq += 1;
        (deadline, seq)
    }
    /// Insert (or replace) `key`, returning the previous value if any
    pub fn insert(&mut self, key: K, value: V, deadline: u64) -> Option<V> {
        self.insert_handle(key, value, deadline).1
    }
    /// [`Self::insert`], also returning the new entry's handle
    pub fn insert_handle(&mut self, key: K, value: V, deadline: u64) -> (Handle, Option<V>) {
        let old = self.remove(&key);
        let order = self.next_order_key(deadline);
        let node = Node {
            key: key.clone(),
            value,
            order,
            run: NIL,
            prev: NIL,
            next: NIL,
        };
        let slot = match self.free.pop() {
            Some(slot) => {
                self.slots[slot].node = Some(node);
                slot
            }
            None => {
                self.slots.push(Slot {
                    generation: 0,
                    node: Some(node),
                });
                self.slots.len() - 1
            }
        };
        self.link(slot);
        self.index.insert(key, slot);
        let handle = Handle {
            slot,
            generation: self.slots[slot].generation,
        };
        (handle, old)
    }
    /// Update the deadline of an existing entry. Returns false if `key` is absent.
    pub fn set_deadline(&mut self, key: &K, deadline: u64) -> bool {
        match self.find(key) {
            Some(handle) => self.set_deadline_at(handle, deadline),
            None => false,
        }
    }
    /// [`Self::set_deadline`] by handle. Returns false if the entry is gone.
    pub fn set_deadline_at(&mut self, handle: Handle, deadline: u64) -> bool {
        if self.node(handle).is_none() {
            return false;
        }
        let order = self.next_order_key(deadline);
        self.unlink(handle.slot);
        self.node_mut(handle.slot).order = order;
        self.link(handle.slot);
        true
    }
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let slot = *self.index.get(key)?;
        Some(self.remove_slot(slot).1)
    }
    /// [`Self::remove`] by handle
    pub fn remove_at(&mut self, handle: Handle) -> Option<(K, V)> {
        self.node(handle)?;
        Some(self.remove_slot(handle.slot))
    }
    /// Remove the entry with the earliest deadline (ties: least recently updated)
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        let (_, slot) = self.first()?;
        Some(self.remove_slot(slot))
    }
    /// Remove the entry with the earliest deadline if that deadline is `<= now`
    pub fn pop_expired(&mut self, now: u64) -> Option<(K, V)> {
        match self.first() {
            Some(((deadline, _), slot)) if deadline <= now => Some(self.remove_slot(slot)),
            _ => None,
        }
    }

    fn node_mut(&mut self, slot: usize) -> &mut Node<K, V> {
        self.slots[slot]
            .node
            .as_mut()
            .expect("ExpiringMap links point at occupied slots")
    }
    /// Order key and slot of the entry with the smallest order key
    fn first(&self) -> Option<(OrderKey, usize)> {
        let runs = self
            .runs
            .iter()
            .filter(|run| !run.is_empty())
            .map(|run| (run.head_order, run.head));
        let overflow = self.overflow.first_key_value().map(|(&order, &slot)| (order, slot));
        runs.chain(overflow).min_by_key(|&(order, _)| order)
    }
    fn remove_slot(&mut self, slot: usize) -> (K, V) {
        self.unlink(slot);
        let entry = &mut self.slots[slot];
        let node = entry
            .node
            .take()
            .expect("ExpiringMap index points at occupied slots");
        entry.generation += 1;
        self.free.push(slot);
        self.index.remove(&node.key);
        (node.key, node.value)
    }
    /// Place the (unlinked) entry in `slot` into the order by its order key
    fn link(&mut self, slot: usize) {
        let order = self.node_mut(slot).order;
        // The run whose last deadline is the latest one not after ours keeps
        // runs of one timeout together; any empty run will do otherwise
        let mut best: Option<usize> = None;
        let mut empty: Option<usize> = None;
        for (i, run) in self.runs.iter().enumerate() {
            if run.is_empty() {
                empty = empty.or(Some(i));
            } else if run.tail_deadline <= order.0
                && best.is_none_or(|b| self.runs[b].tail_deadline < run.tail_deadline)
            {
                best = Some(i);
            }
        }
        let run = match best.or(empty) {
            Some(run) => run,
            None if self.runs.len() < MAX_RUNS => {
                self.runs.push(Run {
                    head: NIL,
                    tail: NIL,
                    head_order: (0, 0),
                    tail_deadline: 0,
                });
                self.runs.len() - 1
            }
            None => {
                let node = self.node_mut(slot);
                node.run = NIL;
                node.prev = NIL;
                node.next = NIL;
                self.overflow.insert(order, slot);
                return;
            }
        };
        // Append: `order` has the largest sequence number yet and a deadline
        // no earlier than the tail's, so the run stays sorted
        let tail = self.runs[run].tail;
        {
            let node = self.node_mut(slot);
            node.run = run;
            node.prev = tail;
            node.next = NIL;
        }
        if tail == NIL {
            self.runs[run].head = slot;
            self.runs[run].head_order = order;
        } else {
            self.node_mut(tail).next = slot;
        }
        self.runs[run].tail = slot;
        self.runs[run].tail_deadline = order.0;
    }
    /// Take the entry in `slot` out of the order
    fn unlink(&mut self, slot: usize) {
        let (run, prev, next, order) = {
            let node = self.node_mut(slot);
            (node.run, node.prev, node.next, node.order)
        };
        if run == NIL {
            self.overflow.remove(&order);
            return;
        }
        if prev == NIL {
            self.runs[run].head = next;
            if next != NIL {
                self.runs[run].head_order = self.node_mut(next).order;
            }
        } else {
            self.node_mut(prev).next = next;
        }
        if next == NIL {
            self.runs[run].tail = prev;
            if prev != NIL {
                self.runs[run].tail_deadline = self.node_mut(prev).order.0;
            }
        } else {
            self.node_mut(next).prev = prev;
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

    #[test]
    fn handles_are_invalidated_by_removal() {
        let mut m = ExpiringMap::new();
        let (a, _) = m.insert_handle("a", 1, 10);
        assert_eq!(m.find(&"a"), Some(a));
        *m.get_mut_at(a).unwrap() += 1;
        assert!(m.set_deadline_at(a, 5));
        assert_eq!(m.deadline(&"a"), Some(5));
        assert_eq!(m.remove_at(a), Some(("a", 2)));
        // The slot is reused, but the old handle does not reach the new entry
        let (b, _) = m.insert_handle("b", 3, 10);
        assert_eq!(m.get_at(a), None);
        assert!(!m.set_deadline_at(a, 1));
        assert_eq!(m.remove_at(a), None);
        assert_eq!(m.get_at(b), Some(&3));
    }

    /// The previous implementation (a hash map plus an ordered index of all
    /// order keys), kept as the reference the run-based order must match
    #[derive(Default)]
    struct Reference {
        entries: HashMap<u32, (OrderKey, u32)>,
        order: BTreeMap<OrderKey, u32>,
        next_seq: u64,
    }
    impl Reference {
        fn order_key(&mut self, deadline: u64) -> OrderKey {
            self.next_seq += 1;
            (deadline, self.next_seq)
        }
        fn insert(&mut self, key: u32, value: u32, deadline: u64) -> Option<u32> {
            let old = self.remove(key);
            let order = self.order_key(deadline);
            self.order.insert(order, key);
            self.entries.insert(key, (order, value));
            old
        }
        fn set_deadline(&mut self, key: u32, deadline: u64) -> bool {
            let order = self.order_key(deadline);
            let Some(entry) = self.entries.get_mut(&key) else {
                return false;
            };
            self.order.remove(&entry.0);
            entry.0 = order;
            self.order.insert(order, key);
            true
        }
        fn remove(&mut self, key: u32) -> Option<u32> {
            let (order, value) = self.entries.remove(&key)?;
            self.order.remove(&order);
            Some(value)
        }
        fn pop_first(&mut self) -> Option<(u32, u32)> {
            let (_, key) = self.order.pop_first()?;
            let (_, value) = self.entries.remove(&key).unwrap();
            Some((key, value))
        }
        fn pop_expired(&mut self, now: u64) -> Option<(u32, u32)> {
            match self.order.first_key_value() {
                Some(((deadline, _), _)) if *deadline <= now => self.pop_first(),
                _ => None,
            }
        }
    }

    /// Random operations, checked against [`Reference`] after every step
    fn check_against_reference(seed: u64, timeouts: &[u64], monotone: bool) {
        let mut state = seed;
        let mut rand = move |n: u64| {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let mut m = ExpiringMap::new();
        let mut r = Reference::default();
        let mut now = 0;
        for step in 0..20_000 {
            now += rand(3);
            let deadline = if monotone {
                now + timeouts[rand(timeouts.len() as u64) as usize]
            } else {
                rand(1000)
            };
            let key = rand(300) as u32;
            match rand(10) {
                0..=2 => assert_eq!(m.insert(key, step, deadline), r.insert(key, step, deadline)),
                3..=5 => assert_eq!(m.set_deadline(&key, deadline), r.set_deadline(key, deadline)),
                6 => assert_eq!(m.remove(&key), r.remove(key)),
                7 => assert_eq!(m.pop_first(), r.pop_first()),
                8 => assert_eq!(m.pop_expired(now), r.pop_expired(now)),
                _ => {
                    assert_eq!(m.get(&key), r.entries.get(&key).map(|(_, v)| v));
                    assert_eq!(m.deadline(&key), r.entries.get(&key).map(|(o, _)| o.0));
                }
            }
            assert_eq!(m.len(), r.entries.len());
        }
        // Drain: the full order must agree
        while let Some(entry) = r.pop_first() {
            assert_eq!(m.pop_first(), Some(entry));
        }
        assert!(m.pop_first().is_none());
    }

    #[test]
    fn matches_reference_with_few_timeouts() {
        // The connection-tracking pattern: now + one of a few timeouts
        for seed in 1..=5 {
            check_against_reference(seed, &[0, 60, 120, 3600], true);
        }
    }

    #[test]
    fn matches_reference_with_many_timeouts() {
        // More timeouts than runs: some order keys go to the overflow index
        let timeouts: Vec<u64> = (0..20).map(|t| t * 37).collect();
        for seed in 1..=5 {
            check_against_reference(seed, &timeouts, true);
        }
    }

    #[test]
    fn matches_reference_with_arbitrary_deadlines() {
        for seed in 1..=5 {
            check_against_reference(seed, &[], false);
        }
    }
}
