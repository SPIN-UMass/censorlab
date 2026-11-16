//! Deadline-ordered queue backing the `("delay", seconds)` action.
//!
//! This is deliberately pure (no I/O, no clock reads): callers supply `now`,
//! so the release order can be unit tested deterministically.
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::time::Instant;

/// Items held until a deadline, released earliest-deadline-first.
///
/// Items with equal deadlines are released in insertion (FIFO) order.
pub struct DelayQueue<T> {
    heap: BinaryHeap<Reverse<Entry<T>>>,
    next_seq: u64,
}

impl<T> Default for DelayQueue<T> {
    fn default() -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_seq: 0,
        }
    }
}

impl<T> DelayQueue<T> {
    pub fn new() -> Self {
        Self::default()
    }
    /// Hold `item` until `deadline`.
    pub fn push(&mut self, deadline: Instant, item: T) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.heap.push(Reverse(Entry {
            deadline,
            seq,
            item,
        }));
    }
    /// Remove and return the earliest-deadline item, if its deadline is at or before `now`.
    pub fn pop_due(&mut self, now: Instant) -> Option<T> {
        if self.next_deadline()? <= now {
            self.pop_any()
        } else {
            None
        }
    }
    /// Remove and return the earliest-deadline item regardless of its deadline.
    pub fn pop_any(&mut self) -> Option<T> {
        self.heap.pop().map(|Reverse(entry)| entry.item)
    }
    /// The earliest deadline currently held.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.heap.peek().map(|Reverse(entry)| entry.deadline)
    }
    pub fn len(&self) -> usize {
        self.heap.len()
    }
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

/// Heap entry ordered by `(deadline, seq)` only; the item never participates.
struct Entry<T> {
    deadline: Instant,
    seq: u64,
    item: T,
}
impl<T> Entry<T> {
    fn key(&self) -> (Instant, u64) {
        (self.deadline, self.seq)
    }
}
impl<T> PartialEq for Entry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}
impl<T> Eq for Entry<T> {}
impl<T> PartialOrd for Entry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Entry<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn single_item_is_released_at_its_deadline() {
        let t0 = Instant::now();
        let mut q = DelayQueue::new();
        q.push(t0 + ms(100), "a");
        assert_eq!(q.next_deadline(), Some(t0 + ms(100)));
        assert_eq!(q.pop_due(t0), None);
        assert_eq!(q.pop_due(t0 + ms(99)), None);
        assert_eq!(q.pop_due(t0 + ms(100)), Some("a"));
        assert!(q.is_empty());
        assert_eq!(q.next_deadline(), None);
    }

    #[test]
    fn out_of_order_deadlines_are_released_in_deadline_order() {
        let t0 = Instant::now();
        let mut q = DelayQueue::new();
        q.push(t0 + ms(60), "late");
        q.push(t0 + ms(20), "early");
        q.push(t0 + ms(40), "middle");
        let later = t0 + ms(1000);
        let order: Vec<_> = std::iter::from_fn(|| q.pop_due(later)).collect();
        assert_eq!(order, vec!["early", "middle", "late"]);
    }

    #[test]
    fn sooner_item_preempts_held_item() {
        let t0 = Instant::now();
        let mut q = DelayQueue::new();
        q.push(t0 + ms(500), "slow");
        q.push(t0 + ms(20), "fast");
        // The wake-up time must move to the sooner deadline
        assert_eq!(q.next_deadline(), Some(t0 + ms(20)));
        assert_eq!(q.pop_due(t0 + ms(20)), Some("fast"));
        // ...and the held item must still be released later
        assert_eq!(q.pop_due(t0 + ms(20)), None);
        assert_eq!(q.next_deadline(), Some(t0 + ms(500)));
        assert_eq!(q.pop_due(t0 + ms(500)), Some("slow"));
    }

    #[test]
    fn equal_deadlines_are_fifo() {
        let t0 = Instant::now();
        let mut q = DelayQueue::new();
        for i in 0..5 {
            q.push(t0, i);
        }
        let order: Vec<_> = std::iter::from_fn(|| q.pop_due(t0)).collect();
        assert_eq!(order, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn pop_any_drains_in_deadline_order_ignoring_time() {
        let t0 = Instant::now();
        let mut q = DelayQueue::new();
        q.push(t0 + ms(30), 3);
        q.push(t0 + ms(10), 1);
        q.push(t0 + ms(20), 2);
        let order: Vec<_> = std::iter::from_fn(|| q.pop_any()).collect();
        assert_eq!(order, vec![1, 2, 3]);
    }
}
