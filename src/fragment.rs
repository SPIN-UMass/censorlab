//! TSPU-style IP fragment normalization.
//!
//! Xue et al. (IMC 2022, Section 5.3.1) observed that Russia's TSPU devices
//!
//! * buffer the fragments of an IPv4 packet and forward them individually,
//!   without reassembly, once the last one has arrived;
//! * forward every fragment with the TTL of the first fragment (offset zero);
//! * forward no fragment of a packet that has a duplicated or overlapping one;
//! * discard an incomplete queue after about 5 seconds; and
//! * discard the queue of a packet with more than 45 fragments.
//!
//! [`Normalizer`] implements exactly that as a pure state machine: it does no
//! I/O and reads no clock.  Callers hand it an opaque item per fragment (a
//! held frame, a held NFQ message, a packet index) and the current time, and
//! get back the items to forward and the items to drop.
//!
//! Only IPv4 is handled; IPv6 fragments are not recognized by
//! [`Fragment::parse`] and so are never buffered.
use smoltcp::wire::{EthernetFrame, EthernetProtocol, Ipv4Packet};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

/// Limits of the fragment cache. The defaults are the values measured on the TSPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Most fragments accepted for one packet; one more discards its queue
    pub max_fragments: usize,
    /// How long an incomplete queue is kept, measured from its first fragment
    pub timeout: Duration,
    /// Most packets buffered at once. When exceeded, the oldest queue is discarded
    pub max_datagrams: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_fragments: 45,
            timeout: Duration::from_secs(5),
            max_datagrams: 4096,
        }
    }
}

/// What identifies the packet a fragment belongs to: source, destination and IP ID
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Key {
    src: [u8; 4],
    dst: [u8; 4],
    ident: u16,
}

/// The fields of an IPv4 fragment that normalization depends on
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub key: Key,
    /// Offset of this fragment's payload in the original packet's payload, in bytes
    pub offset: u32,
    /// Length of this fragment's payload in bytes
    pub len: u32,
    /// Whether more fragments follow (the MF flag)
    pub more: bool,
    pub ttl: u8,
}

impl Fragment {
    /// Recognize an IPv4 fragment (no link-layer header). Returns `None` for
    /// anything else: unfragmented packets, IPv6, and malformed headers.
    pub fn parse(ip_packet: &[u8]) -> Option<Self> {
        if ip_packet.first()? >> 4 != 4 {
            return None;
        }
        let ip = Ipv4Packet::new_checked(ip_packet).ok()?;
        let offset = u32::from(ip.frag_offset());
        let more = ip.more_frags();
        if offset == 0 && !more {
            return None;
        }
        let len = u32::from(ip.total_len()).checked_sub(u32::from(ip.header_len()))?;
        let bytes = ip.into_inner();
        Some(Fragment {
            key: Key {
                src: bytes[12..16].try_into().ok()?,
                dst: bytes[16..20].try_into().ok()?,
                ident: u16::from_be_bytes([bytes[4], bytes[5]]),
            },
            offset,
            len,
            more,
            ttl: bytes[8],
        })
    }

    /// Recognize an IPv4 fragment inside an Ethernet frame
    pub fn parse_ethernet(frame: &[u8]) -> Option<Self> {
        let eth = EthernetFrame::new_checked(frame).ok()?;
        match eth.ethertype() {
            EthernetProtocol::Ipv4 => Self::parse(eth.payload()),
            _ => None,
        }
    }

    fn end(&self) -> u32 {
        self.offset + self.len
    }

    /// Duplicates and partial overlaps both count; so does an empty fragment
    /// that sits inside another one.
    fn overlaps(&self, other: &Fragment) -> bool {
        self.offset == other.offset || (self.offset < other.end() && other.offset < self.end())
    }
}

/// A fragment to forward, with the TTL to give it if that differs from its own
#[derive(Debug, Eq, PartialEq)]
pub struct Released<T> {
    pub item: T,
    pub ttl: Option<u8>,
}

/// What became of the buffered fragments. Both lists empty means the fragment is held.
#[derive(Debug, Eq, PartialEq)]
pub struct Outcome<T> {
    /// A completed packet's fragments, in arrival order
    pub forward: Vec<Released<T>>,
    /// Fragments of discarded queues
    pub drop: Vec<T>,
}

impl<T> Default for Outcome<T> {
    fn default() -> Self {
        Self {
            forward: Vec::new(),
            drop: Vec::new(),
        }
    }
}

enum State<T> {
    /// Fragments held so far, in arrival order
    Buffering(Vec<(Fragment, T)>),
    /// The queue was discarded; the packet's remaining fragments are dropped as they arrive
    Discarding,
}

struct Entry<T> {
    deadline: Duration,
    state: State<T>,
}

/// The fragment cache. Time is a duration since any fixed origin and is
/// expected not to go backwards; if it does, the latest time seen is used.
pub struct Normalizer<T> {
    config: Config,
    entries: HashMap<Key, Entry<T>>,
    /// Keys in deadline order. Entries removed early leave stale records
    /// behind, recognized by their deadline no longer matching.
    order: VecDeque<(Duration, Key)>,
    now: Duration,
}

impl<T> Normalizer<T> {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            order: VecDeque::new(),
            now: Duration::ZERO,
        }
    }

    /// Number of fragments currently held
    pub fn held(&self) -> usize {
        self.entries
            .values()
            .map(|entry| match &entry.state {
                State::Buffering(held) => held.len(),
                State::Discarding => 0,
            })
            .sum()
    }

    /// When the oldest queue times out
    pub fn next_deadline(&self) -> Option<Duration> {
        self.order
            .iter()
            .find(|(deadline, key)| self.entries.get(key).is_some_and(|e| e.deadline == *deadline))
            .map(|(deadline, _)| *deadline)
    }

    /// Discard the queues that have timed out and return their fragments
    pub fn expire(&mut self, now: Duration) -> Vec<T> {
        self.now = self.now.max(now);
        let mut dropped = Vec::new();
        while let Some(&(deadline, key)) = self.order.front() {
            if deadline > self.now {
                break;
            }
            self.order.pop_front();
            if self.entries.get(&key).is_some_and(|e| e.deadline == deadline) {
                dropped.extend(self.remove(&key));
            }
        }
        dropped
    }

    /// Discard everything, e.g. at shutdown or the end of a capture
    pub fn drain(&mut self) -> Vec<T> {
        self.order.clear();
        self.entries
            .drain()
            .flat_map(|(_, entry)| match entry.state {
                State::Buffering(held) => held,
                State::Discarding => Vec::new(),
            })
            .map(|(_, item)| item)
            .collect()
    }

    /// Take a fragment that would otherwise be forwarded
    pub fn push(&mut self, now: Duration, fragment: Fragment, item: T) -> Outcome<T> {
        let mut outcome = Outcome {
            forward: Vec::new(),
            drop: self.expire(now),
        };
        let key = fragment.key;
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.config.max_datagrams.max(1) {
                match self.order.pop_front() {
                    Some((_, oldest)) => outcome.drop.extend(self.remove(&oldest)),
                    None => break,
                }
            }
            let deadline = self.now + self.config.timeout;
            self.order.push_back((deadline, key));
            self.entries.insert(
                key,
                Entry {
                    deadline,
                    state: State::Buffering(Vec::new()),
                },
            );
        }
        let Some(entry) = self.entries.get_mut(&key) else {
            // Unreachable: the entry was just looked up or inserted
            outcome.drop.push(item);
            return outcome;
        };
        let held = match &mut entry.state {
            State::Discarding => {
                outcome.drop.push(item);
                return outcome;
            }
            State::Buffering(held) => held,
        };
        let malformed = fragment.len == 0
            || held.len() >= self.config.max_fragments
            || held.iter().any(|(other, _)| fragment.overlaps(other));
        held.push((fragment, item));
        if malformed || extends_past_last(held) {
            let held = std::mem::take(held);
            entry.state = State::Discarding;
            outcome.drop.extend(held.into_iter().map(|(_, item)| item));
        } else if let Some(ttl) = complete(held) {
            let held = std::mem::take(held);
            self.entries.remove(&key);
            outcome.forward = held
                .into_iter()
                .map(|(fragment, item)| Released {
                    item,
                    ttl: (fragment.ttl != ttl).then_some(ttl),
                })
                .collect();
        }
        outcome
    }

    fn remove(&mut self, key: &Key) -> Vec<T> {
        match self.entries.remove(key).map(|entry| entry.state) {
            Some(State::Buffering(held)) => held.into_iter().map(|(_, item)| item).collect(),
            Some(State::Discarding) | None => Vec::new(),
        }
    }
}

/// The end of the packet, once its last fragment (MF clear) has arrived
fn last_end<T>(held: &[(Fragment, T)]) -> Option<u32> {
    held.iter().find(|(f, _)| !f.more).map(|(f, _)| f.end())
}

/// Whether any fragment lies beyond the last one, or there are two last ones
fn extends_past_last<T>(held: &[(Fragment, T)]) -> bool {
    let Some(end) = last_end(held) else {
        return false;
    };
    held.iter().filter(|(f, _)| !f.more).count() > 1 || held.iter().any(|(f, _)| f.end() > end)
}

/// The first fragment's TTL if `held` (which has no overlaps) covers the whole packet
fn complete<T>(held: &[(Fragment, T)]) -> Option<u8> {
    let end = last_end(held)?;
    let first = held.iter().find(|(f, _)| f.offset == 0)?;
    let covered: u32 = held.iter().map(|(f, _)| f.len).sum();
    (covered == end).then_some(first.0.ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn frag(ident: u16, offset: u32, len: u32, more: bool, ttl: u8) -> Fragment {
        Fragment {
            key: Key {
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
                ident,
            },
            offset,
            len,
            more,
            ttl,
        }
    }

    fn forwarded<T>(items: Vec<(T, Option<u8>)>) -> Vec<Released<T>> {
        items.into_iter().map(|(item, ttl)| Released { item, ttl }).collect()
    }

    /// An IPv4 header followed by `len` payload bytes
    fn ipv4(ident: u16, offset: u16, len: usize, more: bool, ttl: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 20 + len];
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len((20 + len) as u16);
        ip.set_ident(ident);
        ip.set_more_frags(more);
        ip.set_frag_offset(offset);
        ip.set_hop_limit(ttl);
        ip.set_next_header(smoltcp::wire::IpProtocol::Udp);
        ip.set_src_addr([10, 0, 0, 1].into());
        ip.set_dst_addr([10, 0, 0, 2].into());
        ip.fill_checksum();
        bytes
    }

    #[test]
    fn parse_recognizes_only_ipv4_fragments() {
        assert_eq!(Fragment::parse(&ipv4(7, 0, 100, false, 64)), None);
        assert_eq!(
            Fragment::parse(&ipv4(7, 0, 1400, true, 64)),
            Some(frag(7, 0, 1400, true, 64))
        );
        assert_eq!(
            Fragment::parse(&ipv4(7, 1400, 100, false, 3)),
            Some(frag(7, 1400, 100, false, 3))
        );
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&ipv4(7, 1400, 100, false, 3));
        assert_eq!(Fragment::parse_ethernet(&frame), Some(frag(7, 1400, 100, false, 3)));
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        assert_eq!(Fragment::parse_ethernet(&frame), None);
        assert_eq!(Fragment::parse(&[]), None);
        assert_eq!(Fragment::parse(&[0x45, 0, 0]), None);
        // IPv6 is not handled
        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60;
        assert_eq!(Fragment::parse(&v6), None);
    }

    #[test]
    fn fragments_are_held_until_the_last_arrives_then_take_the_first_ttl() {
        let mut n = Normalizer::new(Config::default());
        assert_eq!(n.push(secs(0), frag(1, 0, 1400, true, 64), "a"), Outcome::default());
        assert_eq!(n.push(secs(0), frag(1, 1400, 1400, true, 5), "b"), Outcome::default());
        assert_eq!(n.held(), 2);
        let outcome = n.push(secs(1), frag(1, 2800, 10, false, 64), "c");
        assert_eq!(outcome.forward, forwarded(vec![("a", None), ("b", Some(64)), ("c", None)]));
        assert!(outcome.drop.is_empty());
        assert_eq!(n.held(), 0);
        assert_eq!(n.next_deadline(), None);
    }

    #[test]
    fn out_of_order_fragments_wait_for_the_gap_and_use_the_offset_zero_ttl() {
        let mut n = Normalizer::new(Config::default());
        assert_eq!(n.push(secs(0), frag(1, 16, 8, false, 9), "last"), Outcome::default());
        assert_eq!(n.push(secs(0), frag(1, 8, 8, true, 7), "middle"), Outcome::default());
        let outcome = n.push(secs(0), frag(1, 0, 8, true, 42), "first");
        assert_eq!(
            outcome.forward,
            forwarded(vec![("last", Some(42)), ("middle", Some(42)), ("first", None)])
        );
    }

    #[test]
    fn packets_are_kept_apart_by_ip_id() {
        let mut n = Normalizer::new(Config::default());
        assert_eq!(n.push(secs(0), frag(1, 0, 8, true, 64), "a0"), Outcome::default());
        assert_eq!(n.push(secs(0), frag(2, 0, 8, true, 64), "b0"), Outcome::default());
        let outcome = n.push(secs(0), frag(2, 8, 8, false, 64), "b1");
        assert_eq!(outcome.forward, forwarded(vec![("b0", None), ("b1", None)]));
        assert_eq!(n.held(), 1);
    }

    #[test]
    fn a_duplicate_discards_the_queue_and_the_rest_of_the_packet() {
        let mut n = Normalizer::new(Config::default());
        n.push(secs(0), frag(1, 0, 8, true, 64), "a");
        let outcome = n.push(secs(0), frag(1, 0, 8, true, 64), "dup");
        assert!(outcome.forward.is_empty());
        assert_eq!(outcome.drop, vec!["a", "dup"]);
        // The fragment that would have completed the packet is dropped too
        let outcome = n.push(secs(1), frag(1, 8, 8, false, 64), "b");
        assert_eq!(outcome, Outcome { forward: vec![], drop: vec!["b"] });
        // Once the queue has timed out the IP ID can be used again
        assert_eq!(n.push(secs(5), frag(1, 0, 8, true, 64), "c"), Outcome::default());
        let outcome = n.push(secs(5), frag(1, 8, 8, false, 64), "d");
        assert_eq!(outcome.forward, forwarded(vec![("c", None), ("d", None)]));
    }

    #[test]
    fn an_overlap_discards_the_queue() {
        let mut n = Normalizer::new(Config::default());
        n.push(secs(0), frag(1, 0, 16, true, 64), "a");
        let outcome = n.push(secs(0), frag(1, 8, 16, false, 64), "b");
        assert_eq!(outcome, Outcome { forward: vec![], drop: vec!["a", "b"] });
    }

    #[test]
    fn data_beyond_the_last_fragment_discards_the_queue() {
        let mut n = Normalizer::new(Config::default());
        n.push(secs(0), frag(1, 8, 8, false, 64), "last");
        let outcome = n.push(secs(0), frag(1, 16, 8, true, 64), "beyond");
        assert_eq!(outcome.drop, vec!["last", "beyond"]);
        let mut n = Normalizer::new(Config::default());
        n.push(secs(0), frag(1, 8, 8, false, 64), "last");
        let outcome = n.push(secs(0), frag(1, 24, 8, false, 64), "another last");
        assert_eq!(outcome.drop, vec!["last", "another last"]);
    }

    #[test]
    fn forty_five_fragments_pass_and_forty_six_do_not() {
        for (count, passes) in [(45u32, true), (46, false)] {
            let mut n = Normalizer::new(Config::default());
            let mut forwarded = 0;
            let mut dropped = 0;
            for i in 0..count {
                let outcome = n.push(secs(0), frag(1, i * 8, 8, i + 1 < count, 64), i);
                forwarded += outcome.forward.len();
                dropped += outcome.drop.len();
            }
            assert_eq!(forwarded, if passes { 45 } else { 0 }, "{count} fragments");
            assert_eq!(dropped, if passes { 0 } else { 46 }, "{count} fragments");
        }
    }

    #[test]
    fn an_incomplete_queue_is_discarded_after_the_timeout() {
        let mut n = Normalizer::new(Config::default());
        n.push(secs(10), frag(1, 0, 8, true, 64), "a");
        n.push(secs(12), frag(1, 8, 8, true, 64), "b");
        assert_eq!(n.next_deadline(), Some(secs(15)));
        assert!(n.expire(secs(14)).is_empty());
        assert_eq!(n.expire(secs(15)), vec!["a", "b"]);
        assert_eq!(n.held(), 0);
        // A late last fragment starts a new, incomplete queue
        assert_eq!(n.push(secs(16), frag(1, 16, 8, false, 64), "c"), Outcome::default());
        assert_eq!(n.drain(), vec!["c"]);
    }

    #[test]
    fn push_expires_older_queues_first() {
        let mut n = Normalizer::new(Config::default());
        n.push(secs(0), frag(1, 0, 8, true, 64), "old");
        let outcome = n.push(secs(6), frag(2, 0, 8, true, 64), "new");
        assert_eq!(outcome, Outcome { forward: vec![], drop: vec!["old"] });
    }

    #[test]
    fn the_oldest_queue_is_discarded_when_the_cache_is_full() {
        let config = Config { max_datagrams: 2, ..Config::default() };
        let mut n = Normalizer::new(config);
        n.push(secs(0), frag(1, 0, 8, true, 64), "one");
        n.push(secs(1), frag(2, 0, 8, true, 64), "two");
        let outcome = n.push(secs(2), frag(3, 0, 8, true, 64), "three");
        assert_eq!(outcome, Outcome { forward: vec![], drop: vec!["one"] });
        assert_eq!(n.held(), 2);
    }

    #[test]
    fn time_going_backwards_does_not_extend_a_queue() {
        let mut n = Normalizer::new(Config::default());
        n.push(secs(10), frag(1, 0, 8, true, 64), "a");
        // An earlier timestamp is treated as "now"
        n.push(secs(3), frag(2, 0, 8, true, 64), "b");
        assert_eq!(n.expire(secs(15)), vec!["a", "b"]);
    }
}
