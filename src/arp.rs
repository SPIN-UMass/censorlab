use procfs::ProcError;
use smoltcp::wire::{EthernetAddress, IpAddress};
use std::collections::HashMap;

/// NFQ doesn't give us MAC addresses which means we need to do ARP stuff
#[derive(Debug, Default)]
pub struct ArpCache {
    cache: HashMap<IpAddress, EthernetAddress>,
}

impl ArpCache {
    pub fn insert(&mut self, ip: IpAddress, mac: EthernetAddress) {
        self.cache.insert(ip, mac);
    }
    pub fn resolve(&mut self, ip: IpAddress) -> Result<Option<EthernetAddress>, ProcError> {
        // Check our existing arp cache
        if let Some(mac) = self.cache.get(&ip) {
            return Ok(Some(*mac));
        }
        // Cache miss: load all entries from /proc/net/arp at once
        for entry in procfs::net::arp()? {
            if let Some(mac) = entry.hw_address {
                self.cache.insert(IpAddress::from(entry.ip_address), EthernetAddress(mac));
            }
        }
        Ok(self.cache.get(&ip).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{EthernetAddress, IpAddress, Ipv4Address};

    #[test]
    fn arp_cache_insert_and_hit() {
        let mut cache = ArpCache::default();
        let ip = IpAddress::from(Ipv4Address::new(192, 168, 1, 1));
        let mac = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        cache.insert(ip, mac);
        // resolve should find it in cache without touching /proc
        let result = cache.resolve(ip).unwrap();
        assert_eq!(result, Some(mac));
    }

    #[test]
    fn arp_cache_miss_returns_none_or_error() {
        let mut cache = ArpCache::default();
        let ip = IpAddress::from(Ipv4Address::new(203, 0, 113, 99));
        // This will try /proc/net/arp - might fail in test env but shouldn't panic
        let _ = cache.resolve(ip);
    }
}
