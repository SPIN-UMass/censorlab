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
        let mut result = None;
        // Open up the arp cache and scan for an entry
        // TODO: if we're iterating and scanning we should just pre-cache everything
        for entry in procfs::net::arp()? {
            if IpAddress::from(entry.ip_address) == ip {
                result = entry.hw_address.map(EthernetAddress);
                break;
            }
        }
        if let Some(mac) = result {
            self.insert(ip, mac);
        }
        Ok(result)
    }
}
