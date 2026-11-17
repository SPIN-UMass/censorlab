//! Injection of crafted IP packets (RSTs, forged UDP responses) through the
//! kernel's IP stack.
//!
//! NFQ mode only sees layer-3 packets, so injected packets are sent through
//! raw IP sockets with the header supplied by us (`IPPROTO_RAW`, which implies
//! `IP_HDRINCL` / `IPV6_HDRINCL`).  The kernel then routes them and performs
//! ARP / IPv6 neighbour discovery itself, which means:
//!
//! * IPv4 and IPv6 are handled identically (no hand-rolled neighbour cache);
//! * a packet addressed to one of our own addresses (the censor runs on the
//!   client host) is looped back to the local stack instead of being put on
//!   the wire, where the local host would never see it;
//! * packets for a client behind another interface (the censor forwards
//!   between a client and the WAN) leave through the correct interface.
//!
//! Every injected packet carries [`INJECT_MARK`] so the NFQUEUE rules can
//! exclude it; otherwise our own RSTs would be queued back to us.

use smoltcp::wire::{Ipv4Packet, Ipv6Packet};
use std::io;
use std::mem::size_of;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use thiserror::Error;

/// Firewall mark carried by every injected packet ("CL" + 1).
pub const INJECT_MARK: u32 = 0x434c_0001;

/// Destination address of a raw IPv4/IPv6 packet, if it is well formed.
pub fn ip_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => Ipv4Packet::new_checked(packet)
            .ok()
            .map(|ip| IpAddr::V4(ip.dst_addr())),
        Some(6) => Ipv6Packet::new_checked(packet)
            .ok()
            .map(|ip| IpAddr::V6(ip.dst_addr())),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum InjectError {
    #[error("not a well-formed IPv4/IPv6 packet")]
    Malformed,
    #[error("no raw {0} socket available (opening it failed at startup)")]
    NoSocket(&'static str),
    #[error("sendto failed: {0}")]
    Send(io::Error),
}

/// Raw IPv4 and IPv6 sockets used to inject packets.
pub struct RawIpInjector {
    v4: Option<OwnedFd>,
    v6: Option<OwnedFd>,
    /// Interface index used as the scope of link-local IPv6 destinations
    scope_ifindex: u32,
}

fn open_raw(domain: libc::c_int, mark: u32) -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the result is checked before wrapping it.
    let fd = unsafe { libc::socket(domain, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a freshly created, owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    setsockopt_int(&fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)?;
    if domain == libc::AF_INET6 {
        // Implied by IPPROTO_RAW on Linux, but be explicit
        setsockopt_int(&fd, libc::IPPROTO_IPV6, libc::IPV6_HDRINCL, 1)?;
    }
    Ok(fd)
}

fn setsockopt_int(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: value lives for the duration of the call and its size is passed.
    let res = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl RawIpInjector {
    /// Open raw IPv4 and IPv6 sockets.  Fails only if neither can be opened;
    /// a missing family is reported when a packet of that family is sent.
    pub fn new(scope_ifindex: u32) -> io::Result<Self> {
        let v4 = open_raw(libc::AF_INET, INJECT_MARK);
        let v6 = open_raw(libc::AF_INET6, INJECT_MARK);
        match (v4, v6) {
            (Err(err), Err(_)) => Err(err),
            (v4, v6) => {
                if let Err(err) = &v4 {
                    tracing::warn!("Could not open raw IPv4 socket, IPv4 injection disabled: {err}");
                }
                if let Err(err) = &v6 {
                    tracing::warn!("Could not open raw IPv6 socket, IPv6 injection disabled: {err}");
                }
                Ok(Self {
                    v4: v4.ok(),
                    v6: v6.ok(),
                    scope_ifindex,
                })
            }
        }
    }

    /// Send a complete IP packet (header included); the kernel routes it.
    pub fn send(&self, packet: &[u8]) -> Result<(), InjectError> {
        let res = match ip_destination(packet).ok_or(InjectError::Malformed)? {
            IpAddr::V4(dst) => {
                let fd = self.v4.as_ref().ok_or(InjectError::NoSocket("IPv4"))?;
                // SAFETY: zeroed sockaddr_in is a valid value
                let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                addr.sin_family = libc::AF_INET as libc::sa_family_t;
                addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
                // SAFETY: buffer and address are valid for the given lengths
                unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                        size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
            }
            IpAddr::V6(dst) => {
                let fd = self.v6.as_ref().ok_or(InjectError::NoSocket("IPv6"))?;
                // SAFETY: zeroed sockaddr_in6 is a valid value
                let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                // For raw sockets the port field is the protocol; 0 = socket's own
                addr.sin6_addr.s6_addr = dst.octets();
                if dst.is_unicast_link_local() {
                    addr.sin6_scope_id = self.scope_ifindex;
                }
                // SAFETY: buffer and address are valid for the given lengths
                unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                        size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            }
        };
        if res < 0 {
            Err(InjectError::Send(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::censor::IpPair;
    use crate::transport::construct_reset;
    use smoltcp::wire::{EthernetAddress, EthernetFrame, Ipv4Address, Ipv6Address, TcpSeqNumber};

    fn l3(ips: IpPair) -> Vec<u8> {
        let frame = construct_reset(
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
            ips,
            None,
            1,
            2,
            Some(TcpSeqNumber(0)),
            TcpSeqNumber(0),
        )
        .unwrap();
        EthernetFrame::new_checked(&frame[..]).unwrap().payload().to_vec()
    }

    #[test]
    fn destination_of_ipv4_packet() {
        let pkt = l3(IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        });
        assert_eq!(ip_destination(&pkt), Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn destination_of_ipv6_packet() {
        let pkt = l3(IpPair::V6 {
            src: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            dst: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        });
        assert_eq!(ip_destination(&pkt), Some("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn destination_rejects_garbage() {
        assert_eq!(ip_destination(&[]), None);
        assert_eq!(ip_destination(&[0x45, 0, 0]), None);
        assert_eq!(ip_destination(&[0x60; 10]), None);
        assert_eq!(ip_destination(&[0x00; 60]), None);
    }
}
