//! Default-route discovery used to pick the NFQ interface.

use std::net::Ipv4Addr;
use thiserror::Error;

const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// A default route (`0.0.0.0/0` or `::/0`) that can carry traffic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultRoute {
    pub iface: String,
    pub metric: u32,
}

/// Default IPv4 routes from the kernel's IPv4 routing table.
pub fn ipv4_default_routes(routes: &[procfs::net::RouteEntry]) -> Vec<DefaultRoute> {
    routes
        .iter()
        .filter(|r| {
            r.destination == Ipv4Addr::UNSPECIFIED
                && r.mask == Ipv4Addr::UNSPECIFIED
                && u32::from(r.flags) & RTF_UP != 0
                && u32::from(r.flags) & RTF_REJECT == 0
                && r.iface != "lo"
        })
        .map(|r| DefaultRoute {
            iface: r.iface.clone(),
            metric: r.metrics,
        })
        .collect()
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("malformed line {line} in /proc/net/ipv6_route")]
pub struct Ipv6RouteParseError {
    pub line: usize,
}

fn hex_field(field: &str, len: usize) -> Option<u32> {
    if field.len() != len || !field.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Only fields of up to 8 hex digits are converted to numbers
    if len <= 8 {
        u32::from_str_radix(field, 16).ok()
    } else {
        Some(0)
    }
}

/// Parse the contents of `/proc/net/ipv6_route` and return its usable
/// default routes.  Every line is fully validated (10 fields: dst/plen,
/// src/plen, next hop, metric, refcnt, use, flags, iface); a malformed line
/// is an error rather than being skipped.
pub fn ipv6_default_routes(contents: &str) -> Result<Vec<DefaultRoute>, Ipv6RouteParseError> {
    let mut out = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let err = Ipv6RouteParseError { line: idx + 1 };
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [dst, dst_plen, src, src_plen, next_hop, metric, refcnt, used, flags, iface] =
            fields[..]
        else {
            return Err(err);
        };
        let widths = [
            (dst, 32),
            (dst_plen, 2),
            (src, 32),
            (src_plen, 2),
            (next_hop, 32),
            (metric, 8),
            (refcnt, 8),
            (used, 8),
            (flags, 8),
        ];
        let mut values = [0u32; 9];
        for (i, (field, len)) in widths.into_iter().enumerate() {
            values[i] = hex_field(field, len).ok_or(err.clone())?;
        }
        if iface.is_empty() {
            return Err(err);
        }
        let is_default = dst.bytes().all(|b| b == b'0') && values[1] == 0;
        let flags = values[8];
        if is_default && flags & RTF_UP != 0 && flags & RTF_REJECT == 0 && iface != "lo" {
            out.push(DefaultRoute {
                iface: iface.to_owned(),
                metric: values[5],
            });
        }
    }
    Ok(out)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SelectInterfaceError {
    #[error("no IPv4 or IPv6 default route found; pass the interface explicitly")]
    NoDefaultRoute,
}

/// Choose the interface to run on.
///
/// An explicitly requested interface always wins (it does not need a
/// default route: injection is routed by the kernel).  Otherwise use the
/// interface of the lowest-metric IPv4 default route, falling back to IPv6
/// for IPv6-only hosts.
pub fn select_interface(
    requested: Option<&str>,
    v4_defaults: &[DefaultRoute],
    v6_defaults: &[DefaultRoute],
) -> Result<String, SelectInterfaceError> {
    if let Some(iface) = requested {
        return Ok(iface.to_owned());
    }
    [v4_defaults, v6_defaults]
        .into_iter()
        .find_map(|routes| routes.iter().min_by_key(|r| r.metric))
        .map(|r| r.iface.clone())
        .ok_or(SelectInterfaceError::NoDefaultRoute)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(iface: &str, metric: u32) -> DefaultRoute {
        DefaultRoute {
            iface: iface.into(),
            metric,
        }
    }

    const IPV6_ROUTE: &str = "\
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo
";

    #[test]
    fn parses_ipv6_default_routes() {
        assert_eq!(ipv6_default_routes(IPV6_ROUTE).unwrap(), vec![route("eth0", 0x400)]);
    }

    #[test]
    fn rejects_malformed_ipv6_route_lines() {
        assert_eq!(
            ipv6_default_routes("0000 00 eth0\n"),
            Err(Ipv6RouteParseError { line: 1 })
        );
        let bad_hex = IPV6_ROUTE.replacen("00000400", "0000040g", 1);
        assert_eq!(
            ipv6_default_routes(&bad_hex),
            Err(Ipv6RouteParseError { line: 3 })
        );
    }

    fn v4_entry(iface: &str, dest: [u8; 4], mask: [u8; 4], gw: [u8; 4], flags: u16) -> procfs::net::RouteEntry {
        procfs::net::RouteEntry {
            iface: iface.into(),
            destination: dest.into(),
            gateway: gw.into(),
            flags,
            refcnt: 0,
            in_use: 0,
            metrics: 0,
            mask: mask.into(),
            mtu: 0,
            window: 0,
            irtt: 0,
        }
    }

    #[test]
    fn ipv4_defaults_exclude_subnet_routes() {
        let routes = [
            // Subnet route on docker0 listed first, gateway 0.0.0.0
            v4_entry("docker0", [172, 17, 0, 0], [255, 255, 0, 0], [0; 4], 0x1),
            v4_entry("eth0", [0; 4], [0; 4], [192, 168, 1, 1], 0x3),
            // A down default route is ignored
            v4_entry("eth1", [0; 4], [0; 4], [10, 0, 0, 1], 0x2),
        ];
        assert_eq!(ipv4_default_routes(&routes), vec![route("eth0", 0)]);
    }

    #[test]
    fn requested_interface_wins() {
        let v4 = [route("eth0", 0)];
        assert_eq!(select_interface(Some("eth1"), &v4, &[]).unwrap(), "eth1");
    }

    #[test]
    fn subnet_routes_on_other_interfaces_are_not_defaults() {
        // Only default routes are candidates; lowest metric wins
        let v4 = [route("wlan0", 600), route("eth0", 100)];
        assert_eq!(select_interface(None, &v4, &[]).unwrap(), "eth0");
    }

    #[test]
    fn ipv6_only_host_uses_ipv6_default() {
        let v6 = [route("eth0", 1024)];
        assert_eq!(select_interface(None, &[], &v6).unwrap(), "eth0");
    }

    #[test]
    fn no_default_route_is_a_clear_error() {
        assert_eq!(
            select_interface(None, &[], &[]),
            Err(SelectInterfaceError::NoDefaultRoute)
        );
    }
}
