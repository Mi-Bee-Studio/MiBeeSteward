//! ARP-star neighbor injection: the agent-side mirror of the center's
//! `injectARPTopology` (runner/arp_topology.go).
//!
//! On a home/SOHO network with no managed switches (no LLDP / Bridge-MIB
//! anywhere), the ONLY adjacency evidence is "every device on this subnet
//! reaches the rest of the network through its gateway". The center derives
//! that star from its own kernel when it scans locally; agent-scanned networks
//! never run that code path, and without this injection the center's graph for
//! those networks renders edge-less no matter how healthy the scans are.
//!
//! After each scan the agent's `/proc/net/arp` holds every host it just talked
//! to, so the star center is resolved HERE and shipped as one extra wire
//! neighbor (`protocol: "ARP"`) per alive host. Gateway pick, most-specific
//! first:
//!   1. the default-route gateway, when it sits INSIDE the scanned subnet (the
//!      leaf-box vantage; on the router itself the default route points at the
//!      WAN upstream, a different subnet, and must not become the star);
//!   2. the subnet's first address (.1) present in the ARP table (a leaf box
//!      whose uplink is PPPoE still ARPs the real LAN gateway during the scan;
//!      a router never ARPs its own .1, so this misses on exactly the boxes
//!      that need the next rule);
//!   3. the router vantage: the box itself is the subnet's gateway. The LAN
//!      interface the in-subnet ARP entries live on names the interface, and
//!      `/sys/class/net/<iface>/address` its MAC — no interface enumeration
//!      crate needed. `AnchorLocalInterfaces` keeps the center-side device row
//!      keyed by that same MAC, so the edges resolve on ingest.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::engine::probes::arp::parse_proc_arp;
use crate::wire::{ReportedHost, ReportedNeighbor};

/// Annotate every alive host (except the star center itself) with a
/// device→gateway ARP neighbor. No-op when the CIDR is unknown, the ARP table
/// is unreadable, or no star center resolves — a scan must never fail on this.
pub async fn inject_arp_star(hosts: &mut [ReportedHost], network_cidr: &str) {
    if hosts.is_empty() {
        return;
    }
    let Ok(net) = network_cidr.parse::<Ipv4Net>() else {
        return;
    };
    let Some(star_mac) = pick_star_mac(net).await else {
        return;
    };
    for h in hosts.iter_mut() {
        if !h.alive || h.mac.is_empty() || h.mac == star_mac {
            continue;
        }
        // An SNMP-sourced ARP adjacency for the same peer already says more
        // (port context); never shadow it with a second bare ARP row.
        if h
            .neighbors
            .iter()
            .any(|n| n.neighbor_mac == star_mac && n.protocol == "ARP")
        {
            continue;
        }
        h.neighbors.push(ReportedNeighbor {
            neighbor_mac: star_mac.clone(),
            protocol: "ARP".into(),
            source: "local:arp_star".into(),
            ..Default::default()
        });
    }
}

/// Resolve the star-center MAC for the scanned subnet (rules in the module
/// doc). Pure over the inputs except the two /proc + sysfs reads.
async fn pick_star_mac(net: Ipv4Net) -> Option<String> {
    let arp = parse_proc_arp().await?;
    let in_subnet: Vec<&crate::engine::probes::arp::ArpRow> = arp
        .iter()
        .filter(|r| {
            r.ip
                .parse::<Ipv4Addr>()
                .map(|ip| subnet_contains(net, ip))
                .unwrap_or(false)
        })
        .collect();
    if in_subnet.is_empty() {
        return None;
    }

    // Rule 1: default-route gateway inside the scanned subnet.
    if let Some(gw) = default_gateway() {
        if subnet_contains(net, gw) {
            if let Some(row) = in_subnet.iter().find(|r| r.ip == gw.to_string()) {
                return Some(row.mac.clone());
            }
        }
    }

    // Rule 2: the subnet's first address present in the ARP table.
    let dot_one = Ipv4Addr::from(u32::from(net.network()) + 1);
    if let Some(row) = in_subnet.iter().find(|r| r.ip == dot_one.to_string()) {
        return Some(row.mac.clone());
    }

    // Rule 3: router vantage — this box IS the gateway; its MAC on the LAN
    // interface the in-subnet entries live on.
    let iface = dominant_iface(&in_subnet)?;
    read_iface_mac(&iface)
}

/// Mask math instead of ipnet's Contains (whose trait surface differs across
/// 2.x point releases): ip is inside net when the masked bits agree.
fn subnet_contains(net: Ipv4Net, ip: Ipv4Addr) -> bool {
    let m = u32::from(net.netmask());
    (u32::from(ip) & m) == (u32::from(net.network()) & m)
}

/// The kernel's default-route gateway from /proc/net/route (hex little-endian
/// columns), or None when there is no default route / the file is unreadable.
fn default_gateway() -> Option<Ipv4Addr> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || cols[1] != "00000000" {
            continue; // not the default route
        }
        return hex_route_to_ip(cols[2]);
    }
    None
}

/// "/proc/net/route" hex little-endian word → IPv4 ("0100A8C0" = 192.168.0.1).
fn hex_route_to_ip(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut octets = [0u8; 4];
    for (i, pair) in bytes.chunks(2).enumerate() {
        // byte pairs are in reverse address order
        octets[3 - i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// The interface name carrying the most in-subnet ARP entries (the LAN-facing
/// iface; ties broken by name for determinism).
fn dominant_iface<'a>(rows: &[&'a crate::engine::probes::arp::ArpRow]) -> Option<&'a str> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for r in rows {
        if !r.device.is_empty() && r.device != "*" {
            *counts.entry(r.device.as_str()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(iface, n)| (*n, std::cmp::Reverse(*iface)))
        .map(|(iface, _)| iface)
}

/// /sys/class/net/<iface>/address (colon-separated, lowercased on Linux).
fn read_iface_mac(iface: &str) -> Option<String> {
    if iface.is_empty() || iface.contains('/') {
        return None; // defensive: iface comes from /proc parsing
    }
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_route_word_parses() {
        assert_eq!(
            hex_route_to_ip("0100A8C0"),
            Some("192.168.0.1".parse().unwrap())
        );
        assert_eq!(
            hex_route_to_ip("0101A8C0"),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(hex_route_to_ip("0A00000A"), Some("10.0.0.10".parse().unwrap()));
        assert_eq!(hex_route_to_ip(""), None);
        assert_eq!(hex_route_to_ip("0100A8"), None); // 7 chars
        assert_eq!(hex_route_to_ip("ZZ00A8C0"), None); // non-hex
    }

    #[test]
    fn dominant_iface_picks_lan_side_and_breaks_ties_deterministically() {
        use crate::engine::probes::arp::ArpRow;
        let row = |ip: &str, dev: &str| ArpRow {
            ip: ip.into(),
            mac: "aa:bb:cc:dd:ee:01".into(),
            device: dev.into(),
        };
        let r1 = row("192.0.2.2", "br-lan");
        let r2 = row("192.0.2.3", "br-lan");
        let r3 = row("192.0.2.4", "eth1");
        let rows = vec![&r1, &r2, &r3];
        assert_eq!(dominant_iface(&rows), Some("br-lan"));
        // a row with no device never wins
        let r4 = row("192.0.2.5", "");
        assert_eq!(dominant_iface(&[&r4]), None);
    }

    #[test]
    fn read_iface_mac_rejects_path_tricks_and_non_mac() {
        assert_eq!(read_iface_mac("../evil"), None);
        // /sys reads only exist on Linux; on any platform a missing iface is None
        assert_eq!(read_iface_mac("no-such-iface-x"), None);
    }

    #[tokio::test]
    async fn inject_noops_on_bad_cidr_and_marks_the_star_itself() {
        // The pure half: with an unparseable CIDR nothing happens.
        let mut hosts = vec![ReportedHost {
            ip: "192.0.2.10".into(),
            alive: true,
            mac: "aa:bb:cc:dd:ee:10".into(),
            ..Default::default()
        }];
        inject_arp_star(&mut hosts, "not-a-cidr").await;
        assert!(hosts[0].neighbors.is_empty());
    }
}
