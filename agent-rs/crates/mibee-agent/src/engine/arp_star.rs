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

use crate::engine::probes::arp::{parse_proc_arp, ArpRow};
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
    annotate_star_neighbors(hosts, &star_mac);
}

/// The pure per-host half: every alive, MAC-known host except the star center
/// itself gains exactly one device→gateway ARP neighbor — unless a richer
/// (e.g. SNMP-sourced) ARP adjacency for the same peer is already there.
fn annotate_star_neighbors(hosts: &mut [ReportedHost], star_mac: &str) {
    for h in hosts.iter_mut() {
        if !h.alive || h.mac.is_empty() || h.mac == star_mac {
            continue;
        }
        // An SNMP-sourced ARP adjacency for the same peer already says more
        // (port context); never shadow it with a second bare ARP row.
        if h.neighbors
            .iter()
            .any(|n| n.neighbor_mac == star_mac && n.protocol == "ARP")
        {
            continue;
        }
        h.neighbors.push(ReportedNeighbor {
            neighbor_mac: star_mac.to_string(),
            protocol: "ARP".into(),
            source: "local:arp_star".into(),
            ..Default::default()
        });
    }
}

/// Resolve the star-center MAC for the scanned subnet (rules in the module
/// doc). Thin /proc + sysfs reader around the pure rule ladder.
async fn pick_star_mac(net: Ipv4Net) -> Option<String> {
    let arp = parse_proc_arp().await?;
    pick_star_mac_from(net, &arp, default_gateway(), read_iface_mac)
}

/// The pure rule ladder, split out so the vantage rules are unit-testable
/// without /proc fixtures: filter the ARP table down to the scanned subnet,
/// then apply gateway rules 1-3 using the injected default route and sysfs
/// MAC reader (rule 3's router vantage).
fn pick_star_mac_from(
    net: Ipv4Net,
    rows: &[ArpRow],
    default_gw: Option<Ipv4Addr>,
    iface_mac: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let in_subnet: Vec<&ArpRow> = rows
        .iter()
        .filter(|r| {
            r.ip.parse::<Ipv4Addr>()
                .map(|ip| subnet_contains(net, ip))
                .unwrap_or(false)
        })
        .collect();
    if in_subnet.is_empty() {
        return None;
    }

    // Rule 1: default-route gateway inside the scanned subnet.
    if let Some(gw) = default_gw {
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
    iface_mac(iface)
}

/// Mask math instead of ipnet's Contains (whose trait surface differs across
/// 2.x point releases): ip is inside net when the masked bits agree.
fn subnet_contains(net: Ipv4Net, ip: Ipv4Addr) -> bool {
    let m = u32::from(net.netmask());
    (u32::from(ip) & m) == (u32::from(net.network()) & m)
}

/// The kernel's default-route gateway from /proc/net/route, or None when
/// there is no default route / the file is unreadable.
fn default_gateway() -> Option<Ipv4Addr> {
    default_gateway_from(&std::fs::read_to_string("/proc/net/route").ok()?)
}

/// Pure /proc/net/route scan: the default route is destination 00000000; its
/// gateway column is a hex little-endian word. Header line skipped.
fn default_gateway_from(text: &str) -> Option<Ipv4Addr> {
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
fn dominant_iface<'a>(rows: &[&'a ArpRow]) -> Option<&'a str> {
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

    fn arp_rows(list: &[(&str, &str, &str)]) -> Vec<ArpRow> {
        list.iter()
            .map(|(ip, mac, dev)| ArpRow {
                ip: (*ip).into(),
                mac: (*mac).into(),
                device: (*dev).into(),
            })
            .collect()
    }

    fn net() -> Ipv4Net {
        "192.0.2.0/24".parse().unwrap()
    }

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
        assert_eq!(
            hex_route_to_ip("0A00000A"),
            Some("10.0.0.10".parse().unwrap())
        );
        assert_eq!(hex_route_to_ip(""), None);
        assert_eq!(hex_route_to_ip("0100A8"), None); // 7 chars
        assert_eq!(hex_route_to_ip("ZZ00A8C0"), None); // non-hex
    }

    #[test]
    fn subnet_contains_honors_the_mask() {
        assert!(subnet_contains(net(), "192.0.2.77".parse().unwrap()));
        assert!(!subnet_contains(net(), "192.0.3.1".parse().unwrap()));
        let wide: Ipv4Net = "192.0.0.0/16".parse().unwrap();
        assert!(subnet_contains(wide, "192.0.99.5".parse().unwrap()));
        assert!(!subnet_contains(wide, "192.1.0.1".parse().unwrap()));
    }

    #[test]
    fn rule1_default_gateway_inside_the_subnet_wins() {
        let rows = arp_rows(&[
            ("192.0.2.1", "aa:bb:cc:dd:ee:01", "br-lan"),
            ("192.0.2.5", "aa:bb:cc:dd:ee:05", "br-lan"),
            ("198.51.100.9", "aa:bb:cc:dd:ee:09", "eth-wan"), // outside: ignored
        ]);
        let gw: Ipv4Addr = "192.0.2.1".parse().unwrap();
        // Rules 1/2 resolve before any sysfs read is attempted.
        let star = pick_star_mac_from(net(), &rows, Some(gw), |iface| {
            panic!("rules 1/2 must resolve without the sysfs read: {iface}")
        });
        assert_eq!(star.as_deref(), Some("aa:bb:cc:dd:ee:01"));
    }

    #[test]
    fn rule1_gateway_outside_subnet_or_absent_from_arp_falls_through() {
        let rows = arp_rows(&[
            ("192.0.2.1", "aa:bb:cc:dd:ee:01", "br-lan"),
            ("192.0.2.5", "aa:bb:cc:dd:ee:05", "br-lan"),
        ]);
        // WAN-side default route (router vantage): must not become the star; .1 does.
        let wan_gw: Ipv4Addr = "203.0.113.1".parse().unwrap();
        let star = pick_star_mac_from(net(), &rows, Some(wan_gw), |_| None);
        assert_eq!(star.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        // Gateway numerically inside the subnet but never ARPed: rule 2 answers.
        let silent_gw: Ipv4Addr = "192.0.2.9".parse().unwrap();
        let star = pick_star_mac_from(net(), &rows, Some(silent_gw), |_| None);
        assert_eq!(star.as_deref(), Some("aa:bb:cc:dd:ee:01"));
    }

    #[test]
    fn rule3_router_vantage_reads_the_dominant_lan_iface_mac() {
        // No .1 row and no gateway: this box IS the star, named by its LAN iface.
        let rows = arp_rows(&[
            ("192.0.2.5", "aa:bb:cc:dd:ee:05", "br-lan"),
            ("192.0.2.6", "aa:bb:cc:dd:ee:06", "br-lan"),
            ("192.0.2.7", "aa:bb:cc:dd:ee:07", "eth1"),
        ]);
        let star = pick_star_mac_from(net(), &rows, None, |iface| {
            assert_eq!(iface, "br-lan");
            Some("ff:ee:dd:cc:bb:aa".into())
        });
        assert_eq!(star.as_deref(), Some("ff:ee:dd:cc:bb:aa"));
        // A sysfs miss (unreadable MAC) means no star, never a wrong one.
        let star = pick_star_mac_from(net(), &rows, None, |_| None);
        assert_eq!(star, None);
    }

    #[test]
    fn no_in_subnet_rows_means_no_star() {
        // Everything outside the scanned subnet.
        let rows = arp_rows(&[("198.51.100.9", "aa:bb:cc:dd:ee:09", "eth0")]);
        assert_eq!(pick_star_mac_from(net(), &rows, None, |_| panic!()), None);
        // Garbage IPs in the table are skipped, not fatal.
        let rows = arp_rows(&[("not-an-ip", "aa:bb:cc:dd:ee:0a", "br-lan")]);
        assert_eq!(pick_star_mac_from(net(), &rows, None, |_| panic!()), None);
    }

    #[test]
    fn dominant_iface_picks_lan_side_and_breaks_ties_deterministically() {
        let rows = arp_rows(&[
            ("192.0.2.2", "aa:bb:cc:dd:ee:02", "br-lan"),
            ("192.0.2.3", "aa:bb:cc:dd:ee:03", "br-lan"),
            ("192.0.2.4", "aa:bb:cc:dd:ee:04", "eth1"),
        ]);
        let refs: Vec<&ArpRow> = rows.iter().collect();
        assert_eq!(dominant_iface(&refs), Some("br-lan"));
        // a row with no device never wins
        let r4 = ArpRow {
            ip: "192.0.2.5".into(),
            mac: "aa:bb:cc:dd:ee:05".into(),
            device: "".into(),
        };
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

    #[test]
    fn annotate_gives_each_eligible_host_exactly_one_star_edge() {
        let star = "aa:bb:cc:dd:ee:01";
        let host = |ip: &str, alive: bool, mac: &str| ReportedHost {
            ip: ip.into(),
            alive,
            mac: mac.into(),
            ..Default::default()
        };
        let mut hosts = vec![
            host("192.0.2.5", true, "aa:bb:cc:dd:ee:05"),
            // dead host: no edge
            host("192.0.2.6", false, "aa:bb:cc:dd:ee:06"),
            // MAC-less host: the center could never key the edge
            host("192.0.2.7", true, ""),
            // the star center itself never points at itself
            host("192.0.2.1", true, star),
        ];
        annotate_star_neighbors(&mut hosts, star);
        assert_eq!(hosts[0].neighbors.len(), 1);
        let n = &hosts[0].neighbors[0];
        assert_eq!(n.neighbor_mac, star);
        assert_eq!(n.protocol, "ARP");
        assert_eq!(n.source, "local:arp_star");
        for (i, h) in hosts.iter().enumerate().skip(1) {
            assert!(
                h.neighbors.is_empty(),
                "host #{i} ({}) must stay edge-less",
                h.ip
            );
        }
    }

    #[test]
    fn annotate_never_shadows_an_existing_arp_adjacency() {
        let star = "aa:bb:cc:dd:ee:01";
        let mut hosts = vec![ReportedHost {
            ip: "192.0.2.5".into(),
            alive: true,
            mac: "aa:bb:cc:dd:ee:05".into(),
            neighbors: vec![ReportedNeighbor {
                neighbor_mac: star.into(),
                protocol: "ARP".into(),
                source: "snmp:l2_mib".into(),
                ..Default::default()
            }],
            ..Default::default()
        }];
        annotate_star_neighbors(&mut hosts, star);
        assert_eq!(
            hosts[0].neighbors.len(),
            1,
            "must not duplicate the adjacency"
        );
        assert_eq!(
            hosts[0].neighbors[0].source, "snmp:l2_mib",
            "the richer source wins"
        );
    }

    #[test]
    fn default_gateway_reads_the_default_route_row() {
        let table = concat!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
            "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
            "eth0\t0001A8C0\t0200A8C0\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
        );
        assert_eq!(
            default_gateway_from(table),
            Some("192.168.0.1".parse().unwrap())
        );
        // no default route: only a subnet route present
        let no_default = "Iface\tDestination\tGateway\neth0\t0001A8C0\t0200A8C0\n";
        assert_eq!(default_gateway_from(no_default), None);
        assert_eq!(default_gateway_from(""), None);
    }
}
