//! Passive discovery sources (router-resident Tier-1): dhcp_leases,
//! arp_cache, conntrack + the mDNS/SSDP multicast listener. Findings feed
//! the engine's seed-evidence cache (the #471 fix) and single-host passive
//! reports upstream.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use mibee_fingerprints::Evidence;

use crate::engine::orchestrator::ScanEngine;

/// One lease row from dnsmasq's lease file.
#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
}

/// Parse a dnsmasq lease file: `<expiry> <mac> <ip> <hostname|*> <clientid>`.
pub fn parse_dhcp_leases(text: &str) -> Vec<Lease> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let hostname = if cols[3] == "*" { String::new() } else { cols[3].to_string() };
        out.push(Lease {
            mac: cols[1].to_ascii_lowercase(),
            ip: cols[2].to_string(),
            hostname,
        });
    }
    out
}

pub const LEASE_PATHS: [&str; 2] = ["/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases"];

/// Parse /proc/net/arp into (ip, mac) pairs (reachable entries only).
pub fn parse_proc_arp_pairs(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[2] == "0x2" {
            out.push((cols[0].to_string(), cols[3].to_ascii_lowercase()));
        }
    }
    out
}

/// Parse /proc/net/nf_conntrack: LAN-side endpoints of ESTABLISHED/ASSURED
/// flows as (lan_ip,) tuples within the given CIDR.
pub fn parse_conntrack(text: &str, cidr: &ipnet::Ipv4Net) -> Vec<String> {
    let mut seen = HashSet::new();
    for line in text.lines() {
        if !(line.contains("ESTABLISHED") || line.contains("ASSURED")) {
            continue;
        }
        for part in line.split_whitespace() {
            if let Some(ip) = part.strip_prefix("src=") {
                if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                    if cidr.contains(&v4) {
                        seen.insert(v4.to_string());
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

// ---------- hostapd (WiFi STA associations, Go discovery/hostapd.go) ----------

/// One associated WiFi station. Only the MAC is required; signal/ssid/
/// connected_secs are optional enrichment (Go staInfo).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StaInfo {
    pub mac: String,
    pub signal: String,        // dBm, e.g. "-42"
    pub ssid: String,
    pub connected_secs: String,
}

/// Parse the key=value lines of one hostapd STA-FIRST/STA-NEXT reply.
pub fn parse_hostapd_sta(resp: &str) -> StaInfo {
    let mut info = StaInfo::default();
    for line in resp.split('\n') {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k {
            "addr" => info.mac = v.to_ascii_lowercase(),
            "signal" => info.signal = v.to_string(),
            "connected_time" => info.connected_secs = v.to_string(),
            "ssid" => info.ssid = v.to_string(),
            _ => {}
        }
    }
    info
}

/// Parse `iw dev <iface> station dump` output: one block per station, the
/// MAC in the "Station <mac> (on <iface>)" header, "signal:  -42 dBm"
/// details indented.
pub fn parse_iw_station_dump(out: &str) -> Vec<StaInfo> {
    let mut stas: Vec<StaInfo> = Vec::new();
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("Station ") {
            let mac = rest.split(' ').next().unwrap_or("").to_ascii_lowercase();
            if !mac.is_empty() {
                stas.push(StaInfo { mac, ..Default::default() });
            }
        } else if let Some(last) = stas.last_mut() {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("signal:") {
                let v = v.trim().strip_suffix("dBm").unwrap_or(v.trim()).trim();
                if !v.is_empty() {
                    last.signal = v.to_string();
                }
            }
        }
    }
    stas
}

/// Walk the hostapd control sockets in `ctrl_dir` (one datagram socket per
/// phy, the OpenWrt convention) using the hostapd_cli protocol: STA-FIRST
/// then STA-NEXT <mac> until FAIL. Errors are tolerated per socket (same
/// degrade semantics as Go queryHostapdSocket).
#[cfg(target_family = "unix")]
pub async fn read_via_hostapd_ctrl(ctrl_dir: &str) -> Vec<StaInfo> {
    let mut out = Vec::new();
    let Ok(entries) = tokio::fs::read_dir(ctrl_dir).await else {
        return out;
    };
    let mut paths = Vec::new();
    let mut entries = entries;
    while let Ok(Some(e)) = entries.next_entry().await {
        paths.push(e.path());
    }
    for path in paths {
        // Unbound first: the kernel autobinds an address the ctrl peer can
        // reply to (Go net.Dial("unixgram", …) semantics), then connect.
        let sock = match tokio::net::UnixDatagram::unbound() {
            Ok(s) if s.connect(&path).is_ok() => s,
            _ => continue, // not a socket / perms: try the next one
        };
        let mut cmd = "STA-FIRST".to_string();
        loop {
            if sock.send(cmd.as_bytes()).await.is_err() {
                break;
            }
            let mut buf = [0u8; 4096];
            let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await
            else {
                break;
            };
            let resp = String::from_utf8_lossy(&buf[..n]).into_owned();
            if resp.is_empty() || resp.starts_with("FAIL") {
                break; // no (more) stations
            }
            let info = parse_hostapd_sta(&resp);
            if info.mac.is_empty() {
                break;
            }
            cmd = format!("STA-NEXT {}", info.mac);
            out.push(info);
        }
    }
    out
}

#[cfg(not(target_family = "unix"))]
pub async fn read_via_hostapd_ctrl(_ctrl_dir: &str) -> Vec<StaInfo> {
    Vec::new() // no hostapd ctrl sockets off-unix
}

/// `iw dev <iface> station dump` fallback (works without a readable ctrl
/// socket). One bounded subprocess per interface; failures return nothing.
pub async fn read_via_iw(interfaces: &[String]) -> Vec<StaInfo> {
    let mut out = Vec::new();
    for iface in interfaces {
        let fut = tokio::process::Command::new("iw")
            .args(["dev", iface, "station", "dump"])
            .output();
        let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(3), fut).await else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        out.extend(parse_iw_station_dump(&text));
    }
    out
}

/// WiFi telemetry stashed per MAC, attached to a host's seed evidence when
/// an L3 sighting (dhcp lease / ARP row) names the MAC — the Rust analog of
/// Go's MAC-only enrich-only path (hints ride local scan evidence; no device
/// is fabricated for a MAC with no L3 sighting).
fn wifi_evidence(info: &StaInfo) -> Evidence {
    let mut rd = BTreeMap::from([
        ("mac".to_string(), info.mac.clone()),
        ("discovery_note".to_string(), "wifi_assoc".to_string()),
    ]);
    if !info.signal.is_empty() {
        rd.insert("wifi_signal_dbm".to_string(), info.signal.clone());
    }
    if !info.ssid.is_empty() {
        rd.insert("wifi_ssid".to_string(), info.ssid.clone());
    }
    if !info.connected_secs.is_empty() {
        rd.insert("wifi_connected_secs".to_string(), info.connected_secs.clone());
    }
    Evidence {
        source: "discovery:hostapd".into(),
        kind: "wifi".into(),
        ip: String::new(),
        protocol: "wifi".into(),
        confidence: 0.9,
        raw_data: Some(rd),
        ..Default::default()
    }
}

/// The passive discovery loop: poll interval sources, diff against the
/// previous snapshot, feed observations + passive host reports.
pub struct DiscoverySources {
    pub enabled_dhcp_leases: bool,
    pub enabled_arp_cache: bool,
    pub enabled_conntrack: bool,
    /// hostapd WiFi STA source (Go HostapdSource): ctrl sockets first, iw
    /// station dump fallback; empty interfaces = the ["wlan0"] default.
    pub enabled_hostapd: bool,
    pub hostapd_interfaces: Vec<String>,
    /// router_arp source (Go RouterARPSource): periodic SNMP walk of the
    /// configured routers' ARP tables. Widest coverage — one walk per router
    /// per sweep touches zero end hosts. Community path only (Go passive
    /// parity; v3 is a later enhancement).
    pub enabled_router_arp: bool,
    pub routers: Vec<String>,
    pub router_community: String,
    pub router_timeout: Duration,
    pub network_cidr: Option<ipnet::Ipv4Net>,
}

#[derive(Default)]
pub struct DiscoveryState {
    known: HashSet<String>,
    /// WiFi telemetry per MAC (hostapd sweep); attached to a host's seeds
    /// once, when an L3 sighting first names the MAC.
    wifi_by_mac: std::collections::HashMap<String, Evidence>,
    wifi_attached: HashSet<String>,
    /// Per-router consecutive walk failures: the first failure logs (the
    /// source went blind to that subnet — actionable), subsequent ones stay
    /// silent until recovery (Go RouterARPSource.failStreak).
    router_fail_streak: std::collections::HashMap<String, u32>,
}

pub const HOSTAPD_CTRL_DIR: &str = "/var/run/hostapd";

impl DiscoverySources {
    /// One sweep: returns passive observations to report upstream
    /// (ip, hostname?, mac?) for genuinely-new hosts.
    pub async fn sweep(&self, engine: &ScanEngine, state: &mut DiscoveryState) -> Vec<(String, Option<String>, Option<String>)> {
        let mut newly: Vec<(String, Option<String>, Option<String>)> = Vec::new();
        let mut observations: Vec<(String, Evidence)> = Vec::new();

        if self.enabled_hostapd {
            // hostapd ctrl sockets first; iw station dump when they yield
            // nothing (no sockets / perms / no STA on them).
            let mut stas = read_via_hostapd_ctrl(HOSTAPD_CTRL_DIR).await;
            if stas.is_empty() {
                let ifaces = if self.hostapd_interfaces.is_empty() {
                    vec!["wlan0".to_string()]
                } else {
                    self.hostapd_interfaces.clone()
                };
                stas = read_via_iw(&ifaces).await;
            }
            for sta in &stas {
                state.wifi_by_mac.insert(sta.mac.clone(), wifi_evidence(sta));
            }
        }

        if self.enabled_dhcp_leases {
            for path in LEASE_PATHS {
                if let Ok(text) = tokio::fs::read_to_string(path).await {
                    for lease in parse_dhcp_leases(&text) {
                        if in_cidr(&lease.ip, &self.network_cidr) {
                            if !lease.hostname.is_empty() {
                                let ev = Evidence {
                                    source: "discovery:dhcp_leases".into(),
                                    kind: "hostname".into(),
                                    ip: lease.ip.clone(),
                                    protocol: "dhcp".into(),
                                    confidence: 0.8,
                                    raw_data: Some(
                                        [("hostname".to_string(), lease.hostname.clone())]
                                            .into_iter()
                                            .collect(),
                                    ),
                                    ..Default::default()
                                };
                                observations.push((lease.ip.clone(), ev));
                            }
                            if let Some(wifi) = attach_wifi(state, &lease.mac) {
                                observations.push((lease.ip.clone(), wifi));
                            }
                            if state.known.insert(format!("lease:{}", lease.ip)) {
                                newly.push((
                                    lease.ip.clone(),
                                    if lease.hostname.is_empty() { None } else { Some(lease.hostname.clone()) },
                                    Some(lease.mac.clone()),
                                ));
                            }
                        }
                    }
                    break; // first existing lease file wins
                }
            }
        }
        if self.enabled_arp_cache {
            if let Ok(text) = tokio::fs::read_to_string("/proc/net/arp").await {
                for (ip, mac) in parse_proc_arp_pairs(&text) {
                    if !in_cidr(&ip, &self.network_cidr) {
                        continue;
                    }
                    let ev = Evidence {
                        source: "discovery:arp_cache".into(),
                        kind: "mac".into(),
                        ip: ip.clone(),
                        confidence: 1.0,
                        raw_data: Some(
                            [("mac".to_string(), mac.clone())].into_iter().collect(),
                        ),
                        ..Default::default()
                    };
                    observations.push((ip.clone(), ev));
                    if let Some(wifi) = attach_wifi(state, &mac) {
                        observations.push((ip.clone(), wifi));
                    }
                    if state.known.insert(format!("arp:{ip}")) {
                        newly.push((ip, None, Some(mac)));
                    }
                }
            }
        }
        if self.enabled_conntrack {
            if let (Some(cidr), Ok(text)) = (
                self.network_cidr,
                tokio::fs::read_to_string("/proc/net/nf_conntrack").await,
            ) {
                for ip in parse_conntrack(&text, &cidr) {
                    state.known.insert(format!("ct:{ip}"));
                }
            }
        }
        if self.enabled_router_arp && !self.routers.is_empty() {
            let community = if self.router_community.is_empty() {
                "public".to_string()
            } else {
                self.router_community.clone()
            };
            let mut merged: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for r in &self.routers {
                let addr = crate::engine::probes::snmp_arp::router_addr(r);
                let walked = match addr {
                    Some(a) => {
                        crate::engine::probes::snmp_arp::walk_router_arp_table(
                            a, &community, self.router_timeout, None,
                        )
                        .await
                    }
                    None => Err("invalid router address".to_string()),
                };
                match walked {
                    Ok(table) => {
                        if let Some(prev) = state.router_fail_streak.insert(r.clone(), 0) {
                            if prev > 0 {
                                eprintln!("discovery: router_arp recovered router={r} after_failures={prev}");
                            }
                        }
                        merged.extend(table);
                    }
                    Err(e) => {
                        // First failure per router is actionable (the source is
                        // now blind to that whole subnet); after that, silent
                        // until recovery (Go Warn→Debug streak semantics).
                        let streak = state.router_fail_streak.entry(r.clone()).or_insert(0);
                        *streak += 1;
                        if *streak == 1 {
                            eprintln!(
                                "discovery: router_arp walk failed (source now blind to this subnet) router={r} error={e} hint=check SNMP is enabled on the router and the community matches"
                            );
                        }
                    }
                }
            }
            for (ip, mac) in merged {
                if !in_cidr(&ip, &self.network_cidr) {
                    continue;
                }
                let ev = Evidence {
                    source: "discovery:router_arp".into(),
                    kind: "mac".into(),
                    ip: ip.clone(),
                    confidence: 1.0,
                    raw_data: Some([("mac".to_string(), mac.clone())].into_iter().collect()),
                    ..Default::default()
                };
                observations.push((ip.clone(), ev));
                if let Some(wifi) = attach_wifi(state, &mac) {
                    observations.push((ip.clone(), wifi));
                }
                if state.known.insert(format!("router_arp:{ip}")) {
                    newly.push((ip, None, Some(mac)));
                }
            }
        }
        for (ip, ev) in observations {
            engine.observe(&ip, vec![ev]).await;
        }
        newly
    }
}

/// Take the cached WiFi telemetry for a MAC once (the first L3 sighting);
/// None when the MAC has no cached telemetry or it was already attached.
fn attach_wifi(state: &mut DiscoveryState, mac: &str) -> Option<Evidence> {
    if state.wifi_by_mac.is_empty() || state.wifi_attached.contains(mac) {
        return None;
    }
    state.wifi_attached.insert(mac.to_string());
    state.wifi_by_mac.get(mac).cloned()
}

fn in_cidr(ip: &str, cidr: &Option<ipnet::Ipv4Net>) -> bool {
    match cidr {
        Some(net) => ip
            .parse::<std::net::Ipv4Addr>()
            .map(|v| net.contains(&v))
            .unwrap_or(false),
        None => true, // degrade-open (Go boundary guard parity)
    }
}

/// The mDNS/SSDP multicast listener: two independent socket tasks; each
/// parses packets, filters to the network CIDR, and feeds the seed cache.
pub async fn run_multicast_listener(
    engine: Arc<ScanEngine>,
    cidr: Option<ipnet::Ipv4Net>,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    use socket2::{Domain, Protocol, Socket, Type};
    let join = |group: &str, port: u16| -> Option<tokio::net::UdpSocket> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
        s.set_reuse_address(true).ok()?;
        s.join_multicast_v4(
            &group.parse().ok()?,
            &"0.0.0.0".parse().ok()?,
        )
        .ok()?;
        let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse().ok()?;
        s.bind(&addr.into()).ok()?;
        s.set_nonblocking(true).ok()?;
        let std_sock: std::net::UdpSocket = s.into();
        tokio::net::UdpSocket::from_std(std_sock).ok()
    };
    let (Some(mdns), Some(ssdp)) = (
        join("224.0.0.251", 5353),
        join("239.255.255.250", 1900),
    ) else {
        eprintln!("discovery: multicast sources unavailable (ports busy?); continuing without them");
        return;
    };
    let engine_mdns = Arc::clone(&engine);
    let engine_ssdp = Arc::clone(&engine);
    let cidr_m = cidr;
    let cidr_s = cidr;
    let t1 = tokio::spawn(async move {
        let mut buf = [0u8; 9000];
        loop {
            match mdns.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if !in_cidr(&from.ip().to_string(), &cidr_m) {
                        continue;
                    }
                    if let Ok(msg) = crate::engine::dns::parse_message(&buf[..n]) {
                        if let Some(mut e) =
                            crate::engine::probes::mdns::message_to_evidence(from.ip(), &msg)
                        {
                            e.source = "discovery:multicast".into();
                            engine_mdns.observe(&from.ip().to_string(), vec![e]).await;
                        }
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    });
    let t2 = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match ssdp.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if !in_cidr(&from.ip().to_string(), &cidr_s) {
                        continue;
                    }
                    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if let Some(mut e) = crate::engine::probes::ssdp::parse_ssdp_response(
                        from.ip(),
                        &text,
                    ) {
                        e.source = "discovery:multicast".into();
                        engine_ssdp.observe(&from.ip().to_string(), vec![e]).await;
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    });
    let mut stop = stop;
    while stop.changed().await.is_ok() {}
    t1.abort();
    t2.abort();
}

#[allow(dead_code)]
fn unused(_ip: IpAddr) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> Arc<ScanEngine> {
        use mibee_fingerprints::RuleClassifier;
        Arc::new(ScanEngine {
            probes: vec![],
            classifier: Arc::new(RuleClassifier::new()),
            snmp_tables: Arc::new(crate::engine::identify::SnmpTables::default()),
            rules: Arc::new(crate::engine::device_types::DeviceTypeRules::load_embedded()),
            oui: Arc::new(crate::engine::oui::Oui::parse("")),
            port_spec: vec![],
            per_host_timeout: Duration::from_secs(2),
            per_probe_timeout: Duration::from_secs(2),
            max_concurrent_hosts: 4,
            community: "public".into(),
            snmp_port: 161,
            rdns_servers: vec![],
            routers: vec![],
            allow_reserved: true,
            seeds: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    #[tokio::test]
    async fn router_arp_source_reports_new_hosts_once() {
        use crate::engine::probes::snmp::test_support::spawn_fake_router;
        let root = crate::engine::probes::snmp_arp::OID_IP_NET_TO_MEDIA.to_string();
        let router = spawn_fake_router(
            vec![
                (format!("{root}.2.192.0.2.50"), vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x50]),
                (format!("{root}.2.192.0.2.51"), vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x51]),
            ],
            "1.3.6.1.2.1.4.22.1.3.1".to_string(),
        )
        .await;
        let engine = test_engine();
        let sources = DiscoverySources {
            enabled_dhcp_leases: false,
            enabled_arp_cache: false,
            enabled_conntrack: false,
            enabled_hostapd: false,
            hostapd_interfaces: vec![],
            enabled_router_arp: true,
            routers: vec![format!("127.0.0.1:{}", router.port())],
            router_community: "public".into(),
            router_timeout: Duration::from_secs(2),
            network_cidr: Some("192.0.2.0/24".parse().unwrap()),
        };
        let mut state = DiscoveryState::default();
        let newly = sources.sweep(&engine, &mut state).await;
        let mut sorted = newly;
        sorted.sort();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].0, "192.0.2.50");
        assert_eq!(sorted[0].2.as_deref(), Some("aa:bb:cc:dd:ee:50"));
        // seeds carry the mac evidence for the next scan
        {
            let seeds = engine.seeds.lock().await;
            let evs = seeds.get("192.0.2.50").expect("seeded");
            assert!(evs.iter().any(|e| e.kind == "mac" && e.source == "discovery:router_arp"));
        }
        // second sweep: same table, diff emits nothing
        let again = sources.sweep(&engine, &mut state).await;
        assert!(again.is_empty(), "{again:?}");
    }

    #[tokio::test]
    async fn router_arp_dead_router_counts_streak_no_newly() {
        // bind+drop → port with no listener
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = sock.local_addr().unwrap();
        drop(sock);
        let engine = test_engine();
        let sources = DiscoverySources {
            enabled_dhcp_leases: false,
            enabled_arp_cache: false,
            enabled_conntrack: false,
            enabled_hostapd: false,
            hostapd_interfaces: vec![],
            enabled_router_arp: true,
            routers: vec![format!("127.0.0.1:{}", dead.port())],
            router_community: "public".into(),
            router_timeout: Duration::from_millis(250),
            network_cidr: None,
        };
        let mut state = DiscoveryState::default();
        let newly = sources.sweep(&engine, &mut state).await;
        assert!(newly.is_empty());
        assert_eq!(state.router_fail_streak.get(&format!("127.0.0.1:{}", dead.port())), Some(&1));
        // still failing: streak grows, still no newly
        let _ = sources.sweep(&engine, &mut state).await;
        assert_eq!(state.router_fail_streak.get(&format!("127.0.0.1:{}", dead.port())), Some(&2));
    }


    #[test]
    fn parses_leases() {
        let text = "1760000000 aa:bb:cc:dd:ee:ff 192.0.2.50 viomi-waterheater-e13 *\n1760000000 11:22:33:44:55:66 192.0.2.51 * *\n";
        let leases = parse_dhcp_leases(text);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].hostname, "viomi-waterheater-e13");
        assert_eq!(leases[1].hostname, "");
        assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parses_arp_pairs() {
        let text = "IP address  HW type   Flags  HW address            Mask Device\n192.0.2.5  0x1 0x2 aa:bb:cc:dd:ee:ff * br-lan\n192.0.2.6 0x1 0x0 dd:ee:ff:00:11:22 * br-lan\n";
        let pairs = parse_proc_arp_pairs(text);
        assert_eq!(pairs, vec![("192.0.2.5".into(), "aa:bb:cc:dd:ee:ff".into())]);
    }

    #[test]
    fn parses_conntrack_lan_side() {
        let text = "ipv4 2 tcp 6 300 ESTABLISHED src=203.0.113.9 dst=192.0.2.7 sport=443 dport=51000 src=192.0.2.7 dst=203.0.113.9 sport=51000 dport=443 [ASSURED] mark=0\n";
        let net: ipnet::Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let ips = parse_conntrack(text, &net);
        assert!(ips.contains(&"192.0.2.7".to_string()), "{ips:?}");
    }

    #[test]
    fn parses_hostapd_sta_reply() {
        let resp = "addr=AA:BB:CC:DD:EE:FF\naid=1\nsignal=-42\nconnected_time=1200\nssid=home-net\n";
        let sta = parse_hostapd_sta(resp);
        assert_eq!(sta.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(sta.signal, "-42");
        assert_eq!(sta.ssid, "home-net");
        assert_eq!(sta.connected_secs, "1200");
        // minimal reply: just the MAC
        let sta = parse_hostapd_sta("addr=11:22:33:44:55:66\n");
        assert_eq!(sta.mac, "11:22:33:44:55:66");
        assert_eq!(sta.signal, "");
    }

    #[test]
    fn parses_iw_station_dump() {
        let out = "Station aa:bb:cc:dd:ee:ff (on wlan0)\n\tinactive time:\t30 ms\n\trx bytes:\t1234\n\tsignal:\t  -42 dBm\n\tsignal avg:\t-44 dBm\n\nStation 11:22:33:44:55:66 (on wlan0)\n\tinactive time:\t2 ms\n\tsignal:\t  -60 dBm\n";
        let stas = parse_iw_station_dump(out);
        assert_eq!(stas.len(), 2);
        assert_eq!(stas[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(stas[0].signal, "-42");
        assert_eq!(stas[1].mac, "11:22:33:44:55:66");
        assert_eq!(stas[1].signal, "-60");
    }

    #[test]
    fn wifi_evidence_carries_hints() {
        let ev = wifi_evidence(&StaInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            signal: "-42".into(),
            ssid: "home".into(),
            connected_secs: "1200".into(),
        });
        assert_eq!(ev.kind, "wifi");
        let rd = ev.raw_data.unwrap();
        assert_eq!(rd.get("discovery_note").unwrap(), "wifi_assoc");
        assert_eq!(rd.get("wifi_signal_dbm").unwrap(), "-42");
        assert_eq!(rd.get("wifi_ssid").unwrap(), "home");
        assert_eq!(rd.get("wifi_connected_secs").unwrap(), "1200");
    }

    #[test]
    fn wifi_attaches_once_per_mac() {
        let mut state = DiscoveryState::default();
        assert!(attach_wifi(&mut state, "aa:bb:cc:dd:ee:ff").is_none()); // nothing cached
        state
            .wifi_by_mac
            .insert("aa:bb:cc:dd:ee:ff".into(), wifi_evidence(&StaInfo { mac: "aa:bb:cc:dd:ee:ff".into(), ..Default::default() }));
        assert!(attach_wifi(&mut state, "aa:bb:cc:dd:ee:ff").is_some());
        assert!(attach_wifi(&mut state, "aa:bb:cc:dd:ee:ff").is_none()); // already attached
    }
}
