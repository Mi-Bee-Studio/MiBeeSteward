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
/// flows, within the given CIDR (#504 Go parity):
/// - liveness tokens match Go exactly — bare ESTABLISHED (TCP state field) or
///   bracketed [ASSURED] (UDP flows have no state field); [UNASSURED] does NOT
///   count;
/// - the LAN-local endpoint is whichever side of the flow sits inside the
///   CIDR: outbound flows carry it as src=, inbound as dst=, LAN↔LAN flows
///   contribute both.
pub fn parse_conntrack(text: &str, cidr: &ipnet::Ipv4Net) -> Vec<String> {
    let mut seen = HashSet::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let live = tokens.iter().any(|t| *t == "ESTABLISHED" || *t == "[ASSURED]");
        if !live {
            continue;
        }
        for token in &tokens {
            let value = token
                .strip_prefix("src=")
                .or_else(|| token.strip_prefix("dst="));
            if let Some(ip) = value {
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

// ---------- dns_log (dnsmasq --log-queries tail, Go discovery/dns_log.go) ----------

/// Conventional dnsmasq log paths, probed in order when the config gives none
/// (Go DNSLogSource.files parity).
pub const DNS_LOG_PATHS: [&str; 4] = [
    "/var/log/dnsmasq.log", // explicit --log-facility (common)
    "/tmp/dnsmasq.log",     // OpenWrt ramdisk (often via logread redirect)
    "/var/log/messages",    // syslog fallback (when dnsmasq logs to syslog)
    "/var/log/syslog",      // Debian rsyslog default
];

/// Parse one dnsmasq query line into (querying_host_ip, domain). Only
/// "query[...]" lines carry a "... from <ip>" host sighting; reply/cached
/// lines and locally-originated queries ("from <iface>") yield None. Go
/// parseDnsmasqQuery parity (#504).
pub fn parse_dnsmasq_query(line: &str) -> Option<(String, String)> {
    let rest = line.split("dnsmasq").nth(1)?;
    let rest = &rest[rest.find("query[")?..];
    let close = rest.find(']')?;
    let rest = rest[close + 1..].trim();
    let from = rest.rfind(" from ")?;
    let domain = rest[..from].trim();
    let mut ip = rest[from + " from ".len()..].trim();
    // Defensive: a syslog relay might append junk after the address.
    if let Some(sp) = ip.find(' ') {
        ip = &ip[..sp];
    }
    if domain.is_empty() || ip.is_empty() {
        return None;
    }
    // Reject "from eth0" style non-addresses (locally-originated queries).
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    if !octets.iter().all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()) && o.parse::<u8>().is_ok()) {
        return None;
    }
    Some((ip.to_string(), domain.to_string()))
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
    /// Conntrack table path; empty = /proc/net/nf_conntrack. Test seam.
    pub conntrack_path: String,
    /// dns_log source (Go DNSLogSource): tails dnsmasq --log-queries output;
    /// each LAN host's queries are host sightings + domain seeds (#504).
    pub enabled_dns_log: bool,
    /// Explicit dns log path; empty = the conventional DNS_LOG_PATHS probe.
    pub dns_log_path: String,
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
    /// dns_log tail offsets per file path (Go DNSLogSource.offset map parity).
    dns_offsets: std::collections::HashMap<String, u64>,
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
            let ct_path = if self.conntrack_path.is_empty() {
                "/proc/net/nf_conntrack"
            } else {
                self.conntrack_path.as_str()
            };
            if let (Some(cidr), Ok(text)) =
                (self.network_cidr, tokio::fs::read_to_string(ct_path).await)
            {
                for ip in parse_conntrack(&text, &cidr) {
                    // Go parity (#504): a LAN endpoint with an established flow
                    // is a live-host sighting, reported once on its first
                    // lifetime appearance — the host may answer no probe at
                    // all. No MAC: conntrack is L3+; a later ARP/dhcp/scan
                    // sighting of the same IP fills the MAC and the center
                    // bridge reconciles by IP+network.
                    if state.known.insert(format!("ct:{ip}")) {
                        newly.push((ip, None, None));
                    }
                }
            }
        }
        if self.enabled_dns_log {
            let paths: Vec<String> = if self.dns_log_path.is_empty() {
                DNS_LOG_PATHS.iter().map(|p| p.to_string()).collect()
            } else {
                vec![self.dns_log_path.clone()]
            };
            for path in paths {
                // Go tailFile parity (#504): first sight of a file starts at
                // EOF (history is not replayed — only NEW queries going
                // forward are interesting); a shrunk file (rotation/truncation)
                // restarts from byte 0.
                let Ok(meta) = tokio::fs::metadata(&path).await else { continue };
                let cur = meta.len();
                let prev = *state.dns_offsets.get(&path).unwrap_or(&0);
                let mut start = if prev == 0 { cur } else if cur < prev { 0 } else { prev };
                if start >= cur {
                    state.dns_offsets.insert(path.clone(), cur);
                    continue;
                }
                let Ok(bytes) = tokio::fs::read(&path).await else { continue };
                let chunk = &bytes[start as usize..cur as usize];
                let text = String::from_utf8_lossy(chunk);
                let mut new_off = start;
                for line in text.split_inclusive('\n') {
                    new_off += line.len() as u64;
                    if let Some((ip, domain)) = parse_dnsmasq_query(line) {
                        let ev = Evidence {
                            source: "discovery:dns_log".into(),
                            kind: "dns_query".into(),
                            ip: ip.clone(),
                            protocol: "dns".into(),
                            confidence: 0.8,
                            raw_data: Some(
                                [("domain".to_string(), domain)]
                                    .into_iter()
                                    .collect(),
                            ),
                            ..Default::default()
                        };
                        observations.push((ip.clone(), ev));
                        // Devices that block every inbound probe still make
                        // outbound DNS: the query itself is the sighting.
                        if state.known.insert(format!("dns:{ip}")) {
                            newly.push((ip, None, None));
                        }
                    }
                }
                state.dns_offsets.insert(path, new_off.max(cur));
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

pub(crate) fn in_cidr(ip: &str, cidr: &Option<ipnet::Ipv4Net>) -> bool {
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
            conntrack_path: String::new(),
            enabled_dns_log: false,
            dns_log_path: String::new(),
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
            conntrack_path: String::new(),
            enabled_dns_log: false,
            dns_log_path: String::new(),
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

    /// Go parity (#504): the LAN-local endpoint of a flow is whichever side is
    /// inside the CIDR — inbound flows carry it as dst=, and LAN↔LAN flows
    /// contribute both endpoints.
    #[test]
    fn parses_conntrack_dst_side_and_lan_lan() {
        let net: ipnet::Ipv4Net = "192.0.2.0/24".parse().unwrap();
        // Inbound flow: LAN host is the dst= of the first direction tuple.
        let inbound = "ipv4 2 tcp 6 432000 ESTABLISHED src=198.51.100.9 dst=192.0.2.31 sport=443 dport=51001 [ASSURED] mark=0\n";
        let ips = parse_conntrack(inbound, &net);
        assert_eq!(ips, vec!["192.0.2.31".to_string()], "{ips:?}");
        // LAN↔LAN: both endpoints are LAN-local, both are sightings.
        let lanlan = "ipv4 2 tcp 6 120 ESTABLISHED src=192.0.2.1 dst=192.0.2.55 sport=80 dport=41000 [ASSURED] mark=0\n";
        let ips = parse_conntrack(lanlan, &net);
        assert_eq!(ips.len(), 2, "{ips:?}");
    }

    /// Go parity (#504): [UNASSURED] UDP entries must NOT count as liveness
    /// (Go matches the [ASSURED] token exactly; a contains() check would
    /// wrongly match [UNASSURED]).
    #[test]
    fn parses_conntrack_rejects_unassured_and_nonestablished() {
        let net: ipnet::Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let text = "ipv4 2 udp 17 30 src=192.0.2.8 dst=198.51.100.2 sport=51002 dport=53 [UNASSURED] mark=0\n\
                    ipv4 2 tcp 6 120 TIME_WAIT src=192.0.2.9 dst=198.51.100.3 sport=51003 dport=80 mark=0\n\
                    ipv4 2 udp 17 180 src=192.0.2.10 dst=198.51.100.4 sport=51004 dport=53 [ASSURED] mark=0\n";
        let ips = parse_conntrack(text, &net);
        assert_eq!(ips, vec!["192.0.2.10".to_string()], "{ips:?}");
    }

    /// Go parity (#504): conntrack LAN endpoints are reported as new-host
    /// sightings (first lifetime sighting, once) instead of only being marked
    /// known — a live flow proves the host is up even when it answers nothing.
    #[tokio::test]
    async fn conntrack_source_reports_new_hosts_once() {
        let dir = std::env::temp_dir().join(format!("mibee-ct-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nf_conntrack");
        std::fs::write(
            &path,
            "ipv4 2 tcp 6 300 ESTABLISHED src=192.0.2.50 dst=198.51.100.9 sport=51000 dport=443 [ASSURED] mark=0\n\
             ipv4 2 tcp 6 10 TIME_WAIT src=192.0.2.99 dst=198.51.100.9 sport=51001 dport=443 mark=0\n",
        )
        .unwrap();
        let engine = test_engine();
        let sources = DiscoverySources {
            enabled_dhcp_leases: false,
            enabled_arp_cache: false,
            enabled_conntrack: true,
            enabled_hostapd: false,
            hostapd_interfaces: vec![],
            enabled_router_arp: false,
            routers: vec![],
            router_community: String::new(),
            router_timeout: Duration::from_secs(1),
            network_cidr: Some("192.0.2.0/24".parse().unwrap()),
            conntrack_path: path.to_string_lossy().to_string(),
            enabled_dns_log: false,
            dns_log_path: String::new(),
        };
        let mut state = DiscoveryState::default();
        let newly = sources.sweep(&engine, &mut state).await;
        assert_eq!(newly.len(), 1, "{newly:?}");
        assert_eq!(newly[0].0, "192.0.2.50");
        assert!(newly[0].1.is_none() && newly[0].2.is_none());
        // Second sweep over the same table: nothing new.
        let again = sources.sweep(&engine, &mut state).await;
        assert!(again.is_empty(), "{again:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Go parseDnsmasqQuery parity (#504): only query[...] lines carry a host
    /// sighting; "from <iface>" and non-IP tails are rejected.
    #[test]
    fn parses_dnsmasq_query_lines() {
        let ok = "Oct 11 01:00:00 router dnsmasq[1234]: query[A] example.com from 192.0.2.50";
        assert_eq!(
            parse_dnsmasq_query(ok),
            Some(("192.0.2.50".to_string(), "example.com".to_string()))
        );
        // AAAA flavor
        let ok6 = "dnsmasq[1]: query[AAAA] api.v6.test from 192.0.2.51";
        assert_eq!(
            parse_dnsmasq_query(ok6),
            Some(("192.0.2.51".to_string(), "api.v6.test".to_string()))
        );
        // replies and cached lines: no query[...] token
        assert_eq!(parse_dnsmasq_query("dnsmasq[1]: reply example.com is 192.0.2.9"), None);
        // locally-originated query: "from <iface>", not a host
        assert_eq!(parse_dnsmasq_query("dnsmasq[1]: query[A] router.lan from eth0"), None);
        // junk after the IP (defensive syslog relay) is trimmed
        let junk = "dnsmasq[1]: query[A] x.test from 192.0.2.52 pid=99";
        assert_eq!(
            parse_dnsmasq_query(junk),
            Some(("192.0.2.52".to_string(), "x.test".to_string()))
        );
        // non-dnsmasq syslog line
        assert_eq!(parse_dnsmasq_query("kernel: usb 1-1 disconnected"), None);
    }

    /// Go DNSLogSource parity (#504): the first sweep starts at EOF (history is
    /// not replayed), appended lines are tailed with byte-offset resume, and a
    /// rotated/truncated file restarts from the beginning. Each querying host
    /// is reported once (first lifetime sighting); every query domain becomes
    /// a seed observation for the next scan.
    #[tokio::test]
    async fn dns_log_source_tails_with_offset_resume() {
        let dir = std::env::temp_dir().join(format!("mibee-dns-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dnsmasq.log");
        std::fs::write(&path, "dnsmasq[1]: query[A] history.test from 192.0.2.60
").unwrap();
        let engine = test_engine();
        let sources = DiscoverySources {
            enabled_dhcp_leases: false,
            enabled_arp_cache: false,
            enabled_conntrack: false,
            enabled_hostapd: false,
            hostapd_interfaces: vec![],
            enabled_router_arp: false,
            routers: vec![],
            router_community: String::new(),
            router_timeout: Duration::from_secs(1),
            network_cidr: Some("192.0.2.0/24".parse().unwrap()),
            conntrack_path: String::new(),
            enabled_dns_log: true,
            dns_log_path: path.to_string_lossy().to_string(),
        };
        let mut state = DiscoveryState::default();
        // First sight: skip history, nothing reported.
        let first = sources.sweep(&engine, &mut state).await;
        assert!(first.is_empty(), "{first:?}");
        // Append one query: reported as a new host + a domain seed.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        use std::io::Write;
        writeln!(f, "dnsmasq[1]: query[A] camera.test from 192.0.2.61").unwrap();
        drop(f);
        let second = sources.sweep(&engine, &mut state).await;
        assert_eq!(second.len(), 1, "{second:?}");
        assert_eq!(second[0].0, "192.0.2.61");
        {
            let seeds = engine.seeds.lock().await;
            let evs = seeds.get("192.0.2.61").expect("seeded");
            assert!(
                evs.iter().any(|e| e.kind == "dns_query"
                    && e.source == "discovery:dns_log"
                    && e.raw_data.as_ref().unwrap()["domain"] == "camera.test"),
                "{evs:?}"
            );
        }
        // Same host queries another domain: no duplicate host report, the new
        // domain still seeds.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "dnsmasq[1]: query[A] ntp.test from 192.0.2.61").unwrap();
        drop(f);
        let third = sources.sweep(&engine, &mut state).await;
        assert!(third.is_empty(), "{third:?}");
        {
            let seeds = engine.seeds.lock().await;
            let evs = seeds.get("192.0.2.61").expect("seeded");
            assert!(evs.iter().any(|e| e.raw_data.as_ref().unwrap()["domain"] == "ntp.test"), "{evs:?}");
        }
        // Truncation (rotation): offset resets, a fresh querying host reports.
        std::fs::write(&path, "dnsmasq[1]: query[A] fresh.test from 192.0.2.62
").unwrap();
        let fourth = sources.sweep(&engine, &mut state).await;
        assert_eq!(fourth.len(), 1, "{fourth:?}");
        assert_eq!(fourth[0].0, "192.0.2.62");
        std::fs::remove_dir_all(&dir).ok();
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
