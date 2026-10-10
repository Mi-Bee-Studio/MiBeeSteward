//! Orchestrator + engine: per-host gather (all probes concurrently, merge
//! in probe-name order), classify (rule corpus + SNMP logic classifier),
//! fold, bridge, and ReportedHost conversion. Seed evidence (the Go-gap fix
//! #471 asks for) prepends passive observations before active evidence.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use mibee_fingerprints::{Evidence, RuleClassifier, ServiceIdentity};

use crate::engine::device_types::DeviceTypeRules;
use crate::engine::identify::{
    apply_device_bridge, fold_host_evidence, fold_identities, snmp_classify, DeviceFields,
    SnmpTables,
};
use crate::engine::oui::Oui;
use crate::engine::probes::ProbeHint;
use crate::wire::ReportedHost;

pub struct ScanEngine {
    pub probes: Vec<Box<dyn crate::engine::probes::Probe>>,
    pub classifier: Arc<RuleClassifier>,
    pub snmp_tables: Arc<SnmpTables>,
    pub rules: Arc<DeviceTypeRules>,
    pub oui: Arc<Oui>,
    /// Extra literal ports from a task's port_scan whitelist.
    pub port_spec: Vec<u16>,
    pub per_host_timeout: Duration,
    pub per_probe_timeout: Duration,
    pub max_concurrent_hosts: usize,
    pub community: String,
    /// SNMP target port (161 in production; tests point probes at a
    /// scripted agent).
    pub snmp_port: u16,
    pub rdns_servers: Vec<String>,
    pub routers: Vec<String>,
    pub allow_reserved: bool,
    /// Passive observation cache: ip -> evidence (the seed channel).
    pub seeds: tokio::sync::Mutex<std::collections::HashMap<String, Vec<Evidence>>>,
}

/// An SNMP credential resolved from the agent-local vault before a scan
/// (Go scannerv2.SNMPCredential threaded into the probe hint): v3 carries
/// the USM identity, v1v2c overrides the community. Default = neither
/// (engine-global community).
#[derive(Debug, Clone, Default)]
pub struct ResolvedCredential {
    pub v3: Option<crate::engine::probes::SnmpV3Credential>,
    pub community: Option<String>,
}

impl ScanEngine {
    /// Scan one IP and produce the ReportedHost (None when not alive).
    pub async fn scan_host(&self, ip: IpAddr) -> Option<ReportedHost> {
        self.scan_host_with(ip, &ResolvedCredential::default()).await
    }

    /// Scan with a scan-task/command-bound SNMP credential (agent-local
    /// vault resolves it before the run; Go's ResolveByID/ResolveByName).
    pub async fn scan_host_with(&self, ip: IpAddr, cred: &ResolvedCredential) -> Option<ReportedHost> {
        let hint = ProbeHint {
            timeout: self.per_probe_timeout,
            community: self.community.clone(),
            port_spec: self.port_spec.clone(),
            snmp_port: self.snmp_port,
            mdns_port: 0,
            rdns_servers: self.rdns_servers.clone(),
            oui: Arc::clone(&self.oui),
            snmp_v3: cred.v3.clone(),
            community_override: cred.community.clone(),
        };
        // gather: base probes concurrently under the per-host timeout, then —
        // only when the host proved it speaks SNMP (the sys* Get succeeded, or
        // a passive observation said so) — the L2 MIB family. Go runs the
        // bridge/LLDP/CDP/Q-BRIDGE/STP walks on EVERY host, paying several
        // walk timeouts per non-SNMP host; the gate keeps that cost at zero
        // and the evidence ordering (base then L2) is the only divergence.
        let mut futures = Vec::new();
        for p in &self.probes {
            if !crate::engine::probes::l2_mib::is_l2_probe(p.name()) {
                futures.push(p.probe(ip, &hint));
            }
        }
        let mut gathered = tokio::time::timeout(
            self.per_host_timeout,
            futures::future::join_all(futures),
        )
        .await
        .unwrap_or_default();
        let mut evidence: Vec<Evidence> = Vec::new();
        for evs in gathered.drain(..) {
            evidence.extend(evs);
        }
        // seed evidence (passive observations, possibly a known-SNMP hint)
        // PREPENDS active evidence
        if let Some(seeds) = self.seeds.lock().await.get(&ip.to_string()) {
            let mut with_seeds = seeds.clone();
            with_seeds.extend(evidence);
            evidence = with_seeds;
        }
        let speaks_snmp = evidence
            .iter()
            .any(|e| e.source == "active:snmp" || e.kind == "snmp");
        if speaks_snmp {
            let l2: Vec<_> = self
                .probes
                .iter()
                .filter(|p| crate::engine::probes::l2_mib::is_l2_probe(p.name()))
                .map(|p| p.probe(ip, &hint))
                .collect();
            let l2_gathered = tokio::time::timeout(
                self.per_host_timeout,
                futures::future::join_all(l2),
            )
            .await
            .unwrap_or_default();
            for evs in l2_gathered {
                evidence.extend(evs);
            }
        }

        // Cross-subnet MAC fallback (Go SetPostScanResolver + engine wiring):
        // when no probe resolved a MAC (the local ARP cache is blind off the
        // agent's own subnet) and routers are configured, ask the router that
        // IS on the target subnet. Same evidence shape as the ARP probe, OUI
        // vendor included, so the fold and the wire `mac` field see no
        // difference. Non-fatal: a dead router just leaves the MAC empty.
        // Timeout = per-probe timeout (Go passes the whole-pipeline default,
        // which can stall a scan 5 minutes on an unreachable router).
        if !self.routers.is_empty() && !evidence.iter().any(|e| e.kind == "mac") {
            let community = cred
                .community
                .clone()
                .unwrap_or_else(|| self.community.clone());
            if let Some(mac) = crate::engine::probes::snmp_arp::lookup_mac_via_routers(
                &self.routers,
                &community,
                self.per_probe_timeout,
                cred.v3.as_ref(),
                &ip.to_string(),
            )
            .await
            {
                let mut rd = std::collections::BTreeMap::from([("mac".to_string(), mac.clone())]);
                if let Some((vendor, prefix)) = self.oui.lookup_full(&mac) {
                    rd.insert("vendor".to_string(), vendor.clone());
                    rd.insert("oui_prefix".to_string(), prefix);
                    rd.insert("oui_vendor".to_string(), vendor);
                }
                evidence.push(Evidence {
                    source: "active:arp".into(),
                    kind: "mac".into(),
                    ip: ip.to_string(),
                    protocol: "arp".into(),
                    confidence: 1.0,
                    raw_data: Some(rd),
                    ..Default::default()
                });
            }
        }
        if evidence.is_empty() {
            return None; // not alive
        }

        // classify: rule corpus + SNMP logic classifier (concatenated)
        let mut identities: Vec<ServiceIdentity> = self.classifier.classify(&evidence);
        if let Some(snmp_ident) = snmp_classify(&self.snmp_tables, &evidence) {
            identities.push(snmp_ident);
        }

        // fold + bridge
        let mut fields = DeviceFields::default();
        fold_host_evidence(&mut fields, &evidence);
        fold_identities(&mut fields, &identities, &evidence);
        let open_ports: Vec<u16> = evidence
            .iter()
            .filter(|e| e.kind == "port_open")
            .filter_map(|e| if e.port > 0 && e.port <= 65535 { Some(e.port as u16) } else { None })
            .collect();
        apply_device_bridge(&self.rules, &mut fields, &identities, &open_ports);

        Some(host_to_reported(ip, &evidence, &identities, &fields))
    }

    /// Record passive observations for an IP (discovery sources call this).
    pub async fn observe(&self, ip: &str, evs: Vec<Evidence>) {
        if ip.is_empty() || evs.is_empty() {
            return;
        }
        let mut seeds = self.seeds.lock().await;
        let entry = seeds.entry(ip.to_string()).or_default();
        entry.extend(evs);
        let cap = 16;
        if entry.len() > cap {
            let excess = entry.len() - cap;
            entry.drain(0..excess);
        }
    }
}

/// Go reporter.go hostToReported: fields -> wire host.
pub fn host_to_reported(
    ip: IpAddr,
    evidence: &[Evidence],
    identities: &[ServiceIdentity],
    fields: &DeviceFields,
) -> ReportedHost {
    let g = |k: &str| fields.map.get(k).cloned().unwrap_or_default();
    let mut host = ReportedHost {
        ip: ip.to_string(),
        alive: true,
        mac: {
            let m = g("mac");
            if m.is_empty() {
                evidence
                    .iter()
                    .find(|e| e.kind == "mac")
                    .and_then(|e| e.raw_data.as_ref().and_then(|rd| rd.get("mac").cloned()))
                    .unwrap_or_default()
            } else {
                m
            }
        },
        inferred_type: g("inferred_type"),
        inferred_type_source: g("inferred_type_source"),
        inferred_brand: g("inferred_brand"),
        inferred_model: g("inferred_model"),
        inferred_description: g("inferred_description"),
        inferred_location: g("inferred_location"),
        hostname: {
            let h = g("node_hostname");
            if h.is_empty() { g("sys_name") } else { h }
        },
        ..Default::default()
    };
    // rtt from echo evidence
    if let Some(e) = evidence.iter().find(|e| e.kind == "echo") {
        if let Some(rd) = &e.raw_data {
            if let Some(rtt) = rd.get("rtt_ms") {
                host.rtt_ms = rtt.parse().unwrap_or(0);
            }
        }
    }
    host.open_ports = {
        let ports: Vec<i64> = evidence
            .iter()
            .filter(|e| e.kind == "port_open")
            .map(|e| e.port)
            .filter(|p| *p > 0)
            .collect();
        serde_json::to_string(&ports).unwrap_or_default()
    };
    host.services = identities
        .iter()
        .map(|ident| crate::wire::ReportedService {
            service: ident.service.clone(),
            port: ident.port,
            protocol: ident.protocol.clone(),
            metadata: ident.metadata.clone(),
        })
        .collect();
    host.heartbeats = generate_heartbeats(ip, identities);
    // detected_services: sorted unique service names as JSON array string
    let mut names: Vec<&str> = identities.iter().map(|i| i.service.as_str()).collect();
    names.sort();
    names.dedup();
    host.detected_services = serde_json::to_string(&names).unwrap_or_default();
    // L2 adjacency edges → wire neighbors array (Go hostToReported parity):
    // the evidence slice never crosses the wire, so this extraction is the
    // only way the center's device_neighbors pipeline sees agent topology.
    // Dedup per (neighbor_mac, protocol), mirroring the center's
    // ExtractNeighbors.
    {
        let mut seen = std::collections::HashSet::new();
        for e in evidence.iter().filter(|e| e.kind == "neighbor") {
            let Some(rd) = &e.raw_data else { continue };
            let g = |k: &str| rd.get(k).cloned().unwrap_or_default();
            let (mac, protocol) = (g("neighbor_mac"), g("protocol"));
            if mac.is_empty() || protocol.is_empty() {
                continue;
            }
            if !seen.insert((mac.clone(), protocol.clone())) {
                continue;
            }
            host.neighbors.push(crate::wire::ReportedNeighbor {
                neighbor_mac: mac,
                protocol,
                local_port: g("local_port"),
                remote_port: g("remote_port"),
                vlan_tag: g("vlan_tag"),
                sys_name: g("sys_name"),
                sys_desc: g("sys_desc"),
                source: e.source.clone(),
            });
        }
    }
    host
}

/// Server-class service names (Go handler/services.go serverServiceNames).
const SERVER_SERVICE_NAMES: [&str; 13] = [
    // Databases.
    "mysql", "postgresql", "redis", "mongodb", "mssql", "memcached",
    // Mail.
    "smtp", "pop3", "imap",
    // Remote access.
    "vnc", "rdp",
    // Directory & file-share.
    "ldap", "smb",
];

/// TLS-wrapped server-class names (Go handler/tls_collect.go tlsCollectNames).
const TLS_COLLECT_NAMES: [&str; 8] = [
    "https", "ldaps", "smtps", "imaps", "pop3s", "ftps", "ircs", "telnets",
];

fn scheme_for(port: i64) -> &'static str {
    if port == 443 { "https" } else { "http" }
}

fn url_for(ip: IpAddr, port: i64, path: &str) -> String {
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    format!("{}://{}:{}{}", scheme_for(port), ip, port, path)
}

/// Heartbeat specs per classified identity, port of the Go handler cascade's
/// depth-0 GenerateHeartbeat rules: http → HTTP on /, ssh/rtsp and the
/// server/TLS-class names → TCP on the service port, onvif → HTTP on the
/// SOAP endpoint, camera → ICMP, snmp → SNMP sysUpTime poll with the default
/// community, prometheus → HTTP on /metrics. mdns/ssdp/miot (and cascaded
/// node_exporter, which rides the prometheus heartbeat) emit none.
/// interval/timeout stay 0 — the center applies its defaults (Go omitempty).
pub fn generate_heartbeats(ip: IpAddr, identities: &[ServiceIdentity]) -> Vec<crate::wire::ReportedHeartbeat> {
    use crate::wire::ReportedHeartbeat;
    let mut out = Vec::new();
    for ident in identities {
        let hb = match ident.service.as_str() {
            "http" => Some(ReportedHeartbeat {
                method: "http".into(),
                target: url_for(ip, ident.port, "/"),
                ..Default::default()
            }),
            "prometheus" => Some(ReportedHeartbeat {
                method: "http".into(),
                target: url_for(ip, ident.port, "/metrics"),
                ..Default::default()
            }),
            "ssh" | "rtsp" => Some(ReportedHeartbeat {
                method: "tcp".into(),
                target: format!("{}:{}", ip, ident.port),
                ..Default::default()
            }),
            "onvif" => Some(ReportedHeartbeat {
                method: "http".into(),
                target: format!(
                    "{}://{}:{}/onvif/device_service",
                    scheme_for(ident.port),
                    ip,
                    ident.port
                ),
                ..Default::default()
            }),
            "camera" => Some(ReportedHeartbeat {
                method: "icmp".into(),
                target: ip.to_string(),
                ..Default::default()
            }),
            "snmp" => Some(ReportedHeartbeat {
                method: "snmp".into(),
                target: ip.to_string(),
                snmp_community: "public".into(),
                snmp_oid: "1.3.6.1.2.1.1.3.0".into(), // sysUpTime
                ..Default::default()
            }),
            name if SERVER_SERVICE_NAMES.contains(&name) || TLS_COLLECT_NAMES.contains(&name) => {
                Some(ReportedHeartbeat {
                    method: "tcp".into(),
                    target: format!("{}:{}", ip, ident.port),
                    ..Default::default()
                })
            }
            _ => None,
        };
        if let Some(h) = hb {
            out.push(h);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::probes::default_probes;
    use std::collections::BTreeMap;

    /// Corpus dir that works in BOTH layouts: nested inside the main repo
    /// (MiBeeSteward/agent-rs/crates/mibee-agent → ../../../configs) and the
    /// original standalone checkout next to it (→ ../../../MiBeeSteward/
    /// configs). MIBEE_FP_CORPUS overrides both.
    fn test_corpus_dir() -> String {
        if let Ok(c) = std::env::var("MIBEE_FP_CORPUS") {
            if !c.is_empty() {
                return c;
            }
        }
        for p in [
            "../../../configs/fingerprints",
            "../../../MiBeeSteward/configs/fingerprints",
        ] {
            if std::path::Path::new(p).join("snmp-data.yaml").exists() {
                return p.to_string();
            }
        }
        "../../../configs/fingerprints".to_string()
    }

    #[tokio::test]
    async fn cross_subnet_mac_falls_back_to_router_arp() {
        // Host with a live TCP banner but no local ARP evidence (loopback
        // never populates /proc/net/arp): the engine must fill the MAC from
        // the configured router's SNMP ARP table, with OUI vendor folded.
        use crate::engine::probes::snmp::test_support::spawn_fake_router;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = s.write_all(b"SSH-2.0-test\r\n").await;
            }
        });
        // router table names the scanned host
        let root = crate::engine::probes::snmp_arp::OID_IP_NET_TO_MEDIA.to_string();
        let router = spawn_fake_router(
            vec![(
                format!("{root}.1.127.0.0.1"),
                vec![0x50, 0x46, 0x5D, 0x11, 0x22, 0x33],
            )],
            "1.3.6.1.2.1.4.22.1.3.1".to_string(),
        )
        .await;

        let mut classifier = RuleClassifier::new();
        let corpus = test_corpus_dir();
        classifier.load_from_dir(&corpus).expect("corpus");
        let snmp_text = std::fs::read_to_string(
            std::path::Path::new(&corpus).join("snmp-data.yaml"),
        )
        .unwrap_or_default();
        let engine = ScanEngine {
            probes: default_probes(),
            classifier: Arc::new(classifier),
            snmp_tables: Arc::new(SnmpTables::parse(&snmp_text).unwrap_or_default()),
            rules: Arc::new(DeviceTypeRules::load_embedded()),
            oui: Arc::new(crate::engine::oui::Oui::parse(
                crate::engine::oui::EMBEDDED_OUI,
            )),
            port_spec: vec![port],
            per_host_timeout: Duration::from_secs(10),
            per_probe_timeout: Duration::from_secs(2),
            max_concurrent_hosts: 50,
            community: "public".into(),
            snmp_port: 161,
            rdns_servers: vec![],
            routers: vec![format!("127.0.0.1:{}", router.port())],
            allow_reserved: true,
            seeds: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let host = engine
            .scan_host("127.0.0.1".parse().unwrap())
            .await
            .expect("alive via banner");
        assert_eq!(host.mac, "50:46:5d:11:22:33", "MAC resolved via the router walk");
    }

    #[tokio::test]
    async fn l2_gate_snmp_host_carries_wire_neighbors() {
        // A scripted SNMP agent: answers the sys* Get (opens the L2 gate) and
        // serves an LLDP chassis row. The scanned host must come back with a
        // wire `neighbors` entry built from the LLDP walk.
        use crate::engine::probes::snmp::test_support::spawn_fake_router_typed;
        let root = "1.0.8802.1.1.2.1.4.1.1.5";
        let rows: Vec<(String, u8, Vec<u8>)> = vec![
            ("1.0.8802.1.1.2.1.4.1.1.4.0.10.1".to_string(), 0x02, vec![4]),
            (format!("{root}.0.10.1"), 0x04, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            ("1.0.8802.1.1.2.1.4.1.1.7.0.10.1".to_string(), 0x04, b"swp1".to_vec()),
            ("1.0.8802.1.1.2.1.4.1.1.9.0.10.1".to_string(), 0x04, b"sw-core".to_vec()),
        ];
        let fake = spawn_fake_router_typed(rows, "1.2".to_string()).await;

        let mut classifier = RuleClassifier::new();
        let corpus = test_corpus_dir();
        classifier.load_from_dir(&corpus).expect("corpus");
        let snmp_text =
            std::fs::read_to_string(std::path::Path::new(&corpus).join("snmp-data.yaml"))
                .unwrap_or_default();
        let engine = ScanEngine {
            probes: default_probes(),
            classifier: Arc::new(classifier),
            snmp_tables: Arc::new(SnmpTables::parse(&snmp_text).unwrap_or_default()),
            rules: Arc::new(DeviceTypeRules::load_embedded()),
            oui: Arc::new(crate::engine::oui::Oui::parse(
                crate::engine::oui::EMBEDDED_OUI,
            )),
            port_spec: vec![],
            per_host_timeout: Duration::from_secs(10),
            per_probe_timeout: Duration::from_secs(2),
            max_concurrent_hosts: 50,
            community: "public".into(),
            snmp_port: fake.port(),
            rdns_servers: vec![],
            routers: vec![],
            allow_reserved: true,
            seeds: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let host = engine
            .scan_host("127.0.0.1".parse().unwrap())
            .await
            .expect("alive via the SNMP sys response");
        assert_eq!(host.neighbors.len(), 1, "{:?}", host.neighbors);
        let n = &host.neighbors[0];
        assert_eq!(n.neighbor_mac, "11:22:33:44:55:66");
        assert_eq!(n.protocol, "LLDP");
        assert_eq!(n.local_port, "10");
        assert_eq!(n.remote_port, "swp1");
        assert_eq!(n.sys_name, "sw-core");
        assert_eq!(n.source, "active:lldp_mib");
    }

    #[tokio::test]
    async fn l2_gate_closed_without_snmp_evidence() {
        // Host alive via a TCP banner but SNMP silent: the L2 family must
        // not run (and the wire neighbors array stays empty).
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = s.write_all(b"SSH-2.0-x
").await;
            }
        });
        let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let mut classifier = RuleClassifier::new();
        let corpus = test_corpus_dir();
        classifier.load_from_dir(&corpus).expect("corpus");
        let engine = ScanEngine {
            probes: default_probes(),
            classifier: Arc::new(classifier),
            snmp_tables: Arc::new(SnmpTables::default()),
            rules: Arc::new(DeviceTypeRules::load_embedded()),
            oui: Arc::new(crate::engine::oui::Oui::parse("")),
            port_spec: vec![port],
            per_host_timeout: Duration::from_secs(10),
            per_probe_timeout: Duration::from_millis(700),
            max_concurrent_hosts: 50,
            community: "public".into(),
            snmp_port: dead_port,
            rdns_servers: vec![],
            routers: vec![],
            allow_reserved: true,
            seeds: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let host = engine
            .scan_host("127.0.0.1".parse().unwrap())
            .await
            .expect("alive via banner");
        assert!(host.neighbors.is_empty());
    }

    #[tokio::test]
    async fn scan_host_against_local_services() {
        // A local SSH-greeting listener + a closed everything else; run the
        // engine with a tiny port spec against it.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = s.write_all(b"SSH-2.0-dropbear_2020.81\r\n").await;
            }
        });

        let mut classifier = RuleClassifier::new();
        let corpus = test_corpus_dir();
        classifier.load_from_dir(&corpus).expect("corpus");
        let snmp_text = std::fs::read_to_string(
            std::path::Path::new(&corpus).join("snmp-data.yaml"),
        )
        .unwrap_or_default();
        let engine = ScanEngine {
            probes: default_probes(),
            classifier: Arc::new(classifier),
            snmp_tables: Arc::new(SnmpTables::parse(&snmp_text).unwrap_or_default()),
            rules: Arc::new(DeviceTypeRules::load_embedded()),
            oui: Arc::new(crate::engine::oui::Oui::parse(
                crate::engine::oui::EMBEDDED_OUI,
            )),
            port_spec: vec![port],
            per_host_timeout: Duration::from_secs(10),
            per_probe_timeout: Duration::from_secs(2),
            max_concurrent_hosts: 50,
            community: "public".into(),
            snmp_port: 161,
            rdns_servers: vec![],
            routers: vec![],
            allow_reserved: true,
            seeds: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let host = engine
            .scan_host("127.0.0.1".parse().unwrap())
            .await
            .expect("host alive via banner");
        assert_eq!(host.ip, "127.0.0.1");
        let services: Vec<&str> = host.services.iter().map(|s| s.service.as_str()).collect();
        assert!(services.contains(&"ssh"), "{services:?}");
        let ssh = host.services.iter().find(|s| s.service == "ssh").unwrap();
        assert_eq!(ssh.port, port as i64);
        let ports: Vec<i64> = serde_json::from_str(&host.open_ports).unwrap();
        assert!(ports.contains(&(port as i64)));
    }

    #[test]
    fn host_to_reported_shape() {
        let fields = DeviceFields {
            map: BTreeMap::from([
                ("mac".into(), "aa:bb:cc:dd:ee:ff".into()),
                ("node_hostname".into(), "rpi3b-storage".into()),
                ("inferred_type".into(), "embedded".into()),
                ("inferred_type_source".into(), "heuristic".into()),
            ]),
        };
        let ev = vec![Evidence {
            kind: "echo".into(),
            raw_data: Some(BTreeMap::from([("rtt_ms".to_string(), "12".to_string())])),
            ..Default::default()
        }];
        let ids = vec![ServiceIdentity {
            service: "ssh".into(),
            port: 22,
            protocol: "tcp".into(),
            confidence: 0.95,
            evidence: vec![],
            metadata: None,
        }];
        let host = host_to_reported("192.0.2.5".parse().unwrap(), &ev, &ids, &fields);
        assert_eq!(host.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(host.hostname, "rpi3b-storage");
        assert_eq!(host.rtt_ms, 12);
        assert_eq!(host.detected_services, r#"["ssh"]"#);
        assert_eq!(host.services[0].service, "ssh");
        // ssh identity now also carries a TCP heartbeat spec (Go depth-0 rule)
        assert_eq!(host.heartbeats.len(), 1);
        assert_eq!(host.heartbeats[0].method, "tcp");
        assert_eq!(host.heartbeats[0].target, "192.0.2.5:22");
        assert_eq!(host.heartbeats[0].interval_seconds, 0); // center fills defaults
    }

    fn ident(service: &str, port: i64) -> ServiceIdentity {
        ServiceIdentity {
            service: service.into(),
            port,
            protocol: "tcp".into(),
            confidence: 0.9,
            evidence: vec![],
            metadata: None,
        }
    }

    #[test]
    fn heartbeat_rules_match_go_handlers() {
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let hbs = generate_heartbeats(
            ip,
            &[
                ident("http", 80),
                ident("https", 443),
                ident("ssh", 22),
                ident("rtsp", 8554),
                ident("onvif", 8080),
                ident("camera", 0),
                ident("snmp", 161),
                ident("prometheus", 9100),
                ident("mysql", 3306),
                ident("ldaps", 636),
                ident("mdns", 5353),
                ident("ssdp", 1900),
                ident("miot", 0),
                ident("unknown-thing", 1234),
            ],
        );
        let targets: Vec<(&str, &str)> = hbs.iter().map(|h| (h.method.as_str(), h.target.as_str())).collect();
        assert_eq!(
            targets,
            vec![
                ("http", "http://192.0.2.9:80/"),
                ("tcp", "192.0.2.9:443"),      // https = TLS-collect class → TCP
                ("tcp", "192.0.2.9:22"),
                ("tcp", "192.0.2.9:8554"),
                ("http", "http://192.0.2.9:8080/onvif/device_service"),
                ("icmp", "192.0.2.9"),
                ("snmp", "192.0.2.9"),
                ("http", "http://192.0.2.9:9100/metrics"),
                ("tcp", "192.0.2.9:3306"),
                ("tcp", "192.0.2.9:636"),
            ]
        );
        let snmp_hb = &hbs[6];
        assert_eq!(snmp_hb.snmp_community, "public");
        assert_eq!(snmp_hb.snmp_oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(snmp_hb.interval_seconds, 0);
        assert_eq!(snmp_hb.timeout_seconds, 0);
    }

    #[test]
    fn onvif_on_443_uses_https_scheme() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let hbs = generate_heartbeats(ip, &[ident("onvif", 443)]);
        assert_eq!(hbs[0].target, "https://192.0.2.10:443/onvif/device_service");
    }
}
