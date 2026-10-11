//! eBPF passive source (#498): the agent-side twin of the center's TC
//! observer — the SAME kernel program (byte-identical object), loaded via
//! aya on the agent's own interfaces, so every agent vantage gets the
//! passive funnel without the center being on-box.
//!
//! Routing mirrors the center exactly (`routePassive` in
//! internal/service/scannerv2/ebpf/event.go):
//!
//! - ARP/ND presence sightings are facts about the network, not service
//!   evidence: an ARP sighting with both IP and MAC reports a passive host
//!   upstream (once per IP, first lifetime sighting) and seeds the MAC for
//!   the host's next scan; ND carries no IPv4 (the MAC-keyed channel is
//!   #522) and is dropped, like the center's funnel.
//! - Signature kinds (SSH/RTSP/HTTP/WS-D/DHCP/TLS-SNI/mDNS/SSDP) become
//!   `Evidence` with source `passive:ebpf:tc` and ride the existing
//!   seed-evidence channel into the next scan report — no wire protocol
//!   change, which is why #498 ships without touching openapi.yaml.
//!
//! Degrade contract: [`run`] logs one warn line and returns on ANY observer
//! failure (unsupported host, missing caps, load/attach error); active
//! probing is unaffected.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use mibee_ebpf::event::{Event, Kind};
use mibee_ebpf::observer::{Observer, ObserverConfig};
use mibee_fingerprints::Evidence;

use crate::center::Reporter;
use crate::discovery::in_cidr;
use crate::engine::orchestrator::ScanEngine;
use crate::wire::ReportedHost;

/// What one decoded event translates into. Both legs are optional: presence
/// sightings report hosts, signatures observe evidence, malformed or
/// off-network events do neither.
pub struct Routing {
    /// (ip, mac) to report as a passive host sighting — set once per IP on
    /// its first lifetime ARP sighting.
    pub report_host: Option<(String, String)>,
    /// Seed evidence for the host's next scan.
    pub observe: Option<Evidence>,
}

/// The pure per-event decision (unit-tested): off-network gate, presence
/// split, once-per-IP host reporting, evidence shaping.
pub fn route(ev: &Event, cidr: &Option<ipnet::Ipv4Net>, seen: &mut HashSet<String>) -> Routing {
    if ev.is_presence() {
        // ND carries no IPv4 (MAC-keyed channel pending, #522); ARP needs
        // both fields to be a host sighting. Same drop as the center.
        if ev.kind != Some(Kind::ArpSighting) || ev.ip.is_empty() || ev.mac.is_empty() {
            return Routing {
                report_host: None,
                observe: None,
            };
        }
        if !in_cidr(&ev.ip, cidr) {
            return Routing {
                report_host: None,
                observe: None,
            };
        }
        // The MAC is a hard on-wire fact from the sender itself — seed it
        // for the next scan's L2 probes (arp_cache source parity).
        let evidence = Evidence {
            source: "passive:ebpf:tc".into(),
            kind: "mac".into(),
            ip: ev.ip.clone(),
            protocol: "arp".into(),
            confidence: Kind::ArpSighting.confidence(),
            raw_data: Some(BTreeMap::from([("mac".to_string(), ev.mac.clone())])),
            ..Default::default()
        };
        let report = if seen.insert(format!("ebpf_arp:{}", ev.ip)) {
            Some((ev.ip.clone(), ev.mac.clone()))
        } else {
            None
        };
        Routing {
            report_host: report,
            observe: Some(evidence),
        }
    } else {
        if ev.ip.is_empty() {
            return Routing {
                report_host: None,
                observe: None,
            };
        }
        if !in_cidr(&ev.ip, cidr) {
            return Routing {
                report_host: None,
                observe: None,
            };
        }
        Routing {
            report_host: None,
            observe: Some(to_evidence(ev)),
        }
    }
}

/// Shape a signature event as Evidence — field-for-field the Go decoder's
/// tail: raw-data keys, service_hint, confidence weighting. DHCP's
/// vendor-class rides the server slot; `server` is only set for the kinds
/// that mean a server string.
pub fn to_evidence(ev: &Event) -> Evidence {
    let Some(kind) = ev.kind else {
        return Evidence::default();
    };
    let mut raw = BTreeMap::new();
    if !ev.server.is_empty() && kind != Kind::Dhcp && kind != Kind::NdSighting {
        raw.insert("server".to_string(), ev.server.clone());
    }
    match kind {
        Kind::Dhcp => {
            if !ev.server.is_empty() {
                raw.insert("vendor_class".to_string(), ev.server.clone());
            }
            if !ev.opt55.is_empty() {
                raw.insert("opt55".to_string(), ev.opt55.clone());
            }
            if ev.msg_type > 0 {
                raw.insert("msg_type".to_string(), ev.msg_type.to_string());
            }
        }
        Kind::TlsSni => {
            if !ev.server.is_empty() {
                raw.insert("sni".to_string(), ev.server.clone());
            }
        }
        Kind::Mdns => {
            if !ev.query.is_empty() {
                raw.insert("query".to_string(), ev.query.clone());
            }
        }
        Kind::ArpSighting => {
            raw.insert("mac".to_string(), ev.mac.clone());
            raw.insert(
                "op".to_string(),
                if ev.op_is_request { "request" } else { "reply" }.to_string(),
            );
        }
        Kind::NdSighting => {
            raw.insert("mac".to_string(), ev.mac.clone());
            raw.insert("ipv6".to_string(), ev.ipv6.clone());
            raw.insert("icmp6_type".to_string(), ev.icmp6_type.to_string());
        }
        _ => {}
    }
    raw.insert("service_hint".to_string(), kind.service_hint().to_string());
    Evidence {
        source: "passive:ebpf:tc".into(),
        kind: kind.evidence_kind().into(),
        ip: ev.ip.clone(),
        port: ev.port as i64,
        protocol: ev.protocol.clone(),
        confidence: kind.confidence(),
        raw_data: Some(raw),
        ..Default::default()
    }
}

/// Spawn the observer and apply [`route`] to every event until shutdown.
/// Called from main's task set; returns early (one warn line) when the
/// observer cannot start — a degradation, never a failure.
pub async fn run(
    engine: Arc<ScanEngine>,
    reporter: Arc<Reporter>,
    cidr: Option<ipnet::Ipv4Net>,
    interfaces: Vec<String>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let handle = tokio::runtime::Handle::current();
    let seen = Arc::new(Mutex::new(HashSet::<String>::new()));
    // MIBEE_EBPF_DEBUG=1: log every routing decision (field diagnostics).
    let debug = std::env::var("MIBEE_EBPF_DEBUG").is_ok_and(|v| v != "0" && v != "false");
    let sink = {
        let handle = handle.clone();
        let seen = Arc::clone(&seen);
        let engine = Arc::clone(&engine);
        let reporter = Arc::clone(&reporter);
        let cidr = cidr.clone();
        Arc::new(move |ev: Event| {
            let handle = handle.clone();
            let seen = Arc::clone(&seen);
            let engine = Arc::clone(&engine);
            let reporter = Arc::clone(&reporter);
            let cidr = cidr.clone();
            let debug = debug;
            handle.spawn(async move {
                let routing = {
                    let Ok(mut seen) = seen.lock() else { return };
                    route(&ev, &cidr, &mut seen)
                };
                if debug {
                    eprintln!(
                        "ebpf: debug kind={:?} ip={} -> report={} observe={}",
                        ev.kind,
                        ev.ip,
                        routing.report_host.is_some(),
                        routing.observe.is_some()
                    );
                }
                if let Some((ip, mac)) = routing.report_host {
                    reporter
                        .report_passive(ReportedHost {
                            ip,
                            alive: true,
                            mac,
                            ..Default::default()
                        })
                        .await;
                }
                if let Some(evidence) = routing.observe {
                    let ip = evidence.ip.clone();
                    engine.observe(&ip, vec![evidence]).await;
                }
            });
        })
    };
    let mut observer = match Observer::start(ObserverConfig { interfaces }, sink) {
        Ok(o) => o,
        Err(reason) => {
            eprintln!("ebpf: passive observer inactive ({reason}); active probing unaffected");
            return;
        }
    };
    // Hold the observer until shutdown; the sink tasks carry the routing.
    while stop.changed().await.is_ok() {
        if *stop.borrow() {
            break;
        }
    }
    observer.stop();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp(ip: &str, mac: &str) -> Event {
        Event {
            kind: Some(Kind::ArpSighting),
            ip: ip.into(),
            protocol: "arp".into(),
            mac: mac.into(),
            op_is_request: true,
            ..Default::default()
        }
    }

    fn dhcp(ip: &str) -> Event {
        Event {
            kind: Some(Kind::Dhcp),
            ip: ip.into(),
            port: 68,
            protocol: "udp".into(),
            server: "android-dhcp-13".into(),
            opt55: "1,33,3,6".into(),
            msg_type: 1,
            ..Default::default()
        }
    }

    #[test]
    fn arp_sighting_reports_host_once_and_seeds_mac() {
        let cidr = Some("192.0.2.0/24".parse().unwrap());
        let mut seen = HashSet::new();
        let r = route(&arp("192.0.2.50", "aa:bb:cc:dd:ee:50"), &cidr, &mut seen);
        assert_eq!(
            r.report_host,
            Some(("192.0.2.50".into(), "aa:bb:cc:dd:ee:50".into()))
        );
        let ev = r.observe.expect("mac seed");
        assert_eq!(ev.kind, "mac");
        assert_eq!(ev.raw_data.as_ref().unwrap()["mac"], "aa:bb:cc:dd:ee:50");
        assert_eq!(ev.confidence, 0.8);
        // second sighting of the same IP: seed yes, host report no
        let r = route(&arp("192.0.2.50", "aa:bb:cc:dd:ee:50"), &cidr, &mut seen);
        assert!(r.report_host.is_none());
        assert!(r.observe.is_some());
    }

    #[test]
    fn arp_off_network_and_nd_are_dropped() {
        let cidr = Some("192.0.2.0/24".parse().unwrap());
        let mut seen = HashSet::new();
        let r = route(&arp("198.51.100.9", "aa:bb:cc:dd:ee:ff"), &cidr, &mut seen);
        assert!(r.report_host.is_none() && r.observe.is_none());
        // ND: no IPv4 (MAC-keyed channel is #522) — same drop as the center
        let nd = Event {
            kind: Some(Kind::NdSighting),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ipv6: "fe80::1".into(),
            icmp6_type: 135,
            ..Default::default()
        };
        let r = route(&nd, &cidr, &mut seen);
        assert!(r.report_host.is_none() && r.observe.is_none());
        // no cidr configured: degrade-open (boundary guard parity)
        let r = route(&arp("198.51.100.9", "aa:bb:cc:dd:ee:ff"), &None, &mut seen);
        assert!(r.report_host.is_some());
    }

    #[test]
    fn signature_events_observe_evidence_only() {
        let cidr = Some("192.0.2.0/24".parse().unwrap());
        let mut seen = HashSet::new();
        let r = route(&dhcp("192.0.2.60"), &cidr, &mut seen);
        assert!(r.report_host.is_none());
        let ev = r.observe.expect("evidence");
        assert_eq!(ev.source, "passive:ebpf:tc");
        assert_eq!(ev.kind, "dhcp");
        assert_eq!(ev.port, 68);
        assert_eq!(ev.confidence, 0.8);
        // empty-IP signature (zeroed capture) drops
        let r = route(&dhcp(""), &cidr, &mut seen);
        assert!(r.observe.is_none());
    }

    /// The android vendor-class seed must classify into a dhcp identity with
    /// the REAL corpus — the rig end-to-end expectation, pinned locally so a
    /// corpus/shape drift cannot silently break the passive channel.
    #[test]
    fn dhcp_seed_classifies_with_the_corpus() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../configs/fingerprints");
        if !std::path::Path::new(dir).exists() {
            eprintln!("skipped: {dir} not present (standalone checkout)");
            return;
        }
        let mut c = mibee_fingerprints::RuleClassifier::new();
        c.load_from_dir(dir).expect("corpus loads");
        let idents = c.classify(&[to_evidence(&dhcp("192.0.2.60"))]);
        assert!(
            idents.iter().any(|i| i.service == "dhcp"),
            "dhcp identity expected, got {idents:?}"
        );
    }

    /// Raw-data key parity with the Go decoder's tail.
    #[test]
    fn evidence_raw_keys_match_go() {
        let ev = to_evidence(&dhcp("192.0.2.60"));
        let raw = ev.raw_data.unwrap();
        assert_eq!(raw["vendor_class"], "android-dhcp-13");
        assert_eq!(raw["opt55"], "1,33,3,6");
        assert_eq!(raw["msg_type"], "1");
        assert!(
            !raw.contains_key("server"),
            "dhcp never carries the server key"
        );

        let sni = to_evidence(&Event {
            kind: Some(Kind::TlsSni),
            ip: "192.0.2.61".into(),
            port: 443,
            protocol: "tcp".into(),
            server: "api.example.net".into(),
            ..Default::default()
        });
        let raw = sni.raw_data.unwrap();
        assert_eq!(raw["server"], "api.example.net");
        assert_eq!(raw["sni"], "api.example.net");
        assert_eq!(raw["service_hint"], "https");
        assert_eq!(sni.confidence, 0.7);

        let mut arp_ev = arp("192.0.2.62", "aa:bb:cc:dd:ee:62");
        arp_ev.op_is_request = false;
        let raw = to_evidence(&arp_ev).raw_data.unwrap();
        assert_eq!(raw["op"], "reply");
    }
}
