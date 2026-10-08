//! Probe sources. Each probe gathers evidence for one target IP; the
//! orchestrator runs all probes concurrently and merges results in
//! probe-name-sorted order (Go registry order).

pub mod arp;
pub mod http;
pub mod icmp;
pub mod mdns;
pub mod netbios;
pub mod rdns;
pub mod simple;
pub mod smb;
pub mod l2_mib;
pub mod snmp;
pub mod snmp_arp;
pub mod snmp_v3;
pub mod ssdp;
pub mod tcp;
pub mod tls;

use std::net::IpAddr;
use std::time::Duration;

pub use mibee_fingerprints::Evidence;

use crate::engine::oui::Oui;

/// Per-scan shared configuration (Go probe.ProbeHint). The router-ARP list
/// is NOT here: no Go probe consumes it (cross-subnet MAC resolution is an
/// engine-level post-gather step, see orchestrator + probes/snmp_arp).
#[derive(Clone)]
pub struct ProbeHint {
    pub timeout: Duration,
    pub community: String,
    pub port_spec: Vec<u16>,
    /// UDP port for SNMP probes (Go hardcodes 161; a hint field lets the
    /// engine-level tests point probes at a scripted agent).
    pub snmp_port: u16,
    pub rdns_servers: Vec<String>,
    pub oui: std::sync::Arc<Oui>,
    /// SNMPv3 credential (name/id-resolved before the scan); None = community.
    pub snmp_v3: Option<SnmpV3Credential>,
    /// A bound v1v2c credential's community wins over the global default
    /// (Go dialSNMPReal: cred.Community beats hint.Community).
    pub community_override: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SnmpV3Credential {
    pub username: String,
    pub security_level: String, // noAuthNoPriv | authNoPriv | authPriv
    pub auth_protocol: String,  // MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
    pub auth_passphrase: String,
    pub priv_protocol: String,  // DES | AES | AES192 | AES256 | AES192C | AES256C
    pub priv_passphrase: String,
}

/// Dyn-compatible probe trait: `probe` returns a boxed future (async fn in
/// traits are not object-safe).
pub trait Probe: Send + Sync {
    /// Registry name; evidence merge order sorts on this (Go parity).
    fn name(&self) -> &'static str;
    fn probe<'a>(
        &'a self,
        ip: IpAddr,
        hint: &'a ProbeHint,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Evidence>> + Send + 'a>>;
}

/// Helper for implementing Probe::probe with an async block; the closure
/// parameters become the method parameters (correct lifetimes for boxing).
macro_rules! probe_impl {
    ($ty:ty, $name:expr, |$ip:ident: IpAddr, $hint:ident: &ProbeHint| async move $body:block) => {
        impl Probe for $ty {
            fn name(&self) -> &'static str {
                $name
            }
            fn probe<'a>(
                &'a self,
                $ip: IpAddr,
                $hint: &'a ProbeHint,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Evidence>> + Send + 'a>> {
                Box::pin(async move $body)
            }
        }
    };
}
pub(crate) use probe_impl;

/// Default registry: name-sorted (Go probe/registry.go DefaultProbeSources).
pub fn default_probes() -> Vec<Box<dyn Probe>> {
    let mut probes: Vec<Box<dyn Probe>> = vec![
        Box::new(arp::ArpProbe),
        Box::new(http::HttpProbe),
        Box::new(simple::MetricsProbe),
        Box::new(icmp::IcmpProbe),
        Box::new(mdns::MdnsProbe),
        Box::new(netbios::NetbiosProbe),
        Box::new(simple::OnvifProbe),
        Box::new(l2_mib::BridgeMibProbe),
        Box::new(l2_mib::CdpMibProbe),
        Box::new(l2_mib::LldpMibProbe),
        Box::new(l2_mib::QBridgeMibProbe),
        Box::new(l2_mib::StpMibProbe),
        Box::new(rdns::RdnsProbe),
        Box::new(simple::RtspProbe),
        Box::new(snmp::SnmpProbe),
        Box::new(smb::SmbProbe),
        Box::new(ssdp::SsdpProbe),
        Box::new(tcp::TcpPortsProbe),
        Box::new(tls::TlsProbe),
    ];
    probes.sort_by_key(|p| p.name());
    probes
}

/// Helper: evidence with common fields filled.
pub(crate) fn ev(source: &str, kind: &str, ip: IpAddr, conf: f64) -> Evidence {
    Evidence {
        source: source.to_string(),
        kind: kind.to_string(),
        ip: ip.to_string(),
        confidence: conf,
        ..Default::default()
    }
}

/// Unprivileged ICMP datagram ping (linux; None elsewhere).
pub async fn datagram_ping(ip: std::net::IpAddr, timeout: std::time::Duration) -> Option<()> {
    #[cfg(target_os = "linux")]
    {
        icmp::datagram_ping_once(ip, timeout).await.map(|_| ())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ip, timeout);
        None
    }
}

/// TLS handshake returning cert fields (+ negotiated version as _version).
pub async fn tls_cert_probe(
    host: &str,
    port: u16,
    timeout: std::time::Duration,
) -> Option<std::collections::BTreeMap<String, String>> {
    tls::cert_probe(host, port, timeout).await
}
