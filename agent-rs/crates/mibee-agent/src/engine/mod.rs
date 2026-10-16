//! Scan engine: target expansion, OUI vendor table, device-type heuristics,
//! probes, orchestrator fold, and report building. Behavior ports the Go
//! scannerv2 engine as used by cmd/agent.

pub mod arp_star;
pub mod device_types;
pub mod dns;
pub mod identify;
pub mod orchestrator;
pub mod ports;
pub mod probes;
pub mod oui;
pub mod targets;

pub const EMBEDDED_DEVICE_TYPES: &str = include_str!("../../assets/device_types.yaml");

/// Web-server brand denylist, synced from configs/fingerprints/
/// web-server-brands.txt (same source the Go center embeds) — one shared
/// list, so the two stacks can never disagree.
pub const EMBEDDED_WEB_SERVER_BRANDS: &str = include_str!("../../assets/web_server_brands.txt");

/// Go fuseConfidence (1 - (1-a)(1-b), clamped, capped).
pub fn fuse_confidence(a: f64, b: f64) -> f64 {
    mibee_fingerprints::fuse_confidence(a, b)
}
