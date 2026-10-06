//! Scan engine: target expansion, OUI vendor table, device-type heuristics,
//! probes, orchestrator fold, and report building. Behavior ports the Go
//! scannerv2 engine as used by cmd/agent.

pub mod device_types;
pub mod dns;
pub mod identify;
pub mod orchestrator;
pub mod ports;
pub mod probes;
pub mod oui;
pub mod targets;

pub const EMBEDDED_DEVICE_TYPES: &str = include_str!("../../assets/device_types.yaml");

/// Go fuseConfidence (1 - (1-a)(1-b), clamped, capped).
pub fn fuse_confidence(a: f64, b: f64) -> f64 {
    mibee_fingerprints::fuse_confidence(a, b)
}
