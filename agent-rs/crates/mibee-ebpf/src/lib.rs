//! Passive eBPF observer for the Rust agent (#498): the agent-side twin of
//! the center's TC observer (`internal/service/scannerv2/ebpf`, issues
//! #493/#496/#497/#508).
//!
//! The kernel-side program is SHARED, not rewritten: `ebpf/tc_ingress.bpfel.o`
//! is a byte-for-byte copy of the object the Go center embeds (built from
//! `bpf/tc_ingress.c` via `make sync-agent-rs-assets`; a drift test pins the
//! copies together). Parity of the ten signature kinds and the ARP/ND presence
//! semantics is therefore by construction — one field-verified verifier
//! artifact, two loaders.
//!
//! Layers:
//!
//! - [`event`] — decodes the 124-byte ring-buffer records. Byte-exact port of
//!   the Go decoder; pure, dependency-free, unit-tested on every platform.
//! - [`capability`] — the prerequisite probe + degradation verdict (kernel
//!   ≥ 5.8, root or CAP_BPF + CAP_NET_ADMIN, BTF optional). Pure parsers are
//!   unit-tested everywhere; every failure mode degrades the observer, it
//!   never crashes the agent and never blocks active probing.
//! - [`observer`] — the aya loader/attacher/drain loop behind
//!   `feature = "loader"` AND `target_os = "linux"`. Absent elsewhere by
//!   compile-time design, which is what keeps default builds byte-identical.

pub mod capability;
pub mod event;

#[cfg(all(target_os = "linux", feature = "loader"))]
pub mod observer;
