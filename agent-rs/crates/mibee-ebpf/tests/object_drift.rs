//! The embedded kernel object must stay byte-identical to the copy the Go
//! center embeds (`internal/service/scannerv2/ebpf/tcingress_bpfel.o`, the
//! bpf2go output of `bpf/tc_ingress.c`). One field-verified verifier
//! artifact, two loaders — that is the whole parity story of #498, so drift
//! between the two copies is a CI failure (`make check-agent-rs-assets`
//! guards the same invariant from the Makefile side).
//!
//! When the canonical file is not present (a standalone agent-rs checkout
//! without the surrounding Go repo) the test skips: the Makefile guard owns
//! the check where both trees exist.

use std::path::PathBuf;

#[test]
fn embedded_object_matches_the_center_copy() {
    let canonical: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../internal/service/scannerv2/ebpf/tcingress_bpfel.o");
    if !canonical.exists() {
        eprintln!("skipped: {canonical:?} not present (standalone checkout)");
        return;
    }
    let center = std::fs::read(&canonical).expect("read canonical object");
    let embedded = include_bytes!("../ebpf/tc_ingress.bpfel.o");
    assert_eq!(
        embedded.len(),
        center.len(),
        "embedded object size drifted from the center copy"
    );
    assert_eq!(
        &embedded[..],
        &center[..],
        "embedded object bytes drifted from the center copy — run make sync-agent-rs-assets"
    );
}
