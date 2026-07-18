// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package ebpf hosts the passive ProbeSource implementation backed by a TC
// (Traffic Control) ingress eBPF program. It is the "passive observer" half of
// the Probe layer, complementary to the active probes in package probe.
//
// Two build configurations:
//
//   - Default (no build tag): observer_stub.go provides a no-op PassiveObserver
//     that reports "eBPF disabled". The default `make build` therefore needs no
//     kernel headers, clang, or root, and cross-compiles cleanly.
//
//   - WITH_EBPF tag: observer_real.go links a cilium/ebpf loader that attaches
//     the compiled TC program (bpf/tc_ingress.o, embedded) to configured
//     network interfaces and drains a ring buffer of observed protocol bytes
//     into Evidence. Built via `make build-with-ebpf`.
//
// The Probe interface is identical in both configurations — the orchestrator
// is unaware of which one is active.
package ebpf

import "mibee-steward/internal/service/scannerv2"

// Config controls the passive observer.
type Config struct {
	// Enabled gates whether the observer does anything. Even in the WITH_EBPF
	// build, a disabled flag short-circuits to no-op (useful for environments
	// lacking CAP_BPF/CAP_NET_ADMIN).
	Enabled bool
	// Interfaces are the network interface names to attach the TC program to
	// (e.g. ["eth0", "br-lan"]). When empty and Enabled, attaches to all
	// non-loopback interfaces.
	Interfaces []string
}

// Observer is the PassiveObserver ProbeSource. The concrete behavior depends
// on the build tag (stub vs real). Both satisfy scannerv2.ProbeSource so the
// orchestrator treats eBPF evidence uniformly with active-probe evidence.
type Observer struct {
	cfg Config
}

// New returns an Observer with the given config.
func New(cfg Config) *Observer {
	return &Observer{cfg: cfg}
}

// Compile-time assertion that *Observer is a ProbeSource regardless of build.
var _ scannerv2.ProbeSource = (*Observer)(nil)
