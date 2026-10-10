// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build !WITH_EBPF

// Default build: no eBPF. The Observer is a no-op ProbeSource that contributes
// no evidence. This keeps the default binary free of kernel/BTF/clang
// dependencies and runnable unprivileged on any platform.
//
// To enable the real eBPF observer, build with the WITH_EBPF tag
// (see Makefile target build-with-ebpf and bpf/README.md).

package ebpf

import (
	"context"
	"log/slog"

	"mibee-steward/internal/service/scannerv2"
)

// BuiltWithEBPF reports that this binary has no eBPF loader compiled in.
// Doctor uses it to distinguish "feature turned off" from "feature not
// compiled in".
func BuiltWithEBPF() bool { return false }

// SetHostSighting is the stub-build no-op of the ARP/ND presence sink binding
// (see observer_real.go): without the loader there are no ring-buffer events,
// so there is nothing to route.
func SetHostSighting(func(ip, mac string)) {}

func (o *Observer) Name() string { return "passive:ebpf:tc" }

func (o *Observer) statusSnapshot() Status {
	if !o.cfg.Enabled {
		return Status{State: StateDisabled, Reason: "scanner.ebpf.enabled is false"}
	}
	return Status{State: StateNotBuilt, Reason: "binary built without the WITH_EBPF tag (see make build-with-ebpf)"}
}

// Probe returns no evidence in the stub build. If Enabled was requested but
// the binary lacks eBPF support, it logs a one-time warning so operators know
// passive detection is unavailable (rather than silently absent).
func (o *Observer) Probe(_ context.Context, _ string, _ scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	if o.cfg.Enabled {
		// Log at debug to avoid spamming; the startup banner in NewEngine (Phase 5)
		// logs the build configuration once at info level.
		slog.Debug("eBPF passive observer requested but binary built without WITH_EBPF tag; no-op",
			"interfaces", o.cfg.Interfaces)
	}
	return nil, nil
}
