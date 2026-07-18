// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build !WITH_LLDP

// Stub build (default): no raw-frame LLDP listener. The real implementation
// (lldp_frame_real.go, build tag WITH_LLDP) requires AF_PACKET raw sockets
// (CAP_NET_RAW) to capture ethertype 0x88cc frames, which would break the
// project's unprivileged deployment model. Build with -tags WITH_LLDP to
// enable it. This mirror's the eBPF observer's build-tag pattern.

package discovery

import (
	"context"
	"log/slog"
)

// LLDPFrameSource is nil in the default build — NewLLDPFrameSource returns nil,
// and the caller skips registration. See lldp_frame_real.go (WITH_LLDP) for the
// real listener.
type LLDPFrameSource struct{}

// NewLLDPFrameSource returns nil in the default (no-WITH_LLDP) build, signaling
// to the caller that raw-frame LLDP listening is unavailable. interfaces is the
// list of NIC names to listen on (empty = all). svc is the discovery
// coordinator (for host events); neighborSink receives neighbor edges.
func NewLLDPFrameSource(_ []string, _ *Service, _ func(localMAC string, neighbors []lldpEdge), logger *slog.Logger) *LLDPFrameSource {
	if logger != nil {
		logger.Info("lldp_frame source disabled (build without WITH_LLDP)")
	}
	return nil
}

// Start is unreachable (NewLLDPFrameSource returns nil in this build). Present
// for the type signature so the real/stub files share the same call surface.
func (s *LLDPFrameSource) Start(_ context.Context) {}

// Name satisfies the naming convention used in activeSources logging.
func (s *LLDPFrameSource) Name() string { return "lldp_frame" }
