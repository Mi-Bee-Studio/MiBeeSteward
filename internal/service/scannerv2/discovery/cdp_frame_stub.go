// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build !WITH_CDP

// Stub build (default): no raw-frame CDP listener. The real implementation
// (cdp_frame_real.go, build tag WITH_CDP) requires AF_PACKET raw sockets
// (CAP_NET_RAW) to capture ethertype 0x2000 frames, which would break the
// project's unprivileged deployment model. Build with -tags WITH_CDP to
// enable it. This mirrors the LLDP frame listener's build-tag pattern.

package discovery

import (
	"context"
	"log/slog"
)

// CDPFrameSource is nil in the default build — NewCDPFrameSource returns nil,
// and the caller skips registration. See cdp_frame_real.go (WITH_CDP) for the
// real listener.
type CDPFrameSource struct{}

// NewCDPFrameSource returns nil in the default (no-WITH_CDP) build, signaling
// to the caller that raw-frame CDP listening is unavailable. interfaces is the
// list of NIC names to listen on (empty = all). svc is the discovery
// coordinator (for host events); neighborSink receives neighbor edges.
func NewCDPFrameSource(_ []string, _ *Service, _ func(localMAC string, neighbors []cdpEdge), logger *slog.Logger) *CDPFrameSource {
	if logger != nil {
		logger.Info("cdp_frame source disabled (build without WITH_CDP)")
	}
	return nil
}

// Start is unreachable (NewCDPFrameSource returns nil in this build). Present
// for the type signature so the real/stub files share the same call surface.
func (s *CDPFrameSource) Start(_ context.Context) {}

// Name satisfies the naming convention used in activeSources logging.
func (s *CDPFrameSource) Name() string { return "cdp_frame" }
