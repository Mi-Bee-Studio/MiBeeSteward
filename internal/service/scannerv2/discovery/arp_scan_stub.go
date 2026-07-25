// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build !WITH_ARPSCAN

// Default (no-op) build of the ARP-scan discovery source. The real implementation
// (arp_scan_real.go, build tag WITH_ARPSCAN) sends ARP who-has requests for every
// IP in the local subnet via an AF_PACKET raw socket and emits a NewHostEvent for
// each reply — covering the whole broadcast domain without router access. It
// needs CAP_NET_RAW, so it is build-tag-gated exactly like the LLDP/CDP frame
// sources: the default binary stays unprivileged and NewARPScanSource returns nil.
// Callers (routes.go) guard with `if src := NewARPScanSource(...); src != nil`.

package discovery

import (
	"context"
	"log/slog"
	"time"
)

// ARPScanSource is the no-op stub. The real type (arp_scan_real.go) holds the
// AF_PACKET socket, interface, and sweep state; here it carries nothing because
// the constructor always returns nil.
type ARPScanSource struct{}

// NewARPScanSource returns nil in default builds (the real implementation needs
// CAP_NET_RAW + the WITH_ARPSCAN build tag). interval/cidr/iface are accepted so
// the call site is identical across builds.
func NewARPScanSource(cidr string, interval time.Duration, iface string, svc *Service, logger *slog.Logger) *ARPScanSource {
	_ = cidr
	_ = interval
	_ = iface
	_ = svc
	_ = logger
	return nil
}

// Start is a no-op on the stub. It exists only so the caller's `src.Start(ctx)`
// compiles without a nil-check when src is the stub type; in default builds the
// caller never reaches here (NewARPScanSource returned nil and was skipped).
func (s *ARPScanSource) Start(ctx context.Context) { _ = ctx }
