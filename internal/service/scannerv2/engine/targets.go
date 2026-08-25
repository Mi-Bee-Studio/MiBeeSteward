// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package engine

import (
	"mibee-steward/internal/cidrutil"
)

// Sentinel errors for target parsing. Callers (e.g. the scanner handler) use
// errors.Is against these to distinguish user-supplied-bad-targets (HTTP 400)
// from internal failures, rather than brittle string matching on error text.
//
// They alias the cidrutil sentinels: target expansion/validation lives in
// cidrutil (the leaf package the agent command/report paths also share), and
// parseScanTargets delegates there — one canonical implementation instead of
// the two mirrored copies this package used to keep in sync via a parity test.
var (
	ErrEmptyTargets         = cidrutil.ErrEmptyTargets
	ErrNoValidTargets       = cidrutil.ErrNoValidTargets
	ErrInvalidTarget        = cidrutil.ErrInvalidTarget
	ErrInvalidIPRange       = cidrutil.ErrInvalidIPRange
	ErrIPv6RangeUnsupported = cidrutil.ErrIPv6RangeUnsupported
	ErrTargetRangeTooLarge  = cidrutil.ErrTargetRangeTooLarge
	ErrReservedTarget       = cidrutil.ErrReservedTarget
)

// ParseScanTargets is the exported form of parseScanTargets for callers
// outside this package. A thin alias; the canonical implementation is
// cidrutil.ExpandTargets.
func ParseScanTargets(targets string) ([]string, error) {
	return parseScanTargets(targets)
}

// parseScanTargets expands a target spec into a list of IP strings.
// Supported formats (single or comma-separated):
//   - CIDR: "192.168.1.0/24" (network + broadcast addresses are skipped)
//   - single IP: "192.168.1.5"
//   - IP range: "192.168.1.1-192.168.1.10" or "192.168.1.1-10"
//
// Specs pointing at reserved address space (loopback, unspecified,
// link-local, multicast, limited broadcast, 240/4) are rejected with
// ErrReservedTarget — see cidrutil.ValidateTargets (#317/#254).
func parseScanTargets(targets string) ([]string, error) {
	return cidrutil.ExpandTargets(targets)
}

// expandTargets applies this engine instance's scanner.allow_reserved_targets
// policy to the canonical expansion. Scan execution paths (sync scan, task
// runs) go through here so the escape hatch works end-to-end.
func (e *Engine) expandTargets(targets string) ([]string, error) {
	return cidrutil.ExpandTargetsFor(targets, e.allowReservedTargets)
}

// AllowReservedTargets reports whether the scanner.allow_reserved_targets
// escape hatch is enabled. Entry-point handlers use it to keep their
// validation consistent with what the engine will actually accept.
func (e *Engine) AllowReservedTargets() bool {
	return e.allowReservedTargets
}
