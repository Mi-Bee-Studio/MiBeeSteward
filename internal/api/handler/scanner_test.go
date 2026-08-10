// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"errors"
	"fmt"
	"testing"

	"mibee-steward/internal/service/scannerv2/engine"
)

// TestIsTargetError verifies the handler's isTargetError classifier recognizes
// every engine target-parse sentinel (even when wrapped with extra detail via
// fmt.Errorf("%w")) and rejects unrelated errors. This is the behavior the
// /scanner/scan + /scanner/scan (ScanTargets) error paths rely on to map
// bad-target errors to HTTP 400 rather than 500.
func TestIsTargetError(t *testing.T) {
	targetSentinels := []error{
		engine.ErrEmptyTargets,
		engine.ErrNoValidTargets,
		engine.ErrInvalidTarget,
		engine.ErrInvalidIPRange,
		engine.ErrIPv6RangeUnsupported,
		engine.ErrTargetRangeTooLarge,
	}
	for _, sentinel := range targetSentinels {
		// Direct sentinel.
		if !isTargetError(sentinel) {
			t.Errorf("isTargetError(%v) = false, want true for direct sentinel", sentinel)
		}
		// Wrapped sentinel with detail text — must still match via errors.Is.
		wrapped := fmt.Errorf("%w: some detail", sentinel)
		if !isTargetError(wrapped) {
			t.Errorf("isTargetError(wrapped %v) = false, want true", sentinel)
		}
		// errors.Is itself must resolve the wrap (sanity check of the %w wrapping).
		if !errors.Is(wrapped, sentinel) {
			t.Errorf("errors.Is(wrapped, %v) = false, want true (bad %%w wrap?)", sentinel)
		}
	}

	// Unrelated errors must NOT classify as target errors — otherwise a real
	// internal failure would be masked as a 400 "bad targets".
	if isTargetError(errors.New("scan failed: timeout")) {
		t.Errorf("isTargetError(generic error) = true, want false")
	}
	if isTargetError(nil) {
		t.Errorf("isTargetError(nil) = true, want false")
	}
}
