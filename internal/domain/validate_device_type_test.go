// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package domain

import "testing"

// TestValidateDeviceType covers the device-type allow-list normalizer. These
// cases previously lived in internal/service/scanner_test.go (misplaced — they
// test a domain function, not a service); moved here alongside the code under
// test when the empty internal/service/scanner.go stub was removed (#132).
func TestValidateDeviceType_Valid(t *testing.T) {
	for _, in := range []string{"pc", "embedded", "iot", "other"} {
		if got := ValidateDeviceType(in); got != in {
			t.Errorf("ValidateDeviceType(%q) = %q, want %q", in, got, in)
		}
	}
}

func TestValidateDeviceType_Invalid(t *testing.T) {
	for _, in := range []string{"unknown", "", "PC"} {
		if got := ValidateDeviceType(in); got != "other" {
			t.Errorf("ValidateDeviceType(%q) = %q, want \"other\"", in, got)
		}
	}
}
