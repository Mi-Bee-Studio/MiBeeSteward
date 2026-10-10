// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//go:build WITH_ARPSCAN

package discovery

import "testing"

// Run with `go test -tags WITH_ARPSCAN ./internal/service/scannerv2/discovery/`.
func TestBuiltWithARPSCANTag(t *testing.T) {
	if !BuiltWithARPSCAN() {
		t.Fatal("BuiltWithARPSCAN() = false in a WITH_ARPSCAN build")
	}
}
