// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//go:build WITH_LLDP

package discovery

import "testing"

// The positive side of the #502 introspection: run with
// `go test -tags WITH_LLDP ./internal/service/scannerv2/discovery/`.
func TestBuiltWithLLDPTag(t *testing.T) {
	if !BuiltWithLLDP() {
		t.Fatal("BuiltWithLLDP() = false in a WITH_LLDP build")
	}
}
