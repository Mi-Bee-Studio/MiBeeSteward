// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package probe

import "testing"

// Coverage-headroom pin (#697) for the USN fetch cooldown: a USN may be
// fetched once per cooldown window, an empty USN bypasses the cache key
// (nothing to key on), and the test USNs use unique prefixes so the global
// cooldown map cannot leak into other tests.
func TestUSNCooldownAllows(t *testing.T) {
	usn := "uuid:test-cooldown-687::upnp:InternetGatewayDevice"

	if !usnCooldownAllows(usn) {
		t.Fatalf("first fetch for %q must be allowed", usn)
	}
	if usnCooldownAllows(usn) {
		t.Errorf("second fetch within the cooldown window must be refused")
	}

	// Empty USN always allowed (no key to cooldown on).
	for i := 0; i < 3; i++ {
		if !usnCooldownAllows("") {
			t.Fatalf("empty USN fetch #%d must be allowed", i+1)
		}
	}

	// A different USN is unaffected by the first one's window.
	if !usnCooldownAllows("uuid:test-cooldown-687-other") {
		t.Errorf("a distinct USN must have its own cooldown window")
	}
}
