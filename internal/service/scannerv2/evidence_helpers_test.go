// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package scannerv2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSCertCollected_Service(t *testing.T) {
	require.Equal(t, "https", TLSCertCollected{ServiceName: "https"}.Service())
	require.Equal(t, "ldaps", TLSCertCollected{ServiceName: "ldaps"}.Service())
}

func TestIsValidSNMPSecurityLevel(t *testing.T) {
	for _, lvl := range ValidSNMPSecurityLevels {
		require.True(t, IsValidSNMPSecurityLevel(lvl), lvl)
	}
	require.False(t, IsValidSNMPSecurityLevel("warp"))
	require.False(t, IsValidSNMPSecurityLevel(""))
}
