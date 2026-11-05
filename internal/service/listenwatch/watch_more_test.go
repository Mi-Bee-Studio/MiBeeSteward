// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package listenwatch

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Coverage-headroom pin (#697) for the tiny helper: always returns a pointer
// to a copy (the JSON emit path marshals either way).
func TestStrPtr(t *testing.T) {
	p := strPtr("x")
	require.NotNil(t, p)
	require.Equal(t, "x", *p)
	require.NotNil(t, strPtr(""))
}
