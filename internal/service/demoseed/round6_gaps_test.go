// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package demoseed

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCountJSON(t *testing.T) {
	require.JSONEq(t, `{"demo_devices":5}`, string(CountJSON(5)))
}

func TestFirstLine(t *testing.T) {
	require.Equal(t, "only", firstLine("only"))
	require.Equal(t, "first", firstLine("first\nsecond\nthird"))
	require.Equal(t, "", firstLine(""))
}
