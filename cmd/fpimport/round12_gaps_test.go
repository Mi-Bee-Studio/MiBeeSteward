// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUsagePrints(t *testing.T) {
	require.NotPanics(t, func() { usage() })
}

func TestRecogPreferenceToConfidence(t *testing.T) {
	require.InDelta(t, 0.85, recogPreferenceToConfidence(""), 1e-9)
	require.InDelta(t, 0.9, recogPreferenceToConfidence("0.90"), 1e-9)
	require.InDelta(t, 0.2, recogPreferenceToConfidence("0.20"), 1e-9)
	require.InDelta(t, 1.0, recogPreferenceToConfidence("1.8"), 1e-9, "values >1 clamp")
	require.InDelta(t, 0.85, recogPreferenceToConfidence("bogus"), 1e-9)
	require.InDelta(t, 0.85, recogPreferenceToConfidence("-1"), 1e-9)
}

func TestIsDigits(t *testing.T) {
	require.True(t, isDigits("0123456789"))
	require.False(t, isDigits(""))
	require.False(t, isDigits("12a"))
	require.False(t, isDigits("1.5"))
}
