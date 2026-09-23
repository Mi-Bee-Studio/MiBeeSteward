// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDeviceConfig_DiffBranches pins the A/B diff contract: missing/bad ids →
// 400, unknown config → 404, and a real two-version diff renders.
func TestDeviceConfig_DiffBranches(t *testing.T) {
	h, _, dev1, _, cfgIDs := setupDeviceConfigHandler(t)

	diff := func(dev string, query string) int {
		req := reqWithURLParam(http.MethodGet, "/api/v1/devices/"+dev+"/configs/diff"+query, "", dev)
		w := httptest.NewRecorder()
		h.Diff(w, req)
		return w.Code
	}

	dev := strconv.FormatInt(dev1, 10)
	// Missing/bad a / b → 400.
	require.Equal(t, http.StatusBadRequest, diff(dev, ""))
	require.Equal(t, http.StatusBadRequest, diff(dev, "?a=abc&b=1"))
	require.Equal(t, http.StatusBadRequest, diff(dev, "?a=0&b=1"))
	require.Equal(t, http.StatusBadRequest, diff(dev, "?a=1&b=xyz"))
	// Unknown config id → 404.
	require.Equal(t, http.StatusNotFound, diff(dev, "?a=9999&b=8888"))
	// Bad device id → 400.
	require.Equal(t, http.StatusBadRequest, diff("abc", "?a=1&b=2"))

	// Real diff between the two seeded versions.
	if len(cfgIDs) >= 2 {
		require.Equal(t, http.StatusOK, diff(dev, "?a="+strconv.FormatInt(cfgIDs[0], 10)+"&b="+strconv.FormatInt(cfgIDs[len(cfgIDs)-1], 10)))
	}
}
