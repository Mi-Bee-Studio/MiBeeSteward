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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParsePagination_Contract pins the #274 pagination policy shared by every
// list endpoint: unset/0 → endpoint default; malformed or negative → 400;
// over-max → clamped to max (never an error); offset negative → 400.
func TestParsePagination_Contract(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		wantLimit  int64
		wantOffset int64
		wantOK     bool
	}{
		{"absent → default", "", 20, 0, true},
		{"explicit within range", "limit=50&offset=40", 50, 40, true},
		{"zero means default", "limit=0", 20, 0, true},
		{"over max clamps", "limit=9999", 100, 0, true},
		{"negative limit 400s", "limit=-1", 0, 0, false},
		{"malformed limit 400s", "limit=abc", 0, 0, false},
		{"negative offset 400s", "offset=-5", 0, 0, false},
		{"malformed offset 400s", "offset=1.5", 0, 0, false},
		{"empty strings mean absent", "limit=&offset=", 20, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/thing?"+tc.query, nil)
			limit, offset, ok := ParsePagination(rec, req, 20, 100)
			require.Equal(t, tc.wantOK, ok)
			if !tc.wantOK {
				require.Equal(t, http.StatusBadRequest, rec.Code)
				var body map[string]string
				require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
				require.Contains(t, body, "error", "400 must use the standard error envelope")
				return
			}
			require.Equal(t, tc.wantLimit, limit)
			require.Equal(t, tc.wantOffset, offset)
		})
	}
}

// TestSuccessList_Envelope pins the #274 list envelope: resource-named array
// key + total + limit/offset echo of the EFFECTIVE pagination.
func TestSuccessList_Envelope(t *testing.T) {
	rec := httptest.NewRecorder()
	SuccessList(rec, "devices", []map[string]any{{"id": 1}}, 42, 20, 40)
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, 1, len(body["devices"].([]any)))
	require.Equal(t, float64(42), body["total"])
	require.Equal(t, float64(20), body["limit"])
	require.Equal(t, float64(40), body["offset"])
}
