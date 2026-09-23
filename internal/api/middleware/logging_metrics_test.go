// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLoggingMetricsWrappers_Unwrap: both wrapper types must expose the
// underlying ResponseWriter via Unwrap, http.ResponseController relies on it
// to reach the real Flusher (the SSE /changes/watch endpoint breaks with
// "streaming not supported" otherwise).
func TestLoggingMetricsWrappers_Unwrap(t *testing.T) {
	flushed := make(chan struct{}, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rc := http.NewResponseController(w)
		require.NotPanics(t, func() { _ = rc.Flush() }, "Unwrap chain must reach the real Flusher")
		flushed <- struct{}{}
	})

	rec := httptest.NewRecorder()
	Logging(Metrics(h)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, flushed, 1)
}
