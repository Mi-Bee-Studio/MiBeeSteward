// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
)

// TestTOTPHandler_NoUserContextUnauthorized pins the auth guard on every
// protected 2FA endpoint: without the middleware-injected user, each answers
// 401 before touching the service.
func TestTOTPHandler_NoUserContextUnauthorized(t *testing.T) {
	h := NewTOTPHandler(nil, nil, &config.Config{}, nil)

	for _, tc := range []struct {
		name string
		call func(w http.ResponseWriter, r *http.Request)
	}{
		{"setup", h.Setup},
		{"enable", h.Enable},
		{"disable", h.Disable},
		{"status", h.Status},
	} {
		rec := httptest.NewRecorder()
		tc.call(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/2fa/"+tc.name, nil))
		require.Equal(t, http.StatusUnauthorized, rec.Code, tc.name)
	}
}
