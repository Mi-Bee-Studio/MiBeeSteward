// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/middleware"
)

// These tests pin the CSRF middleware (#171) — the cross-origin + double-submit
// gate that every state-changing browser request must pass. A regression here is
// a CSRF hole (an attacker site forcing authenticated state changes). The
// load-bearing invariants:
//   - safe methods (GET/HEAD/OPTIONS) pass and seed the csrf cookie,
//   - a state-changing request from a CROSS origin is rejected (403),
//   - a same-origin state change needs cookie token == X-CSRF-Token header,
//   - non-browser clients (no Origin + no cookie/header) are allowed through.

func csrfRequest(method, host, origin, referer, cookieVal, headerVal string) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	if host != "" {
		r.Host = host
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	if cookieVal != "" {
		r.AddCookie(&http.Cookie{Name: "csrf_token", Value: cookieVal})
	}
	if headerVal != "" {
		r.Header.Set("X-CSRF-Token", headerVal)
	}
	return r
}

func TestCSRF_SafeMethodSeedsCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	middleware.CSRF(okHandler()).ServeHTTP(rec, csrfRequest(http.MethodGet, "example.com", "", "", "", ""))

	require.Equal(t, http.StatusOK, rec.Code)
	// A GET with no existing csrf cookie must seed one for future state changes.
	setCookie := rec.Header().Get("Set-Cookie")
	require.Contains(t, setCookie, "csrf_token=", "GET must seed a csrf cookie")
}

func TestCSRF_POST_SameOriginMatchingTokenPasses(t *testing.T) {
	rec := httptest.NewRecorder()
	middleware.CSRF(okHandler()).ServeHTTP(rec,
		csrfRequest(http.MethodPost, "example.com", "http://example.com", "", "tok", "tok"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

// TestCSRF_POST_CrossOriginRejected pins the Origin check: a POST whose Origin
// does not match the request host is rejected before the token check even runs.
func TestCSRF_POST_CrossOriginRejected(t *testing.T) {
	rec := httptest.NewRecorder()
	middleware.CSRF(okHandler()).ServeHTTP(rec,
		csrfRequest(http.MethodPost, "example.com", "http://evil.example", "", "tok", "tok"))

	require.Equal(t, http.StatusForbidden, rec.Code, "cross-origin POST must be rejected")
}

// TestCSRF_POST_TokenMismatchRejected pins the double-submit check: even
// same-origin, a cookie/header mismatch is rejected (an attacker can set a
// cookie via a subdomain but cannot forge the matching header).
func TestCSRF_POST_TokenMismatchRejected(t *testing.T) {
	rec := httptest.NewRecorder()
	middleware.CSRF(okHandler()).ServeHTTP(rec,
		csrfRequest(http.MethodPost, "example.com", "http://example.com", "", "cookie-tok", "header-tok"))

	require.Equal(t, http.StatusForbidden, rec.Code, "cookie/header token mismatch must be rejected")
}

// TestCSRF_POST_NoOriginNoRefererPasses pins the non-browser-client carve-out:
// a request with neither Origin nor Referer (a non-browser client with no CSRF
// state) is allowed through. CSRF protects browsers, not API clients.
func TestCSRF_POST_NoOriginNoRefererPasses(t *testing.T) {
	rec := httptest.NewRecorder()
	middleware.CSRF(okHandler()).ServeHTTP(rec,
		csrfRequest(http.MethodPost, "example.com", "", "", "", ""))

	require.Equal(t, http.StatusOK, rec.Code, "non-browser POST (no Origin/Referer) passes")
}

// TestCSRF_POST_NoOriginMismatchedRefererRejected pins the Referer fallback:
// when Origin is absent, a Referer pointing elsewhere is rejected.
func TestCSRF_POST_NoOriginMismatchedRefererRejected(t *testing.T) {
	rec := httptest.NewRecorder()
	middleware.CSRF(okHandler()).ServeHTTP(rec,
		csrfRequest(http.MethodPost, "example.com", "", "http://evil.example/x", "", ""))

	require.Equal(t, http.StatusForbidden, rec.Code, "mismatched Referer must be rejected")
}
