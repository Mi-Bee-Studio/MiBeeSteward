// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

const csrfCookieName = "csrf_token"

// CSRF protects against cross-origin request forgery using two layers:
// 1. Origin header validation (existing)
// 2. Double-submit cookie pattern: cookie token must match X-CSRF-Token header
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method

		// Safe methods: ensure CSRF cookie exists for future state-changing requests
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			ensureCSRFCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}

		// --- Layer 1: Origin check (keep existing logic) ---
		origin := r.Header.Get("Origin")
		host := r.Host

		if origin == "" {
			referer := r.Header.Get("Referer")
			if referer == "" {
				// Neither Origin nor Referer — likely non-browser client
				// Skip CSRF token check for non-browser clients (no cookie set yet)
				next.ServeHTTP(w, r)
				return
			}
			if !strings.HasPrefix(referer, "http://"+host) && !strings.HasPrefix(referer, "https://"+host) {
				slog.Warn("CSRF: rejected request with no Origin and mismatched Referer",
					"referer", referer,
					"host", host,
					"method", method,
					"path", r.URL.Path,
				)
				csrfReject(w)
				return
			}
		} else if !strings.HasPrefix(origin, "http://"+host) && !strings.HasPrefix(origin, "https://"+host) {
			slog.Warn("CSRF: rejected cross-origin request",
				"origin", origin,
				"host", host,
				"method", method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)
			csrfReject(w)
			return
		}

		// --- Layer 2: Double-submit cookie check ---
		cookie, cookieErr := r.Cookie(csrfCookieName)
		headerToken := r.Header.Get("X-CSRF-Token")

		if cookieErr != nil && headerToken == "" {
			// No cookie and no header — non-browser client, allow through
			next.ServeHTTP(w, r)
			return
		}

		if cookieErr != nil || headerToken == "" || cookie.Value != headerToken {
			slog.Warn("CSRF: token validation failed",
				"has_cookie", cookieErr == nil,
				"has_header", headerToken != "",
				"method", method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)
			csrfReject(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ensureCSRFCookie sets a csrf_token cookie if one doesn't already exist.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(csrfCookieName); err == nil {
		return // cookie already exists
	}
	token := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   86400, // 24h
		HttpOnly: false, // MUST be accessible to JS
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func csrfReject(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden origin"}`))
}
