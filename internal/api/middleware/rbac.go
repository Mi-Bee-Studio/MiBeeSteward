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
	"net/http"

	"mibee-steward/internal/domain"
)

// RequireAuth returns middleware that requires a valid authenticated user.
// If no valid user context is found, it responds with 401 Unauthorized.
func RequireAuth(next http.Handler) http.Handler {
	return Authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := GetUserFromContext(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequireAdmin returns middleware that requires an authenticated admin user.
// If no valid user context is found, it responds with 401 Unauthorized.
// If user is not an admin, it responds with 403 Forbidden.
func RequireAdmin(next http.Handler) http.Handler {
	return Authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, role, ok := GetUserFromContext(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if role != "admin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden: admin access required"}`))
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequireCapability returns middleware requiring the authenticated user's role
// to grant cap (#138). It wraps Authenticator, so the role is resolved from the
// JWT claim just like RequireAuth/RequireAdmin. Responses:
//   - no/invalid token → 401 (Authenticator left no user in context),
//   - authenticated but the role lacks cap → 403,
//   - the role grants cap → next.
//
// Use this in place of RequireAdmin where a non-admin role (e.g. operator)
// should be allowed; RequireAdmin stays for hard admin-only surfaces. The
// capability map lives in internal/domain (RoleHas) so role→capability stays a
// single source of truth.
func RequireCapability(capability domain.Capability) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return Authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, role, ok := GetUserFromContext(r)
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			if !domain.RoleHas(domain.UserRole(role), capability) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden: insufficient capability"}`))
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}
