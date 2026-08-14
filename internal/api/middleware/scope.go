// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/authz/scoperesolver"
	"mibee-steward/internal/domain"
)

// NetworkScope resolves the authenticated user's object-level network scope and
// injects it into the request context (domain.ContextKeyUserScope) for the
// inventory query paths and ValidateDeviceScope (#138 Phase 2).
//
// It wraps Authenticator (house style — cf. RequireCapability) so it works in
// any middleware position. On an unauthenticated request (no user in context)
// it simply forwards without injecting a scope; the downstream RequireCapability
// gate will 401. Admin and open-mode resolve to a Global scope; closed-mode
// non-admin resolves to the granted network set (resolver caches + fails open).
func NetworkScope(resolver *scoperesolver.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return Authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, role, ok := GetUserFromContext(r)
			if !ok {
				next.ServeHTTP(w, r) // no user → let the auth gate 401
				return
			}
			scope := resolver.Resolve(r.Context(), userID, domain.UserRole(role))
			ctx := context.WithValue(r.Context(), domain.ContextKeyUserScope, scope)
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
}

// ValidateDeviceScope gates any /devices/{id} route (and its sub-resources:
// neighbors, certificates, configs, systems, heartbeat, documents) on the
// caller's network scope. A Global scope (admin / open mode) always passes. A
// restricted scope passes only if the device's network_id is in the allowed
// set; otherwise 403. A missing or malformed id is forwarded to the handler
// (which renders its own 404/400) so this middleware never masks handler errors.
//
// Must run AFTER NetworkScope (so the scope is in context). Place it via
// r.Use on every /devices/{id}… route group; a nil db disables the check.
func ValidateDeviceScope(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scope := domain.ScopeFromContext(r.Context())
			if scope.IsGlobal() {
				next.ServeHTTP(w, r)
				return
			}
			idStr := chi.URLParam(r, "id")
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				next.ServeHTTP(w, r) // malformed id → handler 404/400
				return
			}
			var networkID sql.NullInt64
			err = db.QueryRowContext(r.Context(),
				`SELECT network_id FROM devices WHERE id = ?`, id).Scan(&networkID)
			if err != nil {
				next.ServeHTTP(w, r) // not found / error → handler 404
				return
			}
			// A device with no assigned network is visible to no restricted scope.
			if !networkID.Valid || !scope.AllowsNetwork(networkID.Int64) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden: device out of network scope"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
