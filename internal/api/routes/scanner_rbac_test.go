// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"
)

// These tests pin the scanner route capability wiring (#138 Phase 1b). Unlike
// the middleware-level capability tests (which prove RequireCapability itself),
// these exercise the REAL router built by NewRouter: one representative route
// per capability tier is fired for each role, asserting the privilege boundary
// is enforced at the route (not just the middleware) layer.
//
// "Pass" means the request cleared the auth gate and reached the handler (so the
// status is anything OTHER than 401/403 — e.g. 200/400/404 from the handler on a
// near-empty test DB). "Deny" means exactly 403 (authenticated, insufficient
// capability) or 401 (no token). This decouples the boundary assertion from
// handler/DB specifics while still catching a mis-wired capability.

// scannerRBACCase is one (route, role) probe.
type scannerRBACCase struct {
	name   string
	method string
	path   string
	role   string // "" = anonymous (no Bearer token)
	pass   bool   // true = expect to clear the gate; false = expect 403 (or 401 if anon)
}

func TestScannerRoutes_CapabilityBoundary(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() {
		heartbeatSvc.Stop()
		shutdown()
	})

	// Representative route per capability tier:
	//   read        → GET    /scanner/results          (discovery:read)
	//   trigger     → POST   /scanner/tasks/999/cancel (scan:trigger, not rate-limited)
	//   manage      → DELETE /scanner/tasks/999        (scan:manage)
	//   device-write→ POST   /scanner/add-devices      (device:write)
	cases := []scannerRBACCase{
		// --- read tier: viewer+ pass ---
		{"read/admin", http.MethodGet, "/api/v1/scanner/results", "admin", true},
		{"read/operator", http.MethodGet, "/api/v1/scanner/results", "operator", true},
		{"read/viewer", http.MethodGet, "/api/v1/scanner/results", "viewer", true},
		{"read/user", http.MethodGet, "/api/v1/scanner/results", "user", true},
		{"read/anon", http.MethodGet, "/api/v1/scanner/results", "", false},

		// --- trigger tier (cancel): operator+ pass, viewer/user 403, anon 401 ---
		{"trigger/admin", http.MethodPost, "/api/v1/scanner/tasks/999/cancel", "admin", true},
		{"trigger/operator", http.MethodPost, "/api/v1/scanner/tasks/999/cancel", "operator", true},
		{"trigger/viewer", http.MethodPost, "/api/v1/scanner/tasks/999/cancel", "viewer", false},
		{"trigger/user", http.MethodPost, "/api/v1/scanner/tasks/999/cancel", "user", false},
		{"trigger/anon", http.MethodPost, "/api/v1/scanner/tasks/999/cancel", "", false},

		// --- manage tier (delete task): operator+ pass, viewer/user 403, anon 401 ---
		{"manage/admin", http.MethodDelete, "/api/v1/scanner/tasks/999", "admin", true},
		{"manage/operator", http.MethodDelete, "/api/v1/scanner/tasks/999", "operator", true},
		{"manage/viewer", http.MethodDelete, "/api/v1/scanner/tasks/999", "viewer", false},
		{"manage/user", http.MethodDelete, "/api/v1/scanner/tasks/999", "user", false},
		{"manage/anon", http.MethodDelete, "/api/v1/scanner/tasks/999", "", false},

		// --- device-write tier (add-devices): operator+ pass, viewer/user 403, anon 401 ---
		{"devwrite/admin", http.MethodPost, "/api/v1/scanner/add-devices", "admin", true},
		{"devwrite/operator", http.MethodPost, "/api/v1/scanner/add-devices", "operator", true},
		{"devwrite/viewer", http.MethodPost, "/api/v1/scanner/add-devices", "viewer", false},
		{"devwrite/user", http.MethodPost, "/api/v1/scanner/add-devices", "user", false},
		{"devwrite/anon", http.MethodPost, "/api/v1/scanner/add-devices", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.role != "" {
				req.Header.Set("Authorization", "Bearer "+tokenForRole(t, cfg.Auth.JWTSecret, tc.role))
			}
			handler.ServeHTTP(rec, req)

			code := rec.Code
			switch {
			case tc.role == "" && tc.pass:
				t.Fatalf("anon marked pass — malformed case")
			case tc.role == "":
				require.Equal(t, http.StatusUnauthorized, code, "anon must be 401")
			case tc.pass:
				require.NotEqual(t, http.StatusUnauthorized, code, "authenticated pass must not be 401")
				require.NotEqual(t, http.StatusForbidden, code, "%s with role %s must clear the gate (got 403)", tc.method, tc.path, tc.role)
			default:
				require.Equal(t, http.StatusForbidden, code, "%s %s with role %s must be denied 403", tc.method, tc.path, tc.role)
			}
		})
	}
}

// tokenForRole signs a JWT (same secret NewRouter configured via SetJWTAuth)
// carrying the given role claim. user_id is arbitrary; the auth gate only reads
// role (and presence of user_id) for the capability check.
func tokenForRole(t *testing.T, secret, role string) string {
	t.Helper()
	auth := jwtauth.New("HS256", []byte(secret), nil)
	_, token, err := auth.Encode(map[string]any{"user_id": float64(1), "role": role})
	require.NoError(t, err)
	return token
}
