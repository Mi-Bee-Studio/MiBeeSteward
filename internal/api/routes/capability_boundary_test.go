// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the capability wiring of the user-JWT route surface (#138
// Phase 1c): every route that used to be a blanket RequireAdmin is now gated by
// a specific capability from internal/domain/capability.go. They exercise the
// REAL router built by NewRouter, firing one representative route per
// capability tier for each role and asserting the privilege boundary holds at
// the route (not just middleware) layer. Scanner-tier coverage lives in
// scanner_rbac_test.go; this file covers the rest of the surface.
//
// "Pass" = the request cleared the auth gate and reached the handler (status is
// anything OTHER than 401/403 — e.g. 200/400/404 from the handler on a
// near-empty test DB). "Deny" = exactly 403 (authenticated but lacks the
// capability) or 401 (no token). This decouples the boundary assertion from
// handler/DB specifics while still catching a mis-wired capability.

// accessLevel names the coarse privilege tier a route sits at. It mirrors the
// capability matrix: read caps are held by every authenticated role; operator
// caps by admin+operator; admin caps by admin only.
type accessLevel int

const (
	levelRead     accessLevel = iota // viewer+ (every authenticated role)
	levelOperator                    // operator+ (admin, operator)
	levelAdmin                       // admin only
)

// capabilityRoute is one representative route for a capability tier.
type capabilityRoute struct {
	label  string
	method string
	path   string
	level  accessLevel
}

// rbacRoles is the set of authenticated roles exercised against every route.
var rbacRoles = []string{"admin", "operator", "viewer", "user"}

// rolePasses reports whether role clears a route gated at lvl. This is the test
// encoding of internal/domain/capability.go's role→capability map (admin =
// everything, operator = reads + operational writes, viewer/user = reads).
func rolePasses(role string, lvl accessLevel) bool {
	switch lvl {
	case levelRead:
		return true // every authenticated role holds the read capabilities
	case levelOperator:
		return role == "admin" || role == "operator"
	case levelAdmin:
		return role == "admin"
	}
	return false
}

func TestRoutes_CapabilityBoundary(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() {
		heartbeatSvc.Stop()
		shutdown()
	})

	routes := []capabilityRoute{
		// --- read tier: CapAuditRead. audit-logs moved off RequireAdmin to
		// CapAuditRead, which the matrix grants to viewer+ — the one read this
		// PR opens to non-admins. (Other inventory reads stay RequireAuth and
		// are covered by TestRoutes_RequireAuthReadsRemainOpen below.) ---
		{"audit-read", http.MethodGet, "/api/v1/audit-logs", levelRead},

		// --- operator write tier (CapDeviceWrite / CapHeartbeatManage /
		// CapDocumentWrite): admin + operator pass, viewer/user 403. ---
		{"device-write", http.MethodPut, "/api/v1/devices/1", levelOperator},
		{"device-systems-write", http.MethodPost, "/api/v1/devices/1/systems", levelOperator},
		{"heartbeat-manage", http.MethodPost, "/api/v1/devices/1/heartbeat-configs", levelOperator},
		{"document-write", http.MethodPost, "/api/v1/documents", levelOperator},
		{"device-document-link", http.MethodPost, "/api/v1/devices/1/documents", levelOperator},

		// --- admin-only manage tier (CapNetworkManage / CapCredManage /
		// CapUserManage / CapAgentManage / CapDashboardManage /
		// CapNotificationManage): only admin passes. ---
		{"network-manage", http.MethodPost, "/api/v1/networks", levelAdmin},
		{"snmp-cred-manage", http.MethodPost, "/api/v1/snmp-credentials", levelAdmin},
		{"ssh-cred-manage", http.MethodGet, "/api/v1/ssh-credentials", levelAdmin},
		{"user-manage", http.MethodGet, "/api/v1/users", levelAdmin},
		{"auth-register", http.MethodPost, "/api/v1/auth/register", levelAdmin},
		{"agent-token-manage", http.MethodGet, "/api/v1/agents/tokens", levelAdmin},
		{"agent-commands-all", http.MethodGet, "/api/v1/agents/commands/all", levelAdmin},
		{"dashboard-manage", http.MethodPost, "/api/v1/dashboard/configs", levelAdmin},
		{"notification-channels", http.MethodPost, "/api/v1/notification/channels", levelAdmin},
		{"notification-rules", http.MethodGet, "/api/v1/notification/rules", levelAdmin},
	}

	for _, rt := range routes {
		for _, role := range rbacRoles {
			role, rt := role, rt
			pass := rolePasses(role, rt.level)
			t.Run(rt.label+"/"+role, func(t *testing.T) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(rt.method, rt.path, nil)
				req.Header.Set("Authorization", "Bearer "+tokenForRole(t, cfg.Auth.JWTSecret, role))
				handler.ServeHTTP(rec, req)

				code := rec.Code
				if pass {
					require.NotEqual(t, http.StatusUnauthorized, code, "pass must not be 401")
					require.NotEqualf(t, http.StatusForbidden, code,
						"%s %s role=%s must clear the gate (got 403)", rt.method, rt.path, role)
				} else {
					require.Equalf(t, http.StatusForbidden, code,
						"%s %s role=%s must be denied 403", rt.method, rt.path, role)
				}
			})
		}
		// anonymous → 401 for every gated route.
		t.Run(rt.label+"/anon", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(rt.method, rt.path, nil)
			handler.ServeHTTP(rec, req)
			require.Equalf(t, http.StatusUnauthorized, rec.Code,
				"%s %s anon must be 401", rt.method, rt.path)
		})
	}
}

// TestRoutes_RequireAuthReadsRemainOpen is a regression guard: the shared
// inventory read surface stays RequireAuth (NOT capability-gated) in this PR,
// so every authenticated role — including viewer — must still read it. This
// catches an accidental tightening where a read route is mis-remapped to an
// admin/operator capability.
func TestRoutes_RequireAuthReadsRemainOpen(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() {
		heartbeatSvc.Stop()
		shutdown()
	})

	reads := []capabilityRoute{
		{"devices", http.MethodGet, "/api/v1/devices", levelRead},
		{"networks", http.MethodGet, "/api/v1/networks", levelRead},
		{"changes", http.MethodGet, "/api/v1/changes", levelRead},
		{"topology", http.MethodGet, "/api/v1/topology", levelRead},
		{"dashboard-overview", http.MethodGet, "/api/v1/dashboard/overview", levelRead},
		{"device-configs", http.MethodGet, "/api/v1/devices/1/configs", levelRead},
		{"heartbeat-results", http.MethodGet, "/api/v1/devices/1/heartbeat-results", levelRead},
	}

	for _, rt := range reads {
		// viewer must pass (the guard's point); anon must still get 401.
		t.Run(rt.label+"/viewer", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("Authorization", "Bearer "+tokenForRole(t, cfg.Auth.JWTSecret, "viewer"))
			handler.ServeHTTP(rec, req)
			require.NotEqual(t, http.StatusUnauthorized, rec.Code)
			require.NotEqual(t, http.StatusForbidden, rec.Code,
				"%s %s viewer must remain readable (RequireAuth)", rt.method, rt.path)
		})
		t.Run(rt.label+"/anon", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(rt.method, rt.path, nil)
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}
