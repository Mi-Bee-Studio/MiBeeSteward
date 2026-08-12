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
	"mibee-steward/internal/domain"
)

// These tests pin RequireCapability (#138 Phase 1a). It wraps Authenticator, so
// the role is taken from the JWT claim — which means operator/viewer can be
// exercised WITHOUT a DB user or a users.role CHECK widening (the claim is
// free-form; Authenticator does not validate it against the users table). That
// lets the capability gate be tested end-to-end before Phase 1b wires real
// operator/viewer accounts.

// withRoleCap wraps RequireCapability(cap) around okHandler (200 "ok").
func withRoleCap(capability domain.Capability) http.Handler {
	return middleware.RequireCapability(capability)(okHandler())
}

func TestRequireCapability_AdminPassesAnyCapability(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 1.0, "role": "admin"})
	for _, c := range []domain.Capability{
		domain.CapDeviceRead, domain.CapScanTrigger, domain.CapUserManage, domain.CapCredManage,
	} {
		rec := newCapRecorder(tok, c)
		require.Equal(t, http.StatusOK, rec.Code, "admin must pass %s", c)
	}
}

func TestRequireCapability_OperatorPassesOpsNotAdminMgmt(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 2.0, "role": "operator"})

	// Operator can trigger scans + write devices.
	require.Equal(t, http.StatusOK, newCapRecorder(tok, domain.CapScanTrigger).Code)
	require.Equal(t, http.StatusOK, newCapRecorder(tok, domain.CapDeviceWrite).Code)

	// Operator must NOT manage users/credentials/networks.
	require.Equal(t, http.StatusForbidden, newCapRecorder(tok, domain.CapUserManage).Code)
	require.Equal(t, http.StatusForbidden, newCapRecorder(tok, domain.CapCredManage).Code)
	require.Equal(t, http.StatusForbidden, newCapRecorder(tok, domain.CapNetworkManage).Code)
}

func TestRequireCapability_ViewerReadsOnly(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 3.0, "role": "viewer"})

	require.Equal(t, http.StatusOK, newCapRecorder(tok, domain.CapDeviceRead).Code, "viewer reads")
	require.Equal(t, http.StatusForbidden, newCapRecorder(tok, domain.CapScanTrigger).Code, "viewer cannot trigger scans")
	require.Equal(t, http.StatusForbidden, newCapRecorder(tok, domain.CapDeviceWrite).Code, "viewer cannot write")
}

// TestRequireCapability_LegacyUserBehavesAsViewer: an existing JWT with the
// legacy "user" role must behave as viewer (so deployed tokens keep working
// through Phase 1 without re-issuance).
func TestRequireCapability_LegacyUserBehavesAsViewer(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 4.0, "role": "user"})

	require.Equal(t, http.StatusOK, newCapRecorder(tok, domain.CapDeviceRead).Code)
	require.Equal(t, http.StatusForbidden, newCapRecorder(tok, domain.CapScanTrigger).Code)
}

func TestRequireCapability_UnauthenticatedReturns401(t *testing.T) {
	useJWTAuth(t)
	// No Bearer token at all.
	rec := httptest.NewRecorder()
	withRoleCap(domain.CapDeviceRead).ServeHTTP(rec, reqWithBearer(""))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestRequireCapability_UnknownRoleRejected: a JWT claiming a role the map does
// not know (e.g. a tampered/future claim) must be rejected (403), never pass.
func TestRequireCapability_UnknownRoleRejected(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 5.0, "role": "superuser"})
	// Even a read capability is denied — unknown roles fail closed.
	require.Equal(t, http.StatusForbidden, newCapRecorder(tok, domain.CapDeviceRead).Code)
}

// newCapRecorder fires one GET through RequireCapability(cap) with the given
// bearer token and returns the recorder.
func newCapRecorder(bearerToken string, capability domain.Capability) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	withRoleCap(capability).ServeHTTP(rec, reqWithBearer(bearerToken))
	return rec
}
