// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the role → capability map (#138 Phase 1a). The map is the
// single source of truth both middleware (RequireCapability) and any UI
// role-awareness read, so its shape — what each role can and cannot do — is a
// security-relevant contract. Fail-closed for unknown roles.

func TestRoleHas_AdminGrantsEverything(t *testing.T) {
	// Admin holds every defined capability (sample the span: read, op, admin).
	for _, c := range []Capability{
		CapDeviceRead, CapScanTrigger, CapScanManage, CapDeviceWrite,
		CapUserManage, CapCredManage, CapNetworkManage, CapAgentManage,
	} {
		require.True(t, RoleHas(RoleAdmin, c), "admin must grant %s", c)
	}
}

func TestRoleHas_OperatorReadsAndOpsButNoAdminMgmt(t *testing.T) {
	// Operator: reads + operational writes.
	for _, c := range []Capability{CapDeviceRead, CapScanTrigger, CapScanManage, CapDeviceWrite, CapHeartbeatManage} {
		require.True(t, RoleHas(RoleOperator, c), "operator must grant %s", c)
	}
	// Operator must NOT reach into admin-only management.
	for _, c := range []Capability{CapUserManage, CapCredManage, CapNetworkManage, CapAgentManage} {
		require.False(t, RoleHas(RoleOperator, c), "operator must NOT grant %s (admin-only)", c)
	}
}

func TestRoleHas_ViewerReadsOnly(t *testing.T) {
	require.True(t, RoleHas(RoleViewer, CapDeviceRead))
	require.True(t, RoleHas(RoleViewer, CapConfigRead))
	// Viewer cannot mutate or trigger anything.
	for _, c := range []Capability{CapDeviceWrite, CapScanTrigger, CapScanManage, CapUserManage} {
		require.False(t, RoleHas(RoleViewer, c), "viewer must NOT grant %s (read-only role)", c)
	}
}

// TestRoleHas_LegacyUserIsViewer pins the migration-free alias: existing "user"
// accounts behave exactly as viewer (no data migration needed in Phase 1).
func TestRoleHas_LegacyUserIsViewer(t *testing.T) {
	for _, c := range []Capability{
		CapDeviceRead, CapConfigRead, CapChangesRead, // reads: yes
		CapDeviceWrite, CapScanTrigger, CapUserManage, // writes: no
	} {
		require.Equal(t, RoleHas(RoleViewer, c), RoleHas(RoleUser, c),
			"legacy 'user' must match viewer for %s", c)
	}
}

// TestRoleHas_UnknownRoleFailsClosed: an empty/garbage role grants nothing.
// This is the guard against a malformed JWT claim or a future role not yet in
// the map — never fail open.
func TestRoleHas_UnknownRoleFailsClosed(t *testing.T) {
	for _, role := range []UserRole{"", "superuser", "root", "OPERATOR"} {
		require.False(t, RoleHas(role, CapDeviceRead), "unknown role %q must grant nothing", role)
	}
}

func TestRoleCapabilities_ReturnsCopy(t *testing.T) {
	caps := RoleCapabilities(RoleOperator)
	require.NotEmpty(t, caps)
	require.True(t, caps[CapScanTrigger])
	// Mutating the returned map must not corrupt the authoritative map.
	caps[CapUserManage] = true
	require.False(t, RoleHas(RoleOperator, CapUserManage),
		"RoleCapabilities must return a copy so callers cannot escalate a role")
}

func TestRoleCapabilities_UnknownRoleNil(t *testing.T) {
	require.Nil(t, RoleCapabilities("nonexistent"))
}
