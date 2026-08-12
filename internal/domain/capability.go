// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package domain

// Capability is a granular permission a role may hold. Routes gate on a
// capability via middleware.RequireCapability (issue #138), replacing the
// binary admin/user string check. Capabilities are defined in code (not a DB
// table) so the role model stays simple to operate; a future phase can promote
// to DB-driven roles/permissions if custom roles become necessary.
type Capability string

const (
	// --- Read capabilities (granted to viewer and inherited by operator/admin) ---
	CapDeviceRead       Capability = "device:read"
	CapNetworkRead      Capability = "network:read"
	CapConfigRead       Capability = "config:read" // device config-backup versions + diff
	CapChangesRead      Capability = "changes:read"
	CapTopologyRead     Capability = "topology:read"
	CapDiscoveryRead    Capability = "discovery:read"
	CapHeartbeatRead    Capability = "heartbeat:read"
	CapDocumentRead     Capability = "document:read"
	CapDashboardRead    Capability = "dashboard:read"
	CapNotificationRead Capability = "notification:read"
	CapAuditRead        Capability = "audit:read"

	// --- Operational capabilities (operator adds these on top of reads) ---
	CapDeviceWrite     Capability = "device:write"     // edit device fields, batch ops
	CapScanTrigger     Capability = "scan:trigger"     // run a scan (sync + async task trigger/cancel)
	CapScanManage      Capability = "scan:manage"      // scan task CRUD
	CapHeartbeatManage Capability = "heartbeat:manage" // heartbeat config CRUD
	CapDocumentWrite   Capability = "document:write"

	// --- Administrative capabilities (admin only) ---
	CapNetworkManage      Capability = "network:manage" // create/edit/delete networks
	CapCredManage         Capability = "cred:manage"    // SNMP + SSH credentials
	CapUserManage         Capability = "user:manage"    // users, roles, network grants
	CapAgentManage        Capability = "agent:manage"   // agent tokens + commands
	CapAuditManage        Capability = "audit:manage"
	CapDashboardManage    Capability = "dashboard:manage"
	CapNotificationManage Capability = "notification:manage" // channels + rules
)

// readCaps is the read-only capability set granted to viewer. operator and
// admin inherit it. Listed explicitly (no wildcard) so the grant is auditable.
var readCaps = map[Capability]bool{
	CapDeviceRead: true, CapNetworkRead: true, CapConfigRead: true,
	CapChangesRead: true, CapTopologyRead: true, CapDiscoveryRead: true,
	CapHeartbeatRead: true, CapDocumentRead: true, CapDashboardRead: true,
	CapNotificationRead: true, CapAuditRead: true,
}

// operatorCaps = reads + operational writes (no user/cred/network/agent mgmt).
var operatorCaps = union(readCaps, map[Capability]bool{
	CapDeviceWrite: true, CapScanTrigger: true, CapScanManage: true,
	CapHeartbeatManage: true, CapDocumentWrite: true,
})

// adminCaps = every defined capability.
var adminCaps = union(operatorCaps, map[Capability]bool{
	CapNetworkManage: true, CapCredManage: true, CapUserManage: true,
	CapAgentManage: true, CapAuditManage: true, CapDashboardManage: true,
	CapNotificationManage: true,
})

// roleCapabilities is the authoritative role → capability map. It is the single
// source of truth for what each role can do; middleware.RequireCapability and
// any UI role-awareness read from here.
var roleCapabilities = map[UserRole]map[Capability]bool{
	RoleAdmin:    adminCaps,
	RoleOperator: operatorCaps,
	RoleViewer:   readCaps,
	RoleUser:     readCaps, // legacy alias for viewer
}

// RoleHas reports whether the role grants the capability. An unknown role (e.g.
// an empty/invalid value) grants nothing — fail-closed.
func RoleHas(role UserRole, capability Capability) bool {
	caps, ok := roleCapabilities[role]
	if !ok {
		return false
	}
	return caps[capability]
}

// RoleCapabilities returns a copy of the capability set for a role (for
// introspection / UI). Returns nil for an unknown role.
func RoleCapabilities(role UserRole) map[Capability]bool {
	caps, ok := roleCapabilities[role]
	if !ok {
		return nil
	}
	out := make(map[Capability]bool, len(caps))
	for c := range caps {
		out[c] = true
	}
	return out
}

// union returns a new map = a ∪ b (does not mutate inputs).
func union(a, b map[Capability]bool) map[Capability]bool {
	out := make(map[Capability]bool, len(a)+len(b))
	for c := range a {
		out[c] = true
	}
	for c := range b {
		out[c] = true
	}
	return out
}
