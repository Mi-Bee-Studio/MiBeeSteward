// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package domain

import "context"

// ScopeMode controls object-level network visibility for non-admin users
// (#138 Phase 2). See internal/config.RBACConfig.
type ScopeMode string

const (
	// ScopeModeOpen (default): a non-admin user sees every network regardless of
	// grants. Preserves existing single-team deployments (no behavior change).
	ScopeModeOpen ScopeMode = "open"
	// ScopeModeClosed: a non-admin user sees only the networks they hold a grant
	// for (MSP / multi-tenant isolation). Admin always bypasses scope.
	ScopeModeClosed ScopeMode = "closed"
)

// Scope is the resolved object-level network scope for an authenticated user.
// It is injected into the request context by the NetworkScope middleware and
// consumed by the device/topology/changes/dashboard query paths + the
// ValidateDeviceScope middleware.
//
// Either Global is true (see everything) OR NetworkIDs is the exhaustive
// allow-list of network_ids the caller may see. A Global scope short-circuits
// every scope check (no filtering) — the common path (admin + open mode).
type Scope struct {
	// Global: when true, the caller is unrestricted (no network filtering).
	Global bool
	// NetworkIDs: when Global is false, the exhaustive set of network_ids the
	// caller may read/operate. May be empty (closed mode + no grants → sees
	// nothing). Callers MUST NOT read this when Global is true.
	NetworkIDs []int64
}

// IsGlobal reports whether the scope is unrestricted.
func (s Scope) IsGlobal() bool { return s.Global }

// AllowsNetwork reports whether a network_id is within the scope. Global scopes
// allow everything; restricted scopes allow only the listed ids.
func (s Scope) AllowsNetwork(networkID int64) bool {
	if s.Global {
		return true
	}
	for _, id := range s.NetworkIDs {
		if id == networkID {
			return true
		}
	}
	return false
}

// Context key carrying the resolved Scope (set by the NetworkScope middleware).
const ContextKeyUserScope contextKey = "user_scope"

// ScopeFromContext returns the resolved Scope from the request context. If no
// scope is present (e.g. the route runs before NetworkScope, or a unit test
// that didn't set one), it returns a Global scope — the safe default for paths
// that are not behind the scope middleware, so unscoped callers are NOT
// accidentally locked out. Code paths that enforce scope are always behind
// NetworkScope, so they will always find a real (non-default) scope.
func ScopeFromContext(ctx context.Context) Scope {
	if v, ok := ctx.Value(ContextKeyUserScope).(Scope); ok {
		return v
	}
	return Scope{Global: true}
}
