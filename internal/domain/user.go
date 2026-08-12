// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package domain

import "time"

// UserRole represents a user's role in the system. Roles map to capability sets
// (see capability.go); authorization is enforced by middleware.RequireCapability,
// not by string-equality on the role. Phase 1a (#138) introduces operator/viewer
// alongside the legacy admin/user; "user" is treated as an alias for "viewer" so
// existing accounts need no data migration.
type UserRole string

const (
	RoleAdmin    UserRole = "admin"    // global administrator: all capabilities, bypasses object scope
	RoleOperator UserRole = "operator" // operational: reads + scan/device/heartbeat ops, no user/cred/network mgmt
	RoleViewer   UserRole = "viewer"   // read-only
	RoleUser     UserRole = "user"     // legacy alias for viewer (existing accounts)
)

// Request types

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"` // optional, defaults to "user"
}

type LoginRequest struct {
	Username string `json:"username"` // accepts username or email
	Password string `json:"password"`
}

type UpdateProfileRequest struct {
	Email string `json:"email"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// Response types

type UserResponse struct {
	ID                 int64     `json:"id"`
	Username           string    `json:"username"`
	Email              string    `json:"email"`
	Role               string    `json:"role"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type LoginResponse struct {
	Token             string       `json:"token"`
	User              UserResponse `json:"user"`
	TwoFactorRequired bool         `json:"two_factor_required,omitempty"`
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
}

// Context key type for user info.
type contextKey string

const (
	ContextKeyUserID contextKey = "user_id"
	ContextKeyRole   contextKey = "role"
	// ContextKeyAgentID / ContextKeyAgentNetworkID are set by the agent-token
	// middleware (RequireAgentToken) for machine-to-machine ingestion requests.
	// Distinct from the user JWT keys so a request is either a user session OR
	// an agent, never both.
	ContextKeyAgentID        contextKey = "agent_id"
	ContextKeyAgentNetworkID contextKey = "agent_network_id"
)
