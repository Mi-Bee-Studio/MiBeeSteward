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

// CreateAgentTokenRequest is the admin payload for creating a discovery-agent
// token (POST /api/v1/agents/tokens). AgentID + NetworkID together scope the
// token: the agent presents it to the ingestion endpoints, and the center tags
// every reported device with the token's network_id.
type CreateAgentTokenRequest struct {
	// AgentID is the stable identifier the agent reports as (e.g. "agent-lan-62").
	// Must be unique; the agent config carries the same value.
	AgentID string `json:"agent_id"`
	// NetworkID is the networks.id this agent discovers for. Devices reported by
	// this agent are tagged with it (devices.network_id).
	NetworkID int64 `json:"network_id"`
	// Name is an optional human label for the admin UI (e.g. "Branch Beijing LAN-62").
	Name string `json:"name,omitempty"`
}

// AgentTokenResponse is the admin-facing view of a token. TokenHash is the
// stored hash (never the plaintext). The plaintext is returned ONLY in
// AgentTokenCreatedResponse at creation time — there is no way to recover it.
type AgentTokenResponse struct {
	ID         int64      `json:"id"`
	AgentID    string     `json:"agent_id"`
	NetworkID  *int64     `json:"network_id,omitempty"`
	Name       string     `json:"name,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// AgentTokenCreatedResponse is returned once at creation: the full token record
// PLUS the plaintext token, which the admin copies into the agent config and
// which is never retrievable again.
type AgentTokenCreatedResponse struct {
	AgentTokenResponse
	// Token is the plaintext bearer token. Shown ONCE — store it securely.
	Token string `json:"token"`
}

// AgentCommandListResponse is the admin view of all agent commands.
type AgentCommandListResponse struct {
	Commands any `json:"commands"` // []db.AgentCommand (sqlc row, JSON-tagged)
	Total    int `json:"total"`
}
