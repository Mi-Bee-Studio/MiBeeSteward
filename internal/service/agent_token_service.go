// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"errors"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// AgentTokenService is the write path for discovery-agent bearer tokens
// (issue #240: the agent_admin handler was grandfathered charter debt). Token
// MINTING stays in the HTTP layer — the plaintext is a one-time credential
// shown in the response — and is injected as a func so tests can pin it;
// persistence + the networks.agent_id wiring live here.
type AgentTokenService struct {
	queries *db.Queries
}

// NewAgentTokenService constructs an AgentTokenService.
func NewAgentTokenService(queries *db.Queries) *AgentTokenService {
	return &AgentTokenService{queries: queries}
}

// TokenMinter returns a freshly-minted (plaintext, hash) pair. The production
// value is middleware.GenerateAgentToken; a func type keeps this package free
// of an api-layer import.
type TokenMinter func() (plaintext, hash string)

var (
	// ErrNetworkIDInvalid maps to 400. (ErrAgentIDRequired — also 400 — is
	// declared once in agent_command_service.go and shared.)
	ErrNetworkIDInvalid = errors.New("network_id is required or does not refer to a known network")
	// ErrAgentIDTaken maps to 409 (UNIQUE(agent_id) collision).
	ErrAgentIDTaken = errors.New("agent_id already exists; choose a unique id")
	// ErrAgentTokenNotFound maps to 404.
	ErrAgentTokenNotFound = errors.New("agent token not found")
)

// Create mints (via mint), stores, and wires a new agent token. Stamping
// networks.agent_id is what makes the center's heartbeat exclusion (no
// cross-subnet probing of agent devices) and the lease-sweeper scope engage
// automatically. The stamp is best-effort: a failure leaves the token
// functional (reports still work); the network just isn't scoped.
func (s *AgentTokenService) Create(ctx context.Context, req domain.CreateAgentTokenRequest, mint TokenMinter) (domain.AgentTokenCreatedResponse, error) {
	if req.AgentID == "" {
		return domain.AgentTokenCreatedResponse{}, ErrAgentIDRequired
	}
	if req.NetworkID <= 0 {
		return domain.AgentTokenCreatedResponse{}, ErrNetworkIDInvalid
	}
	// Verify the network exists so the foreign key isn't dangling.
	if _, err := s.queries.GetNetwork(ctx, req.NetworkID); err != nil {
		return domain.AgentTokenCreatedResponse{}, ErrNetworkIDInvalid
	}

	plaintext, hash := mint()
	networkIDPtr := req.NetworkID // take address of a stable local
	row, err := s.queries.CreateAgentToken(ctx, db.CreateAgentTokenParams{
		AgentID:   req.AgentID,
		TokenHash: hash,
		NetworkID: &networkIDPtr,
		Name:      req.Name,
	})
	if err != nil {
		return domain.AgentTokenCreatedResponse{}, ErrAgentIDTaken
	}

	agentIDStr := req.AgentID
	_ = s.queries.SetNetworkAgentID(ctx, db.SetNetworkAgentIDParams{
		AgentID: &agentIDStr,
		ID:      req.NetworkID,
	})

	return domain.AgentTokenCreatedResponse{
		AgentTokenResponse: domain.AgentTokenResponse{
			ID:         row.ID,
			AgentID:    row.AgentID,
			NetworkID:  row.NetworkID,
			Name:       row.Name,
			CreatedAt:  row.CreatedAt,
			LastUsedAt: row.LastUsedAt,
			RevokedAt:  row.RevokedAt,
		},
		Token: plaintext,
	}, nil
}

// Revoke soft-revokes (sets revoked_at) — the token immediately fails auth.
// Kept soft so the audit trail (last_used_at, created_at) survives. Also
// clears the network's agent_id so the center resumes local probing.
func (s *AgentTokenService) Revoke(ctx context.Context, id int64) error {
	tok, err := s.queries.GetAgentToken(ctx, id)
	if err != nil {
		return ErrAgentTokenNotFound
	}
	n, err := s.queries.RevokeAgentToken(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAgentTokenNotFound
	}
	s.clearNetworkAgentID(ctx, tok)
	return nil
}

// Delete hard-deletes. Prefer Revoke for auditability; Delete is for cleanup
// of test/mistake tokens. Also clears the network's agent_id.
func (s *AgentTokenService) Delete(ctx context.Context, id int64) error {
	tok, err := s.queries.GetAgentToken(ctx, id)
	if err != nil {
		return ErrAgentTokenNotFound
	}
	n, err := s.queries.DeleteAgentToken(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAgentTokenNotFound
	}
	s.clearNetworkAgentID(ctx, tok)
	return nil
}

// clearNetworkAgentID nulls out the agent_id on the token's bound network,
// but ONLY if it matches the token's own agent_id (so revoking a stale token
// doesn't clobber a newer token that re-uses the network). Best-effort: a
// failure here doesn't undo the revoke/delete.
func (s *AgentTokenService) clearNetworkAgentID(ctx context.Context, tok db.AgentToken) {
	if tok.NetworkID == nil {
		return
	}
	net, err := s.queries.GetNetwork(ctx, *tok.NetworkID)
	if err != nil {
		return
	}
	if net.AgentID == nil || *net.AgentID != tok.AgentID {
		return
	}
	empty := ""
	_ = s.queries.SetNetworkAgentID(ctx, db.SetNetworkAgentIDParams{
		AgentID: &empty,
		ID:      *tok.NetworkID,
	})
}
