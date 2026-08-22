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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func setupAgentTokenService(t *testing.T) (*AgentTokenService, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	return NewAgentTokenService(queries), queries
}

// fixedMinter returns a deterministic (plaintext, hash) pair so tests can
// assert what was stored without knowing the hash function.
func fixedMinter(plaintext, hash string) TokenMinter {
	return func() (string, string) { return plaintext, hash }
}

func mustCreateNetwork(t *testing.T, queries *db.Queries, name string) db.Network {
	t.Helper()
	cidr := "10.0.0.0/24"
	net, err := queries.CreateNetwork(context.Background(), db.CreateNetworkParams{Name: name, Cidr: &cidr})
	require.NoError(t, err)
	return net
}

func TestAgentTokenService_CreateStampsNetworkAgentID(t *testing.T) {
	svc, queries := setupAgentTokenService(t)
	ctx := context.Background()
	net := mustCreateNetwork(t, queries, "lan-a")

	resp, err := svc.Create(ctx, domain.CreateAgentTokenRequest{
		AgentID: "agent-a", NetworkID: net.ID,
	}, fixedMinter("plain", "hash"))
	require.NoError(t, err)
	require.Equal(t, "plain", resp.Token, "one-time plaintext returned to the caller")
	require.Equal(t, "agent-a", resp.AgentID)

	after, err := queries.GetNetwork(ctx, net.ID)
	require.NoError(t, err)
	require.NotNil(t, after.AgentID)
	require.Equal(t, "agent-a", *after.AgentID, "network marked agent-managed (heartbeat exclusion + lease sweeper scope)")

	row, err := queries.GetAgentTokenByHash(ctx, "hash")
	require.NoError(t, err)
	require.Equal(t, "agent-a", row.AgentID, "stored row holds the hash, never the plaintext")
}

func TestAgentTokenService_CreateValidation(t *testing.T) {
	svc, queries := setupAgentTokenService(t)
	ctx := context.Background()
	net := mustCreateNetwork(t, queries, "lan-b")

	_, err := svc.Create(ctx, domain.CreateAgentTokenRequest{NetworkID: net.ID}, fixedMinter("p", "h"))
	require.ErrorIs(t, err, ErrAgentIDRequired)

	// Unknown network → invalid (FK would dangle).
	_, err = svc.Create(ctx, domain.CreateAgentTokenRequest{AgentID: "a", NetworkID: 999}, fixedMinter("p", "h"))
	require.ErrorIs(t, err, ErrNetworkIDInvalid)

	// Duplicate agent_id → conflict sentinel.
	_, err = svc.Create(ctx, domain.CreateAgentTokenRequest{AgentID: "dup", NetworkID: net.ID}, fixedMinter("p1", "h1"))
	require.NoError(t, err)
	_, err = svc.Create(ctx, domain.CreateAgentTokenRequest{AgentID: "dup", NetworkID: net.ID}, fixedMinter("p2", "h2"))
	require.ErrorIs(t, err, ErrAgentIDTaken)
}

func TestAgentTokenService_RevokeClearsMatchingNetworkAgentID(t *testing.T) {
	svc, queries := setupAgentTokenService(t)
	ctx := context.Background()
	net := mustCreateNetwork(t, queries, "lan-c")

	_, err := svc.Create(ctx, domain.CreateAgentTokenRequest{AgentID: "agent-c", NetworkID: net.ID}, fixedMinter("p", "h"))
	require.NoError(t, err)
	tok, err := queries.GetAgentTokenByHash(ctx, "h")
	require.NoError(t, err)

	require.NoError(t, svc.Revoke(ctx, tok.ID))

	after, err := queries.GetNetwork(ctx, net.ID)
	require.NoError(t, err)
	require.NotNil(t, after.AgentID)
	require.Equal(t, "", *after.AgentID, "revoke clears the agent_id so the center resumes local probing")
}

func TestAgentTokenService_RevokeKeepsNewerClaimant(t *testing.T) {
	svc, queries := setupAgentTokenService(t)
	ctx := context.Background()
	net := mustCreateNetwork(t, queries, "lan-d")

	// A stale token claims the network, then a NEWER token re-claims it.
	_, err := svc.Create(ctx, domain.CreateAgentTokenRequest{AgentID: "old-agent", NetworkID: net.ID}, fixedMinter("p1", "h1"))
	require.NoError(t, err)
	_, err = svc.Create(ctx, domain.CreateAgentTokenRequest{AgentID: "new-agent", NetworkID: net.ID}, fixedMinter("p2", "h2"))
	require.NoError(t, err)

	stale, err := queries.GetAgentTokenByHash(ctx, "h1")
	require.NoError(t, err)
	require.NoError(t, svc.Revoke(ctx, stale.ID))

	after, err := queries.GetNetwork(ctx, net.ID)
	require.NoError(t, err)
	require.NotNil(t, after.AgentID)
	require.Equal(t, "new-agent", *after.AgentID, "revoking the stale token must NOT clobber the newer claimant")
}

func TestAgentTokenService_DeleteRemovesRowAndClearsNetwork(t *testing.T) {
	svc, queries := setupAgentTokenService(t)
	ctx := context.Background()
	net := mustCreateNetwork(t, queries, "lan-e")

	_, err := svc.Create(ctx, domain.CreateAgentTokenRequest{AgentID: "agent-e", NetworkID: net.ID}, fixedMinter("p", "h"))
	require.NoError(t, err)
	tok, err := queries.GetAgentTokenByHash(ctx, "h")
	require.NoError(t, err)

	require.NoError(t, svc.Delete(ctx, tok.ID))

	_, err = queries.GetAgentToken(ctx, tok.ID)
	require.Error(t, err, "hard delete removes the row")

	after, err := queries.GetNetwork(ctx, net.ID)
	require.NoError(t, err)
	require.Equal(t, "", *after.AgentID)

	require.ErrorIs(t, svc.Delete(ctx, tok.ID), ErrAgentTokenNotFound, "second delete → not-found sentinel")
}

func TestNetworkService_CRUDAndDuplicateName(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewNetworkService(queries, conn)
	ctx := context.Background()

	created, err := svc.Create(ctx, NetworkInput{Name: "branch-x"})
	require.NoError(t, err)
	require.Equal(t, "branch-x", created.Name)

	_, err = svc.Create(ctx, NetworkInput{Name: "branch-x"})
	require.ErrorIs(t, err, ErrNetworkNameTaken)

	_, err = svc.Create(ctx, NetworkInput{Name: "  "})
	require.ErrorIs(t, err, ErrNetworkNameRequired)

	site := "HQ"
	updated, err := svc.Update(ctx, created.ID, NetworkInput{Name: "branch-y", Site: &site})
	require.NoError(t, err)
	require.Equal(t, "branch-y", updated.Name)
	require.NotNil(t, updated.Site)
	require.Equal(t, "HQ", *updated.Site)

	_, err = svc.Update(ctx, 999, NetworkInput{Name: "ghost"})
	require.ErrorIs(t, err, ErrNetworkNotFound)

	require.NoError(t, svc.Delete(ctx, created.ID))
	require.ErrorIs(t, svc.Delete(ctx, created.ID), ErrNetworkNotFound)
}

func TestAgentCommandService_EnqueueBoundaryRejection(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewAgentCommandService(queries, false)
	ctx := context.Background()

	cidr := "192.168.62.0/24"
	net, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "lan-62", Cidr: &cidr})
	require.NoError(t, err)
	agentID := "agent-62"
	require.NoError(t, queries.SetNetworkAgentID(ctx, db.SetNetworkAgentIDParams{AgentID: &agentID, ID: net.ID}))

	// In-network target is accepted.
	cmd, err := svc.Enqueue(ctx, "agent-62", "scan", map[string]interface{}{"targets": "192.168.62.0/24"})
	require.NoError(t, err)
	require.Equal(t, "scan", cmd.Command)

	// Out-of-network target is a typed boundary error whose message names the
	// offending IPs (surfaced verbatim as the 400 body).
	_, err = svc.Enqueue(ctx, "agent-62", "scan", map[string]interface{}{"targets": "192.168.63.1"})
	require.Error(t, err)
	var boundary *BoundaryError
	require.ErrorAs(t, err, &boundary)
	require.Contains(t, boundary.Error(), "outside agent network")
	require.Contains(t, boundary.Error(), "192.168.63.1")

	// Unknown agent (no network binding) degrades open — allowed.
	_, err = svc.Enqueue(ctx, "agent-unknown", "scan", map[string]interface{}{"targets": "10.1.1.1"})
	require.NoError(t, err)

	// Empty command defaults to "scan".
	cmd, err = svc.Enqueue(ctx, "agent-unknown", "", map[string]interface{}{})
	require.NoError(t, err)
	require.Equal(t, "scan", cmd.Command)
}

func TestScannerResultService_BulkDeleteBeforeValidation(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewScannerResultService(queries)

	// Future date → rejected.
	_, err = svc.BulkDeleteBefore(context.Background(), time.Now().Add(24*time.Hour))
	require.ErrorIs(t, err, ErrBeforeDateNotPast)

	// Valid past date → deletes (empty table: 0 rows, no error).
	n, err := svc.BulkDeleteBefore(context.Background(), time.Now().Add(-48*time.Hour))
	require.NoError(t, err)
	require.Zero(t, n)
}
