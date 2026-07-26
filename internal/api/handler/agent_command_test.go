// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/api/handler"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// setupCommandServer builds a server with the agent-command routes over an
// in-memory DB. The supplied network is created with the given cidr + agent_id
// so the Layer 1 boundary check can resolve it. Returns the server + queries.
func setupCommandServer(t *testing.T, cidr, agentID string) (srv *httptest.Server, queries *sqldb.Queries) {
	t.Helper()
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })

	queries = sqldb.New(dbConn)
	net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{
		Name: "lan-bound", Cidr: &cidr, Site: strPtr("site-x"),
	})
	require.NoError(t, err)
	require.NotEmpty(t, net.ID)
	// Stamp agent_id so GetNetworkByAgentID resolves this network for the
	// boundary check. (Minting a token would do this in the real admin path.)
	require.NoError(t, queries.SetNetworkAgentID(context.Background(), sqldb.SetNetworkAgentIDParams{
		AgentID: strPtr(agentID), ID: net.ID,
	}))

	cmd := handler.NewAgentCommandHandler(queries)
	r := chi.NewMux()
	r.Route("/api/v1/agents/{agentId}/commands", func(r chi.Router) {
		r.Post("/", cmd.Create)
	})
	srv = httptest.NewServer(r)
	t.Cleanup(func() { srv.Close() })
	return srv, queries
}

func postCommand(t *testing.T, srv *httptest.Server, agentID string, body map[string]interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/"+agentID+"/commands", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// strPtr returns a pointer to a copy of s — for the *string fields sqlc emits
// for nullable columns (Cidr, Site, AgentID).
func strPtr(s string) *string { return &s }

// TestAgentCommand_BoundaryCheck_Layer1 covers the center-side CIDR gate that
// prevents the issue-#19 mis-dispatch: a scan command whose targets fall outside
// the agent's bound network must be rejected at enqueue time.
func TestAgentCommand_BoundaryCheck_Layer1(t *testing.T) {
	const agentID = "agent-62"
	const cidr = "192.168.62.0/24"

	t.Run("in-network targets accepted", func(t *testing.T) {
		srv, queries := setupCommandServer(t, cidr, agentID)
		resp := postCommand(t, srv, agentID, map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{"targets": "192.168.62.0/24"},
		})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		// Confirm it was actually persisted.
		cmds, err := queries.ListPendingAgentCommands(context.Background(), sqldb.ListPendingAgentCommandsParams{
			AgentID: agentID, Limit: 10,
		})
		require.NoError(t, err)
		require.Len(t, cmds, 1)
		require.Contains(t, cmds[0].Payload, "192.168.62.0/24")
	})

	t.Run("out-of-network CIDR rejected (the issue-#19 case)", func(t *testing.T) {
		srv, queries := setupCommandServer(t, cidr, agentID)
		resp := postCommand(t, srv, agentID, map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{"targets": "192.168.63.0/24"},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		// Nothing persisted.
		cmds, err := queries.ListPendingAgentCommands(context.Background(), sqldb.ListPendingAgentCommandsParams{
			AgentID: agentID, Limit: 10,
		})
		require.NoError(t, err)
		require.Empty(t, cmds)
	})

	t.Run("mixed in/out targets rejected as a whole", func(t *testing.T) {
		srv, _ := setupCommandServer(t, cidr, agentID)
		resp := postCommand(t, srv, agentID, map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{"targets": "192.168.62.5,192.168.63.5"},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("single out-of-network IP rejected", func(t *testing.T) {
		srv, _ := setupCommandServer(t, cidr, agentID)
		resp := postCommand(t, srv, agentID, map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{"targets": "10.0.0.1"},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("no cidr configured -> degrade open (allowed)", func(t *testing.T) {
		// A network WITHOUT cidr must not lock the agent out (historical rows).
		// The check degrades to allow + warn — cidr enforcement is a separate
		// prerequisite (issue #19 前置工作).
		dbConn, err := testutil.SetupTestDBFromSchema()
		require.NoError(t, err)
		t.Cleanup(func() { dbConn.Close() })
		queries := sqldb.New(dbConn)
		net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{Name: "no-cidr"})
		require.NoError(t, err)
		require.NoError(t, queries.SetNetworkAgentID(context.Background(), sqldb.SetNetworkAgentIDParams{
			AgentID: strPtr(agentID), ID: net.ID,
		}))
		cmd := handler.NewAgentCommandHandler(queries)
		r := chi.NewMux()
		r.Post("/api/v1/agents/{agentId}/commands", cmd.Create)
		srv := httptest.NewServer(r)
		t.Cleanup(func() { srv.Close() })

		resp := postCommand(t, srv, agentID, map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{"targets": "192.168.99.0/24"},
		})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("unknown agent -> degrade open (allowed)", func(t *testing.T) {
		// An agent_id with no bound network row can't be validated. Allow +
		// warn: the agent itself will reject if it can't reach the target.
		dbConn, err := testutil.SetupTestDBFromSchema()
		require.NoError(t, err)
		t.Cleanup(func() { dbConn.Close() })
		queries := sqldb.New(dbConn)
		cmd := handler.NewAgentCommandHandler(queries)
		r := chi.NewMux()
		r.Post("/api/v1/agents/{agentId}/commands", cmd.Create)
		srv := httptest.NewServer(r)
		t.Cleanup(func() { srv.Close() })

		resp := postCommand(t, srv, "ghost-agent", map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{"targets": "192.168.99.0/24"},
		})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("invalid targets -> 400", func(t *testing.T) {
		srv, _ := setupCommandServer(t, cidr, agentID)
		resp := postCommand(t, srv, agentID, map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{"targets": "not-an-ip-or-cidr"},
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing targets is NOT a CIDR concern (allowed through)", func(t *testing.T) {
		// Empty/missing targets is the poller's own validation problem ("missing
		// targets" at execute time), not the boundary check's. Don't conflate.
		srv, _ := setupCommandServer(t, cidr, agentID)
		resp := postCommand(t, srv, agentID, map[string]interface{}{
			"command": "scan",
			"payload": map[string]interface{}{},
		})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	})
}
