// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/probetarget"
	"mibee-steward/internal/testutil"
)

// TestAgentCommand_UnauthedBranches: Poll/FleetStatus/ProbeReport mounted
// WITHOUT the agent-token middleware answer 401 with their distinct messages.
func TestAgentCommand_UnauthedBranches(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)

	cmdH := handler.NewAgentCommandHandler(queries, service.NewAgentCommandService(queries, false, false), nil)
	probeH := handler.NewAgentProbeReportHandler(probetarget.New(queries, nil))

	r := chi.NewMux()
	r.Use(chimw.Recoverer)
	r.Get("/api/v1/agents/commands", cmdH.Poll)
	r.Get("/api/v1/agents/status", cmdH.FleetStatus)
	r.Post("/api/v1/agents/probe-report", probeH.Report)
	srv := httptest.NewServer(r)
	t.Cleanup(func() { srv.Close() })

	resp, err := http.Get(srv.URL + "/api/v1/agents/commands")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, err = http.Get(srv.URL + "/api/v1/agents/status")
	require.NoError(t, err)
	resp.Body.Close()
	// FleetStatus without agent context: it doesn't read the context, answers 200.
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Post(srv.URL+"/api/v1/agents/probe-report", "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_PasswordPolicyEndpoint: the public policy endpoint mirrors the
// effective policy (pre-auth, #332).
func TestAuth_PasswordPolicyEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)
	resp, err := http.Get(server.URL + "/api/v1/auth/password-policy")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "min_length")
}
