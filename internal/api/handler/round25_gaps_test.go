// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service"
	scannerv2runner "mibee-steward/internal/service/scannerv2/runner"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

// TestAgentReport_NilRunnerAndBadBody pins the two pre-auth failure shapes of
// the report endpoint: no runner wired → 500; unparseable body → 400.
func TestAgentReport_NilRunnerAndBadBody(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	queries := sqldb.New(db)
	middleware.SetAgentQueries(queries)
	t.Cleanup(func() { middleware.SetAgentQueries(nil) })

	cidr := "192.168.62.0/24"
	net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{Name: "lan-62x", Cidr: &cidr})
	require.NoError(t, err)
	plaintext, hash := middleware.GenerateAgentToken()
	_, err = queries.CreateAgentToken(context.Background(), sqldb.CreateAgentTokenParams{
		AgentID: "agent-x", TokenHash: hash, NetworkID: &net.ID, Name: "x",
	})
	require.NoError(t, err)

	reportH := handler.NewAgentReportHandler(nil, queries, db, nil)
	rn := scannerv2runner.New(nil, queries, db, nil, 0, nil)
	rn.SetRepo(store.NewSQLiteRepository(db, store.Options{}, nil))
	reportReal := handler.NewAgentReportHandler(rn, queries, db, nil)
	r := chi.NewMux()
	r.Use(chimw.Recoverer)
	r.Route("/api/v1/agents", func(r chi.Router) {
		r.Use(middleware.RequireAgentToken)
		r.Post("/report-nil", reportH.Report)
		r.Post("/report", reportReal.Report)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	post := func(path, body string) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/"+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+plaintext)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	require.Equal(t, http.StatusInternalServerError, post("report-nil", `{"agent_id":"agent-x","hosts":[]}`))
	require.Equal(t, http.StatusBadRequest, post("report", "not json"))
}

// TestAgentReport_TokenWithoutNetworkRejected: a token bound to NO network
// cannot attribute devices, the report must 403 before touching the bridge.
func TestAgentReport_TokenWithoutNetworkRejected(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	queries := sqldb.New(db)
	middleware.SetAgentQueries(queries)
	t.Cleanup(func() { middleware.SetAgentQueries(nil) })

	plaintext, hash := middleware.GenerateAgentToken()
	_, err = queries.CreateAgentToken(context.Background(), sqldb.CreateAgentTokenParams{
		AgentID: "agent-unbound", TokenHash: hash, Name: "unbound",
	})
	require.NoError(t, err)

	rn := scannerv2runner.New(nil, queries, db, nil, 0, nil)
	rn.SetRepo(store.NewSQLiteRepository(db, store.Options{}, nil))
	r := chi.NewMux()
	r.Use(chimw.Recoverer)
	r.Route("/api/v1/agents", func(r chi.Router) {
		r.Use(middleware.RequireAgentToken)
		r.Post("/report", handler.NewAgentReportHandler(rn, queries, db, nil).Report)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/report",
		strings.NewReader(`{"agent_id":"agent-unbound","hosts":[]}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestAgentReport_FleetMetaClockOffsetClamp drives the fleet-status snapshot
// branch: a report with a Meta block and a STALE ScannedAt (>1d) has its
// clock offset clamped to 0 instead of poisoning the metric, and the status
// row upserts via the real AgentCommandService.
func TestAgentReport_FleetMetaClockOffsetClamp(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	queries := sqldb.New(db)
	middleware.SetAgentQueries(queries)
	t.Cleanup(func() { middleware.SetAgentQueries(nil) })

	cidr := "192.168.62.0/24"
	net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{Name: "lan-62f", Cidr: &cidr})
	require.NoError(t, err)
	plaintext, hash := middleware.GenerateAgentToken()
	_, err = queries.CreateAgentToken(context.Background(), sqldb.CreateAgentTokenParams{
		AgentID: "agent-fleet", TokenHash: hash, NetworkID: &net.ID, Name: "fleet",
	})
	require.NoError(t, err)

	rn := scannerv2runner.New(nil, queries, db, nil, 0, nil)
	rn.SetRepo(store.NewSQLiteRepository(db, store.Options{}, nil))
	fleetSvc := service.NewAgentCommandService(queries, false, false)
	r := chi.NewMux()
	r.Use(chimw.Recoverer)
	r.Route("/api/v1/agents", func(r chi.Router) {
		r.Use(middleware.RequireAgentToken)
		r.Post("/report", handler.NewAgentReportHandler(rn, queries, db, fleetSvc).Report)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	stale := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	body := `{"agent_id":"agent-fleet","network_cidr":"192.168.62.0/24","scanned_at":"` + stale +
		`","meta":{"version":"test-1.0","hostname":"agent-host","uptime_seconds":42},"hosts":[]}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/report", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The stale ScannedAt was clamped, and the fleet row landed.
	var version string
	var offset sql.NullFloat64
	require.NoError(t, db.QueryRow(
		`SELECT version, clock_offset_seconds FROM agent_status WHERE agent_id = 'agent-fleet'`).
		Scan(&version, &offset))
	require.Equal(t, "test-1.0", version)
	require.Zero(t, offset.Float64, "48h-stale ScannedAt must clamp to 0 offset")
}

// Test2FA_ErrorBranchSweep drives every TOTP error branch through the real
// auth server: bad bodies, missing fields, not-set-up enable, wrong codes,
// not-enabled verify, and wrong-password disable.
func Test2FA_ErrorBranchSweep(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "2faerr", "2faerr@test.com", "user", "Err@2026")
	token := loginAs(t, server, "2faerr", "Err@2026")

	// Verify (public): bad body / missing fields / no-totp user.
	code, _ := postPlain(t, server.URL+"/api/v1/auth/2fa/verify", "not json")
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = postPlain(t, server.URL+"/api/v1/auth/2fa/verify", `{}`)
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = postPlain(t, server.URL+"/api/v1/auth/2fa/verify", `{"user_id":1,"code":"000000"}`)
	require.Equal(t, http.StatusBadRequest, code, "user 1 has no TOTP row → not configured")

	// Enable before setup → 400; empty code → 400; bad body → 400.
	resp := authPost(t, server.URL+"/api/v1/auth/2fa/enable", token, `{"code":"123456"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/enable", token, `{}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/enable", token, "not json")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Disable: bad body / empty password / wrong password.
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/disable", token, "not json")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/disable", token, `{}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/disable", token, `{"password":"wrong"}`)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Setup, then verify against the setup-but-NOT-enabled row.
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/setup", token, `{}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var setup struct {
		Secret string `json:"secret"`
	}
	decodeJSON(t, resp, &setup)
	require.NotEmpty(t, setup.Secret)

	code, _ = postPlain(t, server.URL+"/api/v1/auth/2fa/verify",
		`{"user_id":`+userIDJSON(t, db, "2faerr")+`,"code":"123456"}`)
	require.Equal(t, http.StatusBadRequest, code, "secret exists but not enabled → 2FA is not enabled")

	// Enable with a WRONG code → 422 (the bypass guard, at the route level).
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/enable", token, `{"code":"000000"}`)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)

	// Enable for real, then verify with a wrong code → 422.
	valid, err := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, err)
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/enable", token, `{"code":"`+valid+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	code, _ = postPlain(t, server.URL+"/api/v1/auth/2fa/verify",
		`{"user_id":`+userIDJSON(t, db, "2faerr")+`,"code":"000000"}`)
	require.Equal(t, http.StatusUnprocessableEntity, code)

	// Wrong password on disable AFTER enable.
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/disable", token, `{"password":"wrong"}`)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func postPlain(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

func userIDJSON(t *testing.T, db *sql.DB, username string) string {
	t.Helper()
	var id int64
	require.NoError(t, db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id))
	return strconv.FormatInt(id, 10)
}
