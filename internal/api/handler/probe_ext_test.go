// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service/probeext"
	"mibee-steward/internal/testutil"
)

// setupProbeExt wires the egress/path endpoints over a real probeext service
// (side store in a temp dir, main DB from the full schema) so the handlers
// exercise their true serialization paths.
func setupProbeExt(t *testing.T) (*httptest.Server, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)

	store, err := probeext.OpenStore(filepath.Join(t.TempDir(), "probe_ext.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	cfg := config.ProbeConfig{
		Egress: config.ProbeEgressConfig{Enabled: false},
		Trace:  config.ProbeTraceConfig{Categories: []string{"external"}, IntervalMinutes: 30, MaxTTL: 8, PerHopMs: 200, Concurrency: 1},
	}
	svc := probeext.NewService(cfg, store, queries, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := NewProbeExtHandler(svc)

	r := chi.NewMux()
	r.Get("/api/v1/probe-egress", h.Egress)
	r.Get("/api/v1/probe-paths", h.Paths)
	r.Get("/api/v1/probe-targets/{id}/paths", h.TargetPaths)
	r.Post("/api/v1/probe-targets/{id}/trace", h.TraceNow)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, conn
}

// TestProbeExtEndpoints pins the four endpoints' envelopes: empty shapes,
// the manual trace against a loopback target, per-target history, and the
// invalid-id rejection.
func TestProbeExtEndpoints(t *testing.T) {
	srv, conn := setupProbeExt(t)

	getJSON := func(path string) (int, map[string]any) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		require.NoError(t, err)
		defer resp.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return resp.StatusCode, body
	}

	// Empty state: both snapshots return their empty arrays, not nulls.
	code, eg := getJSON("/api/v1/probe-egress")
	require.Equal(t, 200, code)
	require.Equal(t, []any{}, eg["vantages"])
	code, ps := getJSON("/api/v1/probe-paths")
	require.Equal(t, 200, code)
	require.Equal(t, []any{}, ps["paths"])

	// One external target over loopback; manual trace through the endpoint.
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer site.Close()
	res, err := conn.ExecContext(context.Background(),
		`INSERT INTO probe_targets (name, module, target, source) VALUES ('local', 'http', ?, 'manual')`, site.URL)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)

	resp, err := http.Post(srv.URL+"/api/v1/probe-targets/"+itoa(id)+"/trace", "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var sample map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sample))
	require.Equal(t, "reached", sample["end_state"])
	require.Equal(t, "manual", sample["trigger"])
	require.EqualValues(t, 1, sample["reached_ttl"])

	// Snapshots now carry the sample with target enrichment.
	_, ps = getJSON("/api/v1/probe-paths")
	list := ps["paths"].([]any)
	require.Len(t, list, 1)
	row := list[0].(map[string]any)
	require.Equal(t, "local", row["target_name"])
	require.Equal(t, "http", row["module"])

	// Per-target history returns the same sample.
	code, hist := getJSON("/api/v1/probe-targets/" + itoa(id) + "/paths")
	require.Equal(t, 200, code)
	require.Len(t, hist["paths"].([]any), 1)

	// Unknown (but valid) id: 404 through the service error path.
	resp3, err := http.Post(srv.URL+"/api/v1/probe-targets/424242/trace", "", nil)
	require.NoError(t, err)
	defer resp3.Body.Close()
	require.Equal(t, 404, resp3.StatusCode)

	// Invalid ids are rejected without touching the service.
	resp2, err := http.Post(srv.URL+"/api/v1/probe-targets/notanumber/trace", "", nil)
	require.NoError(t, err)
	require.Equal(t, 400, resp2.StatusCode)
	resp2.Body.Close()
	code, _ = getJSON("/api/v1/probe-targets/-3/paths")
	require.Equal(t, 400, code)
}
