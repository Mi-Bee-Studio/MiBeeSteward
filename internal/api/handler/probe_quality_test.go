// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service/probetarget"
	"mibee-steward/internal/testutil"
)

// qualityHandler builds the quality-family endpoints over a real
// service + schema so the handlers exercise their true serialization paths.
func qualityHandler(t *testing.T) *httptest.Server {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)
	svc := probetarget.NewQualityService(queries,
		config.ProbeQualityConfig{Groups: config.DefaultQualityGroups()},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := NewProbeQualityHandler(svc)

	r := chi.NewMux()
	r.Get("/api/v1/probe-quality", h.GetQuality)
	r.Get("/api/v1/probe-quality/history", h.GetQualityHistory)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// TestQualityEndpoints_Success pins the happy path of all three endpoints:
// 200 plus the payload's discriminating top-level fields. An empty database
// must still produce a well-formed report — the UI renders "no data", never a
// blank panel.
func TestQualityEndpoints_Success(t *testing.T) {
	srv := qualityHandler(t)
	cases := []struct {
		name  string
		url   string
		field string
	}{
		{"quality", "/api/v1/probe-quality?window=60", "categories"},
		{"quality default window", "/api/v1/probe-quality", "window_minutes"},
		{"history", "/api/v1/probe-quality/history?days=30", "days"},
		{"history default days", "/api/v1/probe-quality/history", "days"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.url)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			require.Contains(t, body, tc.field, "%s must carry %q", tc.name, tc.field)
		})
	}
}

// TestQualityEndpoints_RejectsBadQuery pins every validation branch: each
// endpoint clamps its own query parameter and must reject out-of-range and
// unparseable values with 400 before touching the database.
func TestQualityEndpoints_RejectsBadQuery(t *testing.T) {
	srv := qualityHandler(t)
	cases := []string{
		// quality clamps its window to 5..1440 minutes.
		"/api/v1/probe-quality?window=4",
		"/api/v1/probe-quality?window=1441",
		"/api/v1/probe-quality?window=abc",
		// history accepts exactly 7 or 30 days.
		"/api/v1/probe-quality/history?days=8",
		"/api/v1/probe-quality/history?days=0",
		"/api/v1/probe-quality/history?days=nope",
	}
	for _, url := range cases {
		t.Run(url, func(t *testing.T) {
			resp, err := http.Get(srv.URL + url)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, url)
		})
	}
}

// TestQualityEndpoints_ClosedDB pins the 500 branch: each handler surfaces a
// service error rather than panicking when the database is gone (the
// degraded-shutdown case the error branches exist for).
func TestQualityEndpoints_ClosedDB(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	queries := sqldb.New(conn)
	svc := probetarget.NewQualityService(queries,
		config.ProbeQualityConfig{Groups: config.DefaultQualityGroups()},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := NewProbeQualityHandler(svc)
	require.NoError(t, conn.Close())

	r := chi.NewMux()
	r.Get("/api/v1/probe-quality", h.GetQuality)
	r.Get("/api/v1/probe-quality/history", h.GetQualityHistory)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	for _, url := range []string{
		"/api/v1/probe-quality",
		"/api/v1/probe-quality/history",
	} {
		t.Run(url, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+url, nil)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusInternalServerError, resp.StatusCode, url)
		})
	}
}
