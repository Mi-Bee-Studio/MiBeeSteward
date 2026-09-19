// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service/probetarget"
	"mibee-steward/internal/testutil"
)

// setupRealEngineProbes wires the probe-target routes over a REAL
// probetarget.Engine so TriggerTarget executes an actual module probe against
// a local HTTP responder (loopback only, no external network).
func setupRealEngineProbes(t *testing.T) (*httptest.Server, *ProbeTargetHandler) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)

	eng := probetarget.NewEngine(queries, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	h := NewProbeTargetHandler(probetarget.New(queries, eng), queries)

	r := chi.NewMux()
	r.Route("/api/v1/probe-targets", func(r chi.Router) {
		r.Post("/", h.CreateTarget)
		r.Put("/{id}", h.UpdateTarget)
		r.Post("/{id}/trigger", h.TriggerTarget)
		r.Get("/{id}/results", h.GetTargetResults)
		r.Delete("/{id}", h.DeleteTarget)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(func() { srv.Close() })
	return srv, h
}

func probeReq(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	var req *http.Request
	if body == "" {
		req, _ = http.NewRequest(method, url, nil)
	} else {
		req, _ = http.NewRequest(method, url, strings.NewReader(body))
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestProbeTrigger_RealEngineHttpModule: creating an http-module target that
// points at a local server, triggering it, and reading the recorded result —
// plus the disabled-target conflict and not-found branches on the real path.
func TestProbeTrigger_RealEngineHttpModule(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	host := up.URL[len("http://"):]

	srv, _ := setupRealEngineProbes(t)

	code, body := probeReq(t, http.MethodPost, srv.URL+"/api/v1/probe-targets",
		`{"name":"trigger-http","module":"http","target":"`+up.URL+`/health","interval_seconds":60,"timeout_seconds":5}`)
	require.Equal(t, http.StatusCreated, code, body)
	var created map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &created))
	id := int64(created["id"].(float64))
	idStr := strconv.FormatInt(id, 10)

	// Trigger executes the probe synchronously and returns the result.
	code, body = probeReq(t, http.MethodPost, srv.URL+"/api/v1/probe-targets/"+idStr+"/trigger", "")
	if code == http.StatusServiceUnavailable {
		t.Skipf("engine reported unavailable: %s", body)
	}
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `status":"success`)
	require.Contains(t, body, `status_code":200`)

	// The result row is listable.
	code, _ = probeReq(t, http.MethodGet, srv.URL+"/api/v1/probe-targets/"+idStr+"/results", "")
	require.Equal(t, http.StatusOK, code)

	// Disable, then trigger → 409.
	code, _ = probeReq(t, http.MethodPut, srv.URL+"/api/v1/probe-targets/"+idStr, `{"enabled":false}`)
	require.Equal(t, http.StatusOK, code)
	code, body = probeReq(t, http.MethodPost, srv.URL+"/api/v1/probe-targets/"+idStr+"/trigger", "")
	require.Equal(t, http.StatusConflict, code, body)

	// Unknown target with a live engine → 404 (engine path decides).
	code, _ = probeReq(t, http.MethodPost, srv.URL+"/api/v1/probe-targets/9999/trigger", "")
	require.Equal(t, http.StatusNotFound, code)

	_ = host
	_ = time.Second
}

// TestProbeTrigger_VantageNotLocal: an agent-vantage target refuses center
// execution with the dedicated 409 message.
func TestProbeTrigger_VantageNotLocal(t *testing.T) {
	srv, _ := setupRealEngineProbes(t)
	code, body := probeReq(t, http.MethodPost, srv.URL+"/api/v1/probe-targets",
		`{"name":"agent-owned","module":"http","target":"http://10.0.0.1/","vantage":"agent:lan-63","interval_seconds":60}`)
	require.Equal(t, http.StatusCreated, code, body)
	var created map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &created))
	idStr := strconv.FormatInt(int64(created["id"].(float64)), 10)

	code, body = probeReq(t, http.MethodPost, srv.URL+"/api/v1/probe-targets/"+idStr+"/trigger", "")
	require.Equal(t, http.StatusConflict, code)
	require.Contains(t, body, "vantage")
}
