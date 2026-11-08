// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/probeext"
	"mibee-steward/internal/testutil"
)

// newProbeExtService builds a real probeext service over the full test
// schema (the agent report handlers own nothing but the auth+decode shell,
// so their tests go through the real ingest path).
func newProbeExtService(t *testing.T) (*probeext.Service, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	store, err := probeext.OpenStore(filepath.Join(t.TempDir(), "probe_ext.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	queries := db.New(conn)
	return probeext.NewService(config.ProbeConfig{}, store, queries, nil), queries
}

// agentCtxReq builds a POST with the agent identity RequireAgentToken would
// have injected (handlers trust only that context).
func agentCtxReq(t *testing.T, url, body string, withIdentity bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if withIdentity {
		ctx := context.WithValue(r.Context(), domain.ContextKeyAgentID, "agent-62")
		return r.WithContext(ctx)
	}
	return r
}

// TestAgentEgressReportHandler pins the endpoint shell: identity required,
// malformed body 400, empty batch fast-200, real round accepted under the
// reporting agent's identity.
func TestAgentEgressReportHandler(t *testing.T) {
	svc, _ := newProbeExtService(t)
	h := NewAgentEgressReportHandler(svc)

	w := httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/egress-report", `{}`, false))
	require.Equal(t, http.StatusUnauthorized, w.Code)

	w = httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/egress-report", `{not json`, true))
	require.Equal(t, http.StatusBadRequest, w.Code)

	w = httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/egress-report", `{"rounds":[]}`, true))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"accepted":0`)

	round := `{"rounds":[{"round_at":"` + time.Now().UTC().Format(time.RFC3339) +
		`","local":{"iface":"end0","gateway_ip":"192.168.2.1"},"results":[` +
		`{"source":"icanhazip","kind":"http","ok":true,"ip":"93.184.216.34","ms":12}]}]}`
	w = httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/egress-report", round, true))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"accepted":1`)

	paths, err := svc.EgressSnapshot(context.Background())
	require.NoError(t, err)
	require.Len(t, paths, 1)
	require.Equal(t, domain.ProbeVantageAgentPrefix+"agent-62", paths[0].Vantage)
}

// TestAgentPathReportHandler pins the path endpoint shell plus the
// unknown-target skip semantics.
func TestAgentPathReportHandler(t *testing.T) {
	svc, queries := newProbeExtService(t)
	h := NewAgentPathReportHandler(svc)

	w := httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/path-report", `{}`, false))
	require.Equal(t, http.StatusUnauthorized, w.Code)

	w = httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/path-report", `{bad`, true))
	require.Equal(t, http.StatusBadRequest, w.Code)

	w = httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/path-report", `{"paths":[]}`, true))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"accepted":0`)

	// A live target row plus an unknown id: one accepted, one skipped.
	_, err := queries.CreateProbeTarget(context.Background(), db.CreateProbeTargetParams{
		Name: "web", Module: "http", Target: "http://x.example/",
		Vantage:         domain.ProbeVantageAgentPrefix + "agent-62",
		IntervalSeconds: 300, TimeoutSeconds: 10,
		Source:          domain.ProbeSourceManual,
	})
	require.NoError(t, err)
	sample := `{"paths":[{"target_id":1,"end_state":"reached","traced_at":"2026-11-08T08:00:00Z"},` +
		`{"target_id":9999,"end_state":"error","traced_at":"2026-11-08T08:00:00Z"}]}`
	w = httptest.NewRecorder()
	h.Report(w, agentCtxReq(t, "/api/v1/agents/path-report", sample, true))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"accepted":1`)
}
