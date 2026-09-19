// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// closedTestDB opens a schema-complete in-memory DB and closes it right away:
// every later query fails with "sql: database is closed", which is exactly the
// deterministic failure the handlers' 500 branches need.
func closedTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	return conn
}

func TestDashboardHandler_ErrorBranchSweep(t *testing.T) {
	conn := closedTestDB(t)
	h := NewDashboardHandler(service.NewDashboardService(conn, &config.Config{}))

	rec := httptest.NewRecorder()
	h.ListConfigs(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/configs", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	rec = httptest.NewRecorder()
	h.Overview(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	// CreateConfig: bad JSON → 400, invalid widget → 400, valid widget but
	// closed DB → 500.
	rec = httptest.NewRecorder()
	h.CreateConfig(rec, reqWithBodyParams(http.MethodPost, "/api/v1/dashboard/configs", "not json", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.CreateConfig(rec, reqWithBodyParams(http.MethodPost, "/api/v1/dashboard/configs",
		`{"name":"","type":"gauge","query":"up"}`, nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.CreateConfig(rec, reqWithBodyParams(http.MethodPost, "/api/v1/dashboard/configs",
		`{"name":"w","type":"hexagon","data_source":"prometheus","query":"up"}`, nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.CreateConfig(rec, reqWithBodyParams(http.MethodPost, "/api/v1/dashboard/configs",
		`{"name":"w","type":"gauge","data_source":"prometheus","query":"up"}`, nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	// UpdateConfig: bad ID → 400, bad JSON → 400, bad widget → 400, DB → 500.
	for _, tc := range []struct {
		id     string
		body   string
		wantCd int
	}{
		{id: "abc", body: `{}`, wantCd: http.StatusBadRequest},
		{id: "1", body: `not json`, wantCd: http.StatusBadRequest},
		{id: "1", body: `{"name":"w","type":"gauge","data_source":"weird","query":"up"}`, wantCd: http.StatusBadRequest},
		{id: "1", body: `{"name":"w","type":"gauge","data_source":"prometheus","query":"up"}`, wantCd: http.StatusInternalServerError},
	} {
		rec = httptest.NewRecorder()
		h.UpdateConfig(rec, reqWithBodyParams(http.MethodPut, "/api/v1/dashboard/configs/1", tc.body,
			map[string]string{"id": tc.id}))
		require.Equal(t, tc.wantCd, rec.Code, "id=%q body=%q", tc.id, tc.body)
	}

	// DeleteConfig: bad ID → 400, DB failure → 500.
	rec = httptest.NewRecorder()
	h.DeleteConfig(rec, reqWithBodyParams(http.MethodDelete, "/api/v1/dashboard/configs/x", "",
		map[string]string{"id": "x"}))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = httptest.NewRecorder()
	h.DeleteConfig(rec, reqWithBodyParams(http.MethodDelete, "/api/v1/dashboard/configs/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestDashboardHandler_QueryProxyBranches walks the PromQL proxy: 400 on
// missing params, 502 "unreachable" when the configured data source refuses
// connections, 502 generic when no data source is configured at all.
func TestDashboardHandler_QueryProxyBranches(t *testing.T) {
	dead := &config.Config{}
	dead.Dashboard.DataSourceType = "prometheus"
	dead.Dashboard.PrometheusURL = "http://127.0.0.1:1"
	hDead := NewDashboardHandler(service.NewDashboardService(closedTestDB(t), dead))

	unconf := &config.Config{}
	hUnconf := NewDashboardHandler(service.NewDashboardService(closedTestDB(t), unconf))

	rec := httptest.NewRecorder()
	hDead.Query(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/query", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	hDead.Query(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/query?query=up", nil))
	require.Equal(t, http.StatusBadGateway, rec.Code)

	rec = httptest.NewRecorder()
	hUnconf.Query(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/query?query=up", nil))
	require.Equal(t, http.StatusBadGateway, rec.Code)

	// QueryRange: missing query → 400; missing start/end/step → 400; the same
	// two 502 flavors.
	for _, q := range []string{
		"/api/v1/dashboard/query_range",
		"/api/v1/dashboard/query_range?query=up",
		"/api/v1/dashboard/query_range?query=up&start=1&end=2",
	} {
		rec = httptest.NewRecorder()
		hDead.QueryRange(rec, httptest.NewRequest(http.MethodGet, q, nil))
		require.Equal(t, http.StatusBadRequest, rec.Code, "q=%s", q)
	}
	rec = httptest.NewRecorder()
	hDead.QueryRange(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/dashboard/query_range?query=up&start=1&end=2&step=15", nil))
	require.Equal(t, http.StatusBadGateway, rec.Code)
	rec = httptest.NewRecorder()
	hUnconf.QueryRange(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/dashboard/query_range?query=up&start=1&end=2&step=15", nil))
	require.Equal(t, http.StatusBadGateway, rec.Code)
}

// TestScannerResultHandler_ClosedDBSweep pins the 500 branches on the scan
// result/run endpoints — global and scope-restricted variants — against a
// closed DB so every query fails deterministically.
func TestScannerResultHandler_ClosedDBSweep(t *testing.T) {
	conn := closedTestDB(t)
	queries := sqldb.New(conn)
	h := NewScannerResultHandler(queries, conn, service.NewScannerResultService(queries))

	scoped := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), domain.ContextKeyUserScope,
			domain.Scope{NetworkIDs: []int64{1}}))
	}

	rec := httptest.NewRecorder()
	h.ListResults(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scanner/results", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	scopedReq := scoped(httptest.NewRequest(http.MethodGet, "/api/v1/scanner/results?sort=ip&order=asc", nil))
	rec = httptest.NewRecorder()
	h.ListResults(rec, scopedReq)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	rec = httptest.NewRecorder()
	h.GetResult(rec, reqWithBodyParams(http.MethodGet, "/api/v1/scanner/results/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	rec = httptest.NewRecorder()
	h.ListRuns(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scanner/runs", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	scopedRuns := scoped(httptest.NewRequest(http.MethodGet, "/api/v1/scanner/runs", nil))
	rec = httptest.NewRecorder()
	h.ListRuns(rec, scopedRuns)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	rec = httptest.NewRecorder()
	h.GetRun(rec, reqWithBodyParams(http.MethodGet, "/api/v1/scanner/runs/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	// BulkDeleteResults: missing before_date → 400; future date → 400
	// (validated before any DB access); past date + closed DB → 500.
	rec = httptest.NewRecorder()
	h.BulkDeleteResults(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scanner/results/bulk-delete", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.BulkDeleteResults(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/scanner/results/bulk-delete?before_date=tomorrow", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.BulkDeleteResults(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/scanner/results/bulk-delete?before_date=2999-01-01T00:00:00Z", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.BulkDeleteResults(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/scanner/results/bulk-delete?before_date=2020-01-01T00:00:00Z", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	// ExportScanResults: missing/invalid task_id → 400; global scope + closed
	// DB → 500 on the fetch; restricted scope + closed DB → the scope check
	// can't confirm the task → indistinguishable-from-absent 404 (#138 2c).
	rec = httptest.NewRecorder()
	h.ExportScanResults(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scanner/results/export", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.ExportScanResults(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/scanner/results/export?task_id=abc", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.ExportScanResults(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/scanner/results/export?task_id=1", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	scopedExport := scoped(httptest.NewRequest(http.MethodGet,
		"/api/v1/scanner/results/export?task_id=1", nil))
	rec = httptest.NewRecorder()
	h.ExportScanResults(rec, scopedExport)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestScannerResultHelpers pins the SNMP field extractor's tails: empty and
// unparseable snmp_data both yield zero fields.
func TestScannerResultHelpers(t *testing.T) {
	name, descr, brand, devType, loc := extractSNMPFields("", "")
	require.Empty(t, name)
	require.Empty(t, descr)
	require.Empty(t, brand)
	require.Empty(t, devType)
	require.Empty(t, loc)

	name, _, _, _, _ = extractSNMPFields("{not json", "")
	require.Empty(t, name)

	name, _, _, _, _ = extractSNMPFields(`{"sys_name":"sw-core"}`, "")
	require.Equal(t, "sw-core", name)
}
