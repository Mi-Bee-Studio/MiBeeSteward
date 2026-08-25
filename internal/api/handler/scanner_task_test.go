// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2/taskservice"
	"mibee-steward/internal/testutil"
)

// These tests pin ScannerTaskHandler's HTTP error→status mapping (#171). The
// underlying taskservice is covered by taskservice_test.go (incl. the
// scheduler-coupled paths, #205); this locks the thin adapter: create/list/get
// CRUD + the ErrScanTaskNotFound→404 mapping. A nil scheduler is fine — CRUD
// doesn't dispatch scans.

const validScanTaskBody = `{"name":"nightly","targets":"192.168.1.0/24","cron_expr":"0 2 * * *","timeout":60,"concurrent_hosts":16,"pipeline_config":{"icmp":{"enabled":true,"timeout":2}}}`

func setupScannerTaskHandler(t *testing.T) (*ScannerTaskHandler, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	return NewScannerTaskHandler(taskservice.New(queries, conn, nil, false)), queries
}

func TestScannerTaskHandler_CreateThenGet(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTask(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scanner/tasks", strings.NewReader(validScanTaskBody)))
	require.Equal(t, http.StatusCreated, rec.Code)

	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := int64(created["id"].(float64))

	rec = httptest.NewRecorder()
	h.GetTask(rec, reqWithURLParam(http.MethodGet, "/api/v1/scanner/tasks/"+strconv.FormatInt(id, 10), "", strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestScannerTaskHandler_Create_InvalidBody(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)
	rec := httptest.NewRecorder()
	h.CreateTask(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scanner/tasks", strings.NewReader("not-json")))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestScannerTaskHandler_GetTask_NotFound(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)
	rec := httptest.NewRecorder()
	h.GetTask(rec, reqWithURLParam(http.MethodGet, "/api/v1/scanner/tasks/999", "", "999"))
	require.Equal(t, http.StatusNotFound, rec.Code, "missing task → 404")
}

func TestScannerTaskHandler_ListTasks(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)
	// Seed two tasks.
	for _, body := range []string{
		`{"name":"a","targets":"10.0.0.0/24","cron_expr":"0 * * * *","timeout":60,"concurrent_hosts":8,"pipeline_config":{"icmp":{"enabled":true,"timeout":2}}}`,
		`{"name":"b","targets":"10.0.1.0/24","cron_expr":"0 * * * *","timeout":60,"concurrent_hosts":8,"pipeline_config":{"icmp":{"enabled":true,"timeout":2}}}`,
	} {
		rec := httptest.NewRecorder()
		h.CreateTask(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scanner/tasks", strings.NewReader(body)))
		require.Equal(t, http.StatusCreated, rec.Code)
	}

	rec := httptest.NewRecorder()
	h.ListTasks(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scanner/tasks?limit=10", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var list map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&list))
	require.EqualValues(t, 2, list["total"], "both seeded tasks returned")
}

func TestScannerTaskHandler_DeleteThenGetNotFound(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTask(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scanner/tasks", strings.NewReader(validScanTaskBody)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := strconv.FormatInt(int64(created["id"].(float64)), 10)

	rec = httptest.NewRecorder()
	h.DeleteTask(rec, reqWithURLParam(http.MethodDelete, "/api/v1/scanner/tasks/"+id, "", id))
	require.Equal(t, http.StatusNoContent, rec.Code)

	rec = httptest.NewRecorder()
	h.GetTask(rec, reqWithURLParam(http.MethodGet, "/api/v1/scanner/tasks/"+id, "", id))
	require.Equal(t, http.StatusNotFound, rec.Code, "deleted task is gone")
}
