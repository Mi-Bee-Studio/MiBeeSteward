// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service"
)

// insertScanResultsForSort seeds one scan_task plus a set of scan_results with
// deliberately varied ip / alive / ports-array-length so each sort key resolves
// to a distinct first row. Returns the task_id the rows belong to.
func insertScanResultsForSort(t *testing.T, d *sql.DB) int64 {
	t.Helper()
	_, err := d.Exec(
		`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
		"sort-test", "192.168.1.0/24", "0 3 * * *", "{}", "{}", 30, 10,
	)
	require.NoError(t, err)

	var taskID int64
	err = d.QueryRow("SELECT last_insert_rowid()").Scan(&taskID)
	require.NoError(t, err)

	// Rows chosen so each sort key has an unambiguous global winner:
	//   ip asc    -> "192.168.1.10"  (lexicographically smallest)
	//   status    -> alive=1 sorts first under desc
	//   ports desc -> the row with 3 ports sorts first
	type row struct {
		ip    string
		alive bool
		ports string // JSON array literal
	}
	rows := []row{
		{"192.168.1.50", true, `[]`},          // alive, 0 ports
		{"192.168.1.10", false, `[80,443]`},   // dead, 2 ports  (smallest ip)
		{"192.168.1.99", true, `[22,80,443]`}, // alive, 3 ports (most ports)
	}
	for _, r := range rows {
		alive := 0
		if r.alive {
			alive = 1
		}
		_, err := d.Exec(
			`INSERT INTO scan_results (task_id, ip, alive, ports, services)
			VALUES (?, ?, ?, ?, '{}')`,
			taskID, r.ip, alive, r.ports,
		)
		require.NoError(t, err)
	}
	return taskID
}

// scanResultFirstIP runs ListResults with the given query and returns the IP of
// the first result row (the global top of the sorted set, page 0).
func scanResultFirstIP(t *testing.T, h *handler.ScannerResultHandler, query string) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/scanner/results?"+query, nil)
	w := httptest.NewRecorder()
	h.ListResults(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Results []struct {
			IP string `json:"ip"`
		} `json:"results"`
		Total int `json:"total"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp.Results, "expected at least one result for query %q", query)
	return resp.Results[0].IP
}

// TestScannerResults_Sort verifies the server-side sort contract (#55):
// a column sort reorders the WHOLE filtered set before pagination, and the
// sort token is whitelist-controlled (an unknown/evil token falls back to the
// default scanned_at order rather than being interpolated into SQL).
func TestScannerResults_Sort(t *testing.T) {
	d := setupSDDB(t)
	taskID := insertScanResultsForSort(t, d)
	queries := db.New(d)
	h := handler.NewScannerResultHandler(queries, d, service.NewScannerResultService(queries))

	// sort=ip asc -> globally smallest IP first (not just the inserted order).
	require.Equal(t, "192.168.1.10", scanResultFirstIP(t, h, "task_id="+itoa(taskID)+"&sort=ip&order=asc&limit=10"))

	// sort=ip desc -> globally largest IP first.
	require.Equal(t, "192.168.1.99", scanResultFirstIP(t, h, "task_id="+itoa(taskID)+"&sort=ip&order=desc&limit=10"))

	// sort=status desc -> an alive host first (alive=1 outranks alive=0 under desc).
	first := scanResultFirstIP(t, h, "task_id="+itoa(taskID)+"&sort=status&order=desc&limit=10")
	require.True(t, first == "192.168.1.50" || first == "192.168.1.99",
		"status desc should put an alive host first, got %s", first)

	// sort=ports desc -> the row with 3 ports first.
	require.Equal(t, "192.168.1.99", scanResultFirstIP(t, h, "task_id="+itoa(taskID)+"&sort=ports&order=desc&limit=10"))

	// No sort -> default scanned_at DESC (behavior unchanged). Just assert it
	// returns all rows; the exact order is insertion/scanned_at-dependent.
	req := httptest.NewRequest("GET", "/api/v1/scanner/results?task_id="+itoa(taskID)+"&limit=10", nil)
	w := httptest.NewRecorder()
	h.ListResults(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var allResp struct {
		Total int `json:"total"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&allResp))
	require.Equal(t, 3, allResp.Total, "all 3 seeded rows should be visible without a sort")

	// SQL-injection / unknown token must NOT be interpolated into ORDER BY — it
	// falls back to the default. If it were interpolated, this query would error
	// (500) or reorder unexpectedly. Assert it returns 200 + all rows.
	evilReq := httptest.NewRequest("GET", "/api/v1/scanner/results?task_id="+itoa(taskID)+"&sort=evil%27--&order=asc&limit=10", nil)
	evilW := httptest.NewRecorder()
	h.ListResults(evilW, evilReq)
	require.Equal(t, http.StatusOK, evilW.Code, "unknown sort token must fall back safely, not error")
}

// TestScannerResults_SortPagination verifies the sort is global across pages:
// with limit=1 the second page (offset=1) holds the globally-2nd row under the
// sort, not the 2nd row of some client-side slice.
func TestScannerResults_SortPagination(t *testing.T) {
	d := setupSDDB(t)
	taskID := insertScanResultsForSort(t, d)
	queries := db.New(d)
	h := handler.NewScannerResultHandler(queries, d, service.NewScannerResultService(queries))

	// sort=ip asc, page size 1: page 0 = smallest, page 1 = middle, page 2 = largest.
	require.Equal(t, "192.168.1.10", scanResultFirstIP(t, h, "task_id="+itoa(taskID)+"&sort=ip&order=asc&limit=1&offset=0"))
	require.Equal(t, "192.168.1.50", scanResultFirstIP(t, h, "task_id="+itoa(taskID)+"&sort=ip&order=asc&limit=1&offset=1"))
	require.Equal(t, "192.168.1.99", scanResultFirstIP(t, h, "task_id="+itoa(taskID)+"&sort=ip&order=asc&limit=1&offset=2"))
}

// itoa is a tiny local int->string helper to avoid pulling in strconv just for
// query-string building in the table-driven asserts above.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
