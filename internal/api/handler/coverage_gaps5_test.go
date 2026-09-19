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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Round-4 leftovers for the white-box handler test families: the
// update/trigger/cancel paths of scan tasks, the SSH-credential error
// branches, and the probe-target update/results branches. All reuse the
// per-family setups from their original test files.

// --- scan tasks: update / trigger / cancel / runs+results ---

func createGapScanTask(t *testing.T, h *ScannerTaskHandler, body string) int64 {
	t.Helper()
	rec := httptest.NewRecorder()
	h.CreateTask(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scanner/tasks", strings.NewReader(body)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	return int64(created["id"].(float64))
}

func TestScannerTaskHandler_UpdateTask(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)
	id := createGapScanTask(t, h, validScanTaskBody)
	path := "/api/v1/scanner/tasks/" + strconv.FormatInt(id, 10)

	// Full update: rename + new cron → 200 with the new values.
	rec := httptest.NewRecorder()
	h.UpdateTask(rec, reqWithURLParam(http.MethodPut, path, `{"name":"nightly-v2","cron_expr":"30 3 * * *","enabled":true}`, strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusOK, rec.Code)
	var updated map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updated))
	require.Equal(t, "nightly-v2", updated["name"])
	require.Equal(t, "30 3 * * *", updated["cron_expr"])

	// Invalid body → 400; invalid targets → 400 (ValidationError branch);
	// unknown task → 404; bad id → 400.
	rec = httptest.NewRecorder()
	h.UpdateTask(rec, reqWithURLParam(http.MethodPut, path, `{not-json`, strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = httptest.NewRecorder()
	h.UpdateTask(rec, reqWithURLParam(http.MethodPut, path, `{"targets":"not-an-ip-range"}`, strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = httptest.NewRecorder()
	h.UpdateTask(rec, reqWithURLParam(http.MethodPut, "/api/v1/scanner/tasks/9999", `{"name":"x"}`, "9999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = httptest.NewRecorder()
	h.UpdateTask(rec, reqWithURLParam(http.MethodPut, "/api/v1/scanner/tasks/abc", `{"name":"x"}`, "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestScannerTaskHandler_TriggerTask_Mappings(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)

	// Unknown task → 404.
	rec := httptest.NewRecorder()
	h.TriggerTask(rec, reqWithURLParam(http.MethodPost, "/api/v1/scanner/tasks/9999/trigger", "", "9999"))
	require.Equal(t, http.StatusNotFound, rec.Code)

	// Nil scheduler (the setup passes one) → 503 BEFORE the disabled check
	// (scheduler availability gates the whole trigger path).
	disabledID := createGapScanTask(t, h, `{"name":"sleepy","targets":"192.168.1.0/24","cron_expr":"0 2 * * *","timeout":60,"concurrent_hosts":16,"pipeline_config":{"icmp":{"enabled":true,"timeout":2}},"enabled":false}`)
	rec = httptest.NewRecorder()
	h.TriggerTask(rec, reqWithURLParam(http.MethodPost, "/api/v1/scanner/tasks/"+strconv.FormatInt(disabledID, 10)+"/trigger", "", strconv.FormatInt(disabledID, 10)))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	// Enabled task but NO scheduler → 503.
	enabledID := createGapScanTask(t, h, validScanTaskBody)
	rec = httptest.NewRecorder()
	h.TriggerTask(rec, reqWithURLParam(http.MethodPost, "/api/v1/scanner/tasks/"+strconv.FormatInt(enabledID, 10)+"/trigger", "", strconv.FormatInt(enabledID, 10)))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "scheduler")

	// Bad id → 400.
	rec = httptest.NewRecorder()
	h.TriggerTask(rec, reqWithURLParam(http.MethodPost, "/api/v1/scanner/tasks/abc/trigger", "", "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestScannerTaskHandler_CancelAndRunsResults(t *testing.T) {
	h, _ := setupScannerTaskHandler(t)
	id := createGapScanTask(t, h, validScanTaskBody)

	// Cancel: unknown → 404; not running → 409; bad id → 400.
	rec := httptest.NewRecorder()
	h.CancelScanTask(rec, reqWithURLParam(http.MethodPost, "/api/v1/scanner/tasks/9999/cancel", "", "9999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = httptest.NewRecorder()
	h.CancelScanTask(rec, reqWithURLParam(http.MethodPost, "/api/v1/scanner/tasks/"+strconv.FormatInt(id, 10)+"/cancel", "", strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "not currently running")
	rec = httptest.NewRecorder()
	h.CancelScanTask(rec, reqWithURLParam(http.MethodPost, "/api/v1/scanner/tasks/abc/cancel", "", "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// Runs + results: happy path (empty lists) and 404.
	rec = httptest.NewRecorder()
	h.GetTaskRuns(rec, reqWithURLParam(http.MethodGet, "/api/v1/scanner/tasks/"+strconv.FormatInt(id, 10)+"/runs", "", strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusOK, rec.Code)
	var runs map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&runs))
	require.Equal(t, float64(0), runs["total"])

	rec = httptest.NewRecorder()
	h.GetTaskResults(rec, reqWithURLParam(http.MethodGet, "/api/v1/scanner/tasks/"+strconv.FormatInt(id, 10)+"/results", "", strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusOK, rec.Code)

	// Runs/results for an unknown task answer an EMPTY list with the nil
	// scheduler (the not-found check lives on the scheduler path).
	rec = httptest.NewRecorder()
	h.GetTaskRuns(rec, reqWithURLParam(http.MethodGet, "/api/v1/scanner/tasks/9999/runs", "", "9999"))
	require.Equal(t, http.StatusOK, rec.Code)
	rec = httptest.NewRecorder()
	h.GetTaskResults(rec, reqWithURLParam(http.MethodGet, "/api/v1/scanner/tasks/9999/results", "", "9999"))
	require.Equal(t, http.StatusOK, rec.Code)
}

// --- SSH credentials: validation + error branches ---

func TestSSHCredentialHandler_Create_ValidationBranches(t *testing.T) {
	h, _ := setupSSHCredHandler(t)

	cases := []struct {
		name string
		body string
	}{
		{"bad json", `{not-json`},
		{"missing name", `{"auth_method":"password","username":"u","secret":"s"}`},
		{"missing secret", `{"name":"x","auth_method":"password","username":"u","secret":""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(tc.body)))
			require.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
	// The invalid-auth-method branch is asserted by its message elsewhere; pin
	// it here too so the mapping stays 400.
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials",
		strings.NewReader(`{"name":"x","auth_method":"pubkey-magic","username":"u","secret":"s"}`)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "auth_method")
}

func TestSSHCredentialHandler_UpdateErrorBranches(t *testing.T) {
	h, sshDB := setupSSHCredHandler(t)

	// Seed two credentials directly.
	var id1 int64
	res, err := sshDB.Exec(`INSERT INTO ssh_credentials (name, auth_method, username, secret_enc, enabled) VALUES ('one','password','u','enc',1)`)
	require.NoError(t, err)
	id1, _ = res.LastInsertId()
	res, err = sshDB.Exec(`INSERT INTO ssh_credentials (name, auth_method, username, secret_enc, enabled) VALUES ('two','password','u','enc',1)`)
	require.NoError(t, err)
	_, _ = res.LastInsertId()

	put := func(body, id string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/ssh-credentials/"+id, body, id))
		return rec
	}

	rec := put(`{not-json`, strconv.FormatInt(id1, 10))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = put(`{"auth_method":"password","username":"u"}`, strconv.FormatInt(id1, 10))
	require.Equal(t, http.StatusBadRequest, rec.Code) // blank name
	rec = put(`{"name":"renamed","auth_method":"bogus","username":"u"}`, strconv.FormatInt(id1, 10))
	require.Equal(t, http.StatusBadRequest, rec.Code) // bad auth_method
	rec = put(`{"name":"ghost","auth_method":"password","username":"u"}`, "9999")
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = put(`{"name":"two","auth_method":"password","username":"u"}`, strconv.FormatInt(id1, 10))
	require.Equal(t, http.StatusConflict, rec.Code) // rename collides with #2

	// A valid rename with blank secret keeps the ciphertext and round-trips.
	rec = put(`{"name":"renamed","auth_method":"password","username":"u","notes":"ok"}`, strconv.FormatInt(id1, 10))
	require.Equal(t, http.StatusOK, rec.Code)
	var out map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	require.Equal(t, "renamed", out["name"])
	require.Equal(t, "ok", out["notes"])
}

func TestSSHCredentialHandler_DeleteBranches(t *testing.T) {
	h, sshDB := setupSSHCredHandler(t)
	res, err := sshDB.Exec(`INSERT INTO ssh_credentials (name, auth_method, username, secret_enc, enabled) VALUES ('bye','password','u','enc',1)`)
	require.NoError(t, err)
	id, _ := res.LastInsertId()

	rec := httptest.NewRecorder()
	h.Delete(rec, reqWithURLParam(http.MethodDelete, "/api/v1/ssh-credentials/9999", "", "9999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = httptest.NewRecorder()
	h.Delete(rec, reqWithURLParam(http.MethodDelete, "/api/v1/ssh-credentials/abc", "", "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = httptest.NewRecorder()
	h.Delete(rec, reqWithURLParam(http.MethodDelete, "/api/v1/ssh-credentials/"+strconv.FormatInt(id, 10), "", strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusNoContent, rec.Code)
}

// --- probe targets: update / results / trigger branches ---

func TestProbeTargetHandler_UpdateTarget(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets", strings.NewReader(validProbeTargetBody)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := int64(created["id"].(float64))

	// A second target to collide names with.
	rec = httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets",
		strings.NewReader(`{"name":"gitlab","module":"tcp","target":"gitlab.com:443","interval_seconds":60,"timeout_seconds":10}`)))
	require.Equal(t, http.StatusCreated, rec.Code)

	put := func(body, id string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.UpdateTarget(rec, reqWithURLParam(http.MethodPut, "/api/v1/probe-targets/"+id, body, id))
		return rec
	}

	rec = put(`{"name":"github-prod","interval_seconds":120}`, strconv.FormatInt(id, 10))
	require.Equal(t, http.StatusOK, rec.Code)
	var updated map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updated))
	require.Equal(t, "github-prod", updated["name"])
	require.Equal(t, float64(120), updated["interval_seconds"])

	rec = put(`{not-json`, strconv.FormatInt(id, 10))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = put(`{"name":"gitlab"}`, strconv.FormatInt(id, 10))
	require.Equal(t, http.StatusConflict, rec.Code)
	rec = put(`{"name":"x"}`, "9999")
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = put(`{"target":"not a target!!!"}`, strconv.FormatInt(id, 10))
	require.Equal(t, http.StatusBadRequest, rec.Code) // service validation → default 400 branch
	rec = httptest.NewRecorder()
	h.UpdateTarget(rec, reqWithURLParam(http.MethodPut, "/api/v1/probe-targets/abc", `{}`, "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestProbeTargetHandler_ResultsAndTriggerBranches(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets", strings.NewReader(validProbeTargetBody)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := int64(created["id"].(float64))
	idStr := strconv.FormatInt(id, 10)

	// Results: unknown target 404; bad id 400; bad vantage 400; vantage=all
	// 400; happy path is a wrapped empty list.
	get := func(query string, id string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.GetTargetResults(rec, reqWithURLParam(http.MethodGet, "/api/v1/probe-targets/"+id+"/results"+query, "", id))
		return rec
	}
	rec = get("", "9999")
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = get("", "abc")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = get("?vantage=bogus", idStr)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = get("?vantage=all", idStr)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "vantage filter must be")
	rec = get("?vantage=center", idStr)
	require.Equal(t, http.StatusOK, rec.Code)

	// Trigger with the nil engine short-circuits to 503 regardless of the id
	// (pinned by TestProbeTargetHandler_Trigger_EngineUnavailable); the bad-id
	// branch is the only id-level case reachable here.
	trig := func(id string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.TriggerTarget(rec, reqWithURLParam(http.MethodPost, "/api/v1/probe-targets/"+id+"/trigger", "", id))
		return rec
	}
	rec = trig("abc")
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
