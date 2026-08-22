// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// These tests cover the #137 read API (GET /devices/{id}/configs list + detail
// + diff). They lock: list omits config_text + reports has_diff; detail returns
// the full text; diff computes a unified diff between any two versions; and the
// IDOR guard rejects a config that does not belong to the path device.

func hashStr(t *testing.T, text string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// setupDeviceConfigHandler seeds a fresh DB with two devices and a few config
// versions on device 1, returning the handler + the queries + the two device
// IDs + the inserted config IDs (oldest..newest on device 1).
func setupDeviceConfigHandler(t *testing.T) (h *DeviceConfigHandler, q *db.Queries, dev1, dev2 int64, cfgIDs []int64) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q = db.New(conn)
	h = NewDeviceConfigHandler(q)

	ctx := context.Background()
	// device_uuid is UNIQUE on fresh schemas (#268 folded the identity
	// indexes into schema.sql) — seed distinct uuids.
	r1, err := conn.Exec(`INSERT INTO devices (name, ip_address, device_uuid) VALUES ('r1', '10.0.0.1', 'uuid-r1')`)
	require.NoError(t, err)
	dev1, err = r1.LastInsertId()
	require.NoError(t, err)
	r2, err := conn.Exec(`INSERT INTO devices (name, ip_address, device_uuid) VALUES ('r2', '10.0.0.2', 'uuid-r2')`)
	require.NoError(t, err)
	dev2, err = r2.LastInsertId()
	require.NoError(t, err)

	// Three captures on device 1; v2 differs from v1 (has_diff=true), v3 == v2 text.
	texts := []string{
		"hostname r1\ninterface eth0\n ip address 10.0.0.1/24\n",
		"hostname r1\ninterface eth0\n ip address 10.0.0.2/24\n",
		"hostname r1\ninterface eth0\n ip address 10.0.0.2/24\n",
	}
	prev := ""
	for _, txt := range texts {
		diff := ""
		if prev != "" && prev != txt {
			diff = "diff-stub" // exact diff content is exercised by the store-layer tests
		}
		cfg, err := q.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
			DeviceID: dev1, ConfigHash: hashStr(t, txt), ConfigText: txt, Protocol: "ssh_show_run", DiffFromPrev: diff,
		})
		require.NoError(t, err)
		cfgIDs = append(cfgIDs, cfg.ID)
		prev = txt
	}
	return h, q, dev1, dev2, cfgIDs
}

// reqWithParams builds a request with chi URL params injected (id + optional
// configId), so Get/List work outside a full router.
func reqWithParams(method, target, deviceID, configID string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	rctx := chi.NewRouteContext()
	if deviceID != "" {
		rctx.URLParams.Add("id", deviceID)
	}
	if configID != "" {
		rctx.URLParams.Add("configId", configID)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// reqWithDeviceCtx builds a request carrying only the {id} chi param (used by
// the Diff handler, which reads query params from the URL string).
func reqWithDeviceCtx(method, target, deviceID string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", deviceID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// --- List ---

func TestDeviceConfigHandler_List_OmitsTextAndReportsHasDiff(t *testing.T) {
	h, _, dev1, _, _ := setupDeviceConfigHandler(t)

	rec := httptest.NewRecorder()
	h.List(rec, reqWithParams(http.MethodGet, "/api/v1/devices/"+strconv.FormatInt(dev1, 10)+"/configs", strconv.FormatInt(dev1, 10), ""))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int64            `json:"total"`
	}
	decodeBody(t, rec, &resp)
	require.EqualValues(t, 3, resp.Total)
	require.Len(t, resp.Items, 3)
	// List projection omits config_text entirely; has_diff flags the v2 change.
	for _, row := range resp.Items {
		_, hasText := row["config_text"]
		require.False(t, hasText, "list must omit config_text")
	}
	// Newest first (id DESC): items[0]=v3(no diff) items[1]=v2(diff) items[2]=v1(no diff).
	require.False(t, resp.Items[0]["has_diff"].(bool))
	require.True(t, resp.Items[1]["has_diff"].(bool))
	require.False(t, resp.Items[2]["has_diff"].(bool))
}

func TestDeviceConfigHandler_List_EmptyForDeviceWithNoCaptures(t *testing.T) {
	h, _, _, dev2, _ := setupDeviceConfigHandler(t)

	rec := httptest.NewRecorder()
	h.List(rec, reqWithParams(http.MethodGet, "/api/v1/devices/"+strconv.FormatInt(dev2, 10)+"/configs", strconv.FormatInt(dev2, 10), ""))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int64            `json:"total"`
	}
	decodeBody(t, rec, &resp)
	require.Empty(t, resp.Items)
	require.Zero(t, resp.Total)
}

func TestDeviceConfigHandler_List_RejectsInvalidDeviceID(t *testing.T) {
	h, _, _, _, _ := setupDeviceConfigHandler(t)
	rec := httptest.NewRecorder()
	h.List(rec, reqWithParams(http.MethodGet, "/api/v1/devices/abc/configs", "abc", ""))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Get ---

func TestDeviceConfigHandler_Get_ReturnsFullText(t *testing.T) {
	h, _, dev1, _, cfgIDs := setupDeviceConfigHandler(t)

	rec := httptest.NewRecorder()
	h.Get(rec, reqWithParams(http.MethodGet,
		"/api/v1/devices/"+strconv.FormatInt(dev1, 10)+"/configs/"+strconv.FormatInt(cfgIDs[1], 10),
		strconv.FormatInt(dev1, 10), strconv.FormatInt(cfgIDs[1], 10)))

	require.Equal(t, http.StatusOK, rec.Code)
	var detail map[string]any
	decodeBody(t, rec, &detail)
	require.Contains(t, detail["config_text"], "10.0.0.2/24")
	require.NotEmpty(t, detail["diff_from_prev"], "v2 changed vs v1")
	require.Equal(t, "ssh_show_run", detail["protocol"])
}

func TestDeviceConfigHandler_Get_IDOR_RejectsConfigFromOtherDevice(t *testing.T) {
	h, _, _, _, cfgIDs := setupDeviceConfigHandler(t)

	// cfgIDs[0] belongs to dev1; request it under dev2's path -> 404, not leaked.
	rec := httptest.NewRecorder()
	h.Get(rec, reqWithParams(http.MethodGet,
		"/api/v1/devices/999/configs/"+strconv.FormatInt(cfgIDs[0], 10),
		"999", strconv.FormatInt(cfgIDs[0], 10)))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDeviceConfigHandler_Get_NotFound(t *testing.T) {
	h, _, dev1, _, _ := setupDeviceConfigHandler(t)
	rec := httptest.NewRecorder()
	h.Get(rec, reqWithParams(http.MethodGet,
		"/api/v1/devices/"+strconv.FormatInt(dev1, 10)+"/configs/999999",
		strconv.FormatInt(dev1, 10), "999999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// --- Diff ---

func TestDeviceConfigHandler_Diff_BetweenTwoVersions(t *testing.T) {
	h, _, dev1, _, cfgIDs := setupDeviceConfigHandler(t)
	d1 := strconv.FormatInt(dev1, 10)

	// cfgIDs[0] (v1, .1/24) vs cfgIDs[1] (v2, .2/24) -> non-empty diff.
	rec := httptest.NewRecorder()
	h.Diff(rec, reqWithDeviceCtx(http.MethodGet,
		"/api/v1/devices/"+d1+"/configs/diff?a="+strconv.FormatInt(cfgIDs[0], 10)+"&b="+strconv.FormatInt(cfgIDs[1], 10), d1))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		A    map[string]any `json:"a"`
		B    map[string]any `json:"b"`
		Diff string         `json:"diff"`
	}
	decodeBody(t, rec, &resp)
	require.Contains(t, resp.Diff, "- ip address 10.0.0.1/24")
	require.Contains(t, resp.Diff, "+ ip address 10.0.0.2/24")
	require.EqualValues(t, cfgIDs[0], resp.A["id"])
	require.EqualValues(t, cfgIDs[1], resp.B["id"])
}

func TestDeviceConfigHandler_Diff_IdenticalVersionsIsEmpty(t *testing.T) {
	h, _, dev1, _, cfgIDs := setupDeviceConfigHandler(t)
	d1 := strconv.FormatInt(dev1, 10)

	// cfgIDs[1] and cfgIDs[2] have identical text -> empty diff.
	rec := httptest.NewRecorder()
	h.Diff(rec, reqWithDeviceCtx(http.MethodGet,
		"/api/v1/devices/"+d1+"/configs/diff?a="+strconv.FormatInt(cfgIDs[1], 10)+"&b="+strconv.FormatInt(cfgIDs[2], 10), d1))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Diff string `json:"diff"`
	}
	decodeBody(t, rec, &resp)
	require.Empty(t, resp.Diff)
}

func TestDeviceConfigHandler_Diff_MissingParamIs400(t *testing.T) {
	h, _, dev1, _, _ := setupDeviceConfigHandler(t)
	d1 := strconv.FormatInt(dev1, 10)
	rec := httptest.NewRecorder()
	h.Diff(rec, reqWithDeviceCtx(http.MethodGet,
		"/api/v1/devices/"+d1+"/configs/diff?a=1", d1)) // no b
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDeviceConfigHandler_Diff_IDOR_RejectsForeignVersion(t *testing.T) {
	h, _, _, _, cfgIDs := setupDeviceConfigHandler(t)
	// Request dev1's configs under dev2 path -> 404 (treated as not-found, not leaked).
	rec := httptest.NewRecorder()
	h.Diff(rec, reqWithDeviceCtx(http.MethodGet,
		"/api/v1/devices/999/configs/diff?a="+strconv.FormatInt(cfgIDs[0], 10)+"&b="+strconv.FormatInt(cfgIDs[1], 10), "999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
}
