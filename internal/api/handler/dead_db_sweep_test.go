// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/service"
)

// TestDocumentHandler_DeadDB_Sweep drives the document endpoints over a
// dead handle (storage 500s) plus the pure validation arms (bad body / bad
// ID / non-multipart upload / oversized upload).
func TestDocumentHandler_DeadDB_Sweep(t *testing.T) {
	conn := closedTestDB(t)
	dir := t.TempDir()
	audit := service.NewAuditRepository(conn)
	upload := service.NewUploadService(filepath.ToSlash(dir), 16) // 16-byte cap
	h := NewDocumentHandler(service.NewDocumentService(conn, upload), dir, audit)

	r := httptest.NewRecorder()
	h.CreateURL(r, reqWithBodyParams(http.MethodPost, "/api/v1/documents", "not json", nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	h.CreateURL(r, reqWithBodyParams(http.MethodPost, "/api/v1/documents",
		`{"url":"","title":""}`, nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	h.CreateURL(r, reqWithBodyParams(http.MethodPost, "/api/v1/documents",
		`{"url":"https://example.com/doc","title":"doc"}`, nil))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	h.UploadFile(r, httptest.NewRequest(http.MethodPost, "/api/v1/documents/upload", strings.NewReader("not multipart")))
	require.Equal(t, http.StatusBadRequest, r.Code)

	// Oversized upload against the 16-byte cap.
	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n\r\n" +
		strings.Repeat("x", 64) + "\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/documents/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	r = httptest.NewRecorder()
	h.UploadFile(r, req)
	require.NotEqual(t, http.StatusOK, r.Code, "oversized upload must be rejected (413 via the size gate)")

	r = httptest.NewRecorder()
	h.List(r, httptest.NewRequest(http.MethodGet, "/api/v1/documents", nil))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	h.Get(r, reqWithBodyParams(http.MethodGet, "/api/v1/documents/abc", "", map[string]string{"id": "abc"}))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	h.Get(r, reqWithBodyParams(http.MethodGet, "/api/v1/documents/1", "", map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	h.Download(r, reqWithBodyParams(http.MethodGet, "/api/v1/documents/1/download", "", map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	h.Update(r, reqWithBodyParams(http.MethodPut, "/api/v1/documents/1", "not json", map[string]string{"id": "1"}))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	h.Delete(r, reqWithBodyParams(http.MethodDelete, "/api/v1/documents/1", "", map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)
}

// TestHeartbeatHandler_DeadDB_StatsAndHistory drives the heartbeat endpoints
// whose storage sits on the main DB: stats and the history window parse arm.
func TestHeartbeatHandler_DeadDB_StatsAndHistory(t *testing.T) {
	conn := closedTestDB(t)
	hbStore, err := service.OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { hbStore.Close() })
	svc := service.NewHeartbeatService(conn, hbStore, &config.Config{})
	h := NewHeartbeatHandler(svc)

	r := httptest.NewRecorder()
	// Stats read the DEDICATED store too: a valid window succeeds even over
	// a dead main handle.
	h.GetStats(r, reqWithBodyParams(http.MethodGet,
		"/api/v1/heartbeat/stats/1?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusOK, r.Code)

	// History requires ?from=&to=; missing window → 400 before any storage.
	r = httptest.NewRecorder()
	h.ListHistory(r, reqWithBodyParams(http.MethodGet, "/api/v1/heartbeat/history/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusBadRequest, r.Code)

	// History reads the DEDICATED store (not the dead main DB): a valid
	// window succeeds with an empty series.
	r = httptest.NewRecorder()
	h.ListHistory(r, reqWithBodyParams(http.MethodGet,
		"/api/v1/heartbeat/history/1?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusOK, r.Code)
}
