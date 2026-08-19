// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
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

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/probetarget"
	"mibee-steward/internal/testutil"
)

// These tests pin ProbeTargetHandler's HTTP error→status mapping, mirroring
// scanner_task_test.go. The engine-dependent paths (trigger) use a nil engine
// to lock the 503 mapping; the engine itself is covered by engine_test.go.

const validProbeTargetBody = `{"name":"github","module":"tls","target":"github.com:443","interval_seconds":60,"timeout_seconds":10}`

func setupProbeTargetHandler(t *testing.T) (*ProbeTargetHandler, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	return NewProbeTargetHandler(probetarget.New(queries, nil), queries), queries
}

func TestProbeTargetHandler_CreateThenGet(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader(validProbeTargetBody)))
	require.Equal(t, http.StatusCreated, rec.Code)

	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := strconv.FormatInt(int64(created["id"].(float64)), 10)

	rec = httptest.NewRecorder()
	h.GetTarget(rec, reqWithURLParam(http.MethodGet, "/api/v1/probe-targets/"+id, "", id))
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestProbeTargetHandler_Create_InvalidBody(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)
	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader("not-json")))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestProbeTargetHandler_Create_InvalidTarget(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)
	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/",
		strings.NewReader(`{"name":"x","module":"tls","target":"no-port.example.com","interval_seconds":60,"timeout_seconds":10}`)))
	require.Equal(t, http.StatusBadRequest, rec.Code, "validation error → 400")
}

func TestProbeTargetHandler_Create_DuplicateName(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader(validProbeTargetBody)))
		if i == 0 {
			require.Equal(t, http.StatusCreated, rec.Code)
		} else {
			require.Equal(t, http.StatusConflict, rec.Code, "duplicate name → 409")
		}
	}
}

func TestProbeTargetHandler_List(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)
	for _, body := range []string{
		`{"name":"a","module":"tls","target":"a.com:443","interval_seconds":60,"timeout_seconds":10}`,
		`{"name":"b","module":"http","target":"https://b.com","interval_seconds":120,"timeout_seconds":10}`,
	} {
		rec := httptest.NewRecorder()
		h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader(body)))
		require.Equal(t, http.StatusCreated, rec.Code)
	}

	rec := httptest.NewRecorder()
	h.ListTargets(rec, httptest.NewRequest(http.MethodGet, "/api/v1/probe-targets/?limit=10", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var list map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&list))
	require.EqualValues(t, 2, list["total"])
}

func TestProbeTargetHandler_Get_NotFound(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)
	rec := httptest.NewRecorder()
	h.GetTarget(rec, reqWithURLParam(http.MethodGet, "/api/v1/probe-targets/999", "", "999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestProbeTargetHandler_Delete(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader(validProbeTargetBody)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := strconv.FormatInt(int64(created["id"].(float64)), 10)

	rec = httptest.NewRecorder()
	h.DeleteTarget(rec, reqWithURLParam(http.MethodDelete, "/api/v1/probe-targets/"+id, "", id))
	require.Equal(t, http.StatusNoContent, rec.Code)

	rec = httptest.NewRecorder()
	h.DeleteTarget(rec, reqWithURLParam(http.MethodDelete, "/api/v1/probe-targets/"+id, "", id))
	require.Equal(t, http.StatusNotFound, rec.Code, "second delete → 404")
}

func TestProbeTargetHandler_Trigger_EngineUnavailable(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader(validProbeTargetBody)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := strconv.FormatInt(int64(created["id"].(float64)), 10)

	rec = httptest.NewRecorder()
	h.TriggerTarget(rec, reqWithURLParam(http.MethodPost, "/api/v1/probe-targets/"+id+"/trigger", "", id))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "nil engine → 503")
}

func TestProbeTargetHandler_Results_NotFound(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)
	rec := httptest.NewRecorder()
	h.GetTargetResults(rec, reqWithURLParam(http.MethodGet, "/api/v1/probe-targets/999/results", "", "999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestProbeTargetHandler_Certificates_EmptyIs200(t *testing.T) {
	h, _ := setupProbeTargetHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader(validProbeTargetBody)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := strconv.FormatInt(int64(created["id"].(float64)), 10)

	rec = httptest.NewRecorder()
	h.GetTargetCertificates(rec, reqWithURLParam(http.MethodGet, "/api/v1/probe-targets/"+id+"/certificates", "", id))
	require.Equal(t, http.StatusOK, rec.Code, "no certs yet → 200 with empty array (mirrors device endpoint)")

	var out map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	require.EqualValues(t, 0, out["total"])
}

func TestProbeTargetHandler_Certificates_ShapeMatchesDeviceEndpoint(t *testing.T) {
	h, queries := setupProbeTargetHandler(t)

	rec := httptest.NewRecorder()
	h.CreateTarget(rec, httptest.NewRequest(http.MethodPost, "/api/v1/probe-targets/", strings.NewReader(validProbeTargetBody)))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := int64(created["id"].(float64))

	// Seed a 2-cert chain; the response must carry the SAME tlsPortCerts shape
	// the device certificates endpoint emits (so CertificateModal works as-is).
	require.NoError(t, queries.CreateProbeTLSCert(t.Context(), db.CreateProbeTLSCertParams{
		TargetID: id, Port: 443, CertIndex: 0, SubjectCn: "example.com",
		NotAfter: "2026-12-01T00:00:00Z", TlsVersion: "TLS 1.3", Trusted: 1,
	}))
	require.NoError(t, queries.CreateProbeTLSCert(t.Context(), db.CreateProbeTLSCertParams{
		TargetID: id, Port: 443, CertIndex: 1, SubjectCn: "Issuer CA", IsCa: 1,
	}))

	rec = httptest.NewRecorder()
	h.GetTargetCertificates(rec, reqWithURLParam(http.MethodGet,
		"/api/v1/probe-targets/"+strconv.FormatInt(id, 10)+"/certificates", "", strconv.FormatInt(id, 10)))
	require.Equal(t, http.StatusOK, rec.Code)

	var out struct {
		Certificates []struct {
			Port       int    `json:"port"`
			TLSVersion string `json:"tls_version"`
			Trusted    bool   `json:"trusted"`
			Leaf       *struct {
				SubjectCN string `json:"subject_cn"`
				NotAfter  string `json:"not_after"`
			} `json:"leaf"`
			Chain []struct {
				CertIndex int `json:"cert_index"`
			} `json:"chain"`
		} `json:"certificates"`
		Total int `json:"total"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	require.Equal(t, 1, out.Total)
	require.Len(t, out.Certificates, 1)
	entry := out.Certificates[0]
	require.Equal(t, 443, entry.Port)
	require.Equal(t, "TLS 1.3", entry.TLSVersion)
	require.True(t, entry.Trusted)
	require.NotNil(t, entry.Leaf, "leaf (cert_index 0) surfaced separately")
	require.Equal(t, "example.com", entry.Leaf.SubjectCN)
	require.Len(t, entry.Chain, 2)
}
