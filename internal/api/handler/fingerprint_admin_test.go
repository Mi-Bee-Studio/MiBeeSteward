// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
	"mibee-steward/internal/fpsync"
	testutil "mibee-steward/internal/testutil"
)

func corpusA() map[string][]byte {
	return map[string][]byte{
		"banner.yaml": []byte("version: 1\nrules:\n  - id: a1\n    match: {op: contains, value: \"OpenSSH\"}\n    service: ssh\n  - id: a2\n    match: {op: contains, value: \"nginx\"}\n    service: http\n"),
		"ports.yaml":  []byte("version: 1\nrules: []\n"),
	}
}

func corpusB() map[string][]byte {
	return map[string][]byte{
		"banner.yaml": []byte("version: 1\nrules:\n  - id: b1\n    match: {op: contains, value: \"Apache\"}\n    service: http\n"),
	}
}

func newAdminHandler(t *testing.T) *FingerprintAdminHandler {
	t.Helper()
	return NewFingerprintAdminHandler(nil, "", filepath.Join(t.TempDir(), "managed", "fingerprints"), "", nil, nil)
}

func uploadBody(t *testing.T, field, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func putCorpus(t *testing.T, h *FingerprintAdminHandler, files map[string][]byte) (int, map[string]any) {
	t.Helper()
	tgz, err := fpsync.TarGz(files)
	if err != nil {
		t.Fatal(err)
	}
	body, ctype := uploadBody(t, "file", "corpus.tar.gz", tgz)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp
}

func getStatus(t *testing.T, h *FingerprintAdminHandler) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Get(rec, httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestFingerprintAdminStatusEmbedded(t *testing.T) {
	h := newAdminHandler(t)
	st := getStatus(t, h)
	if st["source"] != "embedded" {
		t.Errorf("source = %v, want embedded", st["source"])
	}
	if st["uploads_enabled"] != true {
		t.Error("uploads must be enabled without an explicit fingerprint_path")
	}
	if st["upstream_configured"] != false {
		t.Error("upstream unconfigured by default")
	}
	if st["prev_available"] != false {
		t.Error("no prev initially")
	}
	if rev, _ := st["rev"].(string); len(rev) != 64 {
		t.Errorf("rev missing: %v", st["rev"])
	}
}

func TestFingerprintAdminUploadActivateAndRollback(t *testing.T) {
	h := newAdminHandler(t)

	code, resp := putCorpus(t, h, corpusA())
	if code != http.StatusOK {
		t.Fatalf("upload A: %d %v", code, resp)
	}
	if resp["rule_count"] != float64(2) {
		t.Errorf("rule_count after A = %v, want 2", resp["rule_count"])
	}
	revA, _ := resp["rev"].(string)

	st := getStatus(t, h)
	if st["source"] != "managed" || st["prev_available"] != true {
		t.Fatalf("post-upload status wrong: %v", st)
	}
	// First upload parks the previously-ACTIVE corpus (embedded) as rollback
	// target — rollback must work after any change, including the first.
	if st["prev_rev"] == revA {
		t.Error("prev must differ from the just-uploaded rev")
	}

	// Single-file replace on top of the managed corpus: replaces banner.yaml,
	// keeps ports.yaml; rules change 2 → 1 (b1).
	body, ctype := uploadBody(t, "file", "banner.yaml", corpusB()["banner.yaml"])
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("single-file replace: %d %s", rec.Code, rec.Body.String())
	}
	var resp2 map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp2)
	if resp2["rule_count"] != float64(1) {
		t.Errorf("rule_count after single-file = %v, want 1", resp2["rule_count"])
	}
	st = getStatus(t, h)
	if st["prev_rev"] != revA {
		t.Errorf("prev_rev = %v, want A's rev", st["prev_rev"])
	}

	// File preview from the managed corpus (chi route param via RouteContext).
	req = httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/files/banner.yaml", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "banner.yaml")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	h.FileContent(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "b1") {
		t.Fatalf("file preview: %d %s", rec.Code, rec.Body.String())
	}

	// Rollback returns to corpus A (and parks B as the new prev).
	rec = httptest.NewRecorder()
	h.Rollback(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fingerprints/rollback", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body.String())
	}
	var rb map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rb)
	if rb["rev"] != revA || rb["rule_count"] != float64(2) {
		t.Errorf("rollback facts = %v, want A", rb)
	}
	st = getStatus(t, h)
	if st["rev"] != revA {
		t.Errorf("status after rollback = %v", st["rev"])
	}

	// Second rollback rolls FORWARD to B again (prev swap).
	rec = httptest.NewRecorder()
	h.Rollback(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fingerprints/rollback", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback 2: %d %s", rec.Code, rec.Body.String())
	}
	st = getStatus(t, h)
	if st["rev"] == revA {
		t.Error("second rollback should land on B")
	}
}

func TestFingerprintAdminUploadRejectsBadCorpus(t *testing.T) {
	h := newAdminHandler(t)
	bad := map[string][]byte{
		"broken.yaml": []byte("version: 1\nrules:\n  - id: x\n    match: {op: regex, value: \"(unclosed[\"}\n    service: x\n"),
	}
	code, resp := putCorpus(t, h, bad)
	if code != http.StatusBadRequest {
		t.Fatalf("bad corpus accepted: %d %v", code, resp)
	}
	if !strings.Contains(fmt.Sprint(resp["error"]), "rejected by rule engine") {
		t.Errorf("error should carry the engine verdict: %v", resp["error"])
	}
	// Managed corpus untouched → still embedded.
	if st := getStatus(t, h); st["source"] != "embedded" {
		t.Errorf("source after rejected upload = %v, want embedded", st["source"])
	}
	// Rollback with no prev → 409.
	rec := httptest.NewRecorder()
	h.Rollback(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fingerprints/rollback", nil))
	if rec.Code != http.StatusConflict {
		t.Errorf("rollback without prev = %d", rec.Code)
	}
}

func TestFingerprintAdminUploadConflictWithExplicitPath(t *testing.T) {
	h := NewFingerprintAdminHandler(nil, "/etc/some/dir", filepath.Join(t.TempDir(), "m"), "", nil, nil)
	tgz, _ := fpsync.TarGz(corpusA())
	body, ctype := uploadBody(t, "file", "corpus.tar.gz", tgz)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("explicit-path upload = %d, want 409", rec.Code)
	}
	st := getStatus(t, h)
	if st["uploads_enabled"] != false {
		t.Error("status must flag uploads disabled under explicit path")
	}
}

func TestFingerprintAdminUpstreamCheckAndApply(t *testing.T) {
	upFiles := corpusB()
	tgz, err := fpsync.TarGz(upFiles)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"corpus_version":"9.9.9-test","tarball":"corpus.tar.gz"}`)
		case "/corpus.tar.gz":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(tgz)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	h := NewFingerprintAdminHandler(nil, "", filepath.Join(t.TempDir(), "managed", "fingerprints"), srv.URL+"/manifest.json", nil, nil)

	// Unconfigured upstream → 501 with a hint.
	bare := newAdminHandler(t)
	rec := httptest.NewRecorder()
	bare.Upstream(rec, httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/upstream", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("unconfigured upstream = %d, want 501", rec.Code)
	}

	// Check: diff against embedded, nothing activated.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/upstream", nil)
	rec = httptest.NewRecorder()
	h.Upstream(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upstream check: %d %s", rec.Code, rec.Body.String())
	}
	var chk map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &chk)
	if chk["upstream_version"] != "9.9.9-test" || chk["up_to_date"] != false {
		t.Errorf("check payload wrong: %v", chk)
	}
	if added, _ := chk["added_rules"].([]any); len(added) == 0 || added[0] != "b1" {
		t.Errorf("added_rules should list b1: %v", chk["added_rules"])
	}
	if st := getStatus(t, h); st["source"] != "embedded" {
		t.Errorf("check must not activate: %v", st["source"])
	}

	// One-click apply → managed corpus = upstream corpus.
	rec = httptest.NewRecorder()
	h.UpstreamApply(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fingerprints/upstream/apply", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	if st := getStatus(t, h); st["source"] != "managed" {
		t.Errorf("apply must activate: %v", st["source"])
	}

	// Now up to date.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/upstream", nil)
	rec = httptest.NewRecorder()
	h.Upstream(rec, req)
	chk = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &chk)
	if chk["up_to_date"] != true {
		t.Errorf("post-apply up_to_date = %v", chk["up_to_date"])
	}
}

func TestFingerprintAdminAgents(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	queries := db.New(conn)
	if _, err := conn.Exec(`INSERT INTO agent_status (agent_id, version, fingerprint_rev, last_report_at)
		VALUES ('agent-x', 'v9', 'rev123', ?), ('agent-old', 'v8', '', ?)`,
		time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	h := NewFingerprintAdminHandler(nil, "", filepath.Join(t.TempDir(), "m"), "", queries, nil)
	rec := httptest.NewRecorder()
	h.Agents(rec, httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("agents: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Agents []struct {
			AgentID        string `json:"agent_id"`
			FingerprintRev string `json:"fingerprint_rev"`
			UpToDate       bool   `json:"up_to_date"`
		} `json:"agents"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 {
		t.Fatalf("total = %d", resp.Total)
	}
	byID := map[string]bool{}
	for _, a := range resp.Agents {
		byID[a.AgentID] = true
		if a.AgentID == "agent-old" && a.FingerprintRev != "" {
			t.Error("old agent must report empty rev")
		}
	}
	if !byID["agent-x"] || !byID["agent-old"] {
		t.Errorf("missing agents: %+v", resp.Agents)
	}
}
