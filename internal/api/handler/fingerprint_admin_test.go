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
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
	"mibee-steward/internal/fpsync"
	"mibee-steward/internal/service"
	engine "mibee-steward/internal/service/scannerv2/engine"
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

// TestFingerprintAdminErrorPaths sweeps the remaining error branches:
// malformed uploads, preview misses, upstream failures, and the audit trail.
func TestFingerprintAdminErrorPaths(t *testing.T) {
	// ── upload shape errors ────────────────────────────────────────────────
	h := newAdminHandler(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", bytes.NewReader([]byte("junk")))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-multipart upload = %d, want 400", rec.Code)
	}

	// Single-file upload whose name is not .yaml.
	body, ctype := uploadBody(t, "file", "notes.txt", []byte("hello"))
	req = httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", body)
	req.Header.Set("Content-Type", ctype)
	rec = httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "named .yaml") {
		t.Errorf("non-yaml single file = %d %s", rec.Code, rec.Body.String())
	}

	// tar.gz that is not a corpus at all (no yaml inside).
	body, ctype = uploadBody(t, "file", "corpus.tar.gz", []byte{0x1f, 0x8b, 0x00, 0x00})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", body)
	req.Header.Set("Content-Type", ctype)
	rec = httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("garbage tar.gz = %d, want 400", rec.Code)
	}

	// ── file preview errors ────────────────────────────────────────────────
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "../escape")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/files/../escape", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	h.FileContent(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("traversal preview = %d, want 400", rec.Code)
	}
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("name", "nope.yaml")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/files/nope.yaml", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	h.FileContent(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("missing preview = %d, want 404", rec.Code)
	}

	// ── upstream failure modes ─────────────────────────────────────────────
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"corpus_version":"x"}`)) // missing tarball
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	hu := NewFingerprintAdminHandler(nil, "", filepath.Join(t.TempDir(), "m"), srv.URL+"/manifest.json", nil, nil)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/fingerprints/upstream", nil)
	rec = httptest.NewRecorder()
	hu.Upstream(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "missing tarball") {
		t.Errorf("manifest without tarball = %d %s", rec.Code, rec.Body.String())
	}
	// Apply with an explicit path configured → conflict, no fetch.
	hc := NewFingerprintAdminHandler(nil, "/etc/explicit", filepath.Join(t.TempDir(), "m"), srv.URL+"/manifest.json", nil, nil)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/fingerprints/upstream/apply", nil)
	rec = httptest.NewRecorder()
	hc.UpstreamApply(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("apply under explicit path = %d, want 409", rec.Code)
	}

	// ── audit trail on a real repository ───────────────────────────────────
	conn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auditRepo := service.NewAuditRepository(conn)
	ha := NewFingerprintAdminHandler(nil, "", filepath.Join(t.TempDir(), "managed", "fingerprints"), "", nil, auditRepo)
	putCorpus(t, ha, corpusA()) // upload fires fingerprint.upload into audit_logs
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action='fingerprint.upload'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit row for upload: n=%d err=%v", n, err)
	}
	rec = httptest.NewRecorder()
	ha.Rollback(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fingerprints/rollback", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback with audit: %d", rec.Code)
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action='fingerprint.rollback'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit row for rollback: n=%d err=%v", n, err)
	}
}

// TestFingerprintAdminWithLiveEngine drives the full admin flow against a REAL
// engine: status carries engine facts, activation hot-reloads, CorpusFacts
// follow, and a zip envelope upload takes the zip branch.
func TestFingerprintAdminWithLiveEngine(t *testing.T) {
	dirA := t.TempDir()
	writeEngineCorpus(t, dirA, 2)
	eng, err := engine.NewEngine(nil, engine.Config{FingerprintPath: dirA}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewFingerprintAdminHandler(eng, "", filepath.Join(t.TempDir(), "managed", "fingerprints"), "", nil, nil)

	st := getStatus(t, h)
	if st["engine_rev"] == nil || st["rule_count"] != float64(2) {
		t.Fatalf("engine facts missing from status: %v", st)
	}

	// Full-corpus replacement via a ZIP envelope (the zip upload branch).
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, body := range corpusA() {
		w, _ := zw.Create(name)
		_, _ = w.Write(body)
	}
	zw.Close()
	body, ctype := uploadBody(t, "file", "corpus.zip", zbuf.Bytes())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("zip upload: %d %s", rec.Code, rec.Body.String())
	}
	var up map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &up)
	if up["rule_count"] != float64(2) {
		t.Errorf("zip upload rule_count = %v", up["rule_count"])
	}
	// The engine hot-reloaded onto the managed corpus.
	rev, rules := eng.CorpusFacts()
	if rules != 2 || rev == "" || rev != up["rev"] {
		t.Fatalf("engine facts after upload: rev=%q rules=%d (want %v)", rev, rules, up["rev"])
	}

	// Rollback through the engine path: the first activation parked the
	// then-ACTIVE corpus per the handler's own precedence (here: embedded —
	// the handler does not track an engine-only path, mirroring production
	// wiring where the two always agree). The engine must follow the swap.
	rec = httptest.NewRecorder()
	h.Rollback(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fingerprints/rollback", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("engine rollback: %d", rec.Code)
	}
	if _, rules = eng.CorpusFacts(); rules != 2632 {
		t.Fatalf("engine rules after rollback = %d, want 2632 (embedded)", rules)
	}
	// Corpus facts rev tracks the rollback (content differs from upload).
	rev2, _ := eng.CorpusFacts()
	if rev2 == rev {
		t.Error("rollback did not move the engine rev (same corpus?)")
	}
}

func writeEngineCorpus(t *testing.T, dir string, rules int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "version: 1\nrules:\n"
	for i := 0; i < rules; i++ {
		body += fmt.Sprintf("  - id: e%d\n    match: {op: contains, value: \"probe\"}\n    service: svc\n", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "banner.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFingerprintAdminUpstreamFailureModes: every fetchUpstream error branch
// plus the agents-nil degrade and the oversize-upload cap.
func TestFingerprintAdminUpstreamFailureModes(t *testing.T) {
	mk := func(handler http.HandlerFunc) *FingerprintAdminHandler {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return NewFingerprintAdminHandler(nil, "", filepath.Join(t.TempDir(), "m"), srv.URL+"/manifest.json", nil, nil)
	}
	get := func(h *FingerprintAdminHandler) int {
		rec := httptest.NewRecorder()
		h.Upstream(rec, httptest.NewRequest(http.MethodGet, "/u", nil))
		return rec.Code
	}

	// Manifest endpoint down → 502.
	if c := get(mk(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))); c != http.StatusBadGateway {
		t.Errorf("manifest 404 → %d, want 502", c)
	}
	// Manifest not JSON → 502.
	if c := get(mk(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))); c != http.StatusBadGateway {
		t.Errorf("non-JSON manifest → %d, want 502", c)
	}
	// Tarball 404 → 502.
	if c := get(mk(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			_, _ = w.Write([]byte(`{"corpus_version":"1","tarball":"gone.tar.gz"}`))
			return
		}
		http.NotFound(w, r)
	}))); c != http.StatusBadGateway {
		t.Errorf("tarball 404 → %d, want 502", c)
	}
	// Tarball is not a corpus envelope → 502 (extract error).
	if c := get(mk(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			_, _ = w.Write([]byte(`{"corpus_version":"1","tarball":"c.tar.gz"}`))
			return
		}
		_, _ = w.Write([]byte{0x1f, 0x8b, 0xff, 0xff})
	}))); c != http.StatusBadGateway {
		t.Errorf("garbage tarball → %d, want 502", c)
	}
	// Upstream corpus the engine rejects → 502.
	bad, _ := fpsync.TarGz(map[string][]byte{
		"broken.yaml": []byte("version: 1\nrules:\n  - id: x\n    match: {op: regex, value: \"(unclosed[\"}\n    service: x\n"),
	})
	if c := get(mk(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			_, _ = w.Write([]byte(`{"corpus_version":"1","tarball":"c.tar.gz"}`))
			return
		}
		_, _ = w.Write(bad)
	}))); c != http.StatusBadGateway {
		t.Errorf("rejected corpus → %d, want 502", c)
	}
	// Apply against a broken upstream → 502, nothing activated.
	ha := mk(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	rec := httptest.NewRecorder()
	ha.UpstreamApply(rec, httptest.NewRequest(http.MethodPost, "/a", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("apply broken upstream → %d, want 502", rec.Code)
	}
	if st := getStatus(t, ha); st["source"] != "embedded" {
		t.Errorf("failed apply must not activate: %v", st["source"])
	}

	// Agents with nil queries degrades to an empty table.
	rec = httptest.NewRecorder()
	newAdminHandler(t).Agents(rec, httptest.NewRequest(http.MethodGet, "/ag", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"total":0`) {
		t.Errorf("agents nil-queries degrade: %d %s", rec.Code, rec.Body.String())
	}

	// Oversize upload is refused before staging (cap + 2 bytes).
	big := make([]byte, fpsync.MaxArchiveBytes+2)
	for i := range big {
		big[i] = 'x'
	}
	hb := newAdminHandler(t)
	body, ctype := uploadBody(t, "file", "big.tar.gz", big)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fingerprints", body)
	req.Header.Set("Content-Type", ctype)
	rec = httptest.NewRecorder()
	hb.Put(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "size cap") {
		t.Errorf("oversize upload → %d %s", rec.Code, rec.Body.String())
	}
}
