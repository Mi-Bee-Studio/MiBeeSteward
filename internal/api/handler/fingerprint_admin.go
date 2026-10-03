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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"
	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/db"
	"mibee-steward/internal/fpsync"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/scannerv2/classify"
	enginepkg "mibee-steward/internal/service/scannerv2/engine"
)

// FingerprintAdminHandler is the admin-plane fingerprint corpus management
// surface (settings → fingerprints): status, upload/replace, single-file
// replace, rollback, upstream check + one-click apply, and the fleet's
// corpus-adoption view.
//
// Invariants shared by every mutating path:
//   - a corpus is ACTIVATED only after the rule engine's own loader accepts
//     it (parse + regex validation + non-zero rules); anything else is a 422
//     carrying the engine's error, and the live corpus keeps running;
//   - activation is a directory swap (managed → managed.prev → new), so a
//     crash mid-swap at worst leaves the previous corpus in place;
//   - after activation the engine hot-reloads (no center restart) and the
//     distribution endpoint's revision moves, so sync-enabled agents pick
//     the new corpus up on their next poll.
//
// While scanner.fingerprint_path is explicitly configured the managed
// corpus is shadowed — mutating endpoints answer 409 rather than silently
// fighting the operator's directory.
type FingerprintAdminHandler struct {
	engine       *enginepkg.Engine // nil in tests: hot-reload skipped, facts degrade
	explicitPath string            // scanner.fingerprint_path ("" = not set)
	managedDir   string            // uploaded-corpora workspace (never "")
	upstreamURL  string
	queries      *db.Queries // fleet adoption rows; nil degrades the agents view
	auditRepo    *service.AuditRepository
	client       *http.Client
}

// NewFingerprintAdminHandler constructs the handler. managedDir must be
// non-empty (routes.go derives it from the database directory when the
// config leaves it unset).
func NewFingerprintAdminHandler(eng *enginepkg.Engine, explicitPath, managedDir, upstreamURL string, queries *db.Queries, auditRepo *service.AuditRepository) *FingerprintAdminHandler {
	return &FingerprintAdminHandler{
		engine:       eng,
		explicitPath: explicitPath,
		managedDir:   managedDir,
		upstreamURL:  upstreamURL,
		queries:      queries,
		auditRepo:    auditRepo,
		client:       &http.Client{Timeout: 20 * time.Second},
	}
}

// audit records who changed the corpus (every mutating endpoint fires it;
// failures degrade internally, they never fail the request).
func (h *FingerprintAdminHandler) audit(r *http.Request, action, details string) {
	if h.auditRepo == nil {
		return
	}
	entry := service.AuditLog{
		Action:       action,
		ResourceType: "fingerprint",
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Details:      details,
	}
	if userID, _, ok := middleware.GetUserFromContext(r); ok {
		entry.UserID = &userID
	}
	h.auditRepo.Log(r.Context(), entry)
}

// ── status ────────────────────────────────────────────────────────────────

// Get handles GET /api/v1/fingerprints: the status card.
func (h *FingerprintAdminHandler) Get(w http.ResponseWriter, _ *http.Request) {
	files, source := h.activeCorpus()
	list := make([]namedSize, 0, len(files))
	total := 0
	for name, body := range files {
		list = append(list, namedSize{Name: name, Size: int64(len(body))})
		total += len(body)
	}
	sortFilesByName(list)

	resp := map[string]any{
		"source":              source, // "dir" | "managed" | "embedded"
		"rev":                 fpsync.Hash(files),
		"bytes":               total,
		"files":               list,
		"uploads_enabled":     h.explicitPath == "",
		"upstream_configured": h.upstreamURL != "",
	}
	if h.engine != nil {
		rev, rules := h.engine.CorpusFacts()
		resp["engine_rev"] = rev
		resp["rule_count"] = rules
	}
	if prevFiles, err := fpsync.ReadCorpusDir(h.prevDir()); err == nil && len(prevFiles) > 0 {
		resp["prev_available"] = true
		resp["prev_rev"] = fpsync.Hash(prevFiles)
	} else {
		resp["prev_available"] = false
	}
	Success(w, resp)
}

// FileContent handles GET /api/v1/fingerprints/files/{name}: read-only YAML
// preview of one corpus file from the ACTIVE source.
func (h *FingerprintAdminHandler) FileContent(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(chi.URLParam(r, "name"))
	if name == "." || name == ".." || strings.ToLower(filepath.Ext(name)) != ".yaml" {
		Error(w, http.StatusBadRequest, "file name must be a flat .yaml name")
		return
	}
	files, _ := h.activeCorpus()
	body, ok := files[name]
	if !ok {
		Error(w, http.StatusNotFound, "no such corpus file: "+name)
		return
	}
	Success(w, map[string]any{"name": name, "size": len(body), "content": string(body)})
}

// ── upload / rollback ─────────────────────────────────────────────────────

// Put handles PUT /api/v1/fingerprints (multipart, field "file"):
// a tar.gz/zip full-corpus envelope, or a single .yaml replacing just that
// file within the current corpus. Either way the RESULT is validated as a
// whole before activation.
func (h *FingerprintAdminHandler) Put(w http.ResponseWriter, r *http.Request) {
	if h.explicitPath != "" {
		Error(w, http.StatusConflict, "scanner.fingerprint_path is explicitly configured; the managed corpus is shadowed — edit that directory instead")
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		Error(w, http.StatusBadRequest, "multipart: "+err.Error())
		return
	}
	f, fh, err := h.formFile(r)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, fpsync.MaxArchiveBytes+1))
	if err != nil || len(body) > fpsync.MaxArchiveBytes {
		Error(w, http.StatusBadRequest, "upload exceeds size cap")
		return
	}
	if len(body) == 0 {
		Error(w, http.StatusBadRequest, "empty upload")
		return
	}

	// Stage the candidate corpus: full envelope replaces everything; a lone
	// .yaml replaces just that file on top of the current corpus.
	staging, err := h.stagingDir("fp-upload-*")
	if err != nil {
		Error(w, http.StatusInternalServerError, "staging: "+err.Error())
		return
	}
	defer os.RemoveAll(staging)

	switch {
	case fpsync.IsTarGz(body):
		if _, err := fpsync.ExtractTarGz(staging, body); err != nil {
			Error(w, http.StatusBadRequest, "tar.gz: "+err.Error())
			return
		}
	case fpsync.IsZip(body):
		if _, err := fpsync.ExtractZip(staging, body); err != nil {
			Error(w, http.StatusBadRequest, "zip: "+err.Error())
			return
		}
	default:
		name := filepath.Base(fh.Filename)
		if strings.ToLower(filepath.Ext(name)) != ".yaml" || name == ".yaml" {
			Error(w, http.StatusBadRequest, "single-file upload must be a named .yaml (or upload a tar.gz/zip envelope)")
			return
		}
		if err := h.stageCurrent(staging); err != nil {
			Error(w, http.StatusInternalServerError, "stage current corpus: "+err.Error())
			return
		}
		if err := os.WriteFile(filepath.Join(staging, name), body, 0o644); err != nil {
			Error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	rev, rules, err := h.activate(staging)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	uploadName := "envelope"
	if fh != nil && fh.Filename != "" {
		uploadName = filepath.Base(fh.Filename)
	}
	h.audit(r, "fingerprint.upload", fmt.Sprintf("file=%s rev=%s rules=%d", uploadName, rev, rules))
	Success(w, map[string]any{"rev": rev, "rule_count": rules, "source": "managed"})
}

// Rollback handles POST /api/v1/fingerprints/rollback: swap the managed
// corpus with its predecessor (which becomes the new "previous", so rolling
// forward again is one more click). Same validation pipeline as upload.
func (h *FingerprintAdminHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	if h.explicitPath != "" {
		Error(w, http.StatusConflict, "scanner.fingerprint_path is explicitly configured; nothing to roll back")
		return
	}
	prevFiles, err := fpsync.ReadCorpusDir(h.prevDir())
	if err != nil || len(prevFiles) == 0 {
		Error(w, http.StatusConflict, "no previous corpus to roll back to")
		return
	}
	_ = prevFiles

	// cur → trash, prev → managed, trash → prev (the rolled-forward corpus
	// becomes the new rollback target).
	trash := h.managedDir + ".rollback-tmp"
	_ = os.RemoveAll(trash)
	if _, err := os.Stat(h.managedDir); err == nil {
		if err := os.Rename(h.managedDir, trash); err != nil {
			Error(w, http.StatusInternalServerError, "rollback: "+err.Error())
			return
		}
	}
	if err := os.Rename(h.prevDir(), h.managedDir); err != nil {
		_ = os.Rename(trash, h.managedDir) // best-effort restore
		Error(w, http.StatusInternalServerError, "rollback: "+err.Error())
		return
	}
	_ = os.Rename(trash, h.prevDir())

	// The prev corpus was validated when it was active, but re-validate
	// anyway — the pipeline is cheap and uniform.
	rev, rules, err := h.reloadManaged()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "fingerprint.rollback", fmt.Sprintf("rev=%s rules=%d", rev, rules))
	Success(w, map[string]any{"rev": rev, "rule_count": rules, "source": "managed"})
}

// ── upstream ──────────────────────────────────────────────────────────────

// upstreamManifest is the JSON contract of scanner.fingerprint_upstream.url:
// {corpus_version, tarball, sha256?} — tarball may be relative to the
// manifest URL.
type upstreamManifest struct {
	CorpusVersion string `json:"corpus_version"`
	Tarball       string `json:"tarball"`
	SHA256        string `json:"sha256,omitempty"`
}

// Upstream handles GET /api/v1/fingerprints/upstream: fetch + inspect the
// configured upstream WITHOUT activating anything.
func (h *FingerprintAdminHandler) Upstream(w http.ResponseWriter, r *http.Request) {
	if h.upstreamURL == "" {
		Error(w, http.StatusNotImplemented, "no upstream configured: set scanner.fingerprint_upstream.url (a JSON manifest {corpus_version, tarball, sha256?})")
		return
	}
	staging, rules, diff, err := h.fetchUpstream(r)
	if err != nil {
		Error(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	// Read-only diff: the staging copy of the upstream corpus has served its
	// purpose once the diff is computed. Remove it or every "check for
	// updates" click leaks one fp-upstream-* dir under the data root
	// (field-found 2026-10-04: four stale dirs after a setup session).
	defer os.RemoveAll(staging)
	Success(w, map[string]any{
		"upstream_version": diff.Version,
		"upstream_rev":     diff.Rev,
		"rule_count":       rules,
		"current_rev":      diff.CurrentRev,
		"up_to_date":       diff.Rev == diff.CurrentRev,
		"changed_files":    diff.ChangedFiles,
		"added_rules":      diff.Added,
		"removed_rules":    diff.Removed,
	})
}

// UpstreamApply handles POST /api/v1/fingerprints/upstream/apply: download +
// validate + activate the upstream corpus (the "one-click update").
func (h *FingerprintAdminHandler) UpstreamApply(w http.ResponseWriter, r *http.Request) {
	if h.upstreamURL == "" {
		Error(w, http.StatusNotImplemented, "no upstream configured")
		return
	}
	if h.explicitPath != "" {
		Error(w, http.StatusConflict, "scanner.fingerprint_path is explicitly configured; edit that directory instead")
		return
	}
	staging, _, _, err := h.fetchUpstream(r)
	if err != nil {
		Error(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer os.RemoveAll(staging)
	rev, rules, err := h.activate(staging)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "fingerprint.upstream_apply", fmt.Sprintf("rev=%s rules=%d", rev, rules))
	Success(w, map[string]any{"rev": rev, "rule_count": rules, "source": "managed"})
}

// ── fleet adoption ────────────────────────────────────────────────────────

// Agents handles GET /api/v1/fingerprints/agents: which corpus revision each
// agent runs (the adoption view; empty rev = pre-rev-reporting agent).
func (h *FingerprintAdminHandler) Agents(w http.ResponseWriter, r *http.Request) {
	if h.queries == nil {
		Success(w, map[string]any{"agents": []any{}, "total": 0})
		return
	}
	rows, err := h.queries.ListAgentStatus(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list agent status")
		return
	}
	_, currentRev := "", ""
	if h.engine != nil {
		currentRev, _ = h.engine.CorpusFacts()
	}
	type row struct {
		AgentID        string `json:"agent_id"`
		Version        string `json:"version"`
		FingerprintRev string `json:"fingerprint_rev"`
		UpToDate       bool   `json:"up_to_date"`
		LastReportAt   string `json:"last_report_at"`
	}
	out := make([]row, 0, len(rows))
	for _, a := range rows {
		out = append(out, row{
			AgentID:        a.AgentID,
			Version:        a.Version,
			FingerprintRev: a.FingerprintRev,
			UpToDate:       a.FingerprintRev != "" && (currentRev == "" || a.FingerprintRev == currentRev),
			LastReportAt:   a.LastReportAt.UTC().Format(time.RFC3339),
		})
	}
	Success(w, map[string]any{"agents": out, "total": len(out), "current_rev": currentRev})
}

// ── shared plumbing ───────────────────────────────────────────────────────

// activeCorpus resolves the corpus the engine classifies with, per the load
// precedence: explicit fingerprint_path > managed dir > embedded.
func (h *FingerprintAdminHandler) activeCorpus() (map[string][]byte, string) {
	if h.explicitPath != "" {
		if files, err := fpsync.ReadCorpusDir(h.explicitPath); err == nil && len(files) > 0 {
			return files, "dir"
		}
	}
	if files, err := fpsync.ReadCorpusDir(h.managedDir); err == nil && len(files) > 0 {
		return files, "managed"
	}
	files, err := classifyEmbedded()
	if err != nil {
		return map[string][]byte{}, "embedded"
	}
	return files, "embedded"
}

// stageCurrent copies the active corpus into staging (the base for
// single-file replacement uploads).
func (h *FingerprintAdminHandler) stageCurrent(staging string) error {
	files, _ := h.activeCorpus()
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(staging, name), body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// activate validates the staged corpus, swaps it in as the managed dir
// (parking the current one as .prev — one level only), and hot-reloads.
func (h *FingerprintAdminHandler) activate(staging string) (rev string, rules int, err error) {
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir(staging); err != nil {
		return "", 0, fmt.Errorf("corpus rejected by rule engine: %w", err)
	}
	if !rc.Loaded() {
		return "", 0, errors.New("corpus loaded zero rules")
	}
	if err := os.MkdirAll(filepath.Dir(h.managedDir), 0o755); err != nil {
		return "", 0, err
	}
	_ = os.RemoveAll(h.prevDir())
	if _, statErr := os.Stat(h.managedDir); statErr == nil {
		if err := os.Rename(h.managedDir, h.prevDir()); err != nil {
			return "", 0, err
		}
	} else if err := h.stageCurrent(h.prevDir()); err != nil {
		// First activation: no managed dir yet — materialize the corpus that
		// was active until now (embedded, or the explicit dir) as the rollback
		// target, so "rollback" works after ANY change, including the first.
		return "", 0, err
	}
	if err := os.Rename(staging, h.managedDir); err != nil {
		return "", 0, err
	}
	return h.reloadManaged()
}

// reloadManaged hot-reloads the engine from the managed dir and returns the
// new facts. Engine-less (tests) just computes the facts.
func (h *FingerprintAdminHandler) reloadManaged() (string, int, error) {
	files, err := fpsync.ReadCorpusDir(h.managedDir)
	if err != nil || len(files) == 0 {
		return "", 0, errors.New("managed corpus unreadable after activation")
	}
	if h.engine != nil {
		rev, rules, err := h.engine.ReloadFingerprints(h.managedDir, nil)
		if err != nil {
			return "", 0, err
		}
		return rev, rules, nil
	}
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir(h.managedDir); err != nil {
		return "", 0, err
	}
	return fpsync.Hash(files), rc.RuleCount(), nil
}

type corpusDiff struct {
	Version      string
	Rev          string
	CurrentRev   string
	ChangedFiles []string
	Added        []string
	Removed      []string
}

// fetchUpstream downloads manifest + tarball, validates the corpus, and
// returns (stagingDir, ruleCount, diff, err). Nothing is activated.
func (h *FingerprintAdminHandler) fetchUpstream(r *http.Request) (staging string, rules int, diff *corpusDiff, err error) {
	manJSON, err := h.httpGet(r.Context(), h.upstreamURL)
	if err != nil {
		return "", 0, nil, fmt.Errorf("manifest: %w", err)
	}
	var man upstreamManifest
	if err := json.Unmarshal(manJSON, &man); err != nil {
		return "", 0, nil, fmt.Errorf("manifest is not JSON: %w", err)
	}
	if man.Tarball == "" {
		return "", 0, nil, errors.New("manifest missing tarball url")
	}
	tarURL := man.Tarball
	if !strings.Contains(tarURL, "://") {
		// Relative tarball paths resolve against the manifest's directory
		// (…/manifest.json + corpus.tar.gz → …/corpus.tar.gz).
		if u, perr := url.Parse(h.upstreamURL); perr == nil && u.Path != "" {
			u.Path = path.Join(path.Dir(u.Path), tarURL)
			tarURL = u.String()
		} else {
			tarURL = strings.TrimSuffix(h.upstreamURL, "/") + "/" + tarURL
		}
	}
	tarGz, err := h.httpGet(r.Context(), tarURL)
	if err != nil {
		return "", 0, nil, fmt.Errorf("tarball: %w", err)
	}

	staging, err = h.stagingDir("fp-upstream-*")
	if err != nil {
		return "", 0, nil, err
	}
	if _, err := fpsync.ExtractTarGz(staging, tarGz); err != nil {
		os.RemoveAll(staging)
		return "", 0, nil, fmt.Errorf("tarball: %w", err)
	}
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir(staging); err != nil {
		os.RemoveAll(staging)
		return "", 0, nil, fmt.Errorf("upstream corpus rejected: %w", err)
	}
	if !rc.Loaded() {
		os.RemoveAll(staging)
		return "", 0, nil, errors.New("upstream corpus loaded zero rules")
	}

	upFiles, _ := fpsync.ReadCorpusDir(staging)
	curFiles, _ := h.activeCorpus()
	// Slices start non-nil so an empty diff serializes as [] instead of
	// null — a JSON null crashed the admin UI's render effect (`null.length`)
	// and made the whole upstream panel silently not render.
	diff = &corpusDiff{
		Version:      man.CorpusVersion,
		Rev:          fpsync.Hash(upFiles),
		CurrentRev:   fpsync.Hash(curFiles),
		ChangedFiles: []string{},
		Added:        []string{},
		Removed:      []string{},
	}
	upIDs, curIDs := ruleIDs(upFiles), ruleIDs(curFiles)
	for name := range upFiles {
		if _, ok := curFiles[name]; !ok {
			diff.ChangedFiles = append(diff.ChangedFiles, "+"+name)
		} else if fpsync.Hash(map[string][]byte{name: upFiles[name]}) != fpsync.Hash(map[string][]byte{name: curFiles[name]}) {
			diff.ChangedFiles = append(diff.ChangedFiles, "~"+name)
		}
	}
	for name := range curFiles {
		if _, ok := upFiles[name]; !ok {
			diff.ChangedFiles = append(diff.ChangedFiles, "-"+name)
		}
	}
	sortStrings(diff.ChangedFiles)
	for id := range upIDs {
		if !curIDs[id] {
			diff.Added = append(diff.Added, id)
		}
	}
	for id := range curIDs {
		if !upIDs[id] {
			diff.Removed = append(diff.Removed, id)
		}
	}
	sortStrings(diff.Added)
	sortStrings(diff.Removed)
	if len(diff.Added) > 50 {
		diff.Added = append(diff.Added[:50], fmt.Sprintf("… +%d more", len(diff.Added)-50))
	}
	if len(diff.Removed) > 50 {
		diff.Removed = append(diff.Removed[:50], fmt.Sprintf("… +%d more", len(diff.Removed)-50))
	}
	return staging, rc.RuleCount(), diff, nil
}

func (h *FingerprintAdminHandler) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, fpsync.MaxArchiveBytes+1))
}

func (h *FingerprintAdminHandler) prevDir() string { return h.managedDir + ".prev" }

// stagingDir creates a scratch directory next to the managed dir (parent
// chain ensured — the managed dir may not exist yet on a fresh install).
func (h *FingerprintAdminHandler) stagingDir(pattern string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(h.managedDir), 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(filepath.Dir(h.managedDir), pattern)
}

// formFile returns the (single) uploaded file regardless of its field name.
func (h *FingerprintAdminHandler) formFile(r *http.Request) (multipart.File, *multipart.FileHeader, error) {
	if r.MultipartForm == nil {
		return nil, nil, errors.New("multipart form missing")
	}
	for _, headers := range r.MultipartForm.File {
		if len(headers) == 0 {
			continue
		}
		f, err := headers[0].Open()
		if err != nil {
			return nil, nil, err
		}
		return f, headers[0], nil
	}
	return nil, nil, errors.New("no file part found (field name is arbitrary; exactly one file per request)")
}

// ruleIDs extracts the rule-id set of a corpus with a light YAML pass (used
// for the upstream diff view; the engine remains the validator).
func ruleIDs(files map[string][]byte) map[string]bool {
	ids := map[string]bool{}
	var doc struct {
		Rules []struct {
			ID string `yaml:"id"`
		} `yaml:"rules"`
	}
	for _, body := range files {
		doc.Rules = nil
		if err := yaml.Unmarshal(body, &doc); err != nil {
			continue
		}
		for _, rl := range doc.Rules {
			if rl.ID != "" {
				ids[rl.ID] = true
			}
		}
	}
	return ids
}

func classifyEmbedded() (map[string][]byte, error) { return classify.EmbeddedCorpusFiles() }

type namedSize struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func sortFilesByName(list []namedSize) {
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
}

func sortStrings(s []string) { sort.Strings(s) }
