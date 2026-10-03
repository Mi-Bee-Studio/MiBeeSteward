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
	"log/slog"
	"net/http"
	"strconv"
	"sync"

	"mibee-steward/internal/fpsync"
	"mibee-steward/internal/service/scannerv2/classify"
)

// AgentFingerprintsHandler serves the center's active fingerprint corpus to
// agents (GET /api/v1/agents/fingerprints) — the distribution half of the
// no-recompile corpus-update channel. Agents poll with their last-applied
// revision (?rev=…) and get 204 while unchanged, or the full corpus as a
// deterministic tar.gz (fpsync format) when it changed.
//
// Corpus source precedence mirrors the engine's own load order: an operator
// configured scanner.fingerprint_path dir wins (drop/edit YAML there and
// agents pick it up WITHOUT a center restart — the dir is re-read and
// re-hashed per request), otherwise the embedded corpus compiled into the
// center binary (immutable, hashed once).
//
// Auth: RequireAgentToken (registered alongside the report/command
// endpoints). The corpus is not agent-specific, but distribution is a
// fleet-internal channel — anonymous corpus listing is not offered.
type AgentFingerprintsHandler struct {
	fingerprintPath string

	mu        sync.Mutex
	embedded  bool         // last pack came from the embedded corpus (immutable → cacheable)
	cachedRev string       // rev of the packed envelope
	cachedTar []byte       // tar.gz body for cachedRev
	embeddedL *slog.Logger // lazy "packed corpus" one-shot log
}

// NewAgentFingerprintsHandler constructs the handler. fingerprintPath is the
// center's scanner.fingerprint_path ("" = serve the embedded corpus).
func NewAgentFingerprintsHandler(fingerprintPath string, logger *slog.Logger) *AgentFingerprintsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AgentFingerprintsHandler{fingerprintPath: fingerprintPath, embeddedL: logger}
}

// Get handles GET /api/v1/agents/fingerprints?rev=<last-applied-rev>.
// Responses:
//   - 204 No Content — the agent's rev matches the center's (no body)
//   - 200 — tar.gz envelope (fpsync format), X-Fingerprint-Rev carries the rev
//   - 503 — no corpus available (embedded missing AND dir unreadable)
func (h *AgentFingerprintsHandler) Get(w http.ResponseWriter, r *http.Request) {
	files, fromEmbedded, err := h.loadFiles()
	if err != nil {
		Error(w, http.StatusServiceUnavailable, "fingerprint corpus unavailable: "+err.Error())
		return
	}
	if len(files) == 0 {
		Error(w, http.StatusServiceUnavailable, "fingerprint corpus empty")
		return
	}
	rev := fpsync.Hash(files)

	h.mu.Lock()
	defer h.mu.Unlock()
	// Up-to-date fast path: the agent already runs this exact corpus.
	if r.URL.Query().Get("rev") == rev {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Pack (or reuse) the envelope. External-dir corpora are re-packed when
	// their rev moves; the embedded corpus is immutable so its pack is cached
	// for the process lifetime.
	if h.cachedTar == nil || h.cachedRev != rev || h.embedded != fromEmbedded {
		tarGz, err := fpsync.TarGz(files)
		if err != nil {
			Error(w, http.StatusInternalServerError, "pack corpus: "+err.Error())
			return
		}
		if h.cachedRev != rev {
			h.embeddedL.Info("agent fingerprint corpus packed",
				"rev", rev, "files", len(files), "source", corpusSource(fromEmbedded))
		}
		h.cachedTar, h.cachedRev, h.embedded = tarGz, rev, fromEmbedded
	}
	w.Header().Set("X-Fingerprint-Rev", rev)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(h.cachedTar)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.cachedTar)
}

// loadFiles resolves the corpus per the precedence rule. fromEmbedded reports
// whether the immutable embedded corpus was used (cacheable envelope).
func (h *AgentFingerprintsHandler) loadFiles() (files map[string][]byte, fromEmbedded bool, err error) {
	if h.fingerprintPath != "" {
		files, err = fpsync.ReadCorpusDir(h.fingerprintPath)
		if err != nil {
			return nil, false, err
		}
		if len(files) > 0 {
			return files, false, nil
		}
		// Empty (or newly emptied) dir: fall through to embedded, same as the
		// engine's own degrade path — agents must never see an empty corpus
		// just because an operator created the dir before populating it.
	}
	files, err = classify.EmbeddedCorpusFiles()
	return files, true, err
}

func corpusSource(embedded bool) string {
	if embedded {
		return "embedded"
	}
	return "dir"
}
