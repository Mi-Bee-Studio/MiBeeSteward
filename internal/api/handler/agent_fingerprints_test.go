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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"mibee-steward/internal/fpsync"
)

func getFingerprints(h *AgentFingerprintsHandler, rev string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/fingerprints?rev="+rev, nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	return rec
}

// TestAgentFingerprintsEmbedded serves the real embedded corpus: rev is
// stable, the rev-match fast path is 204, and a mismatch returns a loadable
// tar.gz envelope.
func TestAgentFingerprintsEmbedded(t *testing.T) {
	h := NewAgentFingerprintsHandler("", "", nil)

	rec := getFingerprints(h, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("no-rev request: status %d", rec.Code)
	}
	rev := rec.Header().Get("X-Fingerprint-Rev")
	if len(rev) != 64 {
		t.Fatalf("rev header missing/garbage: %q", rev)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Fatalf("content-type = %q", ct)
	}

	if rec2 := getFingerprints(h, rev); rec2.Code != http.StatusNoContent {
		t.Fatalf("matching rev must 204, got %d", rec2.Code)
	}
	// Envelope loads as a corpus.
	names, err := fpsync.ExtractTarGz(t.TempDir(), rec.Body.Bytes())
	if err != nil {
		t.Fatalf("extract envelope: %v", err)
	}
	if len(names) < 5 {
		t.Fatalf("embedded corpus envelope suspiciously small: %v", names)
	}
	// Determinism: same corpus, same envelope bytes.
	rec3 := getFingerprints(h, "force-redownload")
	if rec3.Body.String() != rec.Body.String() {
		t.Error("envelope bytes not deterministic across packs")
	}
}

// TestAgentFingerprintsDirOverride: a configured fingerprint_path dir wins
// over the embedded corpus, and emptying the dir falls back to embedded.
func TestAgentFingerprintsDirOverride(t *testing.T) {
	dir := t.TempDir()
	corpus := map[string][]byte{"custom.yaml": []byte("version: 1\nrules: []\n")}
	for name, body := range corpus {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := NewAgentFingerprintsHandler(dir, "", nil)

	rec := getFingerprints(h, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	dirRev := rec.Header().Get("X-Fingerprint-Rev")
	if dirRev != fpsync.Hash(corpus) {
		t.Fatalf("dir rev %q != hash of dir corpus %q", dirRev, fpsync.Hash(corpus))
	}
	embeddedOnly := NewAgentFingerprintsHandler("", "", nil)
	embeddedRec := getFingerprints(embeddedOnly, "")
	if dirRev == embeddedRec.Header().Get("X-Fingerprint-Rev") {
		t.Fatal("dir corpus must override embedded")
	}

	// Empty the dir → degrade to embedded, exactly like the engine's own load
	// path (agents must never see an empty corpus from a pre-created dir).
	if err := os.Remove(filepath.Join(dir, "custom.yaml")); err != nil {
		t.Fatal(err)
	}
	rec = getFingerprints(h, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d after emptying dir", rec.Code)
	}
	if got := rec.Header().Get("X-Fingerprint-Rev"); got != embeddedRec.Header().Get("X-Fingerprint-Rev") {
		t.Fatalf("empty dir must fall back to embedded: %q", got)
	}
}

// TestAgentFingerprintsDirLiveUpdate: editing the dir between requests
// changes the served revision with NO restart — the whole point of the
// channel.
func TestAgentFingerprintsDirLiveUpdate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("version: 1\nrules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewAgentFingerprintsHandler(dir, "", nil)
	first := getFingerprints(h, "").Header().Get("X-Fingerprint-Rev")

	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("version: 1\nrules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := getFingerprints(h, first).Header().Get("X-Fingerprint-Rev")
	if second == first || second == "" {
		t.Fatalf("dir edit must move the rev: %q → %q", first, second)
	}
}
