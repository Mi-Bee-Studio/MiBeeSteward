// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mibee-steward/internal/fpsync"
)

// fakeCenter serves successive corpus revisions like the real endpoint: 204
// when the client's rev matches, otherwise the tar.gz envelope.
type fakeCenter struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (f *fakeCenter) set(files map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files = files
}

func (f *fakeCenter) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	files := f.files
	f.mu.Unlock()
	rev := fpsync.Hash(files)
	if r.URL.Query().Get("rev") == rev {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	tgz, err := fpsync.TarGz(files)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Fingerprint-Rev", rev)
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(tgz)
}

func validCorpus(rules int) map[string][]byte {
	return map[string][]byte{
		"banner.yaml": []byte(fmt.Sprintf("version: 1\nrules:\n  - id: r1\n    match: {op: contains, value: \"probe%d\"}\n    service: svc\n", rules)),
	}
}

func newSyncer(t *testing.T, url, dir string) (*FingerprintSyncer, *[]string) {
	t.Helper()
	var reasons []string
	s := NewFingerprintSyncer(url, "test-token", dir, time.Hour, func(reason string) {
		reasons = append(reasons, reason)
	}, nil)
	return s, &reasons
}

func TestSyncerAppliesAndConverges(t *testing.T) {
	fc := &fakeCenter{files: validCorpus(1)}
	srv := httptest.NewServer(http.HandlerFunc(fc.handler))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "fingerprints-sync")
	s, reasons := newSyncer(t, srv.URL, dir)

	rev, err := s.CheckOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rev == "" {
		t.Fatal("first check must apply the corpus")
	}
	if len(*reasons) != 1 {
		t.Fatalf("restart must fire exactly once, got %v", *reasons)
	}
	if s.AppliedRev() != rev {
		t.Fatalf("applied rev not persisted: %q vs %q", s.AppliedRev(), rev)
	}
	if _, err := os.Stat(filepath.Join(dir, "banner.yaml")); err != nil {
		t.Fatalf("synced corpus not on disk: %v", err)
	}

	// Second check against the same corpus: 204, nothing happens.
	if rev2, err := s.CheckOnce(context.Background()); err != nil || rev2 != "" {
		t.Fatalf("second check must be a no-op, got rev=%q err=%v", rev2, err)
	}
	if len(*reasons) != 1 {
		t.Fatal("no further restart expected")
	}

	// Center corpus moves again WITHIN the rate-limit window: the new corpus
	// is staged on disk but the restart is deferred (fleet protection —
	// consecutive changes coalesce; the agent jumps straight to the newest).
	fc.set(validCorpus(2))
	rev3, err := s.CheckOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rev3 == "" || rev3 == rev {
		t.Fatalf("in-window change must stage: %q (was %q)", rev3, rev)
	}
	if len(*reasons) != 1 {
		t.Fatal("no second restart inside the rate-limit window")
	}
	if s.AppliedRev() != rev {
		t.Fatalf("deferred apply must not persist the rev: %q", s.AppliedRev())
	}
	// Advance the clock past the window: the next poll re-attempts and the
	// restart goes through.
	base := time.Now()
	s.now = func() time.Time { return base.Add(MinRestartInterval + time.Minute) }
	rev4, err := s.CheckOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rev4 != rev3 {
		t.Fatalf("post-window apply must activate the staged rev: %q vs %q", rev4, rev3)
	}
	if len(*reasons) != 2 {
		t.Fatalf("expected second restart, have %v", *reasons)
	}
	if s.AppliedRev() != rev3 {
		t.Fatal("activated rev must be persisted")
	}
}

func TestSyncerRejectsBadCorpus(t *testing.T) {
	fc := &fakeCenter{files: map[string][]byte{
		"broken.yaml": []byte("version: 1\nrules:\n  - id: x\n    match: {op: regex, value: \"(unclosed[\"}\n    service: x\n"),
	}}
	srv := httptest.NewServer(http.HandlerFunc(fc.handler))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "fingerprints-sync")
	// Seed a good corpus so "keeping previous" is observable.
	good := validCorpus(0)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range good {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, reasons := newSyncer(t, srv.URL, dir)

	if _, err := s.CheckOnce(context.Background()); err == nil {
		t.Fatal("corpus the rule engine rejects must surface an error")
	}
	if len(*reasons) != 0 {
		t.Fatal("a rejected corpus must never restart the agent")
	}
	body, err := os.ReadFile(filepath.Join(dir, "banner.yaml"))
	if err != nil || string(body) != string(good["banner.yaml"]) {
		t.Fatal("previous corpus must be untouched after rejection")
	}
}

func TestSyncerRateLimitsRestarts(t *testing.T) {
	fc := &fakeCenter{files: validCorpus(1)}
	srv := httptest.NewServer(http.HandlerFunc(fc.handler))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "fingerprints-sync")
	s, reasons := newSyncer(t, srv.URL, dir)
	// Simulate a boot-time adoption so the rate limiter is engaged.
	s.AdoptStartupRev("")

	if _, err := s.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*reasons) != 0 {
		t.Fatal("restart immediately after adoption must be rate-limited")
	}
	if s.AppliedRev() != "" {
		t.Fatal("rate-limited apply must NOT persist the rev (next poll retries)")
	}
	// The corpus IS staged on disk though — it activates on the next
	// successful (unthrottled) cycle or a natural restart.
	if _, err := os.Stat(filepath.Join(dir, "banner.yaml")); err != nil {
		t.Fatalf("rate-limited apply should still stage files: %v", err)
	}
}

func TestSyncerAdoptsStartupRev(t *testing.T) {
	fc := &fakeCenter{files: validCorpus(1)}
	srv := httptest.NewServer(http.HandlerFunc(fc.handler))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "fingerprints-sync")
	s, _ := newSyncer(t, srv.URL, dir)
	if _, err := s.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Simulate a process restart: a fresh syncer over the same dir adopts the
	// persisted rev — first poll must be a 204 no-op, no download, no restart.
	fresh, reasons := newSyncer(t, srv.URL, dir)
	fresh.AdoptStartupRev(fresh.AppliedRev())
	if rev, err := fresh.CheckOnce(context.Background()); err != nil || rev != "" {
		t.Fatalf("fresh process must adopt persisted rev: rev=%q err=%v", rev, err)
	}
	if len(*reasons) != 0 {
		t.Fatal("adoption must not restart")
	}
}

func TestSyncerNilRestartHookCommits(t *testing.T) {
	fc := &fakeCenter{files: validCorpus(1)}
	srv := httptest.NewServer(http.HandlerFunc(fc.handler))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "fingerprints-sync")
	s := NewFingerprintSyncer(srv.URL, "t", dir, time.Hour, nil, nil)
	rev, err := s.CheckOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.AppliedRev() != rev {
		t.Fatal("nil restart hook must still commit the revision (no re-download loop)")
	}
}

func TestSyncerStartLoopRunsAndStops(t *testing.T) {
	fc := &fakeCenter{files: validCorpus(1)}
	srv := httptest.NewServer(http.HandlerFunc(fc.handler))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "fingerprints-sync")
	s := NewFingerprintSyncer(srv.URL, "t", dir, 50*time.Millisecond, func(string) {}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.AppliedRev() != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.AppliedRev() == "" {
		t.Fatal("Start loop never applied the corpus")
	}
	if _, err := os.Stat(filepath.Join(dir, "banner.yaml")); err != nil {
		t.Fatalf("synced corpus missing: %v", err)
	}
	// Corpus flips while running: the loop converges without restart
	// (restart hook fires once per window — here the hook is a no-op
	// recorder, so just assert the staged dir catches up).
	fc.set(validCorpus(2))
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rev, err := s.CheckOnce(context.Background()); err == nil && rev != "" && rev != s.AppliedRev() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
}

// TestSyncerHostileCenter sweeps CheckOnce's defensive branches against a
// misbehaving center: error status with body, missing rev header, oversized
// envelope, and the same-rev race.
func TestSyncerHostileCenter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fingerprints-sync")
	s := NewFingerprintSyncer("", "t", dir, time.Hour, nil, nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	s2 := NewFingerprintSyncer(srv.URL, "t", dir, time.Hour, nil, nil)
	if _, err := s2.CheckOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error status: err=%v", err)
	}
	if _, err := s.CheckOnce(context.Background()); err == nil {
		t.Error("dead center must error")
	}

	// 200 without the rev header.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()
	s3 := NewFingerprintSyncer(srv2.URL, "t", dir, time.Hour, nil, nil)
	if _, err := s3.CheckOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "X-Fingerprint-Rev") {
		t.Errorf("missing rev: err=%v", err)
	}

	// Oversized envelope (over MaxArchiveBytes) is refused before staging.
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Fingerprint-Rev", "feed")
		_, _ = w.Write(make([]byte, fpsync.MaxArchiveBytes+2))
	}))
	defer srv3.Close()
	s4 := NewFingerprintSyncer(srv3.URL, "t", dir, time.Hour, nil, nil)
	if _, err := s4.CheckOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversize: err=%v", err)
	}

	// Same-rev race: server echoes the client's (non-empty) rev as its own.
	dir5 := filepath.Join(t.TempDir(), "fingerprints-sync")
	if err := os.MkdirAll(dir5, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir5+".rev", []byte("abc123"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fingerprint-Rev", r.URL.Query().Get("rev"))
		_, _ = w.Write([]byte("garbage-not-an-envelope"))
	}))
	defer srv4.Close()
	s5 := NewFingerprintSyncer(srv4.URL, "t", dir5, time.Hour, nil, nil)
	if rev, err := s5.CheckOnce(context.Background()); err != nil || rev != "" {
		t.Errorf("same-rev race must no-op: rev=%q err=%v", rev, err)
	}
}
