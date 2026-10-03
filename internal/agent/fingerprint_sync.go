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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"

	"mibee-steward/internal/fpsync"
)

// FingerprintSyncer keeps the agent's fingerprint corpus in step with the
// center (GET /api/v1/agents/fingerprints): poll with the last-applied
// revision, on change download the tar.gz envelope, VALIDATE it with the rule
// engine's own loader (a bad corpus never touches the live one), swap the
// on-disk directory, and re-exec so the engine reloads.
//
// This is the fleet half of the no-recompile corpus-update story: dropping
// edited YAML into the center's scanner.fingerprint_path (or shipping a new
// center binary) propagates to every agent on its next poll — no agent
// binary, package, or per-box SSH involved.
//
// Safety rails:
//   - the envelope is size/count/name-bounded (fpsync.ExtractTarGz)
//   - a corpus that fails rule-engine validation is discarded, the previous
//     corpus keeps running, and the agent does NOT restart
//   - restarts are rate-limited (MinRestartInterval): a flapping corpus
//     directory on the center can churn the fleet at most once per window
//   - the applied revision is persisted next to the synced dir; a fresh
//     process adopts it instead of re-downloading (no restart storm)
type FingerprintSyncer struct {
	centerURL  string
	authToken  string
	client     *http.Client
	dir        string // synced corpus directory (engine loads it via main)
	every      time.Duration
	minRestart time.Duration
	restart    func(reason string) // nil → swap without restart (picked up on next natural restart)
	logger     *slog.Logger
	now        func() time.Time

	// lastRestartAt also serves as "we adopted the on-disk rev" for the rate
	// limiter: adopting at startup counts as a (virtual) restart event so a
	// corpus change right after boot still respects the window.
	lastRestartAt time.Time
}

// MinRestartInterval is the default restart rate limit.
const MinRestartInterval = 5 * time.Minute

// NewFingerprintSyncer constructs the syncer. dir is where the synced corpus
// lives (created on first successful sync); the applied revision is persisted
// in dir+".rev". every <= 0 → 10m. restart may be nil (tests / deployments
// that prefer manual restarts: the swapped corpus is picked up whenever the
// process next starts).
func NewFingerprintSyncer(centerURL, authToken, dir string, every time.Duration, restart func(string), logger *slog.Logger) *FingerprintSyncer {
	if logger == nil {
		logger = slog.Default()
	}
	if every <= 0 {
		every = 10 * time.Minute
	}
	return &FingerprintSyncer{
		centerURL:  centerURL,
		authToken:  authToken,
		client:     newCenterClient(2 * time.Minute),
		dir:        dir,
		every:      every,
		minRestart: MinRestartInterval,
		restart:    restart,
		logger:     logger,
		now:        time.Now,
	}
}

// AppliedRev returns the revision persisted on disk ("" = none). cmd/agent
// logs it at startup so "which corpus revision is this agent running" is
// answerable from the fleet log, not guesswork.
func (s *FingerprintSyncer) AppliedRev() string {
	b, err := os.ReadFile(s.revPath())
	if err != nil {
		return ""
	}
	return string(b)
}

func (s *FingerprintSyncer) revPath() string { return s.dir + ".rev" }

// Start runs the poll loop until ctx is cancelled. The first check happens
// almost immediately so a fresh agent converges quickly.
func (s *FingerprintSyncer) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(s.every)
		defer t.Stop()
		s.check(ctx) // best-effort first poll
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.check(ctx)
			}
		}
	}()
}

// check runs one poll-and-apply cycle; errors are logged, never fatal —
// the next poll retries (CheckOnce surfaces them for tests instead).
func (s *FingerprintSyncer) check(ctx context.Context) {
	if _, err := s.CheckOnce(ctx); err != nil {
		s.logger.Warn("fingerprint sync: check failed", "error", err)
	}
}

// CheckOnce polls the center once and applies a changed corpus when one is
// offered. Returns the applied revision, "" when already up to date.
func (s *FingerprintSyncer) CheckOnce(ctx context.Context) (string, error) {
	applied := s.AppliedRev()
	url := s.centerURL + "/api/v1/agents/fingerprints?rev=" + applied
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return "", nil // already in step
	case http.StatusOK:
		// fall through to apply
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("fingerprints endpoint: status %d: %s", resp.StatusCode, string(body))
	}

	rev := resp.Header.Get("X-Fingerprint-Rev")
	if rev == "" {
		return "", errors.New("fingerprints response missing X-Fingerprint-Rev")
	}
	if rev == applied {
		return "", nil // race: center served an envelope for our own rev
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, fpsync.MaxArchiveBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > fpsync.MaxArchiveBytes {
		return "", fmt.Errorf("corpus envelope exceeds %d bytes", fpsync.MaxArchiveBytes)
	}
	if err := s.apply(rev, body); err != nil {
		return "", err
	}
	return rev, nil
}

// apply validates + swaps the corpus and re-execs (rate-limited). The
// revision file is only written once the corpus is committed to disk; if the
// restart is rate-limited the file is left untouched so the next poll
// re-attempts the full cycle (and the restart) instead of silently running a
// stale in-process corpus forever.
func (s *FingerprintSyncer) apply(rev string, tarGz []byte) error {
	// Stage + validate with the rule engine's own loader — a corpus that
	// fails to load (or loads zero rules) must never displace the live one.
	tmp, err := os.MkdirTemp(filepath.Dir(s.dirOrDot()), "fpsync-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	names, err := fpsync.ExtractTarGz(tmp, tarGz)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir(tmp); err != nil {
		return fmt.Errorf("corpus rejected by rule engine (keeping previous): %w", err)
	}
	if !rc.Loaded() {
		return errors.New("corpus loaded zero rules (keeping previous)")
	}

	// Commit: swap directories, then the revision marker. The engine loads
	// this dir at process start (cmd/agent wires it when
	// scanner.fingerprint_path is unset).
	old := s.dir + ".old"
	_ = os.RemoveAll(old)
	if err := os.Rename(s.dir, old); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmp, s.dir); err != nil {
		// Roll the previous corpus back into place.
		_ = os.Rename(old, s.dir)
		return err
	}
	_ = os.RemoveAll(old)

	if s.restart == nil || s.now().Sub(s.lastRestartAt) < s.minRestart {
		if s.restart != nil {
			s.logger.Warn("fingerprint sync: corpus applied to disk but restart rate-limited; will re-apply next poll",
				"rev", rev, "files", len(names), "min_restart_interval", s.minRestart)
		} else {
			// No restart hook: commit the revision marker — the corpus is on
			// disk and correct, the process picks it up on its next natural
			// restart. Avoids re-downloading every poll.
			_ = os.WriteFile(s.revPath(), []byte(rev), 0o644)
			s.logger.Info("fingerprint sync: corpus applied to disk (no restart hook; loads on next start)",
				"rev", rev, "files", len(names))
		}
		return nil
	}

	// Commit the revision, then re-exec. lastRestartAt/revPath are updated
	// BEFORE the exec replaces this process image.
	s.lastRestartAt = s.now()
	if err := os.WriteFile(s.revPath(), []byte(rev), 0o644); err != nil {
		return err
	}
	s.logger.Info("fingerprint sync: corpus updated, restarting to activate",
		"rev", rev, "files", len(names))
	s.restart("fingerprint corpus updated rev=" + rev)
	return nil
}

func (s *FingerprintSyncer) dirOrDot() string {
	if d := filepath.Dir(s.dir); d != "" {
		return d
	}
	return "."
}

// AdoptStartupRev records the on-disk revision as freshly applied (counting
// as a restart event for the rate limiter) so the first poll after boot
// doesn't immediately re-download what the process already loaded. Called by
// cmd/agent when the engine loaded the synced dir.
func (s *FingerprintSyncer) AdoptStartupRev(rev string) {
	s.lastRestartAt = s.now()
	s.logger.Info("fingerprint sync: adopted on-disk corpus", "rev", rev)
}
