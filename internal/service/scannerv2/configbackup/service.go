// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package configbackup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/configdiff"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2/sshcred"
)

// FetchFunc is the config-fetch signature. Production wires FetchConfig; tests
// inject a mock so runOnce is testable without a real SSH server.
type FetchFunc func(ctx context.Context, host string, port int, cred *sshcred.Credential, brand string, timeout time.Duration) (config string, hostKeyFP string, err error)

// Service is the periodic config-backup sweep (#137). It mirrors cleanup.Service:
// a ticker goroutine (Start/Stop) that runs runOnce on startup + each tick.
// runOnce selects the router/switch/firewall devices with an SSH credential
// bound, fetches each device's running-config, and on a real change stores a new
// device_configs version (with the configdiff vs the prior version) + emits a
// device_config_changed event. Unchanged fetches store nothing (the hash gate).
type Service struct {
	db             *sql.DB
	queries        *db.Queries
	sshResolver    *sshcred.Resolver
	changeRecorder changedetect.ChangeRecorder
	fetchFn        FetchFunc
	interval       time.Duration
	timeout        time.Duration
	port           int
	logger         *slog.Logger
	cancel         context.CancelFunc
	done           chan struct{}
}

// New constructs the Service. fetchFn is FetchConfig in production; tests inject
// a mock. interval<=0 defaults to 6h; timeout<=0 defaults to 30s; port<=0 → 22.
func New(dbConn *sql.DB, queries *db.Queries, sshResolver *sshcred.Resolver, rec changedetect.ChangeRecorder, fetchFn FetchFunc, interval, timeout time.Duration, logger *slog.Logger) *Service {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		db: dbConn, queries: queries, sshResolver: sshResolver, changeRecorder: rec,
		fetchFn: fetchFn, interval: interval, timeout: timeout, port: 22, logger: logger,
		done: make(chan struct{}),
	}
}

// Start runs one sweep immediately, then on every interval tick, until Stop.
func (s *Service) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go func() {
		defer close(s.done)
		s.runOnce(ctx)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runOnce(ctx)
			}
		}
	}()
}

// Stop signals the sweep loop to exit and waits for it.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}

// runOnce backs up every candidate device. Each device is independent — a
// failure (no credential / SSH error / store error) is logged and skipped so one
// bad device doesn't abort the sweep.
func (s *Service) runOnce(ctx context.Context) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ip_address, COALESCE(brand,''), ssh_credential_id
		FROM devices
		WHERE type IN ('router','switch','firewall') AND ssh_credential_id IS NOT NULL`)
	if err != nil {
		s.logger.Warn("configbackup: select devices failed", "error", err)
		return
	}
	// Materialize the candidates and CLOSE the rows cursor BEFORE the per-device
	// work. Holding the cursor open while backupOne runs DB queries + SSH fetch
	// per device would (a) hold a pooled connection for the whole sweep and
	// (b) deadlock under a single-connection pool (test in-memory DB). Scanning
	// into a slice first is both safer and the correct production pattern.
	type candidate struct {
		deviceID  int64
		ip        string
		brand     string
		sshCredID int64
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.deviceID, &c.ip, &c.brand, &c.sshCredID); err != nil {
			s.logger.Warn("configbackup: scan device row", "error", err)
			continue
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	for _, c := range candidates {
		if ctx.Err() != nil {
			return
		}
		s.backupOne(ctx, c.deviceID, c.ip, c.brand, c.sshCredID)
	}
}

// backupOne fetches one device's config, diffs vs the latest stored version, and
// on a change stores a new version + emits an event. First capture (no prior
// version) stores a baseline without emitting (it's not a "change").
func (s *Service) backupOne(ctx context.Context, deviceID int64, ip, brand string, sshCredID int64) {
	cred, err := s.sshResolver.Resolve(ctx, sshCredID)
	if err != nil {
		s.logger.Warn("configbackup: resolve ssh credential skipped", "device_id", deviceID, "cred_id", sshCredID, "error", err)
		return
	}
	config, fp, err := s.fetchFn(ctx, ip, s.port, cred, brand, s.timeout)
	if err != nil {
		s.logger.Warn("configbackup: fetch config failed", "device_id", deviceID, "ip", ip, "error", err)
		return
	}
	// TOFU pin: first connect (no pinned fp) accepts any key; pin the actual fp
	// so subsequent connects verify against it (MITM guard).
	if cred.HostKeyFP == "" && fp != "" {
		if err := sshcred.SetHostKeyFP(ctx, s.db, sshCredID, fp); err != nil {
			s.logger.Warn("configbackup: pin host key failed", "device_id", deviceID, "error", err)
		}
	}

	newHash := hashOf(config)
	latest, err := s.queries.GetLatestDeviceConfig(ctx, deviceID)
	hasLatest := err == nil
	if hasLatest && latest.ConfigHash == newHash {
		return // unchanged — no-op (the common case on a stable device)
	}
	diff := ""
	if hasLatest {
		diff = configdiff.MustDiff("prev", latest.ConfigText, "current", config)
	}
	if _, err := s.queries.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
		DeviceID: deviceID, ConfigHash: newHash, ConfigText: config, Protocol: "ssh", DiffFromPrev: diff,
	}); err != nil {
		s.logger.Warn("configbackup: store config failed", "device_id", deviceID, "error", err)
		return
	}
	if diff != "" {
		// A real change (not the first capture) → record it.
		s.changeRecorder.Record(ctx, changedetect.ChangeEvent{
			ChangeType: changedetect.ChangeTypeDeviceConfigChanged,
			EntityType: changedetect.EntityTypeDevice,
			DeviceID:   deviceID,
		})
	}
	s.logger.Info("configbackup: stored config version", "device_id", deviceID, "changed", diff != "")
}

// hashOf returns the lowercase hex sha256 of s (the device_configs.config_hash).
func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
