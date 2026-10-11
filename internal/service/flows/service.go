// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package flows

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2/ebpf"
)

// cacheTTL bounds how stale the managed-prefix and device-id caches may be.
// Both inputs move slowly (networks and devices change on human timescales);
// a 5-minute window keeps the hot ingest path off the database.
const cacheTTL = 5 * time.Minute

// DBTX is the subset of the database handle the ingester needs (satisfied
// by *sql.DB and the busy-retry wrapper alike).
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// Service ingests drained flow batches: fold to device-level aggregates,
// resolve inventory identities, upsert speaks-with rows, and emit a
// change_log event the first time two MANAGED devices are seen talking
// (the lateral-visibility signal). Everything here is best-effort: a failed
// batch logs and drops — flow telemetry may degrade, never block.
type Service struct {
	conn    DBTX
	queries *db.Queries
	watcher *changedetect.Watcher
	logger  *slog.Logger

	mu          sync.Mutex
	prefixT     time.Time
	prefixCache []netip.Prefix
	deviceT     time.Time
	// deviceIDs caches IP → device id; a missing key inside the cache window
	// is a negative answer (external or unmanaged host).
	deviceIDs map[string]int64
}

// NewService constructs the ingester. watcher may be nil (events still
// persist to change_log; the SSE/rule fan-out just doesn't get pushed).
func NewService(conn DBTX, queries *db.Queries, watcher *changedetect.Watcher, logger *slog.Logger) *Service {
	return &Service{
		conn:      conn,
		queries:   queries,
		watcher:   watcher,
		logger:    logger,
		deviceIDs: make(map[string]int64),
	}
}

// Ingest processes one drained batch end to end. Callers hand off the
// exporter goroutine's batch to a worker (the sink contract); Ingest itself
// is synchronous and safe to call concurrently — caches are mutex-guarded
// and writes run in one transaction.
func (s *Service) Ingest(ctx context.Context, samples []ebpf.FlowSample) {
	if len(samples) == 0 {
		return
	}
	prefixes := s.managedPrefixes(ctx)
	aggs := Fold(samples, prefixes)
	if len(aggs) == 0 {
		return
	}
	ids := s.resolveDevices(ctx, aggs, prefixes)

	now := time.Now().UTC()
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Warn("flows: begin tx failed", "error", err)
		return
	}
	defer tx.Rollback() //nolint:errcheck

	type newPair struct {
		deviceID, peerID int64
		deviceIP, peerIP string
		bytes            uint64
	}
	var events []newPair
	for _, a := range aggs {
		deviceID, ok := ids[a.DeviceIP]
		if !ok {
			continue // LAN-side host is not in the inventory: nothing to attach
		}
		var peerID int64
		if id, known := ids[a.PeerIP]; known && contains(prefixes, mustAddr(a.PeerIP)) {
			peerID = id
		}
		isNew := false
		// Canonical side (lower id) emits the pair event once — both
		// mirrored rows are new on first sight and would double-fire.
		if peerID != 0 && deviceID < peerID {
			// Event candidates are LAN-internal pairs only: first-seen
			// EXTERNAL peers would be noise (every CDN is "new").
			var one int
			err := tx.QueryRowContext(ctx,
				`SELECT 1 FROM device_speaks_with WHERE device_id = ? AND peer_ip = ?`,
				deviceID, a.PeerIP).Scan(&one)
			isNew = err == sql.ErrNoRows
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO device_speaks_with (device_id, peer_ip, peer_device_id, bytes_out, bytes_in, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(device_id, peer_ip) DO UPDATE SET
				bytes_out = device_speaks_with.bytes_out + excluded.bytes_out,
				bytes_in = device_speaks_with.bytes_in + excluded.bytes_in,
				peer_device_id = COALESCE(excluded.peer_device_id, device_speaks_with.peer_device_id),
				last_seen = excluded.last_seen`,
			deviceID, a.PeerIP, nullInt64(peerID), int64(a.BytesOut), int64(a.BytesIn), now, now); err != nil {
			s.logger.Debug("flows: upsert speaks row failed", "device", a.DeviceIP, "peer", a.PeerIP, "error", err)
			continue
		}
		if isNew {
			events = append(events, newPair{
				deviceID: deviceID, peerID: peerID,
				deviceIP: a.DeviceIP, peerIP: a.PeerIP,
				bytes: a.BytesOut + a.BytesIn,
			})
		}
	}
	if err := tx.Commit(); err != nil {
		s.logger.Warn("flows: commit failed", "error", err)
		return
	}

	for _, ev := range events {
		s.emitFirstSeen(ctx, now, ev.deviceID, ev.peerID, ev.peerIP, ev.bytes)
	}
	if len(events) > 0 {
		s.logger.Info("flows: speaks-with aggregates updated",
			"rows", len(aggs), "first_seen_pairs", len(events))
	}
}

// emitFirstSeen writes one change_log row (and pushes it to the watcher) for
// a newly observed managed↔managed conversation. Failures log only.
func (s *Service) emitFirstSeen(ctx context.Context, now time.Time, deviceID, peerID int64, peerIP string, bytes uint64) {
	after, _ := json.Marshal(map[string]any{
		"peer_ip":        peerIP,
		"peer_device_id": peerID,
		"bytes_total":    bytes,
		"source":         "passive:ebpf:flows",
	})
	networkID := s.networkOf(ctx, deviceID)
	row, err := s.queries.CreateChangeLog(ctx, db.CreateChangeLogParams{
		NetworkID:  networkID,
		ChangeType: changedetect.ChangeTypeSpeaksWithNew,
		EntityType: changedetect.EntityTypeDevice,
		EntityID:   &deviceID,
		AfterData:  strPtr(string(after)),
		DetectedAt: now,
	})
	if err != nil {
		s.logger.Warn("flows: write change_log failed", "error", err)
		return
	}
	if s.watcher != nil {
		s.watcher.Push(row)
	}
}

// managedPrefixes returns the inventory's network CIDRs (cached). Parse
// failures and an empty networks table both yield an empty slice — Fold then
// drops everything, which is the safe no-op.
func (s *Service) managedPrefixes(ctx context.Context) []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.prefixT) < cacheTTL {
		return s.prefixCache
	}
	nets, err := s.queries.ListNetworks(ctx)
	if err != nil {
		s.logger.Warn("flows: list networks failed", "error", err)
		return s.prefixCache // stale beats empty
	}
	var out []netip.Prefix
	for _, n := range nets {
		if n.Cidr == nil {
			continue
		}
		if p, err := netip.ParsePrefix(*n.Cidr); err == nil {
			out = append(out, p)
		}
	}
	s.prefixCache = out
	s.prefixT = time.Now()
	return out
}

// resolveDevices maps the batch's distinct IPs to device ids in one cache
// window (first call per window pays one GetDeviceByIP per distinct IP).
func (s *Service) resolveDevices(ctx context.Context, aggs []Agg, prefixes []netip.Prefix) map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.deviceT) < cacheTTL {
		return s.deviceIDs
	}
	distinct := make(map[string]bool)
	for _, a := range aggs {
		distinct[a.DeviceIP] = true
		if contains(prefixes, mustAddr(a.PeerIP)) {
			distinct[a.PeerIP] = true
		}
	}
	s.deviceT = time.Now()
	for ip := range distinct {
		if _, done := s.deviceIDs[ip]; done {
			continue
		}
		if d, err := s.queries.GetDeviceByIP(ctx, ip); err == nil {
			s.deviceIDs[ip] = d.ID
		}
	}
	return s.deviceIDs
}

// networkOf resolves a device's network id (best effort, for change_log
// provenance).
func (s *Service) networkOf(ctx context.Context, deviceID int64) *int64 {
	d, err := s.queries.GetDevice(ctx, deviceID)
	if err != nil || d.NetworkID == nil {
		return nil
	}
	return d.NetworkID
}

func mustAddr(ip string) netip.Addr {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func strPtr(v string) *string { return &v }

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
