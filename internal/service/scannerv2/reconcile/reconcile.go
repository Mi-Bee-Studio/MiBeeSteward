// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package reconcile runs the periodic network-attribution reconciliation job
// (issue #19 Layer 3). It is the "兜底" (bottom-line) defense: even if the
// boundary checks at command dispatch (Layer 1) and report ingestion (Layer 2)
// fail — because a network lacks a cidr, or a future code path bypasses them —
// this job detects devices whose IP no longer belongs to the network they're
// stamped with, and surfaces them so an operator can correct the attribution.
//
// Why detect-and-surface, not auto-fix: automatically re-homing a device to a
// different network is a destructive call (it changes identity, breaks
// historical linkage, and can flap if two networks legitimately overlap on the
// same IP space). The job's job is to FIND the drift; correction stays a human
// decision (issue #19 Layer 4). Findings are exposed via:
//   - structured slog warnings (one per mismatched device, rate-limited),
//   - a Prometheus gauge (mibee_network_mismatches) per network,
//   - the Reconcile() return value (for tests + a future admin endpoint).
package reconcile

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"mibee-steward/internal/cidrutil"
)

// Mismatch is one device whose IP falls outside its stamped network's CIDR.
type Mismatch struct {
	DeviceID  int64
	IP        string
	NetworkID int64
	Network   string // networks.name, for human-facing logs
	CIDR      string // the configured cidr the IP violated ("" = network had none)
}

// Service is the reconciliation job. One ticker drives a full scan; each scan
// loads every network's cidr once and checks its devices in a single query.
type Service struct {
	dbConn   *sql.DB
	interval time.Duration
	logger   *slog.Logger

	// nets caches parsed cidrs per network_id so a scan doesn't re-parse on
	// every device. Invalidated at the start of each scan (a network's cidr can
	// change between scans — e.g. the agent backfill fills it).
	mu   sync.Mutex
	nets map[int64]netCache

	cancel context.CancelFunc
	done   chan struct{}

	metrics *metrics
}

type netCache struct {
	id    int64
	name  string
	cidr  string
	ipNet *net.IPNet // nil = network has no usable cidr (skipped)
}

// New constructs the reconciler. interval ≤0 → 1h. dbConn is the main DB
// (devices + networks). registerer nil → metrics disabled (tests).
func New(dbConn *sql.DB, interval time.Duration, registerer prometheus.Registerer, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = time.Hour
	}
	return &Service{
		dbConn:   dbConn,
		interval: interval,
		logger:   logger,
		nets:     make(map[int64]netCache),
		done:     make(chan struct{}),
		metrics:  newMetrics(registerer),
	}
}

// Start runs one reconciliation immediately, then on every interval tick.
func (s *Service) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go func() {
		defer close(s.done)
		_, _ = s.reconcileOnce(ctx) // best-effort on the initial pass; errors logged inside
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_, _ = s.reconcileOnce(ctx) // best-effort; errors logged inside
			}
		}
	}()
}

// Stop cancels the loop and waits for the in-flight scan to finish.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	<-s.done
}

// Reconcile runs one full pass and returns the mismatches found. It is the
// single entry point for both the ticker and tests (Start launches a goroutine
// which is awkward to drive deterministically).
func (s *Service) Reconcile(ctx context.Context) ([]Mismatch, error) {
	return s.reconcileOnce(ctx)
}

// CleanupStats reports what a CleanupGhosts pass did, for the startup log.
type CleanupStats struct {
	Mismatches    int // total drift detected this pass
	Rehomed       int // ghosts deleted because a correct-network copy exists
	Unresolved    int // ghosts with NO correct-network copy — left for operator
	RehomedIPs    []string
	UnresolvedIPs []string
}

// CleanupGhosts is the one-time startup migration (issue #19 Layer 4). It runs
// a Reconcile pass, then for each mismatched device checks whether the SAME IP
// already exists as a device in the network the IP actually belongs to:
//
//   - if YES: the mismatched row is a duplicate ghost (the correct copy lives
//     elsewhere). Delete the ghost device + its scan_snapshots lease. This is
//     safe — no data loss, the canonical record stays.
//   - if NO: there is no safe target. Leave the row and surface it (counted as
//     Unresolved) so an operator decides. Auto-re-homing to a freshly-created
//     network would be a guess we don't make automatically.
//
// It also re-homes by MAC when the IP's correct network can't be determined
// (no network's cidr contains it) but a same-MAC device exists elsewhere — the
// MAC-primary identity rule means that's the same asset. This covers the ghost
// that was first seen without a MAC and can't IP-match.
//
// Idempotent: a second run finds nothing (the ghosts are gone). Called once at
// startup from cmd/server/main.go's migration phase, after the pre-migration
// VACUUM INTO backup is taken.
func (s *Service) CleanupGhosts(ctx context.Context) (*CleanupStats, error) {
	mismatches, err := s.Reconcile(ctx)
	if err != nil {
		return nil, err
	}
	stats := &CleanupStats{Mismatches: len(mismatches)}
	if len(mismatches) == 0 {
		return stats, nil
	}

	s.mu.Lock()
	netsByID := make(map[int64]netCache, len(s.nets))
	for id, n := range s.nets {
		netsByID[id] = n
	}
	s.mu.Unlock()

	for _, m := range mismatches {
		// Find the network the IP actually belongs to (by cidr containment).
		var correctNet int64
		correctFound := false
		for _, n := range netsByID {
			if n.ipNet != nil && cidrutil.ContainsIP(n.ipNet, m.IP) {
				correctNet = n.id
				correctFound = true
				break
			}
		}
		// Does a device row for this IP already exist in the correct network?
		// (MAC match is the fallback when the IP isn't in ANY configured cidr.)
		hasCanonical := false
		if correctFound {
			var n int64
			err := s.dbConn.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM devices WHERE ip_address = ? AND network_id = ?`, m.IP, correctNet).Scan(&n)
			if err == nil && n > 0 {
				hasCanonical = true
			}
		}
		if !hasCanonical {
			// MAC fallback: a same-MAC device anywhere else means this ghost is
			// a duplicate of that asset (MAC-primary identity is cross-network).
			var mac string
			_ = s.dbConn.QueryRowContext(ctx, `SELECT mac_address FROM devices WHERE id = ?`, m.DeviceID).Scan(&mac)
			if mac != "" {
				var n int64
				err := s.dbConn.QueryRowContext(ctx,
					`SELECT COUNT(*) FROM devices WHERE mac_address = ? AND id != ?`, mac, m.DeviceID).Scan(&n)
				if err == nil && n > 0 {
					hasCanonical = true
				}
			}
		}
		if !hasCanonical {
			stats.Unresolved++
			stats.UnresolvedIPs = append(stats.UnresolvedIPs, m.IP)
			s.logger.Warn("network reconcile: ghost has no canonical copy; left for operator",
				"device_id", m.DeviceID, "ip", m.IP, "network_id", m.NetworkID, "network", m.Network)
			continue
		}
		// Safe to delete the ghost. Remove its lease first (FK is ON DELETE
		// CASCADE on scan_snapshots? — no, scan_snapshots has no FK to devices;
		// it keys on (network_id, ip), so delete it explicitly by the ghost's
		// (network_id, ip)).
		if _, err := s.dbConn.ExecContext(ctx,
			`DELETE FROM scan_snapshots WHERE network_id = ? AND ip = ?`, m.NetworkID, m.IP); err != nil {
			s.logger.Warn("network reconcile: delete ghost lease failed",
				"device_id", m.DeviceID, "ip", m.IP, "error", err)
			continue
		}
		// host_services / host_tls_certs / device_neighbors FK to devices with
		// ON DELETE CASCADE (see db/schema.sql), so deleting the device row
		// cleans those up automatically.
		if _, err := s.dbConn.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, m.DeviceID); err != nil {
			s.logger.Warn("network reconcile: delete ghost device failed",
				"device_id", m.DeviceID, "ip", m.IP, "error", err)
			continue
		}
		stats.Rehomed++
		stats.RehomedIPs = append(stats.RehomedIPs, m.IP)
	}
	if stats.Rehomed > 0 || stats.Unresolved > 0 {
		s.logger.Info("network reconcile: ghost cleanup pass",
			"mismatches", stats.Mismatches, "rehomed", stats.Rehomed,
			"unresolved", stats.Unresolved)
	}
	return stats, nil
}

func (s *Service) reconcileOnce(ctx context.Context) ([]Mismatch, error) {
	// Refresh the network cache: a network's cidr can change between scans.
	if err := s.refreshNetworks(ctx); err != nil {
		s.logger.Warn("network reconcile: refresh networks failed", "error", err)
		return nil, err
	}

	s.mu.Lock()
	nets := make([]netCache, 0, len(s.nets))
	for _, n := range s.nets {
		nets = append(nets, n)
	}
	s.mu.Unlock()

	var allMismatches []Mismatch
	// Reset gauges first so a network that had mismatches but now has none
	// returns to 0 (gauges are set, not incremented, per scan).
	if s.metrics != nil {
		s.metrics.reset()
	}
	for _, n := range nets {
		if n.ipNet == nil {
			// No usable cidr → can't check this network. Don't surface its
			// devices as mismatches (we don't KNOW they're wrong). The
			// prerequisite backfill (issue #19 前置工作) is what fills these.
			continue
		}
		mismatches, err := s.checkNetwork(ctx, n)
		if err != nil {
			s.logger.Warn("network reconcile: check network failed",
				"network_id", n.id, "network", n.name, "error", err)
			continue
		}
		if len(mismatches) > 0 {
			allMismatches = append(allMismatches, mismatches...)
			if s.metrics != nil {
				s.metrics.set(n.id, n.name, len(mismatches))
			}
			// Rate-limit the log: one summary line per network per scan, plus
			// up to 5 sample IPs so an operator scanning logs sees the drift
			// without drowning in noise on a large mismatched network.
			sample := make([]string, 0, 5)
			for i, m := range mismatches {
				if i >= 5 {
					break
				}
				sample = append(sample, m.IP)
			}
			s.logger.Warn("network reconcile: devices with out-of-network IPs detected",
				"network_id", n.id, "network", n.name, "cidr", n.cidr,
				"mismatches", len(mismatches), "sample_ips", sample)
		}
	}
	return allMismatches, nil
}

func (s *Service) checkNetwork(ctx context.Context, n netCache) ([]Mismatch, error) {
	// Pull only ip + id for this network's devices. A network's device set is
	// typically <1000; this is cheap and avoids the cross-join complexity of
	// doing the membership check in SQL (SQLite has no native CIDR type).
	rows, err := s.dbConn.QueryContext(ctx,
		`SELECT id, ip_address FROM devices WHERE network_id = ? AND ip_address != ''`, n.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mismatch
	for rows.Next() {
		var id int64
		var ip string
		if err := rows.Scan(&id, &ip); err != nil {
			return nil, err
		}
		if !cidrutil.ContainsIP(n.ipNet, ip) {
			out = append(out, Mismatch{
				DeviceID: id, IP: ip, NetworkID: n.id, Network: n.name, CIDR: n.cidr,
			})
		}
	}
	return out, rows.Err()
}

// refreshNetworks loads (id, name, cidr) for every network and caches the
// parsed cidr. A network with no/invalid cidr caches ipNet=nil so it's skipped
// without re-parsing every device.
func (s *Service) refreshNetworks(ctx context.Context) error {
	rows, err := s.dbConn.QueryContext(ctx,
		`SELECT id, name, COALESCE(cidr, '') FROM networks`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fresh := make(map[int64]netCache)
	for rows.Next() {
		var id int64
		var name, cidr string
		if err := rows.Scan(&id, &name, &cidr); err != nil {
			return err
		}
		nc := netCache{id: id, name: name, cidr: cidr}
		if ipNet, perr := cidrutil.ParseNetwork(cidr); perr == nil && ipNet != nil {
			nc.ipNet = ipNet
		}
		fresh[id] = nc
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.nets = fresh
	s.mu.Unlock()
	return nil
}
