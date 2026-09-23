// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You should use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"sync"
	"time"

	"mibee-steward/internal/cidrutil"
)

// networkCacheTTL bounds how stale the networks snapshot may be. It matches
// the passive sources' poll cadence (60s): a freshly-created networks row
// starts steering attribution within one interval, without a per-event query.
const networkCacheTTL = time.Minute

// NetworkResolver maps a discovered IP to the network row whose CIDR contains
// it, the data-driven half of passive-discovery attribution (#386). The
// networks table is the ONLY source of truth: adding/edited rows change
// attribution with zero code or config. There are no per-source
// allowlists or prefix special cases here.
//
// On a form-C center (running ON a dual-arm router) the unfiltered sources
// (multicast, dhcp_leases) legitimately observe hosts on BOTH arms; without
// this resolver every sighting was stamped with the center's own network and
// reported as mibee_network_mismatches drift.
type NetworkResolver struct {
	db     *sql.DB
	logger *slog.Logger

	mu     sync.RWMutex
	loaded time.Time
	nets   []resolvedNet
}

// resolvedNet is one parsed networks row.
type resolvedNet struct {
	id    int64
	ipNet *net.IPNet
}

// NewNetworkResolver constructs the resolver. dbConn is the main DB; nil
// returns nil (Resolve on a nil resolver reports no match, callers keep
// their fallback).
func NewNetworkResolver(dbConn *sql.DB) *NetworkResolver {
	if dbConn == nil {
		return nil
	}
	return &NetworkResolver{db: dbConn, logger: slog.Default()}
}

// Resolve returns the network whose CIDR most-specifically contains ip
// (longest prefix wins, so a /24 beats an overlapping /16, same rule as the
// OUI vendor lookup). No match (or a load error) returns the zero
// NullInt64: the caller falls back to the center's own network, preserving
// pre-#386 behavior. Errors never block discovery, attribution is
// logged, never fatal.
func (r *NetworkResolver) Resolve(ctx context.Context, ip string) sql.NullInt64 {
	if r == nil || ip == "" {
		return sql.NullInt64{}
	}
	if err := r.refresh(ctx); err != nil {
		return sql.NullInt64{}
	}

	r.mu.RLock()
	nets := r.nets
	r.mu.RUnlock()

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return sql.NullInt64{}
	}
	var (
		best     sql.NullInt64
		bestBits = -1
	)
	for _, n := range nets {
		if !n.ipNet.Contains(parsed) {
			continue
		}
		if bits, _ := n.ipNet.Mask.Size(); bits > bestBits {
			bestBits = bits
			best = sql.NullInt64{Int64: n.id, Valid: true}
		}
	}
	return best
}

// ResolveGate answers whether a sighting may be attributed at all. It
// returns the matched network (same longest-prefix rule as Resolve) plus
// whether the networks table carries ANY usable CIDR. A sighting that matches
// no network while at least one CIDR is known is off-subnet (e.g. dhcp_leases
// rows for a dual-homed router's WAN arm): the caller drops it instead of
// stamping the local network. With no known geometry (unconfigured install)
// or on a load error it reports no gate, preserving the fallback.
func (r *NetworkResolver) ResolveGate(ctx context.Context, ip string) (sql.NullInt64, bool) {
	if r == nil || ip == "" {
		return sql.NullInt64{}, false
	}
	if err := r.refresh(ctx); err != nil {
		return sql.NullInt64{}, false
	}

	r.mu.RLock()
	nets := r.nets
	r.mu.RUnlock()

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return sql.NullInt64{}, len(nets) > 0
	}
	var (
		best     sql.NullInt64
		bestBits = -1
	)
	for _, n := range nets {
		if !n.ipNet.Contains(parsed) {
			continue
		}
		if bits, _ := n.ipNet.Mask.Size(); bits > bestBits {
			bestBits = bits
			best = sql.NullInt64{Int64: n.id, Valid: true}
		}
	}
	return best, len(nets) > 0
}

// refresh reloads the networks snapshot when the cache has expired. Cheap on
// LAN scale (networks is a handful of rows); the TTL keeps per-event cost at
// a map scan while a new row takes effect within a minute.
func (r *NetworkResolver) refresh(ctx context.Context) error {
	r.mu.RLock()
	fresh := time.Since(r.loaded) < networkCacheTTL
	r.mu.RUnlock()
	if fresh {
		return nil
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, COALESCE(cidr, '') FROM networks`)
	if err != nil {
		r.logger.Warn("discovery: network resolver reload failed; attribution falls back", "error", err)
		return err
	}
	defer rows.Close()
	var nets []resolvedNet
	for rows.Next() {
		var id int64
		var cidr string
		if err := rows.Scan(&id, &cidr); err != nil {
			continue // a malformed row never blocks the rest
		}
		if cidr == "" {
			continue // no cidr → cannot attribute by containment
		}
		ipNet, perr := cidrutil.ParseNetwork(cidr)
		if perr != nil || ipNet == nil {
			r.logger.Warn("discovery: network row has invalid cidr; skipped", "network_id", id, "cidr", cidr)
			continue
		}
		nets = append(nets, resolvedNet{id: id, ipNet: ipNet})
	}
	if err := rows.Err(); err != nil {
		return err
	}

	r.mu.Lock()
	r.nets = nets
	r.loaded = time.Now()
	r.mu.Unlock()
	return nil
}
