// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"mibee-steward/internal/db"
)

// NetworkService is the write path for the logical-network registry (issue
// #240: the network handler was one of the four grandfathered charter-debt
// handlers writing to the DB directly). Reads stay as handler passthroughs.
type NetworkService struct {
	queries *db.Queries
	conn    db.DBTX // raw connection for UPDATE (sqlc truncation workaround)
}

// NewNetworkService constructs a NetworkService. conn powers the raw UPDATE
// statement — sqlc v1.31.1 truncates the generated string for UpdateNetwork's
// multi-bind shape, so the UPDATE is hand-written (db/AGENTS.md convention).
func NewNetworkService(queries *db.Queries, conn db.DBTX) *NetworkService {
	return &NetworkService{queries: queries, conn: conn}
}

var (
	// ErrNetworkNameRequired maps to 400.
	ErrNetworkNameRequired = errors.New("name is required")
	// ErrNetworkNotFound maps to 404.
	ErrNetworkNotFound = errors.New("network not found")
	// ErrNetworkNameTaken maps to 409 (networks.name is UNIQUE).
	ErrNetworkNameTaken = errors.New("a network with this name already exists")
)

// NetworkInput is the create/update payload shared shape. Cidr and Site are
// advisory (no strict validation), matching the previous handler semantics.
type NetworkInput struct {
	Name string
	Cidr *string
	Site *string
}

// Create registers a new logical network — the admin path for defining the
// remote networks agents discover for (the center's own network is
// auto-resolved at startup via resolveNetworkID).
func (s *NetworkService) Create(ctx context.Context, in NetworkInput) (db.Network, error) {
	in = normalizeNetworkInput(in)
	if in.Name == "" {
		return db.Network{}, ErrNetworkNameRequired
	}
	net, err := s.queries.CreateNetwork(ctx, db.CreateNetworkParams{
		Name: in.Name,
		Cidr: in.Cidr,
		Site: in.Site,
	})
	if err != nil {
		if isUniqueConstraintErr(err) {
			return db.Network{}, ErrNetworkNameTaken
		}
		return db.Network{}, err
	}
	return net, nil
}

// Update edits name/cidr/site. agent_id is intentionally NOT editable here
// (owned by the agent-token flow). Runs via raw database/sql and reads the
// updated row back — sqlc v1.31.1 truncates the generated query string for
// this multi-bind UPDATE shape (drops the trailing `?`).
func (s *NetworkService) Update(ctx context.Context, id int64, in NetworkInput) (db.Network, error) {
	in = normalizeNetworkInput(in)
	if in.Name == "" {
		return db.Network{}, ErrNetworkNameRequired
	}
	const stmt = `UPDATE networks SET name = ?, cidr = ?, site = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	res, err := s.conn.ExecContext(ctx, stmt, in.Name, in.Cidr, in.Site, id)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return db.Network{}, ErrNetworkNameTaken
		}
		return db.Network{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return db.Network{}, ErrNetworkNotFound
	}
	return s.queries.GetNetwork(ctx, id)
}

// Delete removes a logical network. FK references are ON DELETE SET NULL
// (devices/vlans/agent_tokens/change_log) or CASCADE (subnets/scan_snapshots),
// so devices keep their rows with a NULL network_id rather than vanishing.
func (s *NetworkService) Delete(ctx context.Context, id int64) error {
	if _, err := s.queries.GetNetwork(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNetworkNotFound
		}
		return err
	}
	return s.queries.DeleteNetwork(ctx, id)
}

// normalizeNetworkInput trims the name and normalizes the advisory pointer
// fields (nil-or-empty-after-trim → nil, so empty strings aren't stored as " ").
func normalizeNetworkInput(in NetworkInput) NetworkInput {
	in.Name = strings.TrimSpace(in.Name)
	in.Cidr = trimPtrToNil(in.Cidr)
	in.Site = trimPtrToNil(in.Site)
	return in
}

func trimPtrToNil(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	if t == "" {
		return nil
	}
	return &t
}

// isUniqueConstraintErr reports whether err is a SQLite UNIQUE constraint
// violation (modernc.org/sqlite returns "UNIQUE constraint failed: ...").
func isUniqueConstraintErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
