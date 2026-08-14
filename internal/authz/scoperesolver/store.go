// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

// Package scoperesolver resolves a user's object-level network scope (#138
// Phase 2): the set of network_ids a non-admin user is granted visibility into.
// It is the read side of the user_network_grants table, with a short TTL cache
// (mirrors internal/service/scannerv2/credresolver). Grants are stored as raw
// SQL (not sqlc) for parity with the other credential-adjacent tables and to
// avoid the sqlc version-drift regen.
package scoperesolver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNotFound is returned by Get when no row matches.
var ErrNotFound = errors.New("network grant not found")

// Grant is one user↔network row.
type Grant struct {
	ID        int64
	UserID    int64
	NetworkID int64
	GrantedAt string
}

// ListByUser returns every grant for a user (the network_ids they may see).
func ListByUser(ctx context.Context, db *sql.DB, userID int64) ([]Grant, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, user_id, network_id, granted_at
		FROM user_network_grants
		WHERE user_id = ?
		ORDER BY network_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list network grants for user %d: %w", userID, err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.UserID, &g.NetworkID, &g.GrantedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// NetworkIDsByUser returns just the granted network_ids for a user.
func NetworkIDsByUser(ctx context.Context, db *sql.DB, userID int64) ([]int64, error) {
	grants, err := ListByUser(ctx, db, userID)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.NetworkID)
	}
	return ids, nil
}

// ListAll returns every grant, joined to usernames/network names for the admin
// management surface (Phase 3). Paginated by limit/offset.
type GrantDetail struct {
	ID          int64
	UserID      int64
	Username    string
	NetworkID   int64
	NetworkName string
	GrantedAt   string
}

func ListAll(ctx context.Context, db *sql.DB, limit, offset int) ([]GrantDetail, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_network_grants`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT g.id, g.user_id, COALESCE(u.username, ''), g.network_id, COALESCE(n.name, ''), g.granted_at
		FROM user_network_grants g
		LEFT JOIN users u ON u.id = g.user_id
		LEFT JOIN networks n ON n.id = g.network_id
		ORDER BY u.username, n.name
		LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list all network grants: %w", err)
	}
	defer rows.Close()
	var out []GrantDetail
	for rows.Next() {
		var g GrantDetail
		if err := rows.Scan(&g.ID, &g.UserID, &g.Username, &g.NetworkID, &g.NetworkName, &g.GrantedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, int(total), rows.Err()
}

// Create inserts a grant. Idempotent at the DB level (UNIQUE(user_id, network_id)):
// a duplicate insert fails with a constraint error the caller maps to "already
// exists". Returns the new row id.
func Create(ctx context.Context, db *sql.DB, userID, networkID int64) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO user_network_grants (user_id, network_id) VALUES (?, ?)`,
		userID, networkID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Delete removes a grant by id. Returns whether a row was deleted.
func Delete(ctx context.Context, db *sql.DB, id int64) (bool, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM user_network_grants WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteByUserNetwork removes a grant by (user_id, network_id). Used when the
// management surface keys off the pair rather than the surrogate id.
func DeleteByUserNetwork(ctx context.Context, db *sql.DB, userID, networkID int64) (bool, error) {
	res, err := db.ExecContext(ctx,
		`DELETE FROM user_network_grants WHERE user_id = ? AND network_id = ?`, userID, networkID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
