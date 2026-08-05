// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package credresolver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SNMPCredentialRow mirrors the snmp_credentials table. Defined here (not in
// internal/db) because sqlc v1.27/v1.31 cannot generate queries for this table
// — it truncates the last token of every SELECT/INSERT/UPDATE/RETURNING
// clause, producing invalid SQL at runtime. ALL access to snmp_credentials is
// therefore raw database/sql in this file. The resolver + handler use these
// helpers; nothing in internal/db touches the table.
type SNMPCredentialRow struct {
	ID                int64
	Name              string
	SecurityLevel     string
	Community         string
	Username          string
	AuthProtocol      string
	AuthPassphraseEnc string
	PrivProtocol      string
	PrivPassphraseEnc string
	Notes             string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// scanCredentialRow scans a full-row SELECT into a SNMPCredentialRow. Shared by
// GetSNMPCredential + GetSNMPCredentialByName + ListSNMPCredentials so the
// column order is defined in exactly one place.
func scanCredentialRow(row interface{ Scan(dest ...any) error }) (SNMPCredentialRow, error) {
	var r SNMPCredentialRow
	err := row.Scan(
		&r.ID, &r.Name, &r.SecurityLevel, &r.Community, &r.Username,
		&r.AuthProtocol, &r.AuthPassphraseEnc, &r.PrivProtocol, &r.PrivPassphraseEnc,
		&r.Notes, &r.CreatedAt, &r.UpdatedAt,
	)
	return r, err
}

// MaskedCredentialRow is the ListSNMPCredentials projection: the *_enc columns
// are deliberately omitted so a masked list can never leak even ciphertext. The
// handler derives has_auth / has_priv booleans from the protocol fields.
type MaskedCredentialRow struct {
	ID            int64
	Name          string
	SecurityLevel string
	Community     string
	Username      string
	AuthProtocol  string
	PrivProtocol  string
	Notes         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func scanMaskedRow(row interface{ Scan(dest ...any) error }) (MaskedCredentialRow, error) {
	var r MaskedCredentialRow
	err := row.Scan(
		&r.ID, &r.Name, &r.SecurityLevel, &r.Community, &r.Username,
		&r.AuthProtocol, &r.PrivProtocol, &r.Notes, &r.CreatedAt, &r.UpdatedAt,
	)
	return r, err
}

// GetSNMPCredential fetches a full credential row by ID (including the
// encrypted blobs — for the resolver, which decrypts in-process).
func GetSNMPCredential(ctx context.Context, db *sql.DB, id int64) (SNMPCredentialRow, error) {
	row := db.QueryRowContext(ctx, `
SELECT id, name, security_level, community, username, auth_protocol,
       auth_passphrase_enc, priv_protocol, priv_passphrase_enc, notes,
       created_at, updated_at
FROM snmp_credentials
WHERE id = ?`, id)
	r, err := scanCredentialRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SNMPCredentialRow{}, sql.ErrNoRows
	}
	return r, err
}

// GetSNMPCredentialByName fetches a full row by name (used by the handler to
// detect duplicate names on create).
func GetSNMPCredentialByName(ctx context.Context, db *sql.DB, name string) (SNMPCredentialRow, error) {
	row := db.QueryRowContext(ctx, `
SELECT id, name, security_level, community, username, auth_protocol,
       auth_passphrase_enc, priv_protocol, priv_passphrase_enc, notes,
       created_at, updated_at
FROM snmp_credentials
WHERE name = ?`, name)
	r, err := scanCredentialRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SNMPCredentialRow{}, sql.ErrNoRows
	}
	return r, err
}

// ListSNMPCredentials returns the masked projection (no encrypted blobs),
// paginated. For UI display where the passphrases must never reach the API.
func ListSNMPCredentials(ctx context.Context, db *sql.DB, limit, offset int64) ([]MaskedCredentialRow, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id, name, security_level, community, username, auth_protocol,
       priv_protocol, notes, created_at, updated_at
FROM snmp_credentials
ORDER BY name
LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MaskedCredentialRow
	for rows.Next() {
		r, err := scanMaskedRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountSNMPCredentials returns the total row count (for list pagination total).
func CountSNMPCredentials(ctx context.Context, db *sql.DB) (int64, error) {
	var count int64
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM snmp_credentials`).Scan(&count)
	return count, err
}

// GetSNMPCredentialName returns just the name for a given ID — used by scan-task
// create/update to validate a referenced credential_id without pulling secrets.
func GetSNMPCredentialName(ctx context.Context, db *sql.DB, id int64) (string, error) {
	var name string
	err := db.QueryRowContext(ctx, `SELECT name FROM snmp_credentials WHERE id = ?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", sql.ErrNoRows
	}
	return name, err
}

// CreateSNMPCredential inserts a credential row and returns the new ID.
func CreateSNMPCredential(ctx context.Context, db *sql.DB, p SNMPCredentialWriteParams) (int64, error) {
	res, err := db.ExecContext(ctx, `
INSERT INTO snmp_credentials (
    name, security_level, community, username, auth_protocol,
    auth_passphrase_enc, priv_protocol, priv_passphrase_enc, notes
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.SecurityLevel, p.Community, p.Username, p.AuthProtocol,
		p.AuthPassphraseEnc, p.PrivProtocol, p.PrivPassphraseEnc, p.Notes)
	if err != nil {
		return 0, fmt.Errorf("create snmp credential: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("create snmp credential: last insert id: %w", err)
	}
	return id, nil
}

// UpdateSNMPCredential updates every mutable field of a credential row.
func UpdateSNMPCredential(ctx context.Context, db *sql.DB, id int64, p SNMPCredentialWriteParams) error {
	_, err := db.ExecContext(ctx, `
UPDATE snmp_credentials
SET name = ?, security_level = ?, community = ?, username = ?, auth_protocol = ?,
    auth_passphrase_enc = ?, priv_protocol = ?, priv_passphrase_enc = ?, notes = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?`,
		p.Name, p.SecurityLevel, p.Community, p.Username, p.AuthProtocol,
		p.AuthPassphraseEnc, p.PrivProtocol, p.PrivPassphraseEnc, p.Notes, id)
	if err != nil {
		return fmt.Errorf("update snmp credential %d: %w", id, err)
	}
	return nil
}

// DeleteSNMPCredential removes a credential row. Returns rows affected (0 = not
// found). ON DELETE SET NULL on scan_tasks.credential_id means tasks bound to a
// deleted credential fall back to the engine's global default rather than break.
func DeleteSNMPCredential(ctx context.Context, db *sql.DB, id int64) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM snmp_credentials WHERE id = ?`, id)
	if err != nil {
		return 0, fmt.Errorf("delete snmp credential %d: %w", id, err)
	}
	return res.RowsAffected()
}

// SNMPCredentialWriteParams is the shared input shape for create + update.
// The handler fills the *_PassphraseEnc fields AFTER encrypting the plaintext
// passphrases (the plaintext never reaches this layer).
type SNMPCredentialWriteParams struct {
	Name              string
	SecurityLevel     string
	Community         string
	Username          string
	AuthProtocol      string
	AuthPassphraseEnc string
	PrivProtocol      string
	PrivPassphraseEnc string
	Notes             string
}
