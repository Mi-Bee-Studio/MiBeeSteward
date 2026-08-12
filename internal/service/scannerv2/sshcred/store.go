// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

// Package sshcred stores and resolves SSH credentials for the device config-
// backup probe (#137). It mirrors the SNMP credential pattern
// (internal/service/scannerv2/credresolver): raw database/sql access (sqlc
// truncates queries on credential tables — see credresolver/store.go) + a
// Resolver that decrypts on read via the shared crypto.Cipher (the same
// security.master_key the SNMP credentials use, so there is one key source).
//
// Plaintext secrets NEVER leave this package's Resolver: the store only moves
// ciphertext (_enc) columns, and the handler (a later PR) encrypts at write
// time + redacts on read, exactly as the SNMP credential handler does.
package sshcred

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Row mirrors the ssh_credentials table. SecretEnc/PassphraseEnc hold AES-GCM
// ciphertext; nothing else here is sensitive.
type Row struct {
	ID            int64
	Name          string
	AuthMethod    string // "password" | "key"
	Username      string
	SecretEnc     string // ciphertext of the password OR PEM private key
	PassphraseEnc string // ciphertext of the key passphrase ("" if none/unencrypted)
	HostKeyFP     string // expected SHA256 fingerprint (TOFU); "" = not pinned
	Enabled       bool
	Notes         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// WriteParams is the create/update input. The caller (handler) fills SecretEnc/
// PassphraseEnc AFTER encrypting the plaintext — plaintext never reaches this
// layer. Mirrors credresolver.SNMPCredentialWriteParams.
type WriteParams struct {
	Name          string
	AuthMethod    string
	Username      string
	SecretEnc     string
	PassphraseEnc string
	HostKeyFP     string
	Enabled       bool
	Notes         string
}

// ErrNotFound is returned when no credential row exists for the requested id.
var ErrNotFound = errors.New("sshcred: credential not found")

// scanRow scans a full-row SELECT into a Row. Shared by Get/GetByName so the
// column order lives in exactly one place.
func scanRow(row interface{ Scan(dest ...any) error }) (Row, error) {
	var r Row
	var enabled int64
	err := row.Scan(
		&r.ID, &r.Name, &r.AuthMethod, &r.Username, &r.SecretEnc, &r.PassphraseEnc,
		&r.HostKeyFP, &enabled, &r.Notes, &r.CreatedAt, &r.UpdatedAt,
	)
	r.Enabled = enabled != 0
	return r, err
}

const allColumns = `id, name, auth_method, username, secret_enc, passphrase_enc, host_key_fp, enabled, notes, created_at, updated_at`

// Get returns the full row (incl. ciphertext) for one credential by id.
func Get(ctx context.Context, db *sql.DB, id int64) (Row, error) {
	r, err := scanRow(db.QueryRowContext(ctx,
		`SELECT `+allColumns+` FROM ssh_credentials WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, ErrNotFound
	}
	return r, err
}

// GetByName returns the full row by name (UNIQUE).
func GetByName(ctx context.Context, db *sql.DB, name string) (Row, error) {
	r, err := scanRow(db.QueryRowContext(ctx,
		`SELECT `+allColumns+` FROM ssh_credentials WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, ErrNotFound
	}
	return r, err
}

// ListRow is a list projection that OMITS the ciphertext columns (the admin list
// view shows metadata only — never the secret blobs). Mirrors credresolver's
// MaskedCredentialRow.
type ListRow struct {
	ID         int64
	Name       string
	AuthMethod string
	Username   string
	HostKeyFP  string
	Enabled    bool
	Notes      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// List returns the metadata-only rows (no ciphertext), ordered newest-first.
func List(ctx context.Context, db *sql.DB, limit, offset int64) ([]ListRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, auth_method, username, host_key_fp, enabled, notes, created_at, updated_at
		 FROM ssh_credentials ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ListRow
	for rows.Next() {
		var r ListRow
		var enabled int64
		if err := rows.Scan(&r.ID, &r.Name, &r.AuthMethod, &r.Username, &r.HostKeyFP,
			&enabled, &r.Notes, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// Create inserts a credential row (ciphertext already filled by the caller) and
// returns the new id.
func Create(ctx context.Context, db *sql.DB, p WriteParams) (int64, error) {
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO ssh_credentials (name, auth_method, username, secret_enc, passphrase_enc, host_key_fp, enabled, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.AuthMethod, p.Username, p.SecretEnc, p.PassphraseEnc, p.HostKeyFP, enabled, p.Notes)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Update overwrites a credential row. Callers pass the FULL desired ciphertext
// set (re-encrypting any changed plaintext + carrying forward unchanged blobs).
func Update(ctx context.Context, db *sql.DB, id int64, p WriteParams) error {
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	res, err := db.ExecContext(ctx, `
		UPDATE ssh_credentials SET name=?, auth_method=?, username=?, secret_enc=?, passphrase_enc=?, host_key_fp=?, enabled=?, notes=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		p.Name, p.AuthMethod, p.Username, p.SecretEnc, p.PassphraseEnc, p.HostKeyFP, enabled, p.Notes, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a credential row; returns rows affected.
func Delete(ctx context.Context, db *sql.DB, id int64) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM ssh_credentials WHERE id = ?`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
