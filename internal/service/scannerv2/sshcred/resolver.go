// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package sshcred

import (
	"context"
	"database/sql"
	"errors"

	"mibee-steward/internal/crypto"
)

// Credential is the decrypted plaintext an SSH client consumes to connect
// (returned by Resolver.Resolve). It is the ONLY type in this package that
// carries plaintext secrets, keeping the decrypt surface small and auditable.
type Credential struct {
	ID         int64
	Name       string
	AuthMethod string // "password" | "key"
	Username   string
	Secret     string // plaintext password OR PEM private key
	Passphrase string // plaintext passphrase for an encrypted key ("" if none)
	HostKeyFP  string // expected SHA256 fingerprint (TOFU); "" = not pinned
}

// ErrDisabled is returned when the resolver has no cipher (no master key
// configured). Lets the probe fall back / skip cleanly, mirroring credresolver.
var ErrDisabled = errors.New("sshcred: disabled (no master key configured)")

// Resolver decrypts SSH credentials on demand via the shared crypto.Cipher. A
// nil cipher (no master key) yields ErrDisabled from every Resolve — SSH
// credential storage is then unavailable, matching the SNMP credential behavior.
//
// No in-memory cache: the config-backup probe resolves a credential at most
// once per device per (hourly) cycle, so the decrypt cost is negligible and a
// cache would only add stale-on-rotate risk. (credresolver caches because the
// SNMP engine resolves per-host-per-scan; the SSH probe does not.)
type Resolver struct {
	db     *sql.DB
	cipher *crypto.Cipher
}

// New constructs the resolver. cipher may be nil (→ Resolve returns ErrDisabled).
func New(db *sql.DB, cipher *crypto.Cipher) *Resolver {
	return &Resolver{db: db, cipher: cipher}
}

// Resolve decrypts the credential with the given id and returns the plaintext
// form an SSH client needs. Returns:
//   - (nil, ErrDisabled) when no master key is configured;
//   - (nil, ErrNotFound) when the row does not exist;
//   - (nil, err) on a decrypt failure (tampered blob / wrong key / malformed).
func (r *Resolver) Resolve(ctx context.Context, id int64) (*Credential, error) {
	if r.cipher == nil {
		return nil, ErrDisabled
	}
	row, err := Get(ctx, r.db, id)
	if err != nil {
		return nil, ErrNotFound
	}
	return r.decryptRow(row)
}

// ResolveByName is the same lookup by credential name.
func (r *Resolver) ResolveByName(ctx context.Context, name string) (*Credential, error) {
	if r.cipher == nil {
		return nil, ErrDisabled
	}
	row, err := GetByName(ctx, r.db, name)
	if err != nil {
		return nil, ErrNotFound
	}
	return r.decryptRow(row)
}

func (r *Resolver) decryptRow(row Row) (*Credential, error) {
	secret, err := r.cipher.Decrypt(row.SecretEnc)
	if err != nil {
		return nil, err
	}
	// passphrase_enc may be empty (unencrypted key / password auth) — Decrypt("")
	// returns ("", nil) per the cipher contract, so this is a no-op then.
	passphrase, err := r.cipher.Decrypt(row.PassphraseEnc)
	if err != nil {
		return nil, err
	}
	return &Credential{
		ID:         row.ID,
		Name:       row.Name,
		AuthMethod: row.AuthMethod,
		Username:   row.Username,
		Secret:     secret,
		Passphrase: passphrase,
		HostKeyFP:  row.HostKeyFP,
	}, nil
}
