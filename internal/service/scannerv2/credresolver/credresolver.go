// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package credresolver turns a stored snmp_credentials row (with AES-GCM
// encrypted passphrases) into an in-process scannerv2.SNMPCredential (with
// decrypted plaintext passphrases) that the scanner engine can thread into
// ProbeHints.
//
// It is the ONLY place that decrypts SNMP credentials, which keeps the
// decryption surface small and auditable. The DB layer (internal/db) sees only
// ciphertext blobs; the engine layer (scannerv2) sees only plaintext
// SNMPCredential structs; this package is the bridge.
//
// A short in-process cache (30s TTL) avoids re-decrypting on every host of a
// /24 scan that all share one credential. The cache keys on credential ID and
// is invalidated when a credential is updated or deleted (Invalidate).
package credresolver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"mibee-steward/internal/crypto"
	"mibee-steward/internal/service/scannerv2"
)

// cacheTTL bounds how long a decrypted credential stays in memory. Short
// enough that an update (rotate passphrase, change security level) takes effect
// promptly for new scans; long enough that a /24 scan (50 hosts, ~seconds)
// reuses one decrypt. 30s matches the router-ARP cache TTL for consistency.
const cacheTTL = 30 * time.Second

// Resolver reads and decrypts SNMP credentials by ID. The zero value is NOT
// usable — construct with New. A nil Resolver (or one with a nil cipher) is
// valid and reports ErrDisabled for every Resolve, which lets the engine run
// in v1/v2c-only deployments without a master key configured.
type Resolver struct {
	db     *sql.DB
	cipher *crypto.Cipher
	cache  map[int64]cacheEntry
	mu     sync.Mutex
}

type cacheEntry struct {
	cred *scannerv2.SNMPCredential
	at   time.Time
}

// ErrDisabled is returned by Resolve when the resolver has no cipher (master
// key not configured). The engine treats this as "no v3 available" and falls
// back to the legacy community path rather than failing the scan.
var ErrDisabled = errors.New("credresolver: disabled (no master key configured)")

// ErrNotFound is returned when no credential row exists for the requested ID.
// Distinct from ErrDisabled so callers can tell "v3 disabled globally" from
// "this specific credential was deleted".
var ErrNotFound = errors.New("credresolver: credential not found")

// New builds a resolver backed by the given *sql.DB + cipher. cipher may be
// nil (→ Resolve returns ErrDisabled), which is how a deployment without a
// master key keeps working for v1/v2c scans. db is used for raw-SQL queries
// (see store.go — sqlc cannot generate for this table).
func New(db *sql.DB, cipher *crypto.Cipher) *Resolver {
	return &Resolver{
		db:     db,
		cipher: cipher,
		cache:  make(map[int64]cacheEntry),
	}
}

// Resolve returns the decrypted SNMPCredential for id. Returns:
//   - (cred, nil) on success;
//   - (nil, ErrDisabled) when no master key is configured (engine falls back);
//   - (nil, ErrNotFound) when the row doesn't exist;
//   - (nil, err) on DB / decrypt errors.
//
// The returned credential carries plaintext passphrases in memory; callers must
// not log or persist them (the SNMPCredential type's json:"-" tags enforce this
// at marshal time too).
func (r *Resolver) Resolve(ctx context.Context, id int64) (*scannerv2.SNMPCredential, error) {
	return r.resolve(ctx, id)
}

// ResolveByID is the engine-facing alias of Resolve. It exists so the engine's
// CredentialResolver interface (engine.CredentialResolver) is satisfied by
// *Resolver without the engine importing this package directly (which would
// create an import cycle: credresolver → scannerv2, engine → credresolver).
// The method name matches the interface; the body is identical to Resolve.
func (r *Resolver) ResolveByID(ctx context.Context, id int64) (*scannerv2.SNMPCredential, error) {
	return r.resolve(ctx, id)
}

// resolve is the shared body of Resolve + ResolveByID.
func (r *Resolver) resolve(ctx context.Context, id int64) (*scannerv2.SNMPCredential, error) {
	if r == nil || r.cipher == nil {
		return nil, ErrDisabled
	}
	if id <= 0 {
		return nil, ErrNotFound
	}

	// Fast path: unexpired cache hit. We hold the lock only long enough to
	// read+check the entry; decrypt (slow path) happens without the lock so a
	// cache miss on one credential doesn't block a concurrent hit on another.
	r.mu.Lock()
	if e, ok := r.cache[id]; ok && time.Since(e.at) < cacheTTL {
		r.mu.Unlock()
		return e.cred, nil
	}
	r.mu.Unlock()

	row, err := GetSNMPCredential(ctx, r.db, id)
	if err != nil {
		// GetSNMPCredential surfaces sql.ErrNoRows for a missing row; normalize
		// to ErrNotFound so callers don't import database/sql to distinguish it.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("credresolver: read credential %d: %w", id, err)
	}

	authPass, err := r.cipher.Decrypt(row.AuthPassphraseEnc)
	if err != nil {
		return nil, fmt.Errorf("credresolver: decrypt auth passphrase for %d: %w", id, err)
	}
	privPass, err := r.cipher.Decrypt(row.PrivPassphraseEnc)
	if err != nil {
		return nil, fmt.Errorf("credresolver: decrypt priv passphrase for %d: %w", id, err)
	}

	cred := &scannerv2.SNMPCredential{
		ID:             row.ID,
		Name:           row.Name,
		SecurityLevel:  row.SecurityLevel,
		Community:      row.Community,
		UserName:       row.Username,
		AuthProtocol:   row.AuthProtocol,
		AuthPassphrase: authPass,
		PrivProtocol:   row.PrivProtocol,
		PrivPassphrase: privPass,
	}

	r.mu.Lock()
	r.cache[id] = cacheEntry{cred: cred, at: time.Now()}
	r.mu.Unlock()
	return cred, nil
}

// Invalidate drops the cached entry for id. Called by the credential handler
// after an update or delete so the next Resolve re-reads + re-decrypts with the
// new values instead of serving stale plaintext.
func (r *Resolver) Invalidate(id int64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.cache, id)
	r.mu.Unlock()
}

// InvalidateAll drops every cached entry. Used when the master key is rotated
// (every previously-decrypted credential is now potentially stale).
func (r *Resolver) InvalidateAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cache = make(map[int64]cacheEntry)
	r.mu.Unlock()
}
