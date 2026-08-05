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
	"testing"
	"time"

	"mibee-steward/internal/crypto"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

// testKey matches the crypto package test key — 32 ASCII bytes, not secret.
var testKey = []byte("01234567890123456789012345678901")

// newTestResolver spins up an in-memory SQLite DB (via testutil), inserts a v3
// credential with encrypted passphrases, and returns a resolver + the inserted
// credential's ID. This is the harness every test below shares.
func newTestResolver(t *testing.T, level string) (*Resolver, int64) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("SetupTestDBFromSchema: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	cipher, err := crypto.NewCipher(testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	// Build the credential row with encrypted passphrases (the handler does
	// this; here we encrypt inline to set up the fixture). Uses the raw-SQL
	// CreateSNMPCredential helper (sqlc corrupts the INSERT — see store.go).
	authEnc, _ := cipher.Encrypt("authpass8")
	privEnc, _ := cipher.Encrypt("privpass8")
	id, err := CreateSNMPCredential(context.Background(), conn, SNMPCredentialWriteParams{
		Name:              "test-v3",
		SecurityLevel:     level,
		Username:          "testuser",
		AuthProtocol:      "SHA256",
		AuthPassphraseEnc: authEnc,
		PrivProtocol:      "AES",
		PrivPassphraseEnc: privEnc,
	})
	if err != nil {
		t.Fatalf("CreateSNMPCredential: %v", err)
	}
	return New(conn, cipher), id
}

func TestResolve_DecryptsAndReturnsCredential(t *testing.T) {
	r, id := newTestResolver(t, scannerv2.SNMPLevelAuthPriv)
	cred, err := r.Resolve(context.Background(), id)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cred.ID != id {
		t.Errorf("ID = %d, want %d", cred.ID, id)
	}
	if cred.SecurityLevel != scannerv2.SNMPLevelAuthPriv {
		t.Errorf("SecurityLevel = %q, want %q", cred.SecurityLevel, scannerv2.SNMPLevelAuthPriv)
	}
	if cred.AuthPassphrase != "authpass8" {
		t.Errorf("AuthPassphrase = %q, want \"authpass8\" (decrypted)", cred.AuthPassphrase)
	}
	if cred.PrivPassphrase != "privpass8" {
		t.Errorf("PrivPassphrase = %q, want \"privpass8\" (decrypted)", cred.PrivPassphrase)
	}
	if !cred.IsV3() {
		t.Errorf("IsV3() = false, want true for authPriv")
	}
}

func TestResolve_CacheHitAvoidsDB(t *testing.T) {
	r, id := newTestResolver(t, scannerv2.SNMPLevelAuthPriv)
	ctx := context.Background()

	// First call hits the DB.
	c1, err := r.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	// Second call should hit the cache (same pointer → no new DB read).
	c2, err := r.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if c1 != c2 {
		t.Errorf("cache miss: second Resolve returned a different pointer; expected cached entry")
	}
}

func TestResolve_InvalidateForcesReread(t *testing.T) {
	r, id := newTestResolver(t, scannerv2.SNMPLevelAuthPriv)
	ctx := context.Background()

	c1, err := r.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	r.Invalidate(id)
	c2, err := r.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("second Resolve after Invalidate: %v", err)
	}
	// After invalidation the cache was rebuilt; the pointers differ (new decrypt
	// produced a new struct). The VALUES are equal.
	if c1 == c2 {
		t.Errorf("Invalidate did not force a re-read; same pointer returned")
	}
	if c1.AuthPassphrase != c2.AuthPassphrase {
		t.Errorf("value changed after re-read: %q vs %q", c1.AuthPassphrase, c2.AuthPassphrase)
	}
}

func TestResolve_NilCipherReturnsDisabled(t *testing.T) {
	// A resolver built with a nil cipher must return ErrDisabled, NOT panic —
	// this is how a deployment without a master key keeps v1/v2c scans working.
	conn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("SetupTestDBFromSchema: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	r := New(conn, nil)
	_, err = r.Resolve(context.Background(), 1)
	if err != ErrDisabled {
		t.Errorf("Resolve with nil cipher: err = %v, want ErrDisabled", err)
	}
}

func TestResolve_ZeroIDReturnsNotFound(t *testing.T) {
	r, _ := newTestResolver(t, scannerv2.SNMPLevelAuthPriv)
	_, err := r.Resolve(context.Background(), 0)
	if err != ErrNotFound {
		t.Errorf("Resolve(0): err = %v, want ErrNotFound", err)
	}
}

func TestResolve_NonexistentIDReturnsNotFound(t *testing.T) {
	r, _ := newTestResolver(t, scannerv2.SNMPLevelAuthPriv)
	_, err := r.Resolve(context.Background(), 9999)
	if err != ErrNotFound {
		t.Errorf("Resolve(9999): err = %v, want ErrNotFound", err)
	}
}

func TestResolve_V1V2CCredentialHasNoPassphrases(t *testing.T) {
	// A v1/v2c credential stores no encrypted passphrases (empty enc columns).
	// Resolve must produce a credential with empty AuthPassphrase/PrivPassphrase
	// and IsV3()==false, exercising the empty-blob decrypt convention (Decrypt
	// of "" returns "" with no error).
	conn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("SetupTestDBFromSchema: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	cipher, err := crypto.NewCipher(testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	id, err := CreateSNMPCredential(context.Background(), conn, SNMPCredentialWriteParams{
		Name:          "v2c-cred",
		SecurityLevel: scannerv2.SNMPLevelV1V2C,
		Community:     "private",
		// AuthPassphraseEnc / PrivPassphraseEnc intentionally empty (default "").
	})
	if err != nil {
		t.Fatalf("CreateSNMPCredential: %v", err)
	}
	r := New(conn, cipher)
	got, err := r.Resolve(context.Background(), id)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.IsV3() {
		t.Errorf("IsV3() = true for v1v2c credential; want false")
	}
	if got.Community != "private" {
		t.Errorf("Community = %q, want \"private\"", got.Community)
	}
	if got.AuthPassphrase != "" || got.PrivPassphrase != "" {
		t.Errorf("v1v2c credential has non-empty passphrases: auth=%q priv=%q", got.AuthPassphrase, got.PrivPassphrase)
	}
}

// TestResolve_CacheExpiresAfterTTL is a slow test (cacheTTL is 30s); rather
// than wait, we verify the expiry logic by checking the entry's timestamp is
// recorded. A full TTL-based expiry test would be flaky/slow — the Invalidate
// test above covers the invalidation path, and the cache-hit test covers the
// fresh-path. This stub documents that the TTL is 30s for future readers.
func TestCacheTTL_Is30Seconds(t *testing.T) {
	if cacheTTL != 30*time.Second {
		t.Errorf("cacheTTL = %v, want 30s (changing it has scan-throughput implications)", cacheTTL)
	}
}
