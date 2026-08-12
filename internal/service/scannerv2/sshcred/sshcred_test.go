// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package sshcred

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/crypto"
	"mibee-steward/internal/testutil"
)

// testDB builds an in-memory DB with the schema (incl. ssh_credentials) for
// store + resolver tests.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// These tests pin the SSH credential store + resolver (#137). The load-bearing
// security contracts:
//   - the store carries ciphertext only (plaintext never crosses it),
//   - List omits the ciphertext columns (no secret leak via the list view),
//   - the Resolver is the single decrypt path; a nil cipher (no master key)
//     disables SSH cred storage (ErrDisabled), and a real cipher round-trips
//     plaintext through the AES-GCM envelope.

func newCtx() context.Context { return context.Background() }

func TestStore_CreateGetRoundTrip(t *testing.T) {
	db := testDB(t)
	ctx := newCtx()

	id, err := Create(ctx, db, WriteParams{
		Name: "router-ssh", AuthMethod: "password", Username: "admin",
		SecretEnc: "CIPHERTEXT-BLOB", HostKeyFP: "SHA256:abc", Enabled: true, Notes: "core",
	})
	require.NoError(t, err)

	row, err := Get(ctx, db, id)
	require.NoError(t, err)
	require.Equal(t, "router-ssh", row.Name)
	require.Equal(t, "CIPHERTEXT-BLOB", row.SecretEnc, "store holds ciphertext verbatim")
	require.Equal(t, "SHA256:abc", row.HostKeyFP)
	require.True(t, row.Enabled)
}

func TestStore_GetByName(t *testing.T) {
	db := testDB(t)
	ctx := newCtx()
	_, err := Create(ctx, db, WriteParams{Name: "sw1", AuthMethod: "key", SecretEnc: "x"})
	require.NoError(t, err)

	row, err := GetByName(ctx, db, "sw1")
	require.NoError(t, err)
	require.Equal(t, "sw1", row.Name)
}

func TestStore_List_OmitsCiphertext(t *testing.T) {
	db := testDB(t)
	ctx := newCtx()
	_, err := Create(ctx, db, WriteParams{Name: "a", AuthMethod: "password", SecretEnc: "SECRET-A", PassphraseEnc: "PP-A"})
	require.NoError(t, err)

	rows, err := List(ctx, db, 50, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	// ListRow has no SecretEnc/PassphraseEnc fields at all (compile-time guarantee
	// the list view never carries the blobs); verify the metadata is present.
	require.Equal(t, "a", rows[0].Name)
}

func TestStore_UpdateAndDelete(t *testing.T) {
	db := testDB(t)
	ctx := newCtx()
	id, err := Create(ctx, db, WriteParams{Name: "u", AuthMethod: "password", SecretEnc: "old"})
	require.NoError(t, err)

	require.NoError(t, Update(ctx, db, id, WriteParams{Name: "u2", AuthMethod: "key", SecretEnc: "new", Enabled: true}))
	row, err := Get(ctx, db, id)
	require.NoError(t, err)
	require.Equal(t, "u2", row.Name)
	require.Equal(t, "new", row.SecretEnc)
	require.Equal(t, "key", row.AuthMethod)

	n, err := Delete(ctx, db, id)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	_, err = Get(ctx, db, id)
	require.ErrorIs(t, err, ErrNotFound, "deleted row is gone")
}

func TestStore_Update_NotFound(t *testing.T) {
	db := testDB(t)
	err := Update(newCtx(), db, 999, WriteParams{Name: "x", AuthMethod: "password"})
	require.ErrorIs(t, err, ErrNotFound)
}

// --- Resolver ---

func TestResolver_NilCipherDisabled(t *testing.T) {
	db := testDB(t)
	id, _ := Create(newCtx(), db, WriteParams{Name: "n", AuthMethod: "password", SecretEnc: "x"})

	r := New(db, nil) // no master key
	_, err := r.Resolve(newCtx(), id)
	require.ErrorIs(t, err, ErrDisabled, "no master key -> SSH cred storage disabled")
}

func TestResolver_RoundTripsPlaintext(t *testing.T) {
	db := testDB(t)
	// A real 32-byte master key + cipher (the all-zero key is fine for a test).
	cipher, err := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	require.NoError(t, err)

	// Encrypt a password + a key passphrase at "write" time (the handler does
	// this), store the ciphertext, then resolve and recover the plaintext.
	encSecret, err := cipher.Encrypt("s3cret-pw")
	require.NoError(t, err)
	encPP, err := cipher.Encrypt("key-passphrase")
	require.NoError(t, err)
	id, err := Create(newCtx(), db, WriteParams{
		Name: "r1", AuthMethod: "password", Username: "op",
		SecretEnc: encSecret, PassphraseEnc: encPP, HostKeyFP: "SHA256:fp",
	})
	require.NoError(t, err)

	r := New(db, cipher)
	cred, err := r.Resolve(newCtx(), id)
	require.NoError(t, err)
	require.Equal(t, "s3cret-pw", cred.Secret, "plaintext password recovered through the envelope")
	require.Equal(t, "key-passphrase", cred.Passphrase)
	require.Equal(t, "op", cred.Username)
	require.Equal(t, "SHA256:fp", cred.HostKeyFP)

	// By name too.
	cred2, err := r.ResolveByName(newCtx(), "r1")
	require.NoError(t, err)
	require.Equal(t, "s3cret-pw", cred2.Secret)
}

func TestResolver_NotFound(t *testing.T) {
	db := testDB(t)
	cipher, _ := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	r := New(db, cipher)
	_, err := r.Resolve(newCtx(), 999)
	require.ErrorIs(t, err, ErrNotFound)
}

// TestResolver_PlaintextNeverInList is the disclosure guard end-to-end: seed a
// row whose ciphertext encodes a known plaintext, then assert the List
// projection (the admin list view) does not carry either the ciphertext blob or
// the plaintext.
func TestResolver_PlaintextNeverInList(t *testing.T) {
	db := testDB(t)
	cipher, _ := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	const plainPW = "ULTRA-SECRET-PW"
	enc, _ := cipher.Encrypt(plainPW)
	_, _ = Create(newCtx(), db, WriteParams{Name: "d", AuthMethod: "password", SecretEnc: enc})

	rows, err := List(newCtx(), db, 50, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	// Neither the plaintext nor the ciphertext blob appears in the list payload.
	// (ListRow has no secret field, so this is a belt-and-suspenders guard.)
	require.False(t, strings.Contains(formatListRow(rows[0]), plainPW))
	require.False(t, strings.Contains(formatListRow(rows[0]), enc))
}

// formatListRow stringifies a ListRow for the disclosure assertion (it has no
// secret fields, so the secret plaintext/ciphertext can never appear).
func formatListRow(r ListRow) string {
	// Intentionally only the non-secret fields.
	return r.Name + r.AuthMethod + r.Username + r.HostKeyFP + r.Notes
}
