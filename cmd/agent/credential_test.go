// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/crypto"
	"mibee-steward/internal/service/scannerv2/credresolver"
)

// openVaultDB provisions a mini-DB (which creates snmp_credentials) plus a
// resolver keyed by a valid 32-byte master key.
func openVaultDB(t *testing.T) (*credentialFixture, func()) {
	t.Helper()
	conn, err := openAgentDB(t.TempDir() + "/agent.db")
	require.NoError(t, err)
	c, err := crypto.NewCipher([]byte(strings.Repeat("k", crypto.MasterKeyLen)))
	require.NoError(t, err)
	fx := &credentialFixture{conn: conn, resolver: credresolver.New(conn, c), cipher: c}
	return fx, func() { conn.Close() }
}

type credentialFixture struct {
	conn     *sql.DB
	resolver *credresolver.Resolver
	cipher   *crypto.Cipher
}

// TestAgentVault_Roundtrip pins the #241 agent-local vault end to end: a
// credential written through the raw-SQL store (as the CLI does) reads back
// through the SAME resolver the engine uses, with passphrases decrypted
// in-process and the v3 security level intact.
func TestAgentVault_Roundtrip(t *testing.T) {
	fx, cleanup := openVaultDB(t)
	defer cleanup()
	ctx := context.Background()

	authEnc, err := fx.cipher.Encrypt("auth-secret")
	require.NoError(t, err)
	privEnc, err := fx.cipher.Encrypt("priv-secret")
	require.NoError(t, err)
	id, err := credresolver.CreateSNMPCredential(ctx, fx.conn, credresolver.SNMPCredentialWriteParams{
		Name: "switch-v3", SecurityLevel: "authPriv", Username: "snmpadmin",
		AuthProtocol: "SHA", AuthPassphraseEnc: authEnc,
		PrivProtocol: "AES", PrivPassphraseEnc: privEnc,
	})
	require.NoError(t, err)

	cred, err := fx.resolver.ResolveByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, cred)
	require.True(t, cred.IsV3())
	require.Equal(t, "switch-v3", cred.Name)
	require.Equal(t, "snmpadmin", cred.UserName)
	require.Equal(t, "auth-secret", cred.AuthPassphrase)
	require.Equal(t, "priv-secret", cred.PrivPassphrase)
}

// TestResolveAgentCredentialID_Degrades covers the agent scan fallbacks: a
// nil resolver (no master key) and a stale ID both yield 0 (community scan)
// instead of an engine-fatal error; a usable ID passes through.
func TestResolveAgentCredentialID_Degrades(t *testing.T) {
	fx, cleanup := openVaultDB(t)
	defer cleanup()
	ctx := context.Background()

	require.Equal(t, int64(0), resolveAgentCredentialID(ctx, nil, 42), "nil resolver (vault disabled) must fall back to community")
	require.Equal(t, int64(0), resolveAgentCredentialID(ctx, fx.resolver, 999), "stale credential id must degrade to 0")

	authEnc, err := fx.cipher.Encrypt("pw")
	require.NoError(t, err)
	id, err := credresolver.CreateSNMPCredential(ctx, fx.conn, credresolver.SNMPCredentialWriteParams{
		Name: "cred-a", SecurityLevel: "authNoPriv", Username: "u",
		AuthProtocol: "SHA", AuthPassphraseEnc: authEnc,
	})
	require.NoError(t, err)
	require.Equal(t, id, resolveAgentCredentialID(ctx, fx.resolver, id), "usable credential id passes through")
}

// TestResolveAgentCredentialName covers the #241 command-channel mapping:
// the center forwards credential NAMES (IDs are per-system); the agent maps
// the name to its local vault, and unknown names degrade to community.
func TestResolveAgentCredentialName(t *testing.T) {
	fx, cleanup := openVaultDB(t)
	defer cleanup()
	ctx := context.Background()

	require.Equal(t, int64(0), resolveAgentCredentialName(ctx, fx.conn, fx.resolver, ""))
	require.Equal(t, int64(0), resolveAgentCredentialName(ctx, fx.conn, fx.resolver, "missing"), "unknown name must degrade to community")
	require.Equal(t, int64(0), resolveAgentCredentialName(ctx, fx.conn, nil, "any"), "disabled vault must degrade to community")

	authEnc, err := fx.cipher.Encrypt("pw")
	require.NoError(t, err)
	id, err := credresolver.CreateSNMPCredential(ctx, fx.conn, credresolver.SNMPCredentialWriteParams{
		Name: "switch-v3", SecurityLevel: "authNoPriv", Username: "u",
		AuthProtocol: "SHA", AuthPassphraseEnc: authEnc,
	})
	require.NoError(t, err)
	require.Equal(t, id, resolveAgentCredentialName(ctx, fx.conn, fx.resolver, "switch-v3"))
}

// TestBuildAgentCredentialResolver mirrors the center's buildCredentialCipher
// degrade semantics: empty key → nil (vault off), wrong length → nil, valid
// key → resolver wired to the mini-DB.
func TestBuildAgentCredentialResolver(t *testing.T) {
	conn, err := openAgentDB(t.TempDir() + "/agent.db")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	require.Nil(t, buildAgentCredentialResolver(conn, &config.Config{}), "no master key = vault disabled")
	require.Nil(t, buildAgentCredentialResolver(conn, &config.Config{Security: config.SecurityConfig{MasterKey: "short"}}),
		"wrong-length key = vault disabled (loud error logged, resolver nil)")
	require.NotNil(t, buildAgentCredentialResolver(conn, &config.Config{Security: config.SecurityConfig{MasterKey: strings.Repeat("k", crypto.MasterKeyLen)}}))
}
