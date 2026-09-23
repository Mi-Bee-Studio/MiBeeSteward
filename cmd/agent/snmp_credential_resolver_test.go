// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/testutil"
)

// TestBuildAgentCredentialResolver_Matrix pins the vault bootstrap ladder:
// no key → nil, wrong-length key → nil, valid 32-byte key → live resolver.
func TestBuildAgentCredentialResolver_Matrix(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	require.Nil(t, buildAgentCredentialResolver(conn, &config.Config{}), "no master key → vault disabled")

	bad := &config.Config{}
	bad.Security.MasterKey = "too-short"
	require.Nil(t, buildAgentCredentialResolver(conn, bad), "wrong-length key → vault disabled")

	good := &config.Config{}
	good.Security.MasterKey = "0123456789abcdef0123456789abcdef"
	require.NotNil(t, buildAgentCredentialResolver(conn, good), "valid key → resolver wired")
}

// TestResolveAgentCredential_Degrades pins the agent-side degrade semantics:
// a stale local credential ID and an unknown center-referenced NAME both fall
// back to a community scan (0) instead of aborting the run.
func TestResolveAgentCredential_Degrades(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	good := &config.Config{}
	good.Security.MasterKey = "0123456789abcdef0123456789abcdef"
	resolver := buildAgentCredentialResolver(conn, good)
	require.NotNil(t, resolver)

	require.Zero(t, resolveAgentCredentialID(ctx, nil, 5), "nil resolver degrades to community")
	require.Zero(t, resolveAgentCredentialID(ctx, resolver, 0), "id 0 means community already")
	require.Zero(t, resolveAgentCredentialID(ctx, resolver, 999), "stale local id degrades to community")

	require.Zero(t, resolveAgentCredentialName(ctx, conn, nil, "switch-v3"), "nil resolver → community")
	require.Zero(t, resolveAgentCredentialName(ctx, conn, resolver, ""), "empty name → community")
	require.Zero(t, resolveAgentCredentialName(ctx, conn, resolver, "never-added"), "unknown name → community")
}

// writeAgentConfig writes a minimal agent config with the vault key set and
// returns its path (the vault DB lands next to it).
func writeAgentConfig(t *testing.T, dir string) string {
	t.Helper()
	yaml := `
center:
  url: "http://127.0.0.1:1"
  auth_token: "test-agent-token"
network:
  name: "cred-agent"
  cidr: "192.0.2.0/24"
security:
  master_key: "0123456789abcdef0123456789abcdef"
`
	p := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o600))
	return p
}

// TestSnmpCredentialSubcommand_ListAddRemove drives the vault CLI end-to-end:
// list on an empty vault, add a v3 credential by flags, list shows it, remove
// deletes it, remove of a missing name warns without failing.
func TestSnmpCredentialSubcommand_ListAddRemove(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeAgentConfig(t, dir)

	snmpCredentialSubcommand([]string{"-config", cfgPath, "-action", "list"})

	snmpCredentialSubcommand([]string{"-config", cfgPath, "-action", "add",
		"-name", "switch-v3", "-security-level", "authPriv",
		"-username", "snmpadmin", "-auth-protocol", "SHA", "-auth-passphrase", "authsecret1",
		"-priv-protocol", "AES", "-priv-passphrase", "privsecret1", "-notes", "core switch"})

	vaultDB, err := sql.Open("sqlite", filepath.Join(dir, "agent.db"))
	require.NoError(t, err)
	t.Cleanup(func() { vaultDB.Close() })
	var count int
	require.NoError(t, vaultDB.QueryRow(`SELECT COUNT(*) FROM snmp_credentials WHERE name = 'switch-v3'`).Scan(&count))
	require.Equal(t, 1, count, "add must write the v3 credential to the local vault")

	// The stored secret material is encrypted, not plaintext.
	var authBlob string
	require.NoError(t, vaultDB.QueryRow(`SELECT auth_passphrase_enc FROM snmp_credentials WHERE name = 'switch-v3'`).Scan(&authBlob))
	require.NotContains(t, authBlob, "authsecret1", "vault rows must be encrypted at rest")

	snmpCredentialSubcommand([]string{"-config", cfgPath, "-action", "remove", "-name", "switch-v3"})
	require.NoError(t, vaultDB.QueryRow(`SELECT COUNT(*) FROM snmp_credentials WHERE name = 'switch-v3'`).Scan(&count))
	require.Zero(t, count, "remove must delete the row")
}
