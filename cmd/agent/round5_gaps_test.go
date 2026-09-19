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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/crypto"
)

// openGapVaultDB opens the agent mini-DB in a temp dir (fresh schema) — the
// same shape `snmp-credential` subcommands operate on.
func openGapVaultDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "agent.db")
	conn, err := openAgentDB(dbPath)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	return dbPath
}

// TestAgentCredentialAdd_ValidationMatrix pins the CLI validation contract of
// addAgentCredential: every missing-field case returns its distinct exit code
// without touching the vault.
func TestAgentCredentialAdd_ValidationMatrix(t *testing.T) {
	ctx := context.Background()
	dbPath := openGapVaultDB(t)
	conn, err := openAgentDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)

	// No cipher (vault disabled) → 1.
	require.Equal(t, 1, addAgentCredential(ctx, conn, nil, credWriteFlags{Name: "x", SecurityLevel: "noAuthNoPriv"}))

	// Missing name → 2.
	require.Equal(t, 2, addAgentCredential(ctx, conn, cipher, credWriteFlags{SecurityLevel: "noAuthNoPriv"}))

	// Unknown security level → 2.
	require.Equal(t, 2, addAgentCredential(ctx, conn, cipher, credWriteFlags{Name: "x", SecurityLevel: "warp"}))

	// v1v2c without community → 2.
	require.Equal(t, 2, addAgentCredential(ctx, conn, cipher, credWriteFlags{Name: "x", SecurityLevel: "v1v2c"}))

	// authNoPriv without username/protocol → 2.
	require.Equal(t, 2, addAgentCredential(ctx, conn, cipher, credWriteFlags{Name: "x", SecurityLevel: "authNoPriv", AuthProtocol: "SHA"}))

	// authPriv without priv-protocol → 2.
	require.Equal(t, 2, addAgentCredential(ctx, conn, cipher, credWriteFlags{Name: "x", SecurityLevel: "authPriv", Username: "u", AuthProtocol: "SHA"}))
}

func TestAgentCredentialAddAndListAndRemove(t *testing.T) {
	ctx := context.Background()
	dbPath := openGapVaultDB(t)
	conn, err := openAgentDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)

	// Empty vault lists fine.
	require.Equal(t, 0, listAgentCredentials(ctx, conn))

	// v1v2c happy path (community, no passphrases).
	require.Equal(t, 0, addAgentCredential(ctx, conn, cipher, credWriteFlags{
		Name: "lan-community", SecurityLevel: "v1v2c", Community: "public", Notes: "lab",
	}))
	// authPriv happy path with passphrases via env (skips the stdin prompts).
	t.Setenv("MIBEE_AGENT_AUTH_PASSPHRASE", "auth-secret")
	t.Setenv("MIBEE_AGENT_PRIV_PASSPHRASE", "priv-secret")
	require.Equal(t, 0, addAgentCredential(ctx, conn, cipher, credWriteFlags{
		Name: "sw-v3", SecurityLevel: "authPriv", Username: "snmpadmin",
		AuthProtocol: "SHA", PrivProtocol: "AES",
	}))

	require.Equal(t, 0, listAgentCredentials(ctx, conn))

	// A scan task bound to the credential falls back to NULL on remove.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, timeout, concurrent_hosts, enabled, credential_id)
		 SELECT 'bound-task', '192.168.1.0/24', '0 3 * * *', '{}', 30, 10, 1, id FROM snmp_credentials WHERE name='sw-v3'`)
	require.NoError(t, err)

	// remove: missing name → 2; unknown → 1; happy → 0 (+ unbind).
	require.Equal(t, 2, removeAgentCredential(ctx, conn, ""))
	require.Equal(t, 1, removeAgentCredential(ctx, conn, "no-such-cred"))
	require.Equal(t, 0, removeAgentCredential(ctx, conn, "sw-v3"))

	var bound interface{}
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT credential_id FROM scan_tasks WHERE name='bound-task'`).Scan(&bound))
	require.Nil(t, bound, "removed credential must unbind scan tasks (SET NULL by hand)")
}

func TestOrDash(t *testing.T) {
	require.Equal(t, "-", orDash(""))
	require.Equal(t, "SHA", orDash("SHA"))
}

func TestReadLineFromStdin(t *testing.T) {
	orig := os.Stdin
	t.Cleanup(func() { os.Stdin = orig })

	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	_, err = w.WriteString("line-one\r\n")
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, "line-one", readLineFromStdin())

	// EOF returns the partial buffer.
	r2, w2, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r2
	require.NoError(t, w2.Close())
	require.Equal(t, "", readLineFromStdin())
}
