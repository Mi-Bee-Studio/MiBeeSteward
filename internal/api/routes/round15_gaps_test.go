// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package routes

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/testutil"
)

// TestBuildCredentialCipherMatrix pins the master-key gate ladder: unset →
// disabled, wrong length → disabled, valid 32 bytes → cipher + resolver.
func TestBuildCredentialCipherMatrix(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	c, r := buildCredentialCipher(db, &config.Config{})
	require.Nil(t, c, "unset key disables the vault")
	require.Nil(t, r)

	c, r = buildCredentialCipher(db, &config.Config{Security: config.SecurityConfig{MasterKey: "too-short"}})
	require.Nil(t, c, "wrong-length key disables the vault")
	require.Nil(t, r)

	c, r = buildCredentialCipher(db, &config.Config{Security: config.SecurityConfig{MasterKey: "0123456789abcdef0123456789abcdef"}})
	require.NotNil(t, c)
	require.NotNil(t, r)
}

// TestHeartbeatDBPathFor + rdnsTimeout defaults.
func TestSmallHelpers(t *testing.T) {
	require.Equal(t, filepath.Join("data", "heartbeat.db"),
		heartbeatDBPathFor(&config.Config{Database: config.DatabaseConfig{SQLite: config.SQLiteConfig{Path: "data/mibee.db"}}}))
	require.Equal(t, filepath.Join("data", "heartbeat.db"),
		heartbeatDBPathFor(&config.Config{}), "empty path falls back to ./data")

	require.Equal(t, 7, rdnsTimeout(config.ScannerConfig{RDNS: config.RDNSConfig{Timeout: 7}}))
	require.Equal(t, 2, rdnsTimeout(config.ScannerConfig{}))
}
