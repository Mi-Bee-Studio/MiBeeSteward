// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See the LICENSE file for the full
// text. A commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestBackupSubcommandsRoundTrip(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	dbPath := filepath.Join(dataDir, "mibee.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO devices (name) VALUES ('camera-1')`)
	require.NoError(t, err)
	_, err = db.Exec(`PRAGMA user_version = 11`)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "instance-id"), []byte("instance-test"), 0o600))

	configPath := filepath.Join(root, "config.yaml")
	configBody := fmt.Sprintf("server:\n  port: 18080\ndatabase:\n  sqlite:\n    path: %q\nauth:\n  jwt_secret: \"backup-test-secret-at-least-32-chars\"\n", filepath.ToSlash(dbPath))
	require.NoError(t, os.WriteFile(configPath, []byte(configBody), 0o600))
	outputDir := filepath.Join(root, "backups")

	require.NoError(t, runBackupSubcommand([]string{
		"-config", configPath, "-output", outputDir, "-retention-days", "0",
	}))
	entries, err := os.ReadDir(outputDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	bundle := filepath.Join(outputDir, entries[0].Name())
	require.NoError(t, runVerifyBackupSubcommand([]string{bundle}))

	targetData := filepath.Join(root, "restored")
	targetConfig := filepath.Join(root, "restored.yaml")
	require.NoError(t, runRestoreSubcommand([]string{
		"-data-dir", targetData, "-config", targetConfig, "-dry-run", bundle,
	}))
	_, err = os.Stat(targetData)
	require.True(t, os.IsNotExist(err))
	require.NoError(t, runRestoreSubcommand([]string{
		"-data-dir", targetData, "-config", targetConfig, bundle,
	}))
	restoredDB, err := sql.Open("sqlite", filepath.Join(targetData, "mibee.db"))
	require.NoError(t, err)
	var name string
	require.NoError(t, restoredDB.QueryRow(`SELECT name FROM devices LIMIT 1`).Scan(&name))
	require.Equal(t, "camera-1", name)
	require.NoError(t, restoredDB.Close())
	_, err = os.Stat(filepath.Join(targetData, "instance-id"))
	require.NoError(t, err)
	_, err = os.Stat(targetConfig)
	require.NoError(t, err)
}

func TestBackupSubcommandRejectsBadRetention(t *testing.T) {
	err := runBackupSubcommand([]string{"-retention-days", "-1"})
	require.ErrorContains(t, err, "must be >= 0")
}

func TestVerifyBackupSubcommandRequiresBundle(t *testing.T) {
	err := runVerifyBackupSubcommand(nil)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "usage:"))
}
