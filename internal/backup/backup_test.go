// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See the LICENSE file for the full
// text. A commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func makeTestDB(t *testing.T, path string, version int, table string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ` + table + ` (id INTEGER PRIMARY KEY, value TEXT)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO `+table+` (value) VALUES (?)`, "snapshot-ok")
	require.NoError(t, err)
	_, err = db.Exec(`PRAGMA user_version = ` + strconv.Itoa(version))
	require.NoError(t, err)
	require.NoError(t, db.Close())
}

func createFixture(t *testing.T) (dataDir, configPath, outputDir string) {
	t.Helper()
	root := t.TempDir()
	dataDir = filepath.Join(root, "data")
	configPath = filepath.Join(root, "config.yaml")
	outputDir = filepath.Join(dataDir, "backups")
	makeTestDB(t, filepath.Join(dataDir, "mibee.db"), 11, "devices")
	makeTestDB(t, filepath.Join(dataDir, "heartbeat.db"), 0, "heartbeat_results")
	makeTestDB(t, filepath.Join(dataDir, "probe_ext.db"), 0, "path_samples")
	writeTestFile(t, filepath.Join(dataDir, "uploads", "manual.pdf"), "pdf-bytes")
	writeTestFile(t, filepath.Join(dataDir, "fingerprints", "custom.yaml"), "version: 1\nrules: []\n")
	writeTestFile(t, filepath.Join(dataDir, "instance-id"), "stable-instance-id")
	writeTestFile(t, configPath, "auth:\n  jwt_secret: test-secret-at-least-32-characters\n")
	return dataDir, configPath, outputDir
}

func TestCreateVerifyRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	result, err := Create(ctx, CreateRequest{
		MainDBPath:            filepath.Join(dataDir, "mibee.db"),
		ConfigPath:            configPath,
		OutputDir:             outputDir,
		RetentionDays:         7,
		AppVersion:            "test",
		ExpectedSchemaVersion: 11,
		Now:                   func() time.Time { return time.Date(2026, 11, 28, 1, 2, 3, 0, time.UTC) },
	})
	require.NoError(t, err)
	require.Equal(t, 11, result.Manifest.SourceSchemaVersion)
	require.True(t, result.Manifest.ContainsSecrets)
	require.Equal(t, "databases/mibee.db", result.Manifest.MainDB)

	paths := map[string]bool{}
	for _, entry := range result.Manifest.Files {
		paths[entry.Path] = true
	}
	for _, want := range []string{
		"databases/mibee.db", "databases/heartbeat.db", "databases/probe_ext.db",
		"uploads/manual.pdf", "fingerprints/custom.yaml", "instance-id", ConfigName,
	} {
		require.True(t, paths[want], "bundle missing %s", want)
	}
	info, err := os.Stat(result.Path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	info, err = os.Stat(filepath.Join(result.Path, ConfigName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	inspected, err := Inspect(ctx, result.Path)
	require.NoError(t, err)
	require.Equal(t, result.Manifest.MainDB, inspected.MainDB)
	verified, err := Verify(ctx, result.Path)
	require.NoError(t, err)
	require.Equal(t, result.Manifest.MainDB, verified.MainDB)

	restoreRoot := t.TempDir()
	targetData := filepath.Join(restoreRoot, "restored")
	targetConfig := filepath.Join(restoreRoot, "restored-config.yaml")
	dry, err := Restore(ctx, result.Path, RestoreRequest{
		DataDir: targetData, ConfigPath: targetConfig, ExpectedSchemaVersion: 11, DryRun: true,
	})
	require.NoError(t, err)
	require.True(t, dry.DryRun)
	_, err = os.Stat(targetData)
	require.True(t, os.IsNotExist(err), "dry-run must not create the data directory")

	restored, err := Restore(ctx, result.Path, RestoreRequest{
		DataDir: targetData, ConfigPath: targetConfig, ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	require.False(t, restored.DryRun)
	for _, rel := range []string{"heartbeat.db", "probe_ext.db", "uploads/manual.pdf", "fingerprints/custom.yaml", "instance-id"} {
		_, err := os.Stat(filepath.Join(targetData, filepath.FromSlash(rel)))
		require.NoError(t, err, "restored data missing %s", rel)
	}
	configRaw, err := os.ReadFile(targetConfig)
	require.NoError(t, err)
	require.Contains(t, string(configRaw), "test-secret-at-least-32-characters")
	db, err := sql.Open("sqlite", filepath.Join(targetData, "mibee.db"))
	require.NoError(t, err)
	var value string
	require.NoError(t, db.QueryRow(`SELECT value FROM devices LIMIT 1`).Scan(&value))
	require.Equal(t, "snapshot-ok", value)
	require.NoError(t, db.Close())
}

func TestVerifyRejectsCorruptionAndPathTraversal(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	result, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	writeTestFile(t, filepath.Join(result.Path, "uploads", "manual.pdf"), "tampered!")
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "SHA-256 mismatch")

	manifestPath := filepath.Join(result.Path, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	var manifest Manifest
	require.NoError(t, json.Unmarshal(raw, &manifest))
	manifest.Files[0].Path = "../escape"
	raw, err = json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, raw, 0o600))
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "escapes bundle")
}

func TestRestoreProtectsTargetAndEnforcesSchema(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	result, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)

	target := filepath.Join(t.TempDir(), "live")
	writeTestFile(t, filepath.Join(target, "keep.txt"), "live")
	_, err = Restore(ctx, result.Path, RestoreRequest{DataDir: target, ExpectedSchemaVersion: 11})
	require.ErrorIs(t, err, ErrTargetExists)
	require.FileExists(t, filepath.Join(target, "keep.txt"))

	_, err = Restore(ctx, result.Path, RestoreRequest{DataDir: target, ExpectedSchemaVersion: 10})
	require.ErrorIs(t, err, ErrSchemaMismatch)

	restored, err := Restore(ctx, result.Path, RestoreRequest{
		DataDir: target, ExpectedSchemaVersion: 10, AllowSchemaMismatch: true, Force: true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, restored.PreviousData)
	require.FileExists(t, filepath.Join(restored.PreviousData, "keep.txt"))
	require.FileExists(t, filepath.Join(target, "mibee.db"))
}

func TestCreateSkipsEmbeddedBackupDirectory(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, _ := createFixture(t)
	writeTestFile(t, filepath.Join(dataDir, "backups", "legacy.db"), "old-backup")
	outputDir := filepath.Join(t.TempDir(), "external-backups")
	result, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	for _, entry := range result.Manifest.Files {
		require.NotEqual(t, "backups/legacy.db", entry.Path)
	}
}

func TestCreateAcceptsConfigInsideDataDirWithoutDuplicateEntry(t *testing.T) {
	ctx := context.Background()
	dataDir, _, outputDir := createFixture(t)
	configPath := filepath.Join(dataDir, ConfigName)
	writeTestFile(t, configPath, "auth:\n  jwt_secret: test-secret-at-least-32-characters\n")
	result, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	count := 0
	for _, entry := range result.Manifest.Files {
		if entry.Path == ConfigName {
			count++
		}
	}
	require.Equal(t, 1, count)
}
