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

func TestCreateValidationErrors(t *testing.T) {
	ctx := context.Background()
	_, err := Create(ctx, CreateRequest{})
	require.ErrorContains(t, err, "main database path is required")
	_, err = Create(ctx, CreateRequest{MainDBPath: filepath.Join(t.TempDir(), "missing.db"), ConfigPath: "config.yaml"})
	require.ErrorContains(t, err, "stat main database")

	dataDir, configPath, _ := createFixture(t)
	_, err = Create(ctx, CreateRequest{MainDBPath: dataDir, ConfigPath: configPath})
	require.ErrorContains(t, err, "not a regular file")
	_, err = Create(ctx, CreateRequest{MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: dataDir})
	require.ErrorContains(t, err, "must not equal")
	_, err = Create(ctx, CreateRequest{MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: filepath.Join(dataDir, "missing-config.yaml")})
	require.ErrorContains(t, err, "copy config")
}

func TestVerifyManifestErrorBranches(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	result, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	manifestPath := filepath.Join(result.Path, "manifest.json")
	original, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	require.NoError(t, os.Remove(manifestPath))
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "read manifest")
	require.NoError(t, os.WriteFile(manifestPath, append(original, make([]byte, 4<<20)...), 0o600))
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "safety limit")
	require.NoError(t, os.WriteFile(manifestPath, []byte("{bad"), 0o600))
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "decode manifest")

	var manifest Manifest
	require.NoError(t, json.Unmarshal(original, &manifest))
	writeManifest := func(m Manifest) {
		raw, marshalErr := json.Marshal(m)
		require.NoError(t, marshalErr)
		require.NoError(t, os.WriteFile(manifestPath, raw, 0o600))
	}
	manifest.Version++
	writeManifest(manifest)
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "unsupported manifest version")

	require.NoError(t, json.Unmarshal(original, &manifest))
	manifest.Files = nil
	writeManifest(manifest)
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "missing main database or file entries")

	require.NoError(t, json.Unmarshal(original, &manifest))
	manifest.Files = append(manifest.Files, manifest.Files[0])
	writeManifest(manifest)
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "duplicate manifest path")

	require.NoError(t, json.Unmarshal(original, &manifest))
	for i := range manifest.Files {
		if manifest.Files[i].Path != ConfigName {
			continue
		}
		manifest.Files = append(manifest.Files[:i], manifest.Files[i+1:]...)
		break
	}
	writeManifest(manifest)
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "missing config.yaml")

	require.NoError(t, json.Unmarshal(original, &manifest))
	for i := range manifest.Files {
		if manifest.Files[i].Path == manifest.MainDB {
			manifest.Files[i].Kind = "file"
		}
	}
	writeManifest(manifest)
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "no matching SQLite main database")

	require.NoError(t, json.Unmarshal(original, &manifest))
	for i := range manifest.Files {
		if manifest.Files[i].Path == manifest.MainDB && manifest.Files[i].SchemaVersion != nil {
			*manifest.Files[i].SchemaVersion = 999
		}
	}
	writeManifest(manifest)
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "schema stamp changed")

	require.NoError(t, json.Unmarshal(original, &manifest))
	for i := range manifest.Files {
		if manifest.Files[i].Kind == "file" && manifest.Files[i].Path != ConfigName {
			manifest.Files[i].Kind = "mystery"
		}
	}
	writeManifest(manifest)
	_, err = Verify(ctx, result.Path)
	require.ErrorContains(t, err, "unknown entry kind")
}

func TestRestoreValidationErrors(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	result, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	_, err = Restore(ctx, result.Path, RestoreRequest{})
	require.ErrorContains(t, err, "data directory is required")
	_, err = Restore(ctx, result.Path, RestoreRequest{DataDir: filepath.Join(result.Path, "nested")})
	require.ErrorContains(t, err, "inside the backup bundle")
	_, err = Restore(ctx, result.Path, RestoreRequest{DataDir: t.TempDir(), ConfigPath: filepath.Join(result.Path, ConfigName)})
	require.ErrorContains(t, err, "inside the backup bundle")

	target := filepath.Join(t.TempDir(), "data")
	_, err = Restore(ctx, result.Path, RestoreRequest{DataDir: target, ConfigPath: filepath.Join(target, ConfigName)})
	require.ErrorContains(t, err, "outside the target data directory")
	writeTestFile(t, target, "file-target")
	_, err = Restore(ctx, result.Path, RestoreRequest{DataDir: target})
	require.ErrorIs(t, err, ErrTargetExists)

	configTarget := filepath.Join(t.TempDir(), "config.yaml")
	writeTestFile(t, configTarget, "live")
	_, err = Restore(ctx, result.Path, RestoreRequest{DataDir: filepath.Join(t.TempDir(), "fresh"), ConfigPath: configTarget})
	require.ErrorIs(t, err, ErrTargetExists)
}

func TestRetentionPrunesOnlyVerifiedOldBundles(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	old, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		Now: func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) },
	})
	require.NoError(t, err)
	corrupt := filepath.Join(outputDir, BundlePrefix+"corrupt")
	require.NoError(t, os.MkdirAll(corrupt, 0o700))
	writeTestFile(t, filepath.Join(corrupt, "manifest.json"), "not-json")
	notes := filepath.Join(outputDir, "operator-notes.txt")
	writeTestFile(t, notes, "keep")
	fresh, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		RetentionDays: 7, Now: func() time.Time { return time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC) },
	})
	require.NoError(t, err)
	_, err = os.Stat(old.Path)
	require.True(t, os.IsNotExist(err), "verified old bundle should be pruned")
	_, err = os.Stat(fresh.Path)
	require.NoError(t, err)
	_, err = os.Stat(corrupt)
	require.NoError(t, err, "unverifiable bundle must never be pruned")
	require.FileExists(t, notes, "non-bundle files must be ignored by retention")
}

func TestRollbackDataAndCollisionSuffix(t *testing.T) {
	root := t.TempDir()
	previous := filepath.Join(root, "data.pre-restore")
	current := filepath.Join(root, "data")
	stage := filepath.Join(root, "stage")
	writeTestFile(t, filepath.Join(previous, "old.txt"), "old")
	writeTestFile(t, filepath.Join(current, "new.txt"), "new")
	rollbackData(current, previous, stage)
	require.FileExists(t, filepath.Join(current, "old.txt"))
	require.FileExists(t, filepath.Join(stage, "new.txt"))

	writeTestFile(t, filepath.Join(current, "new.txt"), "new")
	rollbackData(current, "", stage)
	_, err := os.Stat(current)
	require.True(t, os.IsNotExist(err))
	require.Len(t, randomSuffix(), 8)
}

func TestInspectErrorBranches(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	result, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	manifestPath := filepath.Join(result.Path, "manifest.json")
	original, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	require.NoError(t, os.Remove(manifestPath))
	_, err = Inspect(ctx, result.Path)
	require.ErrorContains(t, err, "read manifest")
	require.NoError(t, os.WriteFile(manifestPath, []byte("{bad"), 0o600))
	_, err = Inspect(ctx, result.Path)
	require.ErrorContains(t, err, "decode manifest")
	require.NoError(t, os.WriteFile(manifestPath, original, 0o600))

	mainPath := filepath.Join(result.Path, "databases", "mibee.db")
	require.NoError(t, os.WriteFile(mainPath, []byte("not-sqlite"), 0o600))
	_, err = Inspect(ctx, result.Path)
	require.ErrorContains(t, err, "main SQLite integrity")
	require.NoError(t, os.Remove(mainPath))
	require.NoError(t, copyRegularFile(filepath.Join(dataDir, "mibee.db"), mainPath))
	require.NoError(t, os.Remove(filepath.Join(result.Path, ConfigName)))
	_, err = Inspect(ctx, result.Path)
	require.ErrorContains(t, err, "config entry missing")
}

func TestLowLevelErrorBranches(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	require.Error(t, vacuumInto(ctx, missing, filepath.Join(root, "out.db")))
	_, err := verifySQLite(ctx, missing)
	require.Error(t, err)
	textFile := filepath.Join(root, "text")
	writeTestFile(t, textFile, "not sqlite")
	_, err = verifySQLite(ctx, textFile)
	require.Error(t, err)
	require.Error(t, copyRegularFile(missing, filepath.Join(root, "copy")))
	require.Error(t, copyRegularFile(root, filepath.Join(root, "copy")))
	writeTestFile(t, filepath.Join(root, "copy"), "exists")
	require.Error(t, copyRegularFile(textFile, filepath.Join(root, "copy")))
	_, err = hashFile(missing, "file")
	require.Error(t, err)
	_, err = hashFile(root, "file")
	require.Error(t, err, "hashing a directory must surface the read failure")
	_, err = fileSHA256(missing)
	require.Error(t, err)
	require.Error(t, writeJSONAtomic(filepath.Join(root, "copy"), map[string]string{"x": "y"}))
	_, err = safeJoin(root, filepath.Join(root, "absolute"))
	require.ErrorContains(t, err, "absolute manifest path")

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, copyDataTree(canceled, root, filepath.Join(root, "stage"), missing, "", false, &[]FileEntry{}), context.Canceled)

	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(textFile, link))
	entries := []FileEntry{}
	err = copyDataTree(ctx, root, filepath.Join(root, "stage2"), missing, "", false, &entries)
	require.ErrorContains(t, err, "symlink")
}

func TestCreateSnapshotAndOutputErrors(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, _ := createFixture(t)
	parentFile := filepath.Join(t.TempDir(), "file")
	writeTestFile(t, parentFile, "x")
	_, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath,
		OutputDir: filepath.Join(parentFile, "backups"),
	})
	require.ErrorContains(t, err, "create output directory")

	badDB := filepath.Join(dataDir, "bad.db")
	writeTestFile(t, badDB, "not sqlite")
	_, err = Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath,
		OutputDir: filepath.Join(t.TempDir(), "backups"),
	})
	require.ErrorContains(t, err, "snapshot bad.db")
}

func TestAdditionalValidationBranches(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, _ := createFixture(t)
	_, err := Create(ctx, CreateRequest{MainDBPath: filepath.Join(dataDir, "mibee.db")})
	require.ErrorContains(t, err, "config path is required")

	// Empty output uses <data-dir>/backups and a fixed timestamp collision uses
	// the suffix path; both are normal operator paths.
	now := func() time.Time { return time.Date(2026, 11, 28, 1, 2, 3, 0, time.UTC) }
	first, err := Create(ctx, CreateRequest{MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, Now: now})
	require.NoError(t, err)
	second, err := Create(ctx, CreateRequest{MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, Now: now})
	require.NoError(t, err)
	require.NotEqual(t, first.Path, second.Path)

	bundle := t.TempDir()
	writeTestFile(t, filepath.Join(bundle, "manifest.json"), `{"version":1,"main_db":"","files":[]}`)
	_, err = Inspect(ctx, bundle)
	require.ErrorContains(t, err, "invalid manifest header")
	writeTestFile(t, filepath.Join(bundle, "manifest.json"), `{"version":1,"main_db":"../escape","files":[{"path":"x"}]}`)
	_, err = Inspect(ctx, bundle)
	require.ErrorContains(t, err, "escapes bundle")

	require.NoError(t, checkTarget(filepath.Join(t.TempDir(), "missing"), false))
	existingFile := filepath.Join(t.TempDir(), "existing")
	writeTestFile(t, existingFile, "replace me")
	require.NoError(t, checkTarget(existingFile, true))
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(configPath, link))
	require.ErrorContains(t, checkTarget(link, false), "not a regular file or directory")

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, pruneOld(canceled, filepath.Dir(first.Path), 7, time.Now()), context.Canceled)
	require.Error(t, pruneOld(ctx, filepath.Join(t.TempDir(), "missing"), 7, time.Now()))
	require.Error(t, writeJSONAtomic(filepath.Join(t.TempDir(), "manifest.json"), make(chan int)))
}

func TestCreateRejectsUnsupportedDatabaseLayouts(t *testing.T) {
	ctx := context.Background()
	t.Run("non-regular side database", func(t *testing.T) {
		dataDir, configPath, outputDir := createFixture(t)
		require.NoError(t, os.Symlink(filepath.Join(dataDir, "mibee.db"), filepath.Join(dataDir, "side.db")))
		_, err := Create(ctx, CreateRequest{
			MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		})
		require.ErrorContains(t, err, "SQLite file is not a regular file")
	})
	t.Run("main database outside top-level glob", func(t *testing.T) {
		dataDir, configPath, outputDir := createFixture(t)
		mainPath := filepath.Join(dataDir, "mibee.sqlite")
		require.NoError(t, copyRegularFile(filepath.Join(dataDir, "mibee.db"), mainPath))
		_, err := Create(ctx, CreateRequest{MainDBPath: mainPath, ConfigPath: configPath, OutputDir: outputDir})
		require.ErrorContains(t, err, "was not found among top-level *.db files")
	})
	t.Run("schema mismatch is recorded and allowed", func(t *testing.T) {
		dataDir, configPath, outputDir := createFixture(t)
		result, err := Create(ctx, CreateRequest{
			MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
			ExpectedSchemaVersion: 999,
		})
		require.NoError(t, err)
		require.Equal(t, 11, result.Manifest.SourceSchemaVersion)
	})
}

func TestVacuumIntoRejectsUnwritableDestination(t *testing.T) {
	ctx := context.Background()
	dataDir, _, _ := createFixture(t)
	err := vacuumInto(ctx, filepath.Join(dataDir, "mibee.db"), filepath.Join(dataDir, "missing", "out.db"))
	require.Error(t, err)
}

func TestRestoreForceReplacesExistingDataAndConfig(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	bundle, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)

	target := filepath.Join(t.TempDir(), "data")
	writeTestFile(t, filepath.Join(target, "old.txt"), "old")
	configTarget := filepath.Join(t.TempDir(), "config.yaml")
	writeTestFile(t, configTarget, "live")
	result, err := Restore(ctx, bundle.Path, RestoreRequest{
		DataDir: target, ConfigPath: configTarget, Force: true,
		Now: func() time.Time { return time.Date(2026, 11, 28, 2, 3, 4, 0, time.UTC) },
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.PreviousData)
	require.FileExists(t, filepath.Join(result.PreviousData, "old.txt"))
	require.FileExists(t, filepath.Join(target, "mibee.db"))
	require.NoFileExists(t, filepath.Join(target, "old.txt"))
	previousConfig, err := filepath.Glob(configTarget + ".pre-restore-*")
	require.NoError(t, err)
	require.Len(t, previousConfig, 1)
	raw, err := os.ReadFile(previousConfig[0])
	require.NoError(t, err)
	require.Equal(t, "live", string(raw))
	raw, err = os.ReadFile(configTarget)
	require.NoError(t, err)
	require.Contains(t, string(raw), "jwt_secret")
}

func TestVerifyRejectsDamagedBundleEntries(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, bundlePath, sourceDataDir string)
		want   string
	}{
		{"size mismatch", func(t *testing.T, bundlePath, _ string) {
			path := filepath.Join(bundlePath, ConfigName)
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, append(raw, 'x'), 0o600))
		}, "size mismatch"},
		{"missing entry", func(t *testing.T, bundlePath, _ string) {
			require.NoError(t, os.Remove(filepath.Join(bundlePath, ConfigName)))
		}, "stat config.yaml"},
		{"non-regular entry", func(t *testing.T, bundlePath, _ string) {
			path := filepath.Join(bundlePath, ConfigName)
			require.NoError(t, os.Remove(path))
			require.NoError(t, os.Mkdir(path, 0o700))
		}, "not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir, configPath, outputDir := createFixture(t)
			bundle, err := Create(ctx, CreateRequest{
				MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
				ExpectedSchemaVersion: 11,
			})
			require.NoError(t, err)
			tc.mutate(t, bundle.Path, dataDir)
			_, err = Verify(ctx, bundle.Path)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestCancelledOperationsStopBeforeWork(t *testing.T) {
	ctx := context.Background()
	dataDir, configPath, outputDir := createFixture(t)
	bundle, err := Create(ctx, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: outputDir,
		ExpectedSchemaVersion: 11,
	})
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = Create(canceled, CreateRequest{
		MainDBPath: filepath.Join(dataDir, "mibee.db"), ConfigPath: configPath, OutputDir: filepath.Join(t.TempDir(), "backups"),
	})
	require.ErrorIs(t, err, context.Canceled)
	_, err = Verify(canceled, bundle.Path)
	require.ErrorIs(t, err, context.Canceled)
	_, err = Restore(canceled, bundle.Path, RestoreRequest{DataDir: filepath.Join(t.TempDir(), "restore")})
	require.ErrorIs(t, err, context.Canceled)
}

func TestCopyDataTreeSkipsExcludedFilesAndBackupSentinel(t *testing.T) {
	ctx := context.Background()
	t.Run("excluded file", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "skip.txt"), "skip")
		writeTestFile(t, filepath.Join(root, "keep.txt"), "keep")
		entries := []FileEntry{}
		require.NoError(t, copyDataTree(ctx, root, filepath.Join(t.TempDir(), "stage"), filepath.Join(root, "skip.txt"), "", false, &entries))
		require.Len(t, entries, 1)
		require.Equal(t, "keep.txt", entries[0].Path)
	})
	t.Run("backups file sentinel", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "backups"), "not a directory")
		writeTestFile(t, filepath.Join(root, "keep.txt"), "keep")
		entries := []FileEntry{}
		require.NoError(t, copyDataTree(ctx, root, filepath.Join(t.TempDir(), "stage"), "", "", false, &entries))
		require.Len(t, entries, 1)
		require.Equal(t, "keep.txt", entries[0].Path)
	})
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
