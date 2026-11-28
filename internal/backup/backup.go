// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See the LICENSE file for the full
// text. A commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Package backup implements self-contained, verified backup bundles for the
// center's data directory. SQLite files are captured with VACUUM INTO (online,
// consistent snapshots); every other regular file is copied with a SHA-256
// manifest. Restore verifies the complete bundle before touching live data.
package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mibee-steward/internal/dbopen"
)

const (
	// ManifestVersion is the backup bundle format version.
	ManifestVersion = 1
	// BundlePrefix identifies managed backup directories.
	BundlePrefix = "mibee-"
	// ConfigName is the fixed restore location inside a bundle.
	ConfigName = "config.yaml"
)

var (
	// ErrSchemaMismatch is returned when a bundle was taken from a different
	// core schema generation. The product's standing policy is fresh DB + scan
	// for core schema crossings, not an untested in-place migration chain.
	ErrSchemaMismatch = errors.New("backup schema version does not match this build")
	// ErrTargetExists protects live data from an accidental overwrite.
	ErrTargetExists = errors.New("restore target already exists and is not empty")
)

// Manifest describes one verified backup bundle. ContainsSecrets is always
// true for current bundles because config.yaml may carry JWT/master keys;
// callers must protect backup directories accordingly.
type Manifest struct {
	Version             int         `json:"version"`
	CreatedAt           time.Time   `json:"created_at"`
	AppVersion          string      `json:"app_version"`
	MainDB              string      `json:"main_db"`
	SourceSchemaVersion int         `json:"source_schema_version"`
	ContainsSecrets     bool        `json:"contains_secrets"`
	Files               []FileEntry `json:"files"`
}

// FileEntry is one checksummed file in a bundle. SQLite entries also carry the
// source PRAGMA user_version (0 is valid for side stores).
type FileEntry struct {
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	Kind          string `json:"kind"`
	SchemaVersion *int   `json:"schema_version,omitempty"`
}

// CreateRequest configures a backup. MainDBPath is required; DataDir is its
// parent. ConfigPath is required and copied into the bundle because encrypted
// credentials are unusable without the matching master key.
type CreateRequest struct {
	MainDBPath            string
	ConfigPath            string
	OutputDir             string
	RetentionDays         int
	AppVersion            string
	ExpectedSchemaVersion int
	Now                   func() time.Time
}

// CreateResult is the committed bundle path and manifest.
type CreateResult struct {
	Path     string
	Manifest *Manifest
}

// RestoreRequest configures a verified restore.
type RestoreRequest struct {
	DataDir               string
	ConfigPath            string // optional; bundle config is copied here when set
	ExpectedSchemaVersion int
	AllowSchemaMismatch   bool
	Force                 bool
	DryRun                bool
	Now                   func() time.Time
}

// RestoreResult describes a completed (or dry-run) restore.
type RestoreResult struct {
	BundlePath   string
	DataDir      string
	ConfigPath   string
	PreviousData string
	DryRun       bool
	FileCount    int
}

// Create writes a complete bundle under OutputDir and returns only after every
// SQLite/file checksum and integrity check passes. A failed attempt leaves no
// final bundle directory behind.
func Create(ctx context.Context, req CreateRequest) (*CreateResult, error) {
	if strings.TrimSpace(req.MainDBPath) == "" {
		return nil, errors.New("backup: main database path is required")
	}
	if strings.TrimSpace(req.ConfigPath) == "" {
		return nil, errors.New("backup: config path is required")
	}
	mainPath, err := filepath.Abs(req.MainDBPath)
	if err != nil {
		return nil, fmt.Errorf("backup: resolve main database: %w", err)
	}
	info, err := os.Lstat(mainPath)
	if err != nil {
		return nil, fmt.Errorf("backup: stat main database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup: main database is not a regular file: %s", mainPath)
	}
	dataDir := filepath.Dir(mainPath)
	if strings.TrimSpace(req.OutputDir) == "" {
		req.OutputDir = filepath.Join(dataDir, "backups")
	}
	outputDir, err := filepath.Abs(req.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("backup: resolve output directory: %w", err)
	}
	if outputDir == dataDir {
		return nil, errors.New("backup: output directory must not equal the live data directory")
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: create output directory: %w", err)
	}
	if err := os.Chmod(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: secure output directory: %w", err)
	}

	now := req.Now
	if now == nil {
		now = time.Now
	}
	createdAt := now().UTC()
	finalDir := filepath.Join(outputDir, BundlePrefix+createdAt.Format("20060102_150405"))
	if _, err := os.Stat(finalDir); err == nil {
		finalDir = filepath.Join(outputDir, BundlePrefix+createdAt.Format("20060102_150405")+"-"+randomSuffix())
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("backup: inspect final path: %w", err)
	}
	tmpDir, err := os.MkdirTemp(outputDir, ".mibee-backup-*")
	if err != nil {
		return nil, fmt.Errorf("backup: create staging directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: secure staging directory: %w", err)
	}

	manifest := &Manifest{
		Version:         ManifestVersion,
		CreatedAt:       createdAt,
		AppVersion:      req.AppVersion,
		MainDB:          "databases/" + filepath.Base(mainPath),
		ContainsSecrets: true,
		Files:           []FileEntry{},
	}

	dbFiles, err := filepath.Glob(filepath.Join(dataDir, "*.db"))
	if err != nil {
		return nil, fmt.Errorf("backup: enumerate SQLite files: %w", err)
	}
	sort.Strings(dbFiles)
	foundMain := false
	for _, src := range dbFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		srcInfo, err := os.Lstat(src)
		if err != nil {
			return nil, fmt.Errorf("backup: stat SQLite file %s: %w", filepath.Base(src), err)
		}
		if !srcInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("backup: SQLite file is not a regular file: %s", filepath.Base(src))
		}
		if samePath(src, mainPath) {
			foundMain = true
		}
		dest := filepath.Join(tmpDir, "databases", filepath.Base(src))
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return nil, fmt.Errorf("backup: create database directory: %w", err)
		}
		if err := vacuumInto(ctx, src, dest); err != nil {
			return nil, fmt.Errorf("backup: snapshot %s: %w", filepath.Base(src), err)
		}
		if err := os.Chmod(dest, 0o600); err != nil {
			return nil, fmt.Errorf("backup: secure snapshot %s: %w", filepath.Base(src), err)
		}
		version, err := verifySQLite(ctx, dest)
		if err != nil {
			return nil, fmt.Errorf("backup: verify snapshot %s: %w", filepath.Base(src), err)
		}
		entry, err := hashFile(dest, "sqlite")
		if err != nil {
			return nil, fmt.Errorf("backup: hash snapshot %s: %w", filepath.Base(src), err)
		}
		entry.Path = "databases/" + filepath.Base(src)
		entry.SchemaVersion = &version
		manifest.Files = append(manifest.Files, entry)
		if samePath(src, mainPath) {
			manifest.SourceSchemaVersion = version
		}
	}
	if !foundMain {
		return nil, fmt.Errorf("backup: main database %s was not found among top-level *.db files", mainPath)
	}
	if req.ExpectedSchemaVersion > 0 && manifest.SourceSchemaVersion != req.ExpectedSchemaVersion {
		// Backups of older schemas remain useful for forensics/recovery, but a
		// normal restore into this build is refused unless explicitly allowed.
		slog.Warn("backup schema differs from running build",
			"source_schema_version", manifest.SourceSchemaVersion,
			"build_schema_version", req.ExpectedSchemaVersion)
	}

	outputRel, outputInsideData := relativeIfInside(outputDir, dataDir)
	if err := copyDataTree(ctx, dataDir, tmpDir, mainPath, outputRel, outputInsideData, &manifest.Files); err != nil {
		return nil, err
	}

	hasRootConfig := false
	for _, entry := range manifest.Files {
		if entry.Path == ConfigName {
			hasRootConfig = true
			break
		}
	}
	if !hasRootConfig {
		configDest := filepath.Join(tmpDir, ConfigName)
		if err := copyRegularFile(req.ConfigPath, configDest); err != nil {
			return nil, fmt.Errorf("backup: copy config: %w", err)
		}
		configEntry, err := hashFile(configDest, "file")
		if err != nil {
			return nil, fmt.Errorf("backup: hash config: %w", err)
		}
		configEntry.Path = ConfigName
		manifest.Files = append(manifest.Files, configEntry)
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })

	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := writeJSONAtomic(manifestPath, manifest); err != nil {
		return nil, fmt.Errorf("backup: write manifest: %w", err)
	}
	if _, err := Verify(ctx, tmpDir); err != nil {
		return nil, fmt.Errorf("backup: final bundle verification: %w", err)
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return nil, fmt.Errorf("backup: commit bundle: %w", err)
	}
	if req.RetentionDays > 0 {
		if err := pruneOld(ctx, outputDir, req.RetentionDays, createdAt); err != nil {
			return nil, fmt.Errorf("backup: prune old bundles: %w", err)
		}
	}
	return &CreateResult{Path: finalDir, Manifest: manifest}, nil
}

// Inspect is the lightweight health-check used by doctor/startup preflight. It
// validates the manifest shape and main SQLite integrity but deliberately does
// not hash every file; use Verify for a complete audit.
func Inspect(ctx context.Context, bundleDir string) (*Manifest, error) {
	abs, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("backup: resolve bundle: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(abs, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("backup: read manifest: %w", err)
	}
	if len(raw) > 4<<20 {
		return nil, errors.New("backup: manifest exceeds 4 MiB safety limit")
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("backup: decode manifest: %w", err)
	}
	if manifest.Version != ManifestVersion || manifest.MainDB == "" || len(manifest.Files) == 0 {
		return nil, errors.New("backup: invalid manifest header")
	}
	mainPath, err := safeJoin(abs, manifest.MainDB)
	if err != nil {
		return nil, err
	}
	if _, err := verifySQLite(ctx, mainPath); err != nil {
		return nil, fmt.Errorf("backup: main SQLite integrity: %w", err)
	}
	if _, err := os.Stat(filepath.Join(abs, ConfigName)); err != nil {
		return nil, fmt.Errorf("backup: config entry missing: %w", err)
	}
	return &manifest, nil
}

// Verify checks manifest structure, every SHA-256/size, and every SQLite
// integrity_check. It never mutates the bundle.
func Verify(ctx context.Context, bundleDir string) (*Manifest, error) {
	abs, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("backup: resolve bundle: %w", err)
	}
	manifestPath := filepath.Join(abs, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("backup: read manifest: %w", err)
	}
	if len(raw) > 4<<20 {
		return nil, errors.New("backup: manifest exceeds 4 MiB safety limit")
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("backup: decode manifest: %w", err)
	}
	if manifest.Version != ManifestVersion {
		return nil, fmt.Errorf("backup: unsupported manifest version %d", manifest.Version)
	}
	if manifest.MainDB == "" || len(manifest.Files) == 0 {
		return nil, errors.New("backup: manifest is missing main database or file entries")
	}
	seen := make(map[string]bool, len(manifest.Files))
	hasConfig := false
	hasMain := false
	for _, entry := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Path == "" || seen[entry.Path] {
			return nil, fmt.Errorf("backup: invalid or duplicate manifest path %q", entry.Path)
		}
		seen[entry.Path] = true
		if entry.Path == ConfigName {
			hasConfig = true
		}
		if entry.Path == manifest.MainDB && entry.Kind == "sqlite" {
			hasMain = true
		}
		path, err := safeJoin(abs, entry.Path)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("backup: stat %s: %w", entry.Path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("backup: bundle entry is not a regular file: %s", entry.Path)
		}
		if info.Size() != entry.Size {
			return nil, fmt.Errorf("backup: size mismatch for %s: got %d want %d", entry.Path, info.Size(), entry.Size)
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, fmt.Errorf("backup: hash %s: %w", entry.Path, err)
		}
		if !strings.EqualFold(sum, entry.SHA256) {
			return nil, fmt.Errorf("backup: SHA-256 mismatch for %s", entry.Path)
		}
		if entry.Kind == "sqlite" {
			version, err := verifySQLite(ctx, path)
			if err != nil {
				return nil, fmt.Errorf("backup: SQLite integrity %s: %w", entry.Path, err)
			}
			if entry.SchemaVersion != nil && *entry.SchemaVersion != version {
				return nil, fmt.Errorf("backup: schema stamp changed for %s", entry.Path)
			}
		} else if entry.Kind != "file" {
			return nil, fmt.Errorf("backup: unknown entry kind %q for %s", entry.Kind, entry.Path)
		}
	}
	if !hasMain {
		return nil, errors.New("backup: manifest has no matching SQLite main database entry")
	}
	if !hasConfig {
		return nil, errors.New("backup: manifest is missing config.yaml")
	}
	mainPath, err := safeJoin(abs, manifest.MainDB)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(mainPath); err != nil {
		return nil, fmt.Errorf("backup: main database entry is missing: %w", err)
	}
	return &manifest, nil
}

// Restore verifies the bundle, stages a complete copy beside the target, then
// swaps it into place. DryRun performs all validation but writes nothing.
func Restore(ctx context.Context, bundleDir string, req RestoreRequest) (*RestoreResult, error) {
	bundleAbs, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("restore: resolve bundle: %w", err)
	}
	manifest, err := Verify(ctx, bundleAbs)
	if err != nil {
		return nil, err
	}
	if req.ExpectedSchemaVersion > 0 && manifest.SourceSchemaVersion != req.ExpectedSchemaVersion && !req.AllowSchemaMismatch {
		return nil, fmt.Errorf("%w: bundle=%d build=%d; use a fresh database and rescan, or explicitly allow the mismatch for forensic recovery",
			ErrSchemaMismatch, manifest.SourceSchemaVersion, req.ExpectedSchemaVersion)
	}
	if strings.TrimSpace(req.DataDir) == "" {
		return nil, errors.New("restore: data directory is required")
	}
	dataDir, err := filepath.Abs(req.DataDir)
	if err != nil {
		return nil, fmt.Errorf("restore: resolve data directory: %w", err)
	}
	if pathWithin(dataDir, bundleAbs) {
		return nil, errors.New("restore: data directory must not be inside the backup bundle")
	}
	configPath := ""
	if strings.TrimSpace(req.ConfigPath) != "" {
		configPath, err = filepath.Abs(req.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("restore: resolve config path: %w", err)
		}
		if pathWithin(configPath, bundleAbs) {
			return nil, errors.New("restore: config path must not be inside the backup bundle")
		}
		if pathWithin(configPath, dataDir) {
			return nil, errors.New("restore: config path must be outside the target data directory")
		}
	}
	if err := checkTarget(dataDir, req.Force); err != nil {
		return nil, err
	}
	if configPath != "" {
		if err := checkTarget(configPath, req.Force); err != nil {
			return nil, fmt.Errorf("restore: config target: %w", err)
		}
	}
	result := &RestoreResult{BundlePath: bundleAbs, DataDir: dataDir, ConfigPath: configPath, DryRun: req.DryRun, FileCount: len(manifest.Files)}
	if req.DryRun {
		return result, nil
	}

	now := req.Now
	if now == nil {
		now = time.Now
	}
	stamp := now().UTC().Format("20060102_150405")
	parent := filepath.Dir(dataDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("restore: create data parent: %w", err)
	}
	stage, err := os.MkdirTemp(parent, ".mibee-restore-*")
	if err != nil {
		return nil, fmt.Errorf("restore: create staging directory: %w", err)
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return nil, fmt.Errorf("restore: secure staging directory: %w", err)
	}

	configStage := ""
	for _, entry := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		src, err := safeJoin(bundleAbs, entry.Path)
		if err != nil {
			return nil, err
		}
		var dest string
		switch {
		case entry.Path == ConfigName:
			if configPath == "" {
				continue
			}
			if configStage == "" {
				if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
					return nil, fmt.Errorf("restore: create config parent: %w", err)
				}
				f, err := os.CreateTemp(filepath.Dir(configPath), ".mibee-config-restore-*")
				if err != nil {
					return nil, fmt.Errorf("restore: create config staging file: %w", err)
				}
				configStage = f.Name()
				f.Close()
				os.Remove(configStage)
			}
			dest = configStage
		case strings.HasPrefix(entry.Path, "databases/"):
			dest = filepath.Join(stage, filepath.Base(entry.Path))
		default:
			dest, err = safeJoin(stage, entry.Path)
			if err != nil {
				return nil, err
			}
		}
		if err := copyRegularFile(src, dest); err != nil {
			return nil, fmt.Errorf("restore: copy %s: %w", entry.Path, err)
		}
	}
	mainStage, err := safeJoin(stage, filepath.Base(manifest.MainDB))
	if err != nil {
		return nil, err
	}
	if _, err := verifySQLite(ctx, mainStage); err != nil {
		return nil, fmt.Errorf("restore: staged main database: %w", err)
	}

	previousData := ""
	if _, err := os.Lstat(dataDir); err == nil {
		previousData = dataDir + ".pre-restore-" + stamp
		if _, err := os.Lstat(previousData); err == nil {
			previousData += "-" + randomSuffix()
		}
		if err := os.Rename(dataDir, previousData); err != nil {
			return nil, fmt.Errorf("restore: preserve previous data directory: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("restore: inspect data target: %w", err)
	}
	if err := os.Rename(stage, dataDir); err != nil {
		if previousData != "" {
			_ = os.Rename(previousData, dataDir)
		}
		return nil, fmt.Errorf("restore: activate staged data: %w", err)
	}
	result.PreviousData = previousData

	if configPath != "" {
		previousConfig := ""
		if _, err := os.Lstat(configPath); err == nil {
			previousConfig = configPath + ".pre-restore-" + stamp
			if _, err := os.Lstat(previousConfig); err == nil {
				previousConfig += "-" + randomSuffix()
			}
			if err := os.Rename(configPath, previousConfig); err != nil {
				rollbackData(dataDir, previousData, stage)
				return nil, fmt.Errorf("restore: preserve previous config: %w", err)
			}
		} else if !os.IsNotExist(err) {
			rollbackData(dataDir, previousData, stage)
			return nil, fmt.Errorf("restore: inspect config target: %w", err)
		}
		if err := os.Rename(configStage, configPath); err != nil {
			if previousConfig != "" {
				_ = os.Rename(previousConfig, configPath)
			}
			rollbackData(dataDir, previousData, stage)
			return nil, fmt.Errorf("restore: activate config: %w", err)
		}
	}
	return result, nil
}

// --- SQLite snapshots -----------------------------------------------------

func vacuumInto(ctx context.Context, src, dest string) error {
	dsn, err := dbopen.DSN(src, "busy_timeout=5000")
	if err != nil {
		return err
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := sql.Open("sqlite", dsn+sep+"mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dest); err != nil {
		return err
	}
	return nil
}

func verifySQLite(ctx context.Context, path string) (int, error) {
	dsn, err := dbopen.DSN(path, "busy_timeout=2000")
	if err != nil {
		return 0, err
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := sql.Open("sqlite", dsn+sep+"mode=ro")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return 0, err
	}
	ok := false
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			rows.Close()
			return 0, err
		}
		if result != "ok" {
			rows.Close()
			return 0, fmt.Errorf("integrity_check: %s", result)
		}
		ok = true
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()
	if !ok {
		return 0, errors.New("integrity_check returned no result")
	}
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

// --- File/manifest helpers ------------------------------------------------

func copyDataTree(ctx context.Context, dataDir, stage, mainPath, outputRel string, outputInsideData bool, entries *[]FileEntry) error {
	return filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if outputInsideData && (rel == outputRel || strings.HasPrefix(rel, outputRel+string(filepath.Separator))) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Never recursively embed the standard backup directory, even when the
		// operator chooses an external -output path.
		if rel == "backups" || strings.HasPrefix(rel, "backups"+string(filepath.Separator)) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup: symlink in data directory is not supported: %s", rel)
		}
		if !d.IsDir() {
			topLevel := filepath.Dir(path) == dataDir
			if samePath(path, mainPath) || (topLevel && (strings.HasSuffix(path, ".db") || strings.HasSuffix(path, ".db-wal") || strings.HasSuffix(path, ".db-shm"))) {
				return nil
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("backup: non-regular file in data directory: %s", rel)
			}
		}
		dest, err := safeJoin(stage, filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(dest, 0o700)
		}
		if err := copyRegularFile(path, dest); err != nil {
			return fmt.Errorf("backup: copy %s: %w", rel, err)
		}
		entry, err := hashFile(dest, "file")
		if err != nil {
			return fmt.Errorf("backup: hash %s: %w", rel, err)
		}
		entry.Path = filepath.ToSlash(rel)
		*entries = append(*entries, entry)
		return nil
	})
}

func copyRegularFile(src, dest string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file: %s", src)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(dest, 0o600)
}

func hashFile(path, kind string) (FileEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileEntry{}, err
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return FileEntry{}, err
	}
	return FileEntry{Size: info.Size(), SHA256: sum, Kind: kind}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSONAtomic(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func safeJoin(root, rel string) (string, error) {
	rel = filepath.FromSlash(rel)
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("backup: absolute manifest path is forbidden: %s", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("backup: manifest path escapes bundle: %s", rel)
	}
	return filepath.Join(root, clean), nil
}

func samePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	return errA == nil && errB == nil && aa == bb
}

func relativeIfInside(path, parent string) (string, bool) {
	rel, err := filepath.Rel(parent, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func pathWithin(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func checkTarget(path string, force bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("target is not a regular file or directory: %s", path)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) > 0 && !force {
			return fmt.Errorf("%w: %s", ErrTargetExists, path)
		}
		return nil
	}
	if !force {
		return fmt.Errorf("%w: %s", ErrTargetExists, path)
	}
	return nil
}

func rollbackData(dataDir, previousData, stage string) {
	if previousData != "" {
		_ = os.Rename(dataDir, stage)
		_ = os.Rename(previousData, dataDir)
		return
	}
	_ = os.RemoveAll(dataDir)
}

func pruneOld(ctx context.Context, outputDir string, retentionDays int, now time.Time) error {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return err
	}
	cutoff := now.AddDate(0, 0, -retentionDays)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), BundlePrefix) {
			continue
		}
		manifest, err := Verify(ctx, filepath.Join(outputDir, entry.Name()))
		if err != nil {
			continue // never delete a bundle we cannot prove is ours/valid
		}
		if manifest.CreatedAt.Before(cutoff) {
			if err := os.RemoveAll(filepath.Join(outputDir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func randomSuffix() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())))
	return hex.EncodeToString(sum[:4])
}
