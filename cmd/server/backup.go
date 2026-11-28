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
	"context"
	"flag"
	"fmt"
	"path/filepath"

	"mibee-steward/internal/backup"
	"mibee-steward/internal/config"
	"mibee-steward/internal/version"
)

func runBackupSubcommand(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	configPath := fs.String("config", "config.yaml", "Path to the live config file")
	dbPath := fs.String("db", "", "Override main SQLite path (default: database.sqlite.path from config)")
	outputDir := fs.String("output", "", "Backup bundle directory (default: <data-dir>/backups)")
	retentionDays := fs.Int("retention-days", 7, "Delete verified bundles older than N days (0 disables pruning)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *retentionDays < 0 {
		return fmt.Errorf("backup: -retention-days must be >= 0")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("backup: load config: %w", err)
	}
	mainPath := *dbPath
	if mainPath == "" {
		mainPath = cfg.Database.SQLite.Path
	}
	if mainPath == "" {
		mainPath = "./data/mibee.db"
	}
	if *outputDir == "" {
		*outputDir = filepath.Join(filepath.Dir(mainPath), "backups")
	}
	result, err := backup.Create(context.Background(), backup.CreateRequest{
		MainDBPath:            mainPath,
		ConfigPath:            *configPath,
		OutputDir:             *outputDir,
		RetentionDays:         *retentionDays,
		AppVersion:            version.Version,
		ExpectedSchemaVersion: SchemaVersion,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Backup complete: %s\n", result.Path)
	fmt.Printf("Schema version: %d; files: %d; bundle contains secrets (protect it accordingly).\n",
		result.Manifest.SourceSchemaVersion, len(result.Manifest.Files))
	return nil
}

func runVerifyBackupSubcommand(args []string) error {
	fs := flag.NewFlagSet("verify-backup", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: mibee-steward verify-backup <bundle-dir>")
	}
	manifest, err := backup.Verify(context.Background(), fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Printf("Backup verified: %s\n", fs.Arg(0))
	fmt.Printf("Created: %s; schema: %d; files: %d\n",
		manifest.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), manifest.SourceSchemaVersion, len(manifest.Files))
	return nil
}

func runRestoreSubcommand(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "./data", "Target data directory")
	configPath := fs.String("config", "", "Optional target config path; restores the bundled config here")
	dryRun := fs.Bool("dry-run", false, "Verify and print the restore plan without writing")
	force := fs.Bool("force", false, "Replace a non-empty target, preserving it as *.pre-restore-<timestamp>")
	allowMismatch := fs.Bool("allow-schema-mismatch", false, "Allow forensic restore from a different core schema (normal restores refuse)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: mibee-steward restore [flags] <bundle-dir>")
	}
	result, err := backup.Restore(context.Background(), fs.Arg(0), backup.RestoreRequest{
		DataDir:               *dataDir,
		ConfigPath:            *configPath,
		ExpectedSchemaVersion: SchemaVersion,
		AllowSchemaMismatch:   *allowMismatch,
		Force:                 *force,
		DryRun:                *dryRun,
	})
	if err != nil {
		return err
	}
	if result.DryRun {
		fmt.Printf("Restore dry-run OK: %s -> %s (%d files)\n", result.BundlePath, result.DataDir, result.FileCount)
		if result.ConfigPath != "" {
			fmt.Printf("Config target: %s\n", result.ConfigPath)
		}
		return nil
	}
	fmt.Printf("Restore complete: %s\n", result.DataDir)
	if result.PreviousData != "" {
		fmt.Printf("Previous data preserved at: %s\n", result.PreviousData)
	}
	if result.ConfigPath != "" {
		fmt.Printf("Config restored: %s\n", result.ConfigPath)
	}
	return nil
}
