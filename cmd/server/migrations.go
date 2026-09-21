// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Database bootstrap. Since v0.7 older databases are not migrated: a new
// database is created from the embedded schema, and an existing database whose
// recorded schema version differs from this build is rejected at startup.
// Schema changes ship as: edit db/schema.sql, bump SchemaVersion, release.

package main

import (
	"database/sql"
	"fmt"
	"log/slog"

	dbsql "mibee-steward/db"
)

// SchemaVersion is the schema generation this build creates. Version 2 was
// the last generation that migrated older databases in place (v0.6 and
// earlier); 3 is the first fresh-only generation.
const SchemaVersion = 3

// runMigrations creates a fresh database from the embedded schema and stamps
// the version, or verifies an existing database is at the current version.
func runMigrations(db *sql.DB, dbPath string) error {
	var current int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current == SchemaVersion {
		return nil
	}
	if current != 0 || hasUserTables(db) {
		return fmt.Errorf("database %s is at schema version %d but this build requires %d on a fresh database; "+
			"this release no longer upgrades older databases. Back up the data directory, remove the old database file, and start again",
			dbPath, current, SchemaVersion)
	}
	if _, err := db.Exec(dbsql.SchemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion)); err != nil {
		return fmt.Errorf("stamp schema version: %w", err)
	}
	slog.Info("database created", "schema_version", SchemaVersion)
	return nil
}

func hasUserTables(db *sql.DB) bool {
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`,
	).Scan(&n); err != nil {
		return true // unreadable catalog: assume non-empty so the caller refuses
	}
	return n > 0
}
