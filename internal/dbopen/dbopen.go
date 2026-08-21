// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, copy, modify, and redistribute it
// under those terms; see LICENSE for the full text. A commercial license is
// available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package dbopen opens SQLite databases with per-connection pragmas applied
// via the DSN.
//
// Exec'ing "PRAGMA busy_timeout=..." on the *sql.DB handle only reaches ONE
// pooled connection — the other pool connections open with SQLite defaults
// (busy_timeout=0) and fail instantly with SQLITE_BUSY under write contention
// (#252). modernc.org/sqlite applies DSN "_pragma" parameters to every new
// connection, which is the only correct way to set per-connection pragmas on
// a multi-connection pool.
package dbopen

import (
	"database/sql"
	"fmt"
	"strings"

	// Registers the "sqlite" driver for the sql.Open call below; nothing from
	// the package is referenced directly.
	_ "modernc.org/sqlite"
)

// Open opens the SQLite file at path with every pragma in pragmas ("name=value",
// no "PRAGMA" keyword) applied to each pool connection as it is created. The
// returned handle is pinged once so connection-level failures surface here
// instead of at first use. Pool sizing (SetMaxOpenConns etc.) is the caller's
// job — pragmas from the DSN hold regardless of pool size.
func Open(path string, pragmas ...string) (*sql.DB, error) {
	dsn, err := DSN(path, pragmas...)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// DSN builds a "file:" URI carrying the pragmas as repeated _pragma query
// parameters. Pragma values containing characters that would break the query
// string (parens, & or #) are rejected rather than silently mangled.
func DSN(path string, pragmas ...string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("dbopen: empty database path")
	}
	var b strings.Builder
	b.WriteString("file:")
	b.WriteString(escapePath(path))
	first := true
	for _, p := range pragmas {
		name, value, ok := strings.Cut(p, "=")
		if !ok {
			return "", fmt.Errorf("dbopen: pragma %q is not name=value", p)
		}
		if strings.ContainsAny(name+value, "()&#") || name == "" || value == "" {
			return "", fmt.Errorf("dbopen: invalid pragma %q", p)
		}
		if first {
			b.WriteByte('?')
			first = false
		} else {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "_pragma=%s(%s)", name, value)
	}
	return b.String(), nil
}

// escapePath percent-escapes the characters a "file:" URI treats as structure
// (?, #, %) while leaving normal path separators intact.
func escapePath(path string) string {
	r := strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")
	return r.Replace(path)
}
