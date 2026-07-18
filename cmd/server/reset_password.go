// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"mibee-steward/internal/config"
	"mibee-steward/internal/service"
	"mibee-steward/internal/version"
)

// resetAdminPasswordSubcommand implements `mibee-steward reset-admin-password`.
//
// It loads the same config the server uses, opens the database, runs migrations
// (so the schema is current even if the server has never been started on this
// data dir), and forces a new password onto the admin user (id=1, created by
// seedAdminUser on first server start). The admin is NOT marked
// must_change_password — this is an operator recovery path, not a first-login
// flow, so the new password is the one the operator intends to keep using.
//
// Password is read from stdin (preferred, avoids shell history) or the
// -password flag / MIBEE_RESET_PASSWORD env var. Usage:
//
//	echo 'newpass' | mibee-steward reset-admin-password -config configs/config.yaml
//	mibee-steward reset-admin-password -config configs/config.yaml -password newpass
//	MIBEE_RESET_PASSWORD=newpass mibee-steward reset-admin-password -config configs/config.yaml
func resetAdminPasswordSubcommand(args []string) {
	fs := flag.NewFlagSet("reset-admin-password", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.example.yaml", "Path to config file")
	pwFlag := fs.String("password", "", "New admin password (prefer stdin to avoid shell history)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "mibee-steward %s — reset admin password\n", version.Version)

	// Resolve password: flag > env > stdin prompt.
	password := *pwFlag
	if password == "" {
		password = os.Getenv("MIBEE_RESET_PASSWORD")
	}
	if password == "" {
		fmt.Fprint(os.Stderr, "Enter new admin password: ")
		pw, err := readPasswordFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nfailed to read password from stdin: %v\n", err)
			os.Exit(1)
		}
		if pw == "" {
			fmt.Fprintln(os.Stderr, "\npassword cannot be empty")
			os.Exit(1)
		}
		fmt.Fprint(os.Stderr, "Confirm new admin password: ")
		confirm, err := readPasswordFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nfailed to read confirmation: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr)
		if pw != confirm {
			fmt.Fprintln(os.Stderr, "passwords do not match")
			os.Exit(1)
		}
		password = pw
	}

	// Load config + open DB (mirrors main()'s bootstrap, minus the HTTP server).
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	initLogger(cfg.Log)

	dbPath := cfg.Database.SQLite.Path
	if dbPath == "" {
		dbPath = "./data/mibee.db"
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}

	// runReset wraps the DB-touching logic so we can defer db.Close() and still
	// os.Exit on error without tripping gocritic's exitAfterDefer (deferred
	// calls are skipped by os.Exit). runReset returns the exit code.
	exitCode := func() int {
		defer db.Close()

		for _, p := range []string{
			"PRAGMA journal_mode=WAL",
			"PRAGMA busy_timeout=5000",
		} {
			if _, err := db.Exec(p); err != nil {
				slog.Error("failed to set pragma", "pragma", p, "error", err)
				return 1
			}
		}

		if err := runMigrations(db, dbPath); err != nil {
			slog.Error("failed to run migrations", "error", err)
			return 1
		}

		// ForceChangePassword does not need a valid JWT secret/expiry to set a
		// password, but NewUserService requires both params.
		expiry := 24 * time.Hour
		userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry)

		// admin user id is 1 — seedAdminUser creates it on first server start. If
		// the server has never been started, the admin user does not exist yet;
		// seed it now with the new password so the operator can log in.
		ctx := context.Background()
		const adminID int64 = 1
		if err := userSvc.ForceChangePassword(ctx, adminID, password); err != nil {
			if err == service.ErrUserNotFound {
				slog.Info("admin user not found; seeding with the new password")
				if _, err := userSvc.Register(ctx, "admin", "admin@localhost", password, "admin"); err != nil {
					slog.Error("failed to seed admin user", "error", err)
					return 1
				}
			} else {
				slog.Error("failed to reset admin password", "error", err)
				return 1
			}
		}

		slog.Info("admin password reset successfully", "username", "admin")
		return 0
	}()

	if exitCode != 0 {
		os.Exit(exitCode)
	}
	fmt.Fprintln(os.Stderr, "Admin password reset successfully. You can now log in as 'admin'.")
}

// readPasswordFromStdin reads a single line from stdin, trimming the trailing
// newline. It does NOT disable echo (the server runs headless; operators who
// need hidden input should use the -password flag or env var).
func readPasswordFromStdin() (string, error) {
	buf := make([]byte, 0, 256)
	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			if b[0] == '\r' {
				continue
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			return strings.TrimSpace(string(buf)), err
		}
	}
	return strings.TrimSpace(string(buf)), nil
}
