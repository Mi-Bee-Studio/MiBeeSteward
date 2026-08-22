// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, copy, modify, and redistribute it
// under those terms; see LICENSE for the full text. A commercial license is
// available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/dbopen"
)

// doctorExit codes: 0 = all checks passed (warnings allowed), 1 = at least
// one failure. Warnings alone do not fail the run — a fresh small deployment
// legitimately warns on some items (e.g. no backup yet).
const doctorFailExit = 1

// doctorCheck is one line of the report.
type doctorCheck struct {
	name    string
	status  string // "ok" | "warn" | "fail" | "skip"
	detail  string
	fixHint string
}

// runDoctor is the `mibee-steward doctor [-config ...]` subcommand (#281): a
// post-install health check that surfaces the operational gotchas the field
// kept hitting — a missing master key, a stale instance holding the port,
// DB corruption, WAL bloat, backup rot — as a ✅/⚠️/❌ report with fix hints,
// instead of leaving the operator to grep logs.
func runDoctor(args []string) {
	os.Exit(doctor(args))
}

// doctor runs the checks and returns the process exit code. Separate from
// runDoctor so os.Exit happens AFTER doctorMain's defers (db.Close) have run.
func doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.example.yaml", "Path to config file")
	_ = fs.Parse(args)

	fmt.Printf("mibee-steward doctor — config %s\n\n", *cfgPath)

	cfg, cfgErr := config.Load(*cfgPath)
	var checks []doctorCheck

	// -- Configuration -----------------------------------------------------
	if cfgErr != nil {
		checks = append(checks, doctorCheck{
			name: "config", status: "fail",
			detail: cfgErr.Error(), fixHint: "fix the YAML (see configs/config.example.yaml for the full reference)",
		})
		printReport(checks)
		return doctorFailExit
	}
	checks = append(checks, doctorCheck{name: "config", status: "ok", detail: "loaded and validated"})

	switch jwt := cfg.Auth.JWTSecret; {
	case jwt == "":
		checks = append(checks, doctorCheck{name: "auth.jwt_secret", status: "fail",
			detail: "not set", fixHint: "set a random 32+ char value (e.g. `openssl rand -hex 32`)"})
	case len(jwt) < 32:
		checks = append(checks, doctorCheck{name: "auth.jwt_secret", status: "warn",
			detail: fmt.Sprintf("short (%d chars)", len(jwt)), fixHint: "use 32+ chars"})
	default:
		checks = append(checks, doctorCheck{name: "auth.jwt_secret", status: "ok", detail: "present"})
	}

	if cfg.Auth.InitialAdminPassword == "" {
		checks = append(checks, doctorCheck{name: "auth.initial_admin_password", status: "fail",
			detail: "not set (admin cannot be created on a fresh DB)", fixHint: "set it, then change it after first login"})
	} else {
		checks = append(checks, doctorCheck{name: "auth.initial_admin_password", status: "ok", detail: "present"})
	}

	mk := cfg.Security.MasterKey
	switch {
	case mk == "":
		checks = append(checks, doctorCheck{name: "security.master_key", status: "warn",
			detail:  "not set — SNMPv3/SSH credential storage disabled (v1/v2c scans unaffected)",
			fixHint: "set a 32-byte hex/base64 value to enable encrypted credentials"})
	case len(mk) != 32 && len(mk) != 44: // 32 raw bytes or base64(32)
		checks = append(checks, doctorCheck{name: "security.master_key", status: "fail",
			detail:  fmt.Sprintf("wrong length (%d bytes decoded input) — must decode to 32 bytes", len(mk)),
			fixHint: "generate with `openssl rand -base64 32`"})
	default:
		checks = append(checks, doctorCheck{name: "security.master_key", status: "ok", detail: "present, plausible length"})
	}

	if cfg.Auth.JWTSecret != "" && cfg.Auth.JWTSecret == cfg.Auth.InitialAdminPassword {
		checks = append(checks, doctorCheck{name: "secret reuse", status: "warn",
			detail: "jwt_secret equals initial_admin_password", fixHint: "use distinct secrets"})
	}

	// -- Database ----------------------------------------------------------
	dbPath := cfg.Database.SQLite.Path
	if dbPath == "" {
		dbPath = "./data/mibee.db"
	}
	db, err := dbopen.Open(dbPath, "busy_timeout=5000", "journal_mode=WAL", "synchronous=NORMAL")
	if err != nil {
		checks = append(checks, doctorCheck{name: "database open", status: "fail",
			detail: err.Error(), fixHint: "check the path and directory permissions"})
		printReport(checks)
		return doctorFailExit
	}
	defer db.Close()
	checks = append(checks, doctorCheck{name: "database open", status: "ok", detail: dbPath})

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _doctor_probe (id INTEGER PRIMARY KEY)`); err != nil {
		checks = append(checks, doctorCheck{name: "database write probe", status: "fail",
			detail: err.Error(), fixHint: "check file permissions / disk space / another process holding an exclusive lock"})
	} else {
		_, _ = db.Exec(`DROP TABLE IF EXISTS _doctor_probe`)
		checks = append(checks, doctorCheck{name: "database write probe", status: "ok", detail: "insert/delete round-trip ok"})
	}

	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		checks = append(checks, doctorCheck{name: "integrity_check", status: "fail",
			detail:  fmt.Sprintf("result=%q err=%v", integrity, err),
			fixHint: "restore the latest data/backups copy (scripts/backup.sh produces them)"})
	} else {
		checks = append(checks, doctorCheck{name: "integrity_check", status: "ok", detail: "ok"})
	}

	var walSize int64
	if fi, err := os.Stat(dbPath + "-wal"); err == nil {
		walSize = fi.Size()
	}
	if walSize > 64<<20 {
		checks = append(checks, doctorCheck{name: "WAL size", status: "warn",
			detail:  fmt.Sprintf("%s (checkpoints are not keeping up or an instance is holding the WAL)", humanBytes(walSize)),
			fixHint: "the maintenance pass checkpoints every retention sweep; if this persists, look for long-lived readers"})
	} else {
		checks = append(checks, doctorCheck{name: "WAL size", status: "ok", detail: humanBytes(walSize)})
	}

	if fi, err := os.Stat(dbPath); err == nil {
		checks = append(checks, doctorCheck{name: "database size", status: "ok", detail: humanBytes(fi.Size())})
	}

	// -- Port / duplicate instance ------------------------------------------
	port := cfg.Server.Port
	if port == 0 {
		port = 8080
	}
	addr := net.JoinHostPort("", strconv.Itoa(port))
	if ln, err := net.Listen("tcp", addr); err != nil {
		checks = append(checks, doctorCheck{name: "port availability", status: "warn",
			detail:  fmt.Sprintf(":%d already in use", port),
			fixHint: "another instance is running (fine on the active server), but do NOT start a second one — two writers on one SQLite file lose data"})
	} else {
		_ = ln.Close()
		checks = append(checks, doctorCheck{name: "port availability", status: "ok", detail: fmt.Sprintf(":%d free", port)})
	}

	// -- Server timeouts vs scan timeout -------------------------------------
	if cfg.Server.WriteTimeout != "" && cfg.Scanner.DefaultTimeout > 0 {
		wt, err := time.ParseDuration(cfg.Server.WriteTimeout)
		want := time.Duration(cfg.Scanner.DefaultTimeout*2+30) * time.Second
		switch {
		case err != nil:
			checks = append(checks, doctorCheck{name: "server.write_timeout", status: "warn",
				detail: "unparseable: " + cfg.Server.WriteTimeout, fixHint: "use a Go duration string like 5m"})
		case wt < want:
			checks = append(checks, doctorCheck{name: "server.write_timeout", status: "warn",
				detail:  fmt.Sprintf("%s < scanner.auto floor %s — large sync scans can be cut mid-response", wt, want),
				fixHint: "raise server.write_timeout (the server auto-raises it at boot; this is for explicit low values)"})
		default:
			checks = append(checks, doctorCheck{name: "server.write_timeout", status: "ok", detail: wt.String()})
		}
	}

	// -- Backups --------------------------------------------------------------
	backupDir := filepath.Join(filepath.Dir(dbPath), "backups")
	if entries, err := os.ReadDir(backupDir); err != nil || len(entries) == 0 {
		checks = append(checks, doctorCheck{name: "backups", status: "warn",
			detail:  "no backups found under " + backupDir,
			fixHint: "schedule scripts/backup.sh (cron: 0 2 * * *)"})
	} else {
		newest := ""
		var newestMod time.Time
		for _, e := range entries {
			if fi, err := e.Info(); err == nil && fi.ModTime().After(newestMod) && strings.HasSuffix(e.Name(), ".db") {
				newestMod, newest = fi.ModTime(), filepath.Join(backupDir, e.Name())
			}
		}
		if newest == "" {
			checks = append(checks, doctorCheck{name: "backups", status: "warn", detail: "no .db backups", fixHint: "schedule scripts/backup.sh"})
		} else {
			age := time.Since(newestMod).Round(time.Hour)
			status, hint := "ok", ""
			if age > 48*time.Hour {
				status, hint = "warn", "older than 48h — check the cron entry"
			}
			checks = append(checks, doctorCheck{name: "backups", status: status,
				detail: fmt.Sprintf("newest %s (%s old)", filepath.Base(newest), age), fixHint: hint})
			// Quick restorability check: the newest backup must open and pass integrity.
			if bdb, err := dbopen.Open(newest, "busy_timeout=2000"); err == nil {
				var ok string
				if err := bdb.QueryRow(`PRAGMA integrity_check`).Scan(&ok); err == nil && ok == "ok" {
					checks = append(checks, doctorCheck{name: "backup restorable", status: "ok", detail: filepath.Base(newest) + " opens, integrity ok"})
				} else {
					checks = append(checks, doctorCheck{name: "backup restorable", status: "fail",
						detail: fmt.Sprintf("integrity=%q err=%v", ok, err), fixHint: "take a fresh backup and investigate disk health"})
				}
				bdb.Close()
			} else {
				checks = append(checks, doctorCheck{name: "backup restorable", status: "fail",
					detail: err.Error(), fixHint: "take a fresh backup"})
			}
		}
	}

	// -- Center reachability (agent-mode config) ------------------------------
	if cfg.Center.URL != "" {
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // reachability probe
		}}
		resp, err := client.Get(strings.TrimSuffix(cfg.Center.URL, "/") + "/api/v1/health")
		if err != nil {
			checks = append(checks, doctorCheck{name: "center reachable", status: "fail",
				detail: err.Error(), fixHint: "check center URL / network path / firewall"})
		} else {
			resp.Body.Close()
			checks = append(checks, doctorCheck{name: "center reachable", status: "ok",
				detail: fmt.Sprintf("%s → HTTP %d", cfg.Center.URL, resp.StatusCode)})
		}
	} else {
		checks = append(checks, doctorCheck{name: "center reachable", status: "skip", detail: "not an agent config (center.url unset)"})
	}

	// ICMP capability (#288): the scanner and heartbeat use unprivileged
	// ICMP (pro-bing SetPrivileged(false)) — datagram ping sockets require
	// the group to be inside /proc/sys/net/ipv4/ping_group_range. The OpenWrt
	// default "1 0" (disabled) leaves every probe "permission denied".
	if raw, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range"); err == nil {
		var lo, hi int
		if n, _ := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d %d", &lo, &hi); n == 2 {
			gid := os.Getgid()
			switch {
			case lo > hi:
				checks = append(checks, doctorCheck{name: "icmp ping_group_range", status: "fail",
					detail:  fmt.Sprintf("disabled (%s) — unprivileged ICMP probes will fail", strings.TrimSpace(string(raw))),
					fixHint: `echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range (or add to sysctl.d; required for ICMP without root)`})
			case gid >= lo && gid <= hi:
				checks = append(checks, doctorCheck{name: "icmp ping_group_range", status: "ok",
					detail: fmt.Sprintf("gid %d within [%d %d]", gid, lo, hi)})
			default:
				checks = append(checks, doctorCheck{name: "icmp ping_group_range", status: "warn",
					detail:  fmt.Sprintf("service gid %d outside [%d %d]", gid, lo, hi),
					fixHint: "widen ping_group_range or run the service under a covered group"})
			}
		}
	}

	printReport(checks)
	for _, c := range checks {
		if c.status == "fail" {
			return doctorFailExit
		}
	}
	return 0
}

func printReport(checks []doctorCheck) {
	icon := map[string]string{"ok": "✅", "warn": "⚠️ ", "fail": "❌", "skip": "—"}
	pass, warn, fail := 0, 0, 0
	for _, c := range checks {
		fmt.Printf("  %s %-26s %s\n", icon[c.status], c.name, c.detail)
		if c.fixHint != "" && (c.status == "fail" || c.status == "warn") {
			fmt.Printf("     %s hint: %s\n", icon[c.status], c.fixHint)
		}
		switch c.status {
		case "ok":
			pass++
		case "warn":
			warn++
		case "fail":
			fail++
		}
	}
	fmt.Printf("\n  %d passed, %d warnings, %d failures\n", pass, warn, fail)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
