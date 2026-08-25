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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"mibee-steward/internal/api/routes"
	"mibee-steward/internal/config"
	"mibee-steward/internal/dbopen"
	"mibee-steward/internal/service"
	scannerv2reconcile "mibee-steward/internal/service/scannerv2/reconcile"
	"mibee-steward/internal/version"
)

var (
	configPath  = flag.String("config", "configs/config.example.yaml", "Path to config file")
	showVersion = flag.Bool("version", false, "Print the build version and exit")
	demoMode    = flag.Bool("demo", false, "Demo mode (#285): seed a fictional inventory on an empty database and keep it active")
)

func main() {
	// Subcommand dispatch: `mibee-steward reset-admin-password` runs the admin
	// password recovery flow instead of starting the server. Must be checked
	// before flag.Parse so the subcommand owns its own flag set.
	if len(os.Args) > 1 && os.Args[1] == "reset-admin-password" {
		resetAdminPasswordSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		runDoctor(os.Args[2:])
		return
	}

	flag.Parse()

	if *showVersion {
		fmt.Println("mibee-steward", version.Version)
		return
	}

	// Load configuration first (before slog init)
	cfg, err := config.Load(*configPath)
	if *demoMode {
		cfg.Server.DemoMode = true
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize structured logger
	initLogger(cfg.Log)

	slog.Info("starting MiBee Steward", "version", version.Version)

	// Ensure data directory exists
	dbPath := cfg.Database.SQLite.Path
	if dbPath == "" {
		dbPath = "./data/mibee.db"
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		slog.Error("failed to create data directory", "error", err, "path", filepath.Dir(dbPath))
		os.Exit(1)
	}

	// Open database connection. Pragmas travel in the DSN so every pooled
	// connection gets them — Exec'ing them on the handle after Open only
	// reached one connection and left the rest failing instantly with
	// SQLITE_BUSY under write contention (#252).
	db, err := dbopen.Open(dbPath,
		"journal_mode=WAL",
		"busy_timeout=5000",
		"synchronous=NORMAL",
		"cache_size=-64000",
		// temp_store=MEMORY keeps temp tables + B-trees in RAM instead of
		// spilling to a temp file — free latency reduction for large scans. (#162)
		"temp_store=MEMORY",
	)
	if err != nil {
		slog.Error("failed to open database", "error", err, "path", dbPath)
		os.Exit(1)
	}

	// Configure connection pool. Was 2 (a common SQLite default), but the
	// heartbeat service's concurrent verdict writes (GetDevice + UpdateDeviceStatus
	// for up to 16 devices at once) starved on 2 connections: a verdict goroutine
	// holding failCountsMu would block on a DB read while the other connection was
	// busy writing — leaving devices stuck on offline. 16 gives the probe pool
	// enough connections to read device state without blocking the writer.
	// WAL mode keeps reads from blocking the single writer, so this is safe.
	db.SetMaxOpenConns(16)
	// Match MaxIdleConns to MaxOpenConns so the pool doesn't churn connections
	// open/close under concurrent scanner + heartbeat load (was 4 << 16). (#162)
	db.SetMaxIdleConns(16)
	// Run migrations
	if err := runMigrations(db, dbPath); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// One-time ghost cleanup (issue #19 Layer 4): detect devices whose IP has
	// drifted outside their stamped network's CIDR, and delete the ones that
	// are proven duplicates (a canonical copy exists in the correct network, or
	// the same MAC lives elsewhere). Runs AFTER the pre-migration VACUUM INTO
	// backup (taken inside runMigrations), so the pre-cleanup state is
	// recoverable. Idempotent — a steady-state instance finds nothing here.
	// Skipped for a fresh DB (no networks/devices) since Reconcile returns empty.
	{
		cleanupSvc := scannerv2reconcile.New(db, 0, nil, slog.Default())
		if stats, err := cleanupSvc.CleanupGhosts(context.Background()); err != nil {
			slog.Warn("startup ghost cleanup failed (continuing)", "error", err)
		} else if stats.Mismatches > 0 {
			slog.Info("startup ghost cleanup complete",
				"mismatches", stats.Mismatches, "rehomed", stats.Rehomed, "unresolved", stats.Unresolved)
		}
		// Reserved-address ghosts (#254): devices the scanner recorded at a
		// network's own address or its broadcast (the broadcast answered pings
		// via every host's fan-out reply). Same backup protection as above.
		if removed, err := cleanupSvc.CleanupReservedAddressDevices(context.Background()); err != nil {
			slog.Warn("startup reserved-address cleanup failed (continuing)", "error", err)
		} else if len(removed) > 0 {
			slog.Info("startup reserved-address cleanup complete", "removed", removed)
		}
	}

	// Ensure upload directory exists
	if cfg.Storage.UploadPath != "" {
		if err := os.MkdirAll(cfg.Storage.UploadPath, 0755); err != nil {
			slog.Error("failed to create upload directory", "error", err, "path", cfg.Storage.UploadPath)
			os.Exit(1)
		}
	}
	// Initial admin password is required
	if cfg.Auth.InitialAdminPassword == "" {
		slog.Error("initial_admin_password must be set in config or via MIBEE_AUTH_INITIAL_ADMIN_PASSWORD env var")
		os.Exit(1)
	}
	expiry := 24 * time.Hour
	if cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.TokenExpiry); err == nil {
			expiry = d
		}
	}
	userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry, cfg.Auth.PasswordPolicy)
	seedAdminUser(userSvc, cfg.Auth.InitialAdminPassword)

	// Create router
	router, heartbeatSvc, shutdownScanner := routes.NewRouter(db, cfg)

	// Determine bind address
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	if cfg.Server.Port == 0 {
		addr = ":8080"
	}

	// Create HTTP server. Timeouts are configurable because the synchronous
	// /scanner/scan endpoint can legitimately run for minutes on large CIDRs;
	// the previous hard-coded 60s WriteTimeout truncated those responses.
	readTO := parseDurationOrDefault(cfg.Server.ReadTimeout, 15*time.Second)
	writeTO := parseDurationOrDefault(cfg.Server.WriteTimeout, 5*time.Minute)
	idleTO := parseDurationOrDefault(cfg.Server.IdleTimeout, 120*time.Second)
	// Guard: WriteTimeout must be at least as long as the configured scanner
	// default timeout × a sane multiplier, or synchronous scans will be cut off.
	if minWrite := time.Duration(cfg.Scanner.DefaultTimeout*2+30) * time.Second; writeTO < minWrite && cfg.Scanner.DefaultTimeout > 0 {
		slog.Warn("server.write_timeout too low for synchronous scans; raising", "configured", writeTO, "raised_to", minWrite)
		writeTO = minWrite
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  readTO,
		WriteTimeout: writeTO,
		IdleTimeout:  idleTO,
	}
	slog.Info("http server timeouts", "read", readTO, "write", writeTO, "idle", idleTO)

	// Start server in goroutine. A bare ListenAndServe that exits on bind error
	// is dangerous under systemd Restart=always: if the previous process's TCP
	// socket hasn't fully released (TIME_WAIT / kernel cleanup lag — common right
	// after a crash or SIGTERM), the new process hits "bind: address already in
	// use", exits 1, systemd restarts it 5s later, it fails again, and the cycle
	// repeats hundreds of times (observed 625 restarts on the test VM). A short
	// retry window lets the port release so one transient failure doesn't become
	// a restart storm.
	go func() {
		slog.Info("listening", "address", addr)
		if err := listenAndServeWithRetry(srv); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")

	// Stop heartbeat scheduler
	heartbeatSvc.Stop()
	slog.Info("heartbeat scheduler stopped")

	// Stop scanner services
	shutdownScanner()
	slog.Info("scanner services stopped")

	// Shutdown HTTP server with 15s timeout.
	// cancel is called explicitly (not deferred) because os.Exit below would
	// skip any deferred calls, leaking the timeout context's resources.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := srv.Shutdown(ctx); err != nil {
		cancel()
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}
	cancel()

	// Close database
	db.Close()
	slog.Info("server stopped")
}

func initLogger(cfg config.LogConfig) {
	level := parseLogLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func seedAdminUser(userSvc *service.UserService, password string) {
	ctx := context.Background()
	if _, err := userSvc.Register(ctx, "admin", "admin@localhost", password, "admin"); err != nil {
		if err == service.ErrUserExists {
			slog.Info("admin user already exists, skipping seed")
			return
		}
		slog.Warn("failed to seed admin user", "error", err)
		return
	}
	// Force admin to change password on first login
	if err := userSvc.SetMustChangePassword(ctx, 1, true); err != nil {
		slog.Warn("failed to set must_change_password for admin", "error", err)
	}
	slog.Info("default admin user created", "username", "admin")
}

// parseDurationOrDefault parses a config duration string (e.g. "5m", "30s"),
// returning def on empty/parse-error with a logged warning.
func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		slog.Warn("invalid duration in config, using default", "value", s, "default", def, "error", err)
		return def
	}
	return d
}

// listenAndServeWithRetry wraps http.Server.ListenAndServe with a bounded retry
// for the "address already in use" error. Under systemd Restart=always, a bare
// ListenAndServe that exits on bind failure causes a restart storm: the
// previous process's socket lingers in TIME_WAIT, each new attempt fails within
// milliseconds, and systemd dutifully restarts it every RestartSec — hundreds
// of cycles before the kernel finally releases the port. The retry holds the
// process alive for up to bindRetryDeadline (spanning several RestartSec windows
// is unnecessary because the retry itself buys the time) so the port can
// release in-process, converting a storm into a single delayed start.
//
// Only EADDRINUSE is retried — other errors (bad config, permission denied) are
// real failures that should surface immediately.
func listenAndServeWithRetry(srv *http.Server) error {
	const (
		bindRetryDeadline = 30 * time.Second
		bindRetryInterval = 1 * time.Second
	)
	deadline := time.Now().Add(bindRetryDeadline)
	for {
		err := srv.ListenAndServe()
		if err == http.ErrServerClosed {
			return err
		}
		if err == nil {
			return nil
		}
		// Retry only on "address already in use" — the one transient bind error
		// that resolves itself as the kernel releases the lingering socket.
		if !isAddrInUse(err) {
			return err
		}
		if time.Now().After(deadline) {
			slog.Error("server: bind retry deadline exceeded", "addr", srv.Addr, "error", err)
			return err
		}
		slog.Warn("server: bind failed (address in use), retrying",
			"addr", srv.Addr, "retry_in", bindRetryInterval, "error", err)
		time.Sleep(bindRetryInterval)
	}
}

// isAddrInUse reports whether err is an "address already in use" bind error.
// On Linux this surfaces as syscall.EADDRINUSE inside a *net.OpError.
func isAddrInUse(err error) bool {
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return sysErr.Err == syscall.EADDRINUSE
	}
	return false
}
