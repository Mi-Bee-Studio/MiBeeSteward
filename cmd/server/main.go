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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
	configPath  = flagSet.String("config", "configs/config.example.yaml", "Path to config file")
	showVersion = flagSet.Bool("version", false, "Print the build version and exit")
	demoMode    = flagSet.Bool("demo", false, "Demo mode (#285): seed a fictional inventory on an empty database and keep it active")
)

// flagSet is the package-level flag set; tests re-parse it instead of relying
// on the process's os.Args.
var flagSet = flag.NewFlagSet("mibee-steward", flag.ContinueOnError)

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

	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runCLI is the testable front of main: flag parsing + config load + the
// data-directory bootstrap, returning errors instead of exiting. serve()
// owns the runtime past this point.
func runCLI(args []string) error {
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Println("mibee-steward", version.Version)
		return nil
	}

	// Load configuration first (before slog init)
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	// Demo flag only after the err check: config.Load returns a nil cfg on
	// failure, so stamping DemoMode before the guard segfaults instead of
	// printing the config error (#327).
	if *demoMode {
		cfg.Server.DemoMode = true
	}

	// Initialize structured logger
	initLogger(cfg.Log)

	slog.Info("starting MiBee Steward", "version", version.Version)

	// Ensure data directory exists
	dbPath := cfg.Database.SQLite.Path
	if dbPath == "" {
		dbPath = "./data/mibee.db"
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("failed to create data directory %s: %w", filepath.Dir(dbPath), err)
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
		return fmt.Errorf("failed to open database %s: %w", dbPath, err)
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

	// Bridge os signals into the plain stop channel serve consumes. serve owns
	// the entire lifecycle (migrations → seed → HTTP → graceful shutdown) so it
	// can be driven in-process by tests with a bare channel.
	stop := make(chan struct{})
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		close(stop)
	}()
	if err := serve(cfg, db, dbPath, stop); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// serveHTTP assembles the router and HTTP server, listens, and runs the
// graceful-shutdown sequence when stop closes. A fatal run-time error (bind
// failure past the retry window) is returned instead of exiting the process,
// so the caller (main) decides the exit code.
func serveHTTP(cfg *config.Config, db *sql.DB, stop <-chan struct{}) error {
	// Create router
	router, heartbeatSvc, shutdownScanner := routes.NewRouter(db, cfg)

	// Determine bind address
	addr := bindAddr(cfg.Server.Host, cfg.Server.Port)

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
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("listening", "address", addr)
		serverErr <- listenAndServeWithRetry(srv)
	}()

	select {
	case <-stop:
	case err := <-serverErr:
		// ErrServerClosed only arrives when Shutdown was already in flight
		// (i.e. via the stop path racing this select); anything else is fatal.
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	slog.Info("shutting down server...")

	// Stop heartbeat scheduler
	heartbeatSvc.Stop()
	slog.Info("heartbeat scheduler stopped")

	// Stop scanner services
	shutdownScanner()
	slog.Info("scanner services stopped")

	// Shutdown HTTP server with 15s timeout.
	// cancel is called explicitly (not deferred) because the caller may
	// os.Exit right after serve returns, which would skip deferred calls and
	// leak the timeout context's resources.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := srv.Shutdown(ctx); err != nil {
		cancel()
		return fmt.Errorf("server forced to shutdown: %w", err)
	}
	cancel()

	// Close database
	db.Close()
	slog.Info("server stopped")
	return nil
}

// serve runs the full server lifecycle after the DB is opened: migrations,
// startup cleanups, admin seeding, router + HTTP listen, and graceful
// shutdown. It returns when stop is closed (main bridges os signals into it;
// tests use a plain channel) or on the first fatal error. All os.Exit calls
// live in main — serve is a plain function so tests can drive it in-process.
func serve(cfg *config.Config, db *sql.DB, dbPath string, stop <-chan struct{}) error {
	// Run migrations
	if err := runMigrations(db, dbPath); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	// One-time ghost cleanup (issue #19 Layer 4): detect devices whose IP has
	// drifted outside their stamped network's CIDR, and delete the ones that
	// are proven duplicates (a canonical copy exists in the correct network, or
	// the same MAC lives elsewhere). A steady-state instance finds nothing
	// here; a fresh DB skips it naturally (Reconcile returns empty).
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
		// via every host's fan-out reply).
		if removed, err := cleanupSvc.CleanupReservedAddressDevices(context.Background()); err != nil {
			slog.Warn("startup reserved-address cleanup failed (continuing)", "error", err)
		} else if len(removed) > 0 {
			slog.Info("startup reserved-address cleanup complete", "removed", removed)
		}
	}

	// Ensure upload directory exists
	if cfg.Storage.UploadPath != "" {
		if err := os.MkdirAll(cfg.Storage.UploadPath, 0755); err != nil {
			return fmt.Errorf("create upload directory: %w", err)
		}
	}
	// Initial admin password: a non-empty value = classic temp credential
	// (forced change on first login); EMPTY = first-run browser setup (the
	// admin is seeded password-less and the login page asks for a password to
	// be created — the installer default).
	if cfg.Auth.InitialAdminPassword == "" {
		slog.Info("auth.initial_admin_password is empty — the admin password will be set in the browser on first run")
	}
	expiry := 24 * time.Hour
	if cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.TokenExpiry); err == nil {
			expiry = d
		}
	}
	userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry, cfg.Auth.PasswordPolicy)
	seedAdminUser(userSvc, cfg.Auth.InitialAdminPassword)

	return serveHTTP(cfg, db, stop)
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

// seedAdminUser creates the bootstrap admin from auth.initial_admin_password.
// An EMPTY password (the installer's default) seeds the first-run state
// instead: the account has no usable password and the SPA's setup screen
// (login page polling /auth/setup-status) walks the operator through picking
// one in the browser — nothing to copy from the installer output. A non-empty
// password is a TEMPORARY credential (it deliberately skips the password
// policy — applying it here is what left fresh installs admin-less whenever
// the configured value failed the character-class rules) and first login
// forces a policy-compliant change via the SPA modal + server-side mcp gate.
func seedAdminUser(userSvc *service.UserService, password string) {
	_, err := userSvc.SeedAdmin(context.Background(), "admin@localhost", password)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			slog.Info("admin user already exists, skipping seed")
			return
		}
		slog.Error("failed to seed admin user — the server will start WITHOUT any login",
			"error", err,
			"remedy", "run `./mibee-steward reset-admin-password -config <config>` to create the admin")
		return
	}
	if password == "" {
		slog.Info("default admin user created with NO password — open the web UI to set it on first run",
			"username", "admin")
		return
	}
	slog.Info("default admin user created (first login will force a password change)", "username", "admin")
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

// bindAddr builds the listen address from server.host/port. net.JoinHostPort
// (not fmt.Sprintf) so IPv6 literals get bracketed: host "::" must yield
// "[::]:8090", not the unparseable ":::8090" — the OpenWrt GL-firmware docs
// recommend exactly that host value as the v4-listener workaround (#288), and
// the old concatenation crash-looped on it ("too many colons in address").
// An empty host keeps the dual-stack ":port" wildcard; port 0 falls back to
// the default 8080.
func bindAddr(host string, port int) string {
	if port == 0 {
		port = 8080
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
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
// bindRetryWindow/bindRetryInterval tune the EADDRINUSE retry loop below.
// Package vars (not consts) purely as a test seam — production values are the
// 30s/1s below.
var (
	bindRetryWindow   = 30 * time.Second
	bindRetryInterval = 1 * time.Second
)

func listenAndServeWithRetry(srv *http.Server) error {
	deadline := time.Now().Add(bindRetryWindow)
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
