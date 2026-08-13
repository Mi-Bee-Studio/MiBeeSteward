package routes

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"mibee-steward/internal/config"

	dbsql "mibee-steward/db"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			JWTSecret: "test-jwt-secret-key-that-is-at-least-32-chars-long-for-testing",
		},
		Server: config.ServerConfig{
			Port: 0,
		},
		Scanner: config.ScannerConfig{
			MaxConcurrentHosts: 10,
			RetentionDays:      7,
		},
		// Auth-gate / capability-boundary tests fire ~100+ requests per test
		// function. The default global limiter (100/min, burst 100) would trip
		// and return 429, which has nothing to do with what these tests assert
		// (401/403 at the auth layer). Raise the user-facing limiters out of the
		// way; rate-limit *behavior* is tested separately in middleware/ against
		// its own isolated limiter.
		RateLimit: config.RateLimitConfig{
			GlobalPerMinute: 1_000_000,
			LoginPerMinute:  1_000_000,
		},
	}
}

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	// modernc's ":memory:" gives each connection its OWN private in-memory DB.
	// NewRouter spawns background goroutines (scheduler/heartbeat/cleanup) that
	// open separate connections, and the request handlers draw from the same
	// pool — so a per-test seed created on one connection would be invisible on
	// another. Pin the pool to a single connection so the seed, schema, and all
	// queries share one in-memory DB. (modernc serializes access; busy_timeout
	// keeps the short-lived background queries from blocking tests.)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	// Apply the production schema (db/schema.sql, embedded). The earlier
	// hand-maintained inline schema drifted from the real devices table
	// (missing scan_source/scan_attributes/... columns the list query
	// SELECTs), which broke any test that exercised GET /devices for
	// real. Using the canonical schema keeps the test DB in lockstep with
	// production (all tables/columns, CREATE TABLE IF NOT EXISTS).
	if _, err = db.Exec(dbsql.SchemaSQL); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return db
}

// TestScannerIntegration verifies that NewRouter initializes scanner services
// and returns a valid HTTP handler and shutdown function without panicking.
func TestScannerIntegration(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)

	handler, heartbeatSvc, shutdownScanner := NewRouter(db, cfg)

	if handler == nil {
		t.Fatal("expected non-nil HTTP handler")
	}
	if heartbeatSvc == nil {
		t.Fatal("expected non-nil HeartbeatService")
	}
	if shutdownScanner == nil {
		t.Fatal("expected non-nil scanner shutdown function")
	}

	// Shutdown should not panic
	heartbeatSvc.Stop()
	shutdownScanner()
}

// TestScannerShutdownIdempotent verifies that calling the scanner shutdown
// function multiple times does not panic.
func TestScannerShutdownIdempotent(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)

	_, heartbeatSvc, shutdownScanner := NewRouter(db, cfg)

	// Call shutdown twice — should not panic
	shutdownScanner()
	shutdownScanner()

	heartbeatSvc.Stop()
}

// TestScannerServicesStart verifies that scanner background services
// can be started and stopped within a short time window (race-free).
func TestScannerServicesStart(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)

	_, _, shutdownScanner := NewRouter(db, cfg)

	// Give services a moment to start, then shut down
	time.Sleep(100 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		shutdownScanner()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner shutdown timed out")
	}
}
