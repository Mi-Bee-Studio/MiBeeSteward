package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

func newRepo(t *testing.T, opts Options) (*SQLiteRepository, context.Context) {
	t.Helper()
	db, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("setup db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSQLiteRepository(db, opts, nil), context.Background()
}

func TestRecordServices_ReplaceOnRescan(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.1"

	// First scan: http + ssh.
	if err := repo.RecordServices(ctx, ip, []scannerv2.ServiceIdentity{
		{Service: "http", Port: 80, Confidence: 0.9, Metadata: map[string]string{"server": "nginx"}},
		{Service: "ssh", Port: 22, Confidence: 0.95},
	}); err != nil {
		t.Fatalf("record services (1): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_services WHERE ip=?`, ip); cnt != 2 {
		t.Fatalf("expected 2 services after first scan, got %d", cnt)
	}

	// Second scan: only http remains (ssh dropped). Replace semantics → 1 row.
	if err := repo.RecordServices(ctx, ip, []scannerv2.ServiceIdentity{
		{Service: "http", Port: 80, Confidence: 0.95, Metadata: map[string]string{"server": "nginx/1.25"}},
	}); err != nil {
		t.Fatalf("record services (2): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_services WHERE ip=?`, ip); cnt != 1 {
		t.Fatalf("expected 1 service after rescan, got %d", cnt)
	}
	// Metadata updated.
	var meta string
	if err := repo.db.QueryRow(`SELECT metadata FROM host_services WHERE ip=? AND service='http'`, ip).Scan(&meta); err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(meta), &m); err != nil {
		t.Fatal(err)
	}
	if m["server"] != "nginx/1.25" {
		t.Errorf("metadata not updated: %v", m)
	}
}

func TestRecordEvidence_SampledByDefault(t *testing.T) {
	repo, ctx := newRepo(t, Options{PersistRawEvidence: false})
	ev := []scannerv2.Evidence{
		{Source: "active:tcp", Kind: "banner", IP: "10.0.0.2", Port: 22, Confidence: 0.9, ObservedAt: time.Now()},
	}
	if err := repo.RecordEvidence(ctx, ev); err != nil {
		t.Fatalf("record evidence: %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM service_evidence`, ); cnt != 0 {
		t.Fatalf("expected 0 evidence rows when sampling off, got %d", cnt)
	}

	// Enable sampling → rows written.
	repo.persistRawEvidence = true
	if err := repo.RecordEvidence(ctx, ev); err != nil {
		t.Fatalf("record evidence (enabled): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM service_evidence`); cnt != 1 {
		t.Fatalf("expected 1 evidence row when sampling on, got %d", cnt)
	}
}

func TestRecordDevice_InsertThenUpdate(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.3"

	// First scan: no device exists → insert minimal row.
	d := scannerv2.DeviceRef{
		IP:    ip,
		Type:  "server",
		Brand: "Dell",
		Fields: map[string]string{
			"open_ports":        "[22,80]",
			"prometheus_url":    "http://10.0.0.3:9090",
			"os":                "linux",
		},
	}
	if err := repo.RecordDevice(ctx, ip, d); err != nil {
		t.Fatalf("record device (insert): %v", err)
	}
	var id int64
	var scanSource, brand, openPorts, promURL, labels string
	if err := repo.db.QueryRow(`SELECT id, scan_source, brand, open_ports, prometheus_url, prometheus_labels FROM devices WHERE ip_address=?`, ip).
		Scan(&id, &scanSource, &brand, &openPorts, &promURL, &labels); err != nil {
		t.Fatalf("query device: %v", err)
	}
	if scanSource != "scanner_v2" {
		t.Errorf("scan_source = %q, want scanner_v2", scanSource)
	}
	if brand != "Dell" {
		t.Errorf("brand = %q, want Dell", brand)
	}
	if openPorts != "[22,80]" {
		t.Errorf("open_ports = %q", openPorts)
	}
	// "os" is an experimental field → folded into prometheus_labels JSON.
	var extra map[string]string
	if err := json.Unmarshal([]byte(labels), &extra); err != nil {
		t.Fatal(err)
	}
	if extra["os"] != "linux" {
		t.Errorf("experimental field 'os' not preserved: %v", extra)
	}

	// Second scan: device exists → update only v2-managed cols, preserve unknown.
	d2 := scannerv2.DeviceRef{
		IP:    ip,
		Type:  "server",
		Brand: "HP", // changed
		Fields: map[string]string{
			"node_exporter_url": "http://10.0.0.3:9100",
		},
	}
	if err := repo.RecordDevice(ctx, ip, d2); err != nil {
		t.Fatalf("record device (update): %v", err)
	}
	var brand2, neURL string
	if err := repo.db.QueryRow(`SELECT brand, node_exporter_url FROM devices WHERE ip_address=?`, ip).Scan(&brand2, &neURL); err != nil {
		t.Fatal(err)
	}
	if brand2 != "HP" {
		t.Errorf("brand not updated: %q", brand2)
	}
	if neURL != "http://10.0.0.3:9100" {
		t.Errorf("node_exporter_url not set: %q", neURL)
	}
}

func TestRecordHeartbeats_InsertAndUpdate(t *testing.T) {
	repo, ctx := newRepo(t, Options{
		DefaultHeartbeatInterval: 30,
		DefaultHeartbeatTimeout:  5,
		DefaultSNMPCommunity:     "public",
		DefaultSNMPOID:           "1.3.6.1.2.1.1.3.0",
	})
	ip := "10.0.0.4"

	// RecordDevice must run first so the IP has a device row.
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "other"}); err != nil {
		t.Fatal(err)
	}

	specs := []scannerv2.HeartbeatSpec{
		{Method: "tcp", Target: ip + ":22"},
		{Method: "icmp", Target: ip},
	}
	if err := repo.RecordHeartbeats(ctx, ip, specs); err != nil {
		t.Fatalf("record heartbeats (insert): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM heartbeat_configs`); cnt != 2 {
		t.Fatalf("expected 2 heartbeat configs, got %d", cnt)
	}

	// Defaults applied: interval 30, timeout 5.
	var interval, timeout int64
	if err := repo.db.QueryRow(`SELECT interval_seconds, timeout_seconds FROM heartbeat_configs WHERE method='tcp'`).Scan(&interval, &timeout); err != nil {
		t.Fatal(err)
	}
	if interval != 30 || timeout != 5 {
		t.Errorf("defaults not applied: interval=%d timeout=%d", interval, timeout)
	}

	// Re-record: same methods → upsert, count unchanged, target updated.
	specs2 := []scannerv2.HeartbeatSpec{
		{Method: "tcp", Target: ip + ":2222", IntervalSeconds: 60},
	}
	if err := repo.RecordHeartbeats(ctx, ip, specs2); err != nil {
		t.Fatalf("record heartbeats (upsert): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM heartbeat_configs`); cnt != 2 {
		t.Errorf("upsert should not add rows, got %d", cnt)
	}
	var target string
	var iv int64
	if err := repo.db.QueryRow(`SELECT target, interval_seconds FROM heartbeat_configs WHERE method='tcp'`).Scan(&target, &iv); err != nil {
		t.Fatal(err)
	}
	if target != ip+":2222" {
		t.Errorf("target not updated: %q", target)
	}
	if iv != 60 {
		t.Errorf("interval not updated: %d", iv)
	}
}

func TestRecordHeartbeats_NoDeviceSkips(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	// No RecordDevice call → no device row → heartbeats skipped gracefully.
	if err := repo.RecordHeartbeats(ctx, "10.0.0.99", []scannerv2.HeartbeatSpec{{Method: "icmp", Target: "10.0.0.99"}}); err != nil {
		t.Fatalf("expected nil error when no device, got %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM heartbeat_configs`); cnt != 0 {
		t.Errorf("expected 0 heartbeats, got %d", cnt)
	}
}

func countRows(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count query failed (%s): %v", q, err)
	}
	return n
}
