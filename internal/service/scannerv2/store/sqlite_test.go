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
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM service_evidence`); cnt != 0 {
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
			"open_ports":     "[22,80]",
			"prometheus_url": "http://10.0.0.3:9090",
			"os":             "linux",
		},
	}
	if err := repo.RecordDevice(ctx, ip, d); err != nil {
		t.Fatalf("record device (insert): %v", err)
	}
	var id int64
	var scanSource, brand, openPorts, promURL, scanAttrs string
	if err := repo.db.QueryRow(`SELECT id, scan_source, brand, open_ports, prometheus_url, scan_attributes FROM devices WHERE ip_address=?`, ip).
		Scan(&id, &scanSource, &brand, &openPorts, &promURL, &scanAttrs); err != nil {
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
	// "os" is a discovery field → folded into scan_attributes.extras JSON
	// (previously prometheus_labels; moved when scan_attributes was added).
	var attr map[string]any
	if err := json.Unmarshal([]byte(scanAttrs), &attr); err != nil {
		t.Fatalf("unmarshal scan_attributes: %v (raw=%q)", err, scanAttrs)
	}
	extras, _ := attr["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("scan_attributes.extras missing or wrong type: %v", attr)
	}
	if extras["os"] != "linux" {
		t.Errorf("experimental field 'os' not preserved in scan_attributes.extras: %v", extras)
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

// TestNormalizeMAC verifies the canonicalization used as the device-identity key
// across the store and runner upsert paths. Both must agree on the MAC form or
// a device stored as "AA-BB..." would never match "aa:bb...".
func TestNormalizeMAC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"},
		{"aabbccddeeff", "aa:bb:cc:dd:ee:ff"},
		{"AABB.CCDD.EEFF", "aa:bb:cc:dd:ee:ff"},
		{"  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff"},
		{"", ""},
		{"not-a-mac", ""},
		{"aa:bb:cc:dd:ee", ""},    // too short
		{"aa:bb:cc:dd:ee:gg", ""}, // non-hex
	}
	for _, c := range cases {
		if got := NormalizeMAC(c.in); got != c.want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRecordDevice_MACPrimaryDedup verifies the MAC-primary identity rule: a
// device observed at two different IPs with the SAME MAC resolves to a single
// asset row (roaming / re-DHCP / seen on two LANs). The row's ip stays the
// first-seen value (updated only when empty) and mac_address is set.
func TestRecordDevice_MACPrimaryDedup(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	mac := "AA:BB:CC:DD:EE:01"

	// First sighting: 192.168.63.10, MAC aa:bb:...
	d1 := scannerv2.DeviceRef{
		IP: "192.168.63.10", Type: "camera",
		Fields: map[string]string{"mac": mac},
	}
	if err := repo.RecordDevice(ctx, "192.168.63.10", d1); err != nil {
		t.Fatalf("record (1): %v", err)
	}

	// Second sighting: DIFFERENT IP (roamed to 62 subnet), SAME MAC.
	d2 := scannerv2.DeviceRef{
		IP: "192.168.62.10", Type: "camera",
		Fields: map[string]string{"mac": mac},
	}
	if err := repo.RecordDevice(ctx, "192.168.62.10", d2); err != nil {
		t.Fatalf("record (2): %v", err)
	}

	// Exactly ONE device row — MAC matched globally, not inserted twice.
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM devices WHERE mac_address=?`, NormalizeMAC(mac)); cnt != 1 {
		t.Fatalf("expected 1 row for roaming MAC, got %d", cnt)
	}
}

// TestRecordDevice_NetworkPartitioning verifies the no-MAC fallback identity:
// (ip, network_id). The same IP on two different networks is two distinct
// devices; the same IP + same network updates the existing row.
func TestRecordDevice_NetworkPartitioning(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1}) // LAN-A (network 1)
	ip := "10.0.0.1"

	// LAN-A sees 10.0.0.1 (no MAC).
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "router"}); err != nil {
		t.Fatalf("record lanA: %v", err)
	}

	// Simulate LAN-B (network 2) on the SAME underlying DB: a second repo with
	// NetworkID=2. Same IP, no MAC → must be a separate row.
	repoB := NewSQLiteRepository(repo.db, Options{NetworkID: 2}, nil)
	if err := repoB.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "router"}); err != nil {
		t.Fatalf("record lanB: %v", err)
	}

	// Two rows: one per (ip, network).
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM devices WHERE ip_address=?`, ip); cnt != 2 {
		t.Fatalf("expected 2 partitioned rows for same IP different network, got %d", cnt)
	}

	// LAN-A re-scans the same IP + same network → UPDATE, not insert (still 2 rows).
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "router", Brand: "Mikrotik"}); err != nil {
		t.Fatalf("record lanA rescan: %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM devices WHERE ip_address=?`, ip); cnt != 2 {
		t.Fatalf("expected 2 rows after same-network rescan (update, not insert), got %d", cnt)
	}
	// The LAN-A row got the brand enrichment.
	var brand string
	if err := repo.db.QueryRow(`SELECT brand FROM devices WHERE ip_address=? AND network_id=1`, ip).Scan(&brand); err != nil {
		t.Fatal(err)
	}
	if brand != "Mikrotik" {
		t.Errorf("LAN-A row brand = %q, want Mikrotik", brand)
	}
}

// TestRecordDevice_LegacyNullNetwork verifies the single-instance default path:
// networkID=0 (NULL) → devices match by (ip, network_id IS NULL). A rescan of
// the same IP updates the existing row rather than creating duplicates.
func TestRecordDevice_LegacyNullNetwork(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 0}) // unresolved → NULL
	ip := "192.168.1.50"

	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "nas"}); err != nil {
		t.Fatalf("record (1): %v", err)
	}
	// Rescan same IP → update, still one row.
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "nas", Brand: "Synology"}); err != nil {
		t.Fatalf("record (2): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM devices WHERE ip_address=? AND network_id IS NULL`, ip); cnt != 1 {
		t.Fatalf("expected 1 legacy NULL-network row after rescan, got %d", cnt)
	}
}

// TestRecordDevice_MACFillsOnRescan verifies that a device first seen WITHOUT a
// MAC (matched by ip+network) gets its mac_address filled on a later scan that
// resolves the MAC (e.g. after an ARP walk), and subsequent scans then key off
// the MAC globally.
func TestRecordDevice_MACFillsOnRescan(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	ip := "192.168.63.20"

	// First scan: no MAC → row created, mac_address empty.
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "embedded"}); err != nil {
		t.Fatalf("record (1): %v", err)
	}
	var mac string
	if err := repo.db.QueryRow(`SELECT mac_address FROM devices WHERE ip_address=?`, ip).Scan(&mac); err != nil {
		t.Fatal(err)
	}
	if mac != "" {
		t.Fatalf("expected empty mac after first scan, got %q", mac)
	}

	// Second scan: MAC resolved → existing row updated, mac_address filled.
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{
		IP: ip, Type: "embedded",
		Fields: map[string]string{"mac": "AA-BB-CC-DD-EE-02"},
	}); err != nil {
		t.Fatalf("record (2): %v", err)
	}
	if err := repo.db.QueryRow(`SELECT mac_address FROM devices WHERE ip_address=?`, ip).Scan(&mac); err != nil {
		t.Fatal(err)
	}
	if mac != "aa:bb:cc:dd:ee:02" {
		t.Errorf("mac_address not filled/normalized: got %q", mac)
	}
}
