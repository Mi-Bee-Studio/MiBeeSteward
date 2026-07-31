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

// seedDeviceRow inserts a device row directly (bypassing RecordDevice, which no
// longer creates identities). Used by tests that need a pre-existing row before
// exercising RecordDevice's enrichment path or RecordHeartbeats/RecordNeighbors.
// Returns the inserted row id.
func seedDeviceRow(t *testing.T, db *sql.DB, ip, mac string, networkID sql.NullInt64) int64 {
	t.Helper()
	now := time.Now().UTC()
	res, err := db.Exec(`
		INSERT INTO devices (name, type, ip_address, mac_address, status, scan_source,
		                     scan_attributes, network_id, first_seen, last_seen,
		                     last_scanned_at, created_at, updated_at)
		VALUES (?, 'other', ?, ?, 'online', 'scanner_v2', '{}', ?, ?, ?, ?, ?, ?)`,
		ip, ip, mac, networkID, now, now, now, now, now)
	if err != nil {
		t.Fatalf("seed device row: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
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

	// RecordDevice no longer creates identities; seed the row first (the runner
	// is the identity creator in production).
	seedDeviceRow(t, repo.db, ip, "", sql.NullInt64{})

	// First RecordDevice: enrich the seeded row with scan data.
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
		t.Fatalf("record device (enrich): %v", err)
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

	// Seed a device row (RecordDevice no longer creates identities).
	seedDeviceRow(t, repo.db, ip, "", sql.NullInt64{})

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

// TestIsLocallyAdministeredMAC covers the locally-administered (U/L) bit check
// (IEEE 802 / RFC 7042). The U/L bit is bit 1 of the first octet (0x02); in a
// canonical MAC its value rides in the LOW nibble of the first octet (mac[1]).
// Inputs are NormalizeMAC's canonical output. Note this is a NEUTRAL factual
// bit: when set it means "locally administered" — it CANNOT, by itself, tell
// privacy randomization (iOS/Android) from a locally fixed setting (soft-router,
// hypervisor, manual). The test asserts the bit value only, not any "randomized"
// interpretation.
func TestIsLocallyAdministeredMAC(t *testing.T) {
	cases := []struct {
		name string
		mac  string
		want bool
	}{
		// U/L set (second hex digit of first octet has bit 0x2): 2,3,6,7,a,b,e,f
		{"locally administered 02", "02:11:22:33:44:55", true},
		{"locally administered 1a", "1a:bb:cc:dd:ee:ff", true},
		{"locally administered 6e", "6e:bb:cc:dd:ee:ff", true},
		{"locally administered 3b", "3b:bb:cc:dd:ee:ff", true},
		{"locally administered 5f", "5f:bb:cc:dd:ee:ff", true}, // low nibble f (1111) & 2 = true
		// U/L clear (low nibble 0,1,4,5,8,9,c,d): 0,1,4,5,8,9,c,d — universally administered
		{"Hikvision universal OUI", "bc:ad:28:11:22:33", false}, // c -> 12 & 2 = 0
		{"universal 00", "00:1a:11:22:33:44", false},
		{"universal 08", "08:00:27:aa:bb:cc", false}, // VirtualBox OUI, universally administered
		{"universal 44", "44:65:0d:aa:bb:cc", false},
		// Edge cases: non-canonical / empty must be false (never panic).
		{"empty", "", false},
		{"too short", "aa:bb", false},
		{"uppercase (non-canonical)", "AA:BB:CC:DD:EE:FF", false}, // expects canonical lowercase
		{"non-hex", "gg:bb:cc:dd:ee:ff", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsLocallyAdministeredMAC(c.mac); got != c.want {
				t.Errorf("IsLocallyAdministeredMAC(%q) = %v, want %v", c.mac, got, c.want)
			}
		})
	}
}

// TestIsMulticastMAC covers the multicast bit check (bit 0 of the first octet,
// 0x01). A unicast device should never source frames from a multicast MAC.
func TestIsMulticastMAC(t *testing.T) {
	cases := []struct {
		name string
		mac  string
		want bool
	}{
		// multicast set (low nibble odd): 1,3,5,7,9,b,d,f
		{"multicast 01", "01:00:5e:00:00:01", true}, // classic IPv4 multicast
		{"multicast 33", "33:33:00:00:00:01", true}, // IPv6 multicast
		{"multicast b3", "b3:bb:cc:dd:ee:ff", true},
		// unicast (low nibble even): 0,2,4,6,8,a,c,e
		{"unicast bc", "bc:ad:28:11:22:33", false},
		{"unicast 02", "02:11:22:33:44:55", false}, // LAA but unicast
		{"empty", "", false},
		{"too short", "aa", false},
		{"non-hex", "zz:bb:cc:dd:ee:ff", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsMulticastMAC(c.mac); got != c.want {
				t.Errorf("IsMulticastMAC(%q) = %v, want %v", c.mac, got, c.want)
			}
		})
	}
}

// TestRecordDevice_DoesNotCreateIdentity verifies the single-writer contract:
// RecordDevice ENRICHES existing rows but never CREATES a device identity (no
// INSERT). Device creation is the sole responsibility of runner.applyDeviceBridge.
// This is what eliminates the dual-write fissure — there is only one identity
// creator, so identity rules (MAC-primary, replacement) live in exactly one place.
//
// The MAC-primary-dedup, network-partitioning, MAC-fills-on-rescan, and
// device-replacement semantics these tests previously asserted at the store
// layer are now covered by runner/device_bridge_test.go (the single writer).
func TestRecordDevice_DoesNotCreateIdentity(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	ip := "192.168.63.20"
	mac := "aa:bb:cc:dd:ee:02"

	// No device row exists yet → RecordDevice is a no-op (must NOT insert).
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{
		IP: ip, Type: "embedded", Brand: "Synology",
		Fields: map[string]string{"mac": mac},
	}); err != nil {
		t.Fatalf("record device on empty db: %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM devices`); cnt != 0 {
		t.Fatalf("RecordDevice created a row (%d) — it must NOT create identities", cnt)
	}

	// Now seed a row (as the runner would) and confirm RecordDevice enriches it.
	seedDeviceRow(t, repo.db, ip, "", sql.NullInt64{Int64: 1, Valid: true})
	if err := repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{
		IP: ip, Type: "nas", Brand: "Synology",
		Fields: map[string]string{"mac": mac},
	}); err != nil {
		t.Fatalf("record device (enrich): %v", err)
	}
	// Still exactly one row (enriched, not duplicated).
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM devices WHERE ip_address=?`, ip); cnt != 1 {
		t.Fatalf("expected 1 row after enrich, got %d", cnt)
	}
	var brand, devMAC string
	if err := repo.db.QueryRow(`SELECT brand, mac_address FROM devices WHERE ip_address=?`, ip).Scan(&brand, &devMAC); err != nil {
		t.Fatal(err)
	}
	if brand != "Synology" {
		t.Errorf("brand not enriched: %q", brand)
	}
	if devMAC != mac {
		t.Errorf("mac not enriched: %q", devMAC)
	}
}
