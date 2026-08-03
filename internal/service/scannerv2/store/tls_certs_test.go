package store

import (
	"database/sql"
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

// TestRecordTLSCerts_ReplacePerPort verifies the delete+insert semantics: a
// second call with the same (ip, port) replaces the prior chain rather than
// appending, while certs on a different port for the same host survive.
func TestRecordTLSCerts_ReplacePerPort(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.1"

	// First scan: port 443 has a single self-signed leaf; port 636 has a leaf.
	first := []scannerv2.TLSCertRecord{
		{IP: ip, Port: 443, CertIndex: 0, SubjectCN: "old.example.com", PEM: "old-leaf"},
		{IP: ip, Port: 636, CertIndex: 0, SubjectCN: "ldaps.example.com", PEM: "ldaps-leaf"},
	}
	if err := repo.RecordTLSCerts(ctx, ip, first); err != nil {
		t.Fatalf("RecordTLSCerts (first): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_tls_certs WHERE ip=?`, ip); cnt != 2 {
		t.Fatalf("expected 2 rows after first call, got %d", cnt)
	}

	// Second scan: port 443 rotated to a fresh 2-cert chain; port 636 NOT in
	// this batch (a partial scan). The 443 rows must be replaced; the 636 row
	// must survive untouched.
	second := []scannerv2.TLSCertRecord{
		{IP: ip, Port: 443, CertIndex: 0, SubjectCN: "new.example.com", PEM: "new-leaf"},
		{IP: ip, Port: 443, CertIndex: 1, SubjectCN: "issuer-ca.example.com", PEM: "issuer"},
	}
	if err := repo.RecordTLSCerts(ctx, ip, second); err != nil {
		t.Fatalf("RecordTLSCerts (second): %v", err)
	}
	// 443: 2 rows (replaced). 636: 1 row (untouched). Total: 3.
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_tls_certs WHERE ip=? AND port=443`, ip); cnt != 2 {
		t.Errorf("port 443 expected 2 rows after replace, got %d", cnt)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_tls_certs WHERE ip=? AND port=636`, ip); cnt != 1 {
		t.Errorf("port 636 expected 1 row (untouched by partial scan), got %d", cnt)
	}

	// The replaced 443 leaf must be the NEW one, not the old.
	var leafCN string
	if err := repo.db.QueryRow(
		`SELECT subject_cn FROM host_tls_certs WHERE ip=? AND port=443 AND cert_index=0`, ip,
	).Scan(&leafCN); err != nil {
		t.Fatal(err)
	}
	if leafCN != "new.example.com" {
		t.Errorf("443 leaf SubjectCN = %q, want new.example.com (old should be replaced)", leafCN)
	}
}

// TestRecordTLSCerts_PersistsErrorRow asserts that a record carrying only an
// Error (handshake failed) still lands in the table — the UI uses these to
// distinguish "we tried this port" from "port not scanned".
func TestRecordTLSCerts_PersistsErrorRow(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.2"

	rec := []scannerv2.TLSCertRecord{
		{IP: ip, Port: 8443, Error: "tls: handshake failure"},
	}
	if err := repo.RecordTLSCerts(ctx, ip, rec); err != nil {
		t.Fatalf("RecordTLSCerts: %v", err)
	}
	var errStr, cn string
	if err := repo.db.QueryRow(
		`SELECT error, subject_cn FROM host_tls_certs WHERE ip=? AND port=8443`, ip,
	).Scan(&errStr, &cn); err != nil {
		t.Fatal(err)
	}
	if errStr != "tls: handshake failure" {
		t.Errorf("error column = %q, want handshake failure text", errStr)
	}
	if cn != "" {
		t.Errorf("error row subject_cn = %q, want empty", cn)
	}
}

// TestRecordTLSCerts_ReplaceAcrossUUIDResolution is the TLS-side mirror of
// TestRecordServices_ReplaceAcrossUUIDResolution. It guards the same #129
// regression class on host_tls_certs: the first scan lands rows before the
// device identity exists (device_uuid=”), and once the runner creates the
// device row between scans the uuid resolves. The DELETE must key on IP+port
// (not the now-resolved uuid) or the device_uuid=” row from scan 1 would
// survive and the cert chain would appear stale/duplicated. Unlike
// host_services, host_tls_certs has no UNIQUE constraint on (ip,port), so the
// failure mode is accumulating duplicate stale rows rather than a silent
// INSERT collision — this test catches both shapes.
func TestRecordTLSCerts_ReplaceAcrossUUIDResolution(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.5"

	// Scan 1: no device row yet → resolveDeviceUUID returns "". The 443 leaf
	// lands with device_uuid=''. Mirrors first discovery via the orchestrator.
	if err := repo.RecordTLSCerts(ctx, ip, []scannerv2.TLSCertRecord{
		{IP: ip, Port: 443, CertIndex: 0, SubjectCN: "old.example.com", PEM: "old-leaf"},
	}); err != nil {
		t.Fatalf("RecordTLSCerts (scan 1): %v", err)
	}
	// Sanity: the row landed with empty device_uuid.
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_tls_certs WHERE ip=? AND device_uuid=''`, ip); cnt != 1 {
		t.Fatalf("scan 1: expected 1 row with empty device_uuid, got %d", cnt)
	}

	// Device row created between scans (runner.applyDeviceBridge → createDevice
	// generates a real uuid). Seed one to mirror that.
	const devUUID = "dev-uuid-tls-aaaaaaaa"
	seedDeviceRowWithUUID(t, repo.db, ip, "aa:bb:cc:dd:ee:ff", sql.NullInt64{}, devUUID)

	// Scan 2: 443 cert rotated. uuid now resolves → the device_uuid='' row from
	// scan 1 must be removed (DELETE keyed on ip+port), not left behind.
	if err := repo.RecordTLSCerts(ctx, ip, []scannerv2.TLSCertRecord{
		{IP: ip, Port: 443, CertIndex: 0, SubjectCN: "new.example.com", PEM: "new-leaf"},
	}); err != nil {
		t.Fatalf("RecordTLSCerts (scan 2): %v", err)
	}

	// Exactly ONE 443 row — not two — carrying scan-2 data + the resolved uuid.
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_tls_certs WHERE ip=? AND port=443`, ip); cnt != 1 {
		t.Fatalf("scan 2: expected 1 row for 443, got %d (uuid-transition left a stale duplicate)", cnt)
	}
	var cn, rowUUID string
	if err := repo.db.QueryRow(
		`SELECT subject_cn, device_uuid FROM host_tls_certs WHERE ip=? AND port=443 AND cert_index=0`, ip,
	).Scan(&cn, &rowUUID); err != nil {
		t.Fatal(err)
	}
	if cn != "new.example.com" {
		t.Errorf("scan 2 data did not win: subject_cn=%q, want %q (scan-1 row survived the uuid transition)", cn, "new.example.com")
	}
	if rowUUID != devUUID {
		t.Errorf("scan 2 row device_uuid=%q, want %q (heal did not run)", rowUUID, devUUID)
	}
}

// TestRecordTLSCerts_EmptyInputIsNoop guards against a regression where an
// empty slice would DELETE everything for the IP (it shouldn't — there's
// nothing to delete because no port is in the batch).
func TestRecordTLSCerts_EmptyInputIsNoop(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.3"

	// Seed one row.
	if err := repo.RecordTLSCerts(ctx, ip, []scannerv2.TLSCertRecord{
		{IP: ip, Port: 443, CertIndex: 0, SubjectCN: "seed"},
	}); err != nil {
		t.Fatal(err)
	}

	// Empty call: must NOT delete the seed.
	if err := repo.RecordTLSCerts(ctx, ip, nil); err != nil {
		t.Fatalf("RecordTLSCerts (nil): %v", err)
	}
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM host_tls_certs WHERE ip=?`, ip); cnt != 1 {
		t.Errorf("empty call should not delete prior rows, got count=%d", cnt)
	}
}
