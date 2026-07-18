package store

import (
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
