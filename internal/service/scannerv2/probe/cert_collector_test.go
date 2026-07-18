package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// startTLSServer launches a TLS listener on a random localhost port using a
// freshly-minted self-signed cert with the given SAN DNS names. Returns the
// listener (close with .Close()), the parsed cert (for assertions), and the
// port it's bound to.
func startTLSServer(t *testing.T, sanDNS []string) (net.Listener, *x509.Certificate, int) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(202607181),
		Subject: pkix.Name{
			CommonName:   "test-leaf.example.com",
			Organization: []string{"MiBee Test Org"},
		},
		DNSNames:                sanDNS,
		NotBefore:               time.Now().Add(-time.Hour),
		NotAfter:                time.Now().Add(90 * 24 * time.Hour), // 90 days out
		KeyUsage:                x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:             []net.IP{net.IPv4(127, 0, 0, 1)},
		BasicConstraintsValid:   true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Echo server: accept, complete the handshake, then close. CollectCertChain
	// only needs the handshake to complete; it doesn't send app data.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
				// Hold the conn open briefly so the client reads ConnectionState
				// before the server-side close tears it down.
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()
	return ln, cert, ln.Addr().(*net.TCPAddr).Port
}

// sha256HexUpper matches the encoding used in cert_collector.go (uppercase hex,
// no separators) so the test can assert against the cert the server presented.
func sha256HexUpper(raw []byte) string {
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// TestCollectCertChain_Success exercises the happy path: a self-signed TLS
// server should produce one cert record (no chain beyond the leaf), with all
// the typed fields populated. The fingerprint, subject, issuer, and SAN are
// checked against the cert the server actually presented.
func TestCollectCertChain_Success(t *testing.T) {
	ln, srvCert, port := startTLSServer(t, []string{"test-leaf.example.com", "alt.example.com"})
	defer ln.Close()

	records := CollectCertChain(context.Background(), "127.0.0.1", port, 2*time.Second)
	if len(records) != 1 {
		t.Fatalf("expected 1 record (leaf only, self-signed), got %d", len(records))
	}
	rec := records[0]
	if rec.Error != "" {
		t.Fatalf("unexpected error: %q", rec.Error)
	}
	if rec.CertIndex != 0 {
		t.Errorf("CertIndex = %d, want 0", rec.CertIndex)
	}
	if rec.SubjectCN != "test-leaf.example.com" {
		t.Errorf("SubjectCN = %q, want test-leaf.example.com", rec.SubjectCN)
	}
	if rec.SubjectOrg != "MiBee Test Org" {
		t.Errorf("SubjectOrg = %q, want MiBee Test Org", rec.SubjectOrg)
	}
	// Self-signed → subject == issuer.
	if !rec.SelfSigned {
		t.Error("SelfSigned = false, want true (subject == issuer for self-signed)")
	}
	if rec.IssuerCN != "test-leaf.example.com" {
		t.Errorf("IssuerCN = %q, want test-leaf.example.com (self-signed)", rec.IssuerCN)
	}
	// SAN: both DNS names present + the loopback IP.
	if rec.SanDNS == "" {
		t.Error("SanDNS empty, want both DNS SANs")
	}
	if !strings.Contains(rec.SanDNS, "alt.example.com") {
		t.Errorf("SanDNS = %q, missing alt.example.com", rec.SanDNS)
	}
	if rec.SanIP == "" {
		t.Error("SanIP empty, want 127.0.0.1")
	}
	// Key: ECDSA P-256 → 256 bits.
	if rec.KeyAlgorithm != "ECDSA" {
		t.Errorf("KeyAlgorithm = %q, want ECDSA", rec.KeyAlgorithm)
	}
	if rec.KeyBits != 256 {
		t.Errorf("KeyBits = %d, want 256 (P-256)", rec.KeyBits)
	}
	// Fingerprint: must match SHA-256 of the DER we minted.
	wantFP := sha256HexUpper(srvCert.Raw)
	if rec.FingerprintSHA256 != wantFP {
		t.Errorf("FingerprintSHA256 = %q, want %q", rec.FingerprintSHA256, wantFP)
	}
	// PEM must contain the cert.
	if rec.PEM == "" {
		t.Fatal("PEM empty")
	}
	if !strings.Contains(rec.PEM, "BEGIN CERTIFICATE") {
		t.Errorf("PEM missing BEGIN marker: %q", rec.PEM[:40])
	}
	// TLS handshake metadata: leaf row should carry version + cipher.
	if rec.TLSVersion == "" {
		t.Error("TLSVersion empty on leaf, want handshake version")
	}
	if rec.CipherSuite == "" {
		t.Error("CipherSuite empty on leaf, want negotiated cipher")
	}
}

// TestCollectCertChain_ClosedPort asserts the failure path: a port nothing is
// listening on yields a single error record carrying only IP/Port/Error.
func TestCollectCertChain_ClosedPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	records := CollectCertChain(context.Background(), "127.0.0.1", port, 1*time.Second)
	if len(records) != 1 {
		t.Fatalf("expected 1 error record, got %d", len(records))
	}
	rec := records[0]
	if rec.Error == "" {
		t.Error("expected non-empty Error on closed-port dial")
	}
	if rec.Port != port {
		t.Errorf("Port = %d, want %d (error record should still carry the port)", rec.Port, port)
	}
	if rec.SubjectCN != "" || rec.PEM != "" {
		t.Error("error record should have empty cert fields")
	}
}

// TestCollectCertChain_NotTLS asserts the failure path: a plaintext TCP server
// (no TLS) yields a single error record. This is the key guarantee behind the
// design — non-TLS ports produce an error record, not an invalid handshake.
func TestCollectCertChain_NotTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Plaintext greeting — TLS handshake from the client will fail
				// with a "tls: first record does not look like a TLS handshake"
				// style error.
				_, _ = c.Write([]byte("SSH-2.0-plaintext\r\n"))
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	records := CollectCertChain(context.Background(), "127.0.0.1", port, 2*time.Second)
	if len(records) != 1 {
		t.Fatalf("expected 1 error record, got %d", len(records))
	}
	if records[0].Error == "" {
		t.Error("expected non-empty Error when dialing a plaintext port")
	}
}

// Compile-time check that scannerv2.TLSCertRecord is used in this test file
// (guards against accidental removal of the import once other tests evolve).
var _ = scannerv2.TLSCertRecord{}
