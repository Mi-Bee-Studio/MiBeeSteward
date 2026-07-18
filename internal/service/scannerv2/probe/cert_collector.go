package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// CollectCertChain performs a TLS handshake against host:port and extracts the
// server's full certificate chain (leaf + issuers) plus the negotiated TLS
// version/cipher and a best-effort trust verdict. It is the single source of
// truth for cert collection: the TLSProbe uses it for evidence, and the
// TLS-wrapped service handlers use it for full persistence.
//
// The function is read-only and never validates the chain (InsecureSkipVerify
// is set so self-signed embedded devices can still be inventoried). The trust
// verdict is computed separately against the system root pool — it informs the
// UI's "trusted" badge but does NOT gate collection.
//
// Returns a TLSCertRecord slice (one per cert) on success. On failure (port
// closed, not TLS, handshake error) returns a single-element slice carrying
// only IP/Port/Error — callers persist it so the UI can show "tried this port,
// could not collect" instead of silently omitting the port.
func CollectCertChain(ctx context.Context, ip string, port int, timeout time.Duration) []scannerv2.TLSCertRecord {
	if timeout <= 0 {
		timeout = tlsProbeTimeout
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Two-pass config: one for collection (InsecureSkipVerify) and one for the
	// trust verdict. We can't do both in a single handshake because
	// InsecureSkipVerify short-circuits verification. So: collect with skip,
	// then attempt a verifying handshake against just the leaf for the verdict.
	state, err := dialTLS(dctx, addr, timeout, true /* skip verify */)
	if err != nil {
		return []scannerv2.TLSCertRecord{{
			IP: ip, Port: port, Error: truncateErr(err.Error()),
		}}
	}
	if len(state.PeerCertificates) == 0 {
		return []scannerv2.TLSCertRecord{{
			IP: ip, Port: port, Error: "tls handshake succeeded but no certificates returned",
		}}
	}

	trusted := chainIsTrusted(dctx, addr, timeout, state.PeerCertificates[0])
	versionStr := tlsVersionString(state.Version)
	cipherStr := tls.CipherSuiteName(state.CipherSuite) //nolint:staticcheck // CipherSuiteName is fine

	out := make([]scannerv2.TLSCertRecord, 0, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		rec := buildCertRecord(ip, port, i, cert)
		// Handshake metadata applies to every row of this port's record so the
		// UI can show it per port (the value is the same for all certs from one
		// handshake). The leaf's TLSVersion/CipherSuite are the canonical ones;
		// other rows inherit them for UI simplicity.
		rec.TLSVersion = versionStr
		rec.CipherSuite = cipherStr
		rec.Trusted = trusted
		out = append(out, rec)
	}
	return out
}

// dialTLS performs the TLS dial with a context-aware net dialer. skipVerify
// toggles InsecureSkipVerify (true for collection, false for the trust check).
func dialTLS(ctx context.Context, addr string, timeout time.Duration, skipVerify bool) (tls.ConnectionState, error) {
	dialer := tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: skipVerify, //nolint:gosec // inventory, not auth
			MinVersion:         tls.VersionTLS10,
		},
		NetDialer: &net.Dialer{Timeout: timeout},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, fmt.Errorf("dialer returned non-TLS connection: %T", conn)
	}
	return tlsConn.ConnectionState(), nil
}

// chainIsTrusted runs a verifying handshake against just the leaf's ServerName
// (empty → IP-based). Used only for the "trusted" badge; failures here do NOT
// affect collection. Best-effort: any error → not trusted.
func chainIsTrusted(ctx context.Context, addr string, timeout time.Duration, leaf *x509.Certificate) bool {
	// Use the leaf's first DNS SAN (or CN) as SNI so name verification matches.
	serverName := ""
	if len(leaf.DNSNames) > 0 {
		serverName = leaf.DNSNames[0]
	} else if leaf.Subject.CommonName != "" && looksLikeHostname(leaf.Subject.CommonName) {
		serverName = leaf.Subject.CommonName
	}
	dialer := tls.Dialer{
		Config: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS10,
		},
		NetDialer: &net.Dialer{Timeout: timeout},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// buildCertRecord maps a *x509.Certificate into a TLSCertRecord. All string
// coercion, PEM encoding, and fingerprinting live here so the call site is a
// one-liner.
func buildCertRecord(ip string, port, idx int, cert *x509.Certificate) scannerv2.TLSCertRecord {
	rec := scannerv2.TLSCertRecord{
		IP:        ip,
		Port:      port,
		CertIndex: idx,

		SubjectCN:  cert.Subject.CommonName,
		SubjectOrg: strings.Join(cert.Subject.Organization, ", "),
		Subject:    cert.Subject.String(),
		IssuerCN:   cert.Issuer.CommonName,
		IssuerOrg:  strings.Join(cert.Issuer.Organization, ", "),
		Issuer:     cert.Issuer.String(),

		SanDNS:   strings.Join(cert.DNSNames, ", "),
		SanIP:    strings.Join(ipStrings(cert.IPAddresses), ", "),
		SanEmail: strings.Join(cert.EmailAddresses, ", "),

		Serial:     cert.SerialNumber.String(),
		NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
		SigAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:       cert.IsCA,
		SelfSigned: cert.Subject.String() == cert.Issuer.String(),
	}

	// Key algorithm + bit size. RSA: N.BitLen; ECDSA: curve.Params().BitSize;
	// Ed25519: 256 bits by spec. Anything else: leave 0 (see publicKeyBits).
	rec.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
	rec.KeyBits = publicKeyBits(cert)

	// SHA-256 fingerprint of the DER (uppercase hex, colon-free — nmap-style is
	// colon-separated; we keep it dense to match the column's "short string"
	// character and render with monospace in the UI).
	sum := sha256.Sum256(cert.Raw)
	rec.FingerprintSHA256 = strings.ToUpper(hex.EncodeToString(sum[:]))

	// PEM (text, header-guarded). Never fails for a valid cert.Raw.
	if block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); block != nil {
		rec.PEM = string(block)
	}
	return rec
}

// ipStrings formats a []net.IP into canonical string form.
func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// tlsVersionString maps a tls.Version constant to a human label. Returns "" for
// unrecognized versions (shouldn't happen post-handshake).
func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionSSL30:
		return "SSL 3.0"
	}
	return ""
}

// looksLikeHostname is a cheap check that a CN looks like a DNS name (contains a
// dot, no spaces) rather than a person/org name. Used to decide whether SNI can
// be set to the CN for the trust check.
func looksLikeHostname(s string) bool {
	return strings.Contains(s, ".") && !strings.ContainsAny(s, " ,")
}

// truncateErr bounds error strings so a verbose TLS error (which can run
// hundreds of chars with the full cert chain dump) doesn't blow up the column.
const maxErrLen = 240

func truncateErr(s string) string {
	s = strings.TrimSpace(s)
	// Collapse the multi-line "x509: ..." chain dump into the first line.
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > maxErrLen {
		s = s[:maxErrLen-3] + "..."
	}
	return s
}
