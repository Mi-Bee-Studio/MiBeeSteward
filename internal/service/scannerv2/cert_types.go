package scannerv2

// TLSCertRecord is one certificate collected from a TLS handshake. A server's
// chain yields one TLSCertRecord per certificate, distinguished by CertIndex
// (0 = leaf/server cert; 1..N = issuers up the chain). All fields are strings
// or ints to keep persistence and JSON marshaling trivial; empty values mean
// "not applicable / not parsed".
//
// This type crosses layer boundaries:
//   - probe/cert_collector produces it (full-chain + PEM extraction),
//   - handler/tls_collect packages it as a CollectedData,
//   - store/sqlite persists it (RecordTLSCerts),
//   - the orchestrator hands it from handler → repository.
type TLSCertRecord struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	CertIndex int    `json:"cert_index"` // 0 = leaf

	// Identity
	SubjectCN  string `json:"subject_cn"`
	SubjectOrg string `json:"subject_org"`
	Subject    string `json:"subject"` // full RFC 4514 DN
	IssuerCN   string `json:"issuer_cn"`
	IssuerOrg  string `json:"issuer_org"`
	Issuer     string `json:"issuer"`

	// Subject Alternative Names (comma-separated when multiple)
	SanDNS   string `json:"san_dns"`
	SanIP    string `json:"san_ip"`
	SanEmail string `json:"san_email"`

	Serial string `json:"serial"` // decimal string

	// Validity, ISO 8601 UTC (e.g. "2026-07-18T12:34:56Z")
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`

	// Crypto details
	SigAlgorithm      string `json:"sig_algorithm"` // SHA256-RSA, ECDSA-SHA256
	KeyAlgorithm      string `json:"key_algorithm"` // RSA, ECDSA, Ed25519
	KeyBits           int    `json:"key_bits"`      // modulus/curve-order bits
	IsCA              bool   `json:"is_ca"`
	SelfSigned        bool   `json:"self_signed"`
	FingerprintSHA256 string `json:"fingerprint_sha256"` // uppercase hex
	PEM               string `json:"pem"`

	// Handshake metadata (leaf only; zero on chain certs)
	TLSVersion  string `json:"tls_version"` // "TLS 1.3"
	CipherSuite string `json:"cipher_suite"`
	Trusted     bool   `json:"trusted"`

	// Error is set (with at least IP/Port populated) when the handshake failed.
	// An error record is still persisted so the UI can show "we tried this port
	// and could not collect a cert" instead of silently missing the port.
	Error string `json:"error,omitempty"`
}

// TLSCertCollected is the CollectedData produced by TLS-wrapped service
// handlers (https, ldaps, imaps, pop3s, smtps, ftps, ircs, telnets). It bundles
// all certs collected for the service's port (one host:port → one handshake →
// one chain). Implements scannerv2.CollectedData.
type TLSCertCollected struct {
	ServiceName string          `json:"service"` // service name of the triggering handler
	Port        int             `json:"port"`
	Certs       []TLSCertRecord `json:"certs"`
}

// Service returns the canonical service name (matches the handler).
func (c TLSCertCollected) Service() string { return c.ServiceName }
