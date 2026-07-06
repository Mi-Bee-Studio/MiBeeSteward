package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// tlsProbeTimeout bounds the TLS handshake + cert read. Short because we only
// want the cert chain, not a full session.
const tlsProbeTimeout = 4 * time.Second

// tlsProbePorts are the ports we attempt a TLS handshake on for cert
// inspection. 443/8443 are the obvious ones; we also try a few well-known
// TLS-speaking admin ports.
var tlsProbePorts = map[int]bool{
	443:  true,
	8443: true,
	9443: true,
	4443: true,
}

// TLSProbe dials the well-known TLS ports and reads the server's certificate
// chain. The certificate's Subject CN, Issuer CN, and SAN DNS names are a rich
// source of identifying signal: CN often contains a hostname or vendor domain
// (e.g. "*.hikvision.com"), and the issuer can identify a self-signed embedded
// device vs. a public-CA-validated server.
//
// The probe is read-only and does not validate the chain (we set
// InsecureSkipVerify so we can inventory self-signed devices).
//
// Name: "active:tls".
type TLSProbe struct{}

// NewTLSProbe returns a TLS cert-inspection probe.
func NewTLSProbe() *TLSProbe { return &TLSProbe{} }

func (p *TLSProbe) Name() string { return "active:tls" }

// Probe attempts a TLS handshake on each candidate port and, on success, emits
// a "tls" evidence with the leaf cert's CN/Issuer/SAN. Closed ports or non-TLS
// services contribute no evidence.
func (p *TLSProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	timeout := tlsProbeTimeout
	if hint.Timeout > 0 && hint.Timeout < timeout {
		timeout = hint.Timeout
	}
	var evs []scannerv2.Evidence
	for port := range tlsProbePorts {
		select {
		case <-ctx.Done():
			return evs, ctx.Err()
		default:
		}
		if ev := p.dialOne(ctx, ip, port, timeout); ev != nil {
			evs = append(evs, *ev)
		}
	}
	return evs, nil
}

// dialOne performs one TLS handshake and extracts cert fields. Returns nil on
// any failure (port closed, not TLS, handshake error).
func (p *TLSProbe) dialOne(ctx context.Context, ip string, port int, timeout time.Duration) *scannerv2.Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// tls.Dial doesn't take a context in stdlib; use DialContext via a Dialer
	// so the per-port attempt respects cancellation.
	dialer := tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // inventory, not auth
		},
		NetDialer: &net.Dialer{Timeout: timeout},
	}
	conn, err := dialer.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	raw := map[string]string{
		"subject_cn":  leaf.Subject.CommonName,
		"issuer_cn":   leaf.Issuer.CommonName,
		"issuer_org":  strings.Join(leaf.Issuer.Organization, ", "),
		"san_dns":     strings.Join(leaf.DNSNames, ", "),
		"san_ip":      strings.Join(sanIPStrings(leaf.IPAddresses), ", "),
		"serial":      leaf.SerialNumber.String(),
		"self_signed": boolStr(certIsSelfSigned(leaf)),
	}
	for k, v := range raw {
		if v == "" {
			delete(raw, k)
		}
	}
	if len(raw) == 0 {
		return nil
	}
	return &scannerv2.Evidence{
		Source:     "active:tls",
		Kind:       "tls",
		IP:         ip,
		Port:       port,
		Protocol:   "tcp",
		RawData:    raw,
		Confidence: 0.95,
		ObservedAt: time.Now(),
	}
}

// sanIPStrings formats a list of net.IP values as their canonical strings.
func sanIPStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// certIsSelfSigned reports whether the subject equals the issuer — the cheap
// heuristic that catches most embedded-device self-signed certs.
func certIsSelfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
