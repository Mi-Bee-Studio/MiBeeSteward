package probe

import (
	"context"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// tlsProbeTimeout bounds the TLS handshake + cert read. Short because we only
// want the cert chain, not a full session.
const tlsProbeTimeout = 4 * time.Second

// DefaultTLSTimeout exposes the probe's per-attempt TLS timeout so callers
// outside package probe (the TLS-wrapped service handlers) can reuse the same
// bound without hardcoding the value.
func DefaultTLSTimeout() time.Duration { return tlsProbeTimeout }

// tlsProbePorts are the ports we attempt a TLS handshake on for the
// classification-time evidence. This is the "fast path" that feeds the TLS
// classifier (and lets the orchestrator emit an `https` identity even before
// the handler-level full-chain collection runs). The full chain + PEM is
// collected separately by the TLS-wrapped service handlers (see handler/
// tls_collect.go) which are dispatched for every port a classifier flags as
// TLS-speaking — so coverage is NOT limited to this set.
//
// Includes the well-known TLS-wrapped service ports so their certs land as
// early evidence (subject_cn / issuer_cn / san are strong brand signals).
var tlsProbePorts = map[int]bool{
	443:  true, // https
	8443: true, // https (alt)
	9443: true, // https (alt)
	4443: true, // https (alt)
	465:  true, // smtps
	636:  true, // ldaps
	989:  true, // ftps (data, often TLS-wrapped)
	990:  true, // ftps (control)
	992:  true, // telnets
	993:  true, // imaps
	994:  true, // ircs
	995:  true, // pop3s
}

// TLSProbe dials the well-known TLS ports and reads the server's certificate
// chain. The certificate's Subject CN, Issuer CN, and SAN DNS names are a rich
// source of identifying signal: CN often contains a hostname or vendor domain
// (e.g. "*.hikvision.com"), and the issuer can identify a self-signed embedded
// device vs. a public-CA-validated server.
//
// The probe emits a lightweight "tls" evidence (CN/Issuer/SAN/validity/algos)
// used for classification and device-enrichment. The full chain + PEM is
// collected at handler time (collectCertChain in cert_collector.go) and
// persisted to host_tls_certs — this probe deliberately stays cheap so it
// doesn't block the gather phase.
//
// Name: "active:tls".
type TLSProbe struct{}

// NewTLSProbe returns a TLS cert-inspection probe.
func NewTLSProbe() *TLSProbe { return &TLSProbe{} }

func (p *TLSProbe) Name() string { return "active:tls" }

// Probe attempts a TLS handshake on each candidate port and, on success, emits
// a "tls" evidence with the leaf cert's CN/Issuer/SAN/validity/signature.
// Closed ports or non-TLS services contribute no evidence (CollectCertChain
// returns an error record but the probe suppresses those here — error records
// are persisted at handler time, not in the evidence stream, to keep the
// evidence slice focused on positive signal).
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
		// CollectCertChain always returns ≥1 record (success → chain records;
		// failure → one error record with IP/Port/Error). For the evidence
		// stream we only want the leaf (cert_index 0) and only when there was
		// no error — error records are persisted later by the handler, not
		// flowed as classification evidence.
		records := CollectCertChain(ctx, ip, port, timeout)
		if len(records) == 0 || records[0].Error != "" {
			continue
		}
		leaf := records[0]
		evs = append(evs, scannerv2.Evidence{
			Source:     "active:tls",
			Kind:       "tls",
			IP:         ip,
			Port:       port,
			Protocol:   "tcp",
			RawData:    leafEvidence(leaf),
			Confidence: 0.95,
			ObservedAt: time.Now(),
		})
	}
	return evs, nil
}

// leafEvidence builds the flat map[string]string evidence payload from a leaf
// cert record. Keys are kept stable (subject_cn, issuer_cn, san_dns, ...) so the
// existing TLSClassifier / orchestrator fold / fingerprint rules continue to
// work unchanged. New keys (not_before, not_after, sig_algorithm,
// key_algorithm, fingerprint_sha256, san_email) are added for richer identity;
// downstream code that doesn't know about them simply ignores them. Empty
// values are omitted so evidence stays compact.
func leafEvidence(leaf scannerv2.TLSCertRecord) map[string]string {
	raw := map[string]string{
		"subject_cn":         leaf.SubjectCN,
		"issuer_cn":          leaf.IssuerCN,
		"issuer_org":         leaf.IssuerOrg,
		"san_dns":            leaf.SanDNS,
		"san_ip":             leaf.SanIP,
		"san_email":          leaf.SanEmail,
		"serial":             leaf.Serial,
		"not_before":         leaf.NotBefore,
		"not_after":          leaf.NotAfter,
		"sig_algorithm":      leaf.SigAlgorithm,
		"key_algorithm":      leaf.KeyAlgorithm,
		"fingerprint_sha256": leaf.FingerprintSHA256,
		"self_signed":        boolStr(leaf.SelfSigned),
	}
	for k, v := range raw {
		if v == "" {
			delete(raw, k)
		}
	}
	return raw
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
