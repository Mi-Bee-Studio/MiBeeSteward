package classify

import (
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// WebClassifier turns the structured "http" evidence from the HTTPProbe into a
// service identity, and infers OS/vendor hints from the Server / X-Powered-By
// headers and the page <title>. This complements the BannerClassifier (which
// keys off the raw HTTP/ response line) by adding the structured fields.
//
// Service names emitted: "http" (re-asserted with version/server metadata).
type WebClassifier struct{}

func (WebClassifier) Service() string { return "web" }

func (WebClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	var out []scannerv2.ServiceIdentity
	for _, e := range ev {
		if e.Kind != "http" || e.RawData == nil {
			continue
		}
		md := map[string]string{}
		for k, v := range e.RawData {
			md[k] = v
		}
		// Infer a product version from the Server header where possible.
		if srv := e.RawData["server"]; srv != "" {
			if v := serverVersion(srv); v != "" {
				md["version"] = v
			}
		}
		out = append(out, scannerv2.ServiceIdentity{
			Service: "http", Port: e.Port, Protocol: "tcp",
			Confidence: fuseConfidence(e.Confidence, 0.85),
			Evidence:   []scannerv2.Evidence{e},
			Metadata:   md,
		})
	}
	return out
}

// serverVersion extracts a version-ish substring from an HTTP Server header
// (e.g. "nginx/1.25.3" → "1.25.3", "Apache/2.4.58 (Debian)" → "2.4.58"). Empty
// when no version is present.
func serverVersion(server string) string {
	i := strings.IndexByte(server, '/')
	if i < 0 {
		return ""
	}
	rest := server[i+1:]
	// Version runs until the next space or paren.
	for j := 0; j < len(rest); j++ {
		if rest[j] == ' ' || rest[j] == '(' {
			return rest[:j]
		}
	}
	return rest
}

// TLSClassifier turns the structured "tls" evidence from the TLSProbe into a
// service identity. It also surfaces the cert CN/SAN as a hostname source and
// the issuer as a vendor hint (e.g. "*.hikvision.com" CN → vendor "Hikvision").
//
// Service names emitted: "https" (on TLS ports), plus host-level metadata.
type TLSClassifier struct{}

func (TLSClassifier) Service() string { return "tls" }

func (TLSClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	var out []scannerv2.ServiceIdentity
	for _, e := range ev {
		if e.Kind != "tls" || e.RawData == nil {
			continue
		}
		// The presence of a TLS handshake on a port is itself strong evidence
		// of HTTPS (or a TLS-wrapped service). Emit an https identity.
		md := map[string]string{}
		for k, v := range e.RawData {
			md[k] = v
		}
		// Vendor hint from the cert CN's domain.
		if cn := e.RawData["subject_cn"]; cn != "" {
			if v := vendorFromCertCN(cn); v != "" {
				md["inferred_brand"] = v
			}
		}
		out = append(out, scannerv2.ServiceIdentity{
			Service: "https", Port: e.Port, Protocol: "tcp",
			Confidence: fuseConfidence(e.Confidence, 0.9),
			Evidence:   []scannerv2.Evidence{e},
			Metadata:   md,
		})
	}
	return out
}

// vendorFromCertCN maps a cert CN/SAN domain to a vendor when the domain is a
// known vendor's. Covers the camera/networking vendors already in the OUI +
// ONVIF brand lists plus a few common infrastructure ones.
func vendorFromCertCN(cn string) string {
	lower := strings.ToLower(cn)
	switch {
	case strings.Contains(lower, "hikvision") || strings.Contains(lower, "hik"):
		return "Hikvision"
	case strings.Contains(lower, "dahua"):
		return "Dahua"
	case strings.Contains(lower, "axis"):
		return "Axis"
	case strings.Contains(lower, "unifi") || strings.Contains(lower, "ubiquiti"):
		return "Ubiquiti"
	case strings.Contains(lower, "synology"):
		return "Synology"
	case strings.Contains(lower, "qnap"):
		return "QNAP"
	case strings.Contains(lower, "cisco"):
		return "Cisco"
	case strings.Contains(lower, "fortinet") || strings.Contains(lower, "fortigate"):
		return "Fortinet"
	}
	return ""
}
