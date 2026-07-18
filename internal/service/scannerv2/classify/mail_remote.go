package classify

import (
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// MailClassifier detects SMTP/POP3/IMAP from their greeting banners. These
// services all volunteer a line on connect, so the passive read in the port
// probe is the primary signal.
//
// Service names emitted: "smtp", "pop3", "imap".
//
// Note on FTP-vs-SMTP ambiguity: both start with "220 ". The BannerClassifier
// already keys "220 " → ftp at 0.7 confidence. To avoid double-classifying,
// this classifier asserts smtp ONLY when the banner contains "ESMTP" or
// "Postfix"/"Sendmail"/"Exim" (which is how nmap disambiguates). A bare "220 "
// without those markers falls through to ftp.
type MailClassifier struct{}

func (MailClassifier) Service() string { return "mail" }

func (MailClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	idx := indexEvidence(ev)
	var out []scannerv2.ServiceIdentity
	for _, e := range idx.byKind["banner"] {
		b := strings.TrimSpace(bannerText(e))
		if b == "" {
			continue
		}
		lower := strings.ToLower(b)

		// SMTP: "220 ... ESMTP" or a known MTA name. The "220 " prefix alone
		// is NOT enough (FTP also uses it) — require a mail-specific marker.
		if strings.HasPrefix(b, "220 ") && (strings.Contains(lower, "esmtp") ||
			strings.Contains(lower, "postfix") || strings.Contains(lower, "sendmail") ||
			strings.Contains(lower, "exim") || strings.Contains(lower, "mail")) {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "smtp", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.9),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
			continue
		}
		// POP3: "+OK" greeting, often "OK POP3 ..." or "+OK Dovecot ready".
		if strings.HasPrefix(b, "+OK") && (strings.Contains(lower, "pop3") ||
			e.Port == 110) {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "pop3", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.9),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
			continue
		}
		// IMAP: "* OK" greeting with "IMAP" or on port 143.
		if strings.HasPrefix(b, "* OK") && (strings.Contains(lower, "imap") ||
			e.Port == 143) {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "imap", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.9),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
			continue
		}
	}
	return out
}

// RemoteAccessClassifier detects VNC/RDP/Telnet from their distinctive banners.
//
// Service names emitted: "vnc", "rdp", "telnet".
//
//   - VNC: greeting is exactly "RFB 003.008\n" (12 bytes). Very distinctive.
//   - RDP: no readable banner (X.224 TPKT); assert on port 3389 only, low conf.
//   - Telnet: starts with IAC bytes 0xFF 0xFB/0xFD (WILL/DO negotiation).
type RemoteAccessClassifier struct{}

func (RemoteAccessClassifier) Service() string { return "remote" }

func (RemoteAccessClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	idx := indexEvidence(ev)
	var out []scannerv2.ServiceIdentity
	for _, e := range idx.byKind["banner"] {
		b := bannerText(e) // NOT trimmed — telnet IAC bytes are leading whitespace-adjacent
		if b == "" {
			continue
		}
		// VNC: "RFB 003.xxx" prefix.
		if strings.HasPrefix(b, "RFB ") {
			ver := strings.TrimRight(b[4:], "\r\n\x00")
			out = append(out, scannerv2.ServiceIdentity{
				Service: "vnc", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.95),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b, "version": ver},
			})
			continue
		}
		// Telnet: IAC (0xFF) followed by WILL(0xFB)/DO(0xFD)/WONT(0xFC)/DONT(0xFE).
		if len(b) >= 2 && b[0] == '\xff' && (b[1] == '\xfb' || b[1] == '\xfd' || b[1] == '\xfc' || b[1] == '\xfe') {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "telnet", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.9),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
			continue
		}
	}

	// Port-only fallback for RDP (no readable banner; X.224 is binary TPKT).
	if portHasOpen(idx, 3389) && !outHasPort(out, 3389) {
		out = append(out, scannerv2.ServiceIdentity{
			Service: "rdp", Port: 3389, Protocol: "tcp",
			Confidence: 0.6, // port-shape only
			Evidence:   idx.byPort[3389],
		})
	}
	return out
}

// MiscClassifier catches a few remaining common services: LDAP (bind-response
// banner on a non-protocol greeting is unreadable, so port-only), DNS (no TCP
// banner; port-only for 53), and NTP (UDP 123 — port-only). These are
// intentionally low-confidence because they're port-shape-only, but they make
// the device record far more useful than a bare "open port".
//
// The well-known TLS-wrapped service ports (465/989/990/992/993/994/995) are
// also asserted here so the TLS-cert-collect handler runs for them and grabs
// their full certificate chain. ldaps (636) was always here; the others join
// it for symmetry. Each emits a distinct service name so the dispatch routes
// to the matching cert-collect handler.
//
// Service names emitted: "ldap", "ldaps", "smb", "ntp", "dns-tcp",
// "smtps", "ftps-data", "ftps", "telnets", "imaps", "ircs", "pop3s".
type MiscClassifier struct{}

func (MiscClassifier) Service() string { return "misc" }

func (MiscClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	idx := indexEvidence(ev)
	var out []scannerv2.ServiceIdentity
	for port, svc := range map[int]string{
		389: "ldap",
		636: "ldaps",
		445: "smb",
		23:  "telnet", // in case the IAC banner wasn't captured
		21:  "ftp",    // in case the 220 banner wasn't captured
		53:  "dns-tcp",
		// TLS-wrapped service ports (assert so the cert-collect handler runs).
		465: "smtps",
		989: "ftps-data",
		990: "ftps",
		992: "telnets",
		993: "imaps",
		994: "ircs",
		995: "pop3s",
	} {
		if portHasOpen(idx, port) {
			out = append(out, scannerv2.ServiceIdentity{
				Service: svc, Port: port, Protocol: "tcp",
				Confidence: 0.5, // port-shape only
				Evidence:   idx.byPort[port],
			})
		}
	}
	return out
}
