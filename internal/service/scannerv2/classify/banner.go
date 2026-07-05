package classify

import (
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// BannerClassifier inspects TCP banner evidence (kind="banner") and emits a
// service identity for SSH/HTTP/RTSP based on the banner's magic prefix. It
// keys off the banner string the port probe passively captured.
//
// Service names emitted: "ssh", "http", "https", "rtsp".
type BannerClassifier struct{}

func (BannerClassifier) Service() string { return "banner" } // multi-emitter; name is nominal

func (BannerClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	idx := indexEvidence(ev)
	var out []scannerv2.ServiceIdentity
	for _, e := range idx.byKind["banner"] {
		b := strings.TrimSpace(bannerText(e))
		if b == "" {
			continue
		}
		switch {
		case hasPrefix(b, "SSH-"):
			out = append(out, scannerv2.ServiceIdentity{
				Service: "ssh", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.95),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b, "version": extractSSHVersion(b)},
			})
		case hasPrefix(b, "HTTP/"):
			out = append(out, scannerv2.ServiceIdentity{
				Service: "http", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.8),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
		case hasPrefix(b, "RTSP/"):
			out = append(out, scannerv2.ServiceIdentity{
				Service: "rtsp", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.95),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
		case hasPrefix(b, "FTP", "220 "): // many FTP servers start with "220-"
			out = append(out, scannerv2.ServiceIdentity{
				Service: "ftp", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.7),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
		}
	}
	return out
}

// extractSSHVersion parses "SSH-2.0-OpenSSH_9.0" → "OpenSSH_9.0".
func extractSSHVersion(b string) string {
	parts := strings.SplitN(b, "-", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}
