package classify

import (
	"testing"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"

	"mibee-steward/internal/service/scannerv2"
)

// TestRuleClassifier_GoldenCases is a QUALITY regression guard: real-world
// evidence samples → expected (service, metadata). Unlike the count/parity
// tests above, this asserts the classifier produces the RIGHT answer for
// representative banners/headers, so a rule edit that breaks identification
// fails here even if the rule count stays the same.
//
// Cases are drawn from the builtin rules (banner.yaml / http-tls.yaml /
// ports.yaml). Each entry feeds one Evidence piece and asserts at least one
// emitted identity matches the expected service + a metadata key.
func TestRuleClassifier_GoldenCases(t *testing.T) {
	rc := loadBuiltinRules(t)

	cases := []struct {
		name      string
		evidence  fp.Evidence
		wantSvc   string // the expected service string
		wantMdKey string // a metadata key that MUST be present (non-empty)
	}{
		{
			name: "ssh banner → ssh + version",
			evidence: fp.Evidence{
				Kind: "banner", IP: "10.0.0.5", Port: 22, Confidence: 0.9,
				RawData: map[string]string{"banner": "SSH-2.0-OpenSSH_9.0p2 Debian-7+deb13u4"},
			},
			wantSvc:   "ssh",
			wantMdKey: "version",
		},
		{
			name: "http server header → http",
			evidence: fp.Evidence{
				Kind: "http", IP: "10.0.0.6", Port: 80, Confidence: 0.85,
				RawData: map[string]string{"server": "nginx", "banner": "HTTP/1.1 200 OK"},
			},
			wantSvc:   "http",
			wantMdKey: "banner",
		},
		{
			name: "smtp greeting → smtp",
			evidence: fp.Evidence{
				Kind: "banner", IP: "10.0.0.7", Port: 25, Confidence: 0.85,
				RawData: map[string]string{"banner": "220 mail.example.com ESMTP Postfix"},
			},
			wantSvc: "smtp",
			// smtp rule emits the banner passthrough
			wantMdKey: "banner",
		},
		{
			name: "port 445 open → smb (port-scoped)",
			evidence: fp.Evidence{
				Kind: "port_open", IP: "10.0.0.8", Port: 445, Confidence: 1.0,
				RawData: map[string]string{"banner": ""},
			},
			wantSvc: "smb",
		},
		{
			name: "port 23 open → telnet (port-scoped)",
			evidence: fp.Evidence{
				Kind: "port_open", IP: "10.0.0.9", Port: 23, Confidence: 1.0,
				RawData: map[string]string{"banner": ""},
			},
			wantSvc: "telnet",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ids := rc.Classify([]scannerv2.Evidence{c.evidence})
			if len(ids) == 0 {
				t.Fatalf("no identity emitted for %q", c.name)
			}
			var matched bool
			for _, id := range ids {
				if id.Service == c.wantSvc {
					if c.wantMdKey != "" && (id.Metadata == nil || id.Metadata[c.wantMdKey] == "") {
						continue // right service but missing the metadata key — keep looking
					}
					matched = true
					break
				}
			}
			if !matched {
				svcs := make([]string, 0, len(ids))
				for _, id := range ids {
					svcs = append(svcs, id.Service)
				}
				t.Fatalf("%q: no identity matched service %q (got %v)", c.name, c.wantSvc, svcs)
			}
		})
	}
}

// TestRuleClassifier_NegativeNoMatch verifies evidence that matches no rule
// produces zero identities — the classifier must not emit spurious services.
func TestRuleClassifier_NegativeNoMatch(t *testing.T) {
	rc := loadBuiltinRules(t)
	ids := rc.Classify([]scannerv2.Evidence{
		{Kind: "banner", IP: "10.0.0.99", Port: 9999, Confidence: 0.5,
			RawData: map[string]string{"banner": "totally-unknown-garbage-no-rule"}},
	})
	if len(ids) != 0 {
		t.Errorf("expected zero identities for non-matching banner, got %d", len(ids))
	}
}
