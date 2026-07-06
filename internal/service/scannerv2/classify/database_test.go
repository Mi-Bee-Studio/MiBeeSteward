package classify

import (
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

func TestDatabaseClassifier_MySQLGreeting(t *testing.T) {
	// MySQL greeting packet: the version string appears after a 1-byte length
	// and is ASCII terminated by 0x00. Simulate the readable portion.
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 3306, Protocol: "tcp",
		RawData:    map[string]string{"banner": "\x5a\x00\x00\x0010.11.8-MariaDB\x00..."},
		Confidence: 0.9,
	}}
	out := DatabaseClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "mysql" {
		t.Fatalf("expected mysql, got %+v", out)
	}
	if out[0].Metadata["version"] == "" {
		t.Errorf("expected version extracted, got %v", out[0].Metadata)
	}
}

func TestDatabaseClassifier_RedisNoauth(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 6379, Protocol: "tcp",
		RawData:    map[string]string{"banner": "-NOAUTH Authentication required."},
		Confidence: 0.9,
	}}
	out := DatabaseClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "redis" {
		t.Fatalf("expected redis, got %+v", out)
	}
}

func TestDatabaseClassifier_PostgresFatal(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 5432, Protocol: "tcp",
		RawData:    map[string]string{"banner": "SFATAL: no PostgreSQL"},
		Confidence: 0.9,
	}}
	out := DatabaseClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "postgresql" {
		t.Fatalf("expected postgresql, got %+v", out)
	}
}

func TestDatabaseClassifier_PortOnlyFallback(t *testing.T) {
	// Open MongoDB port, no banner → low-confidence identity.
	ev := []scannerv2.Evidence{{
		Kind: "port_open", Port: 27017, Protocol: "tcp", Confidence: 1.0,
	}}
	out := DatabaseClassifier{}.Classify(ev)
	found := false
	for _, s := range out {
		if s.Service == "mongodb" && s.Port == 27017 {
			if s.Confidence > 0.55 {
				t.Errorf("port-only confidence should be ~0.5, got %f", s.Confidence)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("expected mongodb port-only fallback, got %+v", out)
	}
}

func TestDatabaseClassifier_NoBannerOnClosedPort(t *testing.T) {
	// No evidence at all → no identities.
	out := DatabaseClassifier{}.Classify(nil)
	if len(out) != 0 {
		t.Errorf("expected no identities, got %+v", out)
	}
}

func TestMailClassifier_SMTPvsFTP(t *testing.T) {
	// "220 mail ESMTP" → smtp (not ftp).
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 25, Protocol: "tcp",
		RawData:    map[string]string{"banner": "220 mail.example.com ESMTP Postfix"},
		Confidence: 0.9,
	}}
	out := MailClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "smtp" {
		t.Fatalf("expected smtp, got %+v", out)
	}
}

func TestMailClassifier_Bare220IsNotSMTP(t *testing.T) {
	// Bare "220 " without ESMTP/Postfix markers should NOT classify as smtp
	// (it's likely FTP — left to BannerClassifier).
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 21, Protocol: "tcp",
		RawData:    map[string]string{"banner": "220 vsFTPd 3.0.5"},
		Confidence: 0.9,
	}}
	out := MailClassifier{}.Classify(ev)
	if len(out) != 0 {
		t.Errorf("bare FTP-style 220 should not classify as smtp, got %+v", out)
	}
}

func TestMailClassifier_POP3(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 110, Protocol: "tcp",
		RawData:    map[string]string{"banner": "+OK Dovecot ready."},
		Confidence: 0.9,
	}}
	out := MailClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "pop3" {
		t.Fatalf("expected pop3, got %+v", out)
	}
}

func TestRemoteAccessClassifier_VNC(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 5900, Protocol: "tcp",
		RawData:    map[string]string{"banner": "RFB 003.008\n"},
		Confidence: 0.9,
	}}
	out := RemoteAccessClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "vnc" {
		t.Fatalf("expected vnc, got %+v", out)
	}
	if out[0].Metadata["version"] != "003.008" {
		t.Errorf("expected version 003.008, got %q", out[0].Metadata["version"])
	}
}

func TestRemoteAccessClassifier_TelnetIAC(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "banner", Port: 23, Protocol: "tcp",
		RawData:    map[string]string{"banner": "\xff\xfd\x01\xff\xfd\x1fLogin: "},
		Confidence: 0.9,
	}}
	out := RemoteAccessClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "telnet" {
		t.Fatalf("expected telnet, got %+v", out)
	}
}

func TestRemoteAccessClassifier_RDPPortOnly(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "port_open", Port: 3389, Protocol: "tcp", Confidence: 1.0,
	}}
	out := RemoteAccessClassifier{}.Classify(ev)
	found := false
	for _, s := range out {
		if s.Service == "rdp" && s.Port == 3389 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected rdp port-only fallback, got %+v", out)
	}
}

func TestMiscClassifier_LDAPandSMB(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "port_open", Port: 389, Protocol: "tcp", Confidence: 1.0},
		{Kind: "port_open", Port: 445, Protocol: "tcp", Confidence: 1.0},
	}
	out := MiscClassifier{}.Classify(ev)
	svcs := map[string]bool{}
	for _, s := range out {
		svcs[s.Service] = true
	}
	if !svcs["ldap"] {
		t.Errorf("expected ldap, got %v", svcs)
	}
	if !svcs["smb"] {
		t.Errorf("expected smb, got %v", svcs)
	}
}

func TestWebClassifier_ServerVersion(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "http", Port: 80, Protocol: "tcp",
		RawData:    map[string]string{"status": "200 OK", "server": "nginx/1.25.3", "title": "Welcome"},
		Confidence: 0.9,
	}}
	out := WebClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "http" {
		t.Fatalf("expected http, got %+v", out)
	}
	if out[0].Metadata["version"] != "1.25.3" {
		t.Errorf("expected nginx version 1.25.3, got %q", out[0].Metadata["version"])
	}
	if out[0].Metadata["title"] != "Welcome" {
		t.Errorf("expected title, got %q", out[0].Metadata["title"])
	}
}

func TestTLSClassifier_HikvisionCN(t *testing.T) {
	ev := []scannerv2.Evidence{{
		Kind: "tls", Port: 443, Protocol: "tcp",
		RawData: map[string]string{
			"subject_cn": "*.hikvision.com",
			"issuer_cn":  "hikvision",
		},
		Confidence: 0.95,
	}}
	out := TLSClassifier{}.Classify(ev)
	if len(out) != 1 || out[0].Service != "https" {
		t.Fatalf("expected https, got %+v", out)
	}
	if out[0].Metadata["inferred_brand"] != "Hikvision" {
		t.Errorf("expected Hikvision brand from CN, got %q", out[0].Metadata["inferred_brand"])
	}
}

func TestServerVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"nginx/1.25.3", "1.25.3"},
		{"Apache/2.4.58 (Debian)", "2.4.58"},
		{"Caddy", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := serverVersion(c.in); got != c.want {
			t.Errorf("serverVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVendorFromCertCN(t *testing.T) {
	cases := []struct{ in, want string }{
		{"*.hikvision.com", "Hikvision"},
		{"camera.dahua.local", "Dahua"},
		{"unifi.ui.com", "Ubiquiti"},
		{"random.example.com", ""},
	}
	for _, c := range cases {
		if got := vendorFromCertCN(c.in); got != c.want {
			t.Errorf("vendorFromCertCN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
