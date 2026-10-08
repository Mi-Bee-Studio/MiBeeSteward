package classify

import (
	"testing"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"
)

// TestRuleClassifier_HostIdentityDomainTolerance pins the 2026-10-02 batch:
// hostnames captured on the field LAN arrive both bare ("Mi-10", a DHCP
// client name) and domain-qualified ("…-pad-6.tail0a1b2c.ts.net", a PTR/mDNS
// name). The phone/pad/TV model rules must accept an optional trailing
// dot-domain suffix, and the new vendor rules (soundbox, repeater, ESP32,
// Banana Pi, MacBook, Xiaomi serial phone, Huawei retail code) must extract
// their identity without leaking device-specific suffixes into the model.
func TestRuleClassifier_HostIdentityDomainTolerance(t *testing.T) {
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir("../../../../configs/fingerprints"); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	hostnameEv := func(host string) []fp.Evidence {
		return []fp.Evidence{{
			Kind:       "hostname",
			IP:         "192.0.2.10",
			RawData:    map[string]string{"hostname": host},
			Confidence: 0.8,
		}}
	}
	cases := []struct {
		host      string
		wantBrand string
		wantModel string // "" = must NOT be set
	}{
		// Domain-qualified forms of the 2026-10-01 rules (the "$" anchor used
		// to reject them — field-found on a tablet hostname typed "other").
		{"user-dexiaomi-pad-6.tail0a1b2c.ts.net", "Xiaomi", "6"},
		{"mi-10", "Xiaomi", "10"},
		{"redmi-15r-5g", "Redmi", "15r-5g"},
		{"mitv4a-1234abcd.tail0a1b2c.ts.net", "Xiaomi", "4a"},
		// New vendor rules, field-found 2026-10-02.
		{"MiAiSoundbox-LX06", "Xiaomi", "LX06"},
		{"xiaomi-repeater-v2_miio12345678", "Xiaomi", "v2"},
		{"XiaoMiRepeater_V2", "Xiaomi", "V2"},
		{"esp32c6-a1b2c3", "Espressif", "esp32c6"},
		{"esp32c3-f8e62c", "Espressif", "esp32c3"},
		{"bananapim5.tail0a1b2c.ts.net", "Banana Pi", "m5"},
		{"MacBookPro.tail0a1b2c.ts.net", "Apple", ""},
		{"2109119BC", "Xiaomi", ""},
		{"KLE-AL00U", "Huawei", "KLE-AL00U"},
		// SBC / NAS vendor rules, field-found 2026-10-04.
		{"orangepi-zero3", "Orange Pi", "zero3"},
		{"nanopineo.tail0a1b2c.ts.net", "FriendlyElec", "neo"},
		{"nanopi-neo2", "FriendlyElec", "neo2"},
		{"R4S-FNOS", "FriendlyElec", "NanoPi R4S"},
		{"nanopi-r4s", "FriendlyElec", "NanoPi R4S"},
		{"Z4S-2PSE", "ZSpace", "Z4S"},
		{"Mijia_Hub_V2-1a2b.tail0a1b2c.ts.net", "Xiaomi", "Hub V2"},
		// Router-as-DHCP-name rule, field-found 2026-10-05.
		{"R68S", "FastRhino", "R68S"},
		// Seeed Studio XIAO firmware default name, field-found 2026-10-08.
		{"Seeed-esp32c6", "Seeed Studio", "esp32c6"},
		{"seeed_esp32c3.tail0a1b2c.ts.net", "Seeed Studio", "esp32c3"},
	}
	for _, tc := range cases {
		ids := rc.Classify(hostnameEv(tc.host))
		var got *fp.ServiceIdentity
		for i := range ids {
			if ids[i].Service == "miot" && got == nil {
				got = &ids[i]
			}
		}
		if got == nil {
			t.Errorf("%s: no miot identity fired", tc.host)
			continue
		}
		if got.Metadata["inferred_brand"] != tc.wantBrand {
			t.Errorf("%s: brand = %q, want %q", tc.host, got.Metadata["inferred_brand"], tc.wantBrand)
		}
		if got.Metadata["inferred_model"] != tc.wantModel {
			t.Errorf("%s: model = %q, want %q", tc.host, got.Metadata["inferred_model"], tc.wantModel)
		}
	}
	// Negative: a generic vendor-less hostname must not fire any identity.
	for _, host := range []string{"some-laptop-42", "web-1.corp.example"} {
		for _, id := range rc.Classify(hostnameEv(host)) {
			if id.Service == "miot" {
				t.Errorf("%s: unexpected miot identity %v", host, id.Metadata)
			}
		}
	}
}

// TestRuleClassifier_SSHBannerOSType pins the banner-ssh keyword_map: the SSH
// greeting suffix yields a normalized os_type the SSHHandler propagates to the
// device record (the os_rules pc/server typing depends on it surviving the
// agent round trip — see ReportedHostToReport).
func TestRuleClassifier_SSHBannerOSType(t *testing.T) {
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir("../../../../configs/fingerprints"); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	for _, tc := range []struct {
		banner  string
		wantOS  string
		wantVer string
	}{
		{"SSH-2.0-OpenSSH_for_Windows_9.5", "Windows", "OpenSSH_for_Windows_9.5"},
		{"SSH-2.0-OpenSSH_9.2p1 Debian-3+deb12u4", "Debian", "OpenSSH_9.2p1 Debian-3+deb12u4"},
		{"SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1", "Ubuntu", "OpenSSH_8.4p1 Ubuntu-5ubuntu1.1"},
	} {
		ev := []fp.Evidence{{
			Kind: "banner", IP: "192.0.2.11", Protocol: "tcp", Port: 22,
			RawData:    map[string]string{"banner": tc.banner},
			Confidence: 0.9,
		}}
		var got *fp.ServiceIdentity
		for i := range rc.Classify(ev) {
			if rc.Classify(ev)[i].Service == "ssh" && got == nil {
				got = &rc.Classify(ev)[i]
			}
		}
		if got == nil {
			t.Errorf("%s: no ssh identity", tc.banner)
			continue
		}
		if got.Metadata["os_type"] != tc.wantOS {
			t.Errorf("%s: os_type = %q, want %q", tc.banner, got.Metadata["os_type"], tc.wantOS)
		}
		if got.Metadata["version"] != tc.wantVer {
			t.Errorf("%s: version = %q, want %q", tc.banner, got.Metadata["version"], tc.wantVer)
		}
	}
}
