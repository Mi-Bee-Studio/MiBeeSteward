package classify

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"

	"mibee-steward/internal/service/scannerv2"
)

// TestRuleClassifier_Parity verifies the data-driven RuleClassifier produces
// byte-identical ServiceIdentity output to the hand-written classifiers it
// replaces, for every rule in configs/fingerprints/. This is the regression
// guard: if a rule drifts from the original classifier's behavior, this fails.
//
// Parity = same {service, port, protocol, confidence (within 1e-9), metadata}.
// We load from the repo's configs/fingerprints/ dir (the real rule files).

// loadBuiltinRules loads ONLY the hand-authored builtin rule files (not
// third-party imports like recog-imported.yaml) into a temp dir. Parity tests
// compare the RuleClassifier against the original code classifiers, so they
// must be isolated from additive third-party rules that emit overlapping
// identities. The production engine loads everything; these tests load builtin-only.
func loadBuiltinRules(t *testing.T) *fp.RuleClassifier {
	t.Helper()
	srcDir := "../../../../configs/fingerprints"
	tmp, err := os.MkdirTemp("", "mibee-fp-test-*")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"banner.yaml", "http-tls.yaml", "ports.yaml", "lldp-cdp.yaml"} {
		b, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir(tmp); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	if !rc.Loaded() {
		t.Fatal("rule classifier did not load any rules")
	}
	return rc
}

func TestRuleClassifier_LoadsAllRules(t *testing.T) {
	rc := loadBuiltinRules(t)
	// builtin-only (recog-imported.yaml excluded — tested via loadFullRules).
	// banner.yaml=8 + http-tls.yaml=12 (6 kind-presence + 6 http-server-*) + ports.yaml=7 (6 port + 1 smb-version) + lldp-cdp.yaml=13 = 40
	if rc.RuleCount() != 40 {
		t.Errorf("expected 40 builtin rules, got %d", rc.RuleCount())
	}
}

// TestRuleClassifier_LoadsWithRecog verifies the full fingerprint dir (including
// third-party Recog imports) loads without error. The production engine loads
// everything; this confirms the Recog regex patterns all compile under RE2.
func TestRuleClassifier_LoadsWithRecog(t *testing.T) {
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir("../../../../configs/fingerprints"); err != nil {
		t.Fatalf("LoadFromDir with recog: %v", err)
	}
	if rc.RuleCount() < 1000 {
		t.Errorf("expected ≥1000 rules with recog, got %d", rc.RuleCount())
	}
	t.Logf("loaded %d rules (builtin + recog)", rc.RuleCount())
}

// assertIdentityEqual compares two ServiceIdentity slices for behavioral parity.
// Duplicates (same service+port emitted by multiple rules, e.g. http/80 from
// both BannerClassifier @0.8 and HTTPClassifier @0.75) are matched
// many-to-many by confidence — each `want` consumes one `got` with the same
// (service, port, confidence). This avoids false mismatches when two rules emit
// the same key at different confidences.
func assertIdentityEqual(t *testing.T, want, got []scannerv2.ServiceIdentity, ctx string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: count mismatch want=%d got=%d\nwant=%+v\ngot =%+v", ctx, len(want), len(got), want, got)
	}
	// Greedy match by (service, port, confidence within 1e-9), consuming got.
	used := make([]bool, len(got))
	for _, w := range want {
		found := false
		for i, g := range got {
			if used[i] {
				continue
			}
			if g.Service != w.Service || g.Port != w.Port {
				continue
			}
			if math.Abs(g.Confidence-w.Confidence) > 1e-9 {
				continue
			}
			used[i] = true
			found = true
			if g.Protocol != w.Protocol {
				t.Errorf("%s: %s/%d protocol want=%s got=%s", ctx, w.Service, w.Port, w.Protocol, g.Protocol)
			}
			for k, v := range w.Metadata {
				if gv, ok := g.Metadata[k]; !ok || gv != v {
					t.Errorf("%s: %s/%d metadata[%s] want=%q got=%q (present=%v)", ctx, w.Service, w.Port, k, v, gv, ok)
				}
			}
			break
		}
		if !found {
			t.Errorf("%s: want identity {svc=%s port=%d conf=%v} not matched in got=%+v", ctx, w.Service, w.Port, w.Confidence, got)
		}
	}
}

// ── BannerClassifier parity ──────────────────────────────────────────────

func TestRuleClassifier_BannerSSH(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "banner", IP: "10.0.0.1", Port: 22, Confidence: 0.9, RawData: map[string]string{"banner": "SSH-2.0-OpenSSH_9.0"}},
	}
	// Original BannerClassifier emits ssh (0.95 fused). HTTPClassifier does NOT
	// match SSH. So want = BannerClassifier output only.
	want := BannerClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "banner-ssh")
	// Specifically check version extraction.
	if s, ok := hasService(got, "ssh"); ok {
		if s.Metadata["version"] != "OpenSSH_9.0" {
			t.Errorf("ssh version want=OpenSSH_9.0 got=%q", s.Metadata["version"])
		}
	}
}

func TestRuleClassifier_BannerRTSPAndHTTP(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 554, Confidence: 0.9, RawData: map[string]string{"banner": "RTSP/1.0 200 OK"}},
		{Kind: "banner", Port: 80, Confidence: 0.9, RawData: map[string]string{"banner": "HTTP/1.1 200 OK"}},
	}
	// BannerClassifier emits rtsp+http (0.95/0.8). HTTPClassifier ALSO emits
	// http at 0.75. Both originals fire → rule classifier must too (both rules).
	want := append(BannerClassifier{}.Classify(ev), HTTPClassifier{}.Classify(ev)...)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "banner-rtsp+http")
}

func TestRuleClassifier_BannerFTP(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 21, Confidence: 0.9, RawData: map[string]string{"banner": "220-FTP server ready"}},
	}
	want := BannerClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "banner-ftp")
}

// ── MailClassifier parity (compound + trim + exclusive group) ────────────

func TestRuleClassifier_SMTP(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 25, Confidence: 0.9, RawData: map[string]string{"banner": "220 mail.example.com ESMTP Postfix"}},
	}
	// BannerClassifier also matches "220 " → ftp. MailClassifier → smtp. Both fire.
	want := append(BannerClassifier{}.Classify(ev), MailClassifier{}.Classify(ev)...)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "smtp")
}

func TestRuleClassifier_POP3ByPort(t *testing.T) {
	rc := loadBuiltinRules(t)
	// "+OK" with no "pop3" keyword, but port 110 → matches via port_eq.
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 110, Confidence: 0.9, RawData: map[string]string{"banner": "+OK Dovecot ready"}},
	}
	want := MailClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "pop3-by-port")
}

func TestRuleClassifier_IMAP(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 143, Confidence: 0.9, RawData: map[string]string{"banner": "* OK [CAPABILITY IMAP4rev1]"}},
	}
	want := MailClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "imap")
}

// ── PrometheusClassifier parity (exclusive group: node wins) ─────────────

func TestRuleClassifier_NodeExporterPreferred(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "metric", Port: 9100, Confidence: 0.9, RawData: map[string]string{
			"content_sample": "node_exporter_build_info{version=\"1.6\"} 1\nprometheus_build_info 1\n",
			"url":            "http://10.0.0.1:9100/metrics",
		}},
	}
	// Original: switch fires isNode ONLY (not also prometheus). Rule classifier
	// must suppress prometheus via exclusive_group.
	want := PrometheusClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "node-exporter-preferred")
	// Explicit: must NOT emit plain prometheus.
	if _, ok := hasService(got, "prometheus"); ok {
		t.Error("rule classifier emitted prometheus when node_exporter matched (exclusive_group failed)")
	}
}

func TestRuleClassifier_PlainPrometheus(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "metric", Port: 9090, Confidence: 0.9, RawData: map[string]string{
			"content_sample": "prometheus_build_info{version=\"2.45\"} 1\n",
			"url":            "http://10.0.0.1:9090/metrics",
		}},
	}
	want := PrometheusClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "plain-prometheus")
}

// ── WebClassifier / TLSClassifier parity ─────────────────────────────────

func TestRuleClassifier_WebVersionExtract(t *testing.T) {
	rc := loadBuiltinRules(t)
	// Use a fictitious server string that has a real version pattern (so version
	// extraction is exercised) but matches no http-server-* product rule — those
	// rules are a RuleClassifier enhancement beyond the hand-written WebClassifier
	// and would otherwise make `want` (WebClassifier output) and `got` diverge in
	// identity count. This keeps the test focused on version extraction parity.
	ev := []scannerv2.Evidence{
		{Kind: "http", Port: 80, Confidence: 0.9, RawData: map[string]string{"server": "MyApp/1.25.3", "title": "Test"}},
	}
	want := WebClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "web-version")
	if s, ok := hasService(got, "http"); ok {
		if s.Metadata["version"] != "1.25.3" {
			t.Errorf("web version want=1.25.3 got=%q", s.Metadata["version"])
		}
	}
}

func TestRuleClassifier_TLSBrandFromCertCN(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "tls", Port: 443, Confidence: 0.9, RawData: map[string]string{"subject_cn": "device.hikvision.com"}},
	}
	want := TLSClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "tls-brand")
	if s, ok := hasService(got, "https"); ok {
		if s.Metadata["inferred_brand"] != "Hikvision" {
			t.Errorf("tls brand want=Hikvision got=%q", s.Metadata["inferred_brand"])
		}
	}
}

// ── RTSPClassifier / ONVIFClassifier parity (kind_presence + brand map) ─

func TestRuleClassifier_RTSPBrand(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "rtsp_banner", Port: 554, Confidence: 0.95, RawData: map[string]string{"server": "Dahua"}},
	}
	want := RTSPClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "rtsp-brand")
}

func TestRuleClassifier_ONVIFAuthRequired(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "onvif_response", Port: 80, Confidence: 0.9, RawData: map[string]string{"server": "Hikvision-ONVIF", "auth_required": "true"}},
	}
	want := ONVIFClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "onvif-auth")
	if s, ok := hasService(got, "onvif"); ok {
		if s.Metadata["auth_required"] != "true" {
			t.Errorf("onvif auth_required want=true got=%q", s.Metadata["auth_required"])
		}
	}
}

// ── MiscClassifier parity (port-only fallback) ───────────────────────────

func TestRuleClassifier_PortFallbacks(t *testing.T) {
	rc := loadBuiltinRules(t)
	// Open ports 389, 636, 445, 53 with port_open evidence.
	ev := []scannerv2.Evidence{
		{Kind: "port_open", Port: 389, Protocol: "tcp", Confidence: 0.9},
		{Kind: "port_open", Port: 636, Protocol: "tcp", Confidence: 0.9},
		{Kind: "port_open", Port: 445, Protocol: "tcp", Confidence: 0.9},
		{Kind: "port_open", Port: 53, Protocol: "tcp", Confidence: 0.9},
	}
	want := MiscClassifier{}.Classify(ev)
	got := rc.Classify(ev)
	assertIdentityEqual(t, want, got, "port-fallbacks")
}

// ── No-match cases (must emit nothing, not panic) ────────────────────────

func TestRuleClassifier_NoMatch(t *testing.T) {
	rc := loadBuiltinRules(t)
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 9999, Confidence: 0.9, RawData: map[string]string{"banner": "UNKNOWN-GARBAGE"}},
	}
	got := rc.Classify(ev)
	// "UNKNOWN-GARBAGE" matches none of the banner rules.
	for _, s := range got {
		if s.Service == "ssh" || s.Service == "http" || s.Service == "ftp" || s.Service == "smtp" {
			t.Errorf("unexpected match on garbage banner: %+v", s)
		}
	}
}

func TestRuleClassifier_EmptyEvidence(t *testing.T) {
	rc := loadBuiltinRules(t)
	if got := rc.Classify(nil); len(got) != 0 {
		t.Errorf("nil evidence should yield nothing, got %+v", got)
	}
}

// ── Missing directory = silent degradation ───────────────────────────────

func TestRuleClassifier_MissingDir(t *testing.T) {
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir("/nonexistent/fingerprints"); err != nil {
		t.Errorf("missing dir should be silent, got error: %v", err)
	}
	if rc.Loaded() {
		t.Error("missing dir should leave classifier unloaded")
	}
	if got := rc.Classify([]scannerv2.Evidence{{Kind: "banner", Port: 22}}); len(got) != 0 {
		t.Errorf("unloaded classifier should emit nothing, got %+v", got)
	}
}

// ── LLDP-CDP identity inference parity ────────────────────────────────
//
// These tests verify that CDP platform and LLDP sysDesc strings produce the
// expected neighbor-identity metadata via the RuleClassifier. They exercise
// the same pipeline the engine.SetNeighborIdentityInfer callback uses.

// hasMetadataInAny is true when at least one identity carries ALL the
// key→value pairs in wantMD.
func hasMetadataInAny(out []scannerv2.ServiceIdentity, wantMD map[string]string) bool {
	for _, id := range out {
		if id.Metadata == nil {
			continue
		}
		allMatch := true
		for k, v := range wantMD {
			if id.Metadata[k] != v {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}
	return false
}

func TestRuleClassifier_LLDPCDP_CiscoSwitchPlatform(t *testing.T) {
	rc := loadBuiltinRules(t)
	// CDP platform: "cisco WS-C2960S-24TS-L"
	// Expect: brand=Cisco, model=WS-C2960S-24TS-L, type=switch
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{"platform": "cisco WS-C2960S-24TS-L"}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "Cisco", "device_type": "switch"}) {
		t.Errorf("Cisco switch not identified; got %+v", identitiesMetadata(got))
	}
	// Model passthrough carries the full platform string on matching rules.
	// Verify that at least one identity set a model.
	foundModel := false
	for _, id := range got {
		if id.Metadata["inferred_model"] != "" {
			foundModel = true
			break
		}
	}
	if !foundModel {
		t.Errorf("Cisco switch model not set; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_CiscoIOSSwitch(t *testing.T) {
	rc := loadBuiltinRules(t)
	// LLDP sysDesc: "Cisco IOS Software, C2960 Software (C2960-LXRE)"
	// Expect: brand=Cisco, type=switch
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{
			"sys_desc": "Cisco IOS Software, C2960 Software (C2960-LXRE)",
		}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "Cisco", "device_type": "switch"}) {
		t.Errorf("Cisco IOS switch not identified; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_HikvisionCamera(t *testing.T) {
	rc := loadBuiltinRules(t)
	// LLDP sysDesc: "Hikvision DS-2CD2142WD-I3 6.0.0 build 210115"
	// Expect: brand=Hikvision, type=camera
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{
			"sys_desc": "Hikvision DS-2CD2142WD-I3 6.0.0 build 210115",
		}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "Hikvision", "device_type": "camera"}) {
		t.Errorf("Hikvision camera not identified; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_UbiquitiAP(t *testing.T) {
	rc := loadBuiltinRules(t)
	// CDP platform: "Ubiquiti UAP-AC-Pro"
	// Expect: brand=Ubiquiti, type=ap
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{"platform": "Ubiquiti UAP-AC-Pro"}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "Ubiquiti", "device_type": "ap"}) {
		t.Errorf("Ubiquiti AP not identified; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_MikroTikRouter(t *testing.T) {
	rc := loadBuiltinRules(t)
	// LLDP sysDesc: "MikroTik RouterOS 7.x"
	// Expect: brand=MikroTik, type=router
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{
			"sys_desc": "MikroTik RouterOS 7.x",
		}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "MikroTik", "device_type": "router"}) {
		t.Errorf("MikroTik router not identified; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_ArubaSwitchSysDesc(t *testing.T) {
	rc := loadBuiltinRules(t)
	// LLDP sysDesc: "Aruba 2930F Switch"
	// Expect: brand=Aruba, type=switch
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{
			"sys_desc": "Aruba 2930F Switch",
		}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "Aruba", "device_type": "switch"}) {
		t.Errorf("Aruba switch not identified; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_JuniperSwitchPlatform(t *testing.T) {
	rc := loadBuiltinRules(t)
	// CDP platform: "Juniper EX3300-48P"
	// Expect: brand=Juniper, type=switch
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{"platform": "Juniper EX3300-48P"}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "Juniper", "device_type": "switch"}) {
		t.Errorf("Juniper switch not identified; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_NexusSwitchPlatform(t *testing.T) {
	rc := loadBuiltinRules(t)
	// CDP platform: "cisco Nexus 9000"
	// Expect: brand=Cisco, type=switch
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{"platform": "cisco Nexus 9000"}},
	}
	got := rc.Classify(ev)
	if !hasMetadataInAny(got, map[string]string{"inferred_brand": "Cisco", "device_type": "switch"}) {
		t.Errorf("Nexus switch not identified; got %+v", identitiesMetadata(got))
	}
}

func TestRuleClassifier_LLDPCDP_NoMatch(t *testing.T) {
	rc := loadBuiltinRules(t)
	// Unknown platform/sysDesc should not produce neighbor-identity matches.
	ev := []scannerv2.Evidence{
		{Kind: "cdp", Confidence: 0.9, RawData: map[string]string{
			"platform": "Unknown-Device-Model-1234",
			"sys_desc": "Some random description without any known vendor",
		}},
	}
	got := rc.Classify(ev)
	// No lldp-cdp identity should have inferred_brand.
	for _, id := range got {
		if id.Metadata != nil && id.Metadata["inferred_brand"] != "" {
			t.Errorf("unexpected brand inference for unknown device: %+v", id.Metadata)
		}
	}
}

// identitiesMetadata returns a human-readable summary of the metadata in classify output.
func identitiesMetadata(out []scannerv2.ServiceIdentity) []map[string]string {
	var result []map[string]string
	for _, id := range out {
		result = append(result, id.Metadata)
	}
	return result
}
