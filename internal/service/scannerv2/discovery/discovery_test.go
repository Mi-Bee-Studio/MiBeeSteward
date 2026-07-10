package discovery

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

// memoryDB opens an in-memory SQLite with the full schema and registers cleanup.
func memoryDB(t *testing.T) *sql.DB {
	t.Helper()
	dbConn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	t.Cleanup(func() { dbConn.Close() })
	return dbConn
}

// --- fake sink + identifier for coordinator tests ---

type fakeSink struct {
	mu       sync.Mutex
	applied  []scannerv2.HostReport
	isNew    bool
}

func (f *fakeSink) Apply(_ context.Context, rep scannerv2.HostReport) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, rep)
	return f.isNew
}

func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

type fakeIdentifier struct {
	reports map[string]scannerv2.HostReport
	alive   map[string]bool
	calls   int
}

func (f *fakeIdentifier) Identify(_ context.Context, ip string) (scannerv2.HostReport, bool) {
	f.calls++
	return f.reports[ip], f.alive[ip]
}

// --- synthesizeReport ---

func TestSynthesizeReport_NoMAC_UnknownType(t *testing.T) {
	ev := NewHostEvent{IP: "10.0.0.5", Source: "arp_cache"}
	rep := synthesizeReport(ev)

	if rep.IP != "10.0.0.5" || !rep.Alive {
		t.Fatalf("expected Alive report for 10.0.0.5, got IP=%q Alive=%v", rep.IP, rep.Alive)
	}
	if rep.Device.Fields["inferred_type"] != "unknown" {
		t.Errorf("expected inferred_type=unknown, got %q", rep.Device.Fields["inferred_type"])
	}
	if len(rep.Evidence) != 0 {
		t.Errorf("expected no mac evidence without MAC, got %d", len(rep.Evidence))
	}
}

func TestSynthesizeReport_WithMAC_AddsEvidenceAndField(t *testing.T) {
	ev := NewHostEvent{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", Source: "router_arp"}
	rep := synthesizeReport(ev)

	if rep.Device.Fields["mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected mac field set, got %q", rep.Device.Fields["mac"])
	}
	foundMac := false
	for _, e := range rep.Evidence {
		if e.Kind == "mac" && e.RawData["mac"] == "aa:bb:cc:dd:ee:ff" {
			foundMac = true
		}
	}
	if !foundMac {
		t.Error("expected a mac Evidence entry")
	}
}

func TestSynthesizeReport_FoldsHints(t *testing.T) {
	ev := NewHostEvent{
		IP:    "10.0.0.6",
		Source: "mdns",
		Hints: map[string]string{"inferred_type": "camera", "discovery_note": "onvif"},
	}
	rep := synthesizeReport(ev)

	if rep.Device.Fields["inferred_type"] != "camera" {
		t.Errorf("expected camera hint folded in, got %q", rep.Device.Fields["inferred_type"])
	}
	if rep.Device.Fields["discovery_note"] != "onvif" {
		t.Errorf("expected discovery_note hint folded in, got %q", rep.Device.Fields["discovery_note"])
	}
}

// --- foldMAC / foldHints ---

func TestFoldMAC_DoesNotClobberExisting(t *testing.T) {
	rep := scannerv2.HostReport{
		IP: "10.0.0.7",
		Device: scannerv2.DeviceRef{
			Fields: map[string]string{"mac": "11:22:33:44:55:66", "inferred_type": "camera"},
		},
	}
	out := foldMAC(rep, "99:88:77:66:55:44")
	if out.Device.Fields["mac"] != "11:22:33:44:55:66" {
		t.Errorf("foldMAC must not clobber an existing mac, got %q", out.Device.Fields["mac"])
	}
}

func TestFoldMAC_AddsWhenMissing(t *testing.T) {
	rep := scannerv2.HostReport{IP: "10.0.0.8", Device: scannerv2.DeviceRef{Fields: map[string]string{}}}
	out := foldMAC(rep, "aa:bb:cc:dd:ee:ff")
	if out.Device.Fields["mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected folded mac, got %q", out.Device.Fields["mac"])
	}
}

func TestFoldHints_DoesNotClobber(t *testing.T) {
	rep := scannerv2.HostReport{
		Device: scannerv2.DeviceRef{Fields: map[string]string{"inferred_type": "camera"}},
	}
	out := foldHints(rep, map[string]string{"inferred_type": "server", "discovery_note": "mdns"})
	// existing type preserved, new hint added
	if out.Device.Fields["inferred_type"] != "camera" {
		t.Errorf("expected existing type preserved, got %q", out.Device.Fields["inferred_type"])
	}
	if out.Device.Fields["discovery_note"] != "mdns" {
		t.Errorf("expected new hint added, got %q", out.Device.Fields["discovery_note"])
	}
}

// --- coordinator handle(): dedup + known-host pre-check ---

// newTestService builds a coordinator wired to an in-memory SQLite DB so the
// known-host pre-check runs against a real (empty) devices table.
func newTestService(t *testing.T, triggerIdentify bool) (*Service, *fakeSink, *fakeIdentifier, *sql.DB) {
	t.Helper()
	dbConn := memoryDB(t) // creates the schema incl. devices + networks
	sink := &fakeSink{isNew: true}
	ident := &fakeIdentifier{reports: map[string]scannerv2.HostReport{}, alive: map[string]bool{}}
	svc := New(Config{Interval: time.Second, TriggerIdentify: triggerIdentify}, sink, ident, dbConn, 0, nil)
	// Run the consumer loop so Emit delivers synchronously.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc.Start(ctx)
	t.Cleanup(svc.Stop)
	return svc, sink, ident, dbConn
}

func TestHandle_KnownHostIsNotProcessed(t *testing.T) {
	svc, sink, ident, dbConn := newTestService(t, true)
	// Insert a device so the known-host pre-check finds it.
	_, err := dbConn.Exec(`INSERT INTO devices (name, ip_address, status) VALUES ('seed', '10.0.0.9', 'online')`)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	// Drain via the consumer loop.
	svc.Emit(NewHostEvent{IP: "10.0.0.9", MAC: "aa:bb:cc:dd:ee:ff", Source: "router_arp"})
	// Allow the consumer goroutine to process.
	time.Sleep(100 * time.Millisecond)

	if sink.count() != 0 {
		t.Errorf("expected no Apply for a known host, got %d", sink.count())
	}
	if ident.calls != 0 {
		t.Errorf("expected no Identify call for a known host, got %d", ident.calls)
	}
}

// TestHandle_KnownMACDifferentIP_NoIdentify guards the DHCP-churn regression:
// a device recorded as .143 (MAC aa:..) that next appears as .144 (same MAC,
// new lease) must NOT be treated as new. Without the MAC-primary pre-check it
// would trigger a full identify scan every poll cycle — a feedback loop that
// destabilized the memory-constrained test VM (75 restarts observed).
func TestHandle_KnownMACDifferentIP_NoIdentify(t *testing.T) {
	svc, sink, ident, dbConn := newTestService(t, true)
	// Device known under a DIFFERENT IP but SAME MAC as the discovery event.
	_, err := dbConn.Exec(`INSERT INTO devices (name, ip_address, mac_address, status) VALUES ('roamer', '10.0.0.50', 'aa:bb:cc:dd:ee:ff', 'online')`)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	// Discovery reports the SAME MAC on a NEW IP — must be recognized as known.
	svc.Emit(NewHostEvent{IP: "10.0.0.99", MAC: "aa:bb:cc:dd:ee:ff", Source: "arp_cache"})
	time.Sleep(150 * time.Millisecond)

	if sink.count() != 0 {
		t.Errorf("expected no Apply for a known MAC under a new IP, got %d", sink.count())
	}
	if ident.calls != 0 {
		t.Errorf("expected no Identify call for a known MAC, got %d", ident.calls)
	}
}


func TestHandle_NewHost_TriggersIdentifyAndApply(t *testing.T) {
	svc, sink, ident, _ := newTestService(t, true)
	ident.alive["10.0.0.10"] = true
	ident.reports["10.0.0.10"] = scannerv2.HostReport{
		IP: "10.0.0.10", Alive: true,
		Device: scannerv2.DeviceRef{Fields: map[string]string{"inferred_type": "camera"}},
	}
	svc.Emit(NewHostEvent{IP: "10.0.0.10", MAC: "11:22:33:44:55:66", Source: "router_arp"})
	time.Sleep(150 * time.Millisecond)

	if ident.calls != 1 {
		t.Errorf("expected 1 Identify call, got %d", ident.calls)
	}
	if sink.count() != 1 {
		t.Fatalf("expected 1 Apply, got %d", sink.count())
	}
	// The identify report should carry the source MAC folded in.
	applied := sink.applied[0]
	if applied.Device.Fields["mac"] != "11:22:33:44:55:66" {
		t.Errorf("expected folded mac on identified report, got %q", applied.Device.Fields["mac"])
	}
}

func TestHandle_NewHost_TriggerIdentifyFalse_SynthesizesOnly(t *testing.T) {
	svc, sink, ident, _ := newTestService(t, false)
	svc.Emit(NewHostEvent{IP: "10.0.0.11", MAC: "aa:bb:cc:dd:ee:ff", Source: "arp_cache"})
	time.Sleep(150 * time.Millisecond)

	if ident.calls != 0 {
		t.Errorf("expected no Identify when TriggerIdentify=false, got %d", ident.calls)
	}
	if sink.count() != 1 {
		t.Fatalf("expected 1 synthesized Apply, got %d", sink.count())
	}
	if sink.applied[0].Device.Fields["inferred_type"] != "unknown" {
		t.Errorf("expected unknown type, got %q", sink.applied[0].Device.Fields["inferred_type"])
	}
}

func TestHandle_RecentDedupSuppressesBurst(t *testing.T) {
	svc, sink, ident, _ := newTestService(t, false)
	// Fire the same IP twice in quick succession.
	svc.Emit(NewHostEvent{IP: "10.0.0.12", Source: "router_arp"})
	svc.Emit(NewHostEvent{IP: "10.0.0.12", Source: "arp_cache"})
	time.Sleep(150 * time.Millisecond)

	if sink.count() != 1 {
		t.Errorf("expected dedup to collapse burst to 1 Apply, got %d", sink.count())
	}
	if ident.calls != 0 {
		t.Errorf("expected no identify calls in no-identify mode")
	}
}

// --- router_arp source diff ---

func TestRouterARPSweep_DiffsAndEmitsOnlyNew(t *testing.T) {
	svc, sink, _, _ := newTestService(t, false)
	src := &RouterARPSource{
		routers:   []string{"dummy"}, // walk will fail; we inject the table directly
		community: "public",
		timeout:   time.Second,
		interval:  time.Hour,
		svc:       svc,
		logger:    nil,
		previous:  map[string]string{},
	}

	// First sweep: two hosts both new.
	first := map[string]string{"10.0.0.20": "aa:aa:aa:aa:aa:aa", "10.0.0.21": "bb:bb:bb:bb:bb:bb"}
	src.injectTableForTest(first)
	time.Sleep(150 * time.Millisecond)
	if got := sink.count(); got != 2 {
		t.Fatalf("first sweep: expected 2 emits, got %d", got)
	}

	// Second sweep: one new, one unchanged.
	second := map[string]string{
		"10.0.0.20": "aa:aa:aa:aa:aa:aa",
		"10.0.0.21": "bb:bb:bb:bb:bb:bb",
		"10.0.0.22": "cc:cc:cc:cc:cc:cc",
	}
	src.injectTableForTest(second)
	time.Sleep(150 * time.Millisecond)
	if got := sink.count(); got != 3 { // 2 + 1 new
		t.Errorf("second sweep: expected 1 new emit (total 3), got %d", got)
	}
}

// --- mDNS / SSDP hint parsing ---

func TestParseMDNSHints(t *testing.T) {
	cases := []struct {
		name   string
		packet string
		want   string
	}{
		{"onvif → camera", "random_header_onvif._tcp.local_tail", "camera"},
		{"rtsp → camera", "foo._rtsp._tcp.local", "camera"},
		{"ipp → printer", "_ipp._tcp.local", "printer"},
		{"smb → nas", "_smb._tcp.local", "nas"},
		{"nothing", "just_some_host.local", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hints := parseMDNSHints([]byte(c.packet))
			if c.want == "" {
				if hints != nil {
					t.Errorf("expected no hints, got %v", hints)
				}
				return
			}
			if hints["inferred_type"] != c.want {
				t.Errorf("expected inferred_type=%s, got %v", c.want, hints)
			}
		})
	}
}

func TestParseSSDPHints(t *testing.T) {
	cases := []struct {
		name   string
		packet string
		want   string
	}{
		{"MediaRenderer", "NOTIFY * HTTP/1.1\r\nSERVER: foo\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n", "mediarenderer"},
		{"InternetGatewayDevice → router", "LOCATION: http://1.2.3.4/desc.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n", "router"},
		{"nothing", "M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hints := parseSSDPHints([]byte(c.packet))
			if c.want == "" {
				if hints != nil {
					t.Errorf("expected no hints, got %v", hints)
				}
				return
			}
			if hints["inferred_type"] != c.want {
				t.Errorf("expected inferred_type=%s, got %v", c.want, hints)
			}
		})
	}
}
