package scannerv2

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"
)

// --- stub probe: emits canned evidence ---

type stubProbe struct {
	name string
	ev   []Evidence
	err  error
}

func (s stubProbe) Name() string { return s.name }
func (s stubProbe) Probe(_ context.Context, _ string, _ ProbeHint) ([]Evidence, error) {
	return s.ev, s.err
}

// --- stub classifier: asserts a service if matching evidence kind present ---

type kindClassifier struct {
	service string
	kind    string
}

func (k kindClassifier) Service() string { return k.service }
func (k kindClassifier) Classify(ev []Evidence) []ServiceIdentity {
	var out []ServiceIdentity
	for _, e := range ev {
		if e.Kind == k.kind {
			out = append(out, ServiceIdentity{
				Service:    k.service,
				Port:       e.Port,
				Confidence: 0.9,
				Evidence:   []Evidence{e},
			})
		}
	}
	return out
}

// --- stub handler: records collect/enrich calls and can trigger ---

type stubHandler struct {
	service   string
	triggers  []Trigger // emitted on every Collect
	collects  []string  // record of services collected
	heartbeat *HeartbeatSpec
}

func (h *stubHandler) Service() string { return h.service }
func (h *stubHandler) GenerateHeartbeat(_ ServiceContext) *HeartbeatSpec {
	return h.heartbeat
}
func (h *stubHandler) Collect(_ context.Context, svc ServiceContext) (CollectedData, []Trigger, error) {
	h.collects = append(h.collects, svc.Identity.Service)
	cd := concreteData{s: svc.Identity.Service}
	return cd, h.triggers, nil
}
func (h *stubHandler) EnrichDevice(svc ServiceContext, _ CollectedData) {
	if svc.Device.Fields == nil {
		svc.Device.Fields = map[string]string{}
	}
	svc.Device.Fields["touched_by"] = svc.Device.Fields["touched_by"] + svc.Identity.Service + ","
}

type concreteData struct{ s string }

func (c concreteData) Service() string { return c.s }

// --- recording repository ---

type recordRepo struct {
	evidence   []Evidence
	services   map[string][]ServiceIdentity
	devices    map[string]DeviceRef
	heartbeats map[string][]HeartbeatSpec
}

func newRecordRepo() *recordRepo {
	return &recordRepo{
		services:   map[string][]ServiceIdentity{},
		devices:    map[string]DeviceRef{},
		heartbeats: map[string][]HeartbeatSpec{},
	}
}

func (r *recordRepo) RecordEvidence(_ context.Context, ev []Evidence) error {
	r.evidence = append(r.evidence, ev...)
	return nil
}
func (r *recordRepo) RecordServices(_ context.Context, ip string, svcs []ServiceIdentity) error {
	r.services[ip] = svcs
	return nil
}
func (r *recordRepo) RecordDevice(_ context.Context, ip string, d DeviceRef) error {
	r.devices[ip] = d
	return nil
}
func (r *recordRepo) RecordHeartbeats(_ context.Context, ip string, specs []HeartbeatSpec) error {
	r.heartbeats[ip] = specs
	return nil
}

func TestOrchestrator_GatherClassifyDispatch(t *testing.T) {
	// Two probes, one classifier per evidence kind, two handlers with a
	// cascade from http → prometheus.
	repo := newRecordRepo()
	reg := NewRegistry()
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 8080, Protocol: "tcp"},
		{Kind: "banner", IP: "10.0.0.1", Port: 8080, RawData: map[string]string{"banner": "HTTP/1.1"}},
	}})
	reg.RegisterProbe(stubProbe{name: "active:snmp", ev: []Evidence{
		{Kind: "snmp", IP: "10.0.0.1", RawData: map[string]string{"sys_descr": "Linux"}},
	}})

	reg.RegisterClassifier(kindClassifier{service: "http", kind: "banner"})
	reg.RegisterClassifier(kindClassifier{service: "snmp", kind: "snmp"})

	httpH := &stubHandler{service: "http", heartbeat: &HeartbeatSpec{Method: "http", Target: "http://10.0.0.1:8080"},
		triggers: []Trigger{{Service: "prometheus", Port: 9090}}}
	promH := &stubHandler{service: "prometheus", heartbeat: &HeartbeatSpec{Method: "http", Target: "http://10.0.0.1:9090/metrics"}}
	snmpH := &stubHandler{service: "snmp", heartbeat: &HeartbeatSpec{Method: "snmp", Target: "10.0.0.1"}}
	reg.RegisterHandler(httpH)
	reg.RegisterHandler(promH)
	reg.RegisterHandler(snmpH)

	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 2, MaxCascadeDepth: 5}, nil)
	report := orch.Run(context.Background(), "10.0.0.1", ProbeHint{Timeout: time.Second})

	if !report.Alive {
		t.Fatal("host should be alive (has evidence)")
	}
	if len(report.Evidence) != 3 {
		t.Fatalf("expected 3 evidence, got %d", len(report.Evidence))
	}
	// Two services classified: http, snmp.
	svcs := serviceNames(report.Services)
	sort.Strings(svcs)
	if !reflect.DeepEqual(svcs, []string{"http", "snmp"}) {
		t.Fatalf("expected services [http snmp], got %v", svcs)
	}
	// Cascade: prometheus handler ran (triggered by http).
	if !containsStr(httpH.collects, "http") {
		t.Errorf("http handler not invoked: %v", httpH.collects)
	}
	if !containsStr(promH.collects, "prometheus") {
		t.Errorf("prometheus handler not cascaded: %v", promH.collects)
	}
	// Only depth-0 heartbeats generated: http + snmp (NOT prometheus, which is depth-1).
	if len(report.Heartbeats) != 2 {
		t.Fatalf("expected 2 depth-0 heartbeats, got %d (%v)", len(report.Heartbeats), report.Heartbeats)
	}
	// Device enriched by http, snmp (depth-0, service-sorted) then prometheus
	// (cascaded from http). Order: http, snmp, prometheus.
	if got := report.Device.Fields["touched_by"]; got != "http,snmp,prometheus," {
		t.Errorf("device enrichment order/content wrong: %q", got)
	}
	// Persistence recorded evidence + services + device + heartbeats.
	if len(repo.evidence) != 3 {
		t.Errorf("repo did not record all evidence: %d", len(repo.evidence))
	}
	if len(repo.services["10.0.0.1"]) != 2 {
		t.Errorf("repo did not record services")
	}
	if repo.devices["10.0.0.1"].IP == "" {
		t.Errorf("repo did not record device")
	}
}

func TestOrchestrator_CycleGuard(t *testing.T) {
	// Two handlers that trigger each other → would loop forever without guard.
	repo := newRecordRepo()
	reg := NewRegistry()
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.2", Port: 22, Protocol: "tcp"},
		{Kind: "banner", IP: "10.0.0.2", Port: 22, RawData: map[string]string{"banner": "SSH-2.0"}},
	}})
	reg.RegisterClassifier(kindClassifier{service: "ssh", kind: "banner"})

	// ssh → ssh (self-cycle) and a ssh → telnet → ssh chain; all must be broken.
	reg.RegisterHandler(&stubHandler{
		service:  "ssh",
		triggers: []Trigger{{Service: "telnet", Port: 23}, {Service: "ssh", Port: 22}},
	})
	reg.RegisterHandler(&stubHandler{
		service:  "telnet",
		triggers: []Trigger{{Service: "ssh", Port: 22}},
	})

	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxCascadeDepth: 5}, nil)
	done := make(chan struct{})
	go func() {
		_ = orch.Run(context.Background(), "10.0.0.2", ProbeHint{Timeout: time.Second})
		close(done)
	}()
	select {
	case <-done:
		// good — did not hang
	case <-time.After(2 * time.Second):
		t.Fatal("orchestrator hung — cycle guard failed")
	}
}

func TestOrchestrator_DeadHostShortCircuit(t *testing.T) {
	// A probe that errors and returns no evidence → host not alive, no
	// classification, no dispatch.
	reg := NewRegistry()
	reg.RegisterProbe(stubProbe{name: "active:tcp", err: errors.New("boom")})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "banner"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	orch := NewOrchestrator(reg, newRecordRepo(), OrchestratorConfig{}, nil)
	report := orch.Run(context.Background(), "10.0.0.3", ProbeHint{})

	if report.Alive {
		t.Error("host with zero evidence should not be alive")
	}
	if len(report.Services) != 0 {
		t.Errorf("dead host should have no services, got %d", len(report.Services))
	}
}

func TestRegistryDeterminism(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterProbe(stubProbe{name: "zeta", ev: nil})
	reg.RegisterProbe(stubProbe{name: "alpha", ev: nil})
	reg.RegisterProbe(stubProbe{name: "mid", ev: nil})

	got := make([]string, 0, 3)
	for _, p := range reg.Probes() {
		got = append(got, p.Name())
	}
	want := []string{"alpha", "mid", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Probes() not sorted: got %v want %v", got, want)
	}
}

func serviceNames(s []ServiceIdentity) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = v.Service
	}
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestSSDPServerToBrand_ShortHeaders(t *testing.T) {
	// Regression: a SERVER header with fewer than 3 whitespace tokens must not
	// panic (previously tokens[2:] sliced out of bounds).
	cases := []string{
		"",                                // empty
		"Linux/4.4",                       // single token
		"Linux/4.4 UPnP/1.1",              // two tokens
		"Linux/4.4 UPnP/1.1 MyDevice/1.0", // full (3 tokens)
	}
	// None of these should panic.
	for _, c := range cases {
		_ = ssdpServerToBrand(c)
		_ = ssdpServerToOS(c)
	}
	// The full header should yield "MyDevice".
	if got := ssdpServerToBrand("Linux/4.4 UPnP/1.1 MyDevice/1.0"); got != "MyDevice" {
		t.Errorf("full header brand = %q, want MyDevice", got)
	}
	// The OS prefix should be extracted.
	if got := ssdpServerToOS("Linux/4.4 UPnP/1.1 MyDevice/1.0"); got != "Linux" {
		t.Errorf("OS = %q, want Linux", got)
	}
	// Short headers yield empty brand.
	if got := ssdpServerToBrand("Linux/4.4"); got != "" {
		t.Errorf("short header brand = %q, want empty", got)
	}
}

func TestIndexByteAndSplitWS(t *testing.T) {
	if indexByte("abc", 'b') != 1 {
		t.Error("indexByte")
	}
	if indexByte("abc", 'z') != -1 {
		t.Error("indexByte miss")
	}
	got := splitWS("a  b\tc")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("splitWS = %v", got)
	}
}
