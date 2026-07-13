package engine

import (
	"testing"

	"mibee-steward/internal/service/scannerv2/ebpf"
)

func TestParseScanTargets_Formats(t *testing.T) {
	cases := []struct {
		in      string
		min     int // expected minimum count
		exact   int // if >0, expect exact count
		wantErr bool
	}{
		{"192.168.1.5", 1, 1, false},
		{"192.168.1.1-5", 5, 5, false},
		{"192.168.1.0/30", 4, 4, false},
		{"192.168.1.5,192.168.1.6", 2, 2, false},
		{"", 0, 0, true},
		{"not-an-ip", 0, 0, true},
	}
	for _, c := range cases {
		got, err := parseScanTargets(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseScanTargets(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseScanTargets(%q) error: %v", c.in, err)
			continue
		}
		if c.exact > 0 && len(got) != c.exact {
			t.Errorf("parseScanTargets(%q) = %d ips, want %d (%v)", c.in, len(got), c.exact, got)
		}
		if len(got) < c.min {
			t.Errorf("parseScanTargets(%q) = %d ips, want ≥%d", c.in, len(got), c.min)
		}
	}
}

func TestNewEngine_AssemblesAllLayers(t *testing.T) {
	// Construct an engine with a nil DB (no persistence) and verify the
	// registry contains the default probes/classifiers/handlers.
	e, err := NewEngine(nil, Config{
		PortSpec:           "22,80",
		MaxConcurrentHosts: 10,
		PerHostTimeout:     0, // default applied
		EBPF:               ebpf.Config{Enabled: false},
	}, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// Registry should have ≥6 probes (active set) + 1 eBPF observer.
	if got := len(e.Registry.Probes()); got < 6 {
		t.Errorf("expected ≥6 probes, got %d", got)
	}
	// Classifiers: RuleClassifier (data-driven, embedded defaults) + 4 logic-
	// retained (SNMP bitmask, Camera cross-evidence, Database, RemoteAccess).
	// The pure-data classifiers are now rule files, not registered as code.
	if got := len(e.Registry.Classifiers()); got < 5 {
		t.Errorf("expected ≥5 classifiers, got %d", got)
	}
	if got := len(e.Registry.Handlers()); got < 7 {
		t.Errorf("expected ≥7 handlers, got %d", got)
	}
	// Defaults applied.
	if e.Orchestrator.MaxConcurrentHosts() != 10 {
		t.Errorf("MaxConcurrentHosts = %d, want 10", e.Orchestrator.MaxConcurrentHosts())
	}
	if e.Orchestrator.PerHostTimeout() == 0 {
		t.Error("PerHostTimeout default not applied")
	}
}
