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
		{"192.168.1.0/30", 2, 2, false},
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

// TestParseScanTargets_ExcludesReservedBounds pins the #254 fix: IPv4 CIDRs
// wider than /31 must not enumerate the network or broadcast address. The
// broadcast IP answered ICMP via every host's fan-out reply and got recorded
// as a phantom always-online device (192.168.63.255 in the wild). /31
// (RFC 3021 point-to-point), /32, and IPv6 keep every address.
func TestParseScanTargets_ExcludesReservedBounds(t *testing.T) {
	got, err := parseScanTargets("192.168.63.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 254 {
		t.Fatalf("/24 = %d ips, want 254", len(got))
	}
	if got[0] != "192.168.63.1" || got[len(got)-1] != "192.168.63.254" {
		t.Fatalf("/24 bounds = [%s, %s], want [.1, .254]", got[0], got[len(got)-1])
	}

	got, err = parseScanTargets("10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("/30 = %v, want [10.0.0.1, 10.0.0.2]", got)
	}

	got, err = parseScanTargets("10.0.0.0/31")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "10.0.0.0" || got[1] != "10.0.0.1" {
		t.Fatalf("/31 = %v, want both RFC 3021 addresses", got)
	}

	got, err = parseScanTargets("10.0.0.7/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "10.0.0.7" {
		t.Fatalf("/32 = %v, want the single host", got)
	}

	// IPv6: no broadcast concept — a /126 enumerates all 4 addresses.
	got, err = parseScanTargets("fd00::/126")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("v6 /126 = %d ips, want 4 (no reserved-bounds exclusion for IPv6)", len(got))
	}
}
