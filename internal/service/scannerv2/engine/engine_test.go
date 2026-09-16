package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"mibee-steward/internal/service/scannerv2"
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
		// Host addresses only: network + broadcast are dropped (#254).
		{"192.168.1.0/30", 2, 2, false},
		{"192.168.1.0/24", 254, 254, false},
		{"192.168.1.5,192.168.1.6", 2, 2, false},
		{"", 0, 0, true},
		{"not-an-ip", 0, 0, true},
		// Reserved address space is rejected outright (#317) — a /22 of
		// loopback once invented 1022 phantom devices on a test center.
		{"127.8.0.0/22", 0, 0, true},
		{"127.0.0.1", 0, 0, true},
		{"0.0.0.0/0", 0, 0, true},
		{"169.254.0.0/16", 0, 0, true},
		{"255.255.255.255", 0, 0, true},
		{"192.168.1.0/24,127.0.0.1", 0, 0, true},
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

// TestParseScanTargets_ReservedSentinel pins the error contract the API layer
// relies on: reserved-range rejections must be classifiable via isTargetError
// (HTTP 400), so they must wrap ErrReservedTarget.
func TestParseScanTargets_ReservedSentinel(t *testing.T) {
	_, err := parseScanTargets("127.8.0.0/22")
	if !errors.Is(err, ErrReservedTarget) {
		t.Errorf("parseScanTargets reserved spec: err = %v, want ErrReservedTarget", err)
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

// TestEngine_SeedEvidenceYieldsMiotIdentity pins the #377 end-to-end engine
// path: a seeded lease-hostname observation (the ONLY identity channel for
// Mijia devices on real networks) must flow through gather→classify→dispatch
// and land the miot identity + brand on the report — with the embedded
// fingerprint rules, no DB, and a target the active probes can't reach.
func TestEngine_SeedEvidenceYieldsMiotIdentity(t *testing.T) {
	e, err := NewEngine(nil, Config{
		PortSpec:             "",
		MaxConcurrentHosts:   2,
		PerHostTimeout:       3 * time.Second,
		PerProbeTimeout:      300 * time.Millisecond,
		AllowReservedTargets: true,
		SeedEvidence: func(ip string) []scannerv2.Evidence {
			if ip != "192.0.2.50" {
				return nil
			}
			return []scannerv2.Evidence{{
				Source:     "discovery:dhcp_leases",
				Kind:       "hostname",
				IP:         ip,
				Protocol:   "dhcp",
				RawData:    map[string]string{"hostname": "viomi-waterheater-e13_miap5E55"},
				Confidence: 0.8,
				ObservedAt: time.Now(),
			}}
		},
		EBPF: ebpf.Config{Enabled: false},
	}, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	reports, err := e.ScanTargets(context.Background(), "192.0.2.50", false, 0)
	if err != nil {
		t.Fatalf("ScanTargets: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("want 1 report, got %d", len(reports))
	}
	rep := reports[0]
	if !rep.Alive {
		t.Fatal("seed evidence must count toward liveness")
	}
	var miot *scannerv2.ServiceIdentity
	for i := range rep.Services {
		if rep.Services[i].Service == "miot" {
			miot = &rep.Services[i]
		}
	}
	if miot == nil {
		t.Fatalf("miot identity missing from %+v", rep.Services)
	}
	if miot.Metadata["inferred_brand"] != "Viomi" || miot.Metadata["appliance"] != "water heater" {
		t.Errorf("miot metadata = %v", miot.Metadata)
	}
	if rep.Device.Fields["inferred_brand"] != "Viomi" {
		t.Errorf("MiotHandler must fold the brand into device fields, got %+v", rep.Device.Fields)
	}
}
