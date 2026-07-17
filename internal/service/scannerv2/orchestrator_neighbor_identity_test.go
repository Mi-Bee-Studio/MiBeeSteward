package scannerv2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// enrichRecordRepo is a mock Repository that records EnrichDeviceByMAC calls.
// It delegates to NoopRepository for methods the test doesn't need.
type enrichRecordRepo struct {
	NoopRepository
	enrichCalls []enrichCall
}

type enrichCall struct {
	mac    string
	fields map[string]string
}

func (r *enrichRecordRepo) EnrichDeviceByMAC(_ context.Context, mac string, fields map[string]string) error {
	r.enrichCalls = append(r.enrichCalls, enrichCall{mac: mac, fields: fields})
	return nil
}

// TestNeighborIdentityEnrichmentPass verifies that the orchestrator's enrichment
// pass inside the dispatch persist block calls EnrichDeviceByMAC for neighbor
// evidence carrying identity keys (sys_name, sys_desc, platform).
func TestNeighborIdentityEnrichmentPass(t *testing.T) {
	repo := &enrichRecordRepo{}
	reg := NewRegistry()

	// Register a probe that emits neighbor evidence with identity keys.
	reg.RegisterProbe(stubProbe{name: "active:lldp", ev: []Evidence{
		{
			Kind: "neighbor",
			IP:   "10.0.0.1",
			RawData: map[string]string{
				"neighbor_mac": "aa:bb:cc:dd:ee:01",
				"protocol":     "LLDP",
				"sys_name":     "switch-a.example.com",
				"sys_desc":     "Cisco IOS Software, C2960S Software",
				"platform":     "cisco",
			},
		},
		// Second neighbor with more identity keys.
		{
			Kind: "neighbor",
			IP:   "10.0.0.1",
			RawData: map[string]string{
				"neighbor_mac": "aa:bb:cc:dd:ee:02",
				"protocol":     "LLDP",
				"sys_name":     "router-b.example.com",
				"sys_desc":     "Juniper Networks",
				"platform":     "juniper",
			},
		},
	}})
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 80, Protocol: "tcp"},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 2, MaxCascadeDepth: 0}, nil)
	// Set up the inference callback: this is where fingerprint logic maps
	// neighbor evidence to device fields.
	orch.SetNeighborIdentityInfer(func(_, neighborMAC, _, _, _ string) map[string]string {
		if neighborMAC == "aa:bb:cc:dd:ee:01" {
			return map[string]string{
				"vendor": "Cisco",
				"model":  "WS-C2960S",
				"type":   "switch",
			}
		}
		if neighborMAC == "aa:bb:cc:dd:ee:02" {
			return map[string]string{
				"vendor":   "Juniper",
				"model":    "MX480",
				"type":     "router",
				"hostname": "router-b",
			}
		}
		return nil
	})

	report := orch.Run(context.Background(), "10.0.0.1", ProbeHint{})
	require.True(t, report.Alive, "surveyed host should be alive")

	// Enrichment pass ran: two neighbors with identity keys → two calls.
	require.Len(t, repo.enrichCalls, 2, "expected 2 enrich calls for 2 identity-carrying neighbors")

	// First neighbor: aa:bb:cc:dd:ee:01 → Cisco WS-C2960S switch.
	call1 := repo.enrichCalls[0]
	require.Equal(t, "aa:bb:cc:dd:ee:01", call1.mac)
	require.Equal(t, "Cisco", call1.fields["vendor"])
	require.Equal(t, "WS-C2960S", call1.fields["model"])
	require.Equal(t, "switch", call1.fields["type"])

	// Second neighbor: aa:bb:cc:dd:ee:02 → Juniper MX480 router.
	call2 := repo.enrichCalls[1]
	require.Equal(t, "aa:bb:cc:dd:ee:02", call2.mac)
	require.Equal(t, "Juniper", call2.fields["vendor"])
	require.Equal(t, "MX480", call2.fields["model"])
	require.Equal(t, "router", call2.fields["type"])
	require.Equal(t, "router-b", call2.fields["hostname"])
}

// TestNeighborIdentityEnrichment_NoIdentityKeys verifies that neighbor evidence
// WITHOUT identity keys (sys_name, sys_desc, platform) does NOT trigger enrichment.
func TestNeighborIdentityEnrichment_NoIdentityKeys(t *testing.T) {
	repo := &enrichRecordRepo{}
	reg := NewRegistry()

	reg.RegisterProbe(stubProbe{name: "active:bridge", ev: []Evidence{
		{
			Kind: "neighbor",
			IP:   "10.0.0.1",
			RawData: map[string]string{
				"neighbor_mac": "aa:bb:cc:dd:ee:03",
				"protocol":     "Bridge-MIB",
				"local_port":   "5",
			},
			// No sys_name/sys_desc/platform — no identity to enrich.
		},
	}})
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 80, Protocol: "tcp"},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 2, MaxCascadeDepth: 0}, nil)
	orch.SetNeighborIdentityInfer(func(_, _, _, _, _ string) map[string]string {
		return map[string]string{"vendor": "test"}
	})

	report := orch.Run(context.Background(), "10.0.0.1", ProbeHint{})
	require.True(t, report.Alive, "surveyed host should be alive")
	// No enrichment calls — identity keys absent in all neighbor evidence.
	require.Empty(t, repo.enrichCalls, "expected no enrich calls when identity keys are absent")
}

// TestNeighborIdentityEnrichment_UnrelatedEvidence verifies that non-neighbor
// evidence (port_open, banner, snmp, etc.) does NOT trigger enrichment.
func TestNeighborIdentityEnrichment_UnrelatedEvidence(t *testing.T) {
	repo := &enrichRecordRepo{}
	reg := NewRegistry()

	// Only non-neighbor evidence — nothing should enrich.
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 80, Protocol: "tcp"},
		{Kind: "banner", IP: "10.0.0.1", Port: 80, RawData: map[string]string{"banner": "nginx"}},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 2, MaxCascadeDepth: 0}, nil)
	orch.SetNeighborIdentityInfer(func(_, _, _, _, _ string) map[string]string {
		return map[string]string{"vendor": "test"}
	})

	report := orch.Run(context.Background(), "10.0.0.1", ProbeHint{})
	require.True(t, report.Alive, "surveyed host should be alive")
	require.Empty(t, repo.enrichCalls, "expected no enrich calls when no neighbor evidence exists")
}

// TestNeighborIdentityEnrichment_NilCallback verifies that a nil
// neighborIdentityInfer callback (default) skips enrichment entirely.
func TestNeighborIdentityEnrichment_NilCallback(t *testing.T) {
	repo := &enrichRecordRepo{}
	reg := NewRegistry()

	reg.RegisterProbe(stubProbe{name: "active:lldp", ev: []Evidence{
		{
			Kind: "neighbor",
			IP:   "10.0.0.1",
			RawData: map[string]string{
				"neighbor_mac": "aa:bb:cc:dd:ee:04",
				"protocol":     "LLDP",
				"sys_name":     "some-switch",
				"platform":     "cisco",
			},
		},
	}})
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 80, Protocol: "tcp"},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	// No SetNeighborIdentityInfer → callback remains nil.
	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 2, MaxCascadeDepth: 0}, nil)

	report := orch.Run(context.Background(), "10.0.0.1", ProbeHint{})
	require.True(t, report.Alive, "surveyed host should be alive")
	require.Empty(t, repo.enrichCalls, "expected no enrich calls when callback is nil")
}

// TestNeighborIdentityEnrichment_NoRepo verifies that when repo is nil
// (no persistence wired), the enrichment pass is skipped without panic.
func TestNeighborIdentityEnrichment_NoRepo(t *testing.T) {
	reg := NewRegistry()

	reg.RegisterProbe(stubProbe{name: "active:lldp", ev: []Evidence{
		{
			Kind: "neighbor",
			IP:   "10.0.0.1",
			RawData: map[string]string{
				"neighbor_mac": "aa:bb:cc:dd:ee:05",
				"protocol":     "LLDP",
				"sys_name":     "test-switch",
				"platform":     "generic",
			},
		},
	}})
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 80, Protocol: "tcp"},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	// Repo is nil — dispatch persist block is skipped entirely.
	orch := NewOrchestrator(reg, nil, OrchestratorConfig{MaxConcurrentHosts: 2, MaxCascadeDepth: 0}, nil)
	orch.SetNeighborIdentityInfer(func(_, _, _, _, _ string) map[string]string {
		return map[string]string{"vendor": "test"}
	})

	report := orch.Run(context.Background(), "10.0.0.1", ProbeHint{})
	require.True(t, report.Alive, "surveyed host should be alive")
	// No panic — enrichment pass skipped because repo is nil.
}

// TestNeighborIdentityEnrichment_CallbackReturnsNil verifies that when the
// inference callback returns nil for a neighbor, no EnrichDeviceByMAC call
// is made for that neighbor.
func TestNeighborIdentityEnrichment_CallbackReturnsNil(t *testing.T) {
	repo := &enrichRecordRepo{}
	reg := NewRegistry()

	reg.RegisterProbe(stubProbe{name: "active:lldp", ev: []Evidence{
		{
			Kind: "neighbor",
			IP:   "10.0.0.1",
			RawData: map[string]string{
				"neighbor_mac": "aa:bb:cc:dd:ee:06",
				"protocol":     "LLDP",
				"sys_name":     "unknown-device",
			},
		},
		// Another neighbor where callback returns fields.
		{
			Kind: "neighbor",
			IP:   "10.0.0.1",
			RawData: map[string]string{
				"neighbor_mac": "aa:bb:cc:dd:ee:07",
				"protocol":     "CDP",
				"sys_name":     "known-device",
				"platform":     "cisco",
			},
		},
	}})
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 80, Protocol: "tcp"},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	// Return nil for the first neighbor, fields for the second.
	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 2, MaxCascadeDepth: 0}, nil)
	orch.SetNeighborIdentityInfer(func(_, neighborMAC, _, _, _ string) map[string]string {
		if neighborMAC == "aa:bb:cc:dd:ee:07" {
			return map[string]string{"vendor": "Cisco", "type": "switch"}
		}
		return nil
	})

	report := orch.Run(context.Background(), "10.0.0.1", ProbeHint{})
	require.True(t, report.Alive, "surveyed host should be alive")

	// Only the second neighbor (where callback returned fields) triggers enrichment.
	require.Len(t, repo.enrichCalls, 1, "expected 1 enrich call (second neighbor only)")
	require.Equal(t, "aa:bb:cc:dd:ee:07", repo.enrichCalls[0].mac)
}
