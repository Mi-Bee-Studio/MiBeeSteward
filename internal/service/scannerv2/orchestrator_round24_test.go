// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package scannerv2

import (
	"context"
	"testing"
	"time"
)

// TestOrchestrator_MACResolverPostScanSynthesis covers the post-gather ARP
// re-read: when no probe collected a MAC (cold neighbour cache), the
// macResolver's answer is synthesized into an active:arp evidence — with the
// OUI vendor keys when the resolver knows them, without when it doesn't, and
// skipped entirely when it has nothing.
func TestOrchestrator_MACResolverPostScanSynthesis(t *testing.T) {
	run := func(resolverMAC, device, vendor, oui string) HostReport {
		repo := newRecordRepo()
		reg := NewRegistry()
		reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
			{Kind: "port_open", IP: "10.0.0.7", Port: 22, Protocol: "tcp"},
		}})
		orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 1}, nil)
		orch.SetMACResolver(func(_ string) (mac, dev, vend, ouiPrefix string) {
			return resolverMAC, device, vendor, oui
		})
		return orch.Run(context.Background(), "10.0.0.7", ProbeHint{Timeout: time.Second})
	}

	// Full answer: synthesized evidence carries mac + device + OUI vendor keys.
	rep := run("aa:bb:cc:dd:ee:ff", "nas-1", "Synology", "aa:bb:cc")
	var synth *Evidence
	for i := range rep.Evidence {
		if rep.Evidence[i].Kind == "mac" && rep.Evidence[i].Source == "active:arp" {
			synth = &rep.Evidence[i]
		}
	}
	if synth == nil {
		t.Fatal("expected a synthesized mac evidence from the post-scan resolver")
	}
	for _, k := range []string{"mac", "device", "vendor", "oui_prefix", "oui_vendor"} {
		if synth.RawData[k] == "" {
			t.Errorf("synthesized evidence missing key %q: %v", k, synth.RawData)
		}
	}
	if synth.Confidence != 1.0 {
		t.Errorf("synthesized evidence confidence = %v, want 1.0", synth.Confidence)
	}

	// MAC known but vendor unknown: evidence appears WITHOUT the vendor keys.
	rep = run("aa:bb:cc:dd:ee:01", "", "", "")
	synth = nil
	for i := range rep.Evidence {
		if rep.Evidence[i].Kind == "mac" && rep.Evidence[i].Source == "active:arp" {
			synth = &rep.Evidence[i]
		}
	}
	if synth == nil {
		t.Fatal("expected synthesized mac evidence without vendor")
	}
	if _, has := synth.RawData["vendor"]; has {
		t.Errorf("vendor key must be absent when the resolver has no vendor: %v", synth.RawData)
	}

	// Resolver has nothing: no synthesis, the probe evidence passes through.
	rep = run("", "", "", "")
	for _, e := range rep.Evidence {
		if e.Kind == "mac" {
			t.Fatalf("no mac evidence expected when the resolver is empty, got %+v", e)
		}
	}
	if len(rep.Evidence) != 1 {
		t.Fatalf("expected the original probe evidence only, got %d", len(rep.Evidence))
	}
}
