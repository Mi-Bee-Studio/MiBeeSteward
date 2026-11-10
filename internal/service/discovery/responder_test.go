// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// probe sends one UDP datagram to the responder and returns the reply (or
// nil on timeout). Keeping the probe logic in the test (instead of a mock)
// exercises the real socket path the App uses.
func probe(t *testing.T, port int, payload string) []byte {
	t.Helper()
	c, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("dial responder: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("send probe: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		return nil // timeout: caller asserts on absence
	}
	return buf[:n]
}

// startResponderOn binds a responder to the exact UDP port given (0 =
// ephemeral) and registers cleanup. Exposed through the internal seam so
// tests can pin ports (bind-conflict coverage) while production passes the
// configured port.
func startResponderOn(t *testing.T, port int, id, name string, apiPort int, tls bool) *Responder {
	t.Helper()
	r := NewResponder(id, name, apiPort, tls, port)
	if err := r.Start(); err != nil {
		t.Fatalf("responder Start: %v", err)
	}
	if r.Port() == 0 {
		t.Fatalf("responder did not report its bound port")
	}
	t.Cleanup(func() { r.Stop() })
	return r
}

// The reply must carry the explicit type ("steward" — the App's
// default-absent semantics mean a missing type is treated as an NVR, so a
// steward reply without type is silently misclassified) plus the shared
// frame fields.
func TestResponderRepliesWithType(t *testing.T) {
	r := startResponderOn(t, 0, "id-steward-1", "steward 主控", 8080, true)

	reply := probe(t, r.Port(), DiscoveryProbeV1)
	if reply == nil {
		t.Fatalf("no reply to %q", DiscoveryProbeV1)
	}

	var got struct {
		V    int    `json:"v"`
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
		API  int    `json:"api"`
		TLS  bool   `json:"tls"`
	}
	if err := json.Unmarshal(reply, &got); err != nil {
		t.Fatalf("decode reply %q: %v", reply, err)
	}
	if got.V != 1 || got.Type != "steward" || got.ID != "id-steward-1" ||
		got.Name != "steward 主控" || got.API != 8080 || !got.TLS {
		t.Fatalf("reply payload mismatch: %+v", got)
	}
}

func TestResponderIgnoresWrongProbe(t *testing.T) {
	r := startResponderOn(t, 0, "id-1", "n", 8080, false)
	if reply := probe(t, r.Port(), "HELLO-DISC"); reply != nil {
		t.Fatalf("answered a non-discovery datagram: %q", reply)
	}
	// Near-miss: prefix matches but is not the exact probe frame.
	if reply := probe(t, r.Port(), DiscoveryProbeV1+" extra"); reply != nil {
		t.Fatalf("answered an extended frame: %q", reply)
	}
}

func TestResponderDropsOversized(t *testing.T) {
	r := startResponderOn(t, 0, "id-1", "n", 8080, false)
	big := DiscoveryProbeV1 + strings.Repeat("A", 200)
	if reply := probe(t, r.Port(), big); reply != nil {
		t.Fatalf("answered an oversized datagram: %q", reply)
	}
}

// A probe flood must not turn the responder into a broadcast amplification
// vector: same source IP replies at most once per throttle window, and
// recovers after the window passes.
func TestResponderThrottlesPerSource(t *testing.T) {
	r := startResponderOn(t, 0, "id-1", "n", 8080, false)

	if reply := probe(t, r.Port(), DiscoveryProbeV1); reply == nil {
		t.Fatalf("first probe got no reply")
	}
	if reply := probe(t, r.Port(), DiscoveryProbeV1); reply != nil {
		t.Fatalf("second probe within throttle window got a reply: %q", reply)
	}
	time.Sleep(replyMinInterval + 150*time.Millisecond)
	if reply := probe(t, r.Port(), DiscoveryProbeV1); reply == nil {
		t.Fatalf("probe after throttle window got no reply")
	}
}

// Start must fail cleanly on a busy port (bind conflict), not panic — the
// routes wiring logs and continues without the responder (snmptrap posture:
// a discovery convenience never blocks boot).
func TestResponderBindConflictFailsCleanly(t *testing.T) {
	// Find a free UDP port by binding and closing a socket (UDP has no
	// TIME_WAIT, so the closed port is immediately rebindable).
	probeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := probeConn.LocalAddr().(*net.UDPAddr).Port
	_ = probeConn.Close()

	r1 := NewResponder("id-1", "n", 8080, false, port)
	if err := r1.Start(); err != nil {
		t.Fatalf("first responder bind :%d: %v", port, err)
	}
	defer r1.Stop()

	r2 := NewResponder("id-2", "n2", 8081, false, port)
	if err := r2.Start(); err == nil {
		r2.Stop()
		t.Fatalf("second responder bound held port :%d without error", port)
	}
	if r2.Port() != 0 {
		t.Fatalf("failed responder must not report a port, got %d", r2.Port())
	}
}
