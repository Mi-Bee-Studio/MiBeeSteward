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
	"net"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The TXT shape is a cross-repo contract (Scout docs/02 §3/§8.2: ver/id/name/
// tls/api, same as NVR's _mibee-nvr._tcp) so the App's single TXT parser
// handles every MiBee service with zero new code. Changing these keys breaks
// App-side discovery.
func TestTXTRecordsShape(t *testing.T) {
	got := TXTRecords("abcd1234", "steward 主控", 8080, true)
	want := []string{
		"ver=1",
		"id=abcd1234",
		"name=" + url.QueryEscape("steward 主控"),
		"tls=1",
		"api=8080",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TXTRecords = %v, want %v", got, want)
	}

	tlsOff := TXTRecords("abcd1234", "x", 80, false)
	if !reflect.DeepEqual(tlsOff[3], "tls=0") {
		t.Fatalf("tls flag = %q, want \"tls=0\"", tlsOff[3])
	}
}

func TestServiceTypeIsRegistered(t *testing.T) {
	// Must match the Scout docs/02 §8.4 type registry row for steward.
	if ServiceType != "_mibee-steward._tcp" {
		t.Fatalf("ServiceType = %q, want %q", ServiceType, "_mibee-steward._tcp")
	}
}

// startTestRegistrar binds a registrar to a loopback ephemeral port so the
// tests exercise the real read/answer path without touching multicast or
// port 5353 (legacy one-shot queries take the same answer-building code).
func startTestRegistrar(t *testing.T, id, name string, apiPort int) (*Registrar, int) {
	t.Helper()
	r := NewRegistrar(id, name, apiPort, false)
	if err := r.startOn("127.0.0.1:0"); err != nil {
		t.Fatalf("registrar start: %v", err)
	}
	t.Cleanup(r.Stop)
	r.mu.Lock()
	port := r.conn.LocalAddr().(*net.UDPAddr).Port
	r.mu.Unlock()
	return r, port
}

// query sends one mDNS question and returns the response (nil on timeout).
func query(t *testing.T, port int, q dnsmessage.Question, known []dnsmessage.Resource) *dnsmessage.Message {
	t.Helper()
	msg := dnsmessage.Message{
		Header:  dnsmessage.Header{ID: 0x1234},
		Answers: known,
		Questions: []dnsmessage.Question{
			{Type: q.Type, Class: dnsmessage.ClassINET, Name: q.Name},
		},
	}
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("dial registrar: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("send query: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	resp := make([]byte, 1500)
	n, err := c.Read(resp)
	if err != nil {
		return nil
	}
	var out dnsmessage.Message
	if err := out.Unpack(resp[:n]); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return &out
}

func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatalf("NewName(%q): %v", s, err)
	}
	return n
}

// A PTR browse query (what the Scout app's NSD browse and avahi send) must
// yield the full record set: PTR for the browse, SRV+TXT for the resolve,
// A for the connect — with the five contract TXT keys.
func TestRegistrarAnswersPTRBrowse(t *testing.T) {
	r, port := startTestRegistrar(t, "id-mdns-1", "steward-lab", 18124)

	resp := query(t, port,
		dnsmessage.Question{Type: dnsmessage.TypePTR, Name: mustName(t, "_mibee-steward._tcp.local.")}, nil)
	if resp == nil {
		t.Fatalf("no answer to PTR browse query")
	}
	if !resp.Response || !resp.Authoritative {
		t.Fatalf("response flags wrong: %+v", resp.Header)
	}
	if resp.ID != 0x1234 {
		t.Fatalf("legacy response must echo the transaction ID, got %#x", resp.ID)
	}

	var sawPTR, sawSRV, sawTXT bool
	var txt []string
	var srvPort uint16
	for _, rr := range resp.Answers {
		name := nameString(rr.Header.Name)
		switch body := rr.Body.(type) {
		case *dnsmessage.PTRResource:
			if name == "_mibee-steward._tcp.local." && nameString(body.PTR) == "steward-lab._mibee-steward._tcp.local." {
				sawPTR = true
			}
		case *dnsmessage.SRVResource:
			if name == "steward-lab._mibee-steward._tcp.local." {
				sawSRV = true
				srvPort = body.Port
			}
		case *dnsmessage.TXTResource:
			if name == "steward-lab._mibee-steward._tcp.local." {
				sawTXT = true
				txt = body.TXT
			}
		}
	}
	if !sawPTR || !sawSRV || !sawTXT {
		t.Fatalf("missing records: ptr=%v srv=%v txt=%v in %+v", sawPTR, sawSRV, sawTXT, resp.Answers)
	}
	if srvPort != 18124 {
		t.Fatalf("SRV port = %d, want 18124", srvPort)
	}
	wantTXT := TXTRecords("id-mdns-1", "steward-lab", 18124, false)
	if !reflect.DeepEqual(txt, wantTXT) {
		t.Fatalf("TXT = %v, want %v", txt, wantTXT)
	}
	// At least one A record for the SRV target (the connect leg).
	sawA := false
	for _, rr := range resp.Answers {
		if rr.Header.Type == dnsmessage.TypeA && nameString(rr.Header.Name) == r.hostFQDN {
			sawA = true
		}
	}
	if !sawA {
		t.Fatalf("no A record for SRV target %q in %+v", r.hostFQDN, resp.Answers)
	}
}

// SRV and TXT queries target the instance record (the resolve phase).
func TestRegistrarAnswersInstanceQueries(t *testing.T) {
	r, port := startTestRegistrar(t, "id-2", "inst", 9000)
	inst := "inst._mibee-steward._tcp.local."

	txtResp := query(t, port, dnsmessage.Question{Type: dnsmessage.TypeTXT, Name: mustName(t, inst)}, nil)
	if txtResp == nil {
		t.Fatalf("no answer to TXT query")
	}
	sawTXT := false
	for _, rr := range txtResp.Answers {
		if rr.Header.Type == dnsmessage.TypeTXT && nameString(rr.Header.Name) == inst {
			sawTXT = true
		}
	}
	if !sawTXT {
		t.Fatalf("no TXT record in %+v", txtResp.Answers)
	}

	srvResp := query(t, port, dnsmessage.Question{Type: dnsmessage.TypeSRV, Name: mustName(t, inst)}, nil)
	if srvResp == nil {
		t.Fatalf("no answer to SRV query")
	}
	_ = r
}

// Known-answer suppression (RFC 6762 §7.1): a query that already carries our
// records gets no answer — answering would spark a storm between instances.
func TestRegistrarKnownAnswerSilence(t *testing.T) {
	_, port := startTestRegistrar(t, "id-3", "inst", 9000)
	known := []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name:  mustName(t, "_mibee-steward._tcp.local."),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		},
		Body: &dnsmessage.PTRResource{PTR: mustName(t, "inst._mibee-steward._tcp.local.")},
	}}
	if resp := query(t, port,
		dnsmessage.Question{Type: dnsmessage.TypePTR, Name: mustName(t, "_mibee-steward._tcp.local.")}, known); resp != nil {
		t.Fatalf("answered a known-answer query: %+v", resp.Answers)
	}
}

// Unrelated questions must not be answered (a steward instance is not an
// NVR, a printer, or anything else on the wire).
func TestRegistrarIgnoresUnrelatedQueries(t *testing.T) {
	_, port := startTestRegistrar(t, "id-4", "inst", 9000)
	if resp := query(t, port,
		dnsmessage.Question{Type: dnsmessage.TypePTR, Name: mustName(t, "_mibee-nvr._tcp.local.")}, nil); resp != nil {
		t.Fatalf("answered a foreign service query: %+v", resp.Answers)
	}
	if resp := query(t, port,
		dnsmessage.Question{Type: dnsmessage.TypeA, Name: mustName(t, "other-host.local.")}, nil); resp != nil {
		t.Fatalf("answered a foreign host query: %+v", resp.Answers)
	}
}

// Two registrars must coexist on 5353 — the scanner's own passive mDNS
// listener (and resident avahi/systemd-resolved) already hold that port, so
// the socket options must tolerate siblings (SO_REUSEADDR, no REUSEPORT).
// CI environments without a usable 5353 skip; the test rig runs this for
// real (issue #729 rig evidence).
func TestRegistrarTwoServersCoexist(t *testing.T) {
	a := NewRegistrar("id-a", "steward-a", 8080, false)
	if err := a.Start(); err != nil {
		t.Skipf("cannot bind 5353 in this environment (%v); coexistence covered on the test rig", err)
	}
	defer a.Stop()
	b := NewRegistrar("id-b", "steward-b", 8081, false)
	if err := b.Start(); err != nil {
		t.Fatalf("second registrar Start (5353 coexistence broken): %v", err)
	}
	defer b.Stop()
}
