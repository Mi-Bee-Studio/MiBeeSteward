// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// dnsAnswer is what the mock resolver replies with for any query.
type dnsAnswer struct {
	ipv4     net.IP // A rdata
	txt      string // TXT rdata
	cname    string // CNAME rdata
	nxdomain bool   // rcode 3, no answer
	silent   bool   // swallow the query, never reply (timeout path)
}

// startMockDNS spins a UDP DNS responder on loopback and returns its address.
// It answers every A/AAAA/CNAME/TXT query with the configured answer.
func startMockDNS(t *testing.T, ans dnsAnswer) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if ans.silent {
				continue
			}
			if reply := buildDNSReply(buf[:n], ans); reply != nil {
				_, _ = pc.WriteTo(reply, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// buildDNSReply crafts a one-question/one-answer DNS reply. It echoes the
// query's ID and question (pointer 0xC00C back into it) and appends a single
// answer record per the dnsAnswer shape.
func buildDNSReply(query []byte, ans dnsAnswer) []byte {
	if len(query) < 12 {
		return nil
	}
	qEnd := 12
	for qEnd < len(query) && query[qEnd] != 0 {
		qEnd += int(query[qEnd]) + 1
	}
	qEnd++    // null label
	qEnd += 4 // qtype + qclass
	qtype := binary.BigEndian.Uint16(query[qEnd-4 : qEnd-2])

	flags := uint16(0x8180) // QR=1, RD=1, RA=1
	var rdata []byte
	var atype uint16
	switch {
	case ans.nxdomain:
		flags |= 3
	case qtype == 28: // AAAA
		atype = 28
		rdata = make([]byte, 16)
		copy(rdata, ans.ipv4.To16())
	case qtype == 5: // CNAME
		atype = 5
		rdata = encodeDNSName(ans.cname)
	case qtype == 16: // TXT
		atype = 16
		rdata = append([]byte{byte(len(ans.txt))}, ans.txt...)
	default: // A
		atype = 1
		rdata = ans.ipv4.To4()
	}

	reply := make([]byte, 0, qEnd+16+len(rdata))
	reply = append(reply, query[:2]...)
	reply = binary.BigEndian.AppendUint16(reply, flags)
	reply = binary.BigEndian.AppendUint16(reply, 1) // qdcount
	answers := uint16(0)
	if !ans.nxdomain {
		answers = 1
	}
	reply = binary.BigEndian.AppendUint16(reply, answers)
	reply = binary.BigEndian.AppendUint16(reply, 0)
	reply = binary.BigEndian.AppendUint16(reply, 0)
	reply = append(reply, query[12:qEnd]...)
	if !ans.nxdomain {
		reply = binary.BigEndian.AppendUint16(reply, 0xC00C) // name pointer
		reply = binary.BigEndian.AppendUint16(reply, atype)
		reply = binary.BigEndian.AppendUint16(reply, 1)  // IN
		reply = binary.BigEndian.AppendUint32(reply, 60) // ttl
		reply = binary.BigEndian.AppendUint16(reply, uint16(len(rdata)))
		reply = append(reply, rdata...)
	}
	return reply
}

func encodeDNSName(name string) []byte {
	out := []byte{}
	for _, label := range splitLabels(name) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

func dnsTarget(resolver string, opts *domain.ProbeOptions) db.ProbeTarget {
	o := opts
	if o == nil {
		o = &domain.ProbeOptions{}
	}
	o.Resolver = resolver
	return db.ProbeTarget{
		ID: 7, Name: "dns", Module: "dns", Target: "example.com",
		IntervalSeconds: 60, TimeoutSeconds: 3,
		Options: mustOptionsJSON(o),
	}
}

// TestExecuteDNS pins the dns module against a mock resolver: A lookup,
// expected_ips matching, NXDOMAIN, and the never-replying timeout path.
func TestExecuteDNS(t *testing.T) {
	exec := defaultTargetExecutor
	ctx := context.Background()
	goodIP := net.ParseIP("93.184.216.34")

	t.Run("A lookup succeeds via pinned resolver", func(t *testing.T) {
		addr := startMockDNS(t, dnsAnswer{ipv4: goodIP})
		out := exec.execute(ctx, dnsTarget(addr, nil))
		require.Equal(t, "success", out.Status)
		require.Greater(t, out.Latency, time.Duration(0))
	})
	t.Run("expected_ips intersect", func(t *testing.T) {
		addr := startMockDNS(t, dnsAnswer{ipv4: goodIP})
		out := exec.execute(ctx, dnsTarget(addr, &domain.ProbeOptions{ExpectedIPs: []string{"93.184.216.34"}}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("expected_ips mismatch fails", func(t *testing.T) {
		addr := startMockDNS(t, dnsAnswer{ipv4: goodIP})
		out := exec.execute(ctx, dnsTarget(addr, &domain.ProbeOptions{ExpectedIPs: []string{"1.1.1.1"}}))
		require.Equal(t, "fail", out.Status)
		require.Contains(t, out.ErrMsg, "expected_ips")
	})
	t.Run("NXDOMAIN fails", func(t *testing.T) {
		addr := startMockDNS(t, dnsAnswer{nxdomain: true})
		out := exec.execute(ctx, dnsTarget(addr, nil))
		require.Equal(t, "fail", out.Status)
		require.Contains(t, out.ErrMsg, "NXDOMAIN")
	})
	t.Run("TXT lookup succeeds", func(t *testing.T) {
		addr := startMockDNS(t, dnsAnswer{txt: "v=spf1 -all"})
		out := exec.execute(ctx, dnsTarget(addr, &domain.ProbeOptions{Record: domain.ProbeRecordTXT}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("CNAME lookup succeeds", func(t *testing.T) {
		addr := startMockDNS(t, dnsAnswer{cname: "cname.example.net"})
		out := exec.execute(ctx, dnsTarget(addr, &domain.ProbeOptions{Record: domain.ProbeRecordCNAME}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("silent resolver times out", func(t *testing.T) {
		addr := startMockDNS(t, dnsAnswer{silent: true})
		out := exec.execute(ctx, dnsTarget(addr, nil))
		require.Equal(t, "timeout", out.Status)
	})
}
