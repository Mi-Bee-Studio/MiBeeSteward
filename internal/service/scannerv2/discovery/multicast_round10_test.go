// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// scriptedConn feeds one packet per ReadFrom call, then blocks until closed
// (ReadFrom returns the closed error, which the loops treat via ctx or log).
type scriptedConn struct {
	packets []struct {
		data []byte
		addr net.Addr
	}
	closed chan struct{}
}

func newScriptedConn() *scriptedConn { return &scriptedConn{closed: make(chan struct{})} }

func (c *scriptedConn) add(data []byte, addr net.Addr) {
	c.packets = append(c.packets, struct {
		data []byte
		addr net.Addr
	}{data, addr})
}

func (c *scriptedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.packets) > 0 {
		p := c.packets[0]
		c.packets = c.packets[1:]
		n := copy(b, p.data)
		return n, p.addr, nil
	}
	<-c.closed
	return 0, nil, errors.New("use of closed connection")
}

func (c *scriptedConn) WriteTo([]byte, net.Addr) (int, error) { return 0, nil }
func (c *scriptedConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

// udpAddr builds a *net.UDPAddr (what srcIP expects from ReadFrom).
func udpAddr(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353} }

func newGapService() *Service {
	return New(Config{}, nil, nil, nil, 0, nil, slog.New(slog.NewTextHandler(discardWriter{}, nil)))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestMDNSReadLoop_ScriptedPacket: one mDNS announcement passes through the
// seed-evidence Observe path and the hint Emit path, then the loop exits on
// ctx cancel.
func TestMDNSReadLoop_ScriptedPacket(t *testing.T) {
	svc := newGapService()
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	m := newMDNSListener(svc, logger)
	require.Equal(t, "mdns", m.proto())

	conn := newScriptedConn()
	// A valid mDNS response: one PTR answer for _onvif._tcp.local (the
	// seed-evidence parser requires a real DNS wire-format message).
	conn.add(dnsMsg(dnsRRGap("_onvif._tcp.local", 12, dnsNameGap("hostcam._onvif._tcp.local"))), udpAddr("192.168.9.10"))
	require.NotNil(t, m)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.readLoop(ctx, conn); close(done) }()
	time.Sleep(300 * time.Millisecond) // let the scripted packet get processed
	cancel()
	conn.Close() // unblock the pending ReadFrom; ctx.Err() != nil → loop exits
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not exit after cancel")
	}

	// The seed-evidence cache holds the observed announcement.
	evs := svc.EvidenceFor("192.168.9.10")
	require.NotEmpty(t, evs, "mDNS announcement must be observed as seed evidence")
	require.Equal(t, "mdns", evs[0].Kind)
	require.Equal(t, "discovery:multicast", evs[0].Source)
}

// TestSSDPReadLoop_ScriptedPacket: an SSDP NOTIFY with recognizable headers
// is observed; hints parse the device class.
func TestSSDPReadLoop_ScriptedPacket(t *testing.T) {
	svc := newGapService()
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	s := newSSDPListener(svc, logger)
	require.Equal(t, "ssdp", s.proto())

	conn := newScriptedConn()
	conn.add([]byte("NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaRenderer\r\nSERVER: Linux UPnP/1.0\r\nUSN: uuid:abc\r\n"),
		udpAddr("192.168.9.11"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.readLoop(ctx, conn); close(done) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not exit after cancel")
	}

	evs := svc.EvidenceFor("192.168.9.11")
	require.NotEmpty(t, evs)
	require.Equal(t, "ssdp", evs[0].Kind)
}

func TestParseHints(t *testing.T) {
	h := parseMDNSHints([]byte("x_onvif._tcp local"))
	require.Equal(t, "camera", h["inferred_type"])

	h = parseSSDPHints([]byte("NT: urn:schemas-upnp-org:device:InternetGatewayDevice"))
	require.Equal(t, "router", h["inferred_type"])
	h = parseSSDPHints([]byte("NT: some Basic device"))
	require.Equal(t, "ssdp-basic", h["discovery_note"])
	require.Nil(t, parseSSDPHints([]byte("nothing recognizable")))
}

func TestMulticastInterfaceHelpers(t *testing.T) {
	// Named missing interface → explicit error.
	_, err := multicastInterface("no-such-iface-xyz")
	require.Error(t, err)

	// A real interface with an IPv4 (loopback qualifies) resolves.
	ifis, err := net.Interfaces()
	require.NoError(t, err)
	var found bool
	for _, ifi := range ifis {
		v4, err := ipv4FromInterface(ifi)
		if err != nil {
			continue // no IPv4 on this one
		}
		found = true
		require.Equal(t, ifi.Index, v4.Index)
		require.NotNil(t, v4.Addr.To4())
		break
	}
	require.True(t, found, "host must have at least one IPv4 interface (loopback)")

	// Auto selection: any result or the explicit error — never a panic.
	if _, err := multicastInterface(""); err != nil {
		require.Contains(t, err.Error(), "multicast-capable")
	}

	// srcIP: UDPAddr → dotted; other addr types → "".
	require.Equal(t, "10.1.2.3", srcIP(&net.UDPAddr{IP: net.ParseIP("10.1.2.3")}))
	require.Equal(t, "", srcIP(&net.TCPAddr{}))
}

// TestMulticastSource_Lifecycle: construct + Done channel semantics without
// binding the real 5353/1900 ports (Start is environment-gated in CI).
func TestMulticastSource_Lifecycle(t *testing.T) {
	src := NewMulticastSource(newGapService(), slog.New(slog.NewTextHandler(discardWriter{}, nil)))
	require.NotNil(t, src)
	select {
	case <-src.Done():
		t.Fatal("Done must not be closed before Start runs to completion")
	default:
	}
}

// dnsNameGap/dnsRRGap/dnsMsg replicate the probe package's DNS fixture
// builders (a valid wire-format message the seed-evidence parser accepts).
func dnsNameGap(name string) []byte {
	out := []byte{}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func dnsRRGap(name string, rtype uint16, rdata []byte) []byte {
	rr := dnsNameGap(name)
	rr = append(rr, byte(rtype>>8), byte(rtype))
	rr = append(rr, 0x00, 0x01)
	rr = append(rr, 0, 0, 0, 120)
	rr = append(rr, byte(len(rdata)>>8), byte(len(rdata)))
	return append(rr, rdata...)
}

func dnsMsg(answers ...[]byte) []byte {
	msg := []byte{
		0x00, 0x00, // ID
		0x84, 0x00, // flags: response + authoritative
		0x00, 0x00, // QDCOUNT
		byte(len(answers) >> 8), byte(len(answers)), // ANCOUNT
		0x00, 0x00, 0x00, 0x00,
	}
	for _, a := range answers {
		msg = append(msg, a...)
	}
	return msg
}
