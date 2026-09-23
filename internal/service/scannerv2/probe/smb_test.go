// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// --- SMB2 Negotiate request builder ---

func TestSMB2NegotiateRequest_WireFormat(t *testing.T) {
	pkt := smb2NegotiateRequest()

	// NetBIOS session header: 4 bytes, length = 64 (SMB2 header) + 36 (body) + 8 (4 dialects).
	require.Len(t, pkt, 4+64+36+8, "total packet length")
	length := uint32(pkt[2])<<8 | uint32(pkt[3])
	require.Equal(t, uint32(64+36+8), length, "NetBIOS length field")

	// SMB2 header magic 0xFE "SMB" + StructureSize 64 + Command=0 (NEGOTIATE).
	hdr := pkt[4:68]
	require.Equal(t, []byte{0xFE, 'S', 'M', 'B'}, hdr[0:4])
	require.Equal(t, uint16(64), binary.LittleEndian.Uint16(hdr[4:6]))
	require.Equal(t, uint16(0), binary.LittleEndian.Uint16(hdr[12:14]), "Command = NEGOTIATE")

	// Body: StructureSize 36, DialectCount 4, SecurityMode 1.
	body := pkt[68 : 68+36]
	require.Equal(t, uint16(36), binary.LittleEndian.Uint16(body[0:2]))
	require.Equal(t, uint16(4), binary.LittleEndian.Uint16(body[2:4]))
	require.Equal(t, uint16(1), binary.LittleEndian.Uint16(body[4:6]))

	// Dialect list: 2.1, 3.0, 3.0.2, 3.1.1 (little-endian uint16s).
	dialects := pkt[68+36:]
	require.Len(t, dialects, 8)
	require.Equal(t, []uint16{0x0202, 0x0300, 0x0302, 0x0311}, []uint16{
		binary.LittleEndian.Uint16(dialects[0:2]),
		binary.LittleEndian.Uint16(dialects[2:4]),
		binary.LittleEndian.Uint16(dialects[4:6]),
		binary.LittleEndian.Uint16(dialects[6:8]),
	})
}

// --- parseSMB2Dialect ---

func TestParseSMB2Dialect(t *testing.T) {
	build := func(dialect uint16) []byte {
		resp := make([]byte, 128)
		resp[0], resp[1], resp[2], resp[3] = 0xFE, 'S', 'M', 'B'
		binary.LittleEndian.PutUint16(resp[68:70], dialect)
		return resp
	}

	cases := []struct {
		name string
		resp []byte
		want string
	}{
		{"too short", make([]byte, 69), ""},
		{"wrong magic", func() []byte { r := build(0x0311); r[0] = 0xFF; return r }(), ""},
		{"2.0", build(0x02FF), "SMB 2.0"},
		{"2.1", build(0x0202), "SMB 2.1"},
		{"3.0", build(0x0300), "SMB 3.0"},
		{"3.0.2", build(0x0302), "SMB 3.0.2"},
		{"3.1.1", build(0x0311), "SMB 3.1.1"},
		{"no dialect picked", build(0x0000), ""},
		{"unknown dialect", build(0x0222), "SMB 0x0222"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, parseSMB2Dialect(tc.resp))
		})
	}
}

// --- SMB1 negotiate request builder ---

func TestSMB1NegotiateRequest_WireFormat(t *testing.T) {
	pkt := smb1NegotiateRequest()

	// NetBIOS length = 32 (header) + 2 (byte count) + 2 (format+count) + dialect string + NUL.
	length := uint32(pkt[2])<<8 | uint32(pkt[3])
	require.Equal(t, uint32(32+2+2+len("PC NETWORK PROGRAM 1.0\x00")), length, "NetBIOS length field")

	hdr := pkt[4:36]
	require.Equal(t, []byte{0xFF, 'S', 'M', 'B'}, hdr[0:4])
	require.Equal(t, byte(0x72), hdr[4], "Command = SMB_COM_NEGOTIATE")

	// The dialect string rides at the tail, format-prefixed (0x02 = ASCII).
	require.Equal(t, byte(0x02), pkt[len(pkt)-len("\x00PC NETWORK PROGRAM 1.0\x00")])
	require.Contains(t, string(pkt), "PC NETWORK PROGRAM 1.0")
}

// --- parseSMB1OS ---

// smb1Response builds an SMB1 Negotiate Response with the given WordCount and
// byte-data (domain + ServerType strings).
func smb1Response(wordCount byte, data []byte) []byte {
	pkt := make([]byte, 32)
	pkt[0], pkt[1], pkt[2], pkt[3] = 0xFF, 'S', 'M', 'B'
	pkt = append(pkt, wordCount)
	pkt = append(pkt, make([]byte, int(wordCount)*2)...)
	bc := make([]byte, 2)
	binary.LittleEndian.PutUint16(bc, uint16(len(data)))
	pkt = append(pkt, bc...)
	pkt = append(pkt, data...)
	return pkt
}

func TestParseSMB1OS(t *testing.T) {
	// Realistic Samba shape: domain then ServerType, both NUL-terminated.
	samba := smb1Response(17, []byte("WORKGROUP\x00Samba 4.15.13-Debian\x00"))
	require.Equal(t, "Samba 4.15.13-Debian", parseSMB1OS(samba))

	// WordCount 0 (parameterless), still finds the second string.
	flat := smb1Response(0, []byte("WG\x00Windows 10 Pro\x00"))
	require.Equal(t, "Windows 10 Pro", parseSMB1OS(flat))

	require.Empty(t, parseSMB1OS(make([]byte, 34)), "too short")
	bad := smb1Response(0, []byte("WG\x00srv\x00"))
	bad[0] = 0xFE
	require.Empty(t, parseSMB1OS(bad), "wrong magic")

	// Truncated packet: declared byte count exceeds the actual data, the
	// parser clamps instead of panicking.
	require.Equal(t, "srv", parseSMB1OS(append(smb1Response(0, []byte("WG\x00srv\x00")), make([]byte, 0)...)))

	// Only one string (no ServerType after the first NUL) → "".
	require.Empty(t, parseSMB1OS(smb1Response(0, []byte("WORKGROUP\x00"))))
	// No NUL at all → "" (first-null guard).
	require.Empty(t, parseSMB1OS(smb1Response(0, []byte("abc"))))
	// ServerType present but unterminated → returns the remainder as-is.
	require.Equal(t, "Samba", parseSMB1OS(smb1Response(0, []byte("WG\x00Samba"))))
}

// --- Probe against fake listeners ---

// fakeSMBServer accepts conns in order and for each hands the request read to
// responses[i] (a function returning the bytes to write back).
func fakeSMBServer(t *testing.T, responses []func(req []byte) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for i := 0; ; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			resp := responses[min(i, len(responses)-1)]
			go func(c net.Conn, respond func([]byte) []byte) {
				defer c.Close()
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Read(buf); err != nil && err != io.EOF {
					return
				}
				_, _ = c.Write(respond(buf))
			}(conn, resp)
		}
	}()
	return ln.Addr().String()
}

func TestSMBProbe_HappyPathSMB2(t *testing.T) {
	smb2Resp := func([]byte) []byte {
		r := make([]byte, 128)
		r[0], r[1], r[2], r[3] = 0xFE, 'S', 'M', 'B'
		binary.LittleEndian.PutUint16(r[68:70], 0x0311) // 3.1.1
		return r
	}
	addr := fakeSMBServer(t, []func([]byte) []byte{smb2Resp})

	p := NewSMBProbe(2 * time.Second)
	ev, err := p.probeAddr(context.Background(), "192.0.2.10", addr)
	require.NoError(t, err)
	require.Len(t, ev, 1)
	require.Equal(t, "smb_negotiate", ev[0].Kind)
	require.Equal(t, "192.0.2.10", ev[0].IP, "evidence carries the bare IP, not host:port")
	require.Equal(t, 445, ev[0].Port)
	require.Equal(t, "SMB 3.1.1", ev[0].RawData["dialect"])
	require.Equal(t, "445", ev[0].RawData["port"])
}

func TestSMBProbe_SMB1FallbackForOSString(t *testing.T) {
	// First connection answers with a NON-SMB2 body (SMB1-only server), second
	// answers the SMB1 negotiate with the Samba ServerType string.
	junk := func([]byte) []byte { return make([]byte, 80) }
	smb1Resp := func([]byte) []byte { return smb1Response(17, []byte("WG\x00Samba 4.15\x00")) }
	addr := fakeSMBServer(t, []func([]byte) []byte{junk, smb1Resp})

	p := NewSMBProbe(2 * time.Second)
	ev, err := p.probeAddr(context.Background(), "192.0.2.11", addr)
	require.NoError(t, err)
	require.Len(t, ev, 1)
	require.Equal(t, "SMB 1.0", ev[0].RawData["dialect"])
	require.Equal(t, "Samba 4.15", ev[0].RawData["os"])
}

func TestSMBProbe_NoEvidencePaths(t *testing.T) {
	p := NewSMBProbe(500 * time.Millisecond)

	// Closed port → no evidence, not an error.
	ev, err := p.probeAddr(context.Background(), "127.0.0.1", "127.0.0.1:1")
	require.NoError(t, err)
	require.Empty(t, ev)

	// Server that accepts but answers garbage on BOTH connections → no evidence.
	garbage := func([]byte) []byte { return []byte("HTTP/1.1 400 Bad Request\r\n\r\n") }
	addr := fakeSMBServer(t, []func([]byte) []byte{garbage, garbage})
	ev, err = p.probeAddr(context.Background(), "192.0.2.12", addr)
	require.NoError(t, err)
	require.Empty(t, ev)
}

// Timeout sanity: NewSMBProbe clamps non-positive timeouts to 3s.
func TestNewSMBProbe_TimeoutClamp(t *testing.T) {
	require.Equal(t, 3*time.Second, NewSMBProbe(0).timeout)
	require.Equal(t, 3*time.Second, NewSMBProbe(-1).timeout)
	require.Equal(t, 1500*time.Millisecond, NewSMBProbe(1500*time.Millisecond).timeout)
}

// Interface conformance, the probe registry contract.
func TestSMBProbe_InterfaceConformance(t *testing.T) {
	var _ scannerv2.ProbeSource = (*SMBProbe)(nil)
	require.Equal(t, "active:smb", NewSMBProbe(time.Second).Name())
}
