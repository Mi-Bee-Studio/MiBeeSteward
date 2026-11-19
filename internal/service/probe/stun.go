// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Minimal RFC 5389 STUN client (stdlib only): one Binding Request per query,
// XOR-MAPPED-ADDRESS decoded with a MAPPED-ADDRESS fallback. Enough for the
// NAT-mapping behavior probe (#750/#753) and the settings-center "test this
// server" button; deliberately not a general STUN library (no attributes
// beyond what the codec needs, no TCP, no relaying).
const (
	stunMagicCookie   = 0x2112A442
	stunAttrXorMapped = 0x0020
	stunAttrMapped    = 0x0001
)

// STUNResult is one server's view of our socket.
type STUNResult struct {
	Server     string        `json:"server"`
	MappedIP   string        `json:"mapped_ip,omitempty"`
	MappedPort int           `json:"mapped_port,omitempty"`
	RTTms      float64       `json:"rtt_ms,omitempty"`
	Err        string        `json:"error,omitempty"`
	RTT        time.Duration `json:"-"`
}

// BuildSTUNBindingRequest returns a 20-byte Binding Request with a random
// transaction ID (the magic cookie + 96 random bits).
func BuildSTUNBindingRequest() ([20]byte, error) {
	var req [20]byte
	binary.BigEndian.PutUint16(req[0:], 0x0001) // type = Binding Request
	binary.BigEndian.PutUint16(req[2:], 0)      // message length
	binary.BigEndian.PutUint32(req[4:], stunMagicCookie)
	if _, err := rand.Read(req[8:20]); err != nil {
		return req, fmt.Errorf("transaction id: %w", err)
	}
	return req, nil
}

// ParseSTUNBindingResponse extracts the mapped address from a Binding
// Response carrying the given transaction ID. XOR-MAPPED-ADDRESS wins
// (RFC 5389 section 3); a legacy MAPPED-ADDRESS is accepted for ancient
// servers.
func ParseSTUNBindingResponse(pkt []byte, txID [12]byte) (ip net.IP, port int, err error) {
	if len(pkt) < 20 {
		return nil, 0, errors.New("short stun response")
	}
	if pkt[0] != 0x01 || pkt[1] != 0x01 {
		return nil, 0, fmt.Errorf("not a binding response (type 0x%02x%02x)", pkt[0], pkt[1])
	}
	if !bytesEqual(pkt[4:8], []byte{0x21, 0x12, 0xA4, 0x42}) {
		return nil, 0, errors.New("stun magic cookie mismatch")
	}
	if !bytesEqual(pkt[8:20], txID[:]) {
		return nil, 0, errors.New("stun transaction id mismatch")
	}
	length := int(binary.BigEndian.Uint16(pkt[2:]))
	if 20+length > len(pkt) {
		length = len(pkt) - 20
	}
	off := 20
	for off+4 <= 20+length {
		attrType := binary.BigEndian.Uint16(pkt[off:])
		attrLen := int(binary.BigEndian.Uint16(pkt[off+2:]))
		body := off + 4
		if body+attrLen > len(pkt) {
			return nil, 0, errors.New("stun attribute overruns packet")
		}
		attr := pkt[body : body+attrLen]
		switch attrType {
		case stunAttrXorMapped:
			if ip, port, aerr := decodeXorMapped(attr); aerr == nil {
				return ip, port, nil
			}
		case stunAttrMapped:
			if ip, port, aerr := decodeMapped(attr); aerr == nil {
				return ip, port, nil
			}
		}
		off = body + attrLen + ((4 - attrLen%4) % 4) // RFC 5389 32-bit padding
	}
	return nil, 0, errors.New("no mapped address in stun response")
}

func decodeXorMapped(body []byte) (net.IP, int, error) {
	if len(body) < 8 || body[1] != 0x01 {
		return nil, 0, errors.New("bad xor-mapped attribute")
	}
	cookie := uint32(stunMagicCookie)
	port := int(binary.BigEndian.Uint16(body[2:])) ^ int(cookie>>16)
	raw := make([]byte, 4)
	copy(raw, body[4:8])
	for i := 0; i < 4; i++ {
		raw[i] ^= byte(cookie >> (24 - 8*i))
	}
	return net.IP(raw), port, nil
}

func decodeMapped(body []byte) (net.IP, int, error) {
	if len(body) < 8 || body[1] != 0x01 {
		return nil, 0, errors.New("bad mapped attribute")
	}
	return net.IP(append([]byte(nil), body[4:8]...)), int(binary.BigEndian.Uint16(body[2:])), nil
}

// bytesEqual is a tiny bytewise compare (encoding/binary's growing list of
// helpers didn't warrant an import for two call sites).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// STUNQuery sends one Binding Request to server ("host:port", port 3478
// implied when absent) and decodes the mapped address. UDP only.
func STUNQuery(server string, timeout time.Duration) (*STUNResult, error) {
	res := &STUNResult{Server: server}
	addr, err := normalizeSTUNServer(server)
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	req, err := BuildSTUNBindingRequest()
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	conn, err := net.DialTimeout("udp4", addr, timeout)
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if derr := conn.SetDeadline(deadline); derr != nil {
		res.Err = derr.Error()
		return res, derr
	}

	start := time.Now()
	if _, werr := conn.Write(req[:]); werr != nil {
		res.Err = werr.Error()
		return res, werr
	}
	var txID [12]byte
	copy(txID[:], req[8:20])
	buf := make([]byte, 1024)
	for {
		n, rerr := conn.Read(buf)
		if rerr != nil {
			res.Err = rerr.Error()
			return res, rerr
		}
		if ip, port, perr := ParseSTUNBindingResponse(buf[:n], txID); perr == nil {
			res.RTT = time.Since(start)
			res.RTTms = float64(res.RTT.Microseconds()) / 1000.0
			res.MappedIP = ip.String()
			res.MappedPort = port
			return res, nil
		}
		// A non-matching datagram (another client's packet on a shared NAT
		// mapping) is skipped; the deadline guards the loop.
		if time.Now().After(deadline) {
			res.Err = "stun timeout"
			return res, errors.New("stun timeout")
		}
	}
}

// normalizeSTUNServer validates "host" / "host:port" (bare stun: URIs
// rejected — callers carry plain endpoints) and resolves to a UDP dial
// address with 3478 implied.
func normalizeSTUNServer(server string) (string, error) {
	s := strings.TrimSpace(server)
	if s == "" {
		return "", errors.New("empty stun server")
	}
	if strings.ContainsAny(s, " \t\"'\\") || strings.Contains(s, "://") {
		return "", fmt.Errorf("stun server must be a plain host:port: %q", s)
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return net.JoinHostPort(s, "3478"), nil
		}
		return "", fmt.Errorf("invalid stun server %q: %w", s, err)
	}
	if port, perr := strconv.Atoi(s[strings.LastIndex(s, ":")+1:]); perr != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid stun port in %q", s)
	}
	return s, nil
}

// ValidateSTUNServer is the settings-layer format gate (#750): same grammar
// as normalizeSTUNServer but returns only whether it parses.
func ValidateSTUNServer(server string) bool {
	_, err := normalizeSTUNServer(server)
	return err == nil
}
