// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stunServerDTO mirrors the wire row for assertions.
type stunRow struct {
	Endpoint string `json:"endpoint"`
	Label    string `json:"label"`
	Builtin  bool   `json:"builtin"`
	Enabled  bool   `json:"enabled"`
}

func getSTUN(t *testing.T, server *httptest.Server, token, query string) (int, map[string]any) {
	t.Helper()
	resp, err := doAuthed(t, server, http.MethodGet, "/api/v1/settings/probes/stun-servers"+query, token, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	decodeJSON(t, resp, &out)
	return resp.StatusCode, out
}

func rowsOf(t *testing.T, body map[string]any) []stunRow {
	t.Helper()
	raw, err := json.Marshal(body["servers"])
	require.NoError(t, err)
	var rows []stunRow
	require.NoError(t, json.Unmarshal(raw, &rows))
	return rows
}

// TestSettings_STUNServers pins the #750 lifecycle: defaults on first read,
// PUT persists the list (custom rows added, builtin disabled-but-present),
// format/dedupe/cap/builtin-protection reject bad payloads, and the
// defaults=1 view stays pristine.
func TestSettings_STUNServers(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Initial: defaults, source=default, five builtin rows.
	code, body := getSTUN(t, server, token, "")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "default", body["source"])
	require.Equal(t, false, body["enabled"], "NAT probing is opt-in (#750)")
	rows := rowsOf(t, body)
	require.Len(t, rows, 5)
	for _, r := range rows {
		require.True(t, r.Builtin, "%s must be builtin", r.Endpoint)
		require.True(t, r.Enabled)
	}

	// PUT: disable one builtin, add a custom node, flip enabled on.
	putBody := `{"enabled":true,"burst_timeout_ms":1200,"servers":[
		{"endpoint":"stun.cloudflare.com:3478","builtin":true,"enabled":false},
		{"endpoint":"stun.l.google.com:19302","builtin":true,"enabled":true},
		{"endpoint":"stun.nextcloud.com:443","builtin":true,"enabled":true},
		{"endpoint":"stun.qq.com:3478","builtin":true,"enabled":true},
		{"endpoint":"stun.miwifi.com:3478","builtin":true,"enabled":true},
		{"endpoint":"my-stun.example.com:3478","label":"self-hosted","enabled":true}
	]}`
	resp, err := doAuthed(t, server, http.MethodPut, "/api/v1/settings/probes/stun-servers", token, bytes.NewBufferString(putBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]any
	decodeJSON(t, resp, &updated)
	require.Equal(t, "overlay", updated["source"])
	require.Equal(t, true, updated["enabled"])
	updatedRows := rowsOf(t, updated)
	require.Len(t, updatedRows, 6)
	for _, r := range updatedRows {
		if r.Endpoint == "stun.cloudflare.com:3478" {
			require.False(t, r.Enabled, "disabled builtin persisted")
			require.Equal(t, "Cloudflare", r.Label, "builtin label forced server-side")
		}
		if r.Endpoint == "my-stun.example.com:3478" {
			require.False(t, r.Builtin)
			require.Equal(t, "self-hosted", r.Label)
		}
	}

	// Re-read persists across requests.
	_, again := getSTUN(t, server, token, "")
	require.Equal(t, "overlay", again["source"])

	// defaults=1 stays pristine (restore-defaults data source).
	code, def := getSTUN(t, server, token, "?defaults=1")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "default", def["source"])
	require.Len(t, rowsOf(t, def), 5)
}

func TestSettings_STUNServersValidation(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	builtin := []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302", "stun.nextcloud.com:443", "stun.qq.com:3478", "stun.miwifi.com:3478"}
	allBuiltin := `[` + strings.Join(mapEndpoints(builtin), ",") + `]`
	overCap := allBuiltin[:len(allBuiltin)-1]
	for i := 0; i < 4; i++ {
		overCap += `,{"endpoint":"x9-` + string(rune('a'+i)) + `.example.com:3478","enabled":true}`
	}
	overCap += `]`

	cases := []struct {
		name, body, wantErr string
	}{
		{"no servers", `{"servers":null}`, "required"},
		{"bad endpoint", `{"servers":[{"endpoint":"https://nope"}]}`, "invalid"},
		{"space endpoint", `{"servers":[{"endpoint":"host with space:3478"}]}`, "invalid"},
		{"duplicate", `{"servers":[{"endpoint":"stun.l.google.com:19302","enabled":true},{"endpoint":"stun.l.google.com:19302","enabled":true}]}`, "duplicate"},
		{"builtin dropped", `{"servers":[{"endpoint":"my-stun.example.com:3478","enabled":true}]}`, "cannot be removed"},
		{"forged builtin", `{"servers":[` + strings.Join(mapEndpoints(builtin[:4]), ",") + `,{"endpoint":"evil.example.com:3478","builtin":true,"enabled":true}]}`, "cannot be removed"},
		{"over cap", `{"servers":` + overCap + `}`, "1-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := doAuthed(t, server, http.MethodPut, "/api/v1/settings/probes/stun-servers", token, bytes.NewBufferString(tc.body))
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", tc.body)
			var out map[string]any
			decodeJSON(t, resp, &out)
			require.Contains(t, strings.ToLower(out["error"].(string)), tc.wantErr)
		})
	}
}

// mapEndpoints wraps bare endpoints as enabled rows (payload shape).
func mapEndpoints(endpoints []string) []string {
	out := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		out = append(out, `{"endpoint":"`+ep+`","enabled":true}`)
	}
	return out
}

// TestSettings_STUNServerTest hits the one-shot test endpoint against a
// loopback fake STUN responder (full UDP round trip inside the handler).
func TestSettings_STUNServerTest(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// The fake responder: echoes the client's source ip:port in a
	// XOR-MAPPED-ADDRESS, exactly the property the UI's "test" shows.
	// Diagnostics: sawReq fires once a request lands; writeErr carries any
	// WriteTo failure so the assertion points at the broken leg.
	fake, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer fake.Close()
	sawReq := make(chan struct{}, 1)
	writeErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, rerr := fake.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if n < 20 || buf[0] != 0x00 || buf[1] != 0x01 {
				continue
			}
			select {
			case sawReq <- struct{}{}:
			default:
			}
			var txID [12]byte
			copy(txID[:], buf[8:20])
			uaddr := addr.(*net.UDPAddr)
			cookie := uint32(0x2112A442)
			body := make([]byte, 8)
			body[1] = 0x01
			binary.BigEndian.PutUint16(body[2:], uint16(uaddr.Port)^(uint16(cookie>>16)))
			for i := 0; i < 4; i++ {
				body[4+i] = uaddr.IP.To4()[i] ^ byte(cookie>>(24-8*i))
			}
			resp := make([]byte, 20+4+8) // header + TLV + body
			resp[0], resp[1] = 0x01, 0x01
			binary.BigEndian.PutUint16(resp[2:], 12) // TLV header + body
			copy(resp[4:8], []byte{0x21, 0x12, 0xA4, 0x42})
			copy(resp[8:20], txID[:])
			binary.BigEndian.PutUint16(resp[20:], 0x0020)
			binary.BigEndian.PutUint16(resp[22:], 8)
			copy(resp[24:], body)
			if _, werr := fake.WriteTo(resp, addr); werr != nil {
				select {
				case writeErr <- werr:
				default:
				}
				return
			}
		}
	}()

	endpoint := fake.LocalAddr().String()
	postBody := `{"endpoint":"` + endpoint + `"}`
	resp, err := doAuthed(t, server, http.MethodPost, "/api/v1/settings/probes/stun-servers/test", token, bytes.NewBufferString(postBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]any
	decodeJSON(t, resp, &out)
	select {
	case <-sawReq:
	case <-time.After(time.Second):
		require.FailNow(t, "fake never received the binding request")
	}
	select {
	case werr := <-writeErr:
		require.FailNow(t, "fake WriteTo failed: %v", werr)
	default:
	}
	require.Equal(t, true, out["ok"], "resp: %v", out)
	require.Equal(t, "127.0.0.1", out["mapped_ip"])
	require.Greater(t, out["rtt_ms"], float64(0))

	// Failure path: nothing listens on that port.
	dead := findFreeUDPAddr(t)
	failBody := `{"endpoint":"` + dead + `"}`
	resp2, err := doAuthed(t, server, http.MethodPost, "/api/v1/settings/probes/stun-servers/test", token, bytes.NewBufferString(failBody))
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var fail map[string]any
	decodeJSON(t, resp2, &fail)
	require.Equal(t, false, fail["ok"])
	require.NotEmpty(t, fail["error"])
}

// findFreeUDPAddr binds and closes a UDP socket to grab a likely-free port
// (the classic race is fine here: nothing else is dialing it).
func findFreeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())
	// Give the kernel a beat to release the port before the test dials it.
	time.Sleep(50 * time.Millisecond)
	return addr
}
