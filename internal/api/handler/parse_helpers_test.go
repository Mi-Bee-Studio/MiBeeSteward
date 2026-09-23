// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
)

// Table tests for the small pure helpers behind the HTTP handlers, parsing,
// formatting, and conversion logic that the endpoint tests only hit on one
// path each.

func TestParseFlexibleTime(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Time
		ok   bool
	}{
		{"empty is no-bound", "", time.Time{}, false},
		{"space datetime", "2026-09-18 10:00:00", time.Date(2026, 9, 18, 10, 0, 0, 0, time.Local), true},
		{"naive iso", "2026-09-18T10:00:00", time.Date(2026, 9, 18, 10, 0, 0, 0, time.Local), true},
		{"rfc3339", "2026-09-18T10:00:00Z", time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC), true},
		{"date only", "2026-09-18", time.Date(2026, 9, 18, 0, 0, 0, 0, time.Local), true},
		{"garbage", "not-a-time", time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFlexibleTime(tc.in)
			require.Equal(t, tc.ok, ok)
			if tc.ok {
				require.True(t, got.Equal(tc.want), "got %v want %v", got, tc.want)
			} else {
				require.True(t, got.IsZero())
			}
		})
	}
}

func TestBuildSDAddress(t *testing.T) {
	cases := []struct {
		ip, target, method, want string
	}{
		{"10.0.0.1", "10.0.0.1:9100", "http", "10.0.0.1:9100"}, // host:port passes through
		{"10.0.0.2", "10.0.0.2:161", "tcp", "10.0.0.2:161"},
		{"10.0.0.3", "", "icmp", "10.0.0.3"},         // falls back to IP
		{"10.0.0.4", "whatever", "snmp", "10.0.0.4"}, // non-http target ignored
		{"", "legacy.example:9100", "http", "legacy.example:9100"},
		{"", "", "", ""}, // nothing usable
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, buildSDAddress(tc.ip, tc.target, tc.method), "ip=%q target=%q method=%q", tc.ip, tc.target, tc.method)
	}
}

func TestTimeStr(t *testing.T) {
	require.Nil(t, timeStr(nil))
	ts := time.Date(2026, 9, 19, 8, 30, 0, 0, time.UTC)
	got := timeStr(&ts)
	require.NotNil(t, got)
	require.Equal(t, "2026-09-19T08:30:00Z", *got)
}

func TestAuthCookieMaxAge(t *testing.T) {
	cfg := func(auth config.AuthConfig) *config.Config { return &config.Config{Auth: auth} }

	require.Equal(t, 7200, authCookieMaxAge(cfg(config.AuthConfig{CookieMaxAge: "2h", TokenExpiry: "1h"})), "CookieMaxAge wins")
	require.Equal(t, 3600, authCookieMaxAge(cfg(config.AuthConfig{TokenExpiry: "1h"})), "TokenExpiry fallback")
	require.Equal(t, 86400, authCookieMaxAge(cfg(config.AuthConfig{CookieMaxAge: "bogus", TokenExpiry: "also-bogus"})), "default 24h")
	require.Equal(t, 86400, authCookieMaxAge(cfg(config.AuthConfig{})))
}

func TestExtractTokenFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	require.Empty(t, extractTokenFromRequest(req))

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "bearer tok-123") // case-insensitive scheme
	require.Equal(t, "tok-123", extractTokenFromRequest(req))

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwdw==")
	require.Empty(t, extractTokenFromRequest(req))

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "cookie-tok"})
	require.Equal(t, "cookie-tok", extractTokenFromRequest(req), "cookie wins over header")
}

func TestReportToHost_EvidenceParsing(t *testing.T) {
	rep := scannerv2.HostReport{
		IP:    "10.1.1.1",
		Alive: true,
		RTTMs: 5,
		Evidence: []scannerv2.Evidence{
			{Kind: "echo", RawData: map[string]string{"rtt_ms": "17"}},
			{Kind: "snmp", RawData: map[string]string{
				"sys_descr":     "Linux router",
				"sys_object_id": "1.3.6.1.4.1.9",
				"sys_location":  "rack 3",
				"sys_contact":   "ops@x",
				"sys_name":      "core-sw",
				"sys_up_time":   "123456",
				"sys_services":  "78",
				"if_number":     "24",
			}},
		},
		Device: scannerv2.DeviceRef{Fields: map[string]string{
			"inferred_type":        "router",
			"inferred_brand":       "cisco",
			"inferred_description": "core switch",
			"inferred_location":    "rack 3",
		}},
	}

	host := reportToHost(rep)
	require.Equal(t, "10.1.1.1", host.IP)
	require.True(t, host.Alive)
	require.Equal(t, int64(17), host.RTTMs, "echo evidence RTT overrides the report RTT")
	require.True(t, host.SNMPSuccess)
	require.Equal(t, "core-sw", host.SNMPName)
	require.Equal(t, "Linux router", host.SNMPDescr)
	require.Equal(t, "1.3.6.1.4.1.9", host.SNMPObjID)
	require.Equal(t, "rack 3", host.SNMPLocation)
	require.Equal(t, "ops@x", host.SNMPContact)
	require.Equal(t, int64(123456), host.SNMPUptime)
	require.Equal(t, 78, host.SNMPServices)
	require.Equal(t, 24, host.SNMPIfCount)
	require.Equal(t, "router", host.InferredType)
	require.Equal(t, "cisco", host.InferredBrand)
	require.Equal(t, "core switch", host.InferredDescription)
	require.Equal(t, "rack 3", host.InferredLocation)
}

func TestReportToHost_GarbageNumericsIgnored(t *testing.T) {
	rep := scannerv2.HostReport{
		Evidence: []scannerv2.Evidence{
			{Kind: "echo", RawData: map[string]string{"rtt_ms": "not-a-number"}},
			{Kind: "snmp", RawData: map[string]string{"sys_up_time": "x", "sys_services": "y", "if_number": "z"}},
		},
	}
	host := reportToHost(rep)
	require.EqualValues(t, 0, host.RTTMs)
	require.True(t, host.SNMPSuccess)
	require.EqualValues(t, 0, host.SNMPUptime)
	require.Equal(t, 0, host.SNMPServices)
	require.Equal(t, 0, host.SNMPIfCount)
}

func TestAddDeviceItemToReport_FieldMarshaling(t *testing.T) {
	item := domain.AddDeviceItem{
		IP:       "10.2.2.2",
		Name:     "manual-cam",
		Type:     "camera",
		Brand:    "hikvision",
		RTTMs:    9,
		PromURL:  "http://10.2.2.2:9090/metrics",
		NEURL:    "http://10.2.2.2:9100/metrics",
		Ports:    []domain.PortInfo{{Port: 80}, {Port: 554}},
		Services: []domain.ServiceInfo{{Name: "http"}, {Name: "rtsp"}},
	}
	rep := addDeviceItemToReport(item)
	require.Equal(t, "10.2.2.2", rep.IP)
	require.True(t, rep.Alive)
	require.Equal(t, "camera", rep.Device.Type)
	require.Equal(t, "hikvision", rep.Device.Brand)
	require.Equal(t, "http://10.2.2.2:9090/metrics", rep.Device.Fields["prometheus_url"])
	require.Equal(t, "http://10.2.2.2:9100/metrics", rep.Device.Fields["node_exporter_url"])
	require.JSONEq(t, `[80,554]`, rep.Device.Fields["open_ports"])
	require.JSONEq(t, `["http","rtsp"]`, rep.Device.Fields["detected_services"])
	require.Equal(t, "camera", rep.Device.Fields["inferred_type"])
	require.Equal(t, "hikvision", rep.Device.Fields["inferred_brand"])

	// Minimal item: no optional fields → no marshaled keys.
	minimal := addDeviceItemToReport(domain.AddDeviceItem{IP: "10.2.2.3"})
	require.NotContains(t, minimal.Device.Fields, "open_ports")
	require.NotContains(t, minimal.Device.Fields, "detected_services")
	require.NotContains(t, minimal.Device.Fields, "prometheus_url")
}
