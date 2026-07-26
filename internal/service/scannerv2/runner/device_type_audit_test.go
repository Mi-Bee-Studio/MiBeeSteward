// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestAudit_RealNetworkHostnames is the data-driven regression test for the
// full-network device-type audit. Each case is a REAL hostname observed on the
// test LAN (lan-62), with the type the YAML rule table (device_types.yaml)
// should now infer. This guards against re-introducing the mis-classifications
// the audit found: Xiaomi IoT appliances (viomi/zhimi/chunmi/mijia/XiaoAi), PC
// laptops (macbook/popos), ESP32 microcontrollers, Jetson, and phones. If you
// add a keyword to device_types.yaml, add the corresponding hostname here so the
// contract is locked. These exercise heuristicDeviceType (→ matchDeviceType),
// the single source of truth now backed by the YAML table.
func TestAudit_RealNetworkHostnames(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
		brand    string
		osType   string
		want     string
	}{
		// ── Xiaomi IoT appliance ecosystem (was "other", should be iot) ──
		{"viomi water heater", "viomi-waterheater-e13_miap5E55", "", "", "iot"},
		{"viomi hood", "viomi-hood-c13_miap5788", "", "", "iot"},
		{"viomi dishwasher", "viomi-dishwasher-m01_miapF20A", "", "", "iot"},
		{"mijia fridge", "midjd7-fridge-5022_mibt5B23", "", "", "iot"},
		{"zhimi air purifier", "zhimi-airp-ua1_mibt6168", "", "", "iot"},
		{"chunmi appliance", "chunmi-ysj-tsj9_mibt89A7", "", "", "iot"},
		{"XiaoAi speaker", "XiaoAiTongXueX6A", "", "", "iot"},
		{"mijia clock", "mijia-clock", "", "", "iot"},
		{"xiaomi AC", "xiaomi-aircondition-c16_mibt2431", "", "", "iot"},
		{"xiaomi gateway", "xiaomi-gateway-hub1", "", "", "iot"},
		// ── ESP32 microcontrollers (was "server", should be iot) ──
		{"esp32c6", "esp32c6-11DB60", "", "", "iot"},
		{"esp32c3", "esp32c3-F8E62C", "", "", "iot"},
		// ── Jetson embedded AI (was "other", should be embedded) ──
		{"jetson", "jetson-ubuntu", "", "", "embedded"},
		// ── PC / laptops (was "other"/"embedded", should be pc) ──
		{"redmi notebook", "redmi-notebook", "", "", "pc"},
		{"notebook redmi popos", "notebook-redmi-popos", "", "", "pc"},
		{"MacBookPro", "MacBookPro", "", "", "pc"},
		{"thinkpad", "thinkpad-x1-carbon", "", "", "pc"},
		// ── Phones (new type; was "other", should be phone) ──
		// NOTE: redmi-notebook must stay pc (notebook beats phone's redmi-15).
		{"Mi-10", "Mi-10", "", "", "phone"},
		{"MickeyPhone", "MickeyPhone", "", "", "phone"},
		{"Redmi 15R 5G", "REDMI-15R-5G", "", "", "phone"},
		{"Huawei AL00", "KLE-AL00U", "", "", "phone"},
		{"Huawei JUY-AL00", "JUY-AL00", "", "", "phone"},
		{"Xiaomi 2109119BC", "2109119BC", "", "", "phone"},
		// ── NAS (regression guard — the .138 极空间 Z4S case) ──
		{"Z4S NAS", "Z4S-2PSE", "MiniDLNA", "", "nas"},
		// ── Cameras (regression guard — must not regress to NAS/other) ──
		{"Hikvision IPC", "IPC-1234ABCD", "hikvision", "", "camera"},
		{"Hikvision DS-2CD", "DS-2CD2143", "hikvision", "", "camera"},
		{"chuangmi camera", "chuangmi_camera_029a02", "", "", "camera"},
		// ── Routers (regression guard) ──
		{"R68s router", "R68s", "iStoreOS", "", "router"},
		{"MiWifi", "MIWIFI SERVER CERT", "nginx", "", "router"},
		// ── OS-label path (SSH banner distro names) ──
		{"Ubuntu PC by OS", "", "", "Ubuntu", "pc"},
		{"Windows PC by OS", "", "", "Windows", "pc"},
		{"Android phone by OS", "", "", "Android", "phone"},
		{"Linux server by OS", "", "", "Linux", "server"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fields := map[string]string{}
			if c.hostname != "" {
				fields["node_hostname"] = c.hostname
			}
			if c.brand != "" {
				fields["inferred_brand"] = c.brand
			}
			if c.osType != "" {
				fields["os_type"] = c.osType
			}
			rep := scannerv2.HostReport{
				IP:    "10.0.0.1",
				Alive: true,
				Device: scannerv2.DeviceRef{
					IP:     "10.0.0.1",
					Fields: fields,
				},
			}
			got, _ := heuristicDeviceType(rep)
			require.Equalf(t, c.want, got,
				"hostname=%q brand=%q os=%q: want %q, got %q",
				c.hostname, c.brand, c.osType, c.want, got)
		})
	}
}

// TestAudit_RedmiNotebookIsPCNotPhone is the critical ordering guard: the
// hostname "redmi-notebook" contains BOTH the pc keyword "notebook" AND would
// match a phone keyword if one were too broad. The pc rule MUST win by priority
// order. This locks the rule-ordering invariant documented in device_types.yaml.
func TestAudit_RedmiNotebookIsPCNotPhone(t *testing.T) {
	rep := scannerv2.HostReport{
		IP: "10.0.0.2", Alive: true,
		Device: scannerv2.DeviceRef{IP: "10.0.0.2",
			Fields: map[string]string{"node_hostname": "redmi-notebook"}},
	}
	gotType, _ := heuristicDeviceType(rep)
	require.Equal(t, "pc", gotType,
		"redmi-notebook must be pc (notebook keyword wins over phone keywords by rule order)")
}

// TestAudit_PortShapeFallback verifies the port-shape rules in device_types.yaml
// still infer types when no hostname/brand/os signal is present (the cross-subnet
// common case). Mirrors the old hardcoded port-shape switch.
func TestAudit_PortShapeFallback(t *testing.T) {
	cases := []struct {
		name  string
		svcs  []scannerv2.ServiceIdentity
		ports []int
		want  string
	}{
		{"smb only", []scannerv2.ServiceIdentity{{Service: "smb", Port: 445}}, nil, "nas"},
		{"rtsp only", []scannerv2.ServiceIdentity{{Service: "rtsp", Port: 554}}, nil, "camera"},
		{"port 9100", nil, []int{9100}, "printer"},
		{"ssh no web", nil, []int{22}, "server"},
		{"ssh with web", nil, []int{22, 80}, ""}, // ssh+web is ambiguous → no guess
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := scannerv2.HostReport{IP: "10.0.0.3", Alive: true,
				Device: scannerv2.DeviceRef{IP: "10.0.0.3", Fields: map[string]string{}}}
			rep.Services = c.svcs
			for _, p := range c.ports {
				rep.Services = append(rep.Services, scannerv2.ServiceIdentity{Port: p})
			}
			got2, _ := heuristicDeviceType(rep)
			require.Equal(t, c.want, got2)
		})
	}
}

// TestTypeSource_Provenance verifies the type-confidence signal: a type set by
// a service handler (protocol evidence) must be marked "protocol", while a type
// set/overridden by the hostname keyword heuristic must be marked "heuristic".
// This is what the UI uses to show users which classifications are trustworthy
// vs. guessable — the core of the "don't pretend to be certain" design.
func TestTypeSource_Provenance(t *testing.T) {
	rn, _, conn := setupTypeTestDB(t)
	ctx := context.Background()

	cases := []struct {
		name         string
		inferredType string // what the handler set (Fields["inferred_type"])
		hostname     string
		wantType     string
		wantSource   string // "" means the key is absent (legacy/unknown)
	}{
		// Handler-set camera from RTSP evidence, no hostname override → protocol.
		{"camera from protocol", "camera", "192.168.1.50", "camera", "protocol"},
		// Handler-set camera, overridden to pc by notebook hostname → heuristic
		// (the deciding factor was the hostname keyword, not the RTSP evidence).
		{"camera overridden to pc", "camera", "redmi-notebook", "pc", "heuristic"},
		// No handler verdict, hostname keyword decides → heuristic.
		{"iot from hostname only", "", "viomi-waterheater-e13", "iot", "heuristic"},
		{"phone from hostname only", "", "Mi-10", "phone", "heuristic"},
		{"nas from hostname only", "", "Z4S-2PSE", "nas", "heuristic"},
		// No handler verdict, no hostname match → "other", source empty (unknown).
		{"no signal at all", "", "192.168.1.99", "other", ""},
		// Handler-set specialized type (router from SNMP) survives → protocol.
		{"router from protocol", "router", "10.0.0.1", "router", "protocol"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := fmt.Sprintf("10.0.0.%d", 100+i)
			fields := map[string]string{}
			if c.inferredType != "" {
				fields["inferred_type"] = c.inferredType
			}
			if c.hostname != "" {
				fields["node_hostname"] = c.hostname
			}
			rep := scannerv2.HostReport{IP: ip, Alive: true,
				Device: scannerv2.DeviceRef{IP: ip, Fields: fields}}
			rn.applyDeviceBridge(ctx, rep, rn.networkID, "test")

			var sa string
			err := conn.QueryRow(
				`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&sa)
			require.NoError(t, err)
			var attr struct {
				InferredType       string `json:"inferred_type"`
				InferredTypeSource string `json:"inferred_type_source"`
			}
			require.NoError(t, json.Unmarshal([]byte(sa), &attr))
			require.Equalf(t, c.wantType, attr.InferredType,
				"type mismatch for %q", c.hostname)
			require.Equalf(t, c.wantSource, attr.InferredTypeSource,
				"type_source mismatch for %q: want %q, got %q",
				c.hostname, c.wantSource, attr.InferredTypeSource)
		})
	}
}

// TestDeviceTypesYAML_InSyncWithSourceOfTruth guards against a common foot-gun:
// the device-type keyword table has TWO copies — the source of truth at
// configs/fingerprints/device-types/device_types.yaml and the //go:embed copy at
// internal/service/scannerv2/runner/device_types.yaml (Go embed can't reach
// outside the package dir, so `make sync-device-types` copies it at build time).
// If a developer edits the source but forgets to sync, the binary ships stale
// keywords. This test fails in that case so CI catches it.
//
// It resolves the repo root by walking up from the test file's location (the
// runner package dir is always <root>/internal/service/scannerv2/runner/).
func TestDeviceTypesYAML_InSyncWithSourceOfTruth(t *testing.T) {
	runnerCopy := "device_types.yaml" // relative to the test's working dir (the package dir)
	srcCopy := filepath.Join("..", "..", "..", "..", "configs", "fingerprints",
		"device-types", "device_types.yaml")

	runnerBytes, err := os.ReadFile(runnerCopy)
	if err != nil {
		t.Skipf("embedded device_types.yaml not found at %s (expected in package dir): %v", runnerCopy, err)
	}
	srcBytes, err := os.ReadFile(srcCopy)
	if err != nil {
		t.Skipf("source-of-truth device_types.yaml not found at %s — "+
			"this test only runs from a full repo checkout: %v", srcCopy, err)
	}
	require.Equalf(t, string(srcBytes), string(runnerBytes),
		"device_types.yaml is OUT OF SYNC: the source of truth "+
			"(configs/fingerprints/device-types/device_types.yaml) differs from the "+
			"//go:embed copy (internal/service/scannerv2/runner/device_types.yaml). "+
			"Run `make sync-device-types` and commit the result.")
}
