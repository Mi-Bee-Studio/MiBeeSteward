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
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

// typeOnly is a test convenience: heuristicDeviceType now returns (type, source),
// but most classification tests only assert the type. This drops the source.
func typeOnly(rep scannerv2.HostReport) string {
	t, _ := heuristicDeviceType(rep)
	return t
}

// reportWithFields builds a HostReport whose Device.Fields the caller controls,
// so PC-signal tests can set node_hostname / os_type (the stock reportFor helper
// only sets inferred_type/brand/mac). extra fields are merged on top of the
// inferred_type/brand/mac defaults.
func reportWithFields(ip, inferredType, brand, mac string, extra map[string]string) scannerv2.HostReport {
	fields := map[string]string{
		"inferred_type":  inferredType,
		"inferred_brand": brand,
		"mac":            mac,
	}
	for k, v := range extra {
		fields[k] = v
	}
	return scannerv2.HostReport{
		IP:    ip,
		Alive: true,
		Device: scannerv2.DeviceRef{
			IP:     ip,
			Type:   inferredType,
			Brand:  brand,
			Fields: fields,
		},
	}
}

// TestHeuristicDeviceType_PCHostnameBeatsRTSP covers the regression at the heart
// of Bug B: a laptop (hostname "redmi-notebook") running a dev RTSP server on
// 8554 must be typed "pc", not "camera". The PC hostname branch was placed
// BEFORE the camera branch and the rtsp port-shape fallback specifically so this
// resolves to pc.
func TestHeuristicDeviceType_PCHostnameBeatsRTSP(t *testing.T) {
	rep := reportWithFields("192.168.62.41", "camera", "", "38:68:93:ad:6a:6f",
		map[string]string{"node_hostname": "redmi-notebook"})
	// An RTSP service on 8554 is exactly what mis-typed this host as a camera.
	rep.Services = []scannerv2.ServiceIdentity{{Service: "rtsp", Port: 8554}}
	require.Equal(t, "pc", typeOnly(rep),
		"a notebook hostname must beat the RTSP port-shape camera inference")
}

// TestHeuristicDeviceType_DesktopOSLabels confirms the OS branch now recognizes
// the distro NAMES SSH banners actually carry (Ubuntu/Debian/macOS), not just
// the bare "linux" substring that never matched an Ubuntu host.
func TestHeuristicDeviceType_DesktopOSLabels(t *testing.T) {
	for _, osVal := range []string{"Ubuntu", "Debian", "macOS", "Darwin"} {
		rep := reportWithFields("10.0.0.5", "", "", "", map[string]string{"os_type": osVal})
		require.Equalf(t, "pc", typeOnly(rep),
			"os_type=%q should classify as pc", osVal)
	}
	// Bare "linux"/"freebsd" stay server (conservative: headless boxes are more
	// likely servers; this preserves existing classifications).
	for _, osVal := range []string{"Linux", "FreeBSD"} {
		rep := reportWithFields("10.0.0.6", "", "", "", map[string]string{"os_type": osVal})
		require.Equalf(t, "server", typeOnly(rep),
			"os_type=%q should stay server (conservative)", osVal)
	}
}

// TestHeuristicDeviceType_NASKeywordsBeatRTSP covers Bug C (the .138 case):
// the 极空间 Z4S (hostname "Z4S-2PSE", vendor "MiniDLNA", ports smb:445 +
// rtsp:554) is a home NAS that streams media over RTSP — it must be typed
// "nas", not "camera". "z4s" was previously (incorrectly) a camera keyword.
func TestHeuristicDeviceType_NASKeywordsBeatRTSP(t *testing.T) {
	rep := reportWithFields("192.168.62.138", "camera", "MiniDLNA", "1c:83:41:e3:6e:68",
		map[string]string{"node_hostname": "Z4S-2PSE"})
	rep.Services = []scannerv2.ServiceIdentity{
		{Service: "smb", Port: 445},
		{Service: "rtsp", Port: 554},
	}
	require.Equal(t, "nas", typeOnly(rep),
		"a Z4S NAS with MiniDLNA vendor + smb must classify as nas, not camera")
}

// TestHeuristicDeviceType_NASBySmbPortOnly confirms the port-shape fallback
// treats smb:445 as a NAS signal even with no hostname/brand hint (a file
// server streaming media over RTSP is still fundamentally a NAS).
func TestHeuristicDeviceType_NASBySmbPortOnly(t *testing.T) {
	// No hostname, no brand, no os — only ports. smb + rtsp → nas (smb wins).
	rep := reportWithFields("10.0.0.20", "", "", "", nil)
	rep.Services = []scannerv2.ServiceIdentity{
		{Service: "smb", Port: 445},
		{Service: "rtsp", Port: 554},
	}
	require.Equal(t, "nas", typeOnly(rep),
		"smb:445 + rtsp:554 with no other signal should be nas, not camera")
}

// TestHeuristicDeviceType_RealCameraUnaffected confirms removing the bad "z4s"
// camera keyword and adding NAS branches did not break real camera detection: a
// Hikvision-style host with a genuine camera hostname (IPC-/DS-2-/hikvision)
// and no NAS signal still classifies as camera.
func TestHeuristicDeviceType_RealCameraUnaffected(t *testing.T) {
	for _, c := range []struct{ host, brand string }{
		{"IPC-1234ABCD", "hikvision"},
		{"DS-2CD2143", "hikvision"}, // DS-2 is the Hikvision camera series
		{"dvr-nvr-01", "dahua"},
	} {
		rep := reportWithFields("192.168.62.200", "", c.brand, "aa:bb:cc:dd:ee:ff",
			map[string]string{"node_hostname": c.host})
		require.Equalf(t, "camera", typeOnly(rep),
			"hostname=%q brand=%q should classify as camera", c.host, c.brand)
	}
}

// TestApplyDeviceBridge_PCSignalOverridesCamera covers the full override path in
// applyDeviceBridge (device_bridge.go ~line 56): when a handler set
// inferred_type="camera" (e.g. CameraHandler from an RTSP port) but the host
// carries a strong PC signal, the persisted type must be "pc". This is the
// end-to-end fix for 192.168.62.41 (redmi-notebook, RTSP on 8554).
func TestApplyDeviceBridge_PCSignalOverridesCamera(t *testing.T) {
	rn, _, conn := setupTypeTestDB(t)
	ctx := context.Background()

	rep := reportWithFields("192.168.62.41", "camera", "", "38:68:93:ad:6a:6f",
		map[string]string{"node_hostname": "redmi-notebook"})
	rep.Services = []scannerv2.ServiceIdentity{{Service: "rtsp", Port: 8554}}

	isNew, _ := rn.applyDeviceBridge(ctx, rep, rn.networkID, "agent-62")
	require.True(t, isNew)

	var devType string
	err := conn.QueryRow(`SELECT type FROM devices WHERE ip_address='192.168.62.41'`).Scan(&devType)
	require.NoError(t, err)
	require.Equal(t, "pc", devType, "a notebook with an RTSP port should persist as pc, not camera")
}

// TestApplyDeviceBridge_NasSignalOverridesCamera covers Bug C end-to-end (the
// .138 case): when a handler set inferred_type="camera" (from rtsp:554) but the
// host carries a strong NAS signal (Z4S hostname + MiniDLNA vendor + smb:445),
// the persisted type must be "nas". This is the fix for 192.168.62.138
// (极空间 Z4S NAS mis-typed as camera).
func TestApplyDeviceBridge_NasSignalOverridesCamera(t *testing.T) {
	rn, _, conn := setupTypeTestDB(t)
	ctx := context.Background()

	rep := reportWithFields("192.168.62.138", "camera", "MiniDLNA", "1c:83:41:e3:6e:68",
		map[string]string{"node_hostname": "Z4S-2PSE"})
	rep.Services = []scannerv2.ServiceIdentity{
		{Service: "smb", Port: 445},
		{Service: "rtsp", Port: 554},
	}

	isNew, _ := rn.applyDeviceBridge(ctx, rep, rn.networkID, "agent-62")
	require.True(t, isNew)

	var devType string
	err := conn.QueryRow(`SELECT type FROM devices WHERE ip_address='192.168.62.138'`).Scan(&devType)
	require.NoError(t, err)
	require.Equal(t, "nas", devType, "a Z4S NAS with MiniDLNA + smb + rtsp should persist as nas, not camera")
}

// TestApplyDeviceBridge_CameraWithoutPCOrNasSignalStaysCamera is the negative
// case: a genuine camera (Hikvision brand, IPC hostname, no PC/NAS signal)
// keeps type camera even though it also exposes RTSP — the override must not
// mis-fire. NOTE: uses a real camera hostname (IPC-), NOT Z4S (which is a NAS).
func TestApplyDeviceBridge_CameraWithoutPCOrNasSignalStaysCamera(t *testing.T) {
	rn, _, conn := setupTypeTestDB(t)
	ctx := context.Background()

	rep := reportWithFields("192.168.62.200", "camera", "hikvision", "1c:83:41:e3:6e:68",
		map[string]string{"node_hostname": "IPC-1234ABCD"})
	rep.Services = []scannerv2.ServiceIdentity{{Service: "rtsp", Port: 554}}

	rn.applyDeviceBridge(ctx, rep, rn.networkID, "agent-62")

	var devType string
	conn.QueryRow(`SELECT type FROM devices WHERE ip_address='192.168.62.200'`).Scan(&devType)
	require.Equal(t, "camera", devType, "a real camera (IPC hostname, hikvision) with no PC/NAS signal must stay camera")
}

// TestIsStrongPcSignal pins the override gate directly so future keyword tweaks
// are caught: notebook/laptop/thinkpad/macbook hostnames + desktop OS labels are
// strong PC signals; a generic server-ish hostname or bare "linux" is NOT (the
// latter must not flip a camera to pc — routers/NAS run RTSP web UIs too).
func TestIsStrongPcSignal(t *testing.T) {
	// Strong: explicit laptop/desktop hostnames.
	for _, h := range []string{"redmi-notebook", "thinkpad-x1", "macbook-pro", "elitebook-840", "surface-go"} {
		rep := reportWithFields("10.0.0.1", "camera", "", "", map[string]string{"node_hostname": h})
		require.Truef(t, isStrongPcSignal(rep), "hostname %q should be a strong PC signal", h)
	}
	// Strong: desktop OS labels from SSH/SNMP banners.
	for _, osVal := range []string{"Ubuntu", "Debian", "macOS", "Windows"} {
		rep := reportWithFields("10.0.0.2", "camera", "", "", map[string]string{"os_type": osVal})
		require.Truef(t, isStrongPcSignal(rep), "os_type %q should be a strong PC signal", osVal)
	}
	// NOT strong: bare linux/freebsd (server-class) and non-laptop hostnames —
	// these must NOT trigger the camera→pc override (would mis-type cameras and
	// routers/NAS that expose RTSP web UIs).
	for _, c := range []struct{ host, osVal string }{
		{"", "Linux"},          // bare linux is server-class, not desktop
		{"orangepi-zero3", ""}, // SBC, not a laptop
		{"nas-box", ""},        // NAS appliance
	} {
		rep := reportWithFields("10.0.0.4", "camera", "", "",
			map[string]string{"node_hostname": c.host, "os_type": c.osVal})
		require.Falsef(t, isStrongPcSignal(rep),
			"hostname=%q os=%q must NOT be a strong PC signal (would mis-type cameras)", c.host, c.osVal)
	}
}

// TestIsStrongNasSignal pins the NAS override gate: NAS hostnames/brands
// (synology/qnap/z4s/zspace/minidlna/readymedia/ugreen/…) and an smb:445 service
// are strong NAS signals; a generic camera hostname or bare RTSP is NOT (the
// latter must not flip a camera to nas — real cameras expose RTSP).
func TestIsStrongNasSignal(t *testing.T) {
	// Strong: NAS hostnames.
	for _, h := range []string{"Z4S-2PSE", "DiskStation-DS920", "QNAP-TS453", "UGREEN-DXP4800"} {
		rep := reportWithFields("10.0.0.1", "camera", "", "", map[string]string{"node_hostname": h})
		require.Truef(t, isStrongNasSignal(rep), "hostname %q should be a strong NAS signal", h)
	}
	// Strong: NAS vendor strings.
	for _, b := range []string{"MiniDLNA", "ReadyMedia", "Synology", "QNAP", "ZSpace"} {
		rep := reportWithFields("10.0.0.2", "camera", b, "", nil)
		require.Truef(t, isStrongNasSignal(rep), "brand %q should be a strong NAS signal", b)
	}
	// Strong: smb:445 service (file sharing), even with no hostname/brand.
	rep := reportWithFields("10.0.0.3", "camera", "", "", nil)
	rep.Services = []scannerv2.ServiceIdentity{{Service: "smb", Port: 445}}
	require.True(t, isStrongNasSignal(rep), "smb:445 service should be a strong NAS signal")

	// NOT strong: a real camera hostname/brand with no NAS signal — must NOT
	// trigger the camera→nas override (real cameras expose RTSP).
	for _, c := range []struct{ host, brand string }{
		{"IPC-1234", "hikvision"},
		{"", "dahua"},
		{"DS-2CD2143", "hikvision"},
	} {
		rep := reportWithFields("10.0.0.4", "camera", c.brand, "", map[string]string{"node_hostname": c.host})
		require.Falsef(t, isStrongNasSignal(rep),
			"hostname=%q brand=%q must NOT be a strong NAS signal (real camera)", c.host, c.brand)
	}
}

// setupTypeTestDB is a lightweight in-memory DB + runner for the device-type
// tests (mirrors setupChangeDetectDB but local to this file to keep the
// classification tests self-contained).
func setupTypeTestDB(t *testing.T) (*Runner, *db.Queries, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	net, err := queries.CreateNetwork(context.Background(), db.CreateNetworkParams{Name: "type-test-net"})
	require.NoError(t, err)
	nid := sql.NullInt64{Int64: net.ID, Valid: true}

	rn := New(nil, queries, conn, nil, 0, nil)
	rn.networkID = nid
	rn.SetRepo(store.NewSQLiteRepository(conn, store.Options{NetworkID: net.ID}, nil))
	rn.SetChangeRecorder(changedetect.NewDBRecorder(queries, nil, 0, nil))
	return rn, queries, conn
}
