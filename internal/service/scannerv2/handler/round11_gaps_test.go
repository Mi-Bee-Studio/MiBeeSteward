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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBasicHandlers_GenerateHeartbeat pins the per-service heartbeat specs:
// method + target formatting for the TCP-family handlers.
func TestBasicHandlers_GenerateHeartbeat(t *testing.T) {
	svc := svcCtx("10.20.0.1", 22, "", nil)

	spec := (SSHHandler{}).GenerateHeartbeat(svc)
	require.Equal(t, "tcp", spec.Method)
	require.Equal(t, "10.20.0.1:22", spec.Target)

	spec = (RTSPHandler{}).GenerateHeartbeat(svcCtx("10.20.0.2", 554, "", nil))
	require.Equal(t, "tcp", spec.Method)
	require.Equal(t, "10.20.0.2:554", spec.Target)

	spec = (ONVIFHandler{}).GenerateHeartbeat(svcCtx("10.20.0.3", 8000, "", nil))
	require.NotNil(t, spec)
	require.Equal(t, "http", spec.Method)
	require.Contains(t, spec.Target, "/onvif/device_service")

	spec = (SNMPHandler{}).GenerateHeartbeat(svcCtx("10.20.0.4", 161, "", nil))
	require.NotNil(t, spec)
	require.Equal(t, "snmp", spec.Method)

	spec = (HTTPHandler{}).GenerateHeartbeat(svcCtx("10.20.0.5", 80, "", nil))
	require.NotNil(t, spec)
	require.Equal(t, "http", spec.Method)

	spec = (PrometheusHandler{}).GenerateHeartbeat(svcCtx("10.20.0.6", 9090, "", nil))
	require.NotNil(t, spec)

	// NodeExporter rides on the Prometheus heartbeat (depth-1 cascade) → nil.
	require.Nil(t, (NodeExporterHandler{}).GenerateHeartbeat(svcCtx("10.20.0.7", 9100, "", nil)))

	// No-collect handlers return nils, not errors.
	data, triggers, err := (SSHHandler{}).Collect(context.Background(), svc)
	require.NoError(t, err)
	require.Nil(t, data)
	require.Nil(t, triggers)
}

// TestSSHHandler_EnrichDevice pins the banner→type/OS propagation rules
// (Windows→pc, os_type preserved when not already set).
func TestSSHHandler_EnrichDevice(t *testing.T) {
	svc := svcCtx("10.20.1.1", 22, "", nil)
	svc.Identity.Metadata = map[string]string{"version": "SSH-2.0-OpenSSH_for_Windows_9.5", "os_type": "windows"}
	(SSHHandler{}).EnrichDevice(svc, nil)
	require.Equal(t, "pc", svc.Device.Fields["inferred_type"])
	require.Equal(t, "windows", svc.Device.Fields["os_type"])

	// An existing stronger type is preserved (Linux box already typed camera).
	svc2 := svcCtx("10.20.1.2", 22, "", nil)
	svc2.Identity.Metadata = map[string]string{"os_type": "linux"}
	svc2.Device.Fields["inferred_type"] = "camera"
	(SSHHandler{}).EnrichDevice(svc2, nil)
	require.Equal(t, "camera", svc2.Device.Fields["inferred_type"])
	require.Equal(t, "linux", svc2.Device.Fields["os_type"])
}

// TestHTTPHandler_Collect_Cascade: a live local HTTP server with /metrics
// triggers the prometheus cascade with the sample threaded through context.
func TestHTTPHandler_Collect_Cascade(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			_, _ = w.Write([]byte("# HELP x"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(up.Close)
	svcPort := urlPort(t, up.URL)

	h := HTTPHandler{}
	data, triggers, err := h.Collect(context.Background(), svcCtx("127.0.0.1", svcPort, "", nil))
	require.NoError(t, err)
	require.NotEmpty(t, triggers, "metrics endpoint must trigger the prometheus cascade")
	require.Equal(t, "prometheus", triggers[0].Service)
	require.Contains(t, triggers[0].Context["metrics_url"], "/metrics")
	require.NotEmpty(t, triggers[0].Context["sample"])
	require.Equal(t, true, data.(HTTPData).MetricsFound)

	// No /metrics → no trigger.
	nometrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(nometrics.Close)
	data, triggers, err = h.Collect(context.Background(), svcCtx("127.0.0.1", urlPort(t, nometrics.URL), "", nil))
	require.NoError(t, err)
	require.Nil(t, triggers)
	require.False(t, data.(HTTPData).MetricsFound)
}

// urlPort extracts the numeric port from a test server's base URL.
func urlPort(t *testing.T, baseURL string) int {
	t.Helper()
	u, err := url.Parse(baseURL)
	require.NoError(t, err)
	p, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	return p
}

func TestWebTypeFromHints(t *testing.T) {
	svc := svcCtx("10.20.2.1", 80, "", nil)
	svc.Identity.Metadata = map[string]string{"server": "RouterOS httpd", "title": "MikroTik"}
	require.Equal(t, "router", webTypeFromHints(svc))

	svc.Identity.Metadata = map[string]string{"server": "Synology DiskStation"}
	require.Equal(t, "nas", webTypeFromHints(svc))

	svc.Identity.Metadata = map[string]string{"title": "Hikvision"}
	require.Equal(t, "camera", webTypeFromHints(svc))

	// Device-field hostname hint participates too.
	svc3 := svcCtx("10.20.2.2", 80, "", nil)
	svc3.Device.Fields["node_hostname"] = "nanopi-main"
	require.Equal(t, "embedded", webTypeFromHints(svc3))

	svc.Identity.Metadata = map[string]string{"server": "nginx"}
	require.Equal(t, "", webTypeFromHints(svc), "generic web server yields no hint (caller defaults)")

	require.Equal(t, "synology", lowercase("Synology"))
	require.True(t, containsAny("a hikvision device", "hikvision"))
	require.False(t, containsAny("plain", "nope"))
}
