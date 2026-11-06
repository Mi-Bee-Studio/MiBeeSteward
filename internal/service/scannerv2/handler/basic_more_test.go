// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"testing"
)

// Coverage-headroom tests (#697) for the simple identity handlers: the
// no-op Collects, the heartbeat shapes, and the enrichment field rules.
// These handlers run on every scan of every camera/ONVIF/SNMP device; the
// enrichment semantics (direct set vs preserve-existing) are user-visible.

func TestONVIFHandler_HeartbeatAndEnrich(t *testing.T) {
	h := ONVIFHandler{}
	ctx := svcCtx("10.0.0.5", 80, "onvif", nil)

	hb := h.GenerateHeartbeat(ctx)
	if hb.Method != "http" {
		t.Errorf("onvif heartbeat method = %q, want http", hb.Method)
	}
	if hb.Target != "http://10.0.0.5:80/onvif/device_service" {
		t.Errorf("onvif heartbeat target = %q", hb.Target)
	}

	// Collect is a no-op for this handler.
	data, triggers, err := h.Collect(context.Background(), ctx)
	if data != nil || triggers != nil || err != nil {
		t.Errorf("onvif Collect = (%v, %v, %v), want nils", data, triggers, err)
	}

	// EnrichDevice pins the camera type and preserves an existing brand.
	ctx = svcCtx("10.0.0.5", 80, "onvif", map[string]string{"inferred_brand": "Hikvision"})
	h.EnrichDevice(ctx, nil)
	if got := ctx.Device.Fields["inferred_type"]; got != "camera" {
		t.Errorf("inferred_type = %q, want camera", got)
	}
	if got := ctx.Device.Fields["inferred_brand"]; got != "Hikvision" {
		t.Errorf("inferred_brand = %q, want Hikvision", got)
	}
}

func TestCameraHandler_HeartbeatAndEnrich(t *testing.T) {
	h := CameraHandler{}
	ctx := svcCtx("10.0.0.6", 554, "rtsp", nil)

	hb := h.GenerateHeartbeat(ctx)
	if hb.Method != "icmp" || hb.Target != "10.0.0.6" {
		t.Errorf("camera heartbeat = %+v, want icmp to the host IP", hb)
	}

	data, triggers, err := h.Collect(context.Background(), ctx)
	if data != nil || triggers != nil || err != nil {
		t.Errorf("camera Collect = (%v, %v, %v), want nils", data, triggers, err)
	}

	ctx = svcCtx("10.0.0.6", 554, "rtsp", map[string]string{"inferred_brand": "Reolink"})
	h.EnrichDevice(ctx, nil)
	if got := ctx.Device.Fields["inferred_type"]; got != "camera" {
		t.Errorf("inferred_type = %q, want camera (set directly, high confidence)", got)
	}
	if got := ctx.Device.Fields["inferred_brand"]; got != "Reolink" {
		t.Errorf("inferred_brand = %q, want Reolink", got)
	}
}

func TestSNMPHandler_HeartbeatAndEnrich(t *testing.T) {
	h := SNMPHandler{}

	// Default community when the identity carries none.
	hb := h.GenerateHeartbeat(svcCtx("10.0.0.7", 161, "snmp", nil))
	if hb.Method != "snmp" || hb.SNMPCommunity != "public" {
		t.Errorf("snmp heartbeat = %+v, want default public community", hb)
	}
	// Explicit community passes through.
	hb = h.GenerateHeartbeat(svcCtx("10.0.0.7", 161, "snmp", map[string]string{"snmp_community": "netbox"}))
	if hb.SNMPCommunity != "netbox" {
		t.Errorf("snmp community = %q, want netbox", hb.SNMPCommunity)
	}

	data, triggers, err := h.Collect(context.Background(), svcCtx("10.0.0.7", 161, "snmp", nil))
	if data != nil || triggers != nil || err != nil {
		t.Errorf("snmp Collect = (%v, %v, %v), want nils", data, triggers, err)
	}

	ctx := svcCtx("10.0.0.7", 161, "snmp", map[string]string{
		"inferred_type": "switch", "inferred_brand": "MikroTik", "sys_descr": "RouterOS 7.14",
	})
	h.EnrichDevice(ctx, nil)
	for k, want := range map[string]string{
		"inferred_type": "switch", "inferred_brand": "MikroTik", "inferred_description": "RouterOS 7.14",
	} {
		if got := ctx.Device.Fields[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}
