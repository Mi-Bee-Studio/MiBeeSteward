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

// Coverage-headroom tests (#697) for the passive-identity handlers
// (mdns/dhcp/ssdp): no heartbeat (announcements carry no probeable port),
// no-op Collect, and the shared mdnsSsdpEnrich field rules — type/brand/
// description/model flow through preserve-existing so stronger in-protocol
// evidence stays in charge.

func TestMdnsHandler_NoHeartbeatNoopCollectEnrich(t *testing.T) {
	h := MdnsHandler{}
	ctx := svcCtx("10.0.0.10", 5353, "mdns", map[string]string{
		"inferred_type": "printer", "inferred_brand": "Brother",
		"inferred_description": "Brother HL", "model": "HL-L2350",
	})

	if hb := h.GenerateHeartbeat(ctx); hb != nil {
		t.Errorf("mdns heartbeat = %+v, want nil (announcements carry no probeable port)", hb)
	}
	data, triggers, err := h.Collect(context.Background(), ctx)
	if data != nil || triggers != nil || err != nil {
		t.Errorf("mdns Collect = (%v, %v, %v), want nils", data, triggers, err)
	}

	h.EnrichDevice(ctx, nil)
	for k, want := range map[string]string{
		"inferred_type": "printer", "inferred_brand": "Brother",
		"inferred_description": "Brother HL", "inferred_model": "HL-L2350",
	} {
		if got := ctx.Device.Fields[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestDhcpHandler_MatchesMdnsEnrich(t *testing.T) {
	h := DhcpHandler{}
	ctx := svcCtx("10.0.0.11", 67, "dhcp", map[string]string{"inferred_brand": "RaspberryPi"})

	if hb := h.GenerateHeartbeat(ctx); hb != nil {
		t.Errorf("dhcp heartbeat = %+v, want nil", hb)
	}
	data, triggers, err := h.Collect(context.Background(), ctx)
	if data != nil || triggers != nil || err != nil {
		t.Errorf("dhcp Collect = (%v, %v, %v), want nils", data, triggers, err)
	}

	h.EnrichDevice(ctx, nil)
	if got := ctx.Device.Fields["inferred_brand"]; got != "RaspberryPi" {
		t.Errorf("inferred_brand = %q, want RaspberryPi", got)
	}
}

func TestSsdpHandler_MatchesMdnsEnrich(t *testing.T) {
	h := SsdpHandler{}
	ctx := svcCtx("10.0.0.12", 1900, "ssdp", map[string]string{"inferred_type": "nvr"})

	if hb := h.GenerateHeartbeat(ctx); hb != nil {
		t.Errorf("ssdp heartbeat = %+v, want nil", hb)
	}
	data, triggers, err := h.Collect(context.Background(), ctx)
	if data != nil || triggers != nil || err != nil {
		t.Errorf("ssdp Collect = (%v, %v, %v), want nils", data, triggers, err)
	}

	h.EnrichDevice(ctx, nil)
	if got := ctx.Device.Fields["inferred_type"]; got != "nvr" {
		t.Errorf("inferred_type = %q, want nvr", got)
	}
}

func TestMdnsSsdpEnrich_EmptyMetadataIsNoop(t *testing.T) {
	ctx := svcCtx("10.0.0.13", 5353, "mdns", nil)
	mdnsSsdpEnrich(ctx)
	if len(ctx.Device.Fields) != 0 {
		t.Errorf("empty metadata must not add fields, got %v", ctx.Device.Fields)
	}
}
