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
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// SSDP device description XML fetch (#506)
// ---------------------------------------------------------------------------

// The UPnP device description a LOCATION header points at is the most
// authoritative structured self-description a UPnP device offers
// (friendlyName / manufacturer / modelName / modelNumber / UDN). mDNS-side
// deep TXT parsing already existed; this closes the SSDP gap.

// validateSSDPLocation guards the description fetch: UPnP LOCATION URLs are
// spec'd as http(s) with the DEVICE'S OWN address as host. Anything else
// (another host, a DNS name, a non-HTTP scheme) is refused — a hostile device
// must not turn the scanner into an SSRF proxy.
func validateSSDPLocation(location, targetIP string) bool {
	if location == "" || targetIP == "" {
		return false
	}
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Hostname() == targetIP
}

// upnpDescription mirrors the device node of a UPnP description document.
// Go's encoding/xml matches local names regardless of namespace, which the
// urn:schemas-upnp-org:device-1-0 types need.
type upnpDescription struct {
	XMLName xml.Name `xml:"root"`
	Device  struct {
		FriendlyName     string `xml:"friendlyName"`
		Manufacturer     string `xml:"manufacturer"`
		ManufacturerURL  string `xml:"manufacturerURL"`
		ModelDescription string `xml:"modelDescription"`
		ModelName        string `xml:"modelName"`
		ModelNumber      string `xml:"modelNumber"`
		UDN              string `xml:"UDN"`
		DeviceType       string `xml:"deviceType"`
	} `xml:"device"`
}

// parseUPnPDescription extracts the identity fields we keep. Returns nil when
// the document carries none of them (not a device description).
func parseUPnPDescription(body []byte) map[string]string {
	var d upnpDescription
	if err := xml.Unmarshal(body, &d); err != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range map[string]string{
		"friendly_name":     strings.TrimSpace(d.Device.FriendlyName),
		"manufacturer":      strings.TrimSpace(d.Device.Manufacturer),
		"model_name":        strings.TrimSpace(d.Device.ModelName),
		"model_number":      strings.TrimSpace(d.Device.ModelNumber),
		"model_description": strings.TrimSpace(d.Device.ModelDescription),
		"udn":               strings.TrimSpace(d.Device.UDN),
		"device_type":       strings.TrimSpace(d.Device.DeviceType),
	} {
		if v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// descHTTPClient: no redirects (the description lives AT the LOCATION), hard
// size cap via LimitReader in fetchUPnPDescription.
var descHTTPClient = &http.Client{
	Timeout: 2 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchUPnPDescription GETs the LOCATION and parses it. The timeout must be
// the probe's remaining budget (the per-probe cap is enforced by the
// orchestrator; staying inside it keeps the whole SSDP round safe).
func fetchUPnPDescription(ctx context.Context, location string, timeout time.Duration) map[string]string {
	client := descHTTPClient
	if timeout > 0 && timeout < client.Timeout {
		client = &http.Client{Timeout: timeout, CheckRedirect: client.CheckRedirect}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return parseUPnPDescription(body)
}
