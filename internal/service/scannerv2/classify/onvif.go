// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package classify

import (
	"mibee-steward/internal/service/scannerv2"
)

// ONVIFClassifier emits an "onvif" identity from ONVIF SOAP-response evidence
// (kind="onvif_response"). It also extracts the Server header as candidate
// brand metadata (camera vendors like Hikvision/Dahua put their name there).
type ONVIFClassifier struct{}

func (ONVIFClassifier) Service() string { return "onvif" }

func (ONVIFClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	var out []scannerv2.ServiceIdentity
	for _, e := range ev {
		if e.Kind != "onvif_response" {
			continue
		}
		md := map[string]string{}
		if e.RawData != nil {
			if s, ok := e.RawData["server"]; ok {
				md["server"] = s
				if b := brandFromServerHeader(s); b != "" {
					md["inferred_brand"] = b
				}
			}
			if e.RawData["auth_required"] == "true" {
				md["auth_required"] = "true"
			}
		}
		out = append(out, scannerv2.ServiceIdentity{
			Service:    "onvif",
			Port:       e.Port,
			Protocol:   "tcp",
			Confidence: fuseConfidence(e.Confidence, 0.85),
			Evidence:   []scannerv2.Evidence{e},
			Metadata:   md,
		})
	}
	return out
}

// brandFromServerHeader extracts a camera brand from an RTSP/ONVIF Server
// header value (e.g. "Hikvision-ONVIF/1.0" → "Hikvision").
func brandFromServerHeader(server string) string {
	known := []string{
		"Hikvision", "Dahua", "Axis", "Bosch", "Sony", "Hanwha",
		"Vivotek", "Reolink", "Uniview", "Honeywell", "FLIR",
	}
	lower := serverLower(server)
	for _, b := range known {
		if contains(lower, serverLower(b)) {
			return b
		}
	}
	return ""
}

func serverLower(s string) string {
	// inline lowercasing without allocating a new package helper conflict
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func contains(s, sub string) bool {
	return len(sub) == 0 || indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
