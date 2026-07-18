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

// RTSPClassifier emits an "rtsp" identity from RTSP-banner evidence
// (kind="rtsp_banner"), capturing the Server header as brand candidate.
type RTSPClassifier struct{}

func (RTSPClassifier) Service() string { return "rtsp" }

func (RTSPClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	var out []scannerv2.ServiceIdentity
	for _, e := range ev {
		if e.Kind != "rtsp_banner" {
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
			if s, ok := e.RawData["status"]; ok {
				md["status"] = s
			}
		}
		out = append(out, scannerv2.ServiceIdentity{
			Service:    "rtsp",
			Port:       e.Port,
			Protocol:   "tcp",
			Confidence: fuseConfidence(e.Confidence, 0.95),
			Evidence:   []scannerv2.Evidence{e},
			Metadata:   md,
		})
	}
	return out
}

// CameraClassifier is a meta-classifier: it asserts a host-level "camera"
// identity when RTSP and/or ONVIF services are present. This drives the device
// type to "camera" and the camera ServiceHandler (Phase 3) will generate an
// RTSP/TCP heartbeat. It runs after the protocol classifiers, consuming their
// identities — but since classifiers are pure over evidence (not identities),
// we re-derive from the underlying rtsp/onvif evidence.
type CameraClassifier struct{}

func (CameraClassifier) Service() string { return "camera" }

func (CameraClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	var rtsp, onvif []scannerv2.Evidence
	for _, e := range ev {
		switch e.Kind {
		case "rtsp_banner":
			rtsp = append(rtsp, e)
		case "onvif_response":
			onvif = append(onvif, e)
		}
	}
	if len(rtsp) == 0 && len(onvif) == 0 {
		return nil
	}
	// Fuse confidence across the camera-relevant evidence.
	allEvidence := append(append([]scannerv2.Evidence{}, rtsp...), onvif...)
	confs := make([]float64, 0, len(allEvidence))
	for _, e := range allEvidence {
		confs = append(confs, e.Confidence)
	}
	md := map[string]string{}
	// Prefer RTSP server header for brand, fall back to ONVIF.
	for _, e := range rtsp {
		if e.RawData != nil {
			if s := e.RawData["server"]; s != "" {
				md["server"] = s
				break
			}
		}
	}
	if md["server"] == "" {
		for _, e := range onvif {
			if e.RawData != nil {
				if s := e.RawData["server"]; s != "" {
					md["server"] = s
					break
				}
			}
		}
	}
	if s := md["server"]; s != "" {
		if b := brandFromServerHeader(s); b != "" {
			md["inferred_brand"] = b
		}
	}
	// The camera identity is host-level (no single port); pick the first
	// observed RTSP port if any, else the first ONVIF port.
	port := 0
	if len(rtsp) > 0 {
		port = rtsp[0].Port
	} else if len(onvif) > 0 {
		port = onvif[0].Port
	}
	return []scannerv2.ServiceIdentity{{
		Service:    "camera",
		Port:       port,
		Protocol:   "tcp",
		Confidence: fuseConfidence(confs...),
		Evidence:   allEvidence,
		Metadata:   md,
	}}
}

// HTTPClassifier emits an "http" identity for any open HTTP-banner port that
// wasn't already claimed by a more specific classifier. This ensures web
// servers get a heartbeat and become cascade candidates (http → /metrics →
// prometheus/node_exporter).
type HTTPClassifier struct{}

func (HTTPClassifier) Service() string { return "http" }

func (HTTPClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	var out []scannerv2.ServiceIdentity
	idx := indexEvidence(ev)
	for _, e := range idx.byKind["banner"] {
		b := bannerText(e)
		if !hasPrefix(b, "HTTP/") {
			continue
		}
		out = append(out, scannerv2.ServiceIdentity{
			Service:    "http",
			Port:       e.Port,
			Protocol:   "tcp",
			Confidence: fuseConfidence(e.Confidence, 0.75),
			Evidence:   []scannerv2.Evidence{e},
			Metadata:   map[string]string{"banner": b},
		})
	}
	return out
}
