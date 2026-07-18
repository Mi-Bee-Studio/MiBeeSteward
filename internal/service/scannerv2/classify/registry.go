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
	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"

	"mibee-steward/internal/service/scannerv2"
)

// DefaultClassifiers returns the standard set of ServiceClassifiers, ready to
// register into a scannerv2.Registry.
//
// The data-driven RuleClassifier comes from the standalone fingerprint library
// (github.com/Mi-Bee-Studio/mibee-fingerprints-go). When loaded, it replaces
// the 9 pure-data code classifiers (Banner/HTTP/RTSP/ONVIF/Prometheus/Mail/Web/
// TLS/Misc) which are now YAML rules in the mibee-fingerprints data repo.
//
// The logic-retained classifiers (SNMP bitmask heuristic, Camera cross-evidence
// fusion, Database byte-offset/dedup, RemoteAccess byte-offset/dedup) stay as
// code — they express logic the declarative rule format intentionally can't.
func DefaultClassifiers(rule *fp.RuleClassifier) []scannerv2.ServiceClassifier {
	out := []scannerv2.ServiceClassifier{}
	ruleActive := rule != nil && rule.Loaded()
	if ruleActive {
		out = append(out, rule)
	}
	// Logic-retained classifiers — always registered (not expressible as rules).
	out = append(out,
		SNMPClassifier{},
		CameraClassifier{},
		DatabaseClassifier{},
		RemoteAccessClassifier{},
	)
	// Pure-data classifiers — only registered as a FALLBACK when no rule
	// classifier is loaded (e.g. unit tests passing nil). When rules are active
	// they are fully covered and would only cause duplicate-identity conflicts.
	if !ruleActive {
		out = append(out,
			BannerClassifier{},
			HTTPClassifier{},
			RTSPClassifier{},
			ONVIFClassifier{},
			PrometheusClassifier{},
			MailClassifier{},
			WebClassifier{},
			TLSClassifier{},
			MiscClassifier{},
		)
	}
	return out
}
