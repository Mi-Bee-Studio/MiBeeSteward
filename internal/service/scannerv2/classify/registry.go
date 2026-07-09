package classify

import "mibee-steward/internal/service/scannerv2"

// DefaultClassifiers returns the standard set of ServiceClassifiers, ready to
// register into a scannerv2.Registry.
//
// The pure-data classifiers (Banner/HTTP/RTSP/ONVIF/Prometheus/Mail/Web/TLS/
// Misc) are now FULLY COVERED by the RuleClassifier's YAML rules — running
// both caused duplicate identities and 100+ UNIQUE-constraint warnings per
// scan (last-writer-wins on the dedup map dropped the richer rule-based
// metadata, e.g. os_type). So those code classifiers are NO LONGER registered
// when a loaded RuleClassifier is available.
//
// The logic-retained classifiers (SNMP bitmask heuristic, Camera cross-evidence
// fusion, Database byte-offset/dedup, RemoteAccess byte-offset/dedup) stay as
// code — they express logic the declarative rule format intentionally can't
// (see docs/fingerprint-spec.md §"Logic plugins").
func DefaultClassifiers(rule *RuleClassifier) []scannerv2.ServiceClassifier {
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
