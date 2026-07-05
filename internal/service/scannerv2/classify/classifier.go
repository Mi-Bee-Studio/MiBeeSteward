// Package classify implements the ② Classifier layer of scannerv2.
//
// Classifiers are pure functions over Evidence: given a host's full evidence
// set, they emit zero or more ServiceIdentity assertions. They never touch
// the network, the device record, or the database. This purity is what lets
// the orchestrator run them in any order and lets tests be deterministic.
//
// To add a new protocol: implement ServiceClassifier and register it via
// DefaultClassifiers() (or RegisterClassifier at construction time). No other
// layer needs changing.
package classify

import (
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// fuseConfidence combines several confidence values into one by taking the
// complement of the product of (1-c) — i.e. independent evidence reinforces.
// A single source keeps its confidence; two 0.9 sources yield ~0.99.
func fuseConfidence(cs ...float64) float64 {
	prod := 1.0
	for _, c := range cs {
		if c < 0 {
			c = 0
		}
		if c > 1 {
			c = 1
		}
		prod *= (1 - c)
	}
	r := 1 - prod
	if r > 1 {
		r = 1
	}
	return r
}

// byPortAndKind indexes evidence by (port, kind) for quick lookup, plus a
// per-port view. Classifiers use it to answer "what do we know about port N?".
type evidenceIndex struct {
	byKind map[string][]scannerv2.Evidence // kind → all matching (any port)
	byPort map[int][]scannerv2.Evidence    // port → all evidence for that port
	snmp   []scannerv2.Evidence            // kind=="snmp" (host-level)
	icmp   []scannerv2.Evidence            // kind=="echo"
}

func indexEvidence(ev []scannerv2.Evidence) evidenceIndex {
	idx := evidenceIndex{
		byKind: make(map[string][]scannerv2.Evidence),
		byPort: make(map[int][]scannerv2.Evidence),
	}
	for _, e := range ev {
		idx.byKind[e.Kind] = append(idx.byKind[e.Kind], e)
		if e.Port != 0 {
			idx.byPort[e.Port] = append(idx.byPort[e.Port], e)
		}
		if e.Kind == "snmp" {
			idx.snmp = append(idx.snmp, e)
		}
		if e.Kind == "echo" {
			idx.icmp = append(idx.icmp, e)
		}
	}
	return idx
}

// bannerText returns the banner string for evidence at a port ("" if none).
func bannerText(e scannerv2.Evidence) string {
	if e.RawData == nil {
		return ""
	}
	return e.RawData["banner"]
}

// hasPrefix tests whether s starts with any of the prefixes (case-insensitive).
func hasPrefix(s string, prefixes ...string) bool {
	up := strings.ToUpper(s)
	for _, p := range prefixes {
		if strings.HasPrefix(up, strings.ToUpper(p)) {
			return true
		}
	}
	return false
}
