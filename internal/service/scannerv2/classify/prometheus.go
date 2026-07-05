package classify

import (
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// PrometheusClassifier inspects /metrics evidence (kind="metric") and emits
// "prometheus" or "node_exporter" identities based on metric-name signatures
// in the content sample. node_exporter is the high-value case (carries host
// hardware info), so it's detected preferentially when node_ metrics appear.
type PrometheusClassifier struct{}

func (PrometheusClassifier) Service() string { return "prometheus" }

func (PrometheusClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	var out []scannerv2.ServiceIdentity
	for _, e := range ev {
		if e.Kind != "metric" {
			continue
		}
		sample := ""
		url := ""
		if e.RawData != nil {
			sample = e.RawData["content_sample"]
			url = e.RawData["url"]
		}
		if sample == "" {
			continue
		}
		isNode := strings.Contains(sample, "node_") || strings.Contains(sample, "node_exporter_build_info")
		isProm := strings.Contains(sample, "prometheus_") || strings.Contains(sample, "prometheus_build_info")

		switch {
		case isNode:
			out = append(out, scannerv2.ServiceIdentity{
				Service: "node_exporter", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.95),
				Evidence:   []scannerv2.Evidence{e},
				Metadata: map[string]string{
					"metrics_url":  url,
					"content_kind": "node_exporter",
				},
			})
		case isProm:
			out = append(out, scannerv2.ServiceIdentity{
				Service: "prometheus", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.9),
				Evidence:   []scannerv2.Evidence{e},
				Metadata: map[string]string{
					"metrics_url":  url,
					"content_kind": "prometheus",
				},
			})
		}
	}
	return out
}
