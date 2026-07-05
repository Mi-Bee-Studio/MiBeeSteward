package probe

import (
	"mibee-steward/internal/service/scannerv2"
)

// DefaultProbeSources returns the standard set of active ProbeSources, ready to
// register into a scannerv2.Registry. The portSpec configures the TCP port
// scan; pass "" to scan only the fingerprint ports.
//
// Order matters only for determinism (the registry sorts by Name anyway).
func DefaultProbeSources(portSpec string) []scannerv2.ProbeSource {
	return []scannerv2.ProbeSource{
		NewICMPProbe(),
		NewPortSpecProbe(portSpec, nil),
		NewSNMPProbe(),
		NewRTSPProbe(),
		NewONVIFProbe(),
		NewHTTPMetricsProbe(),
	}
}
