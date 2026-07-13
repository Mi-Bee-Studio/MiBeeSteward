package probe

import (
	"log/slog"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/vendor"
)

// DefaultProbeSources returns the standard set of active ProbeSources, ready to
// register into a scannerv2.Registry. The portSpec configures the TCP port
// scan; pass "" to scan only the fingerprint ports. oui enables MAC→vendor
// lookup in the ARP probe (may be nil — vendor is then simply omitted).
//
// Order matters only for determinism (the registry sorts by Name anyway).
func DefaultProbeSources(portSpec string, oui *vendor.OUI) []scannerv2.ProbeSource {
	return []scannerv2.ProbeSource{
		NewICMPProbe(),
		NewPortSpecProbe(portSpec, nil),
		NewSNMPProbe(),
		NewRTSPProbe(),
		NewONVIFProbe(),
		NewHTTPMetricsProbe(),
		NewHTTPProbe(),
		NewTLSProbe(),
		NewSMBProbe(0),
		NewARPProbe(oui),
		NewRDNSProbe(),
		NewMDNSProbe(),
		NewSSDPProbe(),
		NewNetBIOSProbe(),
		NewBridgeMIBProbe(slog.Default()),
	}
}
