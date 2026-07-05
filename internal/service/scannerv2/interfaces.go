package scannerv2

import "context"

// ProbeSource is the ① Probe layer interface. Every active probe and passive
// observer implements it. A probe gathers Evidence about a single IP; it does
// no classification and writes nothing to the DB.
//
// Two families of implementation exist:
//   - Active probes (TCP banner, SNMP, RTSP, ONVIF, HTTP-metrics) take a hint
//     and synchronously return evidence for one IP.
//   - Passive observers (eBPF TC) ignore the hint; they run a long-lived
//     capture and emit evidence asynchronously. For passive sources, Probe()
//     returns evidence observed for the IP since the last call (or empty).
type ProbeSource interface {
	// Name identifies the source, e.g. "active:tcp", "passive:ebpf:tc".
	Name() string

	// Probe gathers evidence for ip. hint is advisory (ports, community,
	// timeout). The returned evidence is best-effort: a probe may return
	// partial results alongside an error (e.g. context deadline mid-scan).
	Probe(ctx context.Context, ip string, hint ProbeHint) ([]Evidence, error)
}

// ServiceClassifier is the ② Classifier layer interface. One implementation
// per protocol family. It consumes the full evidence set for a host and emits
// zero or more ServiceIdentities it is confident about.
//
// Classifiers must be pure and side-effect-free: the same evidence always
// yields the same identities. Persistence is the orchestrator's job.
type ServiceClassifier interface {
	// Service is the canonical service name this classifier emits (e.g. "ssh").
	// Used for registration lookup and deduplication.
	Service() string

	// Classify inspects evidence and returns identities it can assert. It must
	// not error on unrecognized evidence — it simply returns nothing.
	Classify(evidence []Evidence) []ServiceIdentity
}

// ServiceHandler is the ③ per-service customization layer. For each
// identified service it (a) generates an adapted heartbeat, (b) optionally
// performs deep collection that may trigger other handlers (cascade), and
// (c) enriches the device record with collected attributes.
//
// Handlers MAY return nil heartbeat / nil data / nil triggers when not
// applicable. Returning a Trigger drives the cascade (see package doc).
type ServiceHandler interface {
	// Service is the canonical service name this handler serves. It must match
	// a ServiceClassifier.Service() output for the orchestrator to dispatch.
	Service() string

	// GenerateHeartbeat returns a heartbeat spec adapted to this service, or
	// nil if no service-specific heartbeat is warranted (the orchestrator will
	// still synthesize a default ICMP heartbeat for the host).
	GenerateHeartbeat(svc ServiceContext) *HeartbeatSpec

	// Collect performs deep, possibly-networked gathering for this service.
	// It returns the data (for EnrichDevice) and zero or more Triggers to
	// invoke other handlers (e.g. http → prometheus → node_exporter).
	// ctx carries the per-host deadline; honor cancellation.
	Collect(ctx context.Context, svc ServiceContext) (data CollectedData, triggers []Trigger, err error)

	// EnrichDevice applies collected data to the device record. It must be
	// deterministic and side-effect-free except for mutating svc.Device.
	EnrichDevice(svc ServiceContext, data CollectedData)
}
