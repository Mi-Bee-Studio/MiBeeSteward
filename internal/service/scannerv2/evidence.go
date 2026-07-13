// Package scannerv2 implements a declarative, plugin-based network scanner.
//
// Architecture (5 orthogonal, independently-extensible layers):
//
//	① Probe        — collects Evidence (active probes / passive eBPF observers)
//	② Classifier   — turns Evidence into ServiceIdentity (per-protocol, registered)
//	③ ServiceHandler — per-service deep collection + heartbeat gen + device enrich (cascading)
//	④ Persistence  — repository interfaces; business layers never touch sqlc directly
//	⑤ Orchestrator — declarative pipeline driving the four layers with cascade triggers
//
// Adding a new protocol requires only (a) a Classifier and (b) a ServiceHandler,
// registered at startup. The orchestrator and persistence layers are untouched.
//
// This package (scannerv2) is the v2 engine. During the transition it coexists
// with the legacy internal/service/scanner package; a config flag selects which
// engine is wired into the API. See Phase 5 of the rebuild plan.
package scannerv2

import (
	"time"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"
)

// Evidence and ServiceIdentity are now type aliases to the standalone
// fingerprint library (github.com/Mi-Bee-Studio/mibee-fingerprints-go). This
// makes them compile-time
// identical to fp.Evidence / fp.ServiceIdentity — no conversion needed at the
// integration boundary. The RuleClassifier in the fingerprint library operates
// directly on these types.
//
// The canonical type definitions live in the fingerprint library's
// fingerprint.go. This alias exists so the scannerv2 package (probes, handlers,
// orchestrator) can reference Evidence/ServiceIdentity without importing the
// library at every use site.
type Evidence = fp.Evidence

// ServiceIdentity is a classified assertion (type alias → fp.ServiceIdentity).
type ServiceIdentity = fp.ServiceIdentity

// ServiceClassifier is the interface a classifier implements (type alias).
type ServiceClassifier = fp.ServiceClassifier

// ProbeHint carries context a probe may use to focus its work. It is advisory:
// probes may ignore it. For example, an active TCP probe given known open ports
// can skip re-confirming them; a passive observer ignores it entirely.
type ProbeHint struct {
	// Ports are ports already believed open on the target (may be empty).
	Ports []int `json:"ports,omitempty"`
	// Community is the SNMP community string to try (default "public").
	Community string `json:"community,omitempty"`
	// Timeout per individual probe attempt.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// CollectedData is the opaque result of a ServiceHandler.Collect call. It is
// passed back to EnrichDevice so handlers can separate "fetch" from "apply"
// (useful for batching persistence and for tests). Implementations define their
// own concrete types; the orchestrator treats it as a pass-through.
type CollectedData interface {
	// Service returns the service this collection was for (matches the handler).
	Service() string
}

// HeartbeatSpec describes a heartbeat config adapted to a specific service.
// ServiceHandlers produce these; the persistence layer persists them.
type HeartbeatSpec struct {
	Method          string `json:"method"`           // "icmp" | "tcp" | "http" | "snmp"
	Target          string `json:"target"`           // host, host:port, or URL
	IntervalSeconds int    `json:"interval_seconds"` // 0 → use default
	TimeoutSeconds  int    `json:"timeout_seconds"`  // 0 → use default
	SNMPCommunity   string `json:"snmp_community,omitempty"`
	SNMPOID         string `json:"snmp_oid,omitempty"`
}

// NeighborSpec describes one L2 adjacency edge discovered via LLDP / CDP /
// Bridge-MIB / ARP. The persistence layer resolves ip → device_id and upserts
// on (device_id, neighbor_mac, protocol). NeighborMAC is the cross-agent merge
// key (a device seen as a neighbor before it's scanned itself gets a NULL
// neighbor_device_id until reconciled).
type NeighborSpec struct {
	NeighborMAC string // canonical "aa:bb:cc:dd:ee:ff" (the merge key)
	Protocol    string // "LLDP" | "CDP" | "Bridge-MIB" | "ARP"
	LocalPort   string // local port label (ifIndex / port name)
	RemotePort  string // remote port label
}

// Trigger requests the orchestrator to invoke another ServiceHandler. This is
// the cascade mechanism: e.g. an HTTP handler that finds a Prometheus endpoint
// returns a Trigger{Service:"prometheus", Port:...} so the Prometheus handler
// runs next. The orchestrator enforces a visited-set + depth cap to prevent
// cycles (see Orchestrator default MaxCascadeDepth).
type Trigger struct {
	Service string `json:"service"`
	Port    int    `json:"port,omitempty"`
	// Context carries forward information from the triggering handler (e.g. the
	// /metrics URL it discovered). The triggered handler reads it.
	Context map[string]string `json:"context,omitempty"`
}

// ServiceContext is the input bundle handed to a ServiceHandler.
type ServiceContext struct {
	IP       string
	Identity ServiceIdentity
	// Device is the known device record (may be nil for newly-discovered hosts).
	Device DeviceRef
	// Evidence is the full evidence set for this host (not just this service),
	// enabling handlers to reason about co-located services.
	Evidence []Evidence
}

// DeviceRef is a minimal, read-write view of a device that handlers update via
// EnrichDevice. It abstracts over the concrete domain.Device / DB row so the
// scannerv2 package need not import domain or db.
type DeviceRef struct {
	IP    string
	Name  string
	Type  string
	Brand string
	Model string
	// Fields holds additional updatable attributes (location, purpose, hardware
	// metrics from node_exporter, prometheus URL, etc.). Keys are stable field
	// names; the persistence layer maps them to DB columns.
	Fields map[string]string
}
