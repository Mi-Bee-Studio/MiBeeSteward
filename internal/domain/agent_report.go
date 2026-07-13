package domain

import "time"

// AgentReport is the payload a discovery agent POSTs to the center's ingestion
// endpoint (POST /api/v1/agents/report). It carries one batch of scan results
// plus the agent's own identity metadata. The center authenticates the agent
// via its bearer token (which binds agent_id + network_id), so those fields
// here are advisory/cross-check rather than the source of truth.
//
// This is a deliberately flat, JSON-tagged projection of scannerv2.HostReport
// (whose nested structs DeviceRef/HostReport carry no JSON tags and aren't safe
// to ship over the wire as-is). The center reconstructs a HostReport from each
// ReportedHost via runner.ReportedHostToReport and feeds it through the same
// device bridge the local scan path uses.
type AgentReport struct {
	// AgentID is the agent's stable identifier (echoes agent_tokens.agent_id;
	// the center uses the token-bound value as authoritative).
	AgentID string `json:"agent_id"`
	// NetworkName is the human network name (e.g. "lan-62"). Advisory — the
	// center resolves network_id from the agent's token, not from this string.
	NetworkName string `json:"network_name,omitempty"`
	// ScannedAt is when the agent ran this scan batch.
	ScannedAt time.Time `json:"scanned_at"`
	// Hosts is the set of alive hosts discovered in this batch. Dead hosts are
	// omitted (the agent reports presence, not absence — change-detection lives
	// at the center).
	Hosts []ReportedHost `json:"hosts"`
}

// ReportedHost is one alive host in an AgentReport. Fields mirror what the
// center's device bridge needs to upsert a device (MAC, inferred type/brand,
// services, ports, SNMP/prometheus enrichment, heartbeats).
type ReportedHost struct {
	IP    string `json:"ip"`
	Alive bool   `json:"alive"`
	// RTTMs is the round-trip time in milliseconds (0 if unmeasured).
	RTTMs int64 `json:"rtt_ms,omitempty"`
	// MAC is the canonical colon-separated lowercase MAC (the agent normalizes
	// via the same NormalizeMAC rule). Empty when ARP/SNMP didn't resolve one.
	MAC string `json:"mac,omitempty"`
	// InferredType / InferredBrand / InferredDescription / InferredLocation are
	// the handler/heuristic verdicts for the device (camera, router, …).
	InferredType        string `json:"inferred_type,omitempty"`
	InferredBrand       string `json:"inferred_brand,omitempty"`
	InferredDescription string `json:"inferred_description,omitempty"`
	InferredLocation    string `json:"inferred_location,omitempty"`
	// Hostname is the best hostname signal (rDNS / SNMP sysName / mDNS).
	Hostname string `json:"hostname,omitempty"`
	// OpenPorts is the JSON the device bridge stores verbatim in
	// devices.open_ports ([{"port":int,"service":string}]).
	OpenPorts string `json:"open_ports,omitempty"`
	// DetectedServices is the JSON stored verbatim in devices.detected_services.
	DetectedServices string `json:"detected_services,omitempty"`
	// PrometheusURL / NodeExporterURL are discovered scrape endpoints.
	PrometheusURL   string `json:"prometheus_url,omitempty"`
	NodeExporterURL string `json:"node_exporter_url,omitempty"`
	// Services is the classified service-identity set (the bridge seeds
	// heartbeat configs from this). Optional — agents that only do liveness
	// discovery may omit it.
	Services []ReportedService `json:"services,omitempty"`
	// Heartbeats is the generated heartbeat specs (method/target/interval). When
	// empty the bridge falls back to an ICMP config so every host still gets
	// liveness monitoring.
	Heartbeats []ReportedHeartbeat `json:"heartbeats,omitempty"`
	// SNMP holds the structured SNMP sys* fields the agent collected (sysDescr,
	// sysObjectID, sysName, …). Folded into scan_attributes by the bridge.
	SNMP *ReportedSNMP `json:"snmp,omitempty"`
}

// ReportedService mirrors scannerv2.ServiceIdentity (the subset the center
// reconstructs to seed heartbeat configs + render detected_services).
type ReportedService struct {
	Service  string            `json:"service"`
	Port     int               `json:"port,omitempty"`
	Protocol string            `json:"protocol,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ReportedHeartbeat mirrors scannerv2.HeartbeatSpec.
type ReportedHeartbeat struct {
	Method          string `json:"method"`
	Target          string `json:"target"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	TimeoutSeconds  int    `json:"timeout_seconds,omitempty"`
	SNMPCommunity   string `json:"snmp_community,omitempty"`
	SNMPOID         string `json:"snmp_oid,omitempty"`
}

// ReportedSNMP holds the SNMP sys* fields. Mirrors domain.SNMPDiscovery.
type ReportedSNMP struct {
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
	SysServices int    `json:"sys_services,omitempty"`
}
