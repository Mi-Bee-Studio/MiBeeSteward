package runner

import (
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
)

// ReportedHostToReport reconstructs a scannerv2.HostReport from a
// domain.ReportedHost (the wire payload an agent POSTs). The center feeds this
// through applyDeviceBridge — the same path the local scan uses — so identity
// rules (MAC-primary → (ip, network_id) fallback) and heartbeat seeding are
// identical for local and remote discovery.
//
// The Device.Fields map is populated with the keys the device bridge reads
// (inferred_type, inferred_brand, mac, hostnames, prometheus/node_exporter
// URLs, open_ports/detected_services JSON). The MAC is normalized to the
// canonical colon-lowercase form (matching store.NormalizeMAC) so the bridge's
// MAC-primary lookup matches mac_address. A MAC is also emitted as a "mac"
// evidence piece so reportMAC()'s fallback path finds it too.
func ReportedHostToReport(h domain.ReportedHost) scannerv2.HostReport {
	mac := store.NormalizeMAC(h.MAC)
	fields := map[string]string{
		"inferred_type":        h.InferredType,
		"inferred_brand":       h.InferredBrand,
		"inferred_description": h.InferredDescription,
		"inferred_location":    h.InferredLocation,
		"node_hostname":        h.Hostname,
		"mac":                  mac,
		"open_ports":           h.OpenPorts,
		"detected_services":    h.DetectedServices,
		"prometheus_url":       h.PrometheusURL,
		"node_exporter_url":    h.NodeExporterURL,
	}
	if h.SNMP != nil {
		fields["sys_name"] = h.SNMP.SysName
	}

	// Rebuild Services + Heartbeats (the bridge seeds heartbeat configs from
	// these; empty Heartbeats → ICMP fallback).
	services := make([]scannerv2.ServiceIdentity, 0, len(h.Services))
	for _, s := range h.Services {
		services = append(services, scannerv2.ServiceIdentity{
			Service:  s.Service,
			Port:     s.Port,
			Protocol: s.Protocol,
			Metadata: s.Metadata,
		})
	}
	heartbeats := make([]scannerv2.HeartbeatSpec, 0, len(h.Heartbeats))
	for _, hb := range h.Heartbeats {
		heartbeats = append(heartbeats, scannerv2.HeartbeatSpec{
			Method:          hb.Method,
			Target:          hb.Target,
			IntervalSeconds: hb.IntervalSeconds,
			TimeoutSeconds:  hb.TimeoutSeconds,
			SNMPCommunity:   hb.SNMPCommunity,
			SNMPOID:         hb.SNMPOID,
		})
	}

	// Emit a MAC evidence piece so reportMAC's evidence fallback resolves the
	// MAC even if a future wire shape drops the Fields["mac"] entry. Already
	// normalized above so the lookup matches mac_address.
	var evidence []scannerv2.Evidence
	if mac != "" {
		evidence = append(evidence, scannerv2.Evidence{
			Source: "active:arp",
			Kind:   "mac",
			IP:     h.IP,
			RawData: map[string]string{
				"mac": mac,
			},
		})
	}

	return scannerv2.HostReport{
		IP:         h.IP,
		Alive:      h.Alive,
		RTTMs:      h.RTTMs,
		Evidence:   evidence,
		Services:   services,
		Heartbeats: heartbeats,
		Device: scannerv2.DeviceRef{
			IP:     h.IP,
			Name:   h.Hostname,
			Type:   h.InferredType,
			Brand:  h.InferredBrand,
			Fields: fields,
		},
	}
}
