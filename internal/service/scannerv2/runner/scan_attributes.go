package runner

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
)

// buildScanAttributes assembles the engine-written scan_attributes document
// from a HostReport. It pulls structured data from three sources:
//   - report.Device.Fields (kernel_version, os_type, cpu_count, memory_total_bytes,
//     prometheus/node_exporter URLs, inferred_type/brand, snmp sysDescr, etc.)
//     which the handler layer's EnrichDevice populated
//   - report.Evidence of kind "snmp" (parsed into the SNMP sub-struct)
//   - report.Services (re-shaped into OpenPorts + DetectedServices arrays)
//
// This is the single funnel through which the runner populates scan_attributes,
// replacing the previous "device bridge only read 4 inferred_* keys" behavior
// that silently dropped os/kernel/cpu/memory.
func buildScanAttributes(rep scannerv2.HostReport) domain.ScanAttributes {
	f := rep.Device.Fields
	attr := domain.ScanAttributes{
		Vendor:              f["inferred_brand"],
		InferredType:        f["inferred_type"],
		InferredDescription: f["inferred_description"],
		OS:                  f["os_type"],
		OSVersion:           f["os_version"],
		KernelVersion:       f["kernel_version"],
		FirmwareVersion:     f["firmware_version"],
		Hostname:            firstNonEmpty(f["node_hostname"], f["sys_name"]),
		ScanSource:          "scanner_v2",
		LastScanRttMs:       rep.RTTMs,
	}

	// node_exporter-sourced numeric fields (previously discarded by the bridge).
	if v, err := strconv.ParseInt(f["memory_total_bytes"], 10, 64); err == nil && v > 0 {
		attr.MemoryTotalBytes = v
	}
	if v, err := strconv.Atoi(f["cpu_count"]); err == nil && v > 0 {
		attr.CPUCount = v
	}
	if v, err := strconv.ParseInt(f["uptime_seconds"], 10, 64); err == nil && v > 0 {
		attr.UptimeSeconds = v
	}
	if v, err := strconv.Atoi(f["ttl"]); err == nil && v > 0 {
		attr.TTL = v
	}

	if v := f["mac"]; v != "" {
		attr.MAC = v
	}

	// Prom fields.
	promURL := f["prometheus_url"]
	neURL := f["node_exporter_url"]
	if promURL != "" || neURL != "" {
		attr.Prometheus = &domain.PrometheusInfo{URL: promURL, NodeExporterURL: neURL}
	}

	// Host-level L2/L3 metadata from the ARP + rDNS probes. These emit
	// per-evidence RawData so we read them here directly (no handler round-trip
	// needed). Vendor preference: SNMP/SNMP-sysObject inferred brand
	// (attr.Vendor, set above from f["inferred_brand"]) wins over OUI, since
	// device vendors sometimes re-brand OUI blocks.
	for _, e := range rep.Evidence {
		if e.RawData == nil {
			continue
		}
		switch e.Kind {
		case "mac":
			if v := e.RawData["mac"]; v != "" && attr.MAC == "" {
				attr.MAC = v
			}
			// OUI vendor only fills attr.Vendor when nothing stronger already did
			// (inferred_brand from SNMP/HTTP Server header beats a generic OUI).
			if attr.Vendor == "" {
				if v := e.RawData["vendor"]; v != "" {
					attr.Vendor = v
				}
			}
		case "hostname":
			if v := e.RawData["hostname"]; v != "" && attr.Hostname == "" {
				attr.Hostname = v
			}
		}
	}

	// SNMP evidence → structured sub-object. We pick the first snmp evidence
	// (the snmp probe emits exactly one per host).
	for _, e := range rep.Evidence {
		if e.Kind != "snmp" || e.RawData == nil {
			continue
		}
		attr.SNMP = &domain.SNMPDiscovery{
			SysDescr:    e.RawData["sys_descr"],
			SysObjectID: e.RawData["sys_object_id"],
			SysName:     e.RawData["sys_name"],
			SysLocation: e.RawData["sys_location"],
			SysContact:  e.RawData["sys_contact"],
		}
		if v, err := strconv.Atoi(e.RawData["sys_services"]); err == nil {
			attr.SNMP.SysServices = v
		}
		// sysUpTime-derived uptime (only fills when nothing stronger already did
		// — node_exporter's uptime would have come from f["uptime_seconds"]).
		if attr.UptimeSeconds == 0 {
			if v, err := strconv.ParseInt(e.RawData["uptime_seconds"], 10, 64); err == nil && v > 0 {
				attr.UptimeSeconds = v
			}
		}
		// Fall back to SNMP sysName for hostname if rDNS/mDNS didn't supply one.
		if attr.Hostname == "" && attr.SNMP.SysName != "" {
			attr.Hostname = attr.SNMP.SysName
		}
		break
	}

	// Services → OpenPorts + DetectedServices arrays.
	attr.OpenPorts, attr.DetectedServices = serviceArrays(rep)
	if rep.Alive {
		attr.LastScannedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// UDP-discovery detail (mDNS/SSDP/NetBIOS) lands under Extras so the typed
	// struct doesn't have to model every TXT/SSDP field. NetBIOS workgroup is
	// promoted to a top-level field because it's a common inventory key.
	if wg := f["netbios_workgroup"]; wg != "" {
		ensureExtras(&attr)["netbios_workgroup"] = wg
	}
	for _, e := range rep.Evidence {
		if e.RawData == nil {
			continue
		}
		switch e.Kind {
		case "mdns":
			if v := e.RawData["services"]; v != "" {
				ensureExtras(&attr)["mdns_services"] = v
			}
			// Promote high-signal TXT records (model/serial) to Extras.
			for _, k := range []string{"txt.model", "txt.serial", "txt.vendor", "txt.manufacturer", "txt.md", "txt.ty"} {
				if v := e.RawData[k]; v != "" {
					key := k[len("txt."):]
					if ensureExtras(&attr)["mdns_"+key] == "" {
						ensureExtras(&attr)["mdns_"+key] = v
					}
				}
			}
		case "ssdp":
			if v := e.RawData["server"]; v != "" {
				ensureExtras(&attr)["ssdp_server"] = v
			}
			if v := e.RawData["location"]; v != "" {
				ensureExtras(&attr)["ssdp_location"] = v
			}
			if v := e.RawData["st"]; v != "" {
				ensureExtras(&attr)["ssdp_st"] = v
			}
		}
	}

	return attr
}

// ensureExtras lazily initializes attr.Extras and returns it for mutation.
func ensureExtras(attr *domain.ScanAttributes) map[string]string {
	if attr.Extras == nil {
		attr.Extras = map[string]string{}
	}
	return attr.Extras
}

// serviceArrays builds the OpenPorts and DetectedServices arrays from the
// report, deduped and sorted for stable output. The shapes match the legacy
// devices.open_ports / devices.detected_services JSON so the frontend parser
// can read either source.
func serviceArrays(rep scannerv2.HostReport) ([]domain.OpenPortEntry, []domain.ServiceEntry) {
	portSvc := map[int]string{}
	for _, s := range rep.Services {
		if s.Port > 0 && s.Service != "" {
			if _, ok := portSvc[s.Port]; !ok {
				portSvc[s.Port] = s.Service
			}
		}
	}

	// Open ports from evidence, deduped + sorted.
	openSet := map[int]bool{}
	for _, e := range rep.Evidence {
		if e.Kind == "port_open" && e.Port > 0 {
			openSet[e.Port] = true
		}
	}
	openPorts := make([]int, 0, len(openSet))
	for p := range openSet {
		openPorts = append(openPorts, p)
	}
	sort.Ints(openPorts)
	openEntries := make([]domain.OpenPortEntry, 0, len(openPorts))
	for _, p := range openPorts {
		openEntries = append(openEntries, domain.OpenPortEntry{Port: p, Service: portSvc[p]})
	}

	// Detected services: stable sort by (port, name).
	svcs := make([]scannerv2.ServiceIdentity, len(rep.Services))
	copy(svcs, rep.Services)
	sort.Slice(svcs, func(i, j int) bool {
		if svcs[i].Port != svcs[j].Port {
			return svcs[i].Port < svcs[j].Port
		}
		return svcs[i].Service < svcs[j].Service
	})
	svcEntries := make([]domain.ServiceEntry, 0, len(svcs))
	for _, s := range svcs {
		var version string
		if s.Metadata != nil {
			version = s.Metadata["version"]
		}
		svcEntries = append(svcEntries, domain.ServiceEntry{
			Port:     s.Port,
			Name:     s.Service,
			Protocol: s.Protocol,
			Version:  version,
		})
	}
	return openEntries, svcEntries
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// marshalScanAttributes is a thin wrapper that never returns an error to its
// callers (a marshal failure on a struct of strings/ints is a programming bug
// and the empty default "{}" is always a safe column value).
func marshalScanAttributes(attr domain.ScanAttributes) string {
	b, err := json.Marshal(attr)
	if err != nil {
		return "{}"
	}
	return string(b)
}
