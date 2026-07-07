package handler

import (
	"context"
	"fmt"

	"mibee-steward/internal/service/scannerv2"
)

// SSHHandler generates a TCP-connect heartbeat on port 22 and records the SSH
// banner version on the device.
type SSHHandler struct{}

func (SSHHandler) Service() string { return "ssh" }

func (SSHHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "tcp",
		Target: fmt.Sprintf("%s:%d", svc.IP, svc.Identity.Port),
	}
}

func (SSHHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil // no deep collection; banner already classified
}

func (SSHHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	// SSH banner "Windows" → device type PC (the legacy heuristic). Otherwise no change.
	if v, ok := svc.Identity.Metadata["version"]; ok && containsFold(v, "Windows") {
		setDeviceField(svc, "inferred_type", "pc")
	}
}

// RTSPHandler generates a TCP-connect heartbeat on the RTSP port. Part of the
// camera detection story: a host with RTSP gets continuous reachability
// monitoring on the camera's video port.
type RTSPHandler struct{}

func (RTSPHandler) Service() string { return "rtsp" }

func (RTSPHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "tcp",
		Target: fmt.Sprintf("%s:%d", svc.IP, svc.Identity.Port),
	}
}

func (RTSPHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (RTSPHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	// RTSP presence → camera type unless a stronger signal already set it.
	preserveExisting(svc, "inferred_type", "camera")
	if b, ok := svc.Identity.Metadata["inferred_brand"]; ok && b != "" {
		preserveExisting(svc, "inferred_brand", b)
	}
}

// ONVIFHandler generates an HTTP heartbeat on the ONVIF port (SOAP endpoint
// reachability). ONVIF also implies camera.
type ONVIFHandler struct{}

func (ONVIFHandler) Service() string { return "onvif" }

func (ONVIFHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "http",
		Target: fmt.Sprintf("%s://%s:%d/onvif/device_service", schemeFor(svc.Identity.Port), svc.IP, svc.Identity.Port),
	}
}

func (ONVIFHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (ONVIFHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	preserveExisting(svc, "inferred_type", "camera")
	if b, ok := svc.Identity.Metadata["inferred_brand"]; ok && b != "" {
		preserveExisting(svc, "inferred_brand", b)
	}
}

// CameraHandler is the host-level meta handler for the "camera" identity. It
// generates an ICMP heartbeat (cameras may drop RTSP without the host being
// down) and pins the camera type/brand.
type CameraHandler struct{}

func (CameraHandler) Service() string { return "camera" }

func (CameraHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "icmp",
		Target: svc.IP,
	}
}

func (CameraHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (CameraHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	// Camera identity is high-confidence; set type + brand directly.
	setDeviceField(svc, "inferred_type", "camera")
	if b, ok := svc.Identity.Metadata["inferred_brand"]; ok && b != "" {
		setDeviceField(svc, "inferred_brand", b)
	}
}

// SNMPHandler generates an SNMP heartbeat and applies the classifier-inferred
// type/brand (router/switch/firewall/nas/...).
type SNMPHandler struct{}

func (SNMPHandler) Service() string { return "snmp" }

func (SNMPHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	community := svc.Identity.Metadata["snmp_community"]
	if community == "" {
		community = "public"
	}
	return &scannerv2.HeartbeatSpec{
		Method:        "snmp",
		Target:        svc.IP,
		SNMPCommunity: community,
		SNMPOID:       "1.3.6.1.2.1.1.3.0", // sysUpTime
	}
}

func (SNMPHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (SNMPHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	if t, ok := svc.Identity.Metadata["inferred_type"]; ok && t != "" {
		setDeviceField(svc, "inferred_type", t)
	}
	if b, ok := svc.Identity.Metadata["inferred_brand"]; ok && b != "" {
		setDeviceField(svc, "inferred_brand", b)
	}
	if d, ok := svc.Identity.Metadata["sys_descr"]; ok && d != "" {
		setDeviceField(svc, "inferred_description", d)
	}
	// OS parsed from sysDescr (e.g. "Linux 5.x", "RouterOS", "Windows"). Parsed
	// by osFromSysDescr in the SNMP classifier; without this the scan_os column
	// was empty for almost every SNMP-reachable device.
	if os, ok := svc.Identity.Metadata["os_type"]; ok && os != "" {
		setDeviceField(svc, "os_type", os)
	}
}

// === field helpers ===

// setDeviceField sets key=value on the device's Fields map, initializing the
// map if needed. Handlers mutate svc.Device in place.
func setDeviceField(svc scannerv2.ServiceContext, key, value string) {
	if svc.Device.Fields == nil {
		svc.Device.Fields = map[string]string{}
	}
	svc.Device.Fields[key] = value
}

// preserveExisting sets key=value only if the device doesn't already have a
// non-empty value for it — used so stronger signals (SNMP brand) win over
// weaker ones (RTSP banner brand).
func preserveExisting(svc scannerv2.ServiceContext, key, value string) {
	if svc.Device.Fields != nil && svc.Device.Fields[key] != "" {
		return
	}
	setDeviceField(svc, key, value)
}

// containsFold reports whether s contains substr, ASCII-case-insensitively.
func containsFold(s, substr string) bool {
	return indexFold(s, substr) >= 0
}

func indexFold(s, substr string) int {
	ls := toLowerASCII(s)
	lsub := toLowerASCII(substr)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return i
		}
	}
	return -1
}

func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
