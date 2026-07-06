package domain

import (
	"testing"
)

func TestMarshalScanAttributes_OmitsZeroValues(t *testing.T) {
	out, err := MarshalScanAttributes(ScanAttributes{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if out != "{}" {
		t.Errorf("empty struct marshalled to %q, want {}", out)
	}
}

func TestMarshalScanAttributes_RoundTrip(t *testing.T) {
	in := ScanAttributes{
		OS:               "Linux",
		OSVersion:        "6.19.0-arch",
		Vendor:           "Hikvision",
		MAC:              "bc:ad:28:11:22:33",
		Hostname:         "cam-front",
		CPUCount:         4,
		MemoryTotalBytes: 8589934592,
		UptimeSeconds:    1843200,
		OpenPorts:        []OpenPortEntry{{Port: 80, Service: "http"}, {Port: 554, Service: "rtsp"}},
		SNMP:             &SNMPDiscovery{SysDescr: "Linux 6.19", SysObjectID: "1.3.6.1.4.1.12345"},
		Prometheus:       &PrometheusInfo{URL: "http://x:9090/metrics", NodeExporterURL: "http://x:9100/metrics"},
	}
	raw, err := MarshalScanAttributes(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := UnmarshalScanAttributes(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.OS != "Linux" || out.Vendor != "Hikvision" || out.MAC != "bc:ad:28:11:22:33" {
		t.Errorf("identity fields lost: %+v", out)
	}
	if out.CPUCount != 4 || out.MemoryTotalBytes != 8589934592 || out.UptimeSeconds != 1843200 {
		t.Errorf("numeric fields lost: %+v", out)
	}
	if out.SNMP == nil || out.SNMP.SysObjectID != "1.3.6.1.4.1.12345" {
		t.Errorf("SNMP sub-struct lost: %+v", out.SNMP)
	}
	if len(out.OpenPorts) != 2 || out.OpenPorts[1].Service != "rtsp" {
		t.Errorf("OpenPorts lost: %+v", out.OpenPorts)
	}
	if out.Prometheus == nil || out.Prometheus.NodeExporterURL == "" {
		t.Errorf("Prometheus sub-struct lost: %+v", out.Prometheus)
	}
}

func TestUnmarshalScanAttributes_EmptyAndInvalid(t *testing.T) {
	if s, err := UnmarshalScanAttributes(""); err != nil || s.OS != "" {
		t.Errorf("empty string should yield zero struct, got %+v err=%v", s, err)
	}
	if _, err := UnmarshalScanAttributes("{not json"); err == nil {
		t.Errorf("invalid JSON should error")
	}
}

func TestMarshalUserAttributes_EmptyIsBraceBrace(t *testing.T) {
	out, err := MarshalUserAttributes(nil)
	if err != nil || out != "{}" {
		t.Errorf("nil map → %q err=%v, want {}", out, err)
	}
	out, err = MarshalUserAttributes(UserAttributes{})
	if err != nil || out != "{}" {
		t.Errorf("empty map → %q err=%v, want {}", out, err)
	}
}

func TestMergeUserAttributes_OverwritesAndDeletes(t *testing.T) {
	base := UserAttributes{"keep": "1", "overwrite": "old", "delete": "x"}
	patch := UserAttributes{"overwrite": "new", "delete": "", "added": "y"}
	merged := MergeUserAttributes(base, patch)
	if merged["keep"] != "1" {
		t.Errorf("unchanged key lost: %v", merged)
	}
	if merged["overwrite"] != "new" {
		t.Errorf("overwrite failed: %v", merged)
	}
	if _, ok := merged["delete"]; ok {
		t.Errorf("empty-value patch should delete key: %v", merged)
	}
	if merged["added"] != "y" {
		t.Errorf("new key not added: %v", merged)
	}
	// Originals untouched.
	if base["delete"] != "x" {
		t.Errorf("base mutated: %v", base)
	}
}

func TestScanLastScannedTime(t *testing.T) {
	s := ScanAttributes{LastScannedAt: "2026-07-05T12:00:00Z"}
	if got := s.ScanLastScannedTime(); got.IsZero() {
		t.Errorf("valid RFC3339 parsed to zero time")
	}
	s2 := ScanAttributes{LastScannedAt: "garbage"}
	if got := s2.ScanLastScannedTime(); !got.IsZero() {
		t.Errorf("garbage string should yield zero time, got %v", got)
	}
	s3 := ScanAttributes{}
	if got := s3.ScanLastScannedTime(); !got.IsZero() {
		t.Errorf("empty string should yield zero time, got %v", got)
	}
}
