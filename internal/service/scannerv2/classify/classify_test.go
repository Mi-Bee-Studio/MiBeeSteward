package classify

import (
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

func hasService(out []scannerv2.ServiceIdentity, name string) (scannerv2.ServiceIdentity, bool) {
	for _, s := range out {
		if s.Service == name {
			return s, true
		}
	}
	return scannerv2.ServiceIdentity{}, false
}

func TestBannerClassifier_SSH(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "banner", IP: "10.0.0.1", Port: 22, Confidence: 0.9, RawData: map[string]string{"banner": "SSH-2.0-OpenSSH_9.0"}},
	}
	out := BannerClassifier{}.Classify(ev)
	s, ok := hasService(out, "ssh")
	if !ok {
		t.Fatalf("no ssh identity; got %+v", out)
	}
	if s.Metadata["version"] != "OpenSSH_9.0" {
		t.Errorf("version = %q", s.Metadata["version"])
	}
}

func TestBannerClassifier_RTSPAndHTTP(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 554, Confidence: 0.9, RawData: map[string]string{"banner": "RTSP/1.0 200 OK"}},
		{Kind: "banner", Port: 80, Confidence: 0.9, RawData: map[string]string{"banner": "HTTP/1.1 200 OK"}},
	}
	out := BannerClassifier{}.Classify(ev)
	if _, ok := hasService(out, "rtsp"); !ok {
		t.Error("missing rtsp")
	}
	if _, ok := hasService(out, "http"); !ok {
		t.Error("missing http")
	}
}

func TestCameraClassifier_FromRTSPAndONVIF(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "rtsp_banner", IP: "10.0.0.5", Port: 554, Confidence: 0.95, RawData: map[string]string{"server": "Hikvision"}},
		{Kind: "onvif_response", IP: "10.0.0.5", Port: 80, Confidence: 0.9, RawData: map[string]string{"server": "Hikvision-ONVIF/1.0"}},
	}
	out := CameraClassifier{}.Classify(ev)
	s, ok := hasService(out, "camera")
	if !ok {
		t.Fatalf("expected camera identity; got %+v", out)
	}
	if s.Metadata["inferred_brand"] != "Hikvision" {
		t.Errorf("brand = %q, want Hikvision", s.Metadata["inferred_brand"])
	}
	// Confidence fused across 2 strong sources should be very high.
	if s.Confidence < 0.99 {
		t.Errorf("confidence %f should be ≥0.99", s.Confidence)
	}
}

func TestCameraClassifier_NoCameraWithoutEvidence(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 80, Confidence: 0.9, RawData: map[string]string{"banner": "HTTP/1.1 200 OK"}},
	}
	out := CameraClassifier{}.Classify(ev)
	if len(out) != 0 {
		t.Errorf("non-camera host should yield no camera identity, got %+v", out)
	}
}

func TestSNMPClassifier_TypeAndBrand(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "snmp", IP: "10.0.0.1", Port: 161, Protocol: "udp", Confidence: 0.95,
			RawData: map[string]string{
				"sys_descr":     "Cisco IOS Software, Version 15.2",
				"sys_services":  "6",
				"sys_object_id": "1.3.6.1.4.1.9.1.2",
			}},
	}
	out := SNMPClassifier{}.Classify(ev)
	s, ok := hasService(out, "snmp")
	if !ok {
		t.Fatalf("no snmp identity; got %+v", out)
	}
	if s.Metadata["inferred_type"] != "router" {
		t.Errorf("type = %q, want router", s.Metadata["inferred_type"])
	}
	if s.Metadata["inferred_brand"] != "Cisco" {
		t.Errorf("brand = %q, want Cisco", s.Metadata["inferred_brand"])
	}
}

func TestSNMPClassifier_SwitchByServices(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "snmp", Port: 161, Confidence: 0.9, RawData: map[string]string{"sys_services": "78", "sys_descr": "ProCurve"}},
	}
	out := SNMPClassifier{}.Classify(ev)
	if out[0].Metadata["inferred_type"] != "switch" {
		t.Errorf("type = %q, want switch", out[0].Metadata["inferred_type"])
	}
}

func TestPrometheusClassifier_NodeExporterPreferred(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "metric", Port: 9100, Confidence: 0.9, RawData: map[string]string{
			"content_sample": "node_exporter_build_info{version=\"1.6\"} 1\nnode_cpu_seconds_total 1.2\nprometheus_build_info 1\n",
			"url":            "http://10.0.0.1:9100/metrics",
		}},
	}
	out := PrometheusClassifier{}.Classify(ev)
	if _, ok := hasService(out, "node_exporter"); !ok {
		t.Errorf("expected node_exporter (preferred over prometheus); got %+v", servicesOf(out))
	}
	// Should NOT also emit plain prometheus when it's node_exporter.
	if _, ok := hasService(out, "prometheus"); ok {
		t.Error("should not emit plain prometheus when node_exporter detected")
	}
}

func TestPrometheusClassifier_PlainPrometheus(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "metric", Port: 9090, Confidence: 0.9, RawData: map[string]string{
			"content_sample": "prometheus_build_info{version=\"2.45\"} 1\ngo_goroutines 42\n",
			"url":            "http://10.0.0.1:9090/metrics",
		}},
	}
	out := PrometheusClassifier{}.Classify(ev)
	s, ok := hasService(out, "prometheus")
	if !ok {
		t.Fatalf("expected prometheus; got %+v", servicesOf(out))
	}
	if s.Metadata["metrics_url"] == "" {
		t.Error("metrics_url not captured")
	}
}

func TestPrometheusClassifier_NotMetrics(t *testing.T) {
	// /metrics returned 200 but content is generic HTML → no metric evidence
	// would be produced by the probe, so classifier sees nothing.
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 9090, Confidence: 0.9, RawData: map[string]string{"banner": "HTTP/1.1 200 OK"}},
	}
	out := PrometheusClassifier{}.Classify(ev)
	if len(out) != 0 {
		t.Errorf("non-metrics evidence should yield no prometheus; got %+v", out)
	}
}

func TestONVIFClassifier_BrandFromServerHeader(t *testing.T) {
	ev := []scannerv2.Evidence{
		{Kind: "onvif_response", Port: 80, Confidence: 0.9, RawData: map[string]string{"server": "Dahua-ONVIF/2.0"}},
	}
	out := ONVIFClassifier{}.Classify(ev)
	s, ok := hasService(out, "onvif")
	if !ok {
		t.Fatalf("no onvif identity; got %+v", out)
	}
	if s.Metadata["inferred_brand"] != "Dahua" {
		t.Errorf("brand = %q, want Dahua", s.Metadata["inferred_brand"])
	}
}

func TestFuseConfidence(t *testing.T) {
	if c := fuseConfidence(0.9, 0.9); c < 0.98 {
		t.Errorf("two 0.9 sources should fuse ≥0.98, got %f", c)
	}
	if c := fuseConfidence(0.5); c != 0.5 {
		t.Errorf("single source should pass through, got %f", c)
	}
	if c := fuseConfidence(); c != 0 {
		t.Errorf("no sources should yield 0, got %f", c)
	}
}

func TestDefaultClassifiers_CoversCamera(t *testing.T) {
	// End-to-end: a host with RTSP+ONVIF evidence should classify as camera
	// via the default classifier set.
	all := []scannerv2.Evidence{
		{Kind: "rtsp_banner", IP: "10.0.0.9", Port: 554, Confidence: 0.95, RawData: map[string]string{"server": "Hikvision"}},
		{Kind: "onvif_response", IP: "10.0.0.9", Port: 80, Confidence: 0.9, RawData: map[string]string{"server": "Hikvision-ONVIF"}},
	}
	var services []scannerv2.ServiceIdentity
	for _, c := range DefaultClassifiers() {
		services = append(services, c.Classify(all)...)
	}
	names := servicesOf(services)
	if !containsStr(names, "camera") {
		t.Errorf("camera not detected by default classifiers; got %v", names)
	}
	if !containsStr(names, "rtsp") || !containsStr(names, "onvif") {
		t.Errorf("rtsp/onvif should also be detected; got %v", names)
	}
}

func servicesOf(s []scannerv2.ServiceIdentity) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = v.Service
	}
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
