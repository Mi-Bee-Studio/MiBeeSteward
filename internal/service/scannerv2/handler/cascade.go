package handler

import (
	"context"
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// HTTPHandler is the cascade entry point for web servers. On Collect it probes
// /metrics on the HTTP port; if a Prometheus endpoint responds, it returns a
// Trigger to invoke the Prometheus handler (which then decides prom vs
// node_exporter). This realizes the user's vision:
//
//	http detected → probe /metrics → if found, cascade to prometheus handler.
type HTTPHandler struct{}

func (HTTPHandler) Service() string { return "http" }

func (HTTPHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "http",
		Target: urlFor(svc.IP, svc.Identity.Port, "/"),
	}
}

func (HTTPHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	metricsURL := urlFor(svc.IP, svc.Identity.Port, "/metrics")
	body := fetchURL(ctx, metricsURL, 0)
	if body == "" {
		return HTTPData{}, nil, nil // no /metrics here
	}
	// Found a metrics endpoint → trigger the Prometheus handler on this port.
	return HTTPData{MetricsFound: true, MetricsURL: metricsURL},
		[]scannerv2.Trigger{{
			Service: "prometheus",
			Port:    svc.Identity.Port,
			Context: map[string]string{"metrics_url": metricsURL, "sample": body},
		}},
		nil
}

func (HTTPHandler) EnrichDevice(svc scannerv2.ServiceContext, data scannerv2.CollectedData) {
	// If collection found a metrics endpoint, record the URL on the device so
	// the UI / Prometheus scraping can find it.
	if hd, ok := data.(HTTPData); ok && hd.MetricsFound {
		setDeviceField(svc, "prometheus_url", hd.MetricsURL)
	}
	// A plain web server implies "server" device type (low confidence).
	preserveExisting(svc, "inferred_type", "server")
}

// PrometheusHandler inspects the metrics sample carried by its trigger (from
// the HTTP handler) or fetched fresh. If the sample contains node_ metrics it
// triggers the NodeExporter handler; otherwise it just records the prometheus
// URL and emits a heartbeat.
type PrometheusHandler struct{}

func (PrometheusHandler) Service() string { return "prometheus" }

func (PrometheusHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	url := svc.Identity.Metadata["metrics_url"]
	if url == "" {
		url = urlFor(svc.IP, svc.Identity.Port, "/metrics")
	}
	return &scannerv2.HeartbeatSpec{
		Method: "http",
		Target: url,
	}
}

func (PrometheusHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	// Prefer the sample passed via cascade context; otherwise fetch.
	sample := svc.Identity.Metadata["sample"]
	metricsURL := svc.Identity.Metadata["metrics_url"]
	if metricsURL == "" {
		metricsURL = urlFor(svc.IP, svc.Identity.Port, "/metrics")
	}
	if sample == "" {
		sample = fetchURL(ctx, metricsURL, 0)
	}
	if sample == "" {
		return PrometheusData{MetricsURL: metricsURL}, nil, nil
	}
	isNode := strings.Contains(sample, "node_") || strings.Contains(sample, "node_exporter_build_info")
	data := PrometheusData{MetricsURL: metricsURL, Sample: sample, IsNode: isNode}
	if isNode {
		// Cascade to the node_exporter handler with the sample in hand.
		return data, []scannerv2.Trigger{{
			Service: "node_exporter",
			Port:    svc.Identity.Port,
			Context: map[string]string{"metrics_url": metricsURL, "sample": sample},
		}}, nil
	}
	return data, nil, nil
}

func (PrometheusHandler) EnrichDevice(svc scannerv2.ServiceContext, data scannerv2.CollectedData) {
	if pd, ok := data.(PrometheusData); ok && pd.MetricsURL != "" {
		setDeviceField(svc, "prometheus_url", pd.MetricsURL)
	}
}

// NodeExporterHandler is the terminal handler of the camera-free cascade. It
// parses the node_exporter metrics sample for hardware attributes (memory,
// CPU count, kernel, OS) and writes them onto the device record — filling in
// the "necessary fields to complete the host" per the user's vision.
type NodeExporterHandler struct{}

func (NodeExporterHandler) Service() string { return "node_exporter" }

func (NodeExporterHandler) GenerateHeartbeat(_ scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return nil // rides on the Prometheus handler's heartbeat (depth-1 cascade)
}

func (NodeExporterHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	sample := svc.Identity.Metadata["sample"]
	metricsURL := svc.Identity.Metadata["metrics_url"]
	if metricsURL == "" {
		metricsURL = urlFor(svc.IP, svc.Identity.Port, "/metrics")
	}
	if sample == "" {
		sample = fetchURL(ctx, metricsURL, 0)
	}
	if sample == "" {
		return NodeExporterData{MetricsURL: metricsURL}, nil, nil
	}
	kernel, osType, mem, cpu := parseNodeExporterSample(sample)
	return NodeExporterData{
		MetricsURL:    metricsURL,
		KernelVersion: kernel,
		OSType:        osType,
		MemTotalBytes: mem,
		CPUCount:      cpu,
	}, nil, nil
}

func (NodeExporterHandler) EnrichDevice(svc scannerv2.ServiceContext, data scannerv2.CollectedData) {
	nd, ok := data.(NodeExporterData)
	if !ok {
		return
	}
	if nd.MetricsURL != "" {
		setDeviceField(svc, "node_exporter_url", nd.MetricsURL)
	}
	if nd.KernelVersion != "" {
		setDeviceField(svc, "kernel_version", nd.KernelVersion)
		// Synology/QNAP run Linux but expose their brand in the kernel string.
		if b := brandFromKernel(nd.KernelVersion); b != "" {
			setDeviceField(svc, "inferred_brand", b)
		}
	}
	if nd.OSType != "" {
		setDeviceField(svc, "os_type", nd.OSType)
	}
	if nd.MemTotalBytes > 0 {
		setDeviceField(svc, "memory_total_bytes", formatInt64(nd.MemTotalBytes))
	}
	if nd.CPUCount > 0 {
		setDeviceField(svc, "cpu_count", formatInt(nd.CPUCount))
	}
	// A host with full node_exporter data and lots of RAM is plausibly a PC/server.
	if nd.MemTotalBytes > 16*1024*1024*1024 {
		preserveExisting(svc, "inferred_type", "pc")
	} else {
		preserveExisting(svc, "inferred_type", "server")
	}
}

// brandFromKernel recognizes NAS vendors in a kernel release string.
func brandFromKernel(kernel string) string {
	k := toLowerASCII(kernel)
	switch {
	case containsFold(k, "qnap"):
		return "QNAP"
	case containsFold(k, "synology"):
		return "Synology"
	}
	return ""
}

func formatInt64(n int64) string {
	return formatInt(int(n))
}
