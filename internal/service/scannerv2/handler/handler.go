// Package handler implements the ③ ServiceHandler layer of scannerv2.
//
// A ServiceHandler owns the per-service behavior: how to heartbeat the service,
// whether to perform deep collection (and which downstream services that
// collection should trigger), and how to enrich the device record from
// collected data. Handlers are independent of each other and of the
// orchestrator — they communicate only via Triggers.
//
// The cascade design (HTTP → /metrics probe → Prometheus handler → node_
// detection → NodeExporter handler → hardware enrich) is the canonical example
// of the user's vision: detection of a service triggers deeper detection that
// progressively fills in the device record.
package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// === CollectedData concrete types ===

// HTTPData is the result of probing an HTTP service for /metrics. It records
// whether a metrics endpoint was found and the discovered URL — used to
// trigger the Prometheus handler.
type HTTPData struct {
	MetricsFound bool
	MetricsURL   string
}

func (d HTTPData) Service() string { return "http" }

// PrometheusData holds the metrics content sample fetched by the Prometheus
// handler. Downstream classification (node_exporter) reads the sample.
type PrometheusData struct {
	MetricsURL string
	Sample     string
	IsNode     bool
}

func (d PrometheusData) Service() string { return "prometheus" }

// NodeExporterData holds parsed node_exporter hardware attributes used to
// enrich the device record.
type NodeExporterData struct {
	MetricsURL    string
	KernelVersion string
	OSType        string
	MemTotalBytes int64
	CPUCount      int
}

func (d NodeExporterData) Service() string { return "node_exporter" }

// PlainData is the no-op CollectedData for handlers that have nothing to
// collect but still generate heartbeats (SSH, RTSP, ONVIF).
type PlainData struct{ S string }

func (d PlainData) Service() string { return d.S }

// httpClient is a shared client used by HTTP/Prometheus/NodeExporter handlers.
// No redirect following — we want raw responses.
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchURL GETs url and returns the body string (up to 64KB) on 200, else "".
func fetchURL(ctx context.Context, url string, timeout time.Duration) string {
	client := httpClient
	if timeout > 0 {
		client = &http.Client{Timeout: timeout, CheckRedirect: httpClient.CheckRedirect}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return string(body)
}

// schemeFor returns "https" for port 443, else "http".
func schemeFor(port int) string {
	if port == 443 {
		return "https"
	}
	return "http"
}

// === node_exporter metric parsers ===

var (
	reMemTotal = regexp.MustCompile(`node_memory_MemTotal_bytes\s+([0-9.e+]+)`)
	reCPUCount = regexp.MustCompile(`node_cpu_seconds_total\{cpu="(\d+)"`)
	reKernel   = regexp.MustCompile(`node_uname_info\{[^}]*release="([^"]+)"`)
	reOSType   = regexp.MustCompile(`node_uname_info\{[^}]*sysname="([^"]+)"`)
)

// parseNodeExporterSample extracts hardware attrs from a node_exporter /metrics sample.
func parseNodeExporterSample(sample string) (kernel, osType string, memTotal int64, cpuCount int) {
	if m := reKernel.FindStringSubmatch(sample); len(m) > 1 {
		kernel = m[1]
	}
	if m := reOSType.FindStringSubmatch(sample); len(m) > 1 {
		osType = m[1]
	}
	if m := reMemTotal.FindStringSubmatch(sample); len(m) > 1 {
		memTotal = parseMetricNumber(m[1])
	}
	// Count distinct cpu="N" values for CPU count.
	seen := map[string]bool{}
	for _, m := range reCPUCount.FindAllStringSubmatch(sample, -1) {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
		}
	}
	cpuCount = len(seen)
	return
}

// parseMetricNumber parses a Prometheus metric value (int, float, scientific).
func parseMetricNumber(s string) int64 {
	s = strings.TrimSpace(s)
	// Handle scientific notation like 8.59e+09.
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f)
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return 0
}

// formatInt is a tiny helper to avoid strconv import noise at call sites.
func formatInt(n int) string { return strconv.Itoa(n) }

// urlFor returns an http(s) URL for ip:port/path.
func urlFor(ip string, port int, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s:%d%s", schemeFor(port), ip, port, path)
}
