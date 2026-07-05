package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// RTSPProbe actively identifies RTSP servers. It connects to candidate ports
// (default 554, 8554) and sends an RTSP OPTIONS request; a server replying
// "RTSP/1.x" yields a banner Evidence tagged kind="rtsp_banner" with the
// Server header in RawData (camera brand lives there).
//
// It uses hint.Ports (from the port-scan evidence) to know where to probe;
// when empty it falls back to default RTSP ports.
//
// Name: "active:rtsp".
type RTSPProbe struct {
	defaultPorts []int
}

// NewRTSPProbe constructs the probe with standard RTSP ports.
func NewRTSPProbe() *RTSPProbe {
	return &RTSPProbe{defaultPorts: []int{554, 8554}}
}

func (p *RTSPProbe) Name() string { return "active:rtsp" }

// Probe connects to each candidate RTSP port and sends OPTIONS.
func (p *RTSPProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	ports := rtspCandidatePorts(hint.Ports, p.defaultPorts)
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var evs []scannerv2.Evidence
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return evs, ctx.Err()
		default:
		}
		if md := rtspProbePort(ctx, ip, port, timeout); md != nil {
			evs = append(evs, scannerv2.Evidence{
				Source:     "active:rtsp",
				Kind:       "rtsp_banner",
				IP:         ip,
				Port:       port,
				Protocol:   "tcp",
				RawData:    md,
				Confidence: 0.95,
				ObservedAt: time.Now(),
			})
		}
	}
	return evs, nil
}

// rtspCandidatePorts returns RTSP-relevant ports from observed, falling back to
// defaults when none match.
func rtspCandidatePorts(observed, defaults []int) []int {
	want := map[int]bool{554: true, 8554: true}
	var out []int
	for _, p := range observed {
		if want[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return defaults
	}
	return out
}

// rtspProbePort dials, sends OPTIONS, and returns raw metadata on RTSP reply.
func rtspProbePort(ctx context.Context, ip string, port int, timeout time.Duration) map[string]string {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")); err != nil {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil
	}
	statusLine = strings.TrimSpace(statusLine)
	if !strings.HasPrefix(statusLine, "RTSP/1.") {
		return nil
	}
	md := map[string]string{"status": statusLine}
	// Scan headers (up to 20 lines) for Server:.
	for i := 0; i < 20; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
			md["server"] = strings.TrimSpace(line[len("Server:"):])
			break
		}
	}
	return md
}

// ONVIFProbe identifies ONVIF devices by POSTing a minimal SOAP
// GetSystemDateAndTime to /onvif/device_service on HTTP ports. A genuine
// ONVIF response carries the ONVIF XML namespace in the body — checking for it
// (not just any 2xx/401) avoids false positives from generic web servers.
//
// Candidate ports: those in hint.Ports that look HTTP (80, 8080, 443, 8443,
// or any with a prior http-banner Evidence). Falls back to [80, 8080].
//
// Name: "active:onvif".
type ONVIFProbe struct{}

// NewONVIFProbe returns the ONVIF probe.
func NewONVIFProbe() *ONVIFProbe { return &ONVIFProbe{} }

func (p *ONVIFProbe) Name() string { return "active:onvif" }

// Probe POSTs the ONVIF SOAP envelope to each candidate HTTP port.
func (p *ONVIFProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	ports := onvifCandidatePorts(hint.Ports)
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var evs []scannerv2.Evidence
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return evs, ctx.Err()
		default:
		}
		if md := onvifProbePort(ctx, ip, port, timeout); md != nil {
			evs = append(evs, scannerv2.Evidence{
				Source:     "active:onvif",
				Kind:       "onvif_response",
				IP:         ip,
				Port:       port,
				Protocol:   "tcp",
				RawData:    md,
				Confidence: 0.9,
				ObservedAt: time.Now(),
			})
		}
	}
	return evs, nil
}

func onvifCandidatePorts(observed []int) []int {
	// Probe every observed open port for the ONVIF endpoint (some cameras
	// expose ONVIF on non-standard ports like 8000/8081). The classifier
	// confirms genuine ONVIF via the body namespace, so over-probing is safe.
	if len(observed) > 0 {
		return dedupPorts(observed)
	}
	return []int{80, 8080}
}

// onvifProbePort sends the SOAP probe and returns metadata on a genuine ONVIF reply.
func onvifProbePort(ctx context.Context, ip string, port int, timeout time.Duration) map[string]string {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/onvif/device_service", scheme, ip, port)
	body := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<td:GetSystemDateAndTime xmlns:td="http://www.onvif.org/ver10/device/wsdl"/>
</s:Body>
</s:Envelope>`

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/soap+xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 404/502/503 → endpoint doesn't exist.
	if resp.StatusCode == 404 || resp.StatusCode == 502 || resp.StatusCode == 503 {
		return nil
	}
	// Read up to 4KB and require an ONVIF XML namespace — this filters out
	// nginx/apache default pages that happen to 200.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	content := string(respBody)
	if !strings.Contains(content, "http://www.onvif.org/ver10/device/wsdl") &&
		!strings.Contains(content, "http://www.onvif.org/ver10/schema") {
		return nil
	}
	md := map[string]string{"status_code": fmt.Sprintf("%d", resp.StatusCode)}
	if resp.StatusCode == 401 {
		md["auth_required"] = "true"
	}
	if s := resp.Header.Get("Server"); s != "" {
		md["server"] = s
	}
	return md
}

// HTTPMetricsProbe fetches /metrics on HTTP ports. A successful fetch yields a
// "metric" Evidence whose RawData["content_sample"] holds the first 4KB. The
// Prometheus classifier inspects this to distinguish prometheus /
// node_exporter / neither.
//
// Name: "active:http_metrics".
type HTTPMetricsProbe struct{}

// NewHTTPMetricsProbe returns the probe.
func NewHTTPMetricsProbe() *HTTPMetricsProbe { return &HTTPMetricsProbe{} }

func (p *HTTPMetricsProbe) Name() string { return "active:http_metrics" }

// Probe fetches /metrics on each candidate HTTP/prometheus port.
func (p *HTTPMetricsProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	ports := metricsCandidatePorts(hint.Ports)
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var evs []scannerv2.Evidence
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return evs, ctx.Err()
		default:
		}
		if md := metricsProbePort(ctx, ip, port, timeout); md != nil {
			evs = append(evs, scannerv2.Evidence{
				Source:     "active:http_metrics",
				Kind:       "metric",
				IP:         ip,
				Port:       port,
				Protocol:   "tcp",
				RawData:    md,
				Confidence: 0.9,
				ObservedAt: time.Now(),
			})
		}
	}
	return evs, nil
}

func metricsCandidatePorts(observed []int) []int {
	// Probe every observed port for /metrics — Prometheus exporters can live
	// on arbitrary ports, and the classifier confirms via content inspection.
	if len(observed) > 0 {
		return dedupPorts(observed)
	}
	return []int{9090, 9100}
}

// dedupPorts removes duplicates, preserving order.
func dedupPorts(in []int) []int {
	seen := make(map[int]bool, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	return out
}

func metricsProbePort(ctx context.Context, ip string, port int, timeout time.Duration) map[string]string {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/metrics", scheme, ip, port)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("metrics probe failed", "ip", ip, "port", port, "error", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	content := string(body)
	if content == "" {
		return nil
	}
	return map[string]string{
		"content_sample": content,
		"url":            url,
	}
}
