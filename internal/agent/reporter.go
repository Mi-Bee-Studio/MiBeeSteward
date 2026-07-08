// Package agent implements the discovery-agent runtime that runs the scannerv2
// engine locally and reports results to an aggregation center. The Reporter
// here is the upstream-reporting component: it receives alive HostReports from
// the runner (via the ReportSink hook), buffers them, and flushes them to the
// center's POST /agents/report endpoint with exponential-backoff retries.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/runner"
)

// Reporter buffers scan results from the local engine and flushes them to the
// center. It implements runner.ReportSink (via its Report method) so the runner
// hands it each scan's alive HostReports without knowing about HTTP.
//
// It is the agent counterpart to the center's ingestion handler. The agent's
// network identity (network_id) is NOT sent in the body — the center resolves
// it from the agent's bearer token (authenticity + scoping live there). The
// reporter just ships the discovery payload + the agent_id label.
type Reporter struct {
	centerURL  string // base URL, e.g. "http://192.168.63.101:8080"
	authToken  string // agent bearer token (minted on the center)
	agentID    string // advisory label echoed in the report body
	client     *http.Client
	logger     *slog.Logger

	mu     sync.Mutex
	buf    []domain.ReportedHost // buffered hosts awaiting the next flush
	flush  time.Duration         // max time between flushes (ReportInterval)
	maxBuf int                   // max hosts buffered before an early flush

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewReporter constructs a Reporter. centerURL is the center base URL,
// authToken the agent's bearer token, agentID the advisory label, flush the
// max interval between flushes (≤0 → 30s), maxBuf the buffer size that triggers
// an early flush (≤0 → 256).
func NewReporter(centerURL, authToken, agentID string, flush time.Duration, maxBuf int, logger *slog.Logger) *Reporter {
	if logger == nil {
		logger = slog.Default()
	}
	if flush <= 0 {
		flush = 30 * time.Second
	}
	if maxBuf <= 0 {
		maxBuf = 256
	}
	return &Reporter{
		centerURL: centerURL,
		authToken: authToken,
		agentID:   agentID,
		client:    &http.Client{Timeout: 30 * time.Second},
		logger:    logger,
		flush:     flush,
		maxBuf:    maxBuf,
	}
}

// Report is the runner.ReportSink implementation. It converts each alive
// HostReport to the wire payload, buffers it, and flushes immediately when the
// buffer fills. Non-blocking past the buffer-append; the actual HTTP POST
// happens on the flush goroutine or inline on a full buffer.
func (r *Reporter) Report(_ context.Context, _ int64, reports []scannerv2.HostReport) {
	r.mu.Lock()
	for _, rep := range reports {
		if !rep.Alive || rep.IP == "" {
			continue
		}
		r.buf = append(r.buf, hostToReported(rep))
	}
	full := len(r.buf) >= r.maxBuf
	r.mu.Unlock()

	if full {
		// Buffer full — flush now rather than waiting for the ticker. Best-effort
		// (run on a background goroutine so the scan pipeline isn't blocked).
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.flushOnce(context.Background())
		}()
	}
}

// Start launches the periodic flush loop. Call once; stop with Stop.
func (r *Reporter) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(r.flush)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.flushOnce(ctx)
			}
		}
	}()
}

// Stop cancels the flush loop and does a final best-effort flush of any buffered
// hosts (so a graceful agent shutdown doesn't drop the last scan batch).
func (r *Reporter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.flushOnce(ctx)
}

// flushOnce drains the buffer and POSTs it to the center with exponential
// backoff on failure. Logs + drops on terminal failure (the next scan refills;
// this is best-effort eventual delivery, not durable — change-detection at the
// center reconciles state across scans).
func (r *Reporter) flushOnce(ctx context.Context) {
	r.mu.Lock()
	if len(r.buf) == 0 {
		r.mu.Unlock()
		return
	}
	hosts := r.buf
	r.buf = nil
	r.mu.Unlock()

	payload := domain.AgentReport{
		AgentID:    r.agentID,
		ScannedAt:  time.Now().UTC(),
		Hosts:      hosts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		r.logger.Warn("agent reporter: marshal failed, dropping batch", "hosts", len(hosts), "error", err)
		return
	}
	url := r.centerURL + "/api/v1/agents/report"

	// Exponential backoff: 1s, 2s, 4s, 8s — then give up this batch.
	backoff := time.Second
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			r.logger.Warn("agent reporter: request build failed", "error", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+r.authToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := r.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				r.logger.Info("agent reporter: report accepted", "hosts", len(hosts), "attempt", attempt)
				return
			}
			// 4xx (except 429) is terminal — retrying won't help (bad token, bad
			// payload). 5xx / 429 → backoff and retry.
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
				r.logger.Warn("agent reporter: center rejected report (terminal)", "status", resp.StatusCode, "hosts", len(hosts))
				return
			}
			err = errRejected{status: resp.StatusCode}
		}
		if attempt >= 4 {
			r.logger.Warn("agent reporter: giving up after retries, dropping batch", "hosts", len(hosts), "last_error", err)
			return
		}
		r.logger.Warn("agent reporter: report failed, retrying", "attempt", attempt, "error", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

// errRejected wraps a non-2xx response so the retry log line is informative.
type errRejected struct{ status int }

func (e errRejected) Error() string { return "center rejected report" }

// hostToReported converts one in-memory HostReport to the wire payload. Mirrors
// runner.ReportedHostToReport in reverse: pulls the MAC (from Fields or the mac
// evidence piece), inferred fields, services, heartbeats. The center
// reconstructs a HostReport from this via ReportedHostToReport.
func hostToReported(rep scannerv2.HostReport) domain.ReportedHost {
	f := rep.Device.Fields
	out := domain.ReportedHost{
		IP:                  rep.IP,
		Alive:               rep.Alive,
		RTTMs:               rep.RTTMs,
		MAC:                 f["mac"],
		InferredType:        f["inferred_type"],
		InferredBrand:       f["inferred_brand"],
		InferredDescription: f["inferred_description"],
		InferredLocation:    f["inferred_location"],
		Hostname:            firstNonEmptyStr(f["node_hostname"], f["sys_name"]),
		OpenPorts:           f["open_ports"],
		DetectedServices:    f["detected_services"],
		PrometheusURL:       f["prometheus_url"],
		NodeExporterURL:     f["node_exporter_url"],
	}
	// MAC fallback from evidence (the ARP probe may put it there rather than Fields).
	if out.MAC == "" {
		for _, e := range rep.Evidence {
			if e.Kind == "mac" && e.RawData != nil && e.RawData["mac"] != "" {
				out.MAC = e.RawData["mac"]
				break
			}
		}
	}
	for _, s := range rep.Services {
		out.Services = append(out.Services, domain.ReportedService{
			Service: s.Service, Port: s.Port, Protocol: s.Protocol, Metadata: s.Metadata,
		})
	}
	for _, hb := range rep.Heartbeats {
		out.Heartbeats = append(out.Heartbeats, domain.ReportedHeartbeat{
			Method: hb.Method, Target: hb.Target, IntervalSeconds: hb.IntervalSeconds,
			TimeoutSeconds: hb.TimeoutSeconds, SNMPCommunity: hb.SNMPCommunity, SNMPOID: hb.SNMPOID,
		})
	}
	return out
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// Compile-time check that Reporter satisfies the runner.ReportSink signature.
var _ runner.ReportSink = (*Reporter)(nil).Report
